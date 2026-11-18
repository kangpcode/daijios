// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijiacs

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

const DefaultLowRxThresholdDBm = -27.0

// CPEDevice tracks one managed ONT/router across TR-069 CWMP & TR-369 USP.
type CPEDevice struct {
	Serial         string            `json:"serial"`
	OUI            string            `json:"oui"`
	Manufacturer   string            `json:"manufacturer"`
	ProductClass   string            `json:"product_class"`
	TemplateID     string            `json:"template_id"`
	Tags           map[string]bool   `json:"tags,omitempty"`
	SubscriberUser string            `json:"subscriber_user,omitempty"`
	BillingStatus  string            `json:"billing_status"` // active | suspended
	AppliedPolicy  int               `json:"applied_policy_version"`
	LastEvents     []string          `json:"last_events,omitempty"`
	LastInformAt   time.Time         `json:"last_inform_at"`
	Params         map[string]string `json:"-"` // raw params protected from direct leak
	Virtual        VirtualParams     `json:"virtual"`
	Queue          []CPETask         `json:"queue,omitempty"`
	ActiveTaskID   string            `json:"active_task_id,omitempty"`
}

// USPMessage models a TR-369 USP protocol record (JSON MTP) routed through DaijiACS.
type USPMessage struct {
	MsgID        string            `json:"msg_id"`
	EndpointID   string            `json:"endpoint_id"` // maps to Serial
	Manufacturer string            `json:"manufacturer,omitempty"`
	ProductClass string            `json:"product_class,omitempty"`
	Type         string            `json:"type"` // GET | SET | OPERATE
	Paths        []string          `json:"paths,omitempty"`
	Params       map[string]string `json:"params,omitempty"`
	Command      string            `json:"command,omitempty"` // Reboot | FactoryReset | FirmwareUpgrade
	URL          string            `json:"url,omitempty"`
}

// MonitoringSummary aggregates fleet CPE health and optical Rx alarms.
type MonitoringSummary struct {
	Brand             string            `json:"brand"`
	TotalCPEs         int               `json:"total_cpes"`
	OnlineCPEs        int               `json:"online_cpes"`
	OfflineCPEs       int               `json:"offline_cpes"`
	LowOpticalAlarms  []string          `json:"low_optical_alarms"`
	SuspendedBilling  int               `json:"suspended_billing"`
	ByVendorTemplate  map[string]int    `json:"by_vendor_template"`
	PendingTasks      int               `json:"pending_tasks"`
	OpticalThreshold  float64           `json:"optical_threshold_dbm"`
}

// Config configures an ACS Server instance.
type Config struct {
	Templates          []VendorTemplate
	Presets            []PresetRule
	CWMPUsername       string
	CWMPPassword       string
	Tokens             *secauth.TokenManager
	RBAC               *secauth.RBACPolicy
	AllowInsecureHTTP  bool // allow http:// firmware URLs in isolated lab LANs
	OfflineThreshold   time.Duration
	LowOpticalDBm      float64
	Now                func() time.Time
}

// Server manages TR-069 CWMP sessions, TR-369 USP records, templates, presets,
// customer WiFi actions (Daimo/DaiWeb), and billing/optical monitoring.
type Server struct {
	cfg Config
	mu  sync.RWMutex
	cpes map[string]*CPEDevice
	sessToSerial map[string]string
	mux *http.ServeMux
}

// NewServer constructs a DaijiACS control plane server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if len(cfg.Templates) == 0 {
		cfg.Templates = DefaultVendorTemplates()
	}
	if cfg.OfflineThreshold <= 0 {
		cfg.OfflineThreshold = 10 * time.Minute
	}
	if cfg.LowOpticalDBm == 0 {
		cfg.LowOpticalDBm = DefaultLowRxThresholdDBm
	}
	if cfg.RBAC == nil {
		cfg.RBAC = secauth.NewDefaultRBACPolicy(true)
	}
	if cfg.Tokens == nil {
		tm, err := secauth.NewTokenManager([]byte("daijiacs-default-signing-key-phase8"), 12*time.Hour)
		if err != nil {
			return nil, err
		}
		cfg.Tokens = tm
	}
	s := &Server{
		cfg:          cfg,
		cpes:         make(map[string]*CPEDevice),
		sessToSerial: make(map[string]string),
		mux:          http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

// EnqueueWiFiConfig translates customer WiFi SSID/passphrase updates into vendor-specific RPC tasks.
func (s *Server) EnqueueWiFiConfig(serial, ssid, passphrase string, enabled *bool) (CPETask, error) {
	if len(ssid) == 0 || len(ssid) > 32 {
		return CPETask{}, fmt.Errorf("%w: SSID must be 1..32 chars", ErrInvalidWiFi)
	}
	if passphrase != "" && (len(passphrase) < 8 || len(passphrase) > 63) {
		return CPETask{}, fmt.Errorf("%w: WPA passphrase must be 8..63 chars", ErrInvalidWiFi)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	dev, ok := s.cpes[serial]
	if !ok {
		return CPETask{}, fmt.Errorf("%w: %s", ErrUnknownCPE, serial)
	}
	tpl := s.findTemplateByID(dev.TemplateID)
	sets := []ParamValue{
		{Name: tpl.WiFiSSIDPath, Type: "xsd:string", Value: ssid},
	}
	if passphrase != "" {
		sets = append(sets, ParamValue{Name: tpl.WiFiPassPath, Type: "xsd:string", Value: passphrase})
	}
	if enabled != nil {
		v := "false"
		if *enabled {
			v = "true"
		}
		sets = append(sets, ParamValue{Name: tpl.WiFiEnablePath, Type: "xsd:boolean", Value: v})
	}

	tk := CPETask{
		ID:        newHexID("wifi"),
		Method:    RPCSetParamValues,
		SetParams: sets,
		Status:    "pending",
		Summary:   fmt.Sprintf("Set WiFi SSID=%q (passphrase masked)", ssid),
		CreatedAt: s.cfg.Now().UTC().Format(time.RFC3339),
	}
	dev.Queue = append(dev.Queue, tk)
	return tk, nil
}

// EnqueueFirmwareUpgrade queues a TR-069 Download RPC after strict URL scheme validation.
func (s *Server) EnqueueFirmwareUpgrade(serial, fwURL string, fileSize int64) (CPETask, error) {
	u, err := url.ParseRequestURI(fwURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(s.cfg.AllowInsecureHTTP && u.Scheme == "http")) {
		return CPETask{}, ErrUnsafeURL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dev, ok := s.cpes[serial]
	if !ok {
		return CPETask{}, fmt.Errorf("%w: %s", ErrUnknownCPE, serial)
	}
	tk := CPETask{
		ID:         newHexID("fw"),
		Method:     RPCDownload,
		CommandKey: newHexID("cmd"),
		FileType:   "1 Firmware Upgrade Image",
		URL:        fwURL,
		FileSize:   fileSize,
		Status:     "pending",
		Summary:    fmt.Sprintf("Firmware Download %s", fwURL),
		CreatedAt:  s.cfg.Now().UTC().Format(time.RFC3339),
	}
	dev.Queue = append(dev.Queue, tk)
	return tk, nil
}

// EnqueueLifecycle queues a Reboot or FactoryReset RPC on serial.
func (s *Server) EnqueueLifecycle(serial string, method RPCMethod) (CPETask, error) {
	if method != RPCReboot && method != RPCFactoryReset {
		return CPETask{}, fmt.Errorf("invalid lifecycle RPC %q", method)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dev, ok := s.cpes[serial]
	if !ok {
		return CPETask{}, fmt.Errorf("%w: %s", ErrUnknownCPE, serial)
	}
	tk := CPETask{
		ID:         newHexID("lc"),
		Method:     method,
		CommandKey: newHexID("cmd"),
		Status:     "pending",
		Summary:    string(method),
		CreatedAt:  s.cfg.Now().UTC().Format(time.RFC3339),
	}
	dev.Queue = append(dev.Queue, tk)
	return tk, nil
}

// ApplyBillingAction integrates DaijiBilling suspend (isolir) / activate actions with CPE WAN provisioning.
func (s *Server) ApplyBillingAction(serial, action string) (CPETask, error) {
	enableWAN := true
	newState := "active"
	switch strings.ToLower(action) {
	case "suspend", "isolir":
		enableWAN = false
		newState = "suspended"
	case "activate", "unsuspend":
		enableWAN = true
		newState = "active"
	default:
		return CPETask{}, fmt.Errorf("unsupported billing action %q", action)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	dev, ok := s.cpes[serial]
	if !ok {
		return CPETask{}, fmt.Errorf("%w: %s", ErrUnknownCPE, serial)
	}
	tpl := s.findTemplateByID(dev.TemplateID)
	val := "false"
	if enableWAN {
		val = "true"
	}
	dev.BillingStatus = newState
	tk := CPETask{
		ID:        newHexID("bill"),
		Method:    RPCSetParamValues,
		SetParams: []ParamValue{{Name: tpl.WANEnablePath, Type: "xsd:boolean", Value: val}},
		Status:    "pending",
		Summary:   fmt.Sprintf("Billing %s (WAN Enable=%s)", newState, val),
		CreatedAt: s.cfg.Now().UTC().Format(time.RFC3339),
	}
	dev.Queue = append(dev.Queue, tk)
	return tk, nil
}

// HandleUSPMessage processes a TR-369 USP record unified onto the same CPE inventory & templates.
func (s *Server) HandleUSPMessage(msg USPMessage) (map[string]any, error) {
	if strings.TrimSpace(msg.EndpointID) == "" || strings.TrimSpace(msg.Type) == "" {
		return nil, ErrInvalidUSP
	}
	s.mu.Lock()
	dev, exists := s.cpes[msg.EndpointID]
	if !exists {
		tpl := MatchTemplate(s.cfg.Templates, msg.Manufacturer, msg.ProductClass, msg.Params)
		dev = &CPEDevice{
			Serial:        msg.EndpointID,
			Manufacturer:  msg.Manufacturer,
			ProductClass:  msg.ProductClass,
			TemplateID:    tpl.ID,
			BillingStatus: "active",
			Params:        make(map[string]string),
			LastInformAt:  s.cfg.Now().UTC(),
		}
		s.cpes[msg.EndpointID] = dev
	}
	dev.LastInformAt = s.cfg.Now().UTC()
	tpl := s.findTemplateByID(dev.TemplateID)

	switch strings.ToUpper(msg.Type) {
	case "GET":
		res := make(map[string]string, len(msg.Paths))
		for _, p := range msg.Paths {
			if val, ok := dev.Params[p]; ok {
				res[p] = val
			}
		}
		s.mu.Unlock()
		return map[string]any{"msg_id": msg.MsgID, "status": "ok", "values": res}, nil

	case "SET":
		for k, v := range msg.Params {
			if p, _, normVal, isVirt := ResolveVirtualSet(tpl, k, v); isVirt {
				dev.Params[p] = normVal
			} else {
				dev.Params[k] = v
			}
		}
		dev.Virtual = ExtractVirtualParams(tpl, dev.Params, true)
		s.mu.Unlock()
		return map[string]any{"msg_id": msg.MsgID, "status": "applied", "template_id": tpl.ID}, nil

	case "OPERATE":
		s.mu.Unlock()
		switch msg.Command {
		case "Reboot":
			tk, err := s.EnqueueLifecycle(msg.EndpointID, RPCReboot)
			return map[string]any{"msg_id": msg.MsgID, "task": tk}, err
		case "FactoryReset":
			tk, err := s.EnqueueLifecycle(msg.EndpointID, RPCFactoryReset)
			return map[string]any{"msg_id": msg.MsgID, "task": tk}, err
		case "FirmwareUpgrade":
			tk, err := s.EnqueueFirmwareUpgrade(msg.EndpointID, msg.URL, 0)
			return map[string]any{"msg_id": msg.MsgID, "task": tk}, err
		default:
			return nil, fmt.Errorf("%w: unknown USP operate command %q", ErrInvalidUSP, msg.Command)
		}
	default:
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: unknown USP type %q", ErrInvalidUSP, msg.Type)
	}
}

// SnapshotMonitoring computes CPE fleet telemetry & low optical Rx alarms.
func (s *Server) SnapshotMonitoring() MonitoringSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.cfg.Now()
	sum := MonitoringSummary{
		Brand:            sysinfo.BrandBanner,
		TotalCPEs:        len(s.cpes),
		LowOpticalAlarms: []string{},
		ByVendorTemplate: make(map[string]int),
		OpticalThreshold: s.cfg.LowOpticalDBm,
	}
	for _, d := range s.cpes {
		sum.ByVendorTemplate[d.TemplateID]++
		if now.Sub(d.LastInformAt) <= s.cfg.OfflineThreshold {
			sum.OnlineCPEs++
		} else {
			sum.OfflineCPEs++
		}
		if d.BillingStatus == "suspended" {
			sum.SuspendedBilling++
		}
		if d.Virtual.OpticalRxDBm != nil && *d.Virtual.OpticalRxDBm < s.cfg.LowOpticalDBm {
			sum.LowOpticalAlarms = append(sum.LowOpticalAlarms,
				fmt.Sprintf("%s (%s): optical Rx=%.2f dBm < %.2f dBm", d.Serial, d.TemplateID, *d.Virtual.OpticalRxDBm, s.cfg.LowOpticalDBm))
		}
		for _, tk := range d.Queue {
			if tk.Status == "pending" || tk.Status == "sent" {
				sum.PendingTasks++
			}
		}
	}
	sort.Strings(sum.LowOpticalAlarms)
	return sum
}

// GetDevice returns a deep snapshot of one CPE device (secret passphrase redacted when redactSecrets is true).
func (s *Server) GetDevice(serial string, redactSecrets bool) (CPEDevice, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.cpes[serial]
	if !ok {
		return CPEDevice{}, false
	}
	return s.cloneDeviceLocked(d, redactSecrets), true
}

func (s *Server) cloneDeviceLocked(d *CPEDevice, redactSecrets bool) CPEDevice {
	cp := *d
	cp.LastEvents = append([]string(nil), d.LastEvents...)
	cp.Queue = make([]CPETask, len(d.Queue))
	for i, tk := range d.Queue {
		if redactSecrets {
			cp.Queue[i] = redactTaskSecrets(tk)
		} else {
			cp.Queue[i] = tk
		}
	}
	tpl := s.findTemplateByID(d.TemplateID)
	cp.Virtual = ExtractVirtualParams(tpl, d.Params, redactSecrets)
	return cp
}

// Handler returns the HTTP multiplexer exposing /tr069, /usp, and /api/v1/acs/* endpoints.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("/tr069", s.handleCWMP)
	s.mux.HandleFunc("/usp", s.requirePerm(secauth.PermConfigWrite, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
		s.handleUSPHTTP(w, r)
	}))
	s.mux.HandleFunc("/api/v1/acs/devices", s.requirePerm(secauth.PermConfigRead, s.handleListDevices))
	s.mux.HandleFunc("/api/v1/acs/devices/", s.handleDeviceSubroutes)
	s.mux.HandleFunc("/api/v1/acs/monitoring", s.requirePerm(secauth.PermNetDiag, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
		writeJSON(w, http.StatusOK, s.SnapshotMonitoring())
	}))
}

func (s *Server) handleCWMP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.CWMPUsername != "" || s.cfg.CWMPPassword != "" {
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(s.cfg.CWMPUsername)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(s.cfg.CWMPPassword)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="DaijiACS CWMP"`)
			http.Error(w, "unauthorized CPE", http.StatusUnauthorized)
			return
		}
	}

	parsed, err := ParseCWMPEnvelope(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if parsed.Kind == "Inform" {
		sid := newHexID("sid")
		s.mu.Lock()
		inf := parsed.Inform
		dev, exists := s.cpes[inf.SerialNumber]
		if !exists {
			tpl := MatchTemplate(s.cfg.Templates, inf.Manufacturer, inf.ProductClass, inf.Params)
			dev = &CPEDevice{
				Serial:        inf.SerialNumber,
				OUI:           inf.OUI,
				Manufacturer:  inf.Manufacturer,
				ProductClass:  inf.ProductClass,
				TemplateID:    tpl.ID,
				BillingStatus: "active",
				Params:        make(map[string]string),
			}
			s.cpes[inf.SerialNumber] = dev
		}
		dev.LastInformAt = s.cfg.Now().UTC()
		dev.LastEvents = inf.Events
		for k, v := range inf.Params {
			dev.Params[k] = v
		}
		tpl := s.findTemplateByID(dev.TemplateID)
		s.applyPresetsLocked(dev, tpl, inf.Events)
		dev.Virtual = ExtractVirtualParams(tpl, dev.Params, true)
		s.sessToSerial[sid] = dev.SerialNumberOrFallback(inf.SerialNumber)
		s.mu.Unlock()

		http.SetCookie(w, &http.Cookie{Name: "daiji_cwmp_sid", Value: sid, Path: "/tr069", HttpOnly: true})
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, BuildInformResponse(parsed.MessageID))
		return
	}

	// Non-Inform step (RPC response or empty POST polling pending tasks): correlate session cookie or ?serial= fallback.
	serial := s.resolveCWMPSessionSerial(r)
	if serial == "" {
		http.Error(w, "missing CWMP session cookie", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	dev, ok := s.cpes[serial]
	if !ok {
		http.Error(w, "unknown CPE session", http.StatusNotFound)
		return
	}

	// Complete active RPC task based on CPE reply.
	if parsed.Kind != "Empty" && dev.ActiveTaskID != "" {
		nowStr := s.cfg.Now().UTC().Format(time.RFC3339)
		for i := range dev.Queue {
			if dev.Queue[i].ID == dev.ActiveTaskID {
				if parsed.Kind == "Fault" {
					dev.Queue[i].Status = "fault"
					dev.Queue[i].FaultCode = parsed.FaultCode
					dev.Queue[i].FaultStr = parsed.FaultStr
				} else {
					dev.Queue[i].Status = "done"
					if parsed.Kind == "GetParameterValuesResponse" {
						for k, v := range parsed.GetValues {
							dev.Params[k] = v
						}
						dev.Virtual = ExtractVirtualParams(s.findTemplateByID(dev.TemplateID), dev.Params, true)
					} else if parsed.Kind == "SetParameterValuesResponse" {
						for _, sp := range dev.Queue[i].SetParams {
							dev.Params[sp.Name] = sp.Value
						}
						dev.Virtual = ExtractVirtualParams(s.findTemplateByID(dev.TemplateID), dev.Params, true)
					}
				}
				dev.Queue[i].UpdatedAt = nowStr
				break
			}
		}
		dev.ActiveTaskID = ""
	}

	// Dispatch next pending task if queued, else end CWMP session cleanly with 204 No Content.
	for i := range dev.Queue {
		if dev.Queue[i].Status == "pending" {
			dev.Queue[i].Status = "sent"
			dev.Queue[i].UpdatedAt = s.cfg.Now().UTC().Format(time.RFC3339)
			dev.ActiveTaskID = dev.Queue[i].ID
			env := BuildTaskEnvelope(newHexID("rpc"), dev.Queue[i])
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, env)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) resolveCWMPSessionSerial(r *http.Request) string {
	if ck, err := r.Cookie("daiji_cwmp_sid"); err == nil && ck.Value != "" {
		s.mu.RLock()
		serial := s.sessToSerial[ck.Value]
		s.mu.RUnlock()
		if serial != "" {
			return serial
		}
	}
	return r.URL.Query().Get("serial")
}

func (s *Server) applyPresetsLocked(dev *CPEDevice, tpl VendorTemplate, events []string) {
	evSet := make(map[string]bool, len(events))
	for _, ev := range events {
		evSet[ev] = true
	}
	nowStr := s.cfg.Now().UTC().Format(time.RFC3339)
	for _, rule := range s.cfg.Presets {
		if rule.PolicyVersion <= dev.AppliedPolicy {
			continue
		}
		if rule.VendorFilter != "" && !strings.Contains(strings.ToLower(dev.Manufacturer+dev.ProductClass+dev.TemplateID), strings.ToLower(rule.VendorFilter)) {
			continue
		}
		if rule.EventFilter != "" && !evSet[rule.EventFilter] {
			continue
		}
		if rule.TagFilter != "" && !dev.Tags[rule.TagFilter] {
			continue
		}
		var sets []ParamValue
		keysV := make([]string, 0, len(rule.VirtualSets))
		for k := range rule.VirtualSets {
			keysV = append(keysV, k)
		}
		sort.Strings(keysV)
		for _, k := range keysV {
			if p, tp, val, ok := ResolveVirtualSet(tpl, k, rule.VirtualSets[k]); ok {
				sets = append(sets, ParamValue{Name: p, Type: tp, Value: val})
			}
		}
		keysR := make([]string, 0, len(rule.RawSets))
		for k := range rule.RawSets {
			keysR = append(keysR, k)
		}
		sort.Strings(keysR)
		for _, k := range keysR {
			sets = append(sets, ParamValue{Name: k, Type: "xsd:string", Value: rule.RawSets[k]})
		}
		if len(sets) > 0 {
			dev.Queue = append(dev.Queue, CPETask{
				ID:        newHexID("preset"),
				Method:    RPCSetParamValues,
				SetParams: sets,
				Status:    "pending",
				Summary:   fmt.Sprintf("Preset %s (v%d)", rule.ID, rule.PolicyVersion),
				CreatedAt: nowStr,
			})
			dev.AppliedPolicy = rule.PolicyVersion
		}
	}
}

func (s *Server) findTemplateByID(id string) VendorTemplate {
	for _, tpl := range s.cfg.Templates {
		if tpl.ID == id {
			return tpl
		}
	}
	return s.cfg.Templates[0]
}

func (d *CPEDevice) SerialNumberOrFallback(fallback string) string {
	if d.Serial != "" {
		return d.Serial
	}
	return fallback
}

func (s *Server) handleUSPHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var msg USPMessage
	if err := json.NewDecoder(io.LimitReader(r.Body, 256*1024)).Decode(&msg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid USP JSON"})
		return
	}
	res, err := s.HandleUSPMessage(msg)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request, claims *secauth.TokenClaims) {
	redact := s.cfg.RBAC.Authorize(claims.Role, secauth.PermConfigReadSecrets) != nil
	s.mu.RLock()
	out := make([]CPEDevice, 0, len(s.cpes))
	for _, d := range s.cpes {
		out = append(out, s.cloneDeviceLocked(d, redact))
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Serial < out[j].Serial })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeviceSubroutes(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/v1/acs/devices/")
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	serial := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch action {
	case "":
		s.requirePerm(secauth.PermConfigRead, func(w http.ResponseWriter, r *http.Request, claims *secauth.TokenClaims) {
			redact := s.cfg.RBAC.Authorize(claims.Role, secauth.PermConfigReadSecrets) != nil
			dev, ok := s.GetDevice(serial, redact)
			if !ok {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
				return
			}
			writeJSON(w, http.StatusOK, dev)
		})(w, r)

	case "wifi":
		s.requirePerm(secauth.PermConfigWrite, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
			var req struct {
				SSID       string `json:"ssid"`
				Passphrase string `json:"passphrase"`
				Enabled    *bool  `json:"enabled"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			tk, err := s.EnqueueWiFiConfig(serial, req.SSID, req.Passphrase, req.Enabled)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, redactTaskSecrets(tk))
		})(w, r)

	case "firmware":
		s.requirePerm(secauth.PermSystemUpdate, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
			var req struct {
				URL      string `json:"url"`
				FileSize int64  `json:"file_size"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			tk, err := s.EnqueueFirmwareUpgrade(serial, req.URL, req.FileSize)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, tk)
		})(w, r)

	case "reboot":
		s.requirePerm(secauth.PermSystemReboot, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
			tk, err := s.EnqueueLifecycle(serial, RPCReboot)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, tk)
		})(w, r)

	case "factory-reset":
		s.requirePerm(secauth.PermSystemReboot, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
			tk, err := s.EnqueueLifecycle(serial, RPCFactoryReset)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, tk)
		})(w, r)

	case "billing-state":
		s.requirePerm(secauth.PermConfigWrite, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
			var req struct {
				Action string `json:"action"` // suspend | activate
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			tk, err := s.ApplyBillingAction(serial, req.Action)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, tk)
		})(w, r)

	default:
		http.NotFound(w, r)
	}
}

func (s *Server) requirePerm(perm secauth.Permission, next func(http.ResponseWriter, *http.Request, *secauth.TokenClaims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		tok := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
		claims, err := s.cfg.Tokens.Verify(tok, perm, s.cfg.Now())
		if err != nil {
			code := http.StatusUnauthorized
			if strings.Contains(err.Error(), "scope") {
				code = http.StatusForbidden
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if err := s.cfg.RBAC.Authorize(claims.Role, perm); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		next(w, r, claims)
	}
}

func redactTaskSecrets(tk CPETask) CPETask {
	out := tk
	if len(tk.SetParams) > 0 {
		out.SetParams = make([]ParamValue, len(tk.SetParams))
		for i, pv := range tk.SetParams {
			cp := pv
			low := strings.ToLower(pv.Name)
			if strings.Contains(low, "pass") || strings.Contains(low, "secret") || strings.Contains(low, "presharedkey") {
				cp.Value = "***REDACTED***"
			}
			out.SetParams[i] = cp
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

var _ = errors.Is
var _ = strconv.Atoi
