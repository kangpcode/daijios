// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijicloud

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

// Server exposes DaijiCloud Public Multi-Tenant APIs, Observability, and ZTP endpoints.
type Server struct {
	cp     *ControlPlane
	tokens *secauth.TokenManager
	mux    *http.ServeMux
}

// NewServer wraps a ControlPlane with authenticated HTTP/REST Public APIs & Observability.
func NewServer(cp *ControlPlane, tokens *secauth.TokenManager) (*Server, error) {
	if cp == nil {
		return nil, errors.New("control plane required")
	}
	if tokens == nil {
		tm, err := secauth.NewTokenManager([]byte("daijicloud-default-jwt-key-phase10"), 12*time.Hour)
		if err != nil {
			return nil, err
		}
		tokens = tm
	}
	s := &Server{cp: cp, tokens: tokens, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

// Handler returns the traced HTTP handler.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		s.cp.obs.IncHTTP()
		traceID := strings.TrimSpace(r.Header.Get("X-Trace-ID"))
		if traceID == "" {
			var b [8]byte
			_, _ = rand.Read(b[:])
			traceID = hex.EncodeToString(b[:])
		}
		w.Header().Set("X-Trace-ID", traceID)
		sw := &statusRecorder{ResponseWriter: w, status: 200}
		s.mux.ServeHTTP(sw, r)
		s.cp.obs.AddTrace(traceID, r.Method+" "+r.URL.Path, sw.status, time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/v1/cloud/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "brand": sysinfo.BrandBanner})
	})

	// ZTP device enrollment endpoint (authenticated solely by signed single-use ZTP claim token).
	s.mux.HandleFunc("/api/v1/cloud/ztp/adopt", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token    string `json:"token"`
			Serial   string `json:"serial"`
			MAC      string `json:"mac"`
			Hostname string `json:"hostname"`
			Platform string `json:"platform"`
			Firmware string `json:"firmware_ver"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		dev, err := s.cp.AdoptViaZTP(req.Token, req.Serial, req.MAC, req.Hostname, req.Platform, req.Firmware)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, dev)
	})

	s.mux.HandleFunc("/api/v1/cloud/orgs/", s.handleOrgScoped)
	s.mux.HandleFunc("/metrics", s.handlePrometheus)
	s.mux.HandleFunc("/api/v1/cloud/observability/traces", s.requireToken(secauth.PermAuditRead, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
		s.cp.obs.mu.Lock()
		traces := append([]TraceSpan(nil), s.cp.obs.traces...)
		logs := append([]LogEntry(nil), s.cp.obs.logs...)
		s.cp.obs.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"traces": traces, "logs": logs})
	}))
}

func (s *Server) handleOrgScoped(w http.ResponseWriter, r *http.Request) {
	// Routes: /api/v1/cloud/orgs/{orgID}/{resource...}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/cloud/orgs/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	orgID := parts[0]
	res := parts[1]

	var needPerm secauth.Permission = secauth.PermConfigRead
	if r.Method == http.MethodPost {
		needPerm = secauth.PermConfigWrite
		if res == "rollouts" {
			needPerm = secauth.PermSystemUpdate
		}
	}

	s.requireToken(needPerm, func(w http.ResponseWriter, r *http.Request, claims *secauth.TokenClaims) {
		siteID := r.URL.Query().Get("site_id")
		if err := s.cp.AuthorizeTenant(claims.Subject, orgID, siteID, needPerm); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}

		switch res {
		case "devices":
			s.cp.mu.RLock()
			var list []CloudDevice
			for _, d := range s.cp.devices {
				if d.OrgID == orgID && (siteID == "" || d.SiteID == siteID) {
					list = append(list, *d)
				}
			}
			s.cp.mu.RUnlock()
			sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
			writeJSON(w, http.StatusOK, list)

		case "ztp-claims":
			var req struct {
				SiteID  string `json:"site_id"`
				Serial  string `json:"serial"`
				Profile string `json:"profile"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			tok, err := s.cp.CreateZTPClaimToken(orgID, req.SiteID, req.Serial, req.Profile, 30*time.Minute)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"ztp_token": tok})

		case "alerts":
			s.cp.mu.RLock()
			var out []CloudAlert
			for _, a := range s.cp.alerts {
				if a.OrgID == orgID {
					out = append(out, *a)
				}
			}
			s.cp.mu.RUnlock()
			writeJSON(w, http.StatusOK, out)

		case "rollouts":
			var req struct {
				SiteID        string `json:"site_id"`
				TargetVersion string `json:"target_version"`
				ImageSHA256   string `json:"image_sha256"`
				CanaryPercent int    `json:"canary_percent"`
				MaxFailurePct int    `json:"max_failure_pct"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			job, err := s.cp.StartCanaryRollout(orgID, req.SiteID, req.TargetVersion, req.ImageSHA256, req.CanaryPercent, req.MaxFailurePct)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, job)

		default:
			http.NotFound(w, r)
		}
	})(w, r)
}

func (s *Server) handlePrometheus(w http.ResponseWriter, r *http.Request) {
	s.cp.mu.RLock()
	total, online, openAlerts := len(s.cp.devices), 0, 0
	for _, d := range s.cp.devices {
		if d.Online {
			online++
		}
	}
	for _, a := range s.cp.alerts {
		if a.Status == "open" {
			openAlerts++
		}
	}
	s.cp.mu.RUnlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = io.WriteString(w, s.cp.obs.RenderPrometheus(total, online, openAlerts))
}

func (s *Server) requireToken(perm secauth.Permission, next func(http.ResponseWriter, *http.Request, *secauth.TokenClaims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		tok := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
		claims, err := s.tokens.Verify(tok, perm, s.cp.nowFn())
		if err != nil {
			code := http.StatusUnauthorized
			if strings.Contains(err.Error(), "scope") {
				code = http.StatusForbidden
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		next(w, r, claims)
	}
}

// ClientSDK is the official typed Go SDK for interacting with the DaijiCloud Public API.
type ClientSDK struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// NewClientSDK instantiates a DaijiCloud Public API SDK client.
func NewClientSDK(baseURL, token string) *ClientSDK {
	return &ClientSDK{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *ClientSDK) CreateZTPClaim(ctx context.Context, orgID, siteID, serial, profile string) (string, error) {
	var resp struct {
		Token string `json:"ztp_token"`
	}
	err := c.doJSON(ctx, http.MethodPost, fmt.Sprintf("/api/v1/cloud/orgs/%s/ztp-claims", orgID), map[string]string{
		"site_id": siteID, "serial": serial, "profile": profile,
	}, &resp)
	return resp.Token, err
}

func (c *ClientSDK) ListDevices(ctx context.Context, orgID, siteID string) ([]CloudDevice, error) {
	path := fmt.Sprintf("/api/v1/cloud/orgs/%s/devices", orgID)
	if siteID != "" {
		path += "?site_id=" + siteID
	}
	var out []CloudDevice
	err := c.doJSON(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

func (c *ClientSDK) StartCanaryRollout(ctx context.Context, orgID, siteID, version, imgSHA256 string, canaryPct, maxFailPct int) (*RolloutJob, error) {
	var job RolloutJob
	err := c.doJSON(ctx, http.MethodPost, fmt.Sprintf("/api/v1/cloud/orgs/%s/rollouts", orgID), map[string]any{
		"site_id": siteID, "target_version": version, "image_sha256": imgSHA256,
		"canary_percent": canaryPct, "max_failure_pct": maxFailPct,
	}, &job)
	return &job, err
}

func (c *ClientSDK) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("daijicloud API HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
