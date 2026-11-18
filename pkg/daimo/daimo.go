// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package daimo implements the backend & client engine for Daimo, the DaijiOS
// Mobile companion app: local & cloud login, HMAC-signed QR onboarding with
// anti-replay, WebSocket push alarm notifications, quick actions (reboot,
// disable user, bandwidth CoA), and monitoring graph time-series.
package daimo

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/daiweb"
	"github.com/kangpcode/daijios/pkg/ispengine"
	"github.com/kangpcode/daijios/pkg/isptools"
	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

var (
	ErrInvalidQR  = errors.New("invalid or tampered onboarding QR payload")
	ErrExpiredQR  = errors.New("onboarding QR code has expired")
	ErrReplayedQR = errors.New("onboarding QR nonce already redeemed")
)

// ConnectionMode selects local LAN vs DaijiCloud relay connectivity.
type ConnectionMode string

const (
	ModeLocal ConnectionMode = "local"
	ModeCloud ConnectionMode = "cloud"
)

// AlarmEvent describes a real-time device alarm dispatched to Daimo mobile clients.
type AlarmEvent struct {
	ID       string `json:"id"`
	DeviceID string `json:"device_id"`
	Severity string `json:"severity"` // critical | warning | info
	Kind     string `json:"kind"`     // wan-down | cpu-high | auth-bruteforce | ap-offline | safe-mode
	Message  string `json:"message"`
	At       string `json:"at"`
}

// PushRegistration binds an OS mobile push token (FCM/APNs/UnifiedPush) to an operator.
type PushRegistration struct {
	DeviceToken string `json:"device_token"`
	Platform    string `json:"platform"` // android | ios | unifiedpush
	Actor       string `json:"actor"`
	Registered  string `json:"registered_at"`
}

// MetricPoint is one time-series sample for Daimo monitoring charts.
type MetricPoint struct {
	Timestamp      string  `json:"ts"`
	CPUPercent     float64 `json:"cpu_percent"`
	MemUsedMB      uint64  `json:"mem_used_mb"`
	MemTotalMB     uint64  `json:"mem_total_mb"`
	RxMbps         float64 `json:"rx_mbps"`
	TxMbps         float64 `json:"tx_mbps"`
	ActiveSessions int     `json:"active_sessions"`
}

// QuickActionRequest invokes a remote operator control command from Daimo.
type QuickActionRequest struct {
	Action       string `json:"action"` // reboot | disable-user | set-bandwidth
	TargetUser   string `json:"target_user,omitempty"`
	UploadKbps   int    `json:"upload_kbps,omitempty"`
	DownloadKbps int    `json:"download_kbps,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// QuickActionResult reports execution outcome for a mobile quick action.
type QuickActionResult struct {
	Action    string `json:"action"`
	Actor     string `json:"actor"`
	Detail    string `json:"detail"`
	Timestamp string `json:"timestamp"`
}

// Config configures a Daimo mobile control gateway.
type Config struct {
	DeviceID   string
	MAC        string
	Config     *configengine.Engine
	Sessions   *ispengine.SessionManager
	MultiWAN   *ispengine.MultiWANMonitor
	Torch      *isptools.TorchAggregator
	Tokens     *secauth.TokenManager
	RBAC       *secauth.RBACPolicy
	BruteForce *secauth.BruteForceGuard
	TOTP       *secauth.TOTPVerifier
	Accounts   map[string]daiweb.Account
	QRSecret   []byte
	OnReboot   func(actor, reason string) error
	Now        func() time.Time
}

// Service implements the Daimo mobile REST + WebSocket push backend.
type Service struct {
	cfg        Config
	mu         sync.RWMutex
	usedNonces map[string]int64
	alarms     []AlarmEvent
	pushTokens map[string]PushRegistration
	subs       map[chan AlarmEvent]struct{}
	series     []MetricPoint
	bootAt     time.Time
	mux        *http.ServeMux
}

// NewService constructs a Daimo mobile API & push alarm service.
func NewService(cfg Config) (*Service, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.DeviceID == "" {
		cfg.DeviceID = "daiji-node-01"
	}
	if cfg.MAC == "" {
		cfg.MAC = "02:64:6a:00:00:01"
	}
	if len(cfg.QRSecret) < 16 {
		cfg.QRSecret = []byte("daijios-daimo-qr-secret-phase7")
	}
	if cfg.RBAC == nil {
		cfg.RBAC = secauth.NewDefaultRBACPolicy(true)
	}
	if cfg.BruteForce == nil {
		cfg.BruteForce = secauth.NewBruteForceGuard(secauth.BruteForcePolicy{
			Enabled:     true,
			MaxAttempts: 5,
			Window:      5 * time.Minute,
			BanDuration: 15 * time.Minute,
		})
	}
	if cfg.TOTP == nil {
		cfg.TOTP = secauth.NewTOTPVerifier(1)
	}
	if cfg.Tokens == nil {
		tm, err := secauth.NewTokenManager([]byte("daijios-daimo-token-key-phase7"), 24*time.Hour)
		if err != nil {
			return nil, err
		}
		cfg.Tokens = tm
	}

	s := &Service{
		cfg:        cfg,
		usedNonces: make(map[string]int64),
		pushTokens: make(map[string]PushRegistration),
		subs:       make(map[chan AlarmEvent]struct{}),
		bootAt:     cfg.Now(),
		mux:        http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

// GenerateOnboardingQR creates an HMAC-SHA256 signed single-use QR URI (never embedding passwords).
func (s *Service) GenerateOnboardingQR(mode ConnectionMode, endpoint, role, actor string, ttl time.Duration) (string, error) {
	if mode != ModeLocal && mode != ModeCloud {
		return "", fmt.Errorf("invalid connection mode %q", mode)
	}
	if endpoint == "" || role == "" || actor == "" {
		return "", errors.New("endpoint, role, and actor are required")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	var nonceBuf [10]byte
	if _, err := rand.Read(nonceBuf[:]); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(nonceBuf[:])
	exp := s.cfg.Now().UTC().Add(ttl).Unix()

	q := url.Values{}
	q.Set("v", "1")
	q.Set("dev", s.cfg.DeviceID)
	q.Set("mac", strings.ToLower(s.cfg.MAC))
	q.Set("mode", string(mode))
	q.Set("ep", endpoint)
	q.Set("role", role)
	q.Set("actor", actor)
	q.Set("nonce", nonce)
	q.Set("exp", strconv.FormatInt(exp, 10))
	sig := computeQRSignature(s.cfg.QRSecret, q)
	q.Set("sig", sig)

	return "daijios://onboard?" + q.Encode(), nil
}

// PairViaQR validates an onboarding QR URI, consumes its one-time nonce, and issues a scoped bearer token.
func (s *Service) PairViaQR(qrURI string) (token string, mode ConnectionMode, endpoint string, claims secauth.TokenClaims, err error) {
	u, err := url.Parse(strings.TrimSpace(qrURI))
	if err != nil || u.Scheme != "daijios" || u.Host != "onboard" {
		return "", "", "", secauth.TokenClaims{}, ErrInvalidQR
	}
	q := u.Query()
	sigHex := q.Get("sig")
	if q.Get("v") != "1" || sigHex == "" {
		return "", "", "", secauth.TokenClaims{}, ErrInvalidQR
	}

	gotSig, err := hex.DecodeString(sigHex)
	expSig, _ := hex.DecodeString(computeQRSignature(s.cfg.QRSecret, q))
	if err != nil || !hmac.Equal(gotSig, expSig) {
		return "", "", "", secauth.TokenClaims{}, ErrInvalidQR
	}

	expUnix, err := strconv.ParseInt(q.Get("exp"), 10, 64)
	if err != nil || s.cfg.Now().UTC().Unix() > expUnix {
		return "", "", "", secauth.TokenClaims{}, ErrExpiredQR
	}

	nonce := q.Get("nonce")
	s.mu.Lock()
	if _, used := s.usedNonces[nonce]; used {
		s.mu.Unlock()
		return "", "", "", secauth.TokenClaims{}, ErrReplayedQR
	}
	s.usedNonces[nonce] = expUnix
	s.mu.Unlock()

	mode = ConnectionMode(q.Get("mode"))
	role := q.Get("role")
	actor := q.Get("actor")
	endpoint = q.Get("ep")
	tok, c, err := s.cfg.Tokens.Issue(actor, role, scopesForRole(role), 24*time.Hour, s.cfg.Now())
	if err != nil {
		return "", "", "", secauth.TokenClaims{}, err
	}
	return tok, mode, endpoint, c, nil
}

// PublishAlarm appends an alarm event and fans it out to connected mobile push subscribers.
func (s *Service) PublishAlarm(ev AlarmEvent) {
	if ev.DeviceID == "" {
		ev.DeviceID = s.cfg.DeviceID
	}
	if ev.At == "" {
		ev.At = s.cfg.Now().UTC().Format(time.RFC3339)
	}
	if ev.ID == "" {
		var b [6]byte
		_, _ = rand.Read(b[:])
		ev.ID = "alm-" + hex.EncodeToString(b[:])
	}

	s.mu.Lock()
	s.alarms = append(s.alarms, ev)
	if len(s.alarms) > 200 {
		s.alarms = s.alarms[len(s.alarms)-200:]
	}
	subsCopy := make([]chan AlarmEvent, 0, len(s.subs))
	for ch := range s.subs {
		subsCopy = append(subsCopy, ch)
	}
	s.mu.Unlock()

	for _, ch := range subsCopy {
		select {
		case ch <- ev:
		default:
		}
	}
}

// RecordMetricSample snapshots current device telemetry into the mobile chart ring buffer.
func (s *Service) RecordMetricSample() MetricPoint {
	snap := daiweb.CollectTelemetrySnapshot(s.cfg.Config, s.cfg.Sessions, s.cfg.MultiWAN, s.cfg.Torch, s.bootAt, s.cfg.Now())
	pt := MetricPoint{
		Timestamp:      snap.Timestamp,
		CPUPercent:     snap.CPUPercent,
		MemUsedMB:      snap.MemUsedMB,
		MemTotalMB:     snap.MemTotalMB,
		RxMbps:         snap.RxMbps,
		TxMbps:         snap.TxMbps,
		ActiveSessions: snap.ActiveSessions,
	}
	s.mu.Lock()
	s.series = append(s.series, pt)
	if len(s.series) > 120 {
		s.series = s.series[len(s.series)-120:]
	}
	s.mu.Unlock()
	return pt
}

// ExecuteQuickAction runs a role-authorized mobile operator quick action.
func (s *Service) ExecuteQuickAction(actor, role string, req QuickActionRequest) (*QuickActionResult, error) {
	nowStr := s.cfg.Now().UTC().Format(time.RFC3339)
	switch req.Action {
	case "reboot":
		if err := s.cfg.RBAC.Authorize(role, secauth.PermSystemReboot); err != nil {
			return nil, err
		}
		if s.cfg.OnReboot != nil {
			if err := s.cfg.OnReboot(actor, req.Reason); err != nil {
				return nil, err
			}
		}
		s.PublishAlarm(AlarmEvent{
			Severity: "warning",
			Kind:     "reboot",
			Message:  fmt.Sprintf("System reboot initiated via Daimo by %s (%s)", actor, req.Reason),
		})
		return &QuickActionResult{Action: "reboot", Actor: actor, Detail: "graceful reboot scheduled", Timestamp: nowStr}, nil

	case "disable-user":
		if err := s.cfg.RBAC.Authorize(role, secauth.PermConfigWrite); err != nil {
			return nil, err
		}
		if strings.TrimSpace(req.TargetUser) == "" {
			return nil, errors.New("target_user is required")
		}
		if s.cfg.Sessions == nil {
			return nil, errors.New("session manager unavailable")
		}
		pkt := &ispengine.RADIUSPacket{Code: ispengine.CodeDisconnectRequest}
		pkt.AddString(ispengine.AttrUserName, req.TargetUser)
		ok, msg := s.cfg.Sessions.HandleCoAPacket(pkt)
		if !ok {
			return nil, fmt.Errorf("disconnect %q failed: %s", req.TargetUser, msg)
		}
		return &QuickActionResult{Action: "disable-user", Actor: actor, Detail: fmt.Sprintf("user %s disconnected (%s)", req.TargetUser, msg), Timestamp: nowStr}, nil

	case "set-bandwidth":
		if err := s.cfg.RBAC.Authorize(role, secauth.PermConfigWrite); err != nil {
			return nil, err
		}
		if strings.TrimSpace(req.TargetUser) == "" || req.UploadKbps <= 0 || req.DownloadKbps <= 0 {
			return nil, errors.New("target_user, upload_kbps > 0, and download_kbps > 0 are required")
		}
		if s.cfg.Sessions == nil {
			return nil, errors.New("session manager unavailable")
		}
		pkt := &ispengine.RADIUSPacket{Code: ispengine.CodeCoARequest}
		pkt.AddString(ispengine.AttrUserName, req.TargetUser)
		pkt.AddDaijiRateLimit(fmt.Sprintf("%d/%d", req.UploadKbps, req.DownloadKbps))
		ok, msg := s.cfg.Sessions.HandleCoAPacket(pkt)
		if !ok {
			return nil, fmt.Errorf("bandwidth CoA for %q failed: %s", req.TargetUser, msg)
		}
		return &QuickActionResult{
			Action:    "set-bandwidth",
			Actor:     actor,
			Detail:    fmt.Sprintf("user %s rate updated to %d/%d kbps", req.TargetUser, req.UploadKbps, req.DownloadKbps),
			Timestamp: nowStr,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported quick action %q", req.Action)
	}
}

// Handler returns the HTTP router for Daimo mobile API & push WebSocket endpoints.
func (s *Service) Handler() http.Handler {
	return s.mux
}

func (s *Service) routes() {
	s.mux.HandleFunc("/api/v1/daimo/login", s.handleLogin)
	s.mux.HandleFunc("/api/v1/daimo/pair-qr", s.handlePairQR)
	s.mux.HandleFunc("/api/v1/daimo/alarms", s.requirePerm(secauth.PermNetDiag, s.handleAlarms))
	s.mux.HandleFunc("/api/v1/daimo/push/register", s.requirePerm(secauth.PermNetDiag, s.handlePushRegister))
	s.mux.HandleFunc("/api/v1/daimo/quick-action", s.requirePerm(secauth.PermNetDiag, s.handleQuickAction))
	s.mux.HandleFunc("/api/v1/daimo/metrics", s.requirePerm(secauth.PermNetDiag, s.handleMetrics))
	s.mux.HandleFunc("/ws/daimo/alarms", s.requirePerm(secauth.PermNetDiag, s.handleWSAlarms))
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	now := s.cfg.Now()
	ip, _ := netip.ParseAddr(strings.Split(r.RemoteAddr, ":")[0])
	if ip.IsValid() && s.cfg.BruteForce.IsBanned(ip, now) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "temporarily blocked due to failed attempts"})
		return
	}
	var req struct {
		Mode     ConnectionMode `json:"mode"`
		Username string         `json:"username"`
		Password string         `json:"password"`
		TOTP     string         `json:"totp"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Mode != ModeLocal && req.Mode != ModeCloud {
		req.Mode = ModeLocal
	}
	acc, ok := s.cfg.Accounts[req.Username]
	if !ok || acc.Disabled || subtle.ConstantTimeCompare([]byte(acc.Password), []byte(req.Password)) != 1 {
		if ip.IsValid() {
			_ = s.cfg.BruteForce.RecordFailure(ip, now)
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	if acc.TOTPSecret != "" {
		if err := s.cfg.TOTP.Verify(acc.Username, acc.TOTPSecret, req.TOTP, now); err != nil {
			if ip.IsValid() {
				_ = s.cfg.BruteForce.RecordFailure(ip, now)
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid 2FA TOTP"})
			return
		}
	}
	tok, claims, err := s.cfg.Tokens.Issue(acc.Username, acc.Role, scopesForRole(acc.Role), 24*time.Hour, now)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      tok,
		"mode":       req.Mode,
		"device_id":  s.cfg.DeviceID,
		"brand":      sysinfo.BrandBanner,
		"role":       claims.Role,
		"expires_at": claims.ExpiresAt,
	})
}

func (s *Service) handlePairQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req struct {
		QRURI string `json:"qr_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	tok, mode, ep, claims, err := s.PairViaQR(req.QRURI)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":    tok,
		"mode":     mode,
		"endpoint": ep,
		"actor":    claims.Subject,
		"role":     claims.Role,
	})
}

func (s *Service) handleAlarms(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
	s.mu.RLock()
	out := append([]AlarmEvent(nil), s.alarms...)
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) handlePushRegister(w http.ResponseWriter, r *http.Request, claims *secauth.TokenClaims) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req struct {
		DeviceToken string `json:"device_token"`
		Platform    string `json:"platform"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.DeviceToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_token required"})
		return
	}
	reg := PushRegistration{
		DeviceToken: req.DeviceToken,
		Platform:    req.Platform,
		Actor:       claims.Subject,
		Registered:  s.cfg.Now().UTC().Format(time.RFC3339),
	}
	s.mu.Lock()
	s.pushTokens[req.DeviceToken] = reg
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, reg)
}

func (s *Service) handleQuickAction(w http.ResponseWriter, r *http.Request, claims *secauth.TokenClaims) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req QuickActionRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	res, err := s.ExecuteQuickAction(claims.Subject, claims.Role, req)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, secauth.ErrForbidden) {
			code = http.StatusForbidden
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Service) handleMetrics(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
	s.RecordMetricSample()
	s.mu.RLock()
	out := append([]MetricPoint(nil), s.series...)
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) handleWSAlarms(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
	ws, err := daiweb.UpgradeWebSocket(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ws.Close()

	ch := make(chan AlarmEvent, 16)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	backlog := append([]AlarmEvent(nil), s.alarms...)
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}()

	for _, ev := range backlog {
		if err := ws.WriteJSON(ev); err != nil {
			return
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := ws.ReadText(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-done:
			return
		case ev := <-ch:
			if err := ws.WriteJSON(ev); err != nil {
				return
			}
		}
	}
}

func (s *Service) requirePerm(perm secauth.Permission, next func(http.ResponseWriter, *http.Request, *secauth.TokenClaims)) http.HandlerFunc {
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

func computeQRSignature(secret []byte, q url.Values) string {
	h := hmac.New(sha256.New, secret)
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%s|%s|%s|%s",
		q.Get("v"), q.Get("dev"), q.Get("mac"), q.Get("mode"),
		q.Get("ep"), q.Get("role"), q.Get("actor"), q.Get("nonce"), q.Get("exp"))
	return hex.EncodeToString(h.Sum(nil))
}

func scopesForRole(role string) []secauth.Permission {
	switch role {
	case "superadmin":
		return []secauth.Permission{
			secauth.PermConfigRead, secauth.PermConfigWrite, secauth.PermConfigCommit,
			secauth.PermConfigReadSecrets, secauth.PermSystemUpdate, secauth.PermSystemReboot,
			secauth.PermSecurityKeys, secauth.PermAuditRead, secauth.PermNetDiag,
		}
	case "netadmin":
		return []secauth.Permission{secauth.PermConfigRead, secauth.PermConfigWrite, secauth.PermConfigCommit, secauth.PermNetDiag, secauth.PermAuditRead}
	case "operator":
		return []secauth.Permission{secauth.PermConfigRead, secauth.PermNetDiag}
	default:
		return []secauth.Permission{secauth.PermConfigRead}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
