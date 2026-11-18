// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daiweb

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/daijicli"
	"github.com/kangpcode/daijios/pkg/ispengine"
	"github.com/kangpcode/daijios/pkg/isptools"
	"github.com/kangpcode/daijios/pkg/schema"
	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
	"github.com/kangpcode/daijios/pkg/wlanctrl"
)

//go:embed assets/*
var assetFS embed.FS

// Account holds one local operator login identity for DaiWeb.
type Account struct {
	Username   string
	Role       string
	Password   string // constant-time secret comparison or hashed secret
	TOTPSecret string // optional Base32 RFC 6238 secret
	Disabled   bool
}

// Dependencies configures a DaiWeb HTTP + WebSocket control & UI server.
type Dependencies struct {
	Config            *configengine.Engine
	Schema            *schema.CompiledSchema
	Sessions          *ispengine.SessionManager
	MultiWAN          *ispengine.MultiWANMonitor
	Torch             *isptools.TorchAggregator
	AC                *wlanctrl.ACController
	Tokens            *secauth.TokenManager
	RBAC              *secauth.RBACPolicy
	BruteForce        *secauth.BruteForceGuard
	TOTP              *secauth.TOTPVerifier
	Accounts          map[string]Account
	TelemetryInterval time.Duration
	BootTime          time.Time
	Now               func() time.Time
}

type cachedAsset struct {
	raw         []byte
	gzipped     []byte
	contentType string
	etag        string
}

// Server serves the DaiWeb SPA, authenticated REST APIs, and RFC 6455 WebSockets.
type Server struct {
	deps   Dependencies
	assets map[string]cachedAsset
	mux    *http.ServeMux
}

// NewServer constructs a hardened, embedded DaiWeb server ready to bind to net/http.
func NewServer(deps Dependencies) (*Server, error) {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.BootTime.IsZero() {
		deps.BootTime = deps.Now()
	}
	if deps.RBAC == nil {
		deps.RBAC = secauth.NewDefaultRBACPolicy(true)
	}
	if deps.BruteForce == nil {
		deps.BruteForce = secauth.NewBruteForceGuard(secauth.BruteForcePolicy{
			Enabled:     true,
			MaxAttempts: 5,
			Window:      5 * time.Minute,
			BanDuration: 15 * time.Minute,
		})
	}
	if deps.TOTP == nil {
		deps.TOTP = secauth.NewTOTPVerifier(1)
	}
	if deps.Tokens == nil {
		tm, err := secauth.NewTokenManager([]byte("daijios-default-signing-key-phase6"), 12*time.Hour)
		if err != nil {
			return nil, err
		}
		deps.Tokens = tm
	}
	if deps.TelemetryInterval <= 0 {
		deps.TelemetryInterval = 1 * time.Second
	}

	s := &Server{
		deps:   deps,
		assets: make(map[string]cachedAsset),
		mux:    http.NewServeMux(),
	}
	if err := s.preloadAssets(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

// Handler returns the HTTP handler wrapped with strict security headers.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self' ws: wss:; base-uri 'none'; frame-ancestors 'none'")
		s.mux.ServeHTTP(w, r)
	})
}

// AssetBundleStats returns total raw & gzipped payload bytes across all DaiWeb frontend assets.
func (s *Server) AssetBundleStats() (rawBytes, gzipBytes int) {
	for _, a := range s.assets {
		rawBytes += len(a.raw)
		gzipBytes += len(a.gzipped)
	}
	return rawBytes, gzipBytes
}

func (s *Server) preloadAssets() error {
	files := map[string]string{
		"assets/index.html": "text/html; charset=utf-8",
		"assets/tokens.css": "text/css; charset=utf-8",
		"assets/app.css":    "text/css; charset=utf-8",
		"assets/app.js":     "application/javascript; charset=utf-8",
	}
	for name, ct := range files {
		raw, err := assetFS.ReadFile(name)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if err != nil {
			return err
		}
		_, _ = gz.Write(raw)
		_ = gz.Close()

		sum := sha256.Sum256(raw)
		s.assets["/"+name] = cachedAsset{
			raw:         raw,
			gzipped:     buf.Bytes(),
			contentType: ct,
			etag:        `"` + hex.EncodeToString(sum[:8]) + `"`,
		}
	}
	return nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.serveAsset("/assets/index.html"))
	s.mux.HandleFunc("/assets/", func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(r.URL.Path)
		if _, ok := s.assets[clean]; !ok {
			http.NotFound(w, r)
			return
		}
		s.serveAsset(clean)(w, r)
	})

	s.mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"product": sysinfo.ProductName,
			"brand":   sysinfo.BrandBanner,
			"version": sysinfo.Version,
		})
	})

	s.mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/v1/auth/logout", s.handleLogout)

	s.mux.HandleFunc("/api/v1/telemetry/snapshot", s.requirePerm(secauth.PermNetDiag, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
		snap := CollectTelemetrySnapshot(s.deps.Config, s.deps.Sessions, s.deps.MultiWAN, s.deps.Torch, s.deps.BootTime, s.deps.Now())
		writeJSON(w, http.StatusOK, snap)
	}))

	s.mux.HandleFunc("/api/v1/topology", s.requirePerm(secauth.PermNetDiag, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
		writeJSON(w, http.StatusOK, BuildTopologyGraph(s.deps.Config, s.deps.MultiWAN, s.deps.AC))
	}))

	s.mux.HandleFunc("/api/v1/ui-schema", s.requirePerm(secauth.PermConfigRead, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
		if s.deps.Schema == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "schema unavailable"})
			return
		}
		fields, err := s.deps.Schema.ExtractUISchema()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, fields)
	}))

	s.mux.HandleFunc("/api/v1/config/running", s.requirePerm(secauth.PermConfigRead, func(w http.ResponseWriter, r *http.Request, claims *secauth.TokenClaims) {
		if s.deps.Config == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config engine unavailable"})
			return
		}
		redact := s.deps.RBAC.Authorize(claims.Role, secauth.PermConfigReadSecrets) != nil
		writeJSON(w, http.StatusOK, s.deps.Config.GetRunning(redact))
	}))

	s.mux.HandleFunc("/api/v1/wizards/apply", s.requirePerm(secauth.PermConfigWrite, s.handleWizardApply))

	s.mux.HandleFunc("/ws/telemetry", s.requirePerm(secauth.PermNetDiag, s.handleWSTelemetry))
	s.mux.HandleFunc("/ws/cli", s.requirePerm(secauth.PermNetDiag, s.handleWSCLI))
}

func (s *Server) serveAsset(key string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if key == "/assets/index.html" && r.URL.Path != "/" && r.URL.Path != "/index.html" && r.URL.Path != "/assets/index.html" {
			http.NotFound(w, r)
			return
		}
		a, ok := s.assets[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", a.contentType)
		w.Header().Set("ETag", a.etag)
		w.Header().Set("Vary", "Accept-Encoding")
		if strings.HasPrefix(key, "/assets/") && key != "/assets/index.html" {
			w.Header().Set("Cache-Control", "public, max-age=3600")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		if r.Header.Get("If-None-Match") == a.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(a.gzipped)
			return
		}
		_, _ = w.Write(a.raw)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	now := s.deps.Now()
	clientIP := parseRemoteIP(r.RemoteAddr)
	if clientIP.IsValid() && s.deps.BruteForce.IsBanned(clientIP, now) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed attempts; temporarily blocked"})
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON request"})
		return
	}

	acc, ok := s.deps.Accounts[req.Username]
	if !ok || acc.Disabled || subtle.ConstantTimeCompare([]byte(acc.Password), []byte(req.Password)) != 1 {
		if clientIP.IsValid() {
			_ = s.deps.BruteForce.RecordFailure(clientIP, now)
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	if acc.TOTPSecret != "" {
		if err := s.deps.TOTP.Verify(acc.Username, acc.TOTPSecret, req.TOTP, now); err != nil {
			if clientIP.IsValid() {
				_ = s.deps.BruteForce.RecordFailure(clientIP, now)
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid 2FA TOTP code"})
			return
		}
	}

	scopes := scopesForRole(acc.Role)
	tok, claims, err := s.deps.Tokens.Issue(acc.Username, acc.Role, scopes, 8*time.Hour, now)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "daiji_session",
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   8 * 3600,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      tok,
		"token_type": "Bearer",
		"role":       claims.Role,
		"scopes":     claims.Scopes,
		"expires_at": claims.ExpiresAt,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	if tok := extractToken(r); tok != "" {
		if claims, err := s.deps.Tokens.Verify(tok, secauth.PermConfigRead, s.deps.Now()); err == nil {
			s.deps.Tokens.Revoke(claims.TokenID, claims.ExpiresAt)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "daiji_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed_out"})
}

func (s *Server) handleWizardApply(w http.ResponseWriter, r *http.Request, claims *secauth.TokenClaims) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req WizardRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 32*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid wizard payload"})
		return
	}
	if req.Commit && !req.Preview {
		if err := s.deps.RBAC.Authorize(claims.Role, secauth.PermConfigCommit); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
	}
	res, err := ApplyWizard(r.Context(), s.deps.Config, s.deps.Schema, claims.Subject, req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleWSTelemetry(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
	if !verifyWSOrigin(r) {
		http.Error(w, "cross-origin websocket rejected", http.StatusForbidden)
		return
	}
	ws, err := UpgradeWebSocket(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ws.Close()
	wsCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Send initial snapshot immediately before entering periodic tick loop.
	_ = ws.WriteJSON(CollectTelemetrySnapshot(s.deps.Config, s.deps.Sessions, s.deps.MultiWAN, s.deps.Torch, s.deps.BootTime, s.deps.Now()))

	go func() {
		defer cancel()
		for {
			if _, err := ws.ReadText(); err != nil {
				return
			}
		}
	}()

	tk := time.NewTicker(s.deps.TelemetryInterval)
	defer tk.Stop()
	for {
		select {
		case <-wsCtx.Done():
			return
		case <-tk.C:
			snap := CollectTelemetrySnapshot(s.deps.Config, s.deps.Sessions, s.deps.MultiWAN, s.deps.Torch, s.deps.BootTime, s.deps.Now())
			if err := ws.WriteJSON(snap); err != nil {
				return
			}
		}
	}
}

func (s *Server) handleWSCLI(w http.ResponseWriter, r *http.Request, claims *secauth.TokenClaims) {
	if !verifyWSOrigin(r) {
		http.Error(w, "cross-origin websocket rejected", http.StatusForbidden)
		return
	}
	if s.deps.Schema == nil {
		http.Error(w, "schema unavailable", http.StatusServiceUnavailable)
		return
	}
	sess, err := daijicli.NewSession(claims.Subject, claims.Role, s.deps.Config, s.deps.Schema)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sess.Sessions = s.deps.Sessions
	sess.MultiWAN = s.deps.MultiWAN
	sess.Torch = s.deps.Torch

	ws, err := UpgradeWebSocket(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ws.Close()
	wsCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = ws.WriteJSON(map[string]any{
		"prompt": sess.Prompt(),
		"output": sysinfo.BrandBanner + " — DaiWeb Terminal Ready",
	})

	for {
		raw, err := ws.ReadText()
		if err != nil {
			return
		}
		var req struct {
			Type   string `json:"type"`
			Cmd    string `json:"cmd"`
			Prefix string `json:"prefix"`
		}
		if err := json.Unmarshal([]byte(raw), &req); err != nil {
			_ = ws.WriteJSON(map[string]any{"prompt": sess.Prompt(), "error": "invalid CLI JSON frame"})
			continue
		}
		if req.Type == "complete" {
			items := sess.Complete(req.Prefix)
			var lines []string
			for _, it := range items {
				lines = append(lines, "  "+it.Token+" — "+it.Description)
			}
			_ = ws.WriteJSON(map[string]any{
				"prompt":      sess.Prompt(),
				"completions": items,
				"output":      strings.Join(lines, "\n"),
			})
			continue
		}
		res, execErr := sess.Execute(wsCtx, req.Cmd)
		if execErr != nil {
			_ = ws.WriteJSON(map[string]any{"prompt": sess.Prompt(), "error": execErr.Error()})
			continue
		}
		_ = ws.WriteJSON(map[string]any{
			"prompt":         sess.Prompt(),
			"output":         res.Output,
			"structured":     res.Structured,
			"exit_requested": res.ExitRequested,
		})
		if res.ExitRequested {
			return
		}
	}
}

func (s *Server) requirePerm(perm secauth.Permission, next func(http.ResponseWriter, *http.Request, *secauth.TokenClaims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := extractToken(r)
		if tok == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		claims, err := s.deps.Tokens.Verify(tok, perm, s.deps.Now())
		if err != nil {
			code := http.StatusUnauthorized
			if strings.Contains(err.Error(), "scope") {
				code = http.StatusForbidden
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if err := s.deps.RBAC.Authorize(claims.Role, perm); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		next(w, r, claims)
	}
}

func extractToken(r *http.Request) string {
	if hdr := r.Header.Get("Authorization"); strings.HasPrefix(hdr, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
	}
	if ck, err := r.Cookie("daiji_session"); err == nil && ck.Value != "" {
		return ck.Value
	}
	return ""
}

func verifyWSOrigin(r *http.Request) bool {
	orig := strings.TrimSpace(r.Header.Get("Origin"))
	if orig == "" {
		return true
	}
	u, err := url.Parse(orig)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func parseRemoteIP(remoteAddr string) netip.Addr {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	addr, _ := netip.ParseAddr(host)
	return addr
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
	case "auditor":
		return []secauth.Permission{secauth.PermConfigRead, secauth.PermAuditRead, secauth.PermNetDiag}
	default:
		return []secauth.Permission{secauth.PermConfigRead}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
