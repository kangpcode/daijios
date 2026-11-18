// SPDX-License-Identifier: Apache-2.0
package daijiscript

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kangpcode/daijios/pkg/ispplan"
	"github.com/kangpcode/daijios/pkg/secauth"
)

func TestDaijiScriptConditionalPermissionsAndWebhookSigning(t *testing.T) {
	var gotSig string
	var gotBody []byte
	var gotEvent string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Daiji-Signature")
		gotEvent = r.Header.Get("X-Daiji-Event")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	secret := "DaijiWebhookHMAC2026!"
	var kicked string

	ae := NewAutomationEngine(ispplan.AutomationBlock{
		Scripts: []ispplan.DaijiScriptDef{
			{
				Name:        "failover-script",
				Permissions: []string{"read", "net"},
				TimeoutMS:   1000,
				Enabled:     true,
				Source: `let mode = "DOWN"
if $mode == "DOWN"
log "Triggering failover actions"
kick_pppoe "stale-user"
emit_webhook "noc" "wan-down"
else
log "WAN healthy"
endif`,
			},
			{
				Name:        "unprivileged-write",
				Permissions: []string{"read"},
				Enabled:     true,
				Source:      `set_config "system.hostname" "pwned"`,
			},
		},
		Schedules: []ispplan.ScriptSchedule{
			{Name: "every-min", ScriptName: "failover-script", IntervalSec: 60, Enabled: true},
		},
		EventHooks: []ispplan.EventHook{
			{Name: "h1", Event: "wan-down", ScriptName: "failover-script", Enabled: true},
		},
		Webhooks: []ispplan.WebhookTarget{
			{Name: "noc", URL: srv.URL, Secret: secret, TimeoutMS: 2000, RetryCount: 1, Enabled: true},
		},
	}, ScriptHostCallbacks{
		OnKickPPPoE: func(target string) error { kicked = target; return nil },
	}, &WebhookDispatcher{AllowLoopbackForTest: true})

	// Trigger event hook -> runs script -> kicks user -> sends HMAC-signed webhook.
	if err := ae.TriggerEvent(context.Background(), "wan-down", nil); err != nil {
		t.Fatalf("TriggerEvent failed: %v", err)
	}
	if kicked != "stale-user" {
		t.Fatalf("expected kick_pppoe 'stale-user', got %q", kicked)
	}
	if gotEvent != "wan-down" {
		t.Fatalf("expected X-Daiji-Event=wan-down, got %q", gotEvent)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(gotBody)
	wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != wantSig {
		t.Fatalf("webhook signature mismatch: got %q want %q", gotSig, wantSig)
	}

	// Permission enforcement check: unprivileged script cannot call set_config.
	_, err := RunScript(context.Background(), ae.scripts["unprivileged-write"], nil, ScriptHostCallbacks{})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}

	// SSRF protection blocks cloud metadata IP 169.254.169.254 even when loopback allowed for test.
	dispStrict := &WebhookDispatcher{}
	if err := dispStrict.Dispatch(context.Background(), ispplan.WebhookTarget{
		Name: "ssrf", URL: "http://169.254.169.254/latest/meta-data", Secret: secret, Enabled: true,
	}, "test", nil); !errors.Is(err, ErrWebhookSSRF) {
		t.Fatalf("expected ErrWebhookSSRF for metadata IP, got %v", err)
	}

	// Scheduler ticks once at t0, skips t0+30s, ticks again at t0+61s.
	t0 := time.Unix(1700000000, 0)
	res1, err := ae.Tick(context.Background(), t0)
	if err != nil || len(res1) != 1 {
		t.Fatalf("expected 1 scheduled execution at t0, got %d err=%v", len(res1), err)
	}
	res2, _ := ae.Tick(context.Background(), t0.Add(30*time.Second))
	if len(res2) != 0 {
		t.Fatalf("expected 0 executions before interval elapsed, got %d", len(res2))
	}
	res3, _ := ae.Tick(context.Background(), t0.Add(61*time.Second))
	if len(res3) != 1 {
		t.Fatalf("expected 1 execution after interval, got %d", len(res3))
	}
}

func TestRESTHandlerAuthenticationAndRBAC(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	tm, _ := secauth.NewTokenManager([]byte("DaijiRESTTestSecretKey2026!"), time.Hour)
	tok, _, _ := tm.Issue("noc-bot", "operator", []secauth.Permission{secauth.PermNetDiag}, time.Hour, now)

	handler := NewRESTHandler(APIDependencies{
		Tokens: tm,
		Now:    func() time.Time { return now },
	})

	// Unauthenticated /health succeeds; protected route returns 401.
	wHealth := httptest.NewRecorder()
	handler.ServeHTTP(wHealth, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if wHealth.Code != http.StatusOK || !strings.Contains(wHealth.Body.String(), "DaijiOS") {
		t.Fatalf("unexpected health response: %d %s", wHealth.Code, wHealth.Body.String())
	}

	wNoAuth := httptest.NewRecorder()
	handler.ServeHTTP(wNoAuth, httptest.NewRequest(http.MethodGet, "/api/v1/isp/sessions", nil))
	if wNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", wNoAuth.Code)
	}

	// Valid token with PermNetDiag accesses /api/v1/isp/sessions -> 200.
	reqOK := httptest.NewRequest(http.MethodGet, "/api/v1/isp/sessions", nil)
	reqOK.Header.Set("Authorization", "Bearer "+tok)
	wOK := httptest.NewRecorder()
	handler.ServeHTTP(wOK, reqOK)
	if wOK.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid scope, got %d: %s", wOK.Code, wOK.Body.String())
	}

	// Token lacking PermConfigRead gets 403 on /api/v1/config/running.
	reqDenied := httptest.NewRequest(http.MethodGet, "/api/v1/config/running", nil)
	reqDenied.Header.Set("Authorization", "Bearer "+tok)
	wDenied := httptest.NewRecorder()
	handler.ServeHTTP(wDenied, reqDenied)
	if wDenied.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for insufficient scope, got %d", wDenied.Code)
	}
}
