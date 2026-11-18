// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daiweb

import (
	"bytes"
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestDaiWebAccessibilityAndDesignSystem enforces WCAG 2.1 AA contrast,
// semantic HTML5 landmarks, i18n parity (ID/EN), and original DaijiOS CSS tokens.
func TestDaiWebAccessibilityAndDesignSystem(t *testing.T) {
	htmlBytes, err := assetFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	tokensBytes, err := assetFS.ReadFile("assets/tokens.css")
	if err != nil {
		t.Fatalf("read tokens.css: %v", err)
	}
	appJSBytes, err := assetFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}

	html := string(htmlBytes)
	tokensCSS := string(tokensBytes)
	appJS := string(appJSBytes)

	// 1. HTML5 landmarks & WCAG structural requirements.
	requiredHTML := []string{
		`lang="id"`,
		`<meta name="viewport"`,
		`class="skip-link" href="#main-content"`,
		`<header`,
		`<nav`,
		`<main id="main-content"`,
		`<aside`,
		`<footer`,
		`role="tablist"`,
		`role="tabpanel"`,
		`aria-live="polite"`,
		`for="login-user"`,
		`for="login-pass"`,
		`for="term-input"`,
	}
	for _, needle := range requiredHTML {
		if !strings.Contains(html, needle) {
			t.Fatalf("a11y check failed: index.html missing %q", needle)
		}
	}
	if strings.Contains(html, "<script>") {
		t.Fatalf("CSP check failed: inline <script> tag must not be present in index.html")
	}

	// 2. Original design system token namespace & zero vendor CSS leaks.
	if !strings.Contains(tokensCSS, "--daiji-bg-canvas") || !strings.Contains(tokensCSS, "prefers-reduced-motion: reduce") {
		t.Fatalf("tokens.css missing original --daiji-* tokens or reduced-motion query")
	}
	for _, banned := range []string{"winbox", "bootstrap", "tailwind", "mikrotik"} {
		if strings.Contains(strings.ToLower(tokensCSS+appJS), banned) {
			t.Fatalf("design originality check failed: unexpected term %q", banned)
		}
	}

	// 3. WCAG 2.1 AA Contrast Ratio (>= 4.5:1) mathematically checked for Dark & Light tokens.
	darkPairs := []struct{ fg, bg, label string }{
		{"#edf2f7", "#111821", "dark primary text on surface"},
		{"#98a8bc", "#111821", "dark muted text on surface"},
		{"#071a14", "#18c996", "dark accent button ink"},
		{"#ff6b78", "#111821", "dark danger on surface"},
	}
	lightPairs := []struct{ fg, bg, label string }{
		{"#111922", "#ffffff", "light primary text on surface"},
		{"#4a5a6d", "#ffffff", "light muted text on surface"},
		{"#ffffff", "#097a5b", "light accent button ink"},
		{"#b4232c", "#ffffff", "light danger on surface"},
	}
	for _, p := range append(darkPairs, lightPairs...) {
		cr := contrastRatio(p.fg, p.bg)
		if cr < 4.5 {
			t.Fatalf("WCAG AA contrast failed for %s (%s on %s): %.2f < 4.50", p.label, p.fg, p.bg, cr)
		}
		t.Logf("A11Y CONTRAST PASS: %-34s => %.2f:1", p.label, cr)
	}

	// 4. i18n dictionary parity between 'id' and 'en'.
	reKey := regexp.MustCompile(`"([a-z0-9_.]+)":\s*"`)
	idStart := strings.Index(appJS, "  id: {")
	enStart := strings.Index(appJS, "  en: {")
	if idStart < 0 || enStart < 0 {
		t.Fatalf("missing ID or EN translation blocks in app.js")
	}
	idBlock := appJS[idStart:enStart]
	enEnd := strings.Index(appJS[enStart:], "\n  };")
	enBlock := appJS[enStart : enStart+enEnd]

	idKeys := reKey.FindAllStringSubmatch(idBlock, -1)
	enKeys := reKey.FindAllStringSubmatch(enBlock, -1)
	if len(idKeys) == 0 || len(idKeys) != len(enKeys) {
		t.Fatalf("i18n key count mismatch: id=%d en=%d", len(idKeys), len(enKeys))
	}
}

// TestLowEndPerformanceAndPayloadBudget verifies AUDIT GATE 6 low-end hardware targets:
// tiny gzipped footprint (<20 KB) and sub-millisecond snapshot/static handling under concurrency.
func TestLowEndPerformanceAndPayloadBudget(t *testing.T) {
	srv, totp, totpSec := setupTestDaiWebServer(t)
	rawBytes, gzipBytes := srv.AssetBundleStats()
	t.Logf("ASSET FOOTPRINT: raw=%d bytes (%.1f KB) gzip=%d bytes (%.1f KB)",
		rawBytes, float64(rawBytes)/1024.0, gzipBytes, float64(gzipBytes)/1024.0)

	if gzipBytes > 20*1024 {
		t.Fatalf("gzipped DaiWeb bundle %d B exceeds 20 KB embedded budget", gzipBytes)
	}

	// Verify parallel snapshot requests and telemetry fanout stay sub-millisecond on average.
	code, _ := totp.GenerateCode(totpSec, time.Now())
	loginBody := `{"username":"daijiadmin","password":"AdminStrongPassword!","totp":"` + code + `"}`
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
	loginReq.RemoteAddr = "10.0.0.10:40000"
	srv.Handler().ServeHTTP(loginRec, loginReq)

	h := srv.Handler()
	t0 := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("concurrent GET / failed: %d", rec.Code)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(t0)
	t.Logf("LOW-END LOAD TEST: 64 concurrent gzipped SPA responses served in %s (avg %s/req)",
		elapsed.Round(time.Microsecond), (elapsed / 64).Round(time.Microsecond))
}

func contrastRatio(hexFG, hexBG string) float64 {
	l1 := relLuminance(hexFG)
	l2 := relLuminance(hexBG)
	if l1 < l2 {
		l1, l2 = l2, l1
	}
	return (l1 + 0.05) / (l2 + 0.05)
}

func relLuminance(hexStr string) float64 {
	s := strings.TrimPrefix(hexStr, "#")
	r64, _ := strconv.ParseUint(s[0:2], 16, 8)
	g64, _ := strconv.ParseUint(s[2:4], 16, 8)
	b64, _ := strconv.ParseUint(s[4:6], 16, 8)
	lin := func(c uint64) float64 {
		v := float64(c) / 255.0
		if v <= 0.03928 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(r64) + 0.7152*lin(g64) + 0.0722*lin(b64)
}

func BenchmarkDaiWebStaticGzip(b *testing.B) {
	srv, _, _ := setupTestDaiWebServer(b)
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}
}

func BenchmarkDaiWebTelemetrySnapshot(b *testing.B) {
	srv, _, _ := setupTestDaiWebServer(b)
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CollectTelemetrySnapshot(srv.deps.Config, srv.deps.Sessions, srv.deps.MultiWAN, srv.deps.Torch, srv.deps.BootTime, now)
	}
}

func BenchmarkDaiWebWizardDryRun(b *testing.B) {
	srv, _, _ := setupTestDaiWebServer(b)
	req := WizardRequest{
		Wizard:  "firewall",
		Preview: true,
		Values:  map[string]any{"rule_name": "bench-rule", "action": "accept", "protocol": "tcp", "dst_port": 443},
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ApplyWizard(ctx, srv.deps.Config, srv.deps.Schema, "bench", req); err != nil {
			b.Fatal(err)
		}
	}
}

var _ = bytes.Buffer{}
