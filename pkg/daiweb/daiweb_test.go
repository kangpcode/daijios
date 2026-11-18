// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daiweb

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/ispengine"
	"github.com/kangpcode/daijios/pkg/ispplan"
	"github.com/kangpcode/daijios/pkg/isptools"
	"github.com/kangpcode/daijios/pkg/netplan"
	"github.com/kangpcode/daijios/pkg/schema"
	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/wlanctrl"
	"github.com/kangpcode/daijios/pkg/wlanplan"
)

func setupTestDaiWebServer(t testing.TB) (*Server, *secauth.TOTPVerifier, string) {
	t.Helper()
	schemaPath := filepath.Join("..", "..", "schema", "daijios.schema.json")
	cfgPath := filepath.Join("..", "..", "schema", "examples", "default-config.json")
	cs, err := schema.LoadFile(schemaPath)
	if err != nil {
		t.Fatalf("LoadFile schema: %v", err)
	}
	rawCfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile config: %v", err)
	}
	var boot map[string]any
	if err := json.Unmarshal(rawCfg, &boot); err != nil {
		t.Fatalf("Unmarshal config: %v", err)
	}

	mig := configengine.NewMigrator()
	_ = netplan.RegisterMigrations(mig)
	eng, err := configengine.Open(context.Background(), configengine.Options{
		BaseDir:           t.TempDir(),
		Schema:            cs,
		Migrator:          mig,
		SemanticValidator: wlanplan.ValidateAllSemantic,
		BootstrapConfig:   boot,
	})
	if err != nil {
		t.Fatalf("Open configengine: %v", err)
	}
	t.Cleanup(func() { eng.Close() })

	totp := secauth.NewTOTPVerifier(1)
	totpSec, err := secauth.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	bngRaw, _ := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "isp-bng-config.json"))
	var bngMap map[string]any
	_ = json.Unmarshal(bngRaw, &bngMap)
	bngCfg, _ := ispplan.ParseConfig(bngMap)

	sessions := ispengine.NewSessionManager(&bngCfg.ISP)
	_, _ = sessions.AuthenticatePPPoE("budi@fiber.daiji", "BudiPass2026!", "aa:bb:cc:11:22:33", time.Now())
	mwan := ispengine.NewMultiWANMonitor(bngCfg.ISP.MultiWAN)
	mwan.RecordProbe("wan-a", "1.1.1.1", 5.5, true)
	torch := isptools.NewTorchAggregator()
	torch.Ingest(isptools.FlowSample{Timestamp: time.Now(), SrcIP: "192.168.88.10", DstIP: "1.1.1.1", Protocol: "TCP", SrcPort: 41234, DstPort: 443, Bytes: 125000, Tx: true})

	const ztpSecret = "test-ac-secret-phase6"
	ac := wlanctrl.NewACController(wlanplan.WirelessBlock{
		Controller: wlanplan.ACControllerConfig{
			Enabled:         true,
			ACName:          "DaijiOS-AC",
			AutoAdoptPolicy: "zero-touch-token",
			OnboardingToken: ztpSecret,
			DefaultAPGroup:  "ap-group",
		},
		APGroups: []wlanplan.WLANAPGroup{{Name: "ap-group"}},
	}, nil)
	_, _ = ac.DiscoverAndAdopt(wlanctrl.AdoptRequest{
		MAC:    "aa:bb:cc:dd:ee:01",
		Serial: "SN-01",
		Model:  "DaijiAP-AX3000",
		IP:     "10.50.0.10",
		Token:  wlanctrl.ComputeOnboardingToken(ztpSecret, "aa:bb:cc:dd:ee:01", "SN-01"),
	})
	_ = ac.RecordHeartbeat("aa:bb:cc:dd:ee:01", 8)

	tm, err := secauth.NewTokenManager([]byte("daiweb-phase6-unit-test-secret"), time.Hour)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}

	srv, err := NewServer(Dependencies{
		Config:            eng,
		Schema:            cs,
		Sessions:          sessions,
		MultiWAN:          mwan,
		Torch:             torch,
		AC:                ac,
		Tokens:            tm,
		TOTP:              totp,
		TelemetryInterval: 40 * time.Millisecond,
		Accounts: map[string]Account{
			"daijiadmin": {Username: "daijiadmin", Role: "superadmin", Password: "AdminStrongPassword!", TOTPSecret: totpSec},
			"viewer":     {Username: "viewer", Role: "readonly", Password: "ViewerPassword!"},
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv, totp, totpSec
}

func TestDaiWebAssetsAuthSecurityAndWizards(t *testing.T) {
	srv, totp, totpSec := setupTestDaiWebServer(t)
	h := srv.Handler()

	// 1. Verify embedded HTML/CSS/JS security headers, ETag, and gzip delivery.
	for _, assetPath := range []string{"/", "/assets/tokens.css", "/assets/app.css", "/assets/app.js"} {
		req := httptest.NewRequest(http.MethodGet, assetPath, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s returned %d", assetPath, rec.Code)
		}
		if rec.Header().Get("Content-Encoding") != "gzip" {
			t.Fatalf("GET %s missing gzip compression", assetPath)
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'self'") {
			t.Fatalf("missing strict security headers on %s: %+v", assetPath, rec.Header())
		}
		gr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
		if err != nil {
			t.Fatalf("gzip decode %s: %v", assetPath, err)
		}
		body, _ := io.ReadAll(gr)
		_ = gr.Close()
		if len(body) == 0 {
			t.Fatalf("empty uncompressed body on %s", assetPath)
		}

		// ETag 304 conditional check.
		req304 := httptest.NewRequest(http.MethodGet, assetPath, nil)
		req304.Header.Set("If-None-Match", rec.Header().Get("ETag"))
		rec304 := httptest.NewRecorder()
		h.ServeHTTP(rec304, req304)
		if rec304.Code != http.StatusNotModified {
			t.Fatalf("expected 304 Not Modified for %s, got %d", assetPath, rec304.Code)
		}
	}

	// 2. Unauthenticated request is rejected.
	recUnauth := httptest.NewRecorder()
	h.ServeHTTP(recUnauth, httptest.NewRequest(http.MethodGet, "/api/v1/telemetry/snapshot", nil))
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthenticated, got %d", recUnauth.Code)
	}

	// 3. Brute-force guard trips after repeated invalid attempts.
	for i := 0; i < 6; i++ {
		badReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"daijiadmin","password":"wrong"}`))
		badReq.RemoteAddr = "198.51.100.99:44123"
		badRec := httptest.NewRecorder()
		h.ServeHTTP(badRec, badReq)
		if i == 5 && badRec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected brute-force 429 on 6th attempt, got %d", badRec.Code)
		}
	}

	// 4. Valid login with TOTP issues bearer token & HttpOnly SameSite=Strict cookie.
	code, err := totp.GenerateCode(totpSec, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	loginBody, _ := json.Marshal(map[string]string{
		"username": "daijiadmin",
		"password": "AdminStrongPassword!",
		"totp":     code,
	})
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginReq.RemoteAddr = "10.0.0.5:50000"
	loginRec := httptest.NewRecorder()
	h.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login failed %d: %s", loginRec.Code, loginRec.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &loginResp)
	if loginResp.Token == "" || !strings.Contains(loginRec.Header().Get("Set-Cookie"), "HttpOnly") {
		t.Fatalf("missing token or HttpOnly cookie: %s / %v", loginResp.Token, loginRec.Header())
	}

	// 5. Inspect Telemetry, Topology, and SSoT UI Schema endpoints.
	authGet := func(p string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Authorization", "Bearer "+loginResp.Token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s failed %d: %s", p, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	snapJSON := authGet("/api/v1/telemetry/snapshot")
	if !strings.Contains(snapJSON, "DaijiOS") || !strings.Contains(snapJSON, `"active_sessions":1`) {
		t.Fatalf("unexpected telemetry snapshot: %s", snapJSON)
	}
	topoJSON := authGet("/api/v1/topology")
	if !strings.Contains(topoJSON, "wan:wan-a") || !strings.Contains(topoJSON, "ap:ap-ddee01") {
		t.Fatalf("unexpected topology graph: %s", topoJSON)
	}
	uiJSON := authGet("/api/v1/ui-schema")
	if !strings.Contains(uiJSON, "system.hostname") {
		t.Fatalf("ui-schema missing system.hostname")
	}
	healthRec := httptest.NewRecorder()
	h.ServeHTTP(healthRec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if healthRec.Code != http.StatusOK || !strings.Contains(healthRec.Body.String(), "DaijiOS") {
		t.Fatalf("unexpected /api/v1/health: %d %s", healthRec.Code, healthRec.Body.String())
	}
	missRec := httptest.NewRecorder()
	h.ServeHTTP(missRec, httptest.NewRequest(http.MethodGet, "/assets/does-not-exist.js", nil))
	if missRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown asset, got %d", missRec.Code)
	}
	runCfgJSON := authGet("/api/v1/config/running")
	if !strings.Contains(runCfgJSON, "$argon2id$") {
		t.Fatalf("expected superadmin unredacted running config")
	}

	// 6. Test all 5 Guided Wizards (dry-run preview & WireGuard secret masking + live commit).
	wizardCases := []struct {
		name    string
		preview bool
		commit  bool
		values  map[string]any
	}{
		{"wan", true, false, map[string]any{"interface": "eth1", "address": "203.0.113.2/30", "gateway": "203.0.113.1", "nat": true}},
		{"lan", true, false, map[string]any{"bridge": "br-lan", "cidr": "192.168.88.1/24"}},
		{"pppoe", true, false, map[string]any{"server_name": "daiji-fiber", "interface": "eth0", "local_ip": "100.64.0.1", "pool_cidr": "100.64.0.0/20", "mtu": 1492}},
		{"vpn", true, false, map[string]any{"wg_name": "wg0", "listen_port": 51820, "tunnel_cidr": "10.99.0.1/24"}},
		{"firewall", false, true, map[string]any{"rule_name": "allow-https", "action": "accept", "protocol": "tcp", "dst_port": 443}},
	}
	for _, wc := range wizardCases {
		payload, _ := json.Marshal(WizardRequest{Wizard: wc.name, Preview: wc.preview, Commit: wc.commit, Values: wc.values})
		wReq := httptest.NewRequest(http.MethodPost, "/api/v1/wizards/apply", bytes.NewReader(payload))
		wReq.Header.Set("Authorization", "Bearer "+loginResp.Token)
		wRec := httptest.NewRecorder()
		h.ServeHTTP(wRec, wReq)
		if wRec.Code != http.StatusOK {
			t.Fatalf("wizard %s failed (%d): %s", wc.name, wRec.Code, wRec.Body.String())
		}
		if wc.name == "vpn" && !strings.Contains(wRec.Body.String(), "REDACTED") {
			t.Fatalf("expected secret masking in VPN wizard diff preview, got: %s", wRec.Body.String())
		}
		if wc.commit && !strings.Contains(wRec.Body.String(), `"committed":true`) {
			t.Fatalf("expected committed=true for %s, got: %s", wc.name, wRec.Body.String())
		}
	}

	// 7. Readonly user can read redacted config but is blocked from wizard mutations.
	roBody, _ := json.Marshal(map[string]string{"username": "viewer", "password": "ViewerPassword!"})
	roLoginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(roBody))
	roLoginReq.RemoteAddr = "10.0.0.6:50001"
	roRec := httptest.NewRecorder()
	h.ServeHTTP(roRec, roLoginReq)
	var roTok struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(roRec.Body.Bytes(), &roTok)
	roCfgReq := httptest.NewRequest(http.MethodGet, "/api/v1/config/running", nil)
	roCfgReq.Header.Set("Authorization", "Bearer "+roTok.Token)
	roCfgRec := httptest.NewRecorder()
	h.ServeHTTP(roCfgRec, roCfgReq)
	if roCfgRec.Code != http.StatusOK || strings.Contains(roCfgRec.Body.String(), "$argon2id$") {
		t.Fatalf("expected redacted running config for readonly, got %d %s", roCfgRec.Code, roCfgRec.Body.String())
	}
	denyReq := httptest.NewRequest(http.MethodPost, "/api/v1/wizards/apply", strings.NewReader(`{"wizard":"firewall","preview":true,"values":{}}`))
	denyReq.Header.Set("Authorization", "Bearer "+roTok.Token)
	denyRec := httptest.NewRecorder()
	h.ServeHTTP(denyRec, denyReq)
	if denyRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for readonly wizard call, got %d", denyRec.Code)
	}

	// 8. Logout revokes token immediately.
	outReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	outReq.Header.Set("Authorization", "Bearer "+loginResp.Token)
	outRec := httptest.NewRecorder()
	h.ServeHTTP(outRec, outReq)
	if outRec.Code != http.StatusOK {
		t.Fatalf("logout failed: %d", outRec.Code)
	}
	afterReq := httptest.NewRequest(http.MethodGet, "/api/v1/telemetry/snapshot", nil)
	afterReq.Header.Set("Authorization", "Bearer "+loginResp.Token)
	afterRec := httptest.NewRecorder()
	h.ServeHTTP(afterRec, afterReq)
	if afterRec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token should be 401, got %d", afterRec.Code)
	}
}

func TestDaiWebWebSocketTelemetryCLIAndCSWSH(t *testing.T) {
	srv, totp, totpSec := setupTestDaiWebServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	code, _ := totp.GenerateCode(totpSec, time.Now())
	loginBody, _ := json.Marshal(map[string]string{"username": "daijiadmin", "password": "AdminStrongPassword!", "totp": code})
	res, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("POST login: %v", err)
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(res.Body).Decode(&loginResp)
	_ = res.Body.Close()

	u, _ := url.Parse(ts.URL)

	// 1. Verify Cross-Origin WebSocket Hijacking (CSWSH) is rejected with 403.
	reqBadOrig, _ := http.NewRequest(http.MethodGet, ts.URL+"/ws/telemetry", nil)
	reqBadOrig.Header.Set("Authorization", "Bearer "+loginResp.Token)
	reqBadOrig.Header.Set("Origin", "https://evil.example.com")
	reqBadOrig.Header.Set("Connection", "Upgrade")
	reqBadOrig.Header.Set("Upgrade", "websocket")
	reqBadOrig.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	badResp, err := http.DefaultClient.Do(reqBadOrig)
	if err != nil || badResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 CSWSH rejection, got err=%v resp=%v", err, badResp)
	}
	_ = badResp.Body.Close()

	// 2. Dial /ws/telemetry & read real-time pushed JSON snapshot frame.
	connTel, brTel := dialTestWS(t, u.Host, "/ws/telemetry", loginResp.Token)
	defer connTel.Close()
	frame1, err := readTestServerWSFrame(brTel)
	if err != nil || !strings.Contains(frame1, `"hostname":"daiji-core-01"`) {
		t.Fatalf("expected telemetry WS snapshot, got err=%v frame=%s", err, frame1)
	}
	_ = writeTestClientWSClose(connTel)

	// 3. Dial /ws/cli & execute commands + Tab completion over WebSocket.
	connCLI, brCLI := dialTestWS(t, u.Host, "/ws/cli", loginResp.Token)
	defer connCLI.Close()
	welcome, err := readTestServerWSFrame(brCLI)
	if err != nil || !strings.Contains(welcome, "DaiWeb Terminal Ready") {
		t.Fatalf("unexpected CLI WS welcome: err=%v frame=%s", err, welcome)
	}
	if err := writeTestClientWSFrame(connCLI, `{"type":"complete","prefix":"sh"}`); err != nil {
		t.Fatalf("write complete: %v", err)
	}
	compResp, err := readTestServerWSFrame(brCLI)
	if err != nil || !strings.Contains(compResp, "show") {
		t.Fatalf("expected CLI WS tab-completion, got err=%v resp=%s", err, compResp)
	}
	if err := writeTestClientWSFrame(connCLI, `{"type":"exec","cmd":"enable"}`); err != nil {
		t.Fatalf("write enable: %v", err)
	}
	execResp, err := readTestServerWSFrame(brCLI)
	if err != nil || !strings.Contains(execResp, "privileged mode") || !strings.Contains(execResp, "#") {
		t.Fatalf("expected privileged prompt transition, got err=%v resp=%s", err, execResp)
	}
}

func dialTestWS(t *testing.T, host, wsPath, token string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", host, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", host, err)
	}
	var key [16]byte
	_, _ = rand.Read(key[:])
	req := "GET " + wsPath + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Origin: http://" + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key[:]) + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Authorization: Bearer " + token + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write WS upgrade: %v", err)
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "101 Switching Protocols") {
		t.Fatalf("WS handshake failed: %q err=%v", statusLine, err)
	}
	for {
		ln, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read WS headers: %v", err)
		}
		if ln == "\r\n" {
			break
		}
	}
	return conn, br
}

func readTestServerWSFrame(br *bufio.Reader) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return "", err
	}
	plen := int(hdr[1] & 0x7F)
	switch plen {
	case 126:
		var ext [2]byte
		_, _ = io.ReadFull(br, ext[:])
		plen = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		_, _ = io.ReadFull(br, ext[:])
		plen = int(binary.BigEndian.Uint64(ext[:]))
	}
	buf := make([]byte, plen)
	if _, err := io.ReadFull(br, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func writeTestClientWSFrame(conn net.Conn, msg string) error {
	payload := []byte(msg)
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	var hdr [10]byte
	hdr[0] = 0x81 // FIN + Text
	n := len(payload)
	hdrLen := 2
	if n < 126 {
		hdr[1] = 0x80 | byte(n)
	} else {
		hdr[1] = 0x80 | 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		hdrLen = 4
	}
	if _, err := conn.Write(hdr[:hdrLen]); err != nil {
		return err
	}
	if _, err := conn.Write(mask[:]); err != nil {
		return err
	}
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	_, err := conn.Write(masked)
	return err
}

func writeTestClientWSClose(conn net.Conn) error {
	var hdr [6]byte
	hdr[0] = 0x88
	hdr[1] = 0x80
	_, err := conn.Write(hdr[:])
	return err
}
