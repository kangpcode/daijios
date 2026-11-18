// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daimo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
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
	"github.com/kangpcode/daijios/pkg/daiweb"
	"github.com/kangpcode/daijios/pkg/ispengine"
	"github.com/kangpcode/daijios/pkg/ispplan"
	"github.com/kangpcode/daijios/pkg/netplan"
	"github.com/kangpcode/daijios/pkg/schema"
	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/wlanplan"
)

func setupTestDaimoService(t testing.TB, nowFn func() time.Time) (*Service, *ispengine.SessionManager, *bool) {
	t.Helper()
	cs, err := schema.LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	rawCfg, _ := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "default-config.json"))
	var boot map[string]any
	_ = json.Unmarshal(rawCfg, &boot)

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

	bngRaw, _ := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "isp-bng-config.json"))
	var bngMap map[string]any
	_ = json.Unmarshal(bngRaw, &bngMap)
	bngCfg, _ := ispplan.ParseConfig(bngMap)
	sessions := ispengine.NewSessionManager(&bngCfg.ISP)
	if _, err := sessions.AuthenticatePPPoE("budi@fiber.daiji", "BudiPass2026!", "aa:bb:cc:11:22:33", time.Now()); err != nil {
		t.Fatalf("AuthenticatePPPoE: %v", err)
	}

	rebooted := false
	svc, err := NewService(Config{
		DeviceID: "daiji-mobile-gw-01",
		MAC:      "02:64:6a:77:88:99",
		Config:   eng,
		Sessions: sessions,
		QRSecret: []byte("daimo-test-qr-hmac-secret-key"),
		Accounts: map[string]daiweb.Account{
			"superop": {Username: "superop", Role: "superadmin", Password: "SuperSecretPassword!"},
			"netop":   {Username: "netop", Role: "netadmin", Password: "NetAdminPassword!"},
		},
		OnReboot: func(actor, reason string) error {
			rebooted = true
			return nil
		},
		Now: nowFn,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, sessions, &rebooted
}

func TestDaimoLoginQROnboardingAlarmsAndQuickActions(t *testing.T) {
	curTime := time.Unix(1700000000, 0).UTC()
	nowFn := func() time.Time { return curTime }
	svc, sessions, rebooted := setupTestDaimoService(t, nowFn)
	ts := httptest.NewServer(svc.Handler())
	defer ts.Close()

	// 1. Local & Cloud login flows.
	for _, mode := range []ConnectionMode{ModeLocal, ModeCloud} {
		body, _ := json.Marshal(map[string]any{"mode": mode, "username": "netop", "password": "NetAdminPassword!"})
		resp, err := http.Post(ts.URL+"/api/v1/daimo/login", "application/json", bytes.NewReader(body))
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("login %s failed: err=%v resp=%v", mode, err, resp)
		}
		_ = resp.Body.Close()
	}

	// 2. QR Onboarding: generate signed URI, verify no password inside, pair once, block replay & expiry.
	qrURI, err := svc.GenerateOnboardingQR(ModeCloud, "https://cloud.daijios.dev/relay/gw-01", "superadmin", "superop", 2*time.Minute)
	if err != nil {
		t.Fatalf("GenerateOnboardingQR: %v", err)
	}
	if strings.Contains(qrURI, "SuperSecretPassword") {
		t.Fatalf("QR URI leaked plaintext password")
	}

	// Tampered QR fails.
	if _, _, _, _, err := svc.PairViaQR(strings.Replace(qrURI, "superadmin", "readonly", 1)); !errors.Is(err, ErrInvalidQR) {
		t.Fatalf("expected ErrInvalidQR on tampering, got %v", err)
	}

	// Redeem via REST /api/v1/daimo/pair-qr.
	pairBody, _ := json.Marshal(map[string]string{"qr_uri": qrURI})
	pairRes, err := http.Post(ts.URL+"/api/v1/daimo/pair-qr", "application/json", bytes.NewReader(pairBody))
	if err != nil || pairRes.StatusCode != http.StatusOK {
		t.Fatalf("pair-qr failed: err=%v resp=%v", err, pairRes)
	}
	var paired struct {
		Token string `json:"token"`
		Mode  string `json:"mode"`
	}
	_ = json.NewDecoder(pairRes.Body).Decode(&paired)
	_ = pairRes.Body.Close()
	if paired.Token == "" || paired.Mode != "cloud" {
		t.Fatalf("unexpected pair response: %+v", paired)
	}

	// Replay same QR fails.
	if _, _, _, _, err := svc.PairViaQR(qrURI); !errors.Is(err, ErrReplayedQR) {
		t.Fatalf("expected ErrReplayedQR, got %v", err)
	}

	// Expired QR fails.
	expQR, _ := svc.GenerateOnboardingQR(ModeLocal, "http://192.168.88.1:8443", "netadmin", "netop", 10*time.Second)
	curTime = curTime.Add(30 * time.Second)
	if _, _, _, _, err := svc.PairViaQR(expQR); !errors.Is(err, ErrExpiredQR) {
		t.Fatalf("expected ErrExpiredQR, got %v", err)
	}

	// 3. Register Push token + stream Alarm via WebSocket.
	pushReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/daimo/push/register", strings.NewReader(`{"device_token":"fcm-pixel-9-xyz","platform":"android"}`))
	pushReq.Header.Set("Authorization", "Bearer "+paired.Token)
	pushResp, err := http.DefaultClient.Do(pushReq)
	if err != nil || pushResp.StatusCode != http.StatusOK {
		t.Fatalf("push register failed: err=%v resp=%v", err, pushResp)
	}
	_ = pushResp.Body.Close()

	u, _ := url.Parse(ts.URL)
	conn, br := dialAlarmsWS(t, u.Host, paired.Token)
	defer conn.Close()
	svc.PublishAlarm(AlarmEvent{Severity: "critical", Kind: "wan-down", Message: "WAN-1 link lost carrier"})
	wsFrame, err := readSingleWSFrame(br)
	if err != nil || !strings.Contains(wsFrame, "wan-down") {
		t.Fatalf("expected WS alarm notification, got err=%v frame=%s", err, wsFrame)
	}

	// 4. Quick Actions: RBAC check for reboot, CoA bandwidth change, and disable-user disconnect.
	if _, err := svc.ExecuteQuickAction("netop", "netadmin", QuickActionRequest{Action: "reboot"}); !errors.Is(err, secauth.ErrForbidden) {
		t.Fatalf("expected ErrForbidden when netadmin triggers reboot, got %v", err)
	}
	if _, err := svc.ExecuteQuickAction("netop", "netadmin", QuickActionRequest{
		Action: "set-bandwidth", TargetUser: "budi@fiber.daiji", UploadKbps: 10000, DownloadKbps: 20000,
	}); err != nil {
		t.Fatalf("set-bandwidth quick action failed: %v", err)
	}
	curSess := sessions.ListSessions()
	if len(curSess) != 1 || curSess[0].DownloadKbps != 20000 {
		t.Fatalf("expected live CoA download=20000, got %+v", curSess)
	}
	if _, err := svc.ExecuteQuickAction("netop", "netadmin", QuickActionRequest{Action: "disable-user", TargetUser: "budi@fiber.daiji"}); err != nil {
		t.Fatalf("disable-user failed: %v", err)
	}
	if len(sessions.ListSessions()) != 0 {
		t.Fatalf("expected session disconnected after disable-user")
	}

	// Superadmin reboot succeeds over HTTP API.
	rbReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/daimo/quick-action", strings.NewReader(`{"action":"reboot","reason":"firmware maintenance"}`))
	rbReq.Header.Set("Authorization", "Bearer "+paired.Token)
	rbResp, err := http.DefaultClient.Do(rbReq)
	if err != nil || rbResp.StatusCode != http.StatusOK || !*rebooted {
		t.Fatalf("reboot HTTP failed: err=%v resp=%v rebooted=%v", err, rbResp, *rebooted)
	}
	_ = rbResp.Body.Close()

	// 5. Monitoring Graph endpoint returns samples.
	mReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/daimo/metrics", nil)
	mReq.Header.Set("Authorization", "Bearer "+paired.Token)
	mResp, err := http.DefaultClient.Do(mReq)
	if err != nil || mResp.StatusCode != http.StatusOK {
		t.Fatalf("metrics HTTP failed: err=%v resp=%v", err, mResp)
	}
	mBody, _ := io.ReadAll(mResp.Body)
	_ = mResp.Body.Close()
	if !strings.Contains(string(mBody), "cpu_percent") {
		t.Fatalf("unexpected metrics payload: %s", string(mBody))
	}
}

func dialAlarmsWS(t *testing.T, host, token string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", host, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", host, err)
	}
	var key [16]byte
	_, _ = rand.Read(key[:])
	req := "GET /ws/daimo/alarms HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key[:]) + "\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer " + token + "\r\n\r\n"
	_, _ = conn.Write([]byte(req))
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "101 Switching Protocols") {
		t.Fatalf("WS upgrade failed: %q err=%v", line, err)
	}
	for {
		hdr, err := br.ReadString('\n')
		if err != nil || hdr == "\r\n" {
			break
		}
	}
	return conn, br
}

func readSingleWSFrame(br *bufio.Reader) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return "", err
	}
	plen := int(hdr[1] & 0x7F)
	if plen == 126 {
		var ext [2]byte
		_, _ = io.ReadFull(br, ext[:])
		plen = int(binary.BigEndian.Uint16(ext[:]))
	}
	buf := make([]byte, plen)
	if _, err := io.ReadFull(br, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func BenchmarkDaimoQRGenerateAndPair(b *testing.B) {
	now := time.Unix(1700000000, 0).UTC()
	svc, _, _ := setupTestDaimoService(b, func() time.Time { return now })
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qr, err := svc.GenerateOnboardingQR(ModeLocal, "http://192.168.88.1:8443", "netadmin", "op", 5*time.Minute)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, _, _, err := svc.PairViaQR(qr); err != nil {
			b.Fatal(err)
		}
	}
}
