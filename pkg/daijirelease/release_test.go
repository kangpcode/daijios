// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijirelease

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kangpcode/daijios/pkg/daidiscovery"
	"github.com/kangpcode/daijios/pkg/daijicloud"
)

func TestReleaseManifestAndSHA256Verification(t *testing.T) {
	dir := t.TempDir()
	samples := map[string][]byte{
		"daiji-ctl-linux-amd64":     []byte("binary-amd64-payload"),
		"daiji-portald-linux-arm64": []byte("binary-arm64-payload"),
	}
	for name, body := range samples {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o755); err != nil {
			t.Fatalf("write sample: %v", err)
		}
	}

	now := time.Date(2026, 11, 19, 6, 30, 0, 0, time.UTC)
	m, err := BuildManifest(dir, "1.2.0-lts", "go1.27.0", now)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if len(m.Artifacts) != 2 || m.LTS.Channel != "lts" {
		t.Fatalf("unexpected manifest: %+v", m)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := SignManifest(priv, m); err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	if err := VerifyManifest(pub, *m); err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}

	// Anti-tamper check on manifest metadata.
	tampered := *m
	tampered.Version = "9.9.9-fake"
	if err := VerifyManifest(pub, tampered); err == nil {
		t.Fatalf("expected signature failure on tampered version")
	}

	sumsPath := filepath.Join(dir, "SHA256SUMS")
	if err := WriteSHA256SUMS(sumsPath, m.Artifacts); err != nil {
		t.Fatalf("WriteSHA256SUMS: %v", err)
	}
	verifiedCount, err := VerifySHA256SUMS(dir, sumsPath)
	if err != nil || verifiedCount != 2 {
		t.Fatalf("VerifySHA256SUMS failed: count=%d err=%v", verifiedCount, err)
	}

	// Corrupt one artifact and confirm detection.
	_ = os.WriteFile(filepath.Join(dir, "daiji-ctl-linux-amd64"), []byte("corrupted"), 0o755)
	if _, err := VerifySHA256SUMS(dir, sumsPath); err == nil {
		t.Fatalf("expected checksum mismatch on mutated artifact")
	}
}

func TestPersistentKeyPEMSignAndPinnedVerify(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "rel.key.pem")
	pubPath := filepath.Join(dir, "rel.pub.pem")
	genPub, genPriv, err := GenerateSigningKeypairPEM(privPath, pubPath)
	if err != nil {
		t.Fatalf("GenerateSigningKeypairPEM: %v", err)
	}
	loadedPriv, err := LoadPrivateKeyPEM(privPath)
	if err != nil || !loadedPriv.Equal(genPriv) {
		t.Fatalf("LoadPrivateKeyPEM mismatch: %v", err)
	}
	loadedPub, err := LoadPublicKeyPEM(pubPath)
	if err != nil || !loadedPub.Equal(genPub) {
		t.Fatalf("LoadPublicKeyPEM mismatch: %v", err)
	}

	artDir := filepath.Join(dir, "dist")
	_ = os.MkdirAll(artDir, 0o755)
	_ = os.WriteFile(filepath.Join(artDir, "daiji-ctl-linux-amd64"), []byte("payload"), 0o755)
	m, err := BuildManifest(artDir, "1.2.0-lts", "go1.27.0", time.Unix(1795043731, 0))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if err := SignManifest(loadedPriv, m); err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	if err := VerifyManifest(loadedPub, *m); err != nil {
		t.Fatalf("VerifyManifest pinned pub: %v", err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyManifest(otherPub, *m); err == nil {
		t.Fatalf("expected VerifyManifest failure against wrong pinned public key")
	}
}

func TestSoak72HourStability(t *testing.T) {
	rep, err := RunSoakSimulation(SoakConfig{
		SimulatedHours: 72,
		OpsPerHour:     10,
	})
	if err != nil {
		t.Fatalf("RunSoakSimulation failed: %v", err)
	}
	if rep.TotalTransactions != 720 || rep.FailedOps != 0 {
		t.Fatalf("unexpected soak report: %+v", rep)
	}
	if rep.GoroutineDelta > 2 {
		t.Fatalf("potential goroutine leak: delta=%d", rep.GoroutineDelta)
	}
	t.Logf("72H SOAK SUMMARY: tx=%d elapsed_ms=%.2f rate=%.0f_ops/s p50=%.1fus p99=%.1fus max=%.1fus heap_start=%dKB heap_end=%dKB goroutine_delta=%d",
		rep.TotalTransactions, rep.ElapsedMs, rep.ThroughputOpsSec, rep.P50LatencyUs, rep.P99LatencyUs, rep.MaxLatencyUs, rep.StartHeapKB, rep.EndHeapKB, rep.GoroutineDelta)
}

// BenchmarkPacketEngineThroughputPPS measures DJDP1 L2 wire packet encode/decode rate (PPS).
func BenchmarkPacketEngineThroughputPPS(b *testing.B) {
	beacon := daidiscovery.DeviceBeacon{
		Type:      daidiscovery.TypeBeacon,
		Protocol:  "DJDP1",
		DeviceID:  "router-pps-01",
		MAC:       "02:64:6a:aa:bb:cc",
		Hostname:  "core-pop-jkt",
		Platform:  "DaijiOS",
		Version:   "1.2.0-lts",
		Arch:      "amd64",
		Interface: "sfp-sfpplus1",
		IPv4:      "10.0.0.1",
		WebPort:   8443,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wire, err := daidiscovery.EncodeWire(beacon)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := daidiscovery.DecodeWire(wire); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEcosystemControlPlaneLatency measures concurrent-safe telemetry + alert ingestion latency.
func BenchmarkEcosystemControlPlaneLatency(b *testing.B) {
	cp := daijicloud.NewControlPlane([]byte("bench-ztp-key"), []byte("bench-dr-key"), nil)
	_ = cp.CreateOrganization(daijicloud.Organization{ID: "org-b", Name: "Bench"})
	_ = cp.CreateSite(daijicloud.Site{ID: "site-b", OrgID: "org-b", Name: "POP"})
	tok, _ := cp.CreateZTPClaimToken("org-b", "site-b", "BENCH-SN", "core", time.Hour)
	dev, _ := cp.AdoptViaZTP(tok, "BENCH-SN", "02:64:6a:ff:00:01", "bench-core", "amd64", "1.2.0-lts")
	tel := daijicloud.DeviceTelemetry{CPUPercent: 44.2, MemPercent: 51.0, RxMbps: 980.0, TxMbps: 412.0, ActiveSessions: 800}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cp.IngestTelemetry(dev.ID, tel); err != nil {
			b.Fatal(err)
		}
	}
}
