// SPDX-License-Identifier: Apache-2.0
package wlanreconcile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kangpcode/daijios/pkg/netreconcile"
	"github.com/kangpcode/daijios/pkg/wlanplan"
)

func loadCampusFixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "campus-ac-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestWLANReconcileIdempotencyAndSecretMasking(t *testing.T) {
	rawCfg := loadCampusFixture(t)
	sim := netreconcile.NewSimulatedDriver("eth0", "wlan0")
	applier := &WLANApplier{Driver: sim}

	if err := applier.Plan(context.Background(), rawCfg, rawCfg, nil); err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	if err := applier.Apply(context.Background(), rawCfg, nil); err != nil {
		t.Fatalf("first Apply failed: %v", err)
	}

	hapd := sim.Files["/etc/hostapd/daiji.conf"]
	for _, tok := range []string{
		"country_code=ID",
		"ssid=DaijiCorp-Secure",
		"wpa_key_mgmt=WPA-EAP-SHA256",
		"ieee80211w=2",
		"ieee80211r=1",
		"mobility_domain=4441",
		"rrm_neighbor_report=1",
		"bss_transition=1",
		"ap_isolate=1",
	} {
		if !strings.Contains(hapd, tok) {
			t.Errorf("hostapd.conf missing %q:\n%s", tok, hapd)
		}
	}

	mesh := sim.Files["/etc/wpa_supplicant/daiji-mesh.conf"]
	if !strings.Contains(mesh, "mode=5") || !strings.Contains(mesh, "DaijiMeshBackhaul") {
		t.Fatalf("mesh config unexpected:\n%s", mesh)
	}
	nft := sim.Files["/etc/nftables.d/daiji-wlan.nft"]
	if !strings.Contains(nft, "iifname \"br-guest\" ip daddr 10.0.0.0/8 counter drop") {
		t.Fatalf("guest isolation nftables missing:\n%s", nft)
	}

	// Second Apply must be idempotent (0 extra hostapd/mesh reloads).
	reloadsBefore := sim.ServiceReloads["hostapd"]
	if err := applier.Apply(context.Background(), rawCfg, nil); err != nil {
		t.Fatalf("second Apply failed: %v", err)
	}
	if sim.ServiceReloads["hostapd"] != reloadsBefore {
		t.Fatalf("expected 0 extra hostapd reloads on idempotent Apply")
	}

	// Preview redaction check.
	parsed, _ := wlanplan.ParseConfig(rawCfg)
	if prev := RenderHostapdConfig(&parsed.Wireless, true); strings.Contains(prev, "Daiji8021xRad2026!") || strings.Contains(prev, "0011223344556677") {
		t.Fatal("hostapd preview leaked RADIUS or r0kh secret")
	}
	if meshPrev := RenderMeshConfig(&parsed.Wireless, true); strings.Contains(meshPrev, "DaijiMeshSAEKey2026!") {
		t.Fatal("mesh preview leaked SAE password")
	}
}
