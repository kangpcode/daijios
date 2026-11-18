// SPDX-License-Identifier: Apache-2.0
package netplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/schema"
)

func loadJSONConfig(t *testing.T, relPath string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", relPath))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestISPCoreConfigPassesSchemaAndSemanticValidation(t *testing.T) {
	cs, err := schema.LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "isp-core-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.ValidateJSON(raw); err != nil {
		t.Fatalf("isp-core-config.json failed schema validation: %v", err)
	}
	cfg := loadJSONConfig(t, "schema/examples/isp-core-config.json")
	if err := ValidateSemantic(cfg); err != nil {
		t.Fatalf("isp-core-config.json failed semantic validation: %v", err)
	}

	// Check Phase 1 secrets are automatically recognized by SSoT schema.
	if !cs.IsSecretPath("interfaces.vrrp[0].auth_secret") {
		t.Fatal("expected vrrp auth_secret to be classified as secret")
	}
	if !cs.IsSecretPath("routing.bgp.neighbors[0].password") {
		t.Fatal("expected bgp neighbor password to be classified as secret")
	}
}

func TestSemanticRejectsInvalidTopologies(t *testing.T) {
	cfg := loadJSONConfig(t, "schema/examples/isp-core-config.json")

	// Inject multiple semantic faults: reserved VRF table 254, bad DHCP range, unknown BGP route-map.
	routing := cfg["routing"].(map[string]any)
	vrfs := routing["vrfs"].([]any)
	vrfs[0].(map[string]any)["table_id"] = float64(254)

	dhcp := cfg["ip"].(map[string]any)["dhcp"].(map[string]any)
	pools := dhcp["servers"].([]any)
	pools[0].(map[string]any)["range_start"] = "10.99.99.5"

	bgp := routing["bgp"].(map[string]any)
	bgp["neighbors"].([]any)[0].(map[string]any)["route_map_in"] = "NONEXISTENT-RM"

	err := ValidateSemantic(cfg)
	if err == nil {
		t.Fatal("expected semantic validation failure, got nil")
	}
	msg := err.Error()
	for _, tok := range []string{"reserved table_id 254", "outside subnet", "NONEXISTENT-RM"} {
		if !strings.Contains(msg, tok) {
			t.Errorf("expected semantic error to contain %q, got: %s", tok, msg)
		}
	}

	// Test VRRP duplicate VRID and bonding/bridge slave conflict and QinQ validation.
	cfg2 := loadJSONConfig(t, "schema/examples/isp-core-config.json")
	ifaces2 := cfg2["interfaces"].(map[string]any)
	vrrps := ifaces2["vrrp"].([]any)
	dupVRRP := map[string]any{
		"name": "vrrp-dup", "interface": "br-campus", "vrid": float64(50),
		"priority": float64(100), "virtual_ips": []any{"192.168.50.253/24"}, "enabled": true,
	}
	ifaces2["vrrp"] = append(vrrps, dupVRRP)
	vlans := ifaces2["vlans"].([]any)
	vlans[1].(map[string]any)["qinq_inner_vid"] = float64(0)
	bonds := ifaces2["bondings"].([]any)
	bonds[0].(map[string]any)["members"] = []any{"eth1", "eth3"} // eth3 also attached to br-campus

	err2 := ValidateSemantic(cfg2)
	if err2 == nil {
		t.Fatal("expected semantic conflict errors")
	}
	msg2 := err2.Error()
	for _, tok := range []string{"duplicate VRRP VRID 50", "requires qinq_inner_vid", "attached to both"} {
		if !strings.Contains(msg2, tok) {
			t.Errorf("expected error %q in: %s", tok, msg2)
		}
	}

	// Reject newline config injection in descriptions/secrets.
	cfg3 := loadJSONConfig(t, "schema/examples/isp-core-config.json")
	cfg3["routing"].(map[string]any)["bgp"].(map[string]any)["neighbors"].([]any)[0].(map[string]any)["description"] = "ok\nrouter bgp 99999"
	if err3 := ValidateSemantic(cfg3); err3 == nil || !strings.Contains(err3.Error(), "forbidden control/newline") {
		t.Fatalf("expected newline injection rejection, got %v", err3)
	}
}

func TestBackwardCompatibleMigration100To110(t *testing.T) {
	cs, err := schema.LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	v100 := map[string]any{
		"schema_version": "1.0.0",
		"system": map[string]any{
			"hostname":    "legacy-100",
			"timezone":    "UTC",
			"ntp_servers": []any{"pool.ntp.org"},
			"watchdog":    map[string]any{"enabled": true, "timeout_sec": 30, "max_failed_boots": 3},
		},
		"management": map[string]any{
			"ssh":    map[string]any{"enabled": true, "port": 22, "password_auth": false},
			"api":    map[string]any{"enabled": true, "port": 8443, "tls_enabled": true},
			"daiweb": map[string]any{"enabled": true, "port": 443},
		},
		"updates": map[string]any{
			"channel": "stable", "auto_check": true, "require_signature": true, "confirm_timeout_sec": 180,
		},
	}

	mig := configengine.NewMigrator()
	if err := RegisterMigrations(mig); err != nil {
		t.Fatal(err)
	}
	upgraded, steps, err := mig.Migrate(v100, "1.3.0")
	if err != nil {
		t.Fatalf("Migrate 1.0.0->1.3.0 failed: %v", err)
	}
	if len(steps) != 3 || steps[0] != "1.0.0->1.1.0" || steps[1] != "1.1.0->1.2.0" || steps[2] != "1.2.0->1.3.0" {
		t.Fatalf("unexpected migration steps: %v", steps)
	}
	if err := cs.Validate(upgraded); err != nil {
		t.Fatalf("migrated config failed 1.3.0 schema validation: %v", err)
	}
}
