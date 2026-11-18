// SPDX-License-Identifier: Apache-2.0
package secplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kangpcode/daijios/pkg/schema"
)

func loadEdgeSecFixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "isp-edge-sec-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestEdgeSecurityConfigValidatesAndSecretsIndexed(t *testing.T) {
	cs, err := schema.LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "isp-edge-sec-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.ValidateJSON(raw); err != nil {
		t.Fatalf("isp-edge-sec-config.json failed schema validation: %v", err)
	}
	cfg := loadEdgeSecFixture(t)
	if err := ValidateAllSemantic(cfg); err != nil {
		t.Fatalf("ValidateAllSemantic failed: %v", err)
	}

	// Verify WireGuard, IPsec, and L2TP secrets are automatically detected by SSoT schema.
	for _, secretPath := range []string{
		"vpn.wireguard[0].private_key",
		"vpn.wireguard[0].peers[0].preshared_key",
		"vpn.ipsec.tunnels[0].psk",
		"vpn.l2tp.ipsec_psk",
	} {
		if !cs.IsSecretPath(secretPath) {
			t.Errorf("expected %q to be classified as secret", secretPath)
		}
	}
}

func TestSecuritySemanticRejectsPPTPRootLoginAndNFTInjection(t *testing.T) {
	cfg := loadEdgeSecFixture(t)

	cfg["vpn"].(map[string]any)["pptp"] = map[string]any{
		"enabled": true, "legacy_acknowledged": false, "require_mppe128": true,
	}
	cfg["security"].(map[string]any)["ssh_hardening"].(map[string]any)["permit_root_login"] = true
	cfg["firewall"].(map[string]any)["filter_rules"].([]any)[0].(map[string]any)["comment"] = "bad; drop inet daiji_filter"
	cfg["qos"].(map[string]any)["queue_trees"].([]any)[0].(map[string]any)["rate_kbps"] = float64(500000)

	err := ValidateSecuritySemantic(cfg)
	if err == nil {
		t.Fatal("expected semantic rejection, got nil")
	}
	msg := err.Error()
	for _, tok := range []string{
		"legacy_acknowledged=true",
		"permit_root_login=true",
		"forbidden control or template delimiter",
		"exceeds ceil_kbps",
	} {
		if !strings.Contains(msg, tok) {
			t.Errorf("expected %q in semantic errors: %s", tok, msg)
		}
	}
}
