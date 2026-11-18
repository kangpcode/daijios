// SPDX-License-Identifier: Apache-2.0
package ispplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kangpcode/daijios/pkg/schema"
)

func loadBNGFixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "isp-bng-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestBNGConfigSchemaAndSemanticAndSecrets(t *testing.T) {
	cs, err := schema.LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "isp-bng-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.ValidateJSON(raw); err != nil {
		t.Fatalf("isp-bng-config.json failed schema validation: %v", err)
	}
	cfg := loadBNGFixture(t)
	if err := ValidateAllSemantic(cfg); err != nil {
		t.Fatalf("ValidateAllSemantic failed: %v", err)
	}

	for _, secPath := range []string{
		"isp.radius.client.coa_secret",
		"isp.radius.client.servers[0].secret",
		"isp.pppoe.secrets[0].password",
		"telemetry.snmp.v3_users[0].auth_pass",
		"automation.webhooks[0].secret",
	} {
		if !cs.IsSecretPath(secPath) {
			t.Errorf("expected %q to be marked secret in SSoT schema", secPath)
		}
	}
}

func TestISPSemanticRejectsBadPoolProfileWANTableAndHook(t *testing.T) {
	cfg := loadBNGFixture(t)
	isp := cfg["isp"].(map[string]any)
	isp["pppoe"].(map[string]any)["servers"].([]any)[0].(map[string]any)["ip_pool"] = "missing-pool"
	isp["multi_wan"].(map[string]any)["wans"].([]any)[0].(map[string]any)["routing_table"] = float64(254)
	cfg["automation"].(map[string]any)["event_hooks"].([]any)[0].(map[string]any)["webhook_name"] = "missing-wh"

	err := ValidateISPSemantic(cfg)
	if err == nil {
		t.Fatal("expected semantic errors, got nil")
	}
	msg := err.Error()
	for _, tok := range []string{"missing-pool", "reserved (253-255)", "missing-wh"} {
		if !strings.Contains(msg, tok) {
			t.Errorf("expected %q in semantic errors: %s", tok, msg)
		}
	}
}
