// SPDX-License-Identifier: Apache-2.0
package wlanplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kangpcode/daijios/pkg/schema"
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

func TestCampusACConfigValidatesAndSecretsIndexed(t *testing.T) {
	cs, err := schema.LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "campus-ac-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.ValidateJSON(raw); err != nil {
		t.Fatalf("campus-ac-config.json failed schema validation: %v", err)
	}
	cfg := loadCampusFixture(t)
	if err := ValidateAllSemantic(cfg); err != nil {
		t.Fatalf("ValidateAllSemantic failed: %v", err)
	}

	for _, secPath := range []string{
		"wireless.controller.onboarding_token",
		"wireless.ssids[0].radius_secret",
		"wireless.ssids[0].roaming.r0kh_key",
		"wireless.mesh.sae_password",
	} {
		if !cs.IsSecretPath(secPath) {
			t.Errorf("expected %q to be marked secret", secPath)
		}
	}
}

func TestWirelessSemanticRejectsBadEnterpriseMeshAndInjection(t *testing.T) {
	cfg := loadCampusFixture(t)
	w := cfg["wireless"].(map[string]any)
	w["ssids"].([]any)[0].(map[string]any)["radius_secret"] = ""
	w["ssids"].([]any)[0].(map[string]any)["ssid"] = "Evil\ninterface=eth0"
	w["aps"].([]any)[0].(map[string]any)["mesh_role"] = "node"

	err := ValidateWirelessSemantic(cfg)
	if err == nil {
		t.Fatal("expected semantic error, got nil")
	}
	msg := err.Error()
	for _, tok := range []string{"requires radius_server and radius_secret", "forbidden control/newline", "mesh_role='root'"} {
		if !strings.Contains(msg, tok) {
			t.Errorf("expected %q in errors: %s", tok, msg)
		}
	}
}
