// SPDX-License-Identifier: Apache-2.0
package schema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadCanonicalSchema(t *testing.T) *CompiledSchema {
	t.Helper()
	cs, err := LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		t.Fatalf("failed to load canonical schema: %v", err)
	}
	return cs
}

func TestCanonicalDefaultConfigValidates(t *testing.T) {
	cs := loadCanonicalSchema(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "default-config.json"))
	if err != nil {
		t.Fatalf("failed to read default-config.json: %v", err)
	}
	if err := cs.ValidateJSON(raw); err != nil {
		t.Fatalf("expected default-config.json to be valid, got: %v", err)
	}
}

func TestValidationRejectsInvalidFields(t *testing.T) {
	cs := loadCanonicalSchema(t)

	badJSON := []byte(`{
	  "schema_version": "not-semver",
	  "unknown_top_level": true,
	  "system": {
	    "hostname": "-bad-host-",
	    "timezone": "Asia/Jakarta",
	    "watchdog": {
	      "enabled": true,
	      "timeout_sec": 9999,
	      "max_failed_boots": 3
	    },
	    "users": [
	      {
	        "username": "a",
	        "role": "godmode",
	        "enabled": true
	      }
	    ]
	  },
	  "management": {
	    "ssh": { "enabled": true, "port": 70000, "password_auth": false },
	    "api": { "enabled": true, "port": 8443, "tls_enabled": true },
	    "daiweb": { "enabled": true, "port": 443 }
	  },
	  "interfaces": {
	    "physical": [
	      {
	        "name": "eth0",
	        "role": "wan",
	        "addresses": ["999.999.1.1/24"],
	        "enabled": true
	      }
	    ]
	  },
	  "updates": {
	    "channel": "nightly",
	    "auto_check": true,
	    "require_signature": true,
	    "confirm_timeout_sec": 10
	  }
	}`)

	err := cs.ValidateJSON(badJSON)
	if err == nil {
		t.Fatal("expected validation failure, got nil")
	}
	msg := err.Error()
	expectedTokens := []string{
		"schema_version",
		"unknown_top_level",
		"system.hostname",
		"timeout_sec",
		"users[0].role",
		"ssh.port",
		"addresses[0]",
		"updates.channel",
		"confirm_timeout_sec",
	}
	for _, tok := range expectedTokens {
		if !strings.Contains(msg, tok) {
			t.Errorf("expected error to mention %q, got: %s", tok, msg)
		}
	}
}

func TestSSoTProjectionsAndSecrets(t *testing.T) {
	cs := loadCanonicalSchema(t)

	cliSpecs, err := cs.ExtractCLISpec()
	if err != nil {
		t.Fatalf("ExtractCLISpec failed: %v", err)
	}
	if len(cliSpecs) < 15 {
		t.Fatalf("expected rich CLI projection (>=15 commands), got %d", len(cliSpecs))
	}

	uiFields, err := cs.ExtractUISchema()
	if err != nil {
		t.Fatalf("ExtractUISchema failed: %v", err)
	}
	if len(uiFields) < 15 {
		t.Fatalf("expected rich UI projection (>=15 fields), got %d", len(uiFields))
	}

	openapi := cs.ExtractOpenAPISpec()
	if openapi["openapi"] != "3.1.0" {
		t.Fatalf("expected OpenAPI 3.1.0, got %v", openapi["openapi"])
	}

	if !cs.IsSecretPath("system.users[0].password_hash") {
		t.Fatal("expected system.users[0].password_hash to be classified as secret")
	}
	if !cs.IsSecretPath("management.api.signing_secret") {
		t.Fatal("expected management.api.signing_secret to be classified as secret")
	}
	if cs.IsSecretPath("system.hostname") {
		t.Fatal("system.hostname must not be classified as secret")
	}
}

func BenchmarkValidateDefaultConfig(b *testing.B) {
	cs, err := LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		b.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "default-config.json"))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := cs.ValidateJSON(raw); err != nil {
			b.Fatal(err)
		}
	}
}
