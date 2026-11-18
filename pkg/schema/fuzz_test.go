// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package schema

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzConfigJSONValidate fuzzes SSoT JSON Schema validation against arbitrary configuration payloads.
func FuzzConfigJSONValidate(f *testing.F) {
	cs, err := LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		f.Fatalf("LoadFile schema: %v", err)
	}
	defRaw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "default-config.json"))
	if err != nil {
		f.Fatalf("ReadFile default-config: %v", err)
	}
	f.Add(defRaw)
	f.Add([]byte(`{"schema_version":"1.0.0","system":{"hostname":"fuzz-box"}}`))
	f.Add([]byte(`{`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 16384 {
			return
		}
		_ = cs.ValidateJSON(raw)
	})
}
