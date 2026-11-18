// SPDX-License-Identifier: Apache-2.0
package fsatomic

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteJSONAtomicPermissionsAndOverwrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nested", "cfg.json")
	if err := WriteJSONAtomic(p, map[string]any{"k": "v1"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONAtomic(p, map[string]any{"k": "v2"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %v", info.Mode().Perm())
	}
}
