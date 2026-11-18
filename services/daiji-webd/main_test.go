// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestDaijiWebdCheckMode(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "schema", "daijios.schema.json")
	cfgPath := filepath.Join("..", "..", "schema", "examples", "default-config.json")
	var out, errBuf bytes.Buffer
	code := run([]string{
		"--store", t.TempDir(),
		"--schema", schemaPath,
		"--bootstrap", cfgPath,
		"--check",
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("daiji-webd --check exited %d stderr=%s stdout=%s", code, errBuf.String(), out.String())
	}
	if !strings.Contains(out.String(), "DaijiOS — Ecosystem by kangpcode") || !strings.Contains(out.String(), "DaiWeb bundle ready:") {
		t.Fatalf("unexpected daiji-webd stdout:\n%s", out.String())
	}
}
