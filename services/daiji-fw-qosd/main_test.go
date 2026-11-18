// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/schema"
)

func TestDaijiFWQoSDDryRunReconciliation(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "schema", "daijios.schema.json")
	cfgPath := filepath.Join("..", "..", "schema", "examples", "isp-edge-sec-config.json")
	storeDir := t.TempDir()

	cs, err := schema.LoadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var boot map[string]any
	if err := json.Unmarshal(raw, &boot); err != nil {
		t.Fatal(err)
	}
	eng, err := configengine.Open(context.Background(), configengine.Options{
		BaseDir:         storeDir,
		Schema:          cs,
		BootstrapConfig: boot,
	})
	if err != nil {
		t.Fatal(err)
	}
	eng.Close()

	var out, errBuf bytes.Buffer
	code := run([]string{
		"--store", storeDir,
		"--schema", schemaPath,
		"--dry-run=true",
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("daiji-fw-qosd exited %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "reconciled revision=rev-000001") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}
