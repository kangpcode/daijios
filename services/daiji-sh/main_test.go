// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestDaijiShellBatchAndInteractive(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "schema", "daijios.schema.json")
	cfgPath := filepath.Join("..", "..", "schema", "examples", "default-config.json")
	storeDir := t.TempDir()

	// 1. Batch mode: initialize store, configure hostname, commit, show version as JSON.
	var out, errBuf bytes.Buffer
	code := run([]string{
		"--store", storeDir,
		"--schema", schemaPath,
		"--bootstrap", cfgPath,
		"--cmd", "enable; config; set system.hostname daiji-sh-host; commit via-shell; show version",
	}, strings.NewReader(""), &out, &errBuf)
	if code != 0 {
		t.Fatalf("batch exited %d stderr=%s stdout=%s", code, errBuf.String(), out.String())
	}
	if !strings.Contains(out.String(), "Committed") || !strings.Contains(out.String(), "DaijiOS") {
		t.Fatalf("unexpected batch stdout:\n%s", out.String())
	}

	// 2. Interactive REPL: verify boot banner, prompt progression, /tab completion, '?', and RBAC error tolerance.
	out.Reset()
	errBuf.Reset()
	replScript := strings.Join([]string{
		"show system.hostname",
		"?",
		"/tab sh",
		"enable",
		"config",
		"enter system",
		"/tab set motd",
		"top",
		"exit",
		"exit",
		"exit",
	}, "\n") + "\n"

	code = run([]string{
		"--store", storeDir,
		"--schema", schemaPath,
	}, strings.NewReader(replScript), &out, &errBuf)
	if code != 0 {
		t.Fatalf("interactive exited %d stderr=%s stdout=%s", code, errBuf.String(), out.String())
	}
	got := out.String()
	for _, want := range []string{
		"DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)",
		"daiji-sh-host",
		"daijiadmin@daiji-sh-host(cfg:system)#",
		"motd_banner",
		"Session closed.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("interactive output missing %q:\n%s", want, got)
		}
	}

	// 3. Readonly batch rejection on privileged escalation.
	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"--store", storeDir,
		"--schema", schemaPath,
		"--role", "readonly",
		"--cmd", "enable",
	}, strings.NewReader(""), &out, &errBuf)
	if code == 0 {
		t.Fatalf("expected non-zero exit when readonly calls enable in batch mode")
	}
}
