// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDaijiClouddCheckMode(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--check"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("daiji-cloudd --check exited %d stderr=%s stdout=%s", code, errBuf.String(), out.String())
	}
	if !strings.Contains(out.String(), "DaijiOS — Ecosystem by kangpcode") || !strings.Contains(out.String(), "DaijiCloud ready") {
		t.Fatalf("unexpected daiji-cloudd stdout:\n%s", out.String())
	}
}
