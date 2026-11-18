// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kangpcode/daijios/pkg/daidiscovery"
)

func TestDaijiDeskDiscoverAndQR(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sec := "desk-test-hmac-secret"
	resp, err := daidiscovery.StartResponder(ctx, "127.0.0.1:0", daidiscovery.DeviceBeacon{
		DeviceID: "desk-node-01",
		MAC:      "02:64:6a:aa:11:22",
		Hostname: "daiji-lab-gw",
		IPv4:     "127.0.0.1",
		WebPort:  8443,
	}, []byte(sec))
	if err != nil {
		t.Fatalf("StartResponder: %v", err)
	}
	defer resp.Stop()

	var out, errBuf bytes.Buffer
	code := run([]string{
		"discover", "--target", resp.AddrStr, "--secret", sec, "--timeout", (100 * time.Millisecond).String(), "--json",
	}, &out, &errBuf)
	if code != 0 || !strings.Contains(out.String(), "daiji-lab-gw") {
		t.Fatalf("discover exited %d out=%s err=%s", code, out.String(), errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"qr-onboard", "--device", "gw-01", "--mode", "cloud", "--endpoint", "https://cloud.daijios.dev", "--secret", "qr-secret-key-min16",
	}, &out, &errBuf)
	if code != 0 || !strings.HasPrefix(out.String(), "daijios://onboard?") {
		t.Fatalf("qr-onboard exited %d out=%s err=%s", code, out.String(), errBuf.String())
	}
}
