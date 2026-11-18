// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// daiji-desk provides DaiDesk & Daimo LAN/Cloud control commands:
// L2 MAC discovery (DJDP1), QR onboarding generation, and offline/cloud agent startup.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/kangpcode/daijios/pkg/daidiscovery"
	"github.com/kangpcode/daijios/pkg/daimo"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stdout, "%s\nUsage: daiji-desk <discover|qr-onboard|banner>\n", sysinfo.BrandBanner)
		return 0
	}
	sub := args[0]
	fs := flag.NewFlagSet("daiji-desk "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)

	target := fs.String("target", "255.255.255.255:56780", "UDP probe target host:port")
	secret := fs.String("secret", "", "optional HMAC secret for DJDP1 or QR onboarding")
	timeout := fs.Duration("timeout", 250*time.Millisecond, "discovery probe timeout")
	jsonOut := fs.Bool("json", false, "JSON output")

	deviceID := fs.String("device", "daiji-node-01", "device identifier")
	mac := fs.String("mac", "02:64:6a:00:00:01", "device MAC address")
	mode := fs.String("mode", "local", "connection mode: local | cloud")
	endpoint := fs.String("endpoint", "http://192.168.88.1:8443", "endpoint URL")
	actor := fs.String("actor", "daijiadmin", "operator username")
	role := fs.String("role", "superadmin", "RBAC role")
	ttl := fs.Duration("ttl", 5*time.Minute, "QR token validity TTL")

	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	switch sub {
	case "banner":
		fmt.Fprint(stdout, sysinfo.RenderBootBanner("daiji-desk", runtime.GOARCH, "A", sysinfo.Version, false))
		return 0

	case "discover":
		targets := strings.Split(*target, ",")
		beacons, err := daidiscovery.ProbeTargets(targets, []byte(*secret), *timeout)
		if err != nil {
			fmt.Fprintf(stderr, "discovery error: %v\n", err)
			return 1
		}
		if *jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(beacons)
			return 0
		}
		if len(beacons) == 0 {
			fmt.Fprintln(stdout, "(no DJDP1 devices discovered)")
			return 0
		}
		for _, b := range beacons {
			fmt.Fprintf(stdout, "%-18s %-20s %-16s %s (%s)\n", b.MAC, b.Hostname, b.IPv4, b.Version, b.Platform)
		}
		return 0

	case "qr-onboard":
		svc, err := daimo.NewService(daimo.Config{
			DeviceID: *deviceID,
			MAC:      *mac,
			QRSecret: []byte(*secret),
		})
		if err != nil {
			fmt.Fprintf(stderr, "init error: %v\n", err)
			return 1
		}
		uri, err := svc.GenerateOnboardingQR(daimo.ConnectionMode(*mode), *endpoint, *role, *actor, *ttl)
		if err != nil {
			fmt.Fprintf(stderr, "qr error: %v\n", err)
			return 1
		}
		if *jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			_ = enc.Encode(map[string]any{"qr_uri": uri, "mode": *mode, "brand": sysinfo.BrandBanner})
			return 0
		}
		fmt.Fprintln(stdout, uri)
		return 0

	default:
		_ = context.Background()
		fmt.Fprintf(stderr, "unknown daiji-desk subcommand %q\n", sub)
		return 2
	}
}
