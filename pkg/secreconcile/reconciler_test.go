// SPDX-License-Identifier: Apache-2.0
package secreconcile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kangpcode/daijios/pkg/netreconcile"
	"github.com/kangpcode/daijios/pkg/secplan"
)

func loadEdgeFixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "isp-edge-sec-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestPhase2SecurityReconciliationIdempotencyAndSecretMasking(t *testing.T) {
	rawCfg := loadEdgeFixture(t)
	sim := netreconcile.NewSimulatedDriver("eth0", "eth1", "br-lan")
	applier := &SecurityApplier{Driver: sim}

	if err := applier.Plan(context.Background(), rawCfg, rawCfg, nil); err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	if err := applier.Apply(context.Background(), rawCfg, nil); err != nil {
		t.Fatalf("first Apply failed: %v", err)
	}

	// Verify nftables output (filter, NAT, mangle, bridge L2 port security, brute-force sets).
	nft := sim.Files["/etc/nftables.d/daiji.nft"]
	for _, tok := range []string{
		"table inet daiji_filter",
		"set daiji_ban_v4",
		"set mgmt_trusted",
		"tcp flags & (fin|syn|rst|ack) == syn limit rate over 300/second",
		"table inet daiji_nat",
		"masquerade",
		"dnat to 192.168.10.50:80",
		"table inet daiji_mangle",
		"tcp option maxseg size set rt mtu",
		"table bridge daiji_l2sec",
	} {
		if !strings.Contains(nft, tok) {
			t.Errorf("nftables ruleset missing %q:\n%s", tok, nft)
		}
	}

	// Verify QoS tc commands (HTB root, IFB download CAKE, queue tree, simple queue PCQ).
	joined := strings.Join(sim.Commands, "\n")
	for _, cmdTok := range []string{
		"tc qdisc replace dev eth0 root handle 1: htb default 99",
		"ip link add name ifb-eth0 type ifb",
		"tc class replace dev eth0 parent 1:1 classid 1:10 htb rate 50000kbit ceil 100000kbit",
		"cake bandwidth 10000kbit dual-dsthost",
		"ip link add name wg0 type wireguard",
		"ip link add name vti0 type vti",
		"ip link add name eoip-dc type gretap local 203.0.113.2 remote 198.51.100.20 key 101",
		"sysctl -w net.ipv4.tcp_syncookies=1",
	} {
		if !strings.Contains(joined, cmdTok) {
			t.Errorf("missing expected command %q", cmdTok)
		}
	}

	// Verify SSH hardening.
	sshd := sim.Files["/etc/ssh/sshd_config.d/99-daiji.conf"]
	if !strings.Contains(sshd, "PermitRootLogin no") || !strings.Contains(sshd, "MaxAuthTries 3") {
		t.Fatalf("unexpected sshd hardening config:\n%s", sshd)
	}

	// Verify idempotency: second Apply must produce 0 extra service reloads or nft -f re-executions.
	sshReloads := sim.ServiceReloads["sshd"]
	swanReloads := sim.ServiceReloads["strongswan"]
	if err := applier.Apply(context.Background(), rawCfg, nil); err != nil {
		t.Fatalf("second idempotent Apply failed: %v", err)
	}
	if sim.ServiceReloads["sshd"] != sshReloads || sim.ServiceReloads["strongswan"] != swanReloads {
		t.Fatalf("unexpected service reload on idempotent Apply")
	}

	// Verify secret masking in VPN preview renderers.
	secCfg, _ := secplan.ParseConfig(rawCfg)
	wgPreview := RenderWireGuardConfig(secCfg.VPN.WireGuard[0], true)
	if strings.Contains(wgPreview, "AAAAAAAAAAA") || !strings.Contains(wgPreview, "***REDACTED***") {
		t.Fatalf("WireGuard private key leaked in preview:\n%s", wgPreview)
	}
	swanPreview := RenderSwanctlConfig(secCfg, true)
	if strings.Contains(swanPreview, "DaijiIPsecStrongKey2026!") || !strings.Contains(swanPreview, "***REDACTED***") {
		t.Fatalf("IPsec PSK leaked in preview:\n%s", swanPreview)
	}
}

func BenchmarkSecurityReconcileApply(b *testing.B) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "isp-edge-sec-config.json"))
	if err != nil {
		b.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		b.Fatal(err)
	}
	sim := netreconcile.NewSimulatedDriver("eth0", "eth1", "br-lan")
	applier := &SecurityApplier{Driver: sim}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := applier.Apply(context.Background(), cfg, nil); err != nil {
			b.Fatal(err)
		}
	}
}
