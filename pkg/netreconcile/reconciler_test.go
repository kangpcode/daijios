// SPDX-License-Identifier: Apache-2.0
package netreconcile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/netplan"
	"github.com/kangpcode/daijios/pkg/schema"
)

func loadISPCoreFixture(t *testing.T) (*schema.CompiledSchema, map[string]any) {
	t.Helper()
	cs, err := schema.LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "isp-core-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cs, cfg
}

func TestFullPhase1ReconciliationIdempotencyAndCleanup(t *testing.T) {
	cs, ispCfg := loadISPCoreFixture(t)
	sim := NewSimulatedDriver("eth0", "eth1", "eth2", "eth3", "eth4")
	applier := &NetworkApplier{Driver: sim}

	eng, err := configengine.Open(context.Background(), configengine.Options{
		BaseDir:           t.TempDir(),
		Schema:            cs,
		Applier:           applier,
		SemanticValidator: netplan.ValidateSemantic,
		BootstrapConfig:   ispCfg,
	})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer eng.Close()

	// Trigger initial Apply directly through NetworkApplier to verify full reconciliation.
	if err := applier.Apply(context.Background(), ispCfg, nil); err != nil {
		t.Fatalf("first Apply failed: %v", err)
	}

	// Verify rendered daemon files exist and contain Phase 1 protocols.
	frr := sim.Files["/etc/frr/frr.conf"]
	for _, token := range []string{
		"vrf vrf-cust",
		"router ospf",
		"router ospf6",
		"router bgp 65100",
		"route-map RM-ISP-OUT out",
		"send-community both",
		"maximum-paths 4",
		"router isis DAIJI-CORE",
		"mpls ldp",
	} {
		if !strings.Contains(frr, token) {
			t.Errorf("frr.conf missing %q:\n%s", token, frr)
		}
	}
	if !strings.Contains(sim.Files["/etc/kea/kea-dhcp4.conf"], "192.168.50.0/24") {
		t.Fatal("kea-dhcp4.conf missing pool subnet")
	}
	if !strings.Contains(sim.Files["/etc/keepalived/keepalived.conf"], "virtual_router_id 50") {
		t.Fatal("keepalived.conf missing VRID 50")
	}
	if !strings.Contains(sim.Files["/etc/dnsmasq.d/daiji.conf"], "dnssec") {
		t.Fatal("dnsmasq.conf missing dnssec")
	}
	if !strings.Contains(sim.Files["/etc/chrony/chrony.conf"], "0.id.pool.ntp.org") {
		t.Fatal("chrony.conf missing NTP pool")
	}
	if !strings.Contains(sim.Files["/etc/lldpd.d/daiji.conf"], "tx-interval 30") {
		t.Fatal("lldpd.conf missing tx-interval")
	}
	if !strings.Contains(sim.Files["/etc/daiji/dhcp-relay.conf"], "10.255.0.10") {
		t.Fatal("dhcp-relay.conf missing upstream relay server")
	}

	// Verify idempotency: second Apply with identical config must NOT reload daemons or fail on duplicate links!
	reloadsAfterFirst := sim.ServiceReloads["frr"]
	if err := applier.Apply(context.Background(), ispCfg, nil); err != nil {
		t.Fatalf("second idempotent Apply failed: %v", err)
	}
	if sim.ServiceReloads["frr"] != reloadsAfterFirst {
		t.Fatalf("expected 0 extra frr reloads on idempotent Apply, got %d -> %d",
			reloadsAfterFirst, sim.ServiceReloads["frr"])
	}

	// Verify orphan deletion when removing a VLAN via transactional ConfigEngine Commit.
	if err := eng.SetCandidate("netadmin", mutateRemoveVLAN(t, ispCfg, "vlan100")); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Commit(context.Background(), "netadmin", "remove vlan100", configengine.CommitOptions{}); err != nil {
		t.Fatalf("Commit removing vlan100 failed: %v", err)
	}
	if sim.LinkExists("vlan100") {
		t.Fatal("expected deleted vlan100 to be removed from kernel links")
	}

	// Verify kernel commands for QinQ, ECMP, PBR, ARP, Storm Control, Port Security, and Mirroring.
	joinedCmds := strings.Join(sim.Commands, "\n")
	for _, cmdTok := range []string{
		"sysctl -w net.ipv4.ip_forward=1",
		"ip link add vrf-cust type vrf table 100",
		"ip link add name bond0 type bond mode 802.3ad lacp_rate fast",
		"proto 802.1ad id 2000",
		"bridge link set dev eth3 guard on",
		"bridge link set dev eth3 learning off",
		"action mirred egress mirror dev eth4",
		"ip neigh replace 10.10.0.2 lladdr aa:bb:cc:dd:ee:02 dev bond0 nud permanent",
		"ip rule add priority 100 from 172.16.100.0/24 table 100",
		"nexthop via 10.10.0.2 dev bond0 weight 2",
		"mstpctl setforcevers br-campus mstp",
	} {
		if !strings.Contains(joinedCmds, cmdTok) {
			t.Errorf("expected kernel command %q in simulated exec trace", cmdTok)
		}
	}
}

func TestPlanRejectsInvalidSemanticAndRIPRender(t *testing.T) {
	_, rawCfg := loadISPCoreFixture(t)
	rawCfg["routing"].(map[string]any)["rip"] = map[string]any{
		"enabled":            true,
		"version":            float64(2),
		"networks":           []any{"10.10.0.0/30"},
		"passive_interfaces": []any{"br-campus"},
		"redistribute":       []any{"connected"},
	}
	cfg, err := netplan.ParseConfig(rawCfg)
	if err != nil {
		t.Fatal(err)
	}
	frr := RenderFRRConfig(cfg, false)
	if !strings.Contains(frr, "router rip") || !strings.Contains(frr, "network 10.10.0.0/30") {
		t.Fatalf("expected RIP section in frr.conf:\n%s", frr)
	}

	sim := NewSimulatedDriver("eth0", "eth1", "eth2", "eth3", "eth4")
	applier := &NetworkApplier{Driver: sim}
	rawCfg["routing"].(map[string]any)["vrfs"].([]any)[0].(map[string]any)["table_id"] = float64(255)
	if err := applier.Plan(context.Background(), rawCfg, rawCfg, nil); err == nil {
		t.Fatal("expected Plan() to reject reserved VRF table_id 255")
	}
}

func TestSecretMaskingInPreviewRenderers(t *testing.T) {
	_, rawCfg := loadISPCoreFixture(t)
	cfg, err := netplan.ParseConfig(rawCfg)
	if err != nil {
		t.Fatal(err)
	}
	maskedFRR := RenderFRRConfig(cfg, true)
	if strings.Contains(maskedFRR, "bgpPeerSecret2026") || !strings.Contains(maskedFRR, "***REDACTED***") {
		t.Fatalf("BGP password was not masked in redacted FRR render:\n%s", maskedFRR)
	}
	maskedVRRP := RenderKeepalived(cfg, true)
	if strings.Contains(maskedVRRP, "daijiVrrpKey2026") || !strings.Contains(maskedVRRP, "***REDACTED***") {
		t.Fatalf("VRRP secret was not masked in redacted keepalived render:\n%s", maskedVRRP)
	}
}

func mutateRemoveVLAN(t *testing.T, orig map[string]any, name string) map[string]any {
	t.Helper()
	b, _ := json.Marshal(orig)
	var cp map[string]any
	_ = json.Unmarshal(b, &cp)
	ifaces := cp["interfaces"].(map[string]any)
	vlans := ifaces["vlans"].([]any)
	kept := make([]any, 0, len(vlans))
	for _, v := range vlans {
		if v.(map[string]any)["name"] != name {
			kept = append(kept, v)
		}
	}
	ifaces["vlans"] = kept
	return cp
}

func BenchmarkNetworkReconcileApply(b *testing.B) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "isp-core-config.json"))
	if err != nil {
		b.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		b.Fatal(err)
	}
	sim := NewSimulatedDriver("eth0", "eth1", "eth2", "eth3", "eth4")
	applier := &NetworkApplier{Driver: sim}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := applier.Apply(context.Background(), cfg, nil); err != nil {
			b.Fatal(err)
		}
	}
}
