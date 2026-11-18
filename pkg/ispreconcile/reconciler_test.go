// SPDX-License-Identifier: Apache-2.0
package ispreconcile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kangpcode/daijios/pkg/ispplan"
	"github.com/kangpcode/daijios/pkg/netreconcile"
)

func loadBNGFixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "isp-bng-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestISPReconcileIdempotencyAndSecretRedaction(t *testing.T) {
	rawCfg := loadBNGFixture(t)
	sim := netreconcile.NewSimulatedDriver("eth0", "eth1", "eth2", "eth3")
	applier := &ISPApplier{Driver: sim}

	if err := applier.Plan(context.Background(), rawCfg, rawCfg, nil); err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	if err := applier.Apply(context.Background(), rawCfg, nil); err != nil {
		t.Fatalf("first Apply failed: %v", err)
	}

	accel := sim.Files["/etc/accel-ppp.conf"]
	for _, tok := range []string{"pppoe", "ipoe", "radius", "dae-server=0.0.0.0:3799", "100.64.0.0/20,name=pool-pppoe-res"} {
		if !strings.Contains(accel, tok) {
			t.Errorf("accel-ppp.conf missing %q:\n%s", tok, accel)
		}
	}
	if !strings.Contains(sim.Files["/etc/snmp/snmpd.conf"], "SHA256") {
		t.Fatalf("snmpd.conf missing SNMPv3 SHA256:\n%s", sim.Files["/etc/snmp/snmpd.conf"])
	}
	if !strings.Contains(sim.Files["/etc/nftables.d/daiji-mwan.nft"], "jhash ip saddr . ip daddr") {
		t.Fatalf("daiji-mwan.nft missing PCC load balancing")
	}

	// Second Apply must be idempotent (0 extra daemon reloads).
	reloadsBefore := sim.ServiceReloads["accel-ppp"]
	if err := applier.Apply(context.Background(), rawCfg, nil); err != nil {
		t.Fatalf("second Apply failed: %v", err)
	}
	if sim.ServiceReloads["accel-ppp"] != reloadsBefore {
		t.Fatalf("expected 0 extra reloads on idempotent Apply")
	}

	// Preview redaction check.
	parsed, _ := ispplan.ParseConfig(rawCfg)
	if preview := RenderAccelPPP(parsed, true); strings.Contains(preview, "DaijiCoASecret2026!") {
		t.Fatal("CoA secret leaked in redacted accel-ppp preview")
	}
	if snmpPrev := RenderSNMPD(parsed, true); strings.Contains(snmpPrev, "DaijiSNMPAuth2026!") {
		t.Fatal("SNMPv3 auth pass leaked in redacted snmpd preview")
	}
}
