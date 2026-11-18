// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package ispreconcile

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/ispplan"
	"github.com/kangpcode/daijios/pkg/netreconcile"
)

// ISPApplier implements configengine.Applier for Phase 3 ISP services & telemetry.
type ISPApplier struct {
	Driver netreconcile.SystemDriver
}

func (a *ISPApplier) Plan(_ context.Context, _, target map[string]any, _ []configengine.DiffEntry) error {
	return ispplan.ValidateAllSemantic(target)
}

func (a *ISPApplier) Apply(ctx context.Context, target map[string]any, _ []configengine.DiffEntry) error {
	cfg, err := ispplan.ParseConfig(target)
	if err != nil {
		return err
	}

	type fileTarget struct {
		service string
		path    string
		content []byte
		mode    os.FileMode
		active  bool
	}
	targets := []fileTarget{
		{
			service: "accel-ppp",
			path:    "/etc/accel-ppp.conf",
			content: []byte(RenderAccelPPP(cfg, false)),
			mode:    0o600,
			active:  len(cfg.ISP.PPPoE.Servers) > 0 || len(cfg.ISP.IPoE.Servers) > 0,
		},
		{
			service: "freeradius",
			path:    "/etc/freeradius/3.0/clients.conf",
			content: []byte(RenderFreeRADIUSClients(cfg, false)),
			mode:    0o600,
			active:  cfg.ISP.RADIUS.Server.Enabled,
		},
		{
			service: "snmpd",
			path:    "/etc/snmp/snmpd.conf",
			content: []byte(RenderSNMPD(cfg, false)),
			mode:    0o600,
			active:  cfg.Telemetry.SNMP.Enabled,
		},
		{
			service: "rsyslog",
			path:    "/etc/rsyslog.d/99-daiji.conf",
			content: []byte(RenderRsyslog(cfg)),
			mode:    0o644,
			active:  cfg.Telemetry.Syslog.Enabled,
		},
		{
			service: "softflowd",
			path:    "/etc/daiji/netflow.conf",
			content: []byte(RenderNetFlow(cfg)),
			mode:    0o644,
			active:  cfg.Telemetry.NetFlow.Enabled,
		},
	}

	for _, t := range targets {
		changed, err := a.Driver.WriteFile(t.path, t.content, t.mode)
		if err != nil {
			return err
		}
		if changed && t.active {
			if err := a.Driver.ReloadService(ctx, t.service); err != nil {
				return err
			}
		}
	}

	// Reconcile Multi-WAN per-WAN routing tables and PCC/Hotspot nftables.
	if cfg.ISP.MultiWAN.Enabled {
		for _, w := range cfg.ISP.MultiWAN.WANs {
			if !w.Enabled || w.RoutingTable == 0 {
				continue
			}
			_ = a.Driver.Exec(ctx, "ip", "route", "replace", "default", "via", w.Gateway, "dev", w.Interface,
				"table", strconv.FormatUint(uint64(w.RoutingTable), 10))
			if cfg.ISP.MultiWAN.Mode == "load-balance-pcc" {
				mark := strconv.Itoa(100 + int(w.RoutingTable))
				_ = a.Driver.Exec(ctx, "ip", "rule", "del", "fwmark", mark)
				if err := a.Driver.Exec(ctx, "ip", "rule", "add", "fwmark", mark,
					"table", strconv.FormatUint(uint64(w.RoutingTable), 10)); err != nil {
					return err
				}
			}
		}
	}

	mwanNFT := []byte(RenderMultiWANNFT(cfg))
	if changed, err := a.Driver.WriteFile("/etc/nftables.d/daiji-mwan.nft", mwanNFT, 0o600); err != nil {
		return err
	} else if changed {
		if err := a.Driver.Exec(ctx, "nft", "-f", "/etc/nftables.d/daiji-mwan.nft"); err != nil {
			return fmt.Errorf("apply mwan/hotspot nftables: %w", err)
		}
	}

	return nil
}
