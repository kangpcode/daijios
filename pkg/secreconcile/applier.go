// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package secreconcile

import (
	"context"
	"fmt"
	"strconv"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/netreconcile"
	"github.com/kangpcode/daijios/pkg/secplan"
)

// SecurityApplier reconciles Phase 2 Firewall (nftables), QoS (tc), VPNs, and OS Hardening.
type SecurityApplier struct {
	Driver netreconcile.SystemDriver
}

func (a *SecurityApplier) Plan(_ context.Context, _, target map[string]any, _ []configengine.DiffEntry) error {
	if err := secplan.ValidateAllSemantic(target); err != nil {
		return err
	}
	cfg, err := secplan.ParseConfig(target)
	if err != nil {
		return err
	}
	if _, err := RenderDPIRulesJSON(cfg); err != nil {
		return err
	}
	_ = RenderNFTables(cfg)
	_ = BuildQoSCommands(cfg)
	return nil
}

func (a *SecurityApplier) Apply(ctx context.Context, target map[string]any, _ []configengine.DiffEntry) error {
	cfg, err := secplan.ParseConfig(target)
	if err != nil {
		return err
	}

	// 1. Kernel security & conntrack sysctls.
	for _, knob := range HardeningSysctls(cfg) {
		if err := a.Driver.Exec(ctx, "sysctl", "-w", knob); err != nil {
			return err
		}
	}

	// 2. Atomic nftables ruleset load.
	nftBody := []byte(RenderNFTables(cfg))
	nftChanged, err := a.Driver.WriteFile("/etc/nftables.d/daiji.nft", nftBody, 0o600)
	if err != nil {
		return err
	}
	if nftChanged {
		if err := a.Driver.Exec(ctx, "nft", "-f", "/etc/nftables.d/daiji.nft"); err != nil {
			return err
		}
	}

	// 3. L7 DPI rule table.
	dpiBytes, err := RenderDPIRulesJSON(cfg)
	if err != nil {
		return err
	}
	if changed, err := a.Driver.WriteFile("/etc/daiji/dpi-rules.json", dpiBytes, 0o600); err != nil {
		return err
	} else if changed && cfg.Firewall.L7DPI.Enabled {
		_ = a.Driver.ReloadService(ctx, "daiji-dpid")
	}

	// 4. QoS IFB setup + tc commands.
	for _, qi := range cfg.QoS.Interfaces {
		if qi.DownloadKbps > 0 {
			ifb := "ifb-" + qi.Interface
			if len(ifb) > 15 {
				ifb = ifb[:15]
			}
			if !a.Driver.LinkExists(ifb) {
				if err := a.Driver.Exec(ctx, "ip", "link", "add", "name", ifb, "type", "ifb"); err != nil {
					return err
				}
			}
			if err := a.Driver.Exec(ctx, "ip", "link", "set", "dev", ifb, "up"); err != nil {
				return err
			}
		}
	}
	for _, tcArgs := range BuildQoSCommands(cfg) {
		if err := a.Driver.Exec(ctx, "tc", tcArgs...); err != nil {
			return err
		}
	}

	// 5. VPN tunnels (WireGuard, IPsec/VTI, OpenVPN, L2TP, SSTP, EoIP).
	if err := a.reconcileVPNs(ctx, cfg); err != nil {
		return err
	}

	// 6. SSH daemon hardening.
	sshChanged, err := a.Driver.WriteFile("/etc/ssh/sshd_config.d/99-daiji.conf", []byte(RenderSSHDHardening(cfg)), 0o644)
	if err != nil {
		return err
	}
	if sshChanged {
		if err := a.Driver.ReloadService(ctx, "sshd"); err != nil {
			return err
		}
	}
	return nil
}

func (a *SecurityApplier) reconcileVPNs(ctx context.Context, cfg *secplan.SecurityConfig) error {
	for _, wg := range cfg.VPN.WireGuard {
		if !wg.Enabled {
			continue
		}
		if !a.Driver.LinkExists(wg.Interface) {
			if err := a.Driver.Exec(ctx, "ip", "link", "add", "name", wg.Interface, "type", "wireguard"); err != nil {
				return err
			}
		}
		confPath := fmt.Sprintf("/etc/wireguard/%s.conf", wg.Interface)
		changed, err := a.Driver.WriteFile(confPath, []byte(RenderWireGuardConfig(wg, false)), 0o600)
		if err != nil {
			return err
		}
		if changed {
			if err := a.Driver.Exec(ctx, "wg", "setconf", wg.Interface, confPath); err != nil {
				return err
			}
		}
		if wg.MTU > 0 {
			_ = a.Driver.Exec(ctx, "ip", "link", "set", "dev", wg.Interface, "mtu", strconv.Itoa(wg.MTU))
		}
		_ = a.Driver.Exec(ctx, "ip", "link", "set", "dev", wg.Interface, "up")
		for _, cidr := range wg.Addresses {
			_ = a.Driver.Exec(ctx, "ip", "addr", "replace", cidr, "dev", wg.Interface)
		}
	}

	swanChanged, err := a.Driver.WriteFile("/etc/swanctl/conf.d/daiji.conf", []byte(RenderSwanctlConfig(cfg, false)), 0o600)
	if err != nil {
		return err
	}
	if cfg.VPN.IPsec.Enabled {
		for _, tun := range cfg.VPN.IPsec.Tunnels {
			if tun.Enabled && tun.VTIInterface != "" && !a.Driver.LinkExists(tun.VTIInterface) {
				if err := a.Driver.Exec(ctx, "ip", "link", "add", "name", tun.VTIInterface, "type", "vti",
					"local", tun.LocalIP, "remote", tun.RemoteIP, "key", strconv.FormatUint(uint64(tun.VTIKey), 10)); err != nil {
					return err
				}
				_ = a.Driver.Exec(ctx, "ip", "link", "set", "dev", tun.VTIInterface, "up")
			}
		}
		if swanChanged {
			if err := a.Driver.ReloadService(ctx, "strongswan"); err != nil {
				return err
			}
		}
	}

	for _, ov := range cfg.VPN.OpenVPN {
		if !ov.Enabled {
			continue
		}
		p := fmt.Sprintf("/etc/openvpn/%s/%s.conf", ov.Role, ov.Name)
		if changed, err := a.Driver.WriteFile(p, []byte(RenderOpenVPNConfig(ov)), 0o600); err != nil {
			return err
		} else if changed {
			_ = a.Driver.ReloadService(ctx, "openvpn-"+ov.Name)
		}
	}

	if l2tpChg, err := a.Driver.WriteFile("/etc/xl2tpd/xl2tpd.conf", []byte(RenderL2TPConfig(cfg)), 0o600); err != nil {
		return err
	} else if l2tpChg && cfg.VPN.L2TP.Enabled {
		_ = a.Driver.ReloadService(ctx, "xl2tpd")
	}

	if sstpChg, err := a.Driver.WriteFile("/etc/daiji/sstp.conf", []byte(RenderSSTPConfig(cfg)), 0o600); err != nil {
		return err
	} else if sstpChg && cfg.VPN.SSTP.Enabled {
		_ = a.Driver.ReloadService(ctx, "sstpd")
	}

	for _, eo := range cfg.VPN.EoIP {
		if !eo.Enabled {
			continue
		}
		if !a.Driver.LinkExists(eo.Name) {
			if err := a.Driver.Exec(ctx, "ip", "link", "add", "name", eo.Name, "type", "gretap",
				"local", eo.LocalIP, "remote", eo.RemoteIP, "key", strconv.Itoa(eo.TunnelID)); err != nil {
				return err
			}
		}
		if eo.MTU > 0 {
			_ = a.Driver.Exec(ctx, "ip", "link", "set", "dev", eo.Name, "mtu", strconv.Itoa(eo.MTU))
		}
		if eo.Bridge != "" {
			_ = a.Driver.Exec(ctx, "ip", "link", "set", "dev", eo.Name, "master", eo.Bridge)
		}
		_ = a.Driver.Exec(ctx, "ip", "link", "set", "dev", eo.Name, "up")
	}

	return nil
}
