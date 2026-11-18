// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package netreconcile

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/netplan"
)

// NetworkApplier implements configengine.Applier to translate validated DaijiOS
// networking configurations idempotently into Linux kernel & control-plane state.
type NetworkApplier struct {
	Driver SystemDriver
}

// Plan checks cross-field semantic invariants and verifies config generation before Apply.
func (a *NetworkApplier) Plan(_ context.Context, _, target map[string]any, _ []configengine.DiffEntry) error {
	if err := netplan.ValidateSemantic(target); err != nil {
		return err
	}
	cfg, err := netplan.ParseConfig(target)
	if err != nil {
		return err
	}
	if _, err := RenderKeaDHCP4(cfg); err != nil {
		return fmt.Errorf("render kea-dhcp4: %w", err)
	}
	_ = RenderFRRConfig(cfg, false)
	return nil
}

// Apply reconciles kernel interfaces, sysctl, switching, VRFs, routes, and control daemons idempotently.
func (a *NetworkApplier) Apply(ctx context.Context, target map[string]any, _ []configengine.DiffEntry) error {
	cfg, err := netplan.ParseConfig(target)
	if err != nil {
		return err
	}
	prev, err := a.Driver.LoadManagedState()
	if err != nil {
		return err
	}
	next := &ManagedState{}

	if err := a.reconcileSysctls(ctx, cfg); err != nil {
		return err
	}
	if err := a.reconcileVRFs(ctx, cfg, prev, next); err != nil {
		return err
	}
	if err := a.reconcilePhysical(ctx, cfg); err != nil {
		return err
	}
	if err := a.reconcileBondings(ctx, cfg, prev, next); err != nil {
		return err
	}
	if err := a.reconcileVLANs(ctx, cfg, prev, next); err != nil {
		return err
	}
	if err := a.reconcileVethAndTunnels(ctx, cfg, prev, next); err != nil {
		return err
	}
	if err := a.reconcileBridgesAndSwitching(ctx, cfg, prev, next); err != nil {
		return err
	}
	if err := a.reconcileARPAndRouting(ctx, cfg, prev, next); err != nil {
		return err
	}
	if err := a.reconcileDaemons(ctx, cfg); err != nil {
		return err
	}
	return a.Driver.SaveManagedState(next)
}

func (a *NetworkApplier) reconcileSysctls(ctx context.Context, cfg *netplan.NetworkConfig) error {
	v4 := "1"
	if cfg.IP.IPv4Forward != nil && !*cfg.IP.IPv4Forward {
		v4 = "0"
	}
	v6 := "1"
	if cfg.IP.IPv6Forward != nil && !*cfg.IP.IPv6Forward {
		v6 = "0"
	}
	rp := "2"
	if cfg.IP.RPFilter != nil {
		rp = strconv.Itoa(*cfg.IP.RPFilter)
	}
	proxyARP := "0"
	if cfg.IP.ARPProxy {
		proxyARP = "1"
	}
	knobs := []string{
		"net.ipv4.ip_forward=" + v4,
		"net.ipv6.conf.all.forwarding=" + v6,
		"net.ipv4.conf.all.rp_filter=" + rp,
		"net.ipv4.conf.all.proxy_arp=" + proxyARP,
	}
	if cfg.Routing.MPLS.Enabled && cfg.Routing.MPLS.LabelRangeMax > 0 {
		knobs = append(knobs, fmt.Sprintf("net.mpls.platform_labels=%d", cfg.Routing.MPLS.LabelRangeMax))
	}
	for _, k := range knobs {
		if err := a.Driver.Exec(ctx, "sysctl", "-w", k); err != nil {
			return err
		}
	}
	return nil
}

func (a *NetworkApplier) reconcileVRFs(ctx context.Context, cfg *netplan.NetworkConfig, prev, next *ManagedState) error {
	desired := make(map[string]bool)
	for _, v := range cfg.Routing.VRFs {
		desired[v.Name] = true
		next.VRFs = append(next.VRFs, v.Name)
		if !a.Driver.LinkExists(v.Name) {
			if err := a.Driver.Exec(ctx, "ip", "link", "add", v.Name, "type", "vrf", "table", strconv.FormatUint(uint64(v.TableID), 10)); err != nil {
				return err
			}
		}
		if err := a.Driver.Exec(ctx, "ip", "link", "set", "dev", v.Name, "up"); err != nil {
			return err
		}
	}
	for _, old := range prev.VRFs {
		if !desired[old] && a.Driver.LinkExists(old) {
			if err := a.Driver.Exec(ctx, "ip", "link", "del", old); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *NetworkApplier) reconcilePhysical(ctx context.Context, cfg *netplan.NetworkConfig) error {
	for _, p := range cfg.Interfaces.Physical {
		if err := a.applyCommonLinkAndIP(ctx, p.Name, p.MTU, p.VRF, p.Addresses, p.Enabled); err != nil {
			return err
		}
		if p.MACOverride != "" {
			if err := a.Driver.Exec(ctx, "ip", "link", "set", "dev", p.Name, "address", p.MACOverride); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *NetworkApplier) reconcileBondings(ctx context.Context, cfg *netplan.NetworkConfig, prev, next *ManagedState) error {
	desired := make(map[string]bool)
	for _, b := range cfg.Interfaces.Bondings {
		desired[b.Name] = true
		next.Bondings = append(next.Bondings, b.Name)
		if !a.Driver.LinkExists(b.Name) {
			args := []string{"link", "add", "name", b.Name, "type", "bond", "mode", b.Mode}
			if b.Mode == "802.3ad" && b.LACPRate != "" {
				args = append(args, "lacp_rate", b.LACPRate)
			}
			if b.XmitHashPolicy != "" {
				args = append(args, "xmit_hash_policy", b.XmitHashPolicy)
			}
			if err := a.Driver.Exec(ctx, "ip", args...); err != nil {
				return err
			}
		}
		for _, member := range b.Members {
			_ = a.Driver.Exec(ctx, "ip", "link", "set", "dev", member, "down")
			if err := a.Driver.Exec(ctx, "ip", "link", "set", "dev", member, "master", b.Name); err != nil {
				return err
			}
			if err := a.Driver.Exec(ctx, "ip", "link", "set", "dev", member, "up"); err != nil {
				return err
			}
		}
		if err := a.applyCommonLinkAndIP(ctx, b.Name, b.MTU, b.VRF, b.Addresses, b.Enabled); err != nil {
			return err
		}
	}
	return a.deleteRemovedLinks(ctx, prev.Bondings, desired)
}

func (a *NetworkApplier) reconcileVLANs(ctx context.Context, cfg *netplan.NetworkConfig, prev, next *ManagedState) error {
	desired := make(map[string]bool)
	for _, v := range cfg.Interfaces.VLANs {
		desired[v.Name] = true
		next.VLANs = append(next.VLANs, v.Name)
		proto := "802.1Q"
		if v.Protocol == "802.1ad" {
			proto = "802.1ad"
		}
		if !a.Driver.LinkExists(v.Name) {
			if v.Protocol == "802.1ad" && v.QinQInnerVID > 0 {
				outerName := v.Name + ".s"
				if !a.Driver.LinkExists(outerName) {
					if err := a.Driver.Exec(ctx, "ip", "link", "add", "link", v.Parent, "name", outerName,
						"type", "vlan", "proto", "802.1ad", "id", strconv.Itoa(v.VID)); err != nil {
						return err
					}
				}
				_ = a.Driver.Exec(ctx, "ip", "link", "set", "dev", outerName, "up")
				if err := a.Driver.Exec(ctx, "ip", "link", "add", "link", outerName, "name", v.Name,
					"type", "vlan", "proto", "802.1Q", "id", strconv.Itoa(v.QinQInnerVID)); err != nil {
					return err
				}
			} else {
				if err := a.Driver.Exec(ctx, "ip", "link", "add", "link", v.Parent, "name", v.Name,
					"type", "vlan", "proto", proto, "id", strconv.Itoa(v.VID)); err != nil {
					return err
				}
			}
		}
		if err := a.applyCommonLinkAndIP(ctx, v.Name, v.MTU, v.VRF, v.Addresses, v.Enabled); err != nil {
			return err
		}
	}
	return a.deleteRemovedLinks(ctx, prev.VLANs, desired)
}

func (a *NetworkApplier) reconcileVethAndTunnels(ctx context.Context, cfg *netplan.NetworkConfig, prev, next *ManagedState) error {
	desiredVeth := make(map[string]bool)
	for _, ve := range cfg.Interfaces.Veth {
		desiredVeth[ve.Name] = true
		next.Veths = append(next.Veths, ve.Name)
		if !a.Driver.LinkExists(ve.Name) {
			if err := a.Driver.Exec(ctx, "ip", "link", "add", "name", ve.Name, "type", "veth", "peer", "name", ve.Peer); err != nil {
				return err
			}
		}
		if err := a.applyCommonLinkAndIP(ctx, ve.Name, ve.MTU, ve.VRF, ve.Addresses, ve.Enabled); err != nil {
			return err
		}
	}
	if err := a.deleteRemovedLinks(ctx, prev.Veths, desiredVeth); err != nil {
		return err
	}

	desiredTun := make(map[string]bool)
	for _, t := range cfg.Interfaces.Tunnels {
		desiredTun[t.Name] = true
		next.Tunnels = append(next.Tunnels, t.Name)
		if !a.Driver.LinkExists(t.Name) {
			args := []string{"link", "add", "name", t.Name, "type", t.Mode}
			if t.Mode == "vxlan" {
				args = append(args, "id", strconv.FormatUint(uint64(t.VNI), 10), "local", t.LocalIP)
				if t.RemoteIP != "" {
					args = append(args, "remote", t.RemoteIP)
				}
				if t.Dev != "" {
					args = append(args, "dev", t.Dev)
				}
				port := t.DstPort
				if port <= 0 {
					port = 4789
				}
				args = append(args, "dstport", strconv.Itoa(port))
			} else {
				args = append(args, "local", t.LocalIP, "remote", t.RemoteIP)
				if t.TTL > 0 {
					args = append(args, "ttl", strconv.Itoa(t.TTL))
				}
				if t.Key > 0 {
					args = append(args, "key", strconv.FormatUint(uint64(t.Key), 10))
				}
			}
			if err := a.Driver.Exec(ctx, "ip", args...); err != nil {
				return err
			}
		}
		if err := a.applyCommonLinkAndIP(ctx, t.Name, t.MTU, t.VRF, t.Addresses, t.Enabled); err != nil {
			return err
		}
	}
	return a.deleteRemovedLinks(ctx, prev.Tunnels, desiredTun)
}

func (a *NetworkApplier) reconcileBridgesAndSwitching(ctx context.Context, cfg *netplan.NetworkConfig, prev, next *ManagedState) error {
	desired := make(map[string]bool)
	for _, br := range cfg.Interfaces.Bridges {
		desired[br.Name] = true
		next.Bridges = append(next.Bridges, br.Name)
		stpVal := "0"
		if br.STPMode == "stp" || br.STPMode == "rstp" || br.STPMode == "mstp" {
			stpVal = "1"
		}
		vfVal := "0"
		if br.VLANFiltering {
			vfVal = "1"
		}
		mcastVal := "0"
		if br.IGMPSnooping || br.MLDSnooping {
			mcastVal = "1"
		}

		if !a.Driver.LinkExists(br.Name) {
			if err := a.Driver.Exec(ctx, "ip", "link", "add", "name", br.Name, "type", "bridge",
				"vlan_filtering", vfVal, "stp_state", stpVal, "mcast_snooping", mcastVal); err != nil {
				return err
			}
		} else {
			if err := a.Driver.Exec(ctx, "ip", "link", "set", "dev", br.Name, "type", "bridge",
				"vlan_filtering", vfVal, "stp_state", stpVal, "mcast_snooping", mcastVal); err != nil {
				return err
			}
		}

		for _, port := range br.Ports {
			if err := a.Driver.Exec(ctx, "ip", "link", "set", "dev", port.Interface, "master", br.Name); err != nil {
				return err
			}
			if br.VLANFiltering {
				if port.PVID > 0 {
					_ = a.Driver.Exec(ctx, "bridge", "vlan", "add", "dev", port.Interface, "vid", strconv.Itoa(port.PVID), "pvid", "untagged")
				}
				for _, vid := range port.UntaggedVIDs {
					if vid != port.PVID {
						_ = a.Driver.Exec(ctx, "bridge", "vlan", "add", "dev", port.Interface, "vid", strconv.Itoa(vid), "untagged")
					}
				}
				for _, vid := range port.TaggedVIDs {
					_ = a.Driver.Exec(ctx, "bridge", "vlan", "add", "dev", port.Interface, "vid", strconv.Itoa(vid))
				}
			}
			if port.BPDUGuard {
				_ = a.Driver.Exec(ctx, "bridge", "link", "set", "dev", port.Interface, "guard", "on")
			}
			if port.EdgePort {
				_ = a.Driver.Exec(ctx, "bridge", "link", "set", "dev", port.Interface, "fastleave", "on")
			}
			if port.PortSecurity != nil && port.PortSecurity.Enabled {
				_ = a.Driver.Exec(ctx, "bridge", "link", "set", "dev", port.Interface, "learning", "off")
				for _, mac := range port.PortSecurity.StaticMACs {
					_ = a.Driver.Exec(ctx, "bridge", "fdb", "replace", mac, "dev", port.Interface, "master", "static")
				}
			}
			if port.StormControl != nil && port.StormControl.BroadcastPPS > 0 {
				_ = a.Driver.Exec(ctx, "tc", "qdisc", "replace", "dev", port.Interface, "clsact")
				rateKbps := strconv.Itoa(port.StormControl.BroadcastPPS) + "kbit"
				_ = a.Driver.Exec(ctx, "tc", "filter", "replace", "dev", port.Interface, "ingress",
					"protocol", "all", "u32", "match", "u32", "0", "0",
					"police", "rate", rateKbps, "burst", "64k", "drop")
			}
		}

		if br.Mirror != nil && br.Mirror.Enabled {
			for _, src := range br.Mirror.SourcePorts {
				_ = a.Driver.Exec(ctx, "tc", "qdisc", "replace", "dev", src, "clsact")
				if br.Mirror.Direction == "ingress" || br.Mirror.Direction == "both" {
					_ = a.Driver.Exec(ctx, "tc", "filter", "replace", "dev", src, "ingress",
						"matchall", "action", "mirred", "egress", "mirror", "dev", br.Mirror.DestPort)
				}
				if br.Mirror.Direction == "egress" || br.Mirror.Direction == "both" {
					_ = a.Driver.Exec(ctx, "tc", "filter", "replace", "dev", src, "egress",
						"matchall", "action", "mirred", "egress", "mirror", "dev", br.Mirror.DestPort)
				}
			}
		}

		if br.STPMode == "mstp" || br.STPMode == "rstp" {
			_ = a.Driver.Exec(ctx, "mstpctl", "addbridge", br.Name)
			_ = a.Driver.Exec(ctx, "mstpctl", "setforcevers", br.Name, br.STPMode)
			if br.STPPriority >= 0 {
				_ = a.Driver.Exec(ctx, "mstpctl", "settreeprio", br.Name, "0", strconv.Itoa(br.STPPriority/4096))
			}
		}

		if err := a.applyCommonLinkAndIP(ctx, br.Name, br.MTU, br.VRF, br.Addresses, br.Enabled); err != nil {
			return err
		}
	}
	return a.deleteRemovedLinks(ctx, prev.Bridges, desired)
}

func (a *NetworkApplier) reconcileARPAndRouting(ctx context.Context, cfg *netplan.NetworkConfig, prev, next *ManagedState) error {
	for _, arp := range cfg.IP.ARPStatic {
		if err := a.Driver.Exec(ctx, "ip", "neigh", "replace", arp.IP, "lladdr", arp.MAC, "dev", arp.Interface, "nud", "permanent"); err != nil {
			return err
		}
	}

	// Reconcile policy-based routing rules idempotently.
	desiredRules := make(map[string]bool)
	for _, pbr := range cfg.Routing.PolicyRoutes {
		args := []string{"rule", "add", "priority", strconv.Itoa(pbr.Priority)}
		if pbr.SrcPrefix != "" {
			args = append(args, "from", pbr.SrcPrefix)
		}
		if pbr.DstPrefix != "" {
			args = append(args, "to", pbr.DstPrefix)
		}
		if pbr.InInterface != "" {
			args = append(args, "iif", pbr.InInterface)
		}
		if pbr.FWMark > 0 {
			args = append(args, "fwmark", strconv.FormatUint(uint64(pbr.FWMark), 10))
		}
		if pbr.Action == "blackhole" || pbr.Action == "unreachable" {
			args = append(args, pbr.Action)
		} else {
			args = append(args, "table", strconv.FormatUint(uint64(pbr.TableID), 10))
		}
		ruleSig := strings.Join(args[2:], " ")
		desiredRules[ruleSig] = true
		next.PolicyRules = append(next.PolicyRules, ruleSig)
		// Replace by deleting old matching priority first if already tracked.
		_ = a.Driver.Exec(ctx, "ip", "rule", "del", "priority", strconv.Itoa(pbr.Priority))
		if err := a.Driver.Exec(ctx, "ip", args...); err != nil {
			return err
		}
	}
	for _, oldRule := range prev.PolicyRules {
		if !desiredRules[oldRule] {
			parts := strings.Fields(oldRule)
			if len(parts) >= 2 {
				_ = a.Driver.Exec(ctx, "ip", "rule", "del", parts[0], parts[1])
			}
		}
	}

	// Reconcile static & ECMP kernel routes.
	vrfTables := make(map[string]uint32, len(cfg.Routing.VRFs))
	for _, v := range cfg.Routing.VRFs {
		vrfTables[v.Name] = v.TableID
	}
	desiredRoutes := make(map[string]bool)
	for _, rt := range cfg.Routing.StaticRoutes {
		if !rt.Enabled {
			continue
		}
		args := []string{"route", "replace", rt.Prefix}
		if rt.VRF != "" {
			if tbl, ok := vrfTables[rt.VRF]; ok {
				args = append(args, "table", strconv.FormatUint(uint64(tbl), 10))
			}
		}
		if rt.Distance > 0 {
			args = append(args, "metric", strconv.Itoa(rt.Distance))
		}
		if len(rt.ECMPHops) > 0 {
			for _, hop := range rt.ECMPHops {
				args = append(args, "nexthop", "via", hop.NextHop)
				if hop.Interface != "" {
					args = append(args, "dev", hop.Interface)
				}
				if hop.Weight > 0 {
					args = append(args, "weight", strconv.Itoa(hop.Weight))
				}
			}
		} else {
			if rt.NextHop != "" {
				args = append(args, "via", rt.NextHop)
			}
			if rt.Interface != "" {
				args = append(args, "dev", rt.Interface)
			}
		}
		sig := rt.Prefix + "@" + rt.VRF
		desiredRoutes[sig] = true
		next.StaticRoutes = append(next.StaticRoutes, sig)
		if err := a.Driver.Exec(ctx, "ip", args...); err != nil {
			return err
		}
	}
	for _, oldSig := range prev.StaticRoutes {
		if !desiredRoutes[oldSig] {
			parts := strings.SplitN(oldSig, "@", 2)
			delArgs := []string{"route", "del", parts[0]}
			if len(parts) == 2 && parts[1] != "" {
				if tbl, ok := vrfTables[parts[1]]; ok {
					delArgs = append(delArgs, "table", strconv.FormatUint(uint64(tbl), 10))
				}
			}
			_ = a.Driver.Exec(ctx, "ip", delArgs...)
		}
	}
	return nil
}

func (a *NetworkApplier) reconcileDaemons(ctx context.Context, cfg *netplan.NetworkConfig) error {
	keaBytes, err := RenderKeaDHCP4(cfg)
	if err != nil {
		return err
	}
	type daemonSpec struct {
		service string
		path    string
		content []byte
		mode    uint32
	}
	specs := []daemonSpec{
		{service: "frr", path: "/etc/frr/frr.conf", content: []byte(RenderFRRConfig(cfg, false)), mode: 0o600},
		{service: "kea-dhcp4", path: "/etc/kea/kea-dhcp4.conf", content: keaBytes, mode: 0o640},
		{service: "dnsmasq", path: "/etc/dnsmasq.d/daiji.conf", content: []byte(RenderDnsmasq(cfg)), mode: 0o644},
		{service: "keepalived", path: "/etc/keepalived/keepalived.conf", content: []byte(RenderKeepalived(cfg, false)), mode: 0o600},
		{service: "chrony", path: "/etc/chrony/chrony.conf", content: []byte(RenderChrony(cfg)), mode: 0o644},
		{service: "dhcp-relay", path: "/etc/daiji/dhcp-relay.conf", content: []byte(RenderDHCPRelay(cfg)), mode: 0o644},
		{service: "lldpd", path: "/etc/lldpd.d/daiji.conf", content: []byte(RenderLLDPD(cfg)), mode: 0o644},
	}

	sort.Slice(specs, func(i, j int) bool { return specs[i].service < specs[j].service })
	for _, sp := range specs {
		changed, err := a.Driver.WriteFile(sp.path, sp.content, os.FileMode(sp.mode))
		if err != nil {
			return err
		}
		if changed {
			if err := a.Driver.ReloadService(ctx, sp.service); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *NetworkApplier) applyCommonLinkAndIP(ctx context.Context, name string, mtu int, vrf string, addrs []string, enabled bool) error {
	if mtu > 0 {
		if err := a.Driver.Exec(ctx, "ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu)); err != nil {
			return err
		}
	}
	if vrf != "" {
		if err := a.Driver.Exec(ctx, "ip", "link", "set", "dev", name, "master", vrf); err != nil {
			return err
		}
	}
	state := "down"
	if enabled {
		state = "up"
	}
	if err := a.Driver.Exec(ctx, "ip", "link", "set", "dev", name, state); err != nil {
		return err
	}
	for _, cidr := range addrs {
		if err := a.Driver.Exec(ctx, "ip", "addr", "replace", cidr, "dev", name); err != nil {
			return err
		}
	}
	return nil
}

func (a *NetworkApplier) deleteRemovedLinks(ctx context.Context, prevList []string, desired map[string]bool) error {
	for _, old := range prevList {
		if !desired[old] && a.Driver.LinkExists(old) {
			if err := a.Driver.Exec(ctx, "ip", "link", "del", old); err != nil {
				return err
			}
		}
	}
	return nil
}
