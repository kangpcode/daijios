// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package netplan

import (
	"fmt"
	"net/netip"
	"strings"
)

// ValidateSemantic enforces cross-field networking invariants beyond JSON Schema syntax.
func ValidateSemantic(rawCfg map[string]any) error {
	cfg, err := ParseConfig(rawCfg)
	if err != nil {
		return fmt.Errorf("parse network config: %w", err)
	}

	var errs []string
	ifaceNames := make(map[string]string)

	registerIface := func(name, kind string) {
		if prev, dup := ifaceNames[name]; dup {
			errs = append(errs, fmt.Sprintf("duplicate interface name %q (%s and %s)", name, prev, kind))
			return
		}
		ifaceNames[name] = kind
	}

	// Collect VRFs first to validate VRF references across interfaces and routing.
	vrfMap := make(map[string]uint32)
	vrfTables := make(map[uint32]string)
	for _, v := range cfg.Routing.VRFs {
		if v.TableID == 0 || v.TableID == 253 || v.TableID == 254 || v.TableID == 255 {
			errs = append(errs, fmt.Sprintf("vrf %q uses Linux reserved table_id %d", v.Name, v.TableID))
		}
		if _, dup := vrfMap[v.Name]; dup {
			errs = append(errs, fmt.Sprintf("duplicate VRF name %q", v.Name))
		}
		if prev, dupTbl := vrfTables[v.TableID]; dupTbl {
			errs = append(errs, fmt.Sprintf("duplicate VRF table_id %d (%q and %q)", v.TableID, prev, v.Name))
		}
		vrfMap[v.Name] = v.TableID
		vrfTables[v.TableID] = v.Name
		registerIface(v.Name, "vrf")
	}

	for _, p := range cfg.Interfaces.Physical {
		registerIface(p.Name, "physical")
	}
	for _, b := range cfg.Interfaces.Bondings {
		registerIface(b.Name, "bonding")
	}
	for _, v := range cfg.Interfaces.VLANs {
		registerIface(v.Name, "vlan")
	}
	for _, br := range cfg.Interfaces.Bridges {
		registerIface(br.Name, "bridge")
	}
	for _, ve := range cfg.Interfaces.Veth {
		registerIface(ve.Name, "veth")
		if ve.Peer != "" {
			registerIface(ve.Peer, "veth-peer")
		}
	}
	for _, t := range cfg.Interfaces.Tunnels {
		registerIface(t.Name, "tunnel")
		if t.Mode == "vxlan" && t.VNI == 0 {
			errs = append(errs, fmt.Sprintf("vxlan tunnel %q requires vni > 0", t.Name))
		}
		if t.Mode != "vxlan" && t.RemoteIP == "" {
			errs = append(errs, fmt.Sprintf("tunnel %q mode %s requires remote_ip", t.Name, t.Mode))
		}
	}

	// Validate VRF bindings and parent interfaces.
	checkVRFRef := func(owner, vrf string) {
		if vrf == "" {
			return
		}
		if _, ok := vrfMap[vrf]; !ok {
			errs = append(errs, fmt.Sprintf("%s references undefined VRF %q", owner, vrf))
		}
	}

	for _, p := range cfg.Interfaces.Physical {
		checkVRFRef("physical "+p.Name, p.VRF)
	}
	for _, v := range cfg.Interfaces.VLANs {
		checkVRFRef("vlan "+v.Name, v.VRF)
		if _, ok := ifaceNames[v.Parent]; !ok {
			errs = append(errs, fmt.Sprintf("vlan %q references unknown parent interface %q", v.Name, v.Parent))
		}
		if v.Protocol == "802.1ad" && v.QinQInnerVID == 0 {
			errs = append(errs, fmt.Sprintf("QinQ vlan %q (802.1ad) requires qinq_inner_vid", v.Name))
		}
	}

	// Ensure bonding members and bridge ports do not collide.
	slaveOwner := make(map[string]string)
	for _, b := range cfg.Interfaces.Bondings {
		checkVRFRef("bonding "+b.Name, b.VRF)
		for _, m := range b.Members {
			if _, ok := ifaceNames[m]; !ok {
				errs = append(errs, fmt.Sprintf("bonding %q member %q does not exist", b.Name, m))
			}
			if prev, used := slaveOwner[m]; used {
				errs = append(errs, fmt.Sprintf("interface %q attached to both %s and bond %s", m, prev, b.Name))
			}
			slaveOwner[m] = "bond " + b.Name
		}
	}

	for _, br := range cfg.Interfaces.Bridges {
		checkVRFRef("bridge "+br.Name, br.VRF)
		portSet := make(map[string]bool)
		for _, bp := range br.Ports {
			if _, ok := ifaceNames[bp.Interface]; !ok {
				errs = append(errs, fmt.Sprintf("bridge %q port %q does not exist", br.Name, bp.Interface))
			}
			if prev, used := slaveOwner[bp.Interface]; used {
				errs = append(errs, fmt.Sprintf("interface %q attached to both %s and bridge %s", bp.Interface, prev, br.Name))
			}
			slaveOwner[bp.Interface] = "bridge " + br.Name
			portSet[bp.Interface] = true
		}
		if br.Mirror != nil && br.Mirror.Enabled {
			if _, ok := ifaceNames[br.Mirror.DestPort]; !ok {
				errs = append(errs, fmt.Sprintf("bridge %q mirror dest_port %q does not exist", br.Name, br.Mirror.DestPort))
			}
			for _, src := range br.Mirror.SourcePorts {
				if src == br.Mirror.DestPort {
					errs = append(errs, fmt.Sprintf("bridge %q mirror source_port and dest_port cannot both be %q", br.Name, src))
				}
				if !portSet[src] {
					errs = append(errs, fmt.Sprintf("bridge %q mirror source_port %q is not a member port", br.Name, src))
				}
			}
		}
	}

	// Validate VRRP VRID uniqueness per interface and auth secret requirement.
	vrrpSeen := make(map[string]bool)
	for _, vr := range cfg.Interfaces.VRRP {
		if _, ok := ifaceNames[vr.Interface]; !ok {
			errs = append(errs, fmt.Sprintf("vrrp %q references unknown interface %q", vr.Name, vr.Interface))
		}
		key := fmt.Sprintf("%s#%d", vr.Interface, vr.VRID)
		if vrrpSeen[key] {
			errs = append(errs, fmt.Sprintf("duplicate VRRP VRID %d on interface %q", vr.VRID, vr.Interface))
		}
		vrrpSeen[key] = true
		if vr.AuthType == "pass" && len(vr.AuthSecret) < 4 {
			errs = append(errs, fmt.Sprintf("vrrp %q with auth_type=pass requires auth_secret", vr.Name))
		}
	}

	// Validate DHCP server pool ranges inside subnet and start <= end.
	for _, pool := range cfg.IP.DHCP.Servers {
		if _, ok := ifaceNames[pool.Interface]; !ok {
			errs = append(errs, fmt.Sprintf("dhcp pool %q references unknown interface %q", pool.Name, pool.Interface))
		}
		pfx, err1 := netip.ParsePrefix(pool.Subnet)
		startIP, err2 := netip.ParseAddr(pool.RangeStart)
		endIP, err3 := netip.ParseAddr(pool.RangeEnd)
		if err1 == nil && err2 == nil && err3 == nil {
			if !pfx.Contains(startIP) || !pfx.Contains(endIP) {
				errs = append(errs, fmt.Sprintf("dhcp pool %q range %s-%s outside subnet %s", pool.Name, startIP, endIP, pfx))
			}
			if startIP.Compare(endIP) > 0 {
				errs = append(errs, fmt.Sprintf("dhcp pool %q range_start %s > range_end %s", pool.Name, startIP, endIP))
			}
		}
	}

	// Validate static/ECMP routes.
	for i, rt := range cfg.Routing.StaticRoutes {
		checkVRFRef(fmt.Sprintf("static_route[%d]", i), rt.VRF)
		if rt.NextHop == "" && rt.Interface == "" && len(rt.ECMPHops) == 0 {
			errs = append(errs, fmt.Sprintf("static_route[%d] (%s) must define next_hop, interface, or ecmp_hops", i, rt.Prefix))
		}
	}

	// Validate BGP route-maps and prefix-lists.
	if cfg.Routing.BGP.Enabled {
		if cfg.Routing.BGP.ASN == 0 {
			errs = append(errs, "routing.bgp.enabled=true requires asn > 0")
		}
		checkVRFRef("routing.bgp", cfg.Routing.BGP.VRF)
		plSet := make(map[string]bool)
		for _, pl := range cfg.Routing.BGP.PrefixLists {
			plSet[pl.Name] = true
			for _, r := range pl.Rules {
				if r.LE > 0 && r.GE > r.LE {
					errs = append(errs, fmt.Sprintf("prefix_list %q seq %d has ge (%d) > le (%d)", pl.Name, r.Seq, r.GE, r.LE))
				}
			}
		}
		rmSet := make(map[string]bool)
		for _, rm := range cfg.Routing.BGP.RouteMaps {
			rmSet[rm.Name] = true
			for _, ent := range rm.Entries {
				if ent.MatchPrefixList != "" && !plSet[ent.MatchPrefixList] {
					errs = append(errs, fmt.Sprintf("route_map %q references unknown prefix_list %q", rm.Name, ent.MatchPrefixList))
				}
			}
		}
		for _, nb := range cfg.Routing.BGP.Neighbors {
			if nb.RouteMapIn != "" && !rmSet[nb.RouteMapIn] {
				errs = append(errs, fmt.Sprintf("bgp neighbor %s references unknown route_map_in %q", nb.PeerIP, nb.RouteMapIn))
			}
			if nb.RouteMapOut != "" && !rmSet[nb.RouteMapOut] {
				errs = append(errs, fmt.Sprintf("bgp neighbor %s references unknown route_map_out %q", nb.PeerIP, nb.RouteMapOut))
			}
		}
	}

	// Validate MPLS label range.
	if cfg.Routing.MPLS.Enabled && cfg.Routing.MPLS.LabelRangeMax > 0 &&
		cfg.Routing.MPLS.LabelRangeMin >= cfg.Routing.MPLS.LabelRangeMax {
		errs = append(errs, "routing.mpls.label_range_min must be < label_range_max")
	}

	// Guard against control-character / newline config injection in daemon template strings.
	checkLineSafe := func(field, s string) {
		if strings.ContainsAny(s, "\r\n\x00") {
			errs = append(errs, fmt.Sprintf("%s contains forbidden control/newline characters", field))
		}
	}
	for _, v := range cfg.Routing.VRFs {
		checkLineSafe("vrf."+v.Name+".description", v.Description)
	}
	for _, vr := range cfg.Interfaces.VRRP {
		checkLineSafe("vrrp."+vr.Name+".auth_secret", vr.AuthSecret)
	}
	for _, nb := range cfg.Routing.BGP.Neighbors {
		checkLineSafe("bgp.neighbor."+nb.PeerIP+".description", nb.Description)
		checkLineSafe("bgp.neighbor."+nb.PeerIP+".password", nb.Password)
	}
	checkLineSafe("ip.dns.local_domain", cfg.IP.DNS.LocalDomain)

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
