// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package netreconcile

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kangpcode/daijios/pkg/netplan"
)

const secretMask = "***REDACTED***"

func sanitizeLine(s string) string {
	return strings.NewReplacer("\r", "", "\n", " ", "\x00", "").Replace(s)
}

// RenderFRRConfig generates a unified FRRouting configuration (frr.conf) covering
// VRF, BFD, prefix-lists, route-maps, OSPFv2, OSPFv3, BGP (iBGP/eBGP/ECMP), RIP, IS-IS, and MPLS/LDP.
func RenderFRRConfig(cfg *netplan.NetworkConfig, redactSecrets bool) string {
	var b strings.Builder
	host := cfg.System.Hostname
	if host == "" {
		host = "daiji-router"
	}
	fmt.Fprintf(&b, "! DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	fmt.Fprintf(&b, "frr defaults traditional\n")
	fmt.Fprintf(&b, "hostname %s\n", host)
	fmt.Fprintf(&b, "service integrated-vtysh-config\n!\n")

	for _, vrf := range cfg.Routing.VRFs {
		fmt.Fprintf(&b, "vrf %s\n", sanitizeLine(vrf.Name))
		if vrf.Description != "" {
			fmt.Fprintf(&b, " description %s\n", sanitizeLine(vrf.Description))
		}
		fmt.Fprintf(&b, "exit-vrf\n!\n")
	}

	if len(cfg.Routing.BFD) > 0 {
		fmt.Fprintf(&b, "bfd\n")
		for _, bp := range cfg.Routing.BFD {
			fmt.Fprintf(&b, " profile %s\n", bp.Name)
			if bp.MinTxMS > 0 {
				fmt.Fprintf(&b, "  transmit-interval %d\n", bp.MinTxMS)
			}
			if bp.MinRxMS > 0 {
				fmt.Fprintf(&b, "  receive-interval %d\n", bp.MinRxMS)
			}
			if bp.DetectMultiplier > 0 {
				fmt.Fprintf(&b, "  detect-multiplier %d\n", bp.DetectMultiplier)
			}
			if bp.EchoMode {
				fmt.Fprintf(&b, "  echo-mode\n")
			}
			fmt.Fprintf(&b, " exit\n")
			peerLine := fmt.Sprintf(" peer %s", bp.PeerIP)
			if bp.Interface != "" {
				peerLine += " interface " + bp.Interface
			}
			if bp.VRF != "" {
				peerLine += " vrf " + bp.VRF
			}
			fmt.Fprintf(&b, "%s\n", peerLine)
			fmt.Fprintf(&b, "  profile %s\n", bp.Name)
			fmt.Fprintf(&b, " exit\n")
		}
		fmt.Fprintf(&b, "exit\n!\n")
	}

	for _, pl := range cfg.Routing.BGP.PrefixLists {
		for _, r := range pl.Rules {
			line := fmt.Sprintf("ip prefix-list %s seq %d %s %s", pl.Name, r.Seq, r.Action, r.Prefix)
			if r.GE > 0 {
				line += fmt.Sprintf(" ge %d", r.GE)
			}
			if r.LE > 0 {
				line += fmt.Sprintf(" le %d", r.LE)
			}
			fmt.Fprintf(&b, "%s\n", line)
		}
	}
	if len(cfg.Routing.BGP.PrefixLists) > 0 {
		fmt.Fprintf(&b, "!\n")
	}

	for _, rm := range cfg.Routing.BGP.RouteMaps {
		for _, ent := range rm.Entries {
			fmt.Fprintf(&b, "route-map %s %s %d\n", rm.Name, ent.Action, ent.Seq)
			if ent.MatchPrefixList != "" {
				fmt.Fprintf(&b, " match ip address prefix-list %s\n", ent.MatchPrefixList)
			}
			if ent.MatchCommunity != "" {
				fmt.Fprintf(&b, " match community %s\n", ent.MatchCommunity)
			}
			if ent.SetLocalPref != nil {
				fmt.Fprintf(&b, " set local-preference %d\n", *ent.SetLocalPref)
			}
			if ent.SetMED != nil {
				fmt.Fprintf(&b, " set metric %d\n", *ent.SetMED)
			}
			if ent.SetASPrepend != "" {
				fmt.Fprintf(&b, " set as-path prepend %s\n", ent.SetASPrepend)
			}
			if ent.SetCommunity != "" {
				fmt.Fprintf(&b, " set community %s\n", ent.SetCommunity)
			}
			fmt.Fprintf(&b, "exit\n!\n")
		}
	}

	if cfg.Routing.OSPF.Enabled {
		hdr := "router ospf"
		if cfg.Routing.OSPF.VRF != "" {
			hdr += " vrf " + cfg.Routing.OSPF.VRF
		}
		fmt.Fprintf(&b, "%s\n", hdr)
		if cfg.Routing.OSPF.RouterID != "" {
			fmt.Fprintf(&b, " ospf router-id %s\n", cfg.Routing.OSPF.RouterID)
		}
		for _, pi := range cfg.Routing.OSPF.PassiveInterfaces {
			fmt.Fprintf(&b, " passive-interface %s\n", pi)
		}
		for _, rd := range cfg.Routing.OSPF.Redistribute {
			fmt.Fprintf(&b, " redistribute %s\n", rd)
		}
		if cfg.Routing.OSPF.DefaultOriginate {
			fmt.Fprintf(&b, " default-information originate\n")
		}
		for _, area := range cfg.Routing.OSPF.Areas {
			for _, net := range area.Networks {
				fmt.Fprintf(&b, " network %s area %s\n", net, area.AreaID)
			}
			if area.AreaType == "stub" || area.AreaType == "nssa" {
				fmt.Fprintf(&b, " area %s %s\n", area.AreaID, area.AreaType)
			}
			if area.AuthType == "md5" {
				fmt.Fprintf(&b, " area %s authentication message-digest\n", area.AreaID)
			}
		}
		fmt.Fprintf(&b, "exit\n!\n")
	}

	if cfg.Routing.OSPFv3.Enabled {
		hdr := "router ospf6"
		if cfg.Routing.OSPFv3.VRF != "" {
			hdr += " vrf " + cfg.Routing.OSPFv3.VRF
		}
		fmt.Fprintf(&b, "%s\n", hdr)
		if cfg.Routing.OSPFv3.RouterID != "" {
			fmt.Fprintf(&b, " ospf6 router-id %s\n", cfg.Routing.OSPFv3.RouterID)
		}
		for _, area := range cfg.Routing.OSPFv3.Areas {
			for _, ifName := range area.Interfaces {
				fmt.Fprintf(&b, " interface %s area %s\n", ifName, area.AreaID)
			}
		}
		fmt.Fprintf(&b, "exit\n!\n")
	}

	if cfg.Routing.BGP.Enabled && cfg.Routing.BGP.ASN > 0 {
		hdr := fmt.Sprintf("router bgp %d", cfg.Routing.BGP.ASN)
		if cfg.Routing.BGP.VRF != "" {
			hdr += " vrf " + cfg.Routing.BGP.VRF
		}
		fmt.Fprintf(&b, "%s\n", hdr)
		if cfg.Routing.BGP.RouterID != "" {
			fmt.Fprintf(&b, " bgp router-id %s\n", cfg.Routing.BGP.RouterID)
		}
		if cfg.Routing.BGP.GracefulRestart {
			fmt.Fprintf(&b, " bgp graceful-restart\n")
		}
		for _, nb := range cfg.Routing.BGP.Neighbors {
			fmt.Fprintf(&b, " neighbor %s remote-as %d\n", nb.PeerIP, nb.RemoteASN)
			if nb.Description != "" {
				fmt.Fprintf(&b, " neighbor %s description %s\n", nb.PeerIP, sanitizeLine(nb.Description))
			}
			if nb.UpdateSource != "" {
				fmt.Fprintf(&b, " neighbor %s update-source %s\n", nb.PeerIP, sanitizeLine(nb.UpdateSource))
			}
			if nb.EBGPMultihop > 1 {
				fmt.Fprintf(&b, " neighbor %s ebgp-multihop %d\n", nb.PeerIP, nb.EBGPMultihop)
			}
			if nb.BFD {
				fmt.Fprintf(&b, " neighbor %s bfd\n", nb.PeerIP)
			}
			if nb.Password != "" {
				pw := sanitizeLine(nb.Password)
				if redactSecrets {
					pw = secretMask
				}
				fmt.Fprintf(&b, " neighbor %s password %s\n", nb.PeerIP, pw)
			}
		}
		fmt.Fprintf(&b, " address-family ipv4 unicast\n")
		if cfg.Routing.BGP.ECMPMaxPaths > 1 {
			fmt.Fprintf(&b, "  maximum-paths %d\n", cfg.Routing.BGP.ECMPMaxPaths)
		}
		for _, net := range cfg.Routing.BGP.Networks {
			fmt.Fprintf(&b, "  network %s\n", net)
		}
		for _, nb := range cfg.Routing.BGP.Neighbors {
			if nb.SendCommunity {
				fmt.Fprintf(&b, "  neighbor %s send-community both\n", nb.PeerIP)
			}
			if nb.SoftReconfig {
				fmt.Fprintf(&b, "  neighbor %s soft-reconfiguration inbound\n", nb.PeerIP)
			}
			if nb.RouteMapIn != "" {
				fmt.Fprintf(&b, "  neighbor %s route-map %s in\n", nb.PeerIP, nb.RouteMapIn)
			}
			if nb.RouteMapOut != "" {
				fmt.Fprintf(&b, "  neighbor %s route-map %s out\n", nb.PeerIP, nb.RouteMapOut)
			}
		}
		fmt.Fprintf(&b, " exit-address-family\n")
		fmt.Fprintf(&b, "exit\n!\n")
	}

	if cfg.Routing.RIP.Enabled {
		hdr := "router rip"
		if cfg.Routing.RIP.VRF != "" {
			hdr += " vrf " + cfg.Routing.RIP.VRF
		}
		fmt.Fprintf(&b, "%s\n", hdr)
		if cfg.Routing.RIP.Version > 0 {
			fmt.Fprintf(&b, " version %d\n", cfg.Routing.RIP.Version)
		}
		for _, net := range cfg.Routing.RIP.Networks {
			fmt.Fprintf(&b, " network %s\n", net)
		}
		for _, pi := range cfg.Routing.RIP.PassiveInterfaces {
			fmt.Fprintf(&b, " passive-interface %s\n", pi)
		}
		for _, rd := range cfg.Routing.RIP.Redistribute {
			fmt.Fprintf(&b, " redistribute %s\n", rd)
		}
		fmt.Fprintf(&b, "exit\n!\n")
	}

	if cfg.Routing.ISIS.Enabled {
		tag := "DAIJI-CORE"
		hdr := "router isis " + tag
		if cfg.Routing.ISIS.VRF != "" {
			hdr += " vrf " + cfg.Routing.ISIS.VRF
		}
		fmt.Fprintf(&b, "%s\n", hdr)
		if cfg.Routing.ISIS.NetID != "" {
			fmt.Fprintf(&b, " net %s\n", cfg.Routing.ISIS.NetID)
		}
		if cfg.Routing.ISIS.Level != "" {
			fmt.Fprintf(&b, " is-type %s\n", cfg.Routing.ISIS.Level)
		}
		fmt.Fprintf(&b, "exit\n!\n")
		for _, isIf := range cfg.Routing.ISIS.Interfaces {
			fmt.Fprintf(&b, "interface %s\n", isIf.Name)
			fmt.Fprintf(&b, " ip router isis %s\n", tag)
			if isIf.Metric > 0 {
				fmt.Fprintf(&b, " isis metric %d\n", isIf.Metric)
			}
			if isIf.BFD {
				fmt.Fprintf(&b, " isis bfd\n")
			}
			if isIf.Passive {
				fmt.Fprintf(&b, " isis passive\n")
			}
			fmt.Fprintf(&b, "exit\n!\n")
		}
	}

	if cfg.Routing.MPLS.Enabled && cfg.Routing.MPLS.LDP.Enabled {
		fmt.Fprintf(&b, "mpls ldp\n")
		if cfg.Routing.MPLS.LDP.RouterID != "" {
			fmt.Fprintf(&b, " router-id %s\n", cfg.Routing.MPLS.LDP.RouterID)
		}
		fmt.Fprintf(&b, " address-family ipv4\n")
		if cfg.Routing.MPLS.LDP.TransportIP != "" {
			fmt.Fprintf(&b, "  discovery transport-address %s\n", cfg.Routing.MPLS.LDP.TransportIP)
		}
		for _, ifName := range cfg.Routing.MPLS.LDP.Interfaces {
			fmt.Fprintf(&b, "  interface %s\n", ifName)
		}
		fmt.Fprintf(&b, " exit-address-family\n")
		fmt.Fprintf(&b, "exit\n!\n")
	}

	fmt.Fprintf(&b, "line vty\n!\nend\n")
	return b.String()
}

// RenderKeaDHCP4 generates a Kea DHCPv4 server JSON configuration.
func RenderKeaDHCP4(cfg *netplan.NetworkConfig) ([]byte, error) {
	ifaces := make([]string, 0)
	subnets := make([]map[string]any, 0)

	for _, pool := range cfg.IP.DHCP.Servers {
		if !pool.Enabled {
			continue
		}
		ifaces = append(ifaces, pool.Interface)
		options := make([]map[string]any, 0)
		if pool.Gateway != "" {
			options = append(options, map[string]any{"name": "routers", "data": pool.Gateway})
		}
		if len(pool.DNSServers) > 0 {
			options = append(options, map[string]any{"name": "domain-name-servers", "data": strings.Join(pool.DNSServers, ", ")})
		}
		if pool.DomainName != "" {
			options = append(options, map[string]any{"name": "domain-name", "data": pool.DomainName})
		}
		reservations := make([]map[string]any, 0, len(pool.StaticLeases))
		for _, sl := range pool.StaticLeases {
			res := map[string]any{"hw-address": sl.MAC, "ip-address": sl.IP}
			if sl.Hostname != "" {
				res["hostname"] = sl.Hostname
			}
			reservations = append(reservations, res)
		}
		lease := pool.LeaseTimeSec
		if lease <= 0 {
			lease = 86400
		}
		subnets = append(subnets, map[string]any{
			"subnet":      pool.Subnet,
			"interface":   pool.Interface,
			"valid-lifetime": lease,
			"pools": []map[string]any{
				{"pool": fmt.Sprintf("%s - %s", pool.RangeStart, pool.RangeEnd)},
			},
			"option-data":  options,
			"reservations": reservations,
		})
	}

	doc := map[string]any{
		"Dhcp4": map[string]any{
			"interfaces-config": map[string]any{"interfaces": ifaces},
			"lease-database":    map[string]any{"type": "memfile", "persist": true, "name": "/var/lib/kea/kea-leases4.csv"},
			"subnet4":           subnets,
		},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// RenderDnsmasq generates a dnsmasq DNS forwarder/cache configuration.
func RenderDnsmasq(cfg *netplan.NetworkConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	if !cfg.IP.DNS.Enabled {
		fmt.Fprintf(&b, "port=0\n")
		return b.String()
	}
	port := cfg.IP.DNS.Port
	if port <= 0 {
		port = 53
	}
	fmt.Fprintf(&b, "port=%d\nbind-interfaces\nno-resolv\n", port)
	for _, la := range cfg.IP.DNS.ListenAddresses {
		fmt.Fprintf(&b, "listen-address=%s\n", la)
	}
	for _, up := range cfg.IP.DNS.Upstreams {
		fmt.Fprintf(&b, "server=%s\n", up)
	}
	if cfg.IP.DNS.CacheSize > 0 {
		fmt.Fprintf(&b, "cache-size=%d\n", cfg.IP.DNS.CacheSize)
	}
	if cfg.IP.DNS.DNSSEC {
		fmt.Fprintf(&b, "dnssec\n")
	}
	if cfg.IP.DNS.LocalDomain != "" {
		fmt.Fprintf(&b, "domain=%s\nlocal=/%s/\n", cfg.IP.DNS.LocalDomain, cfg.IP.DNS.LocalDomain)
	}
	for _, h := range cfg.IP.DNS.StaticHosts {
		fmt.Fprintf(&b, "host-record=%s,%s\n", h.Hostname, h.IP)
	}
	return b.String()
}

// RenderKeepalived generates a keepalived VRRP configuration.
func RenderKeepalived(cfg *netplan.NetworkConfig, redactSecrets bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "! DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	for _, vr := range cfg.Interfaces.VRRP {
		if !vr.Enabled {
			continue
		}
		fmt.Fprintf(&b, "vrrp_instance %s {\n", vr.Name)
		fmt.Fprintf(&b, "  state BACKUP\n")
		fmt.Fprintf(&b, "  interface %s\n", vr.Interface)
		fmt.Fprintf(&b, "  virtual_router_id %d\n", vr.VRID)
		fmt.Fprintf(&b, "  priority %d\n", vr.Priority)
		advSec := float64(vr.AdvertIntMS) / 1000.0
		if advSec <= 0 {
			advSec = 1.0
		}
		fmt.Fprintf(&b, "  advert_int %.3f\n", advSec)
		if !vr.Preempt {
			fmt.Fprintf(&b, "  nopreempt\n")
		}
		if vr.AuthType == "pass" && vr.AuthSecret != "" {
			sec := vr.AuthSecret
			if redactSecrets {
				sec = secretMask
			}
			fmt.Fprintf(&b, "  authentication {\n    auth_type PASS\n    auth_pass %s\n  }\n", sec)
		}
		if len(vr.TrackInterfaces) > 0 {
			fmt.Fprintf(&b, "  track_interface {\n")
			for _, ti := range vr.TrackInterfaces {
				fmt.Fprintf(&b, "    %s\n", ti)
			}
			fmt.Fprintf(&b, "  }\n")
		}
		fmt.Fprintf(&b, "  virtual_ipaddress {\n")
		for _, vip := range vr.VirtualIPs {
			fmt.Fprintf(&b, "    %s\n", vip)
		}
		fmt.Fprintf(&b, "  }\n}\n")
	}
	return b.String()
}

// RenderChrony generates a chrony NTP client/server configuration.
func RenderChrony(cfg *netplan.NetworkConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	servers := cfg.IP.NTP.Servers
	if len(servers) == 0 {
		servers = cfg.System.NTPServers
	}
	for _, s := range servers {
		fmt.Fprintf(&b, "pool %s iburst\n", s)
	}
	fmt.Fprintf(&b, "makestep 1.0 3\nrtcsync\n")
	if cfg.IP.NTP.ServerMode {
		for _, sub := range cfg.IP.NTP.AllowSubnets {
			fmt.Fprintf(&b, "allow %s\n", sub)
		}
	}
	return b.String()
}

// RenderLLDPD generates lldpd daemon settings.
func RenderLLDPD(cfg *netplan.NetworkConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	if !cfg.Switching.LLDP.Enabled {
		return b.String()
	}
	tx := cfg.Switching.LLDP.TxIntervalSec
	if tx <= 0 {
		tx = 30
	}
	hold := cfg.Switching.LLDP.TxHold
	if hold <= 0 {
		hold = 4
	}
	fmt.Fprintf(&b, "configure lldp tx-interval %d\n", tx)
	fmt.Fprintf(&b, "configure lldp tx-hold %d\n", hold)
	if len(cfg.Switching.LLDP.Interfaces) > 0 {
		fmt.Fprintf(&b, "configure system interface pattern %s\n", strings.Join(cfg.Switching.LLDP.Interfaces, ","))
	}
	return b.String()
}

// RenderDHCPRelay generates dhcrelay / Kea-relay environment configuration.
func RenderDHCPRelay(cfg *netplan.NetworkConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	for _, r := range cfg.IP.DHCP.Relays {
		if !r.Enabled {
			continue
		}
		fmt.Fprintf(&b, "RELAY_%s_INTERFACES=%q\n", sanitizeLine(r.Name), strings.Join(r.ListenInterfaces, ","))
		fmt.Fprintf(&b, "RELAY_%s_SERVERS=%q\n", sanitizeLine(r.Name), strings.Join(r.UpstreamServers, ","))
		fmt.Fprintf(&b, "RELAY_%s_CIRCUIT_ID=%v\n", sanitizeLine(r.Name), r.CircuitID)
	}
	return b.String()
}
