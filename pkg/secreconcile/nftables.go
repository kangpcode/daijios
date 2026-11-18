// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package secreconcile implements the idempotent Phase 2 reconcilers for
// nftables (filter, NAT, mangle, DPI, bridge port security), Linux tc QoS
// (HTB/CAKE/fq_codel/queue-tree/simple-queue/PCQ), VPNs, and OS hardening.
package secreconcile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kangpcode/daijios/pkg/secplan"
)

func sanitizeNFT(s string) string {
	return strings.NewReplacer("\r", "", "\n", " ", "\x00", "", `"`, `'`, ";", "", "{", "", "}", "").Replace(s)
}

// RenderNFTables produces a complete atomic nftables ruleset (/etc/nftables.d/daiji.nft).
func RenderNFTables(cfg *secplan.SecurityConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#!/usr/sbin/nft -f\n")
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n\n")

	// Atomic table setup & flush ensures zero-downtime rule replacement.
	for _, tbl := range []string{"inet daiji_filter", "inet daiji_nat", "inet daiji_mangle"} {
		fmt.Fprintf(&b, "table %s {}\nflush table %s\n", tbl, tbl)
	}
	b.WriteByte('\n')

	inPol := defaultOr(cfg.Firewall.DefaultPolicy.Input, "drop")
	fwdPol := defaultOr(cfg.Firewall.DefaultPolicy.Forward, "drop")
	outPol := defaultOr(cfg.Firewall.DefaultPolicy.Output, "accept")

	// 1. Stateful Filter Table
	fmt.Fprintf(&b, "table inet daiji_filter {\n")
	fmt.Fprintf(&b, "  set daiji_ban_v4 {\n    type ipv4_addr\n    flags timeout\n  }\n")
	fmt.Fprintf(&b, "  set daiji_ban_v6 {\n    type ipv6_addr\n    flags timeout\n  }\n")

	for _, al := range cfg.Firewall.AddressLists {
		addrType := "ipv4_addr"
		if al.Family == "ipv6" {
			addrType = "ipv6_addr"
		}
		fmt.Fprintf(&b, "  set %s {\n    type %s\n    flags interval,timeout\n", sanitizeNFT(al.Name), addrType)
		if len(al.Entries) > 0 {
			elems := make([]string, 0, len(al.Entries))
			for _, ent := range al.Entries {
				if ent.TimeoutSec > 0 {
					elems = append(elems, fmt.Sprintf("%s timeout %ds", ent.CIDR, ent.TimeoutSec))
				} else {
					elems = append(elems, ent.CIDR)
				}
			}
			fmt.Fprintf(&b, "    elements = { %s }\n", strings.Join(elems, ", "))
		}
		fmt.Fprintf(&b, "  }\n")
	}

	rules := append([]secplan.FirewallFilterRule(nil), cfg.Firewall.FilterRules...)
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Order != rules[j].Order {
			return rules[i].Order < rules[j].Order
		}
		return rules[i].ID < rules[j].ID
	})

	writeFilterChain := func(chainName, policy string) {
		fmt.Fprintf(&b, "  chain %s {\n    type filter hook %s priority filter; policy %s;\n", chainName, chainName, policy)
		if chainName == "input" {
			fmt.Fprintf(&b, "    iif \"lo\" accept\n")
		}
		if chainName == "input" || chainName == "forward" {
			fmt.Fprintf(&b, "    ct state established,related accept\n")
			if cfg.Firewall.Conntrack.LogInvalid {
				fmt.Fprintf(&b, "    ct state invalid log prefix \"DAIJI-CT-INVALID \" drop\n")
			} else {
				fmt.Fprintf(&b, "    ct state invalid drop\n")
			}
			if cfg.Security.BruteForce.Enabled || len(cfg.Firewall.FilterRules) > 0 {
				fmt.Fprintf(&b, "    ip saddr @daiji_ban_v4 drop\n")
				fmt.Fprintf(&b, "    ip6 saddr @daiji_ban_v6 drop\n")
			}
		}
		if chainName == "input" && cfg.Firewall.Conntrack.SYNFloodProtect {
			rate := cfg.Firewall.Conntrack.SYNRatePerSec
			if rate <= 0 {
				rate = 200
			}
			fmt.Fprintf(&b, "    tcp flags & (fin|syn|rst|ack) == syn limit rate over %d/second burst %d packets drop\n", rate, rate*2)
		}
		for _, r := range rules {
			if !r.Enabled || r.Chain != chainName {
				continue
			}
			fmt.Fprintf(&b, "    %s\n", formatFilterRule(r))
		}
		fmt.Fprintf(&b, "  }\n")
	}

	writeFilterChain("input", inPol)
	writeFilterChain("forward", fwdPol)
	writeFilterChain("output", outPol)
	fmt.Fprintf(&b, "}\n\n")

	// 2. NAT Table
	nats := append([]secplan.FirewallNATRule(nil), cfg.Firewall.NATRules...)
	sort.Slice(nats, func(i, j int) bool {
		if nats[i].Order != nats[j].Order {
			return nats[i].Order < nats[j].Order
		}
		return nats[i].ID < nats[j].ID
	})
	fmt.Fprintf(&b, "table inet daiji_nat {\n")
	fmt.Fprintf(&b, "  chain prerouting {\n    type nat hook prerouting priority dstnat; policy accept;\n")
	for _, nr := range nats {
		if !nr.Enabled || (nr.Type != "dnat" && nr.Type != "redirect") {
			continue
		}
		fmt.Fprintf(&b, "    %s\n", formatNATRule(nr))
	}
	fmt.Fprintf(&b, "  }\n")
	fmt.Fprintf(&b, "  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n")
	for _, nr := range nats {
		if !nr.Enabled || (nr.Type != "masquerade" && nr.Type != "snat") {
			continue
		}
		fmt.Fprintf(&b, "    %s\n", formatNATRule(nr))
	}
	fmt.Fprintf(&b, "  }\n}\n\n")

	// 3. Mangle / Mark / MSS Clamp Table
	mangles := append([]secplan.FirewallMangleRule(nil), cfg.Firewall.MangleRules...)
	sort.Slice(mangles, func(i, j int) bool {
		if mangles[i].Order != mangles[j].Order {
			return mangles[i].Order < mangles[j].Order
		}
		return mangles[i].ID < mangles[j].ID
	})
	fmt.Fprintf(&b, "table inet daiji_mangle {\n")
	for _, hook := range []struct {
		name string
		prio string
	}{
		{"prerouting", "mangle"},
		{"forward", "mangle"},
		{"postrouting", "mangle"},
		{"output", "mangle"},
	} {
		fmt.Fprintf(&b, "  chain %s {\n    type filter hook %s priority %s; policy accept;\n", hook.name, hook.name, hook.prio)
		for _, mr := range mangles {
			if !mr.Enabled || mr.Chain != hook.name {
				continue
			}
			fmt.Fprintf(&b, "    %s\n", formatMangleRule(mr))
		}
		fmt.Fprintf(&b, "  }\n")
	}
	fmt.Fprintf(&b, "}\n")

	// 4. Bridge L2 Port Security Table (closes Phase 1 port_security enforcement)
	var l2Rules []string
	for _, br := range cfg.Interfaces.Bridges {
		for _, p := range br.Ports {
			if p.PortSecurity != nil && p.PortSecurity.Enabled && len(p.PortSecurity.StaticMACs) > 0 {
				macs := strings.Join(p.PortSecurity.StaticMACs, ", ")
				l2Rules = append(l2Rules, fmt.Sprintf("    iifname %q ether saddr != { %s } counter drop", p.Interface, macs))
			}
		}
	}
	if len(l2Rules) > 0 {
		fmt.Fprintf(&b, "\ntable bridge daiji_l2sec {}\nflush table bridge daiji_l2sec\n")
		fmt.Fprintf(&b, "table bridge daiji_l2sec {\n  chain ingress_filter {\n    type filter hook prerouting priority -300; policy accept;\n")
		for _, line := range l2Rules {
			fmt.Fprintf(&b, "%s\n", line)
		}
		fmt.Fprintf(&b, "  }\n}\n")
	}

	return b.String()
}

func formatFilterRule(r secplan.FirewallFilterRule) string {
	var parts []string
	if r.InInterface != "" {
		parts = append(parts, fmt.Sprintf("iifname %q", r.InInterface))
	}
	if r.OutInterface != "" {
		parts = append(parts, fmt.Sprintf("oifname %q", r.OutInterface))
	}
	if r.SrcIP != "" {
		parts = append(parts, ipPrefixExpr("saddr", r.SrcIP))
	}
	if r.SrcList != "" {
		parts = append(parts, fmt.Sprintf("ip saddr @%s", sanitizeNFT(r.SrcList)))
	}
	if r.DstIP != "" {
		parts = append(parts, ipPrefixExpr("daddr", r.DstIP))
	}
	if r.DstList != "" {
		parts = append(parts, fmt.Sprintf("ip daddr @%s", sanitizeNFT(r.DstList)))
	}
	if r.Protocol != "" && r.Protocol != "any" {
		if r.SrcPort != "" {
			parts = append(parts, fmt.Sprintf("%s sport { %s }", r.Protocol, r.SrcPort))
		}
		if r.DstPort != "" {
			parts = append(parts, fmt.Sprintf("%s dport { %s }", r.Protocol, r.DstPort))
		}
		if r.SrcPort == "" && r.DstPort == "" {
			parts = append(parts, fmt.Sprintf("meta l4proto %s", r.Protocol))
		}
	}
	if len(r.ConnState) > 0 {
		parts = append(parts, fmt.Sprintf("ct state { %s }", strings.Join(r.ConnState, ", ")))
	}
	if r.MarkMatch > 0 {
		parts = append(parts, fmt.Sprintf("meta mark %d", r.MarkMatch))
	}
	parts = append(parts, "counter")
	if r.Log {
		pfx := sanitizeNFT(r.LogPrefix)
		if pfx == "" {
			pfx = "DAIJI-FW "
		}
		parts = append(parts, fmt.Sprintf("log prefix %q", pfx))
	}
	parts = append(parts, r.Action)
	if r.Comment != "" {
		parts = append(parts, fmt.Sprintf("comment %q", sanitizeNFT(r.Comment)))
	}
	return strings.Join(parts, " ")
}

func formatNATRule(nr secplan.FirewallNATRule) string {
	var parts []string
	if nr.InInterface != "" {
		parts = append(parts, fmt.Sprintf("iifname %q", nr.InInterface))
	}
	if nr.OutInterface != "" {
		parts = append(parts, fmt.Sprintf("oifname %q", nr.OutInterface))
	}
	if nr.SrcIP != "" {
		parts = append(parts, ipPrefixExpr("saddr", nr.SrcIP))
	}
	if nr.DstIP != "" {
		parts = append(parts, ipPrefixExpr("daddr", nr.DstIP))
	}
	if nr.Protocol != "" && nr.Protocol != "any" && nr.DstPort > 0 {
		parts = append(parts, fmt.Sprintf("%s dport %d", nr.Protocol, nr.DstPort))
	}
	switch nr.Type {
	case "masquerade":
		parts = append(parts, "masquerade")
	case "snat":
		parts = append(parts, "snat to "+nr.ToAddresses)
	case "dnat":
		target := nr.ToAddresses
		if nr.ToPort > 0 {
			target = fmt.Sprintf("%s:%d", nr.ToAddresses, nr.ToPort)
		}
		parts = append(parts, "dnat to "+target)
	case "redirect":
		if nr.ToPort > 0 {
			parts = append(parts, fmt.Sprintf("redirect to :%d", nr.ToPort))
		} else {
			parts = append(parts, "redirect")
		}
	}
	return strings.Join(parts, " ")
}

func formatMangleRule(mr secplan.FirewallMangleRule) string {
	var parts []string
	if mr.SrcIP != "" {
		parts = append(parts, ipPrefixExpr("saddr", mr.SrcIP))
	}
	if mr.DstIP != "" {
		parts = append(parts, ipPrefixExpr("daddr", mr.DstIP))
	}
	if mr.Protocol != "" && mr.Protocol != "any" && mr.DstPort != "" {
		parts = append(parts, fmt.Sprintf("%s dport { %s }", mr.Protocol, mr.DstPort))
	}
	if mr.MSSClampPMTU {
		parts = append(parts, "tcp flags syn tcp option maxseg size set rt mtu")
	}
	if mr.SetMark > 0 {
		parts = append(parts, fmt.Sprintf("meta mark set %d", mr.SetMark))
	}
	if mr.SetDSCP != nil {
		parts = append(parts, fmt.Sprintf("ip dscp set %d", *mr.SetDSCP))
	}
	return strings.Join(parts, " ")
}

func ipPrefixExpr(dir, cidr string) string {
	if strings.Contains(cidr, ":") {
		return "ip6 " + dir + " " + cidr
	}
	return "ip " + dir + " " + cidr
}

func defaultOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
