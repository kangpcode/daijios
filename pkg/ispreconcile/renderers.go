// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package ispreconcile implements idempotent Phase 3 reconcilers for accel-ppp
// (PPPoE/IPoE), FreeRADIUS, Hotspot captive portal & Multi-WAN PCC nftables,
// IPFIX/NetFlow, SNMP v1/2c/v3, and Syslog.
package ispreconcile

import (
	"fmt"
	"strings"

	"github.com/kangpcode/daijios/pkg/ispplan"
)

const secretMask = "***REDACTED***"

func sanitizeLine(s string) string {
	return strings.NewReplacer("\r", "", "\n", " ", "\x00", "").Replace(s)
}

// RenderAccelPPP generates /etc/accel-ppp.conf for PPPoE & IPoE BNG termination.
func RenderAccelPPP(cfg *ispplan.FullISPConfig, redactSecrets bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	fmt.Fprintf(&b, "[modules]\nlog_syslog\n")
	if len(cfg.ISP.PPPoE.Servers) > 0 {
		fmt.Fprintf(&b, "pppoe\n")
	}
	if len(cfg.ISP.IPoE.Servers) > 0 {
		fmt.Fprintf(&b, "ipoe\n")
	}
	fmt.Fprintf(&b, "auth_pap\nauth_chap_md5\nauth_mschap_v2\n")
	if cfg.ISP.RADIUS.Client.Enabled {
		fmt.Fprintf(&b, "radius\n")
	}
	fmt.Fprintf(&b, "ippool\nshaper\n\n[core]\nlog-error=/var/log/accel-ppp/core.log\nthread-count=4\n\n")

	if len(cfg.ISP.PPPoE.Servers) > 0 {
		srv := cfg.ISP.PPPoE.Servers[0]
		fmt.Fprintf(&b, "[pppoe]\nverbose=1\nac-name=%s\n", sanitizeLine(srv.ACName))
		if srv.ServiceName != "" {
			fmt.Fprintf(&b, "service-name=%s\n", sanitizeLine(srv.ServiceName))
		}
		for _, s := range cfg.ISP.PPPoE.Servers {
			if s.Enabled {
				fmt.Fprintf(&b, "interface=%s\n", s.Interface)
			}
		}
		fmt.Fprintf(&b, "ip-pool=%s\nmtu=%d\nmru=%d\n", srv.IPPool, srv.MTU, srv.MRU)
		if srv.LocalIP != "" {
			fmt.Fprintf(&b, "local-ip=%s\n", srv.LocalIP)
		}
		fmt.Fprintf(&b, "\n")
	}

	if len(cfg.ISP.IPoE.Servers) > 0 {
		fmt.Fprintf(&b, "[ipoe]\nverbose=1\n")
		for _, ipoe := range cfg.ISP.IPoE.Servers {
			if ipoe.Enabled {
				fmt.Fprintf(&b, "interface=%s,mode=L2,shared=1,ifcfg=1\n", ipoe.Interface)
			}
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "[ip-pool]\n")
	for _, pool := range cfg.ISP.IPPools {
		for _, rng := range pool.Ranges {
			fmt.Fprintf(&b, "%s,name=%s\n", rng, pool.Name)
		}
	}
	fmt.Fprintf(&b, "\n")

	if cfg.ISP.RADIUS.Client.Enabled {
		rc := cfg.ISP.RADIUS.Client
		fmt.Fprintf(&b, "[radius]\nnas-identifier=%s\n", sanitizeLine(rc.NASIdentifier))
		if rc.NASIP != "" {
			fmt.Fprintf(&b, "nas-ip-address=%s\n", rc.NASIP)
		}
		for _, rs := range rc.Servers {
			sec := rs.Secret
			if redactSecrets {
				sec = secretMask
			}
			fmt.Fprintf(&b, "server=%s,%s,auth-port=%d,acct-port=%d,req-limit=50,fail-timeout=5\n",
				rs.Host, sec, rs.AuthPort, rs.AcctPort)
		}
		if rc.CoAEnabled {
			coaSec := rc.CoASecret
			if redactSecrets {
				coaSec = secretMask
			}
			fmt.Fprintf(&b, "dae-server=0.0.0.0:%d,%s\n", rc.CoAPort, coaSec)
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

// RenderFreeRADIUSClients renders /etc/freeradius/3.0/clients.conf.
func RenderFreeRADIUSClients(cfg *ispplan.FullISPConfig, redactSecrets bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	if !cfg.ISP.RADIUS.Server.Enabled {
		return b.String()
	}
	for _, cl := range cfg.ISP.RADIUS.Server.Clients {
		sec := cl.Secret
		if redactSecrets {
			sec = secretMask
		}
		fmt.Fprintf(&b, "client %s {\n  ipaddr = %s\n  secret = %q\n}\n", sanitizeLine(cl.Name), cl.CIDR, sec)
	}
	return b.String()
}

// RenderMultiWANNFT renders /etc/nftables.d/daiji-mwan.nft for PCC load balancing & Hotspot walled garden.
func RenderMultiWANNFT(cfg *ispplan.FullISPConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#!/usr/sbin/nft -f\n# DaijiOS Multi-WAN PCC & Hotspot Captive Rules\n")
	fmt.Fprintf(&b, "table inet daiji_isp {}\nflush table inet daiji_isp\n")
	fmt.Fprintf(&b, "table inet daiji_isp {\n")

	if cfg.ISP.MultiWAN.Enabled && len(cfg.ISP.MultiWAN.WANs) > 0 {
		totalW := 0
		for _, w := range cfg.ISP.MultiWAN.WANs {
			if w.Enabled {
				totalW += w.Weight
			}
		}
		if totalW > 0 {
			fmt.Fprintf(&b, "  chain mwan_prerouting {\n    type filter hook prerouting priority mangle; policy accept;\n")
			if cfg.ISP.MultiWAN.Mode == "load-balance-pcc" {
				cur := 0
				for _, w := range cfg.ISP.MultiWAN.WANs {
					if !w.Enabled || w.Weight <= 0 {
						continue
					}
					hi := cur + w.Weight - 1
					mark := 100 + int(w.RoutingTable)
					if cur == hi {
						fmt.Fprintf(&b, "    ct state new jhash ip saddr . ip daddr . tcp sport . tcp dport mod %d == %d meta mark set %d ct mark set meta mark\n",
							totalW, cur, mark)
					} else {
						fmt.Fprintf(&b, "    ct state new jhash ip saddr . ip daddr . tcp sport . tcp dport mod %d %d-%d meta mark set %d ct mark set meta mark\n",
							totalW, cur, hi, mark)
					}
					cur += w.Weight
				}
				fmt.Fprintf(&b, "    ct mark != 0 meta mark set ct mark\n")
			}
			fmt.Fprintf(&b, "  }\n")
		}
	}

	if len(cfg.ISP.Hotspot.Servers) > 0 {
		fmt.Fprintf(&b, "  set hotspot_auth_macs {\n    type ether_addr\n    flags timeout\n  }\n")
		fmt.Fprintf(&b, "  chain hotspot_redirect {\n    type nat hook prerouting priority dstnat; policy accept;\n")
		for _, hs := range cfg.ISP.Hotspot.Servers {
			if !hs.Enabled {
				continue
			}
			for _, wg := range hs.WalledGardenCIDRs {
				fmt.Fprintf(&b, "    iifname %q ip daddr %s accept\n", hs.Interface, wg)
			}
			fmt.Fprintf(&b, "    iifname %q ether saddr != @hotspot_auth_macs tcp dport 80 redirect to :8080\n", hs.Interface)
		}
		fmt.Fprintf(&b, "  }\n")
	}

	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// RenderSNMPD generates /etc/snmp/snmpd.conf supporting v1/v2c and hardened SNMPv3 (SHA256/AES128).
func RenderSNMPD(cfg *ispplan.FullISPConfig, redactSecrets bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	if !cfg.Telemetry.SNMP.Enabled {
		return b.String()
	}
	port := cfg.Telemetry.SNMP.Port
	if port <= 0 {
		port = 161
	}
	addr := cfg.Telemetry.SNMP.ListenAddress
	if addr == "" {
		addr = "0.0.0.0"
	}
	fmt.Fprintf(&b, "agentAddress udp:%s:%d\n", addr, port)
	if cfg.Telemetry.SNMP.SysLocation != "" {
		fmt.Fprintf(&b, "sysLocation %s\n", sanitizeLine(cfg.Telemetry.SNMP.SysLocation))
	}
	if cfg.Telemetry.SNMP.SysContact != "" {
		fmt.Fprintf(&b, "sysContact %s\n", sanitizeLine(cfg.Telemetry.SNMP.SysContact))
	}
	if cfg.Telemetry.SNMP.Version == "v3" {
		for _, u := range cfg.Telemetry.SNMP.V3Users {
			ap := u.AuthPass
			pp := u.PrivPass
			if redactSecrets {
				ap = secretMask
				pp = secretMask
			}
			fmt.Fprintf(&b, "createUser %s %s %q %s %q\nrouser %s authPriv\n",
				u.Username, strings.ToUpper(u.AuthProto), ap, strings.ToUpper(u.PrivProto), pp, u.Username)
		}
	} else if cfg.Telemetry.SNMP.CommunityRO != "" {
		comm := cfg.Telemetry.SNMP.CommunityRO
		if redactSecrets {
			comm = secretMask
		}
		fmt.Fprintf(&b, "rocommunity %s\n", comm)
	}
	return b.String()
}

// RenderRsyslog generates /etc/rsyslog.d/99-daiji.conf for local & remote TLS/TCP/UDP syslog.
func RenderRsyslog(cfg *ispplan.FullISPConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	if !cfg.Telemetry.Syslog.Enabled {
		return b.String()
	}
	for _, t := range cfg.Telemetry.Syslog.RemoteTargets {
		protoPrefix := "@"
		if t.Proto == "tcp" || t.Proto == "tls" {
			protoPrefix = "@@"
		}
		fmt.Fprintf(&b, "*.%s %s%s:%d\n", t.MinSeverity, protoPrefix, sanitizeLine(t.Host), t.Port)
	}
	return b.String()
}

// RenderNetFlow generates /etc/daiji/netflow.conf for IPFIX/NetFlow collectors.
func RenderNetFlow(cfg *ispplan.FullISPConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	if !cfg.Telemetry.NetFlow.Enabled {
		return b.String()
	}
	fmt.Fprintf(&b, "version=%s\nactive_timeout=%d\nsampling_rate=%d\n",
		cfg.Telemetry.NetFlow.Version, cfg.Telemetry.NetFlow.ActiveTimeoutSec, cfg.Telemetry.NetFlow.SamplingRate)
	for _, c := range cfg.Telemetry.NetFlow.Collectors {
		fmt.Fprintf(&b, "collector=%s:%d\n", c.Host, c.Port)
	}
	return b.String()
}
