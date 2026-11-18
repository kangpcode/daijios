// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package secreconcile

import (
	"fmt"
	"strings"

	"github.com/kangpcode/daijios/pkg/secplan"
)

const secretMask = "***REDACTED***"

// RenderWireGuardConfig emits wg-quick/wg setconf configuration for a WireGuard interface.
func RenderWireGuardConfig(wg secplan.WireGuardInterface, redactSecrets bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	fmt.Fprintf(&b, "[Interface]\n")
	pk := wg.PrivateKey
	if redactSecrets {
		pk = secretMask
	}
	fmt.Fprintf(&b, "PrivateKey = %s\n", pk)
	fmt.Fprintf(&b, "ListenPort = %d\n", wg.ListenPort)
	for _, p := range wg.Peers {
		fmt.Fprintf(&b, "\n[Peer]\n# %s\n", p.Name)
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			psk := p.PresharedKey
			if redactSecrets {
				psk = secretMask
			}
			fmt.Fprintf(&b, "PresharedKey = %s\n", psk)
		}
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.PersistentKeepalive)
		}
	}
	return b.String()
}

// RenderSwanctlConfig emits strongSwan IKEv2 / IPsec configuration (/etc/swanctl/conf.d/daiji.conf).
func RenderSwanctlConfig(cfg *secplan.SecurityConfig, redactSecrets bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	if !cfg.VPN.IPsec.Enabled {
		return b.String()
	}
	fmt.Fprintf(&b, "connections {\n")
	for _, t := range cfg.VPN.IPsec.Tunnels {
		if !t.Enabled {
			continue
		}
		ikeProp := t.IKEProposals
		if ikeProp == "" {
			ikeProp = "aes256gcm16-prfsha384-ecp384"
		}
		espProp := t.ESPProposals
		if espProp == "" {
			espProp = "aes256gcm16-ecp384"
		}
		dpd := t.DPDDelaySec
		if dpd <= 0 {
			dpd = 30
		}
		fmt.Fprintf(&b, "  %s {\n", t.Name)
		fmt.Fprintf(&b, "    version = 2\n")
		fmt.Fprintf(&b, "    local_addrs = %s\n", t.LocalIP)
		fmt.Fprintf(&b, "    remote_addrs = %s\n", t.RemoteIP)
		fmt.Fprintf(&b, "    proposals = %s\n", ikeProp)
		fmt.Fprintf(&b, "    dpd_delay = %ds\n", dpd)
		fmt.Fprintf(&b, "    local {\n      auth = %s\n    }\n", t.AuthMethod)
		fmt.Fprintf(&b, "    remote {\n      auth = %s\n    }\n", t.AuthMethod)
		fmt.Fprintf(&b, "    children {\n      %s-child {\n", t.Name)
		fmt.Fprintf(&b, "        local_ts = %s\n", strings.Join(t.LocalTS, ","))
		fmt.Fprintf(&b, "        remote_ts = %s\n", strings.Join(t.RemoteTS, ","))
		fmt.Fprintf(&b, "        esp_proposals = %s\n", espProp)
		if t.VTIKey > 0 {
			fmt.Fprintf(&b, "        mark_in = %d\n        mark_out = %d\n", t.VTIKey, t.VTIKey)
		}
		fmt.Fprintf(&b, "      }\n    }\n  }\n")
	}
	fmt.Fprintf(&b, "}\n\nsecrets {\n")
	for _, t := range cfg.VPN.IPsec.Tunnels {
		if !t.Enabled || t.AuthMethod != "psk" || t.PSK == "" {
			continue
		}
		psk := t.PSK
		if redactSecrets {
			psk = secretMask
		}
		fmt.Fprintf(&b, "  ike-%s {\n    id = %s\n    secret = %q\n  }\n", t.Name, t.RemoteIP, psk)
	}
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// RenderOpenVPNConfig emits hardened OpenVPN server/client configuration.
func RenderOpenVPNConfig(ov secplan.OpenVPNInstance) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	if ov.Role == "server" {
		fmt.Fprintf(&b, "mode server\ntls-server\n")
	} else {
		fmt.Fprintf(&b, "client\n")
		if ov.RemoteHost != "" {
			fmt.Fprintf(&b, "remote %s %d\n", ov.RemoteHost, ov.Port)
		}
	}
	fmt.Fprintf(&b, "proto %s\nport %d\ndev %s\n", defaultOr(ov.Proto, "udp"), ov.Port, defaultOr(ov.DevType, "tun"))
	fmt.Fprintf(&b, "data-ciphers %s\ntls-version-min 1.3\n", defaultOr(ov.Cipher, "AES-256-GCM"))
	if ov.CACert != "" {
		fmt.Fprintf(&b, "ca %s\n", ov.CACert)
	}
	if ov.Cert != "" {
		fmt.Fprintf(&b, "cert %s\n", ov.Cert)
	}
	if ov.PrivateKeyPath != "" {
		fmt.Fprintf(&b, "key %s\n", ov.PrivateKeyPath)
	}
	if ov.Subnet != "" && ov.Role == "server" {
		fmt.Fprintf(&b, "# pool_cidr %s\n", ov.Subnet)
	}
	fmt.Fprintf(&b, "persist-key\npersist-tun\n")
	return b.String()
}

// RenderL2TPAndSSTPConfigs renders L2TP/xl2tpd and SSTP/PPTP tunnel daemon descriptors.
func RenderL2TPConfig(cfg *secplan.SecurityConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "; DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	if !cfg.VPN.L2TP.Enabled {
		return b.String()
	}
	fmt.Fprintf(&b, "[global]\nlisten-addr = %s\n\n[lns default]\nip range = %s\nlocal ip = %s\nrequire chap = yes\nrefuse pap = yes\n",
		cfg.VPN.L2TP.ListenIP, cfg.VPN.L2TP.ClientPool, cfg.VPN.L2TP.LocalIP)
	return b.String()
}

func RenderSSTPConfig(cfg *secplan.SecurityConfig) string {
	if !cfg.VPN.SSTP.Enabled {
		return "# SSTP disabled\n"
	}
	return fmt.Sprintf("# DaijiOS SSTP Server\nlisten_port=%d\ncert=%s\nkey=%s\npool=%s\n",
		cfg.VPN.SSTP.ListenPort, cfg.VPN.SSTP.CertPath, cfg.VPN.SSTP.PrivateKeyPath, cfg.VPN.SSTP.ClientPool)
}
