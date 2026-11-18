// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package wlanreconcile implements idempotent Phase 4 reconcilers for hostapd
// (WPA2/WPA3/Enterprise, 802.11k/v/r, guest isolation), 802.11s Mesh, and nftables guest L2/L3 isolation.
package wlanreconcile

import (
	"fmt"
	"strings"

	"github.com/kangpcode/daijios/pkg/wlanplan"
)

const secretMask = "***REDACTED***"

func sanitizeLine(s string) string {
	return strings.NewReplacer("\r", "", "\n", " ", "\x00", "").Replace(s)
}

// RenderHostapdConfig generates multi-BSS hostapd configuration for local radio / AP profile rendering.
func RenderHostapdConfig(cfg *wlanplan.WirelessBlock, redactSecrets bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	if !cfg.Controller.Enabled || len(cfg.SSIDs) == 0 {
		return b.String()
	}
	cc := cfg.Controller.CountryCode
	if cc == "" {
		cc = "ID"
	}

	first := true
	idx := 0
	for _, s := range cfg.SSIDs {
		if !s.Enabled {
			continue
		}
		iface := fmt.Sprintf("wlan0_%d", idx)
		if first {
			iface = "wlan0"
			fmt.Fprintf(&b, "interface=%s\ndriver=nl80211\ncountry_code=%s\nieee80211d=1\nieee80211n=1\nieee80211ac=1\nieee80211ax=1\n",
				iface, cc)
			first = false
		} else {
			fmt.Fprintf(&b, "\nbss=%s\n", iface)
		}
		idx++

		if s.Bridge != "" {
			fmt.Fprintf(&b, "bridge=%s\n", sanitizeLine(s.Bridge))
		}
		fmt.Fprintf(&b, "ssid=%s\n", sanitizeLine(s.SSID))
		if s.Hidden {
			fmt.Fprintf(&b, "ignore_broadcast_ssid=1\n")
		}
		if s.MaxClients > 0 {
			fmt.Fprintf(&b, "max_num_sta=%d\n", s.MaxClients)
		}
		if s.GuestIsolation.ClientIsolation {
			fmt.Fprintf(&b, "ap_isolate=1\n")
		}
		if s.Roaming.Dot11k {
			fmt.Fprintf(&b, "rrm_neighbor_report=1\nrrm_beacon_report=1\n")
		}
		if s.Roaming.Dot11v {
			fmt.Fprintf(&b, "bss_transition=1\nwnm_sleep_mode=1\n")
		}
		if s.Roaming.Dot11r {
			md := s.Roaming.MobilityDomain
			if md == "" {
				md = "4441"
			}
			r0kh := s.Roaming.R0KHKey
			if redactSecrets {
				r0kh = secretMask
			}
			fmt.Fprintf(&b, "ieee80211r=1\nmobility_domain=%s\nft_over_ds=1\nft_psk_generate_local=1\nr0kh=ff:ff:ff:ff:ff:ff * %s\nr1kh=00:00:00:00:00:00 00:00:00:00:00:00 %s\n",
				md, r0kh, r0kh)
		}

		pass := sanitizeLine(s.Passphrase)
		radSec := sanitizeLine(s.RadiusSecret)
		if redactSecrets {
			pass = secretMask
			radSec = secretMask
		}

		switch s.SecurityMode {
		case "open", "captive-portal":
			fmt.Fprintf(&b, "auth_algs=1\nwpa=0\n")
		case "wpa2-psk":
			fmt.Fprintf(&b, "wpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nieee80211w=1\nwpa_passphrase=%s\n", pass)
		case "wpa3-sae":
			fmt.Fprintf(&b, "wpa=2\nwpa_key_mgmt=SAE\nrsn_pairwise=CCMP\nieee80211w=2\nsae_password=%s\n", pass)
		case "wpa2-wpa3-mixed":
			fmt.Fprintf(&b, "wpa=2\nwpa_key_mgmt=WPA-PSK SAE\nrsn_pairwise=CCMP\nieee80211w=1\nwpa_passphrase=%s\nsae_password=%s\n", pass, pass)
		case "wpa2-enterprise":
			fmt.Fprintf(&b, "ieee8021x=1\nwpa=2\nwpa_key_mgmt=WPA-EAP\nrsn_pairwise=CCMP\nieee80211w=1\nauth_server_addr=%s\nauth_server_port=%d\nauth_server_shared_secret=%s\n",
				s.RadiusServer, defaultPort(s.RadiusPort, 1812), radSec)
		case "wpa3-enterprise":
			fmt.Fprintf(&b, "ieee8021x=1\nwpa=2\nwpa_key_mgmt=WPA-EAP-SHA256\nrsn_pairwise=CCMP\nieee80211w=2\nauth_server_addr=%s\nauth_server_port=%d\nauth_server_shared_secret=%s\n",
				s.RadiusServer, defaultPort(s.RadiusPort, 1812), radSec)
		}
	}
	return b.String()
}

// RenderMeshConfig renders /etc/wpa_supplicant/daiji-mesh.conf for 802.11s SAE Mesh backhaul.
func RenderMeshConfig(cfg *wlanplan.WirelessBlock, redactSecrets bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	if !cfg.Mesh.Enabled {
		return b.String()
	}
	pw := sanitizeLine(cfg.Mesh.SAEPassword)
	if redactSecrets {
		pw = secretMask
	}
	cc := cfg.Controller.CountryCode
	if cc == "" {
		cc = "ID"
	}
	fmt.Fprintf(&b, "country=%s\nuser_mpm=1\nsae_pwe=2\n\nnetwork={\n  ssid=%q\n  mode=5\n  frequency=5180\n  key_mgmt=SAE\n  psk=%q\n  ieee80211w=2\n}\n",
		cc, sanitizeLine(cfg.Mesh.MeshID), pw)
	return b.String()
}

// RenderWLANGuestNFT renders /etc/nftables.d/daiji-wlan.nft enforcing guest LAN CIDR isolation.
func RenderWLANGuestNFT(cfg *wlanplan.WirelessBlock) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#!/usr/sbin/nft -f\n# DaijiOS Guest WiFi Isolation\n")
	fmt.Fprintf(&b, "table inet daiji_wlan {}\nflush table inet daiji_wlan\n")
	fmt.Fprintf(&b, "table inet daiji_wlan {\n  chain guest_forward {\n    type filter hook forward priority -10; policy accept;\n")
	for _, s := range cfg.SSIDs {
		if !s.Enabled || s.Bridge == "" || len(s.GuestIsolation.BlockLANCIDRs) == 0 {
			continue
		}
		// Permit essential DNS/DHCP before blocking internal RFC1918 LAN access.
		fmt.Fprintf(&b, "    iifname %q udp dport { 53, 67 } accept\n", s.Bridge)
		fmt.Fprintf(&b, "    iifname %q tcp dport 53 accept\n", s.Bridge)
		for _, cidr := range s.GuestIsolation.BlockLANCIDRs {
			fmt.Fprintf(&b, "    iifname %q ip daddr %s counter drop\n", s.Bridge, cidr)
		}
	}
	fmt.Fprintf(&b, "  }\n}\n")
	return b.String()
}

func defaultPort(p, fallback int) int {
	if p <= 0 {
		return fallback
	}
	return p
}
