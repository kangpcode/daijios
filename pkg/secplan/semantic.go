// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package secplan

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kangpcode/daijios/pkg/netplan"
)

// ValidateAllSemantic enforces both Phase 1 networking invariants and Phase 2 security/QoS/VPN policies.
func ValidateAllSemantic(rawCfg map[string]any) error {
	if err := netplan.ValidateSemantic(rawCfg); err != nil {
		return err
	}
	return ValidateSecuritySemantic(rawCfg)
}

// ValidateSecuritySemantic verifies Phase 2 Firewall, QoS, VPN, and Hardening invariants.
func ValidateSecuritySemantic(rawCfg map[string]any) error {
	cfg, err := ParseConfig(rawCfg)
	if err != nil {
		return fmt.Errorf("parse security config: %w", err)
	}

	var errs []string
	checkLineSafe := func(field, s string) {
		if strings.ContainsAny(s, "\r\n\x00;{}") {
			errs = append(errs, fmt.Sprintf("%s contains forbidden control or template delimiter characters", field))
		}
	}

	knownBridges := make(map[string]bool)
	for _, br := range cfg.Interfaces.Bridges {
		knownBridges[br.Name] = true
	}

	// Firewall address-lists & rule consistency.
	listNames := make(map[string]bool)
	for _, al := range cfg.Firewall.AddressLists {
		if listNames[al.Name] {
			errs = append(errs, fmt.Sprintf("duplicate firewall address_list %q", al.Name))
		}
		listNames[al.Name] = true
		for _, ent := range al.Entries {
			checkLineSafe("address_list."+al.Name+".comment", ent.Comment)
		}
	}

	for _, sig := range cfg.Firewall.L7DPI.CustomSignatures {
		if sig.PayloadRegex != "" {
			if _, err := regexp.Compile(sig.PayloadRegex); err != nil {
				errs = append(errs, fmt.Sprintf("invalid DPI regex on %q: %v", sig.Name, err))
			}
		}
	}

	seenFilterIDs := make(map[string]bool)
	for _, fr := range cfg.Firewall.FilterRules {
		if seenFilterIDs[fr.ID] {
			errs = append(errs, fmt.Sprintf("duplicate firewall filter rule id %q", fr.ID))
		}
		seenFilterIDs[fr.ID] = true
		if fr.SrcList != "" && !listNames[fr.SrcList] {
			errs = append(errs, fmt.Sprintf("filter rule %q references unknown src_list %q", fr.ID, fr.SrcList))
		}
		if fr.DstList != "" && !listNames[fr.DstList] {
			errs = append(errs, fmt.Sprintf("filter rule %q references unknown dst_list %q", fr.ID, fr.DstList))
		}
		checkLineSafe("filter."+fr.ID+".log_prefix", fr.LogPrefix)
		checkLineSafe("filter."+fr.ID+".comment", fr.Comment)
	}

	for _, nr := range cfg.Firewall.NATRules {
		if (nr.Type == "dnat" || nr.Type == "snat") && nr.ToAddresses == "" {
			errs = append(errs, fmt.Sprintf("nat rule %q (%s) requires to_addresses", nr.ID, nr.Type))
		}
		if nr.Type == "masquerade" && nr.OutInterface == "" {
			errs = append(errs, fmt.Sprintf("nat masquerade rule %q requires out_interface", nr.ID))
		}
		checkLineSafe("nat."+nr.ID+".comment", nr.Comment)
	}

	// QoS validations.
	rootSched := make(map[string]string)
	for _, qi := range cfg.QoS.Interfaces {
		rootSched[qi.Interface] = qi.Scheduler
	}
	for _, qt := range cfg.QoS.QueueTrees {
		if sc, ok := rootSched[qt.ParentInterface]; ok && sc != "htb" {
			errs = append(errs, fmt.Sprintf("qos queue_tree %q requires root scheduler 'htb' on %s (got %q)", qt.Name, qt.ParentInterface, sc))
		}
		if qt.RateKbps > qt.CeilKbps {
			errs = append(errs, fmt.Sprintf("qos queue_tree %q rate_kbps (%d) exceeds ceil_kbps (%d)", qt.Name, qt.RateKbps, qt.CeilKbps))
		}
	}
	for _, sq := range cfg.QoS.SimpleQueues {
		if sc, ok := rootSched[sq.Interface]; ok && sc != "htb" {
			errs = append(errs, fmt.Sprintf("qos simple_queue %q requires root scheduler 'htb' on %s (got %q)", sq.Name, sq.Interface, sc))
		}
		if sq.BurstUploadKbps > 0 && sq.BurstUploadKbps < sq.MaxUploadKbps {
			errs = append(errs, fmt.Sprintf("qos simple_queue %q burst_upload_kbps (%d) must be >= max_upload_kbps (%d)",
				sq.Name, sq.BurstUploadKbps, sq.MaxUploadKbps))
		}
		if sq.BurstDownloadKbps > 0 && sq.BurstDownloadKbps < sq.MaxDownloadKbps {
			errs = append(errs, fmt.Sprintf("qos simple_queue %q burst_download_kbps (%d) must be >= max_download_kbps (%d)",
				sq.Name, sq.BurstDownloadKbps, sq.MaxDownloadKbps))
		}
	}

	// VPN validations.
	wgPorts := make(map[int]string)
	for _, wg := range cfg.VPN.WireGuard {
		if prev, dup := wgPorts[wg.ListenPort]; dup {
			errs = append(errs, fmt.Sprintf("wireguard listen_port %d duplicated on %s and %s", wg.ListenPort, prev, wg.Interface))
		}
		wgPorts[wg.ListenPort] = wg.Interface
		checkLineSafe("wireguard."+wg.Interface+".private_key", wg.PrivateKey)
	}
	if cfg.VPN.IPsec.Enabled {
		for _, tun := range cfg.VPN.IPsec.Tunnels {
			if tun.AuthMethod == "psk" && len(tun.PSK) < 12 {
				errs = append(errs, fmt.Sprintf("ipsec tunnel %q auth_method=psk requires psk >= 12 chars", tun.Name))
			}
			checkLineSafe("ipsec."+tun.Name+".psk", tun.PSK)
		}
	}
	if cfg.VPN.L2TP.Enabled && len(cfg.VPN.L2TP.IPsecPSK) < 12 {
		errs = append(errs, "vpn.l2tp.enabled=true requires ipsec_psk >= 12 chars")
	}
	if cfg.VPN.PPTP.Enabled && !cfg.VPN.PPTP.LegacyAcknowledged {
		errs = append(errs, "vpn.pptp uses cryptographically weak MS-CHAPv2; set legacy_acknowledged=true to explicitly permit")
	}
	eoipIDs := make(map[int]string)
	for _, eo := range cfg.VPN.EoIP {
		if prev, dup := eoipIDs[eo.TunnelID]; dup {
			errs = append(errs, fmt.Sprintf("duplicate EoIP tunnel_id %d (%s and %s)", eo.TunnelID, prev, eo.Name))
		}
		eoipIDs[eo.TunnelID] = eo.Name
		if eo.Bridge != "" && !knownBridges[eo.Bridge] {
			errs = append(errs, fmt.Sprintf("eoip tunnel %q references unknown bridge %q", eo.Name, eo.Bridge))
		}
	}

	// Hardening checks.
	if cfg.Security.SSHHardening.PermitRootLogin {
		errs = append(errs, "security.ssh_hardening.permit_root_login=true violates DaijiOS hardening policy")
	}
	if cfg.Security.FirmwareSecurity.RequireSignedAB && !cfg.Updates.RequireSignature {
		errs = append(errs, "updates.require_signature must remain true when security.firmware_security.require_signed_ab=true")
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
