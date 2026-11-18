// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package ispplan

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/kangpcode/daijios/pkg/secplan"
)

// ValidateAllSemantic validates Phase 1 (netplan), Phase 2 (secplan), and Phase 3 (ispplan).
func ValidateAllSemantic(rawCfg map[string]any) error {
	if err := secplan.ValidateAllSemantic(rawCfg); err != nil {
		return err
	}
	return ValidateISPSemantic(rawCfg)
}

// ValidateISPSemantic verifies Phase 3 ISP, Multi-WAN, Telemetry, and Automation invariants.
func ValidateISPSemantic(rawCfg map[string]any) error {
	cfg, err := ParseConfig(rawCfg)
	if err != nil {
		return fmt.Errorf("parse isp config: %w", err)
	}

	var errs []string
	checkLineSafe := func(field, s string) {
		if strings.ContainsAny(s, "\r\n\x00") {
			errs = append(errs, fmt.Sprintf("%s contains forbidden control/newline characters", field))
		}
	}

	pools := make(map[string]bool)
	for _, p := range cfg.ISP.IPPools {
		if pools[p.Name] {
			errs = append(errs, fmt.Sprintf("duplicate ip_pool %q", p.Name))
		}
		pools[p.Name] = true
	}

	profiles := make(map[string]bool)
	for _, pr := range cfg.ISP.Profiles {
		if profiles[pr.Name] {
			errs = append(errs, fmt.Sprintf("duplicate isp profile %q", pr.Name))
		}
		profiles[pr.Name] = true
		if pr.AddressPool != "" && !pools[pr.AddressPool] {
			errs = append(errs, fmt.Sprintf("profile %q references unknown address_pool %q", pr.Name, pr.AddressPool))
		}
		if pr.ExpiredPool != "" && !pools[pr.ExpiredPool] {
			errs = append(errs, fmt.Sprintf("profile %q references unknown expired_pool %q", pr.Name, pr.ExpiredPool))
		}
		if pr.BurstDownloadKbps > 0 && pr.BurstDownloadKbps < pr.DownloadKbps {
			errs = append(errs, fmt.Sprintf("profile %q burst_download_kbps < download_kbps", pr.Name))
		}
	}

	hasRadiusServers := cfg.ISP.RADIUS.Client.Enabled && len(cfg.ISP.RADIUS.Client.Servers) > 0
	if cfg.ISP.RADIUS.Client.Enabled && len(cfg.ISP.RADIUS.Client.Servers) == 0 {
		errs = append(errs, "isp.radius.client.enabled=true requires at least one radius server")
	}

	for _, srv := range cfg.ISP.PPPoE.Servers {
		if !pools[srv.IPPool] {
			errs = append(errs, fmt.Sprintf("pppoe server %q references unknown ip_pool %q", srv.Name, srv.IPPool))
		}
		if srv.DefaultProfile != "" && !profiles[srv.DefaultProfile] {
			errs = append(errs, fmt.Sprintf("pppoe server %q references unknown default_profile %q", srv.Name, srv.DefaultProfile))
		}
		if srv.Enabled && srv.UseRADIUS && !hasRadiusServers {
			errs = append(errs, fmt.Sprintf("pppoe server %q has use_radius=true but radius client has no servers", srv.Name))
		}
	}

	seenUsers := make(map[string]bool)
	for _, sec := range cfg.ISP.PPPoE.Secrets {
		if seenUsers[sec.Username] {
			errs = append(errs, fmt.Sprintf("duplicate pppoe secret username %q", sec.Username))
		}
		seenUsers[sec.Username] = true
		if !profiles[sec.Profile] {
			errs = append(errs, fmt.Sprintf("pppoe secret %q references unknown profile %q", sec.Username, sec.Profile))
		}
		checkLineSafe("pppoe.secret."+sec.Username, sec.Password)
	}

	for _, hs := range cfg.ISP.Hotspot.Servers {
		if !pools[hs.AddressPool] {
			errs = append(errs, fmt.Sprintf("hotspot server %q references unknown address_pool %q", hs.Name, hs.AddressPool))
		}
		if hs.DefaultProfile != "" && !profiles[hs.DefaultProfile] {
			errs = append(errs, fmt.Sprintf("hotspot server %q references unknown default_profile %q", hs.Name, hs.DefaultProfile))
		}
	}
	for _, v := range cfg.ISP.Hotspot.Vouchers {
		if !profiles[v.Profile] {
			errs = append(errs, fmt.Sprintf("hotspot voucher %q references unknown profile %q", v.Code, v.Profile))
		}
	}

	// Multi-WAN checks.
	if cfg.ISP.MultiWAN.Enabled {
		if len(cfg.ISP.MultiWAN.WANs) == 0 {
			errs = append(errs, "isp.multi_wan.enabled=true requires at least one WAN link")
		}
		seenTables := make(map[uint32]string)
		for _, w := range cfg.ISP.MultiWAN.WANs {
			if w.RoutingTable == 0 || w.RoutingTable == 253 || w.RoutingTable == 254 || w.RoutingTable == 255 {
				errs = append(errs, fmt.Sprintf("multi_wan %q routing_table %d cannot be 0 or Linux reserved (253-255)", w.Name, w.RoutingTable))
			}
			if prev, dup := seenTables[w.RoutingTable]; dup {
				errs = append(errs, fmt.Sprintf("multi_wan %q routing_table %d duplicates %q", w.Name, w.RoutingTable, prev))
			}
			seenTables[w.RoutingTable] = w.Name
			if (w.CheckMethod == "recursive" || w.CheckMethod == "netwatch-icmp") && len(w.CheckTargets) == 0 {
				errs = append(errs, fmt.Sprintf("multi_wan %q check_method=%s requires check_targets", w.Name, w.CheckMethod))
			}
		}
	}

	// Telemetry checks.
	if cfg.Telemetry.SNMP.Enabled {
		if cfg.Telemetry.SNMP.Version == "v3" && len(cfg.Telemetry.SNMP.V3Users) == 0 {
			errs = append(errs, "telemetry.snmp version=v3 requires at least one v3_user")
		}
		if (cfg.Telemetry.SNMP.Version == "v1" || cfg.Telemetry.SNMP.Version == "v2c") && cfg.Telemetry.SNMP.CommunityRO == "" {
			errs = append(errs, "telemetry.snmp v1/v2c requires community_ro")
		}
		checkLineSafe("snmp.sys_location", cfg.Telemetry.SNMP.SysLocation)
		checkLineSafe("snmp.sys_contact", cfg.Telemetry.SNMP.SysContact)
	}

	// Automation cross-references.
	scripts := make(map[string]bool)
	for _, sc := range cfg.Automation.Scripts {
		scripts[sc.Name] = true
	}
	webhooks := make(map[string]bool)
	for _, wh := range cfg.Automation.Webhooks {
		webhooks[wh.Name] = true
		u, err := url.Parse(wh.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			errs = append(errs, fmt.Sprintf("webhook %q url must be http or https", wh.Name))
		}
	}
	for _, sch := range cfg.Automation.Schedules {
		if !scripts[sch.ScriptName] {
			errs = append(errs, fmt.Sprintf("schedule %q references unknown script %q", sch.Name, sch.ScriptName))
		}
	}
	for _, eh := range cfg.Automation.EventHooks {
		if eh.ScriptName != "" && !scripts[eh.ScriptName] {
			errs = append(errs, fmt.Sprintf("event_hook %q references unknown script %q", eh.Name, eh.ScriptName))
		}
		if eh.WebhookName != "" && !webhooks[eh.WebhookName] {
			errs = append(errs, fmt.Sprintf("event_hook %q references unknown webhook %q", eh.Name, eh.WebhookName))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
