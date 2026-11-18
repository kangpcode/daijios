// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package wlanplan

import (
	"fmt"
	"strings"

	"github.com/kangpcode/daijios/pkg/ispplan"
)

// ValidateAllSemantic validates Phase 1..4 invariants across the entire schema.
func ValidateAllSemantic(rawCfg map[string]any) error {
	if err := ispplan.ValidateAllSemantic(rawCfg); err != nil {
		return err
	}
	return ValidateWirelessSemantic(rawCfg)
}

// ValidateWirelessSemantic verifies Phase 4 Wireless Controller, SSID, RF, AP, and Mesh invariants.
func ValidateWirelessSemantic(rawCfg map[string]any) error {
	cfg, err := ParseConfig(rawCfg)
	if err != nil {
		return fmt.Errorf("parse wireless config: %w", err)
	}
	w := cfg.Wireless
	var errs []string
	checkSafe := func(field, val string) {
		if strings.ContainsAny(val, "\r\n\x00") {
			errs = append(errs, fmt.Sprintf("%s contains forbidden control/newline characters", field))
		}
	}

	if w.Controller.Enabled {
		checkSafe("wireless.controller.ac_name", w.Controller.ACName)
		if w.Controller.AutoAdoptPolicy == "zero-touch-token" && len(w.Controller.OnboardingToken) < 12 {
			errs = append(errs, "wireless.controller zero-touch-token policy requires onboarding_token >= 12 chars")
		}
	}

	ssids := make(map[string]bool)
	for _, s := range w.SSIDs {
		if ssids[s.Name] {
			errs = append(errs, fmt.Sprintf("duplicate wireless ssid template %q", s.Name))
		}
		ssids[s.Name] = true
		checkSafe("wireless.ssid."+s.Name+".ssid", s.SSID)
		checkSafe("wireless.ssid."+s.Name+".passphrase", s.Passphrase)

		switch s.SecurityMode {
		case "wpa2-psk", "wpa3-sae", "wpa2-wpa3-mixed":
			if len(s.Passphrase) < 8 {
				errs = append(errs, fmt.Sprintf("ssid %q (%s) requires passphrase >= 8 chars", s.Name, s.SecurityMode))
			}
		case "wpa2-enterprise", "wpa3-enterprise":
			if s.RadiusServer == "" || len(s.RadiusSecret) < 8 {
				errs = append(errs, fmt.Sprintf("ssid %q (%s) requires radius_server and radius_secret", s.Name, s.SecurityMode))
			}
		}
		if s.Roaming.Dot11r && len(s.Roaming.R0KHKey) < 16 {
			errs = append(errs, fmt.Sprintf("ssid %q with 802.11r enabled requires r0kh_key >= 16 chars", s.Name))
		}
	}

	rfProfiles := make(map[string]bool)
	for _, rf := range w.RFProfiles {
		if rfProfiles[rf.Name] {
			errs = append(errs, fmt.Sprintf("duplicate rf_profile %q", rf.Name))
		}
		rfProfiles[rf.Name] = true
		if rf.AutoPower.Enabled && rf.AutoPower.MinTxDBm > rf.AutoPower.MaxTxDBm {
			errs = append(errs, fmt.Sprintf("rf_profile %q min_tx_dbm (%d) > max_tx_dbm (%d)",
				rf.Name, rf.AutoPower.MinTxDBm, rf.AutoPower.MaxTxDBm))
		}
	}

	apGroups := make(map[string]bool)
	for _, g := range w.APGroups {
		if apGroups[g.Name] {
			errs = append(errs, fmt.Sprintf("duplicate ap_group %q", g.Name))
		}
		apGroups[g.Name] = true
		if !rfProfiles[g.RFProfile] {
			errs = append(errs, fmt.Sprintf("ap_group %q references unknown rf_profile %q", g.Name, g.RFProfile))
		}
		for _, sName := range g.SSIDs {
			if !ssids[sName] {
				errs = append(errs, fmt.Sprintf("ap_group %q references unknown ssid %q", g.Name, sName))
			}
		}
	}

	if w.Controller.DefaultAPGroup != "" && !apGroups[w.Controller.DefaultAPGroup] {
		errs = append(errs, fmt.Sprintf("wireless.controller.default_ap_group %q does not exist", w.Controller.DefaultAPGroup))
	}

	apMACs := make(map[string]bool)
	apNames := make(map[string]bool)
	meshRoots := 0
	for _, ap := range w.APs {
		normMAC := strings.ToLower(ap.MAC)
		if apMACs[normMAC] {
			errs = append(errs, fmt.Sprintf("duplicate managed AP mac %q", ap.MAC))
		}
		apMACs[normMAC] = true
		if apNames[ap.Name] {
			errs = append(errs, fmt.Sprintf("duplicate managed AP name %q", ap.Name))
		}
		apNames[ap.Name] = true
		if !apGroups[ap.APGroup] {
			errs = append(errs, fmt.Sprintf("managed AP %q references unknown ap_group %q", ap.Name, ap.APGroup))
		}
		if ap.MeshRole == "root" && ap.Enabled {
			meshRoots++
		}
	}

	if w.Mesh.Enabled {
		checkSafe("wireless.mesh.mesh_id", w.Mesh.MeshID)
		if w.Mesh.MeshID == "" || len(w.Mesh.SAEPassword) < 8 {
			errs = append(errs, "wireless.mesh.enabled=true requires mesh_id and sae_password >= 8 chars")
		}
		if len(w.APs) > 0 && meshRoots == 0 {
			errs = append(errs, "wireless.mesh.enabled=true requires at least one AP with mesh_role='root'")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
