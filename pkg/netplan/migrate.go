// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package netplan

import "github.com/kangpcode/daijios/pkg/configengine"

// RegisterMigrations registers backward-compatible schema migrations onto m.
func RegisterMigrations(m *configengine.Migrator) error {
	if err := m.Register("1.0.0", "1.1.0", migrate100To110); err != nil {
		return err
	}
	if err := m.Register("1.1.0", "1.2.0", migrate110To120); err != nil {
		return err
	}
	if err := m.Register("1.2.0", "1.3.0", migrate120To130); err != nil {
		return err
	}
	return m.Register("1.3.0", "1.4.0", migrate130To140)
}

func migrate130To140(cfg map[string]any) (map[string]any, error) {
	if _, hasWLAN := cfg["wireless"]; !hasWLAN {
		cfg["wireless"] = map[string]any{
			"controller": map[string]any{
				"enabled":           false,
				"ac_name":           "DaijiOS-AC",
				"mode":              "local",
				"country_code":      "ID",
				"control_port":      float64(5246),
				"dtls_enabled":      true,
				"auto_adopt_policy": "zero-touch-token",
			},
		}
	}
	return cfg, nil
}

func migrate120To130(cfg map[string]any) (map[string]any, error) {
	if _, hasTel := cfg["telemetry"]; !hasTel {
		cfg["telemetry"] = map[string]any{
			"syslog": map[string]any{
				"enabled":            true,
				"local_buffer_lines": float64(5000),
			},
		}
	}
	return cfg, nil
}

func migrate110To120(cfg map[string]any) (map[string]any, error) {
	if _, hasSec := cfg["security"]; !hasSec {
		cfg["security"] = map[string]any{
			"rbac":       map[string]any{"enforce": true, "default_role": "readonly"},
			"two_factor": map[string]any{"enforce_for_admins": true, "issuer": "DaijiOS", "window_skew": float64(1)},
			"ssh_hardening": map[string]any{
				"permit_root_login": false,
				"max_auth_tries":    float64(3),
				"idle_timeout_sec":  float64(600),
			},
			"bruteforce": map[string]any{
				"enabled":          true,
				"ssh_max_attempts": float64(5),
				"ssh_window_sec":   float64(300),
				"api_max_attempts": float64(10),
				"api_window_sec":   float64(300),
				"ban_duration_sec": float64(3600),
			},
			"firmware_security": map[string]any{
				"secure_boot_required": true,
				"require_signed_dpk":   true,
				"require_signed_ab":    true,
				"audit_log_immutable":  true,
			},
		}
	}
	return cfg, nil
}

func migrate100To110(cfg map[string]any) (map[string]any, error) {
	// Preserve all existing fields; materialize default ip & switching blocks cleanly if missing.
	if _, hasIP := cfg["ip"]; !hasIP {
		ntpServers := []any{}
		if sys, ok := cfg["system"].(map[string]any); ok {
			if srvs, ok := sys["ntp_servers"].([]any); ok {
				ntpServers = srvs
			}
		}
		cfg["ip"] = map[string]any{
			"ipv4_forward": true,
			"ipv6_forward": true,
			"rp_filter":    2,
			"dns": map[string]any{
				"enabled":    true,
				"port":       53,
				"cache_size": 4096,
				"dnssec":     true,
			},
			"ntp": map[string]any{
				"enabled":     true,
				"servers":     ntpServers,
				"server_mode": false,
			},
		}
	}
	if _, hasSw := cfg["switching"]; !hasSw {
		cfg["switching"] = map[string]any{
			"lldp": map[string]any{
				"enabled":         true,
				"tx_interval_sec": 30,
				"tx_hold":         4,
				"cdp_compat":      true,
				"med_enabled":     true,
			},
		}
	}
	return cfg, nil
}
