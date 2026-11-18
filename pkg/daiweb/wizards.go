// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daiweb

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/schema"
)

// WizardRequest defines a guided setup wizard mutation (with optional dry-run preview).
type WizardRequest struct {
	Wizard  string         `json:"wizard"`  // wan | lan | pppoe | vpn | firewall
	Preview bool           `json:"preview"` // dry-run: validate & return redacted diff without committing
	Commit  bool           `json:"commit"`
	Values  map[string]any `json:"values"`
}

// WizardResult returns validation outcome, redacted config diffs, and optional commit revision.
type WizardResult struct {
	Wizard    string                   `json:"wizard"`
	Preview   bool                     `json:"preview"`
	Committed bool                     `json:"committed"`
	Revision  string                   `json:"revision,omitempty"`
	Diffs     []configengine.DiffEntry `json:"diffs"`
}

// ApplyWizard stages guided changes against SSoT schema & configengine transactionally.
func ApplyWizard(ctx context.Context, eng *configengine.Engine, cs *schema.CompiledSchema, actor string, req WizardRequest) (*WizardResult, error) {
	if eng == nil || cs == nil {
		return nil, fmt.Errorf("config engine and schema are required")
	}
	switch req.Wizard {
	case "wan":
		if err := stageWANWizard(eng, actor, req.Values); err != nil {
			_ = eng.DiscardCandidate(actor)
			return nil, err
		}
	case "lan":
		if err := stageLANWizard(eng, actor, req.Values); err != nil {
			_ = eng.DiscardCandidate(actor)
			return nil, err
		}
	case "pppoe":
		if err := stagePPPoEWizard(eng, actor, req.Values); err != nil {
			_ = eng.DiscardCandidate(actor)
			return nil, err
		}
	case "vpn":
		if err := stageVPNWizard(eng, actor, req.Values); err != nil {
			_ = eng.DiscardCandidate(actor)
			return nil, err
		}
	case "firewall":
		if err := stageFirewallWizard(eng, actor, req.Values); err != nil {
			_ = eng.DiscardCandidate(actor)
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported wizard %q", req.Wizard)
	}

	if err := eng.ValidateCandidate(); err != nil {
		_ = eng.DiscardCandidate(actor)
		return nil, err
	}

	safeDiffs := configengine.RedactDiff(eng.DiffCandidate(), cs.IsSecretPath)
	out := &WizardResult{
		Wizard:  req.Wizard,
		Preview: req.Preview,
		Diffs:   safeDiffs,
	}

	if req.Preview || !req.Commit {
		if req.Preview {
			_ = eng.DiscardCandidate(actor)
		}
		return out, nil
	}

	res, err := eng.Commit(ctx, actor, fmt.Sprintf("daiweb wizard:%s", req.Wizard), configengine.CommitOptions{})
	if err != nil {
		return nil, err
	}
	out.Committed = true
	out.Revision = res.Revision.ID
	return out, nil
}

func stageWANWizard(eng *configengine.Engine, actor string, v map[string]any) error {
	iface := strVal(v["interface"], "eth1")
	addr := strVal(v["address"], "203.0.113.2/30")
	gw := strVal(v["gateway"], "203.0.113.1")
	enableNAT, _ := v["nat"].(bool)

	if err := upsertArrayObject(eng, actor, "interfaces.physical", "name", map[string]any{
		"name":      iface,
		"role":      "wan",
		"mtu":       float64(1500),
		"addresses": []any{addr},
		"enabled":   true,
	}); err != nil {
		return err
	}
	if err := upsertArrayObject(eng, actor, "routing.static_routes", "prefix", map[string]any{
		"prefix":    "0.0.0.0/0",
		"next_hop":  gw,
		"interface": iface,
		"distance":  float64(1),
		"enabled":   true,
	}); err != nil {
		return err
	}
	if enableNAT {
		return upsertArrayObject(eng, actor, "firewall.nat_rules", "id", map[string]any{
			"id":            "wiz-wan-masq-" + iface,
			"type":          "masquerade",
			"order":         float64(10),
			"out_interface": iface,
			"enabled":       true,
		})
	}
	return nil
}

func stageLANWizard(eng *configengine.Engine, actor string, v map[string]any) error {
	br := strVal(v["bridge"], "br-lan")
	cidr := strVal(v["cidr"], "192.168.88.1/24")

	return upsertArrayObject(eng, actor, "interfaces.bridges", "name", map[string]any{
		"name":           br,
		"vlan_filtering": false,
		"stp_mode":       "rstp",
		"ports":          []any{},
		"addresses":      []any{cidr},
		"enabled":        true,
	})
}

func stagePPPoEWizard(eng *configengine.Engine, actor string, v map[string]any) error {
	srv := strVal(v["server_name"], "daiji-fiber")
	iface := strVal(v["interface"], "eth0")
	poolCIDR := strVal(v["pool_cidr"], "100.64.0.0/20")
	localIP := strVal(v["local_ip"], "100.64.0.1")
	mtu := numVal(v["mtu"], 1492)
	poolName := "pool-" + srv

	if err := upsertArrayObject(eng, actor, "isp.ip_pools", "name", map[string]any{
		"name":   poolName,
		"ranges": []any{poolCIDR},
	}); err != nil {
		return err
	}
	return upsertArrayObject(eng, actor, "isp.pppoe.servers", "name", map[string]any{
		"name":         srv,
		"service_name": srv,
		"ac_name":      "DaijiOS-BNG",
		"interface":    iface,
		"local_ip":     localIP,
		"ip_pool":      poolName,
		"mtu":          float64(mtu),
		"mru":          float64(mtu),
		"auth_methods": []any{"chap", "mschapv2"},
		"enabled":      true,
	})
}

func stageVPNWizard(eng *configengine.Engine, actor string, v map[string]any) error {
	wg := strVal(v["wg_name"], "wg0")
	port := numVal(v["listen_port"], 51820)
	cidr := strVal(v["tunnel_cidr"], "10.99.0.1/24")

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	privB64 := base64.StdEncoding.EncodeToString(raw[:])

	return upsertArrayObject(eng, actor, "vpn.wireguard", "interface", map[string]any{
		"interface":   wg,
		"listen_port": float64(port),
		"private_key": privB64,
		"addresses":   []any{cidr},
		"mtu":         float64(1420),
		"enabled":     true,
	})
}

func stageFirewallWizard(eng *configengine.Engine, actor string, v map[string]any) error {
	ruleID := strVal(v["rule_name"], "allow-https-mgmt")
	action := strVal(v["action"], "accept")
	proto := strVal(v["protocol"], "tcp")
	port := numVal(v["dst_port"], 443)

	return upsertArrayObject(eng, actor, "firewall.filter_rules", "id", map[string]any{
		"id":       ruleID,
		"chain":    "input",
		"order":    float64(50),
		"protocol": proto,
		"dst_port": strconv.Itoa(port),
		"action":   action,
		"enabled":  true,
	})
}

func upsertArrayObject(eng *configengine.Engine, actor, dotPath, keyField string, obj map[string]any) error {
	cand := eng.GetCandidate(false)
	cur := lookupCandidatePath(cand, dotPath)
	var arr []any
	if existing, ok := cur.([]any); ok {
		arr = append(arr, existing...)
	}
	replaced := false
	targetKey := fmt.Sprintf("%v", obj[keyField])
	for i, el := range arr {
		if m, ok := el.(map[string]any); ok && fmt.Sprintf("%v", m[keyField]) == targetKey {
			arr[i] = obj
			replaced = true
			break
		}
	}
	if !replaced {
		arr = append(arr, obj)
	}
	return eng.SetPath(actor, dotPath, arr)
}

func lookupCandidatePath(root map[string]any, dotPath string) any {
	var cur any = root
	for _, seg := range splitDot(dotPath) {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[seg]
	}
	return cur
}

func splitDot(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

func strVal(v any, fallback string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return fallback
}

func numVal(v any, fallback int) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case string:
		if i, err := strconv.Atoi(x); err == nil {
			return i
		}
	}
	return fallback
}
