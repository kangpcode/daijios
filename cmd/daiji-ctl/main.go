// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// daiji-ctl is the Phase 0 foundational control & verification CLI for DaijiOS.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kangpcode/daijios/pkg/abupdate"
	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/daijiscript"
	"github.com/kangpcode/daijios/pkg/ispplan"
	"github.com/kangpcode/daijios/pkg/ispreconcile"
	"github.com/kangpcode/daijios/pkg/isptools"
	"github.com/kangpcode/daijios/pkg/netplan"
	"github.com/kangpcode/daijios/pkg/netreconcile"
	"github.com/kangpcode/daijios/pkg/schema"
	"github.com/kangpcode/daijios/pkg/secplan"
	"github.com/kangpcode/daijios/pkg/secreconcile"
	"github.com/kangpcode/daijios/pkg/sysinfo"
	"github.com/kangpcode/daijios/pkg/wlanctrl"
	"github.com/kangpcode/daijios/pkg/wlanplan"
	"github.com/kangpcode/daijios/pkg/wlanreconcile"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 0
	}
	switch args[0] {
	case "banner":
		fmt.Fprint(stdout, sysinfo.RenderBootBanner("daiji-router", "", "A", sysinfo.Version, false))
		return 0
	case "about":
		return cmdAbout(args[1:], stdout, stderr)
	case "schema":
		return cmdSchema(args[1:], stdout, stderr)
	case "config":
		return cmdConfig(args[1:], stdout, stderr)
	case "net":
		return cmdNet(args[1:], stdout, stderr)
	case "sec":
		return cmdSec(args[1:], stdout, stderr)
	case "isp":
		return cmdISP(args[1:], stdout, stderr)
	case "wlan":
		return cmdWLAN(args[1:], stdout, stderr)
	case "ab":
		return cmdAB(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "%s\n\nUsage:\n"+
		"  daiji-ctl banner\n"+
		"  daiji-ctl about [--json] [--profile appliance|chr-vm|embedded]\n"+
		"  daiji-ctl schema <validate|export-cli|export-ui|export-openapi> --schema <path> [--config <path>]\n"+
		"  daiji-ctl config <init|show|set|diff|commit|commit-confirm|confirm|rollback|save|revisions|verify-audit> [flags]\n"+
		"  daiji-ctl net <plan|render-frr|render-kea|render-keepalived> --schema <path> --config <path>\n"+
		"  daiji-ctl sec <render-nft|render-qos|render-vpn|audit-check> --schema <path> --config <path>\n"+
		"  daiji-ctl isp <render-accel|render-mwan|render-snmp|run-script|bw-test> --schema <path> --config <path>\n"+
		"  daiji-ctl wlan <render-hostapd|render-mesh|render-nft|rrm-solve> --schema <path> --config <path>\n"+
		"  daiji-ctl ab status --state-dir <dir>\n",
		sysinfo.BrandBanner,
	)
}

func cmdAbout(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("about", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output JSON")
	profile := fs.String("profile", string(sysinfo.ProfileAppliance), "build profile")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	info := sysinfo.About(sysinfo.BuildProfile(*profile), "A", false)
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(info)
		return 0
	}
	fmt.Fprintf(stdout, "%s\nVersion: %s\nArch:    %s\nProfile: %s\nSlot:    %s\n",
		info.BrandBanner, info.Version, info.Architecture, info.Profile, info.ActiveSlot)
	return 0
}

func cmdSchema(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "schema subcommand required: validate | export-cli | export-ui | export-openapi")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("schema "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	schemaPath := fs.String("schema", "schema/daijios.schema.json", "path to DaijiOS schema JSON")
	configPath := fs.String("config", "schema/examples/default-config.json", "path to config JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cs, err := schema.LoadFile(*schemaPath)
	if err != nil {
		fmt.Fprintf(stderr, "error loading schema: %v\n", err)
		return 1
	}

	switch sub {
	case "validate":
		raw, err := os.ReadFile(*configPath)
		if err != nil {
			fmt.Fprintf(stderr, "error reading config: %v\n", err)
			return 1
		}
		if err := cs.ValidateJSON(raw); err != nil {
			fmt.Fprintf(stderr, "INVALID: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "VALID: %s conforms to DaijiOS schema %s\n", *configPath, cs.Root.SchemaVersion)
		return 0
	case "export-cli":
		specs, err := cs.ExtractCLISpec()
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		return writeJSONOut(stdout, specs)
	case "export-ui":
		ui, err := cs.ExtractUISchema()
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		return writeJSONOut(stdout, ui)
	case "export-openapi":
		return writeJSONOut(stdout, cs.ExtractOpenAPISpec())
	default:
		fmt.Fprintf(stderr, "unknown schema subcommand %q\n", sub)
		return 2
	}
}

func cmdConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "config subcommand required")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("config "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	storeDir := fs.String("store", "/var/lib/daiji/config", "config store directory")
	schemaPath := fs.String("schema", "schema/daijios.schema.json", "path to DaijiOS schema")
	bootstrapPath := fs.String("bootstrap", "schema/examples/default-config.json", "bootstrap JSON file")
	actor := fs.String("actor", "admin", "operator username")
	msg := fs.String("msg", "cli change", "commit message")
	pathKey := fs.String("path", "", "dot path (e.g. system.hostname)")
	valRaw := fs.String("value", "", "value (JSON or string)")
	revRef := fs.String("rev", "1", "revision id or offset")
	timeout := fs.Duration("timeout", 60*time.Second, "commit-confirm timeout")
	commitNow := fs.Bool("commit", false, "immediately commit rollback")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	cs, err := schema.LoadFile(*schemaPath)
	if err != nil {
		fmt.Fprintf(stderr, "error loading schema: %v\n", err)
		return 1
	}

	var boot map[string]any
	if sub == "init" {
		raw, err := os.ReadFile(*bootstrapPath)
		if err != nil {
			fmt.Fprintf(stderr, "error reading bootstrap: %v\n", err)
			return 1
		}
		if err := json.Unmarshal(raw, &boot); err != nil {
			fmt.Fprintf(stderr, "invalid bootstrap json: %v\n", err)
			return 1
		}
	}

	mig := configengine.NewMigrator()
	_ = netplan.RegisterMigrations(mig)
	eng, err := configengine.Open(context.Background(), configengine.Options{
		BaseDir:           *storeDir,
		Schema:            cs,
		Migrator:          mig,
		SemanticValidator: wlanplan.ValidateAllSemantic,
		BootstrapConfig:   boot,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error opening config engine: %v\n", err)
		return 1
	}
	defer eng.Close()

	switch sub {
	case "init":
		fmt.Fprintf(stdout, "Initialized DaijiOS config store at %s (rev=%s)\n", *storeDir, eng.CurrentRevisionID())
		return 0
	case "show":
		return writeJSONOut(stdout, eng.GetRunning(true))
	case "set":
		if *pathKey == "" {
			fmt.Fprintln(stderr, "--path is required")
			return 2
		}
		parsedVal := parseDynamicValue(*valRaw)
		if err := eng.SetPath(*actor, *pathKey, parsedVal); err != nil {
			fmt.Fprintf(stderr, "set failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Staged %s in candidate\n", *pathKey)
		return 0
	case "diff":
		diffs := eng.DiffCandidate()
		fmt.Fprintln(stdout, configengine.FormatDiff(diffs, cs.IsSecretPath))
		return 0
	case "commit":
		res, err := eng.Commit(context.Background(), *actor, *msg, configengine.CommitOptions{})
		if err != nil {
			fmt.Fprintf(stderr, "commit failed: %v\n", err)
			return 1
		}
		if !res.Changed {
			fmt.Fprintln(stdout, "No candidate changes to commit.")
			return 0
		}
		fmt.Fprintf(stdout, "Committed %s (%d diff(s))\n", res.Revision.ID, len(res.Diffs))
		return 0
	case "commit-confirm":
		res, err := eng.CommitConfirm(context.Background(), *actor, *msg, *timeout)
		if err != nil {
			fmt.Fprintf(stderr, "commit-confirm failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Committed %s pending confirmation until %s\n", res.Revision.ID, res.ConfirmDeadline.Format(time.RFC3339))
		return 0
	case "confirm":
		if err := eng.Confirm(*actor); err != nil {
			fmt.Fprintf(stderr, "confirm failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "Confirmed active commit.")
		return 0
	case "save":
		if err := eng.SaveStartup(*actor); err != nil {
			fmt.Fprintf(stderr, "save failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "Saved running config to startup.")
		return 0
	case "rollback":
		res, err := eng.Rollback(context.Background(), *actor, *revRef, *commitNow)
		if err != nil {
			fmt.Fprintf(stderr, "rollback failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Rollback target=%s committed=%v\n", res.Revision.ID, *commitNow)
		return 0
	case "revisions":
		revs, err := eng.ListRevisions()
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		for _, r := range revs {
			fmt.Fprintf(stdout, "%s  %s  actor=%s  sha256=%s  %s\n",
				r.ID, r.Timestamp.Format(time.RFC3339), r.Actor, r.ConfigSHA256[:12], r.Message)
		}
		return 0
	case "verify-audit":
		cnt, err := eng.VerifyAuditLog()
		if err != nil {
			fmt.Fprintf(stderr, "AUDIT TAMPER DETECTED: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "OK: verified %d hash-chained audit entries\n", cnt)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown config subcommand %q\n", sub)
		return 2
	}
}

func cmdAB(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "status" {
		fmt.Fprintln(stderr, "usage: daiji-ctl ab status --state-dir <dir>")
		return 2
	}
	fs := flag.NewFlagSet("ab status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", "/var/lib/daiji/ab", "A/B update state directory")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	hostArch := sysinfo.NormalizeArch(os.Getenv("DAIJI_ARCH"))
	if hostArch == "" {
		hostArch = sysinfo.NormalizeArch(runtime.GOARCH)
	}
	mgr, err := abupdate.NewManager(abupdate.Options{
		Backend:  abupdate.FileEnvBackend{Path: filepath.Join(*stateDir, "bootenv.json")},
		HostArch: hostArch,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	env, err := mgr.Status()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return writeJSONOut(stdout, env)
}

func cmdNet(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "net subcommand required: plan | render-frr | render-kea | render-keepalived")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("net "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	schemaPath := fs.String("schema", "schema/daijios.schema.json", "path to DaijiOS schema")
	configPath := fs.String("config", "schema/examples/isp-core-config.json", "path to config JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cs, err := schema.LoadFile(*schemaPath)
	if err != nil {
		fmt.Fprintf(stderr, "error loading schema: %v\n", err)
		return 1
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "error reading config: %v\n", err)
		return 1
	}
	if err := cs.ValidateJSON(raw); err != nil {
		fmt.Fprintf(stderr, "schema error: %v\n", err)
		return 1
	}
	var cfgMap map[string]any
	if err := json.Unmarshal(raw, &cfgMap); err != nil {
		fmt.Fprintf(stderr, "json error: %v\n", err)
		return 1
	}
	if err := netplan.ValidateSemantic(cfgMap); err != nil {
		fmt.Fprintf(stderr, "semantic error: %v\n", err)
		return 1
	}
	netCfg, err := netplan.ParseConfig(cfgMap)
	if err != nil {
		fmt.Fprintf(stderr, "parse error: %v\n", err)
		return 1
	}

	switch sub {
	case "plan":
		phys := make([]string, 0, len(netCfg.Interfaces.Physical))
		for _, p := range netCfg.Interfaces.Physical {
			phys = append(phys, p.Name)
		}
		sim := netreconcile.NewSimulatedDriver(phys...)
		applier := &netreconcile.NetworkApplier{Driver: sim}
		if err := applier.Apply(context.Background(), cfgMap, nil); err != nil {
			fmt.Fprintf(stderr, "plan failed: %v\n", err)
			return 1
		}
		for _, cmd := range sim.Commands {
			fmt.Fprintln(stdout, cmd)
		}
		return 0
	case "render-frr":
		fmt.Fprint(stdout, netreconcile.RenderFRRConfig(netCfg, true))
		return 0
	case "render-kea":
		keaBytes, err := netreconcile.RenderKeaDHCP4(netCfg)
		if err != nil {
			fmt.Fprintf(stderr, "kea render failed: %v\n", err)
			return 1
		}
		fmt.Fprint(stdout, string(keaBytes))
		return 0
	case "render-keepalived":
		fmt.Fprint(stdout, netreconcile.RenderKeepalived(netCfg, true))
		return 0
	default:
		fmt.Fprintf(stderr, "unknown net subcommand %q\n", sub)
		return 2
	}
}

func cmdSec(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "sec subcommand required: render-nft | render-qos | render-vpn | audit-check")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("sec "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	schemaPath := fs.String("schema", "schema/daijios.schema.json", "path to DaijiOS schema")
	configPath := fs.String("config", "schema/examples/isp-edge-sec-config.json", "path to config JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cs, err := schema.LoadFile(*schemaPath)
	if err != nil {
		fmt.Fprintf(stderr, "error loading schema: %v\n", err)
		return 1
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "error reading config: %v\n", err)
		return 1
	}
	if err := cs.ValidateJSON(raw); err != nil {
		fmt.Fprintf(stderr, "schema error: %v\n", err)
		return 1
	}
	var cfgMap map[string]any
	if err := json.Unmarshal(raw, &cfgMap); err != nil {
		fmt.Fprintf(stderr, "json error: %v\n", err)
		return 1
	}
	if err := secplan.ValidateAllSemantic(cfgMap); err != nil {
		fmt.Fprintf(stderr, "semantic error: %v\n", err)
		return 1
	}
	secCfg, err := secplan.ParseConfig(cfgMap)
	if err != nil {
		fmt.Fprintf(stderr, "parse error: %v\n", err)
		return 1
	}

	switch sub {
	case "render-nft":
		fmt.Fprint(stdout, secreconcile.RenderNFTables(secCfg))
		return 0
	case "render-qos":
		for _, cmd := range secreconcile.BuildQoSCommands(secCfg) {
			fmt.Fprintln(stdout, "tc "+strings.Join(cmd, " "))
		}
		return 0
	case "render-vpn":
		for _, wg := range secCfg.VPN.WireGuard {
			fmt.Fprintln(stdout, secreconcile.RenderWireGuardConfig(wg, true))
		}
		fmt.Fprint(stdout, secreconcile.RenderSwanctlConfig(secCfg, true))
		return 0
	case "audit-check":
		findings := make([]string, 0)
		if secCfg.Management.SSH.PasswordAuth {
			findings = append(findings, "WARN: management.ssh.password_auth=true")
		}
		if !secCfg.Management.API.TLSEnabled {
			findings = append(findings, "CRITICAL: management.api.tls_enabled=false")
		}
		if !secCfg.Security.RBAC.Enforce {
			findings = append(findings, "HIGH: security.rbac.enforce=false")
		}
		if !secCfg.Security.BruteForce.Enabled {
			findings = append(findings, "MEDIUM: security.bruteforce.enabled=false")
		}
		if !secCfg.Updates.RequireSignature {
			findings = append(findings, "CRITICAL: updates.require_signature=false")
		}
		if len(findings) == 0 {
			fmt.Fprintln(stdout, "AUDIT PASS: 0 security posture findings")
			return 0
		}
		for _, f := range findings {
			fmt.Fprintln(stdout, f)
		}
		return 1
	default:
		fmt.Fprintf(stderr, "unknown sec subcommand %q\n", sub)
		return 2
	}
}

func cmdISP(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "isp subcommand required: render-accel | render-mwan | render-snmp | run-script | bw-test")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("isp "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	schemaPath := fs.String("schema", "schema/daijios.schema.json", "path to DaijiOS schema")
	configPath := fs.String("config", "schema/examples/isp-bng-config.json", "path to config JSON")
	scriptName := fs.String("script", "", "DaijiScript name for run-script")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	if sub == "bw-test" {
		res, err := isptools.RunLoopbackBandwidthTest(context.Background(), 1024*1024)
		if err != nil {
			fmt.Fprintf(stderr, "bw-test failed: %v\n", err)
			return 1
		}
		return writeJSONOut(stdout, res)
	}

	cs, err := schema.LoadFile(*schemaPath)
	if err != nil {
		fmt.Fprintf(stderr, "error loading schema: %v\n", err)
		return 1
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "error reading config: %v\n", err)
		return 1
	}
	if err := cs.ValidateJSON(raw); err != nil {
		fmt.Fprintf(stderr, "schema error: %v\n", err)
		return 1
	}
	var cfgMap map[string]any
	if err := json.Unmarshal(raw, &cfgMap); err != nil {
		fmt.Fprintf(stderr, "json error: %v\n", err)
		return 1
	}
	if err := ispplan.ValidateAllSemantic(cfgMap); err != nil {
		fmt.Fprintf(stderr, "semantic error: %v\n", err)
		return 1
	}
	ispCfg, err := ispplan.ParseConfig(cfgMap)
	if err != nil {
		fmt.Fprintf(stderr, "parse error: %v\n", err)
		return 1
	}

	switch sub {
	case "render-accel":
		fmt.Fprint(stdout, ispreconcile.RenderAccelPPP(ispCfg, true))
		return 0
	case "render-mwan":
		fmt.Fprint(stdout, ispreconcile.RenderMultiWANNFT(ispCfg))
		return 0
	case "render-snmp":
		fmt.Fprint(stdout, ispreconcile.RenderSNMPD(ispCfg, true))
		return 0
	case "run-script":
		for _, sc := range ispCfg.Automation.Scripts {
			if *scriptName == "" || sc.Name == *scriptName {
				res, err := daijiscript.RunScript(context.Background(), sc, nil, daijiscript.ScriptHostCallbacks{
					OnLog: func(msg string) { fmt.Fprintf(stdout, "[script:%s] %s\n", sc.Name, msg) },
				})
				if err != nil {
					fmt.Fprintf(stderr, "script error: %v\n", err)
					return 1
				}
				return writeJSONOut(stdout, res)
			}
		}
		fmt.Fprintf(stderr, "script %q not found\n", *scriptName)
		return 1
	default:
		fmt.Fprintf(stderr, "unknown isp subcommand %q\n", sub)
		return 2
	}
}

func cmdWLAN(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "wlan subcommand required: render-hostapd | render-mesh | render-nft | rrm-solve")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("wlan "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	schemaPath := fs.String("schema", "schema/daijios.schema.json", "path to DaijiOS schema")
	configPath := fs.String("config", "schema/examples/campus-ac-config.json", "path to config JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cs, err := schema.LoadFile(*schemaPath)
	if err != nil {
		fmt.Fprintf(stderr, "error loading schema: %v\n", err)
		return 1
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "error reading config: %v\n", err)
		return 1
	}
	if err := cs.ValidateJSON(raw); err != nil {
		fmt.Fprintf(stderr, "schema error: %v\n", err)
		return 1
	}
	var cfgMap map[string]any
	if err := json.Unmarshal(raw, &cfgMap); err != nil {
		fmt.Fprintf(stderr, "json error: %v\n", err)
		return 1
	}
	if err := wlanplan.ValidateAllSemantic(cfgMap); err != nil {
		fmt.Fprintf(stderr, "semantic error: %v\n", err)
		return 1
	}
	wCfg, err := wlanplan.ParseConfig(cfgMap)
	if err != nil {
		fmt.Fprintf(stderr, "parse error: %v\n", err)
		return 1
	}

	switch sub {
	case "render-hostapd":
		fmt.Fprint(stdout, wlanreconcile.RenderHostapdConfig(&wCfg.Wireless, true))
		return 0
	case "render-mesh":
		fmt.Fprint(stdout, wlanreconcile.RenderMeshConfig(&wCfg.Wireless, true))
		return 0
	case "render-nft":
		fmt.Fprint(stdout, wlanreconcile.RenderWLANGuestNFT(&wCfg.Wireless))
		return 0
	case "rrm-solve":
		var rf wlanplan.WLANRFProfile
		if len(wCfg.Wireless.RFProfiles) > 0 {
			rf = wCfg.Wireless.RFProfiles[0]
		}
		plans := wlanctrl.OptimizeRF(wCfg.Wireless.APs, rf, nil)
		return writeJSONOut(stdout, plans)
	default:
		fmt.Fprintf(stderr, "unknown wlan subcommand %q\n", sub)
		return 2
	}
}

func parseDynamicValue(raw string) any {
	if raw == "true" {
		return true
	}
	if raw == "false" {
		return false
	}
	if i, err := strconv.Atoi(raw); err == nil {
		return float64(i)
	}
	var anyVal any
	if strings.HasPrefix(raw, "[") || strings.HasPrefix(raw, "{") {
		if err := json.Unmarshal([]byte(raw), &anyVal); err == nil {
			return anyVal
		}
	}
	return raw
}

func writeJSONOut(w io.Writer, v any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return 1
	}
	return 0
}
