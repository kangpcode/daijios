// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// daiji-ctl is the Phase 0 foundational control & verification CLI for DaijiOS.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
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
	"github.com/kangpcode/daijios/pkg/daijiacs"
	"github.com/kangpcode/daijios/pkg/daijibilling"
	"github.com/kangpcode/daijios/pkg/daijicli"
	"github.com/kangpcode/daijios/pkg/daijicloud"
	"github.com/kangpcode/daijios/pkg/daijiportal"
	"github.com/kangpcode/daijios/pkg/daijirelease"
	"github.com/kangpcode/daijios/pkg/daijiscript"
	"github.com/kangpcode/daijios/pkg/daimo"
	"github.com/kangpcode/daijios/pkg/daiweb"
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
	case "cli":
		return cmdCLI(args[1:], stdout, stderr)
	case "web":
		return cmdWeb(args[1:], stdout, stderr)
	case "mobile":
		return cmdMobile(args[1:], stdout, stderr)
	case "acs":
		return cmdACS(args[1:], stdout, stderr)
	case "billing":
		return cmdBilling(args[1:], stdout, stderr)
	case "cloud":
		return cmdCloud(args[1:], stdout, stderr)
	case "portal":
		return cmdPortal(args[1:], stdout, stderr)
	case "release":
		return cmdRelease(args[1:], stdout, stderr)
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
		"  daiji-ctl cli <export-command-schema|search|exec> [flags]\n"+
		"  daiji-ctl web check --schema <path> [--json]\n"+
		"  daiji-ctl mobile qr-onboard --mode <local|cloud> --endpoint <url> [--actor <name>]\n"+
		"  daiji-ctl acs templates [--json]\n"+
		"  daiji-ctl billing simulate-cycle [--json]\n"+
		"  daiji-ctl cloud dr-check [--json]\n"+
		"  daiji-ctl portal license-demo [--json]\n"+
		"  daiji-ctl release <keygen|manifest|verify|soak> [flags]\n"+
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
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return 1
	}
	return 0
}

func cmdCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "cli subcommand required: export-command-schema | search | exec")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("cli "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	schemaPath := fs.String("schema", "schema/daijios.schema.json", "path to DaijiOS schema JSON")
	storeDir := fs.String("store", "/var/lib/daiji/config", "config store directory")
	actor := fs.String("actor", "daijiadmin", "operator username")
	role := fs.String("role", "superadmin", "RBAC role")
	cmdStr := fs.String("cmd", "", "semicolon-separated CLI commands to execute")
	query := fs.String("q", "", "fuzzy search query")
	limit := fs.Int("limit", 15, "max search hits")
	jsonOut := fs.Bool("json", false, "output structured JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cs, err := schema.LoadFile(*schemaPath)
	if err != nil {
		fmt.Fprintf(stderr, "error loading schema: %v\n", err)
		return 1
	}

	switch sub {
	case "export-command-schema":
		doc, err := daijicli.BuildCommandSchema(cs)
		if err != nil {
			fmt.Fprintf(stderr, "build command schema error: %v\n", err)
			return 1
		}
		return writeJSONOut(stdout, doc)

	case "search":
		if strings.TrimSpace(*query) == "" {
			fmt.Fprintln(stderr, "--q is required")
			return 2
		}
		reg, err := daijicli.BuildRegistry(cs)
		if err != nil {
			fmt.Fprintf(stderr, "build registry error: %v\n", err)
			return 1
		}
		hits := reg.FuzzySearch(*query, *limit)
		if *jsonOut {
			return writeJSONOut(stdout, hits)
		}
		for _, h := range hits {
			fmt.Fprintf(stdout, "%-45s (%s) score=%d %s\n", h.Path, h.Type, h.Score, h.Description)
		}
		return 0

	case "exec":
		if strings.TrimSpace(*cmdStr) == "" {
			fmt.Fprintln(stderr, "--cmd is required")
			return 2
		}
		mig := configengine.NewMigrator()
		_ = netplan.RegisterMigrations(mig)
		eng, err := configengine.Open(context.Background(), configengine.Options{
			BaseDir:           *storeDir,
			Schema:            cs,
			Migrator:          mig,
			SemanticValidator: wlanplan.ValidateAllSemantic,
		})
		if err != nil {
			fmt.Fprintf(stderr, "open config engine failed: %v\n", err)
			return 1
		}
		defer eng.Close()

		sess, err := daijicli.NewSession(*actor, *role, eng, cs)
		if err != nil {
			fmt.Fprintf(stderr, "init session failed: %v\n", err)
			return 1
		}
		for _, part := range strings.Split(*cmdStr, ";") {
			line := strings.TrimSpace(part)
			if line == "" {
				continue
			}
			res, err := sess.Execute(context.Background(), line)
			if err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
				return 1
			}
			if *jsonOut && res.Structured != nil {
				if writeJSONOut(stdout, res.Structured) != 0 {
					return 1
				}
			} else if res.Output != "" {
				fmt.Fprintln(stdout, res.Output)
			}
		}
		return 0

	default:
		fmt.Fprintf(stderr, "unknown cli subcommand %q\n", sub)
		return 2
	}
}

func cmdWeb(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprintln(stderr, "web subcommand required: check")
		return 2
	}
	fs := flag.NewFlagSet("web check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	schemaPath := fs.String("schema", "schema/daijios.schema.json", "path to DaijiOS schema JSON")
	jsonOut := fs.Bool("json", false, "output JSON summary")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cs, err := schema.LoadFile(*schemaPath)
	if err != nil {
		fmt.Fprintf(stderr, "error loading schema: %v\n", err)
		return 1
	}
	srv, err := daiweb.NewServer(daiweb.Dependencies{Schema: cs})
	if err != nil {
		fmt.Fprintf(stderr, "error initializing daiweb: %v\n", err)
		return 1
	}
	rawB, gzB := srv.AssetBundleStats()
	fields, err := cs.ExtractUISchema()
	if err != nil {
		fmt.Fprintf(stderr, "error extracting UI schema: %v\n", err)
		return 1
	}
	if *jsonOut {
		return writeJSONOut(stdout, map[string]any{
			"brand":        sysinfo.BrandBanner,
			"raw_bytes":    rawB,
			"gzip_bytes":   gzB,
			"ui_fields":    len(fields),
			"theme_modes":  []string{"daiji-dark", "daiji-light", "system"},
			"i18n_locales": []string{"id", "en"},
		})
	}
	fmt.Fprintf(stdout, "DAIWEB CHECK PASS: raw=%dB gzip=%dB ui_fields=%d\n", rawB, gzB, len(fields))
	return 0
}

func cmdMobile(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "qr-onboard" {
		fmt.Fprintln(stderr, "mobile subcommand required: qr-onboard")
		return 2
	}
	fs := flag.NewFlagSet("mobile qr-onboard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	deviceID := fs.String("device", "daiji-node-01", "device ID")
	mac := fs.String("mac", "02:64:6a:00:00:01", "device MAC")
	mode := fs.String("mode", "local", "connection mode: local | cloud")
	endpoint := fs.String("endpoint", "http://192.168.88.1:8443", "target URL")
	actor := fs.String("actor", "daijiadmin", "operator actor")
	role := fs.String("role", "superadmin", "RBAC role")
	secret := fs.String("secret", "daijios-daimo-qr-secret-phase7", "QR HMAC secret")
	ttl := fs.Duration("ttl", 5*time.Minute, "QR expiration TTL")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	svc, err := daimo.NewService(daimo.Config{
		DeviceID: *deviceID,
		MAC:      *mac,
		QRSecret: []byte(*secret),
	})
	if err != nil {
		fmt.Fprintf(stderr, "init error: %v\n", err)
		return 1
	}
	uri, err := svc.GenerateOnboardingQR(daimo.ConnectionMode(*mode), *endpoint, *role, *actor, *ttl)
	if err != nil {
		fmt.Fprintf(stderr, "qr error: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, uri)
	return 0
}

func cmdACS(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "templates" {
		fmt.Fprintln(stderr, "acs subcommand required: templates")
		return 2
	}
	fs := flag.NewFlagSet("acs templates", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	tpls := daijiacs.DefaultVendorTemplates()
	if *jsonOut {
		return writeJSONOut(stdout, tpls)
	}
	for _, tp := range tpls {
		fmt.Fprintf(stdout, "%-20s %-10s optical=%s\n", tp.ID, tp.RootModel, tp.OpticalRxPath)
	}
	return 0
}

func cmdBilling(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "simulate-cycle" {
		fmt.Fprintln(stderr, "billing subcommand required: simulate-cycle")
		return 2
	}
	fs := flag.NewFlagSet("billing simulate-cycle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output JSON summary")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	simNow := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	eng := daijibilling.NewEngine(daijibilling.Options{Now: func() time.Time { return simNow }})
	_ = eng.AddReseller(daijibilling.Reseller{ID: "res-01", Name: "Reseller Utama", CommissionPct: 10, Active: true}, "cli")
	_ = eng.AddPlan(daijibilling.ServicePlan{ID: "fiber-50m", Name: "Fiber 50M", MonthlyPriceCents: 200000, TaxRatePct: 11, GraceDays: 7, LateFeeCents: 10000}, "cli")
	_ = eng.AddCustomer(daijibilling.Customer{
		ID: "cust-01", Name: "Demo Customer", Phone: "+62811111111", Email: "demo@daiji.id",
		PPPoEUsername: "demo@daiji", ResellerID: "res-01", PlanID: "fiber-50m",
		CycleType: daijibilling.CycleFixedDay, ActivatedAt: simNow, PPPoEActive: true,
	}, "cli")
	invs, err := eng.GenerateMonthlyInvoices("cli")
	if err != nil || len(invs) == 0 {
		fmt.Fprintf(stderr, "billing simulation failed: %v\n", err)
		return 1
	}
	if _, err := eng.MarkInvoicePaid(invs[0].ID, "qris", "cli-qris-001", invs[0].TotalCents, "cli"); err != nil {
		fmt.Fprintf(stderr, "payment settle failed: %v\n", err)
		return 1
	}
	rep := eng.GenerateFinancialReport("2026-11")
	if *jsonOut {
		return writeJSONOut(stdout, rep)
	}
	fmt.Fprintf(stdout, "DAIJI-BILLING SIM OK: invoices=%d collected=%d tax=%d\n", rep.PaidInvoices, rep.CollectedCents, rep.TaxTotalCents)
	return 0
}

func cmdCloud(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "dr-check" {
		fmt.Fprintln(stderr, "cloud subcommand required: dr-check")
		return 2
	}
	fs := flag.NewFlagSet("cloud dr-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	cp := daijicloud.NewControlPlane(nil, nil, nil)
	_ = cp.CreateOrganization(daijicloud.Organization{ID: "org-dr", Name: "DR Verify"})
	_ = cp.CreateSite(daijicloud.Site{ID: "site-1", OrgID: "org-dr", Name: "Primary POP"})
	tok, _ := cp.CreateZTPClaimToken("org-dr", "site-1", "CLI-SN01", "edge", time.Hour)
	_, _ = cp.AdoptViaZTP(tok, "CLI-SN01", "02:64:6a:00:00:01", "cli-node", "amd64", "1.1.0")
	snap, err := cp.ExportDisasterRecoverySnapshot()
	if err != nil {
		fmt.Fprintf(stderr, "DR export failed: %v\n", err)
		return 1
	}
	standby := daijicloud.NewControlPlane(nil, nil, nil)
	if err := standby.RestoreDisasterRecoverySnapshot(snap); err != nil {
		fmt.Fprintf(stderr, "DR restore failed: %v\n", err)
		return 1
	}
	if *jsonOut {
		return writeJSONOut(stdout, map[string]any{
			"brand":       sysinfo.BrandBanner,
			"dr_verified": true,
			"orgs":        len(snap.Orgs),
			"sites":       len(snap.Sites),
			"devices":     len(snap.Devices),
		})
	}
	fmt.Fprintf(stdout, "DAIJICLOUD DR CHECK PASS: orgs=%d sites=%d devices=%d\n", len(snap.Orgs), len(snap.Sites), len(snap.Devices))
	return 0
}

func cmdPortal(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "license-demo" {
		fmt.Fprintln(stderr, "portal subcommand required: license-demo")
		return 2
	}
	fs := flag.NewFlagSet("portal license-demo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output JSON")
	hwID := fs.String("hw", "HW-DAIJIOS-001", "hardware fingerprint ID")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	portal, err := daijiportal.NewPortal(nil, nil)
	if err != nil {
		fmt.Fprintf(stderr, "portal error: %v\n", err)
		return 1
	}
	inv, lic, err := portal.PurchaseLicense("org-demo", "official", "sku-ent", *hwID, 10, 12)
	if err != nil {
		fmt.Fprintf(stderr, "purchase error: %v\n", err)
		return 1
	}
	verified, err := daijiportal.VerifyOfflineLicense(portal.PublicKey(), lic.OfflineBlob, *hwID, "multi-tenant", 5, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "offline verify error: %v\n", err)
		return 1
	}
	if *jsonOut {
		return writeJSONOut(stdout, map[string]any{
			"brand":        sysinfo.BrandBanner,
			"invoice_id":   inv.ID,
			"license_id":   verified.LicenseID,
			"tier":         verified.Tier,
			"offline_blob": lic.OfflineBlob,
		})
	}
	fmt.Fprintf(stdout, "DAIJIPORTAL ED25519 VERIFIED: license=%s tier=%s devices=%d\n", verified.LicenseID, verified.Tier, verified.MaxDevices)
	return 0
}

func cmdRelease(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "release subcommand required: manifest | verify | soak")
		return 2
	}
	sub := args[0]
	switch sub {
	case "soak":
		fs := flag.NewFlagSet("release soak", flag.ContinueOnError)
		fs.SetOutput(stderr)
		jsonOut := fs.Bool("json", false, "output JSON")
		hours := fs.Int("hours", 72, "simulated soak duration in hours")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		rep, err := daijirelease.RunSoakSimulation(daijirelease.SoakConfig{SimulatedHours: *hours, OpsPerHour: 10})
		if err != nil {
			fmt.Fprintf(stderr, "soak error: %v\n", err)
			return 1
		}
		if *jsonOut {
			return writeJSONOut(stdout, rep)
		}
		fmt.Fprintf(stdout, "SOAK %dH PASS: tx=%d failed=%d p99=%.1fus heap=%dKB->%dKB goroutine_delta=%d\n",
			rep.SimulatedHours, rep.TotalTransactions, rep.FailedOps, rep.P99LatencyUs, rep.StartHeapKB, rep.EndHeapKB, rep.GoroutineDelta)
		return 0

	case "manifest":
		fs := flag.NewFlagSet("release manifest", flag.ContinueOnError)
		fs.SetOutput(stderr)
		dir := fs.String("dir", "bin/dist", "artifact directory")
		outDir := fs.String("out", "bin/release", "output directory for manifest.json & SHA256SUMS")
		ver := fs.String("version", sysinfo.Version, "release version")
		jsonOut := fs.Bool("json", false, "output JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		m, err := daijirelease.BuildManifest(*dir, *ver, runtime.Version(), time.Now().UTC())
		if err != nil {
			fmt.Fprintf(stderr, "build manifest error: %v\n", err)
			return 1
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Fprintf(stderr, "keygen error: %v\n", err)
			return 1
		}
		if err := daijirelease.SignManifest(priv, m); err != nil {
			fmt.Fprintf(stderr, "sign manifest error: %v\n", err)
			return 1
		}
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			fmt.Fprintf(stderr, "mkdir out error: %v\n", err)
			return 1
		}
		sumsPath := filepath.Join(*outDir, "SHA256SUMS")
		manifestPath := filepath.Join(*outDir, "manifest.json")
		if err := daijirelease.WriteSHA256SUMS(sumsPath, m.Artifacts); err != nil {
			fmt.Fprintf(stderr, "write SHA256SUMS error: %v\n", err)
			return 1
		}
		if err := daijirelease.SaveManifestJSON(manifestPath, m); err != nil {
			fmt.Fprintf(stderr, "save manifest error: %v\n", err)
			return 1
		}
		if *jsonOut {
			return writeJSONOut(stdout, map[string]any{
				"brand":     m.Brand,
				"version":   m.Version,
				"artifacts": len(m.Artifacts),
				"manifest":  manifestPath,
				"sums":      sumsPath,
				"lts_until": m.LTS.ActiveUntil,
			})
		}
		fmt.Fprintf(stdout, "RELEASE MANIFEST SIGNED: version=%s artifacts=%d out=%s\n", m.Version, len(m.Artifacts), *outDir)
		return 0

	case "verify":
		fs := flag.NewFlagSet("release verify", flag.ContinueOnError)
		fs.SetOutput(stderr)
		dir := fs.String("dir", "bin/dist", "artifact directory")
		manifestPath := fs.String("manifest", "bin/release/manifest.json", "manifest.json path")
		sumsPath := fs.String("sums", "bin/release/SHA256SUMS", "SHA256SUMS path")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		raw, err := os.ReadFile(*manifestPath)
		if err != nil {
			fmt.Fprintf(stderr, "read manifest error: %v\n", err)
			return 1
		}
		var m daijirelease.ReleaseManifest
		if err := json.Unmarshal(raw, &m); err != nil {
			fmt.Fprintf(stderr, "parse manifest error: %v\n", err)
			return 1
		}
		pubBytes, err := hex.DecodeString(m.PublicKey)
		if err != nil {
			fmt.Fprintf(stderr, "decode public key error: %v\n", err)
			return 1
		}
		if err := daijirelease.VerifyManifest(ed25519.PublicKey(pubBytes), m); err != nil {
			fmt.Fprintf(stderr, "manifest verify failed: %v\n", err)
			return 1
		}
		cnt, err := daijirelease.VerifySHA256SUMS(*dir, *sumsPath)
		if err != nil {
			fmt.Fprintf(stderr, "checksum verify failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "RELEASE VERIFIED: version=%s ed25519=OK checksums=%d\n", m.Version, cnt)
		return 0

	default:
		fmt.Fprintf(stderr, "unknown release subcommand %q\n", sub)
		return 2
	}
}
