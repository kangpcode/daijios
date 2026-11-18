// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// daiji-ispd is the Phase 3 ISP access, Multi-WAN, telemetry, and automation daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/daijiscript"
	"github.com/kangpcode/daijios/pkg/ispengine"
	"github.com/kangpcode/daijios/pkg/ispplan"
	"github.com/kangpcode/daijios/pkg/ispreconcile"
	"github.com/kangpcode/daijios/pkg/netplan"
	"github.com/kangpcode/daijios/pkg/netreconcile"
	"github.com/kangpcode/daijios/pkg/schema"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daiji-ispd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	storeDir := fs.String("store", "/var/lib/daiji/config", "config store directory")
	schemaPath := fs.String("schema", "schema/daijios.schema.json", "path to DaijiOS schema JSON")
	dryRun := fs.Bool("dry-run", false, "validate and reconcile without mutating host OS")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cs, err := schema.LoadFile(*schemaPath)
	if err != nil {
		fmt.Fprintf(stderr, "load schema failed: %v\n", err)
		return 1
	}

	mig := configengine.NewMigrator()
	_ = netplan.RegisterMigrations(mig)

	applier := &ispreconcile.ISPApplier{
		Driver: &netreconcile.LinuxDriver{DryRun: *dryRun},
	}

	eng, err := configengine.Open(context.Background(), configengine.Options{
		BaseDir:           *storeDir,
		Schema:            cs,
		Applier:           applier,
		Migrator:          mig,
		SemanticValidator: ispplan.ValidateAllSemantic,
	})
	if err != nil {
		fmt.Fprintf(stderr, "open config engine failed: %v\n", err)
		return 1
	}
	defer eng.Close()

	running := eng.GetRunning(false)
	if err := applier.Plan(context.Background(), running, running, nil); err != nil {
		fmt.Fprintf(stderr, "isp plan validation failed: %v\n", err)
		return 1
	}
	if err := applier.Apply(context.Background(), running, nil); err != nil {
		fmt.Fprintf(stderr, "isp reconciliation failed: %v\n", err)
		return 1
	}

	cfg, err := ispplan.ParseConfig(running)
	if err != nil {
		fmt.Fprintf(stderr, "parse running config failed: %v\n", err)
		return 1
	}
	sessMgr := ispengine.NewSessionManager(&cfg.ISP)
	mwan := ispengine.NewMultiWANMonitor(cfg.ISP.MultiWAN)
	_ = daijiscript.NewAutomationEngine(cfg.Automation, daijiscript.ScriptHostCallbacks{}, nil)

	fmt.Fprintf(stdout, "%s\ndaiji-ispd: reconciled revision=%s sessions=%d wans=%d dry_run=%v\n",
		sysinfo.BrandBanner, eng.CurrentRevisionID(), len(sessMgr.ListSessions()), len(mwan.Snapshot()), *dryRun)
	return 0
}
