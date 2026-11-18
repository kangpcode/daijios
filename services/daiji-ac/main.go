// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// daiji-ac is the Phase 4 Wireless Controller (AC), RRM, Roaming, & Mesh daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/netplan"
	"github.com/kangpcode/daijios/pkg/netreconcile"
	"github.com/kangpcode/daijios/pkg/schema"
	"github.com/kangpcode/daijios/pkg/sysinfo"
	"github.com/kangpcode/daijios/pkg/wlanctrl"
	"github.com/kangpcode/daijios/pkg/wlanplan"
	"github.com/kangpcode/daijios/pkg/wlanreconcile"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daiji-ac", flag.ContinueOnError)
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

	applier := &wlanreconcile.WLANApplier{
		Driver: &netreconcile.LinuxDriver{DryRun: *dryRun},
	}

	eng, err := configengine.Open(context.Background(), configengine.Options{
		BaseDir:           *storeDir,
		Schema:            cs,
		Applier:           applier,
		Migrator:          mig,
		SemanticValidator: wlanplan.ValidateAllSemantic,
	})
	if err != nil {
		fmt.Fprintf(stderr, "open config engine failed: %v\n", err)
		return 1
	}
	defer eng.Close()

	running := eng.GetRunning(false)
	if err := applier.Plan(context.Background(), running, running, nil); err != nil {
		fmt.Fprintf(stderr, "wireless plan validation failed: %v\n", err)
		return 1
	}
	if err := applier.Apply(context.Background(), running, nil); err != nil {
		fmt.Fprintf(stderr, "wireless reconciliation failed: %v\n", err)
		return 1
	}

	cfg, err := wlanplan.ParseConfig(running)
	if err != nil {
		fmt.Fprintf(stderr, "parse running config failed: %v\n", err)
		return 1
	}
	ac := wlanctrl.NewACController(cfg.Wireless, nil)
	var rf wlanplan.WLANRFProfile
	if len(cfg.Wireless.RFProfiles) > 0 {
		rf = cfg.Wireless.RFProfiles[0]
	}
	plans := wlanctrl.OptimizeRF(cfg.Wireless.APs, rf, nil)

	fmt.Fprintf(stdout, "%s\ndaiji-ac: reconciled revision=%s aps=%d rrm_plans=%d dry_run=%v\n",
		sysinfo.BrandBanner, eng.CurrentRevisionID(), len(ac.Inventory()), len(plans), *dryRun)
	return 0
}
