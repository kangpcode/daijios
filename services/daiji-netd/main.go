// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// daiji-netd is the Phase 1 networking core reconciler daemon for DaijiOS.
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
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daiji-netd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	storeDir := fs.String("store", "/var/lib/daiji/config", "config store directory")
	schemaPath := fs.String("schema", "schema/daijios.schema.json", "path to DaijiOS schema JSON")
	statePath := fs.String("state", "/var/lib/daiji/netd-state.json", "path to managed link state file")
	dryRun := fs.Bool("dry-run", false, "validate and reconcile without mutating host OS")
	once := fs.Bool("once", true, "reconcile running configuration once and exit")
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

	driver := &netreconcile.LinuxDriver{
		StatePath: *statePath,
		DryRun:    *dryRun,
	}
	applier := &netreconcile.NetworkApplier{Driver: driver}

	eng, err := configengine.Open(context.Background(), configengine.Options{
		BaseDir:           *storeDir,
		Schema:            cs,
		Applier:           applier,
		Migrator:          mig,
		SemanticValidator: netplan.ValidateSemantic,
	})
	if err != nil {
		fmt.Fprintf(stderr, "open config engine failed: %v\n", err)
		return 1
	}
	defer eng.Close()

	running := eng.GetRunning(false)
	if err := applier.Plan(context.Background(), running, running, nil); err != nil {
		fmt.Fprintf(stderr, "network plan validation failed: %v\n", err)
		return 1
	}
	if err := applier.Apply(context.Background(), running, nil); err != nil {
		fmt.Fprintf(stderr, "network reconciliation failed: %v\n", err)
		return 1
	}
	_ = eng.MarkBootHealthy("daiji-netd")

	fmt.Fprintf(stdout, "%s\ndaiji-netd: reconciled revision=%s dry_run=%v once=%v\n",
		sysinfo.BrandBanner, eng.CurrentRevisionID(), *dryRun, *once)
	return 0
}
