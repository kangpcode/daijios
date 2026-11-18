// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// daiji-fw-qosd is the Phase 2 firewall, QoS, VPN, and OS hardening reconciler daemon.
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
	"github.com/kangpcode/daijios/pkg/secplan"
	"github.com/kangpcode/daijios/pkg/secreconcile"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daiji-fw-qosd", flag.ContinueOnError)
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

	applier := &secreconcile.SecurityApplier{
		Driver: &netreconcile.LinuxDriver{DryRun: *dryRun},
	}

	eng, err := configengine.Open(context.Background(), configengine.Options{
		BaseDir:           *storeDir,
		Schema:            cs,
		Applier:           applier,
		Migrator:          mig,
		SemanticValidator: secplan.ValidateAllSemantic,
	})
	if err != nil {
		fmt.Fprintf(stderr, "open config engine failed: %v\n", err)
		return 1
	}
	defer eng.Close()

	running := eng.GetRunning(false)
	if err := applier.Plan(context.Background(), running, running, nil); err != nil {
		fmt.Fprintf(stderr, "security plan validation failed: %v\n", err)
		return 1
	}
	if err := applier.Apply(context.Background(), running, nil); err != nil {
		fmt.Fprintf(stderr, "security reconciliation failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "%s\ndaiji-fw-qosd: reconciled revision=%s dry_run=%v\n",
		sysinfo.BrandBanner, eng.CurrentRevisionID(), *dryRun)
	return 0
}
