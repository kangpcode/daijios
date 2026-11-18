// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// daiji-webd serves the embedded DaiWeb UI, REST APIs, and RFC 6455 WebSocket streams.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/daiweb"
	"github.com/kangpcode/daijios/pkg/netplan"
	"github.com/kangpcode/daijios/pkg/schema"
	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
	"github.com/kangpcode/daijios/pkg/wlanplan"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daiji-webd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listenAddr := fs.String("listen", ":8443", "HTTP listen address")
	storeDir := fs.String("store", "/var/lib/daiji/config", "config store directory")
	schemaPath := fs.String("schema", "schema/daijios.schema.json", "path to DaijiOS schema JSON")
	bootstrapPath := fs.String("bootstrap", "", "optional bootstrap config JSON if store is empty")
	adminPass := fs.String("admin-password", "", "optional operator password (lab/dev override)")
	signingKey := fs.String("signing-key", "", "HMAC-SHA256 signing key (auto-generated if omitted)")
	checkOnly := fs.Bool("check", false, "initialize server, verify asset bundle & exit cleanly")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cs, err := schema.LoadFile(*schemaPath)
	if err != nil {
		fmt.Fprintf(stderr, "load schema failed: %v\n", err)
		return 1
	}

	var boot map[string]any
	if *bootstrapPath != "" {
		raw, err := os.ReadFile(*bootstrapPath)
		if err != nil {
			fmt.Fprintf(stderr, "read bootstrap failed: %v\n", err)
			return 1
		}
		if err := json.Unmarshal(raw, &boot); err != nil {
			fmt.Fprintf(stderr, "parse bootstrap failed: %v\n", err)
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
		fmt.Fprintf(stderr, "open config engine failed: %v\n", err)
		return 1
	}
	defer eng.Close()

	keyBytes := []byte(*signingKey)
	if len(keyBytes) < 16 {
		var rnd [32]byte
		_, _ = rand.Read(rnd[:])
		keyBytes = []byte(hex.EncodeToString(rnd[:]))
	}
	tm, err := secauth.NewTokenManager(keyBytes, 12*time.Hour)
	if err != nil {
		fmt.Fprintf(stderr, "token manager init failed: %v\n", err)
		return 1
	}

	accounts := map[string]daiweb.Account{}
	if *adminPass != "" {
		accounts["daijiadmin"] = daiweb.Account{Username: "daijiadmin", Role: "superadmin", Password: *adminPass}
	}

	srv, err := daiweb.NewServer(daiweb.Dependencies{
		Config:   eng,
		Schema:   cs,
		Tokens:   tm,
		Accounts: accounts,
	})
	if err != nil {
		fmt.Fprintf(stderr, "daiweb init failed: %v\n", err)
		return 1
	}

	rawB, gzB := srv.AssetBundleStats()
	fmt.Fprintln(stdout, sysinfo.RenderBootBanner("daiji-webd", runtime.GOARCH, "A", sysinfo.Version, eng.SafeMode()))
	fmt.Fprintf(stdout, "DaiWeb bundle ready: raw=%dB gzip=%dB paths=OK listen=%s\n", rawB, gzB, *listenAddr)

	if *checkOnly {
		return 0
	}

	httpSrv := &http.Server{
		Addr:              *listenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shCtx)
	}()

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(stderr, "http serve error: %v\n", err)
		return 1
	}
	return 0
}
