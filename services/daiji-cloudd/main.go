// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// daiji-cloudd runs the Phase 10 DaijiCloud multi-tenant fleet control plane & Public API server.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/kangpcode/daijios/pkg/daijicloud"
	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daiji-cloudd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listenAddr := fs.String("listen", ":8080", "HTTP multi-tenant API listen address")
	ztpSecret := fs.String("ztp-secret", "", "ZTP HMAC signing secret")
	drSecret := fs.String("dr-secret", "", "Disaster Recovery snapshot HMAC key")
	checkOnly := fs.Bool("check", false, "verify ControlPlane & DR readiness and exit cleanly")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var rnd [32]byte
	_, _ = rand.Read(rnd[:])
	tm, err := secauth.NewTokenManager([]byte(hex.EncodeToString(rnd[:])), 12*time.Hour)
	if err != nil {
		fmt.Fprintf(stderr, "token manager error: %v\n", err)
		return 1
	}

	cp := daijicloud.NewControlPlane([]byte(*ztpSecret), []byte(*drSecret), nil)
	srv, err := daijicloud.NewServer(cp, tm)
	if err != nil {
		fmt.Fprintf(stderr, "daiji-cloudd init error: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, sysinfo.RenderBootBanner("daiji-cloudd", runtime.GOARCH, "A", sysinfo.Version, false))
	fmt.Fprintf(stdout, "DaijiCloud ready: listen=%s api=/api/v1/cloud/* metrics=/metrics\n", *listenAddr)

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
