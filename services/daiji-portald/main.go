// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// daiji-portald runs the Phase 11 DaijiPortal SaaS server:
// white-label reseller branding, Ed25519 online/offline licensing,
// marketplace/subscriptions, signed update channels, tickets, and KB.
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

	"github.com/kangpcode/daijios/pkg/daijiportal"
	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daiji-portald", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listenAddr := fs.String("listen", ":8070", "HTTP DaijiPortal SaaS listen address")
	checkOnly := fs.Bool("check", false, "verify Ed25519 keys, portal hub, and exit cleanly")
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

	portal, err := daijiportal.NewPortal(nil, nil)
	if err != nil {
		fmt.Fprintf(stderr, "portal init error: %v\n", err)
		return 1
	}
	srv, err := daijiportal.NewServer(portal, tm)
	if err != nil {
		fmt.Fprintf(stderr, "portal server error: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, sysinfo.RenderBootBanner("daiji-portald", runtime.GOARCH, "A", sysinfo.Version, false))
	fmt.Fprintf(stdout, "DaijiPortal ready: listen=%s ed25519_pub=%s\n", *listenAddr, hex.EncodeToString(portal.PublicKey()[:8]))

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
