// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// daiji-billingd runs the Phase 9 DaijiBilling PPPoE billing, webhook, and Customer Portal server.
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

	"github.com/kangpcode/daijios/pkg/daijibilling"
	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daiji-billingd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listenAddr := fs.String("listen", ":8090", "HTTP billing/portal/webhook listen address")
	midtransKey := fs.String("midtrans-key", "", "Midtrans SHA-512 server key")
	xenditToken := fs.String("xendit-token", "", "Xendit callback token")
	qrisSecret := fs.String("qris-secret", "", "QRIS/VA HMAC-SHA256 webhook secret")
	checkOnly := fs.Bool("check", false, "verify billing engine initialization and exit cleanly")
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

	eng := daijibilling.NewEngine(daijibilling.Options{
		MidtransKey:    *midtransKey,
		XenditToken:    *xenditToken,
		QRISHMACSecret: *qrisSecret,
	})
	srv, err := daijibilling.NewServer(eng, tm, rnd[:])
	if err != nil {
		fmt.Fprintf(stderr, "daiji-billingd init error: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, sysinfo.RenderBootBanner("daiji-billingd", runtime.GOARCH, "A", sysinfo.Version, false))
	fmt.Fprintf(stdout, "DaijiBilling ready: listen=%s portal=/portal webhooks=/webhooks/billing/*\n", *listenAddr)

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
