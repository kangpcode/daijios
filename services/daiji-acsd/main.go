// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// daiji-acsd is the Phase 8 DaijiACS TR-069 (CWMP) & TR-369 (USP) Auto-Configuration Server daemon.
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

	"github.com/kangpcode/daijios/pkg/daijiacs"
	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daiji-acsd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listenAddr := fs.String("listen", ":7547", "CWMP/USP HTTP listen address")
	cwmpUser := fs.String("cwmp-user", "daiji-cpe", "CWMP HTTP Basic Auth username")
	cwmpPass := fs.String("cwmp-pass", "", "CWMP HTTP Basic Auth password (optional)")
	allowHTTP := fs.Bool("allow-http-fw", false, "allow http:// firmware upgrade URLs in lab environments")
	checkOnly := fs.Bool("check", false, "verify templates/server initialization and exit cleanly")
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

	templates := daijiacs.DefaultVendorTemplates()
	srv, err := daijiacs.NewServer(daijiacs.Config{
		Templates:         templates,
		CWMPUsername:      *cwmpUser,
		CWMPPassword:      *cwmpPass,
		Tokens:            tm,
		AllowInsecureHTTP: *allowHTTP,
		Presets: []daijiacs.PresetRule{
			{
				ID:            "daiji-default-bootstrap",
				PolicyVersion: 1,
				EventFilter:   "0 BOOTSTRAP",
				VirtualSets:   map[string]string{"virtual.inform.interval": "300"},
			},
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "daiji-acsd init error: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, sysinfo.RenderBootBanner("daiji-acsd", runtime.GOARCH, "A", sysinfo.Version, false))
	fmt.Fprintf(stdout, "DaijiACS ready: templates=%d listen=%s cwmp_path=/tr069 usp_path=/usp\n", len(templates), *listenAddr)

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
