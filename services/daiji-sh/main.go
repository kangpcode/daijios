// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// daiji-sh is the portable interactive & batch DaijiOS Original CLI Shell.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/daijicli"
	"github.com/kangpcode/daijios/pkg/netplan"
	"github.com/kangpcode/daijios/pkg/schema"
	"github.com/kangpcode/daijios/pkg/sysinfo"
	"github.com/kangpcode/daijios/pkg/wlanplan"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daiji-sh", flag.ContinueOnError)
	fs.SetOutput(stderr)
	storeDir := fs.String("store", "/var/lib/daiji/config", "config store directory")
	schemaPath := fs.String("schema", "schema/daijios.schema.json", "path to DaijiOS schema JSON")
	bootstrapPath := fs.String("bootstrap", "", "optional bootstrap config JSON if store is empty")
	actor := fs.String("actor", "daijiadmin", "operator username")
	role := fs.String("role", "superadmin", "RBAC role")
	batchCmd := fs.String("cmd", "", "non-interactive command(s) separated by ';'")
	jsonOut := fs.Bool("json", false, "emit JSON results where structured output exists")
	quiet := fs.Bool("quiet", false, "suppress startup banner and prompts")
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

	sess, err := daijicli.NewSession(*actor, *role, eng, cs)
	if err != nil {
		fmt.Fprintf(stderr, "init cli session failed: %v\n", err)
		return 1
	}

	ctx := context.Background()

	// Non-interactive batch mode (--cmd).
	if strings.TrimSpace(*batchCmd) != "" {
		for _, part := range strings.Split(*batchCmd, ";") {
			cmd := strings.TrimSpace(part)
			if cmd == "" {
				continue
			}
			res, err := sess.Execute(ctx, cmd)
			if err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
				return 1
			}
			writeCommandResult(stdout, res, *jsonOut)
			if res.ExitRequested {
				return 0
			}
		}
		return 0
	}

	// Interactive shell mode (portable stdio REPL across amd64/arm64/armv7/mipsel/mips64le).
	if !*quiet {
		hostname := extractHostname(eng)
		fmt.Fprintln(stdout, sysinfo.RenderBootBanner(hostname, runtime.GOARCH, "A", sysinfo.Version, eng.SafeMode()))
		fmt.Fprintln(stdout, "Type '?' or 'help' for commands, '/tab <prefix>' or '<prefix>\\t' to complete, 'exit' to leave.")
	}

	scanner := bufio.NewScanner(stdin)
	for {
		if !*quiet {
			fmt.Fprint(stdout, sess.Prompt())
		}
		if !scanner.Scan() {
			break
		}
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			continue
		}

		// Portable Tab completion trigger: `/tab <prefix>` or trailing `\t` or literal TAB char.
		if strings.HasPrefix(trimmed, "/tab ") || trimmed == "/tab" || strings.HasSuffix(rawLine, "\t") || strings.HasSuffix(trimmed, `\t`) {
			prefix := extractCompletionPrefix(rawLine, trimmed)
			items := sess.Complete(prefix)
			if *jsonOut {
				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				_ = enc.Encode(items)
			} else {
				for _, it := range items {
					fmt.Fprintf(stdout, "  %-28s %s\n", it.Token, it.Description)
				}
				if len(items) == 0 {
					fmt.Fprintln(stdout, "  (no completions)")
				}
			}
			continue
		}

		res, err := sess.Execute(ctx, trimmed)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			continue
		}
		writeCommandResult(stdout, res, *jsonOut)
		if res.ExitRequested {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(stderr, "input error: %v\n", err)
		return 1
	}
	return 0
}

func extractHostname(eng *configengine.Engine) string {
	run := eng.GetRunning(true)
	if sysMap, ok := run["system"].(map[string]any); ok {
		if h, ok := sysMap["hostname"].(string); ok && h != "" {
			return h
		}
	}
	return "daiji"
}

func extractCompletionPrefix(rawLine, trimmed string) string {
	if trimmed == "/tab" {
		return ""
	}
	if strings.HasPrefix(trimmed, "/tab ") {
		return strings.TrimPrefix(trimmed, "/tab ")
	}
	if strings.HasSuffix(rawLine, "\t") {
		return strings.TrimSuffix(rawLine, "\t")
	}
	return strings.TrimSuffix(trimmed, `\t`)
}

func writeCommandResult(stdout io.Writer, res *daijicli.CommandResult, asJSON bool) {
	if res == nil {
		return
	}
	if asJSON && res.Structured != nil {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res.Structured)
		return
	}
	if res.Output != "" {
		fmt.Fprintln(stdout, res.Output)
	}
}
