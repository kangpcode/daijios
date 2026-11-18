// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijicli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/schema"
)

// FuzzCLIParserAndPipe fuzzes DaijiOS pipe parsing, completion, and interactive session execution.
func FuzzCLIParserAndPipe(f *testing.F) {
	seeds := []string{
		"show system version",
		"show interfaces | include eth | count",
		"show schema | json",
		"configure",
		"set system hostname \"edge-jkt-01\"",
		"commit-confirm 5",
		"show ? ",
		"invalid ||| \"unclosed",
		"!99999999",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	cs, err := schema.LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		f.Fatalf("LoadFile schema: %v", err)
	}
	rawCfg, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "default-config.json"))
	if err != nil {
		f.Fatalf("ReadFile default-config: %v", err)
	}
	var boot map[string]any
	if err := json.Unmarshal(rawCfg, &boot); err != nil {
		f.Fatalf("Unmarshal bootstrap: %v", err)
	}
	eng, err := configengine.Open(context.Background(), configengine.Options{
		BaseDir:         f.TempDir(),
		Schema:          cs,
		BootstrapConfig: boot,
	})
	if err != nil {
		f.Fatalf("configengine.Open: %v", err)
	}
	sess, err := NewSession("fuzzop", "superadmin", eng, cs)
	if err != nil {
		f.Fatalf("NewSession: %v", err)
	}
	ctx := context.Background()

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 2048 {
			return
		}
		_, _, _ = SplitPipes(raw)
		_ = sess.ContextualHelp(raw)
		_ = sess.Registry.FuzzySearch(raw, 5)
		_, _ = sess.Execute(ctx, raw)
	})
}
