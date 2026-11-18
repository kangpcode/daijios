// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijicli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/ispengine"
	"github.com/kangpcode/daijios/pkg/ispplan"
	"github.com/kangpcode/daijios/pkg/isptools"
	"github.com/kangpcode/daijios/pkg/netplan"
	"github.com/kangpcode/daijios/pkg/schema"
	"github.com/kangpcode/daijios/pkg/wlanplan"
)

func loadTestEngine(t *testing.T) (*schema.CompiledSchema, *configengine.Engine) {
	t.Helper()
	schemaPath := filepath.Join("..", "..", "schema", "daijios.schema.json")
	cfgPath := filepath.Join("..", "..", "schema", "examples", "default-config.json")

	cs, err := schema.LoadFile(schemaPath)
	if err != nil {
		t.Fatalf("LoadFile schema: %v", err)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile bootstrap: %v", err)
	}
	var boot map[string]any
	if err := json.Unmarshal(raw, &boot); err != nil {
		t.Fatalf("Unmarshal bootstrap: %v", err)
	}
	mig := configengine.NewMigrator()
	_ = netplan.RegisterMigrations(mig)

	eng, err := configengine.Open(context.Background(), configengine.Options{
		BaseDir:           t.TempDir(),
		Schema:            cs,
		Migrator:          mig,
		SemanticValidator: wlanplan.ValidateAllSemantic,
		BootstrapConfig:   boot,
	})
	if err != nil {
		t.Fatalf("Open configengine: %v", err)
	}
	t.Cleanup(func() { eng.Close() })
	return cs, eng
}

func TestModeHierarchyAndRBAC(t *testing.T) {
	ctx := context.Background()
	cs, eng := loadTestEngine(t)

	// Readonly role cannot enter privileged or config mode.
	roSess, err := NewSession("viewer", "readonly", eng, cs)
	if err != nil {
		t.Fatalf("NewSession readonly: %v", err)
	}
	if _, err := roSess.Execute(ctx, "show version"); err != nil {
		t.Fatalf("readonly show version failed: %v", err)
	}
	if _, err := roSess.Execute(ctx, "enable"); err == nil {
		t.Fatalf("expected readonly 'enable' to be denied by RBAC")
	}

	// Superadmin walks the full mode hierarchy.
	sess, err := NewSession("daijiadmin", "superadmin", eng, cs)
	if err != nil {
		t.Fatalf("NewSession admin: %v", err)
	}
	if sess.Mode != ModeUser || !strings.HasSuffix(sess.Prompt(), "> ") {
		t.Fatalf("unexpected initial mode/prompt: %q / %q", sess.Mode, sess.Prompt())
	}

	// User mode blocks config/startup/debug.
	for _, blocked := range []string{"config", "set system.hostname x", "show startup", "show revisions", "save", "debug config-tree"} {
		if _, err := sess.Execute(ctx, blocked); err == nil {
			t.Fatalf("expected user mode to block %q", blocked)
		}
	}

	if _, err := sess.Execute(ctx, "enable"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if sess.Mode != ModePrivileged || !strings.HasSuffix(sess.Prompt(), "# ") {
		t.Fatalf("unexpected privileged prompt: %q", sess.Prompt())
	}

	if _, err := sess.Execute(ctx, "config"); err != nil {
		t.Fatalf("config: %v", err)
	}
	if sess.Mode != ModeConfig || !strings.HasSuffix(sess.Prompt(), "(cfg)# ") {
		t.Fatalf("unexpected config prompt: %q", sess.Prompt())
	}

	if _, err := sess.Execute(ctx, "enter management"); err != nil {
		t.Fatalf("enter management: %v", err)
	}
	if sess.Mode != ModeSubConfig || sess.SubContext != "management" || !strings.Contains(sess.Prompt(), "(cfg:management)# ") {
		t.Fatalf("unexpected sub-config prompt: mode=%s ctx=%s prompt=%s", sess.Mode, sess.SubContext, sess.Prompt())
	}

	if _, err := sess.Execute(ctx, "enter ssh"); err != nil {
		t.Fatalf("enter nested ssh: %v", err)
	}
	if sess.SubContext != "management.ssh" {
		t.Fatalf("expected SubContext management.ssh, got %q", sess.SubContext)
	}

	if _, err := sess.Execute(ctx, "up"); err != nil {
		t.Fatalf("up: %v", err)
	}
	if sess.SubContext != "management" {
		t.Fatalf("expected SubContext management after up, got %q", sess.SubContext)
	}

	if _, err := sess.Execute(ctx, "top"); err != nil {
		t.Fatalf("top: %v", err)
	}
	if sess.Mode != ModeConfig || sess.SubContext != "" {
		t.Fatalf("expected ModeConfig after top, got %s (%s)", sess.Mode, sess.SubContext)
	}

	// Step down: config -> privileged -> user -> exit session.
	for _, wantMode := range []Mode{ModePrivileged, ModeUser} {
		if _, err := sess.Execute(ctx, "exit"); err != nil {
			t.Fatalf("exit: %v", err)
		}
		if sess.Mode != wantMode {
			t.Fatalf("expected mode %s, got %s", wantMode, sess.Mode)
		}
	}
	res, err := sess.Execute(ctx, "exit")
	if err != nil || !res.ExitRequested {
		t.Fatalf("expected ExitRequested on final exit, got res=%+v err=%v", res, err)
	}
}

func TestCompletionHelpFuzzyAliasHistoryPipes(t *testing.T) {
	ctx := context.Background()
	cs, eng := loadTestEngine(t)
	sess, err := NewSession("daijiadmin", "superadmin", eng, cs)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// Tab completion in user mode & pipe completion.
	if comps := sess.Complete("sh"); len(comps) != 1 || comps[0].Token != "show" {
		t.Fatalf("unexpected verb completion for 'sh': %+v", comps)
	}
	if comps := sess.Complete("show a"); len(comps) < 2 {
		t.Fatalf("expected show targets for 'show a' (about, audit-verify), got %+v", comps)
	}
	pipeComps := sess.Complete("show running | in")
	if len(pipeComps) != 1 || pipeComps[0].Token != "include" {
		t.Fatalf("expected pipe include completion, got %+v", pipeComps)
	}

	// Enter config + sub-config to test relative completion, enum completion, and '?'.
	_, _ = sess.Execute(ctx, "enable")
	_, _ = sess.Execute(ctx, "config")
	enumComps := sess.Complete("set updates.channel ")
	if len(enumComps) != 3 {
		t.Fatalf("expected 3 enum completions for updates.channel, got %+v", enumComps)
	}
	enterComps := sess.Complete("enter sys")
	if len(enterComps) == 0 || enterComps[0].Token != "system" {
		t.Fatalf("expected 'enter system' container completion, got %+v", enterComps)
	}

	_, _ = sess.Execute(ctx, "enter system")
	subComps := sess.Complete("set motd")
	if len(subComps) != 1 || subComps[0].Token != "motd_banner" {
		t.Fatalf("expected relative sub-config completion 'motd_banner', got %+v", subComps)
	}
	_, _ = sess.Execute(ctx, "top")

	// Contextual '?' help: leaf metadata, verb args, and root list.
	if res, err := sess.Execute(ctx, "?"); err != nil || !strings.Contains(res.Output, "commit") {
		t.Fatalf("'?' failed: %v output=%s", err, res.Output)
	}
	if res, err := sess.Execute(ctx, "set system.hostname ?"); err != nil || !strings.Contains(res.Output, "string") {
		t.Fatalf("'set system.hostname ?' failed: %v output=%v", err, res)
	}
	if res, err := sess.Execute(ctx, "set updates.channel?"); err != nil || !strings.Contains(res.Output, "stable|lts|beta") {
		t.Fatalf("'set updates.channel?' failed: %v output=%v", err, res)
	}

	// Fuzzy search: substring & ordered subsequence ("syshn" -> system.hostname).
	hits := sess.Registry.FuzzySearch("syshn", 5)
	if len(hits) == 0 || hits[0].Path != "system.hostname" {
		t.Fatalf("fuzzy search 'syshn' failed: %+v", hits)
	}
	searchRes, err := sess.Execute(ctx, "search ssh")
	if err != nil || !strings.Contains(searchRes.Output, "management.ssh") {
		t.Fatalf("search cmd failed: %v %+v", err, searchRes)
	}

	// Alias expansion & unalias.
	if _, err := sess.Execute(ctx, "alias sr show running"); err != nil {
		t.Fatalf("alias define: %v", err)
	}
	if res, err := sess.Execute(ctx, "sr | include daiji-core-01 | count"); err != nil || strings.TrimSpace(res.Output) != "1" {
		t.Fatalf("alias + chainable pipes failed: err=%v out=%+v", err, res)
	}
	if _, err := sess.Execute(ctx, "unalias sr"); err != nil {
		t.Fatalf("unalias: %v", err)
	}

	// Quoted pipe & | json & | exclude.
	jsonRes, err := sess.Execute(ctx, "show version | json")
	if err != nil || !strings.Contains(jsonRes.Output, `"brand_banner"`) {
		t.Fatalf("show version | json failed: err=%v out=%v", err, jsonRes)
	}
	excRes, err := sess.Execute(ctx, "show running | exclude schema_version")
	if err != nil || strings.Contains(excRes.Output, "schema_version") {
		t.Fatalf("pipe exclude failed: err=%v", err)
	}
	if _, err := sess.Execute(ctx, "show running | bogus"); err == nil {
		t.Fatalf("expected invalid pipe error")
	}

	// Secret redaction in history & !N recall.
	_, _ = sess.Execute(ctx, "set system.users[0].password_hash secretpassphrasevalue123")
	histRes, err := sess.Execute(ctx, "history")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if strings.Contains(histRes.Output, "secretpassphrasevalue123") || !strings.Contains(histRes.Output, "***REDACTED***") {
		t.Fatalf("history failed to redact secret: %s", histRes.Output)
	}
	if _, err := sess.Execute(ctx, "!9999"); err == nil {
		t.Fatalf("expected error on invalid history recall !9999")
	}
	if _, err := sess.Execute(ctx, "!1"); err != nil {
		t.Fatalf("history recall !1 failed: %v", err)
	}
}

func TestConfigLifecycleRollbackMonitorAndSubsystems(t *testing.T) {
	ctx := context.Background()
	cs, eng := loadTestEngine(t)
	sess, err := NewSession("daijiadmin", "superadmin", eng, cs)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// Attach live ISP subsystems so show sessions/wans and monitor traffic return structured data.
	bngRaw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "isp-bng-config.json"))
	if err != nil {
		t.Fatalf("ReadFile bng: %v", err)
	}
	var bngMap map[string]any
	if err := json.Unmarshal(bngRaw, &bngMap); err != nil {
		t.Fatalf("Unmarshal bng: %v", err)
	}
	bngCfg, err := ispplan.ParseConfig(bngMap)
	if err != nil {
		t.Fatalf("ParseConfig bng: %v", err)
	}

	sess.Sessions = ispengine.NewSessionManager(&bngCfg.ISP)
	if _, err := sess.Sessions.AuthenticatePPPoE("budi@fiber.daiji", "BudiPass2026!", "aa:bb:cc:11:22:33", time.Now()); err != nil {
		t.Fatalf("AuthenticatePPPoE: %v", err)
	}
	sess.MultiWAN = ispengine.NewMultiWANMonitor(bngCfg.ISP.MultiWAN)
	sess.MultiWAN.RecordProbe("wan-a", "1.1.1.1", 4.2, true)
	sess.Torch = isptools.NewTorchAggregator()
	sess.Torch.Ingest(isptools.FlowSample{
		Timestamp: time.Now(),
		SrcIP:     "192.168.88.10",
		DstIP:     "1.1.1.1",
		Protocol:  "UDP",
		SrcPort:   5353,
		DstPort:   53,
		Bytes:     4096,
		Tx:        true,
	})

	if res, err := sess.Execute(ctx, "show sessions"); err != nil || !strings.Contains(res.Output, "budi@fiber.daiji") {
		t.Fatalf("show sessions failed: err=%v res=%+v", err, res)
	}
	if res, err := sess.Execute(ctx, "show wans"); err != nil || !strings.Contains(res.Output, "wan-a") {
		t.Fatalf("show wans failed: err=%v res=%+v", err, res)
	}
	if res, err := sess.Execute(ctx, "monitor traffic | json"); err != nil || !strings.Contains(res.Output, "192.168.88.10") {
		t.Fatalf("monitor traffic failed: err=%v res=%+v", err, res)
	}

	_, _ = sess.Execute(ctx, "enable")
	_, _ = sess.Execute(ctx, "config")
	_, _ = sess.Execute(ctx, "set system.hostname daiji-temp-edit")
	if diffRes, err := sess.Execute(ctx, "diff"); err != nil || !strings.Contains(diffRes.Output, "daiji-temp-edit") {
		t.Fatalf("diff failed: err=%v res=%+v", err, diffRes)
	}
	if _, err := sess.Execute(ctx, "discard"); err != nil {
		t.Fatalf("discard failed: %v", err)
	}

	// Stage real change, validate, commit-confirm + confirm, save, and rollback.
	_, _ = sess.Execute(ctx, "set system.hostname daiji-committed")
	_, _ = sess.Execute(ctx, "unset system.domain_name")
	if _, err := sess.Execute(ctx, "set system.domain_name edge.daiji.local"); err != nil {
		t.Fatalf("set domain_name: %v", err)
	}
	if _, err := sess.Execute(ctx, "validate"); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := sess.Execute(ctx, "commit-confirm 3"); err != nil {
		t.Fatalf("commit-confirm: %v", err)
	}
	if _, err := sess.Execute(ctx, "confirm"); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if _, err := sess.Execute(ctx, "save"); err != nil {
		t.Fatalf("save: %v", err)
	}
	if res, err := sess.Execute(ctx, "show startup | include daiji-committed"); err != nil || !strings.Contains(res.Output, "daiji-committed") {
		t.Fatalf("show startup check failed: err=%v res=%+v", err, res)
	}
	if res, err := sess.Execute(ctx, "debug config-tree | json"); err != nil || !strings.Contains(res.Output, `"total_paths"`) {
		t.Fatalf("debug config-tree failed: err=%v res=%+v", err, res)
	}
	if _, err := sess.Execute(ctx, "rollback 1 --commit"); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if res, err := sess.Execute(ctx, "show system hostname"); err != nil || !strings.Contains(res.Output, "daiji-core-01") {
		t.Fatalf("expected hostname rolled back to daiji-core-01, got err=%v out=%v", err, res)
	}
}

func TestCommandSchemaSynchronizedWithSSoT(t *testing.T) {
	cs, err := schema.LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	doc, err := BuildCommandSchema(cs)
	if err != nil {
		t.Fatalf("BuildCommandSchema: %v", err)
	}
	if doc.SchemaVersion != cs.Root.SchemaVersion {
		t.Fatalf("version mismatch: %s vs %s", doc.SchemaVersion, cs.Root.SchemaVersion)
	}
	if len(doc.Modes) != 4 {
		t.Fatalf("expected 4 modes, got %d", len(doc.Modes))
	}

	verbSet := make(map[string]bool)
	for _, v := range doc.Verbs {
		verbSet[v.Name] = true
	}
	for _, requiredVerb := range []string{"show", "set", "unset", "add", "remove", "commit", "rollback", "diff", "monitor", "debug"} {
		if !verbSet[requiredVerb] {
			t.Fatalf("command schema missing required Fase 5 verb %q", requiredVerb)
		}
	}

	nodeMap := make(map[string]SchemaNodeMeta, len(doc.Paths))
	for _, p := range doc.Paths {
		nodeMap[p.DotPath] = p
	}
	for _, mapping := range doc.CLIMappings {
		if _, ok := nodeMap[mapping.ConfigPath]; !ok {
			t.Fatalf("CLI mapping %q (%s) missing from CommandRegistry SSoT tree", mapping.ConfigPath, mapping.CLIPath)
		}
	}
}

func BenchmarkCLISessionExecute(b *testing.B) {
	schemaPath := filepath.Join("..", "..", "schema", "daijios.schema.json")
	cfgPath := filepath.Join("..", "..", "schema", "examples", "default-config.json")
	cs, err := schema.LoadFile(schemaPath)
	if err != nil {
		b.Fatal(err)
	}
	raw, _ := os.ReadFile(cfgPath)
	var boot map[string]any
	_ = json.Unmarshal(raw, &boot)
	eng, err := configengine.Open(context.Background(), configengine.Options{
		BaseDir:         b.TempDir(),
		Schema:          cs,
		BootstrapConfig: boot,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer eng.Close()

	sess, err := NewSession("bench", "superadmin", eng, cs)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sess.Execute(ctx, "show running | include hostname"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTabComplete(b *testing.B) {
	cs, err := schema.LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		b.Fatal(err)
	}
	sess, _ := NewSession("bench", "superadmin", nil, cs)
	sess.Mode = ModeConfig
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sess.Complete("set system.")
	}
}

func BenchmarkFuzzySearch(b *testing.B) {
	cs, err := schema.LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		b.Fatal(err)
	}
	reg, err := BuildRegistry(cs)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reg.FuzzySearch("pppoe", 10)
	}
}
