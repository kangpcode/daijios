// SPDX-License-Identifier: Apache-2.0
package configengine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kangpcode/daijios/pkg/schema"
)

func loadTestSchemaAndBootstrap(t *testing.T) (*schema.CompiledSchema, map[string]any) {
	t.Helper()
	cs, err := schema.LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "default-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cs, cfg
}

type faultInjectApplier struct {
	failOnHostname string
	appliedHosts   []string
}

func (f *faultInjectApplier) Plan(_ context.Context, _, target map[string]any, _ []DiffEntry) error {
	return nil
}

func (f *faultInjectApplier) Apply(_ context.Context, target map[string]any, _ []DiffEntry) error {
	sys, _ := target["system"].(map[string]any)
	host, _ := sys["hostname"].(string)
	if f.failOnHostname != "" && host == f.failOnHostname {
		return errors.New("simulated kernel/daemon apply failure")
	}
	f.appliedHosts = append(f.appliedHosts, host)
	return nil
}

func TestCommitDiffRollbackAndSecretRedaction(t *testing.T) {
	cs, boot := loadTestSchemaAndBootstrap(t)
	dir := t.TempDir()
	applier := &faultInjectApplier{}

	eng, err := Open(context.Background(), Options{
		BaseDir:         dir,
		Schema:          cs,
		Applier:         applier,
		BootstrapConfig: boot,
	})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer eng.Close()

	// Redacted read should mask password_hash.
	redacted := eng.GetRunning(true)
	users := redacted["system"].(map[string]any)["users"].([]any)
	if users[0].(map[string]any)["password_hash"] != "***REDACTED***" {
		t.Fatalf("expected password_hash to be redacted, got %v", users[0])
	}

	// Lock exclusivity check.
	if err := eng.Lock("admin1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := eng.SetPath("admin2", "system.hostname", "hijack"); !errors.Is(err, ErrLockedByOther) {
		t.Fatalf("expected ErrLockedByOther, got %v", err)
	}

	if err := eng.SetPath("admin1", "system.hostname", "edge-sby-01"); err != nil {
		t.Fatal(err)
	}
	diffs := eng.DiffCandidate()
	if len(diffs) != 1 || diffs[0].Path != "system.hostname" {
		t.Fatalf("unexpected diffs: %+v", diffs)
	}

	res, err := eng.Commit(context.Background(), "admin1", "rename edge router", CommitOptions{})
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	if !res.Changed || res.Revision.ID != "rev-000002" {
		t.Fatalf("unexpected commit result: %+v", res)
	}

	// Verify startup remained old until SaveStartup is explicitly invoked.
	if eng.GetStartup(false)["system"].(map[string]any)["hostname"] != "daiji-core-01" {
		t.Fatal("startup unexpectedly mutated before SaveStartup")
	}
	if err := eng.SaveStartup("admin1"); err != nil {
		t.Fatal(err)
	}
	if eng.GetStartup(false)["system"].(map[string]any)["hostname"] != "edge-sby-01" {
		t.Fatal("SaveStartup did not persist running config")
	}

	// Rollback 1 (previous revision rev-000001).
	rbRes, err := eng.Rollback(context.Background(), "admin1", "1", true)
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}
	if !rbRes.Changed || eng.GetRunning(false)["system"].(map[string]any)["hostname"] != "daiji-core-01" {
		t.Fatalf("rollback did not restore original hostname: %+v", eng.GetRunning(false)["system"])
	}

	count, err := eng.VerifyAuditLog()
	if err != nil || count < 4 {
		t.Fatalf("VerifyAuditLog failed: count=%d err=%v", count, err)
	}
}

func TestCommitApplyFailureTriggersCompensatingRollback(t *testing.T) {
	cs, boot := loadTestSchemaAndBootstrap(t)
	applier := &faultInjectApplier{failOnHostname: "broken-host"}

	eng, err := Open(context.Background(), Options{
		BaseDir:         t.TempDir(),
		Schema:          cs,
		Applier:         applier,
		BootstrapConfig: boot,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	if err := eng.SetPath("netops", "system.hostname", "broken-host"); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Commit(context.Background(), "netops", "bad apply", CommitOptions{}); err == nil {
		t.Fatal("expected commit failure")
	}
	// Running state must remain daiji-core-01 and applier must have received compensating rollback.
	if got := eng.GetRunning(false)["system"].(map[string]any)["hostname"]; got != "daiji-core-01" {
		t.Fatalf("running mutated despite failed apply: %v", got)
	}
	if len(applier.appliedHosts) == 0 || applier.appliedHosts[len(applier.appliedHosts)-1] != "daiji-core-01" {
		t.Fatalf("expected compensating rollback apply to daiji-core-01, got %v", applier.appliedHosts)
	}
}

func TestCommitConfirmAutoRollbackAndCrashRecovery(t *testing.T) {
	cs, boot := loadTestSchemaAndBootstrap(t)
	dir := t.TempDir()

	eng, err := Open(context.Background(), Options{
		BaseDir:         dir,
		Schema:          cs,
		BootstrapConfig: boot,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Case 1: Confirm in time cancels rollback.
	_ = eng.SetPath("admin", "system.hostname", "confirmed-host")
	if _, err := eng.CommitConfirm(context.Background(), "admin", "confirm test", 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := eng.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
	if eng.PendingConfirmStatus() != nil {
		t.Fatal("pending confirm should be cleared after Confirm()")
	}

	// Case 2: Timeout triggers automatic deadman rollback.
	_ = eng.SetPath("admin", "system.hostname", "lockout-host")
	if _, err := eng.CommitConfirm(context.Background(), "admin", "auto rollback test", 60*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if eng.PendingConfirmStatus() == nil &&
			eng.GetRunning(false)["system"].(map[string]any)["hostname"] == "confirmed-host" {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if got := eng.GetRunning(false)["system"].(map[string]any)["hostname"]; got != "confirmed-host" {
		t.Fatalf("commit-confirm failed to auto-rollback, got hostname=%v", got)
	}
	eng.Close()

	// Case 3: Crash during CommitConfirm recovers on next Open after deadline.
	var clock int64
	nowBase := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	nowFn := func() time.Time {
		return nowBase.Add(time.Duration(atomic.LoadInt64(&clock)) * time.Second)
	}
	dir2 := t.TempDir()
	eng2, err := Open(context.Background(), Options{
		BaseDir:         dir2,
		Schema:          cs,
		BootstrapConfig: boot,
		Now:             nowFn,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = eng2.SetPath("admin", "system.hostname", "crashed-unconfirmed")
	if _, err := eng2.CommitConfirm(context.Background(), "admin", "crash before confirm", 10*time.Second); err != nil {
		t.Fatal(err)
	}
	// Simulate crash (close daemon without Confirm), advance clock past deadline, reopen.
	eng2.Close()
	atomic.StoreInt64(&clock, 20)

	eng3, err := Open(context.Background(), Options{
		BaseDir: dir2,
		Schema:  cs,
		Now:     nowFn,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng3.Close()
	if got := eng3.GetRunning(false)["system"].(map[string]any)["hostname"]; got != "daiji-core-01" {
		t.Fatalf("crash recovery did not revert unconfirmed commit, got %v", got)
	}
}

func TestSchemaMigrationAndSafeModeAndAuditTamperDetection(t *testing.T) {
	cs, boot := loadTestSchemaAndBootstrap(t)
	dir := t.TempDir()

	// Simulate an older v0.9.0 startup config on disk.
	oldBoot := deepCopyMap(boot)
	oldBoot["schema_version"] = "0.9.0"
	delete(oldBoot["system"].(map[string]any), "motd_banner")
	if err := writeJSONAtomic(filepath.Join(dir, "startup.json"), oldBoot); err != nil {
		t.Fatal(err)
	}

	mig := NewMigrator()
	if err := mig.Register("0.9.0", "1.0.0", func(cfg map[string]any) (map[string]any, error) {
		sys := cfg["system"].(map[string]any)
		sys["motd_banner"] = "DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)"
		return cfg, nil
	}); err != nil {
		t.Fatal(err)
	}
	if cs.Root.SchemaVersion != "" && cs.Root.SchemaVersion != "1.0.0" {
		if err := mig.Register("1.0.0", cs.Root.SchemaVersion, func(cfg map[string]any) (map[string]any, error) {
			return cfg, nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Boot 1..3 cold boots without MarkBootHealthy -> SafeMode triggers at attempt 3.
	for attempt := 1; attempt <= 3; attempt++ {
		eng, err := Open(context.Background(), Options{
			BaseDir:        dir,
			Schema:         cs,
			Migrator:       mig,
			ColdBoot:       true,
			MaxFailedBoots: 3,
		})
		if err != nil {
			t.Fatalf("attempt %d Open failed: %v", attempt, err)
		}
		if attempt < 3 && eng.SafeMode() {
			t.Fatalf("entered safe mode too early at attempt %d", attempt)
		}
		if attempt == 3 {
			if !eng.SafeMode() {
				t.Fatal("expected SafeMode=true on 3rd failed boot")
			}
			if err := eng.MarkBootHealthy("recovery-admin"); err != nil {
				t.Fatal(err)
			}
			if eng.SafeMode() {
				t.Fatal("SafeMode should clear after MarkBootHealthy")
			}
		}
		eng.Close()
	}

	// Verify audit chain detects tampering.
	eng, err := Open(context.Background(), Options{BaseDir: dir, Schema: cs})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.VerifyAuditLog(); err != nil {
		t.Fatalf("valid audit log failed verification: %v", err)
	}
	eng.Close()

	auditPath := filepath.Join(dir, "audit.jsonl")
	rawAudit, _ := os.ReadFile(auditPath)
	tampered := strings.Replace(string(rawAudit), "SAFE_MODE_ENTERED", "TAMPERED_ACTION", 1)
	if err := os.WriteFile(auditPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	engTampered, err := Open(context.Background(), Options{BaseDir: dir, Schema: cs})
	if err != nil {
		t.Fatal(err)
	}
	defer engTampered.Close()
	if _, err := engTampered.VerifyAuditLog(); !errors.Is(err, ErrAuditChainTampered) {
		t.Fatalf("expected ErrAuditChainTampered, got %v", err)
	}
}

func BenchmarkConfigDiffAndCommit(b *testing.B) {
	cs, err := schema.LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		b.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "default-config.json"))
	if err != nil {
		b.Fatal(err)
	}
	var boot map[string]any
	if err := json.Unmarshal(raw, &boot); err != nil {
		b.Fatal(err)
	}
	eng, err := Open(context.Background(), Options{
		BaseDir:         b.TempDir(),
		Schema:          cs,
		BootstrapConfig: boot,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer eng.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host := "daiji-bench-a"
		if i%2 == 0 {
			host = "daiji-bench-b"
		}
		if err := eng.SetPath("bench", "system.hostname", host); err != nil {
			b.Fatal(err)
		}
		if _, err := eng.Commit(context.Background(), "bench", "bench commit", CommitOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}
