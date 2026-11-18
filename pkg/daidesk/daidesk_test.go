// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daidesk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/daidiscovery"
	"github.com/kangpcode/daijios/pkg/netplan"
	"github.com/kangpcode/daijios/pkg/schema"
	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/wlanplan"
)

type testDeviceNode struct {
	eng  *configengine.Engine
	cs   *schema.CompiledSchema
	fm   *FileManager
	srv  *httptest.Server
	tok  string
	port int
}

func spawnTestNode(t testing.TB, hostname string) *testDeviceNode {
	t.Helper()
	cs, err := schema.LoadFile(filepath.Join("..", "..", "schema", "daijios.schema.json"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "default-config.json"))
	var boot map[string]any
	_ = json.Unmarshal(raw, &boot)
	boot["system"].(map[string]any)["hostname"] = hostname

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
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { eng.Close() })

	fm, err := NewFileManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileManager: %v", err)
	}
	tm, _ := secauth.NewTokenManager([]byte("daidesk-test-token-secret-phase7"), time.Hour)
	tok, _, err := tm.Issue("deskadmin", "superadmin", []secauth.Permission{
		secauth.PermConfigRead, secauth.PermConfigWrite, secauth.PermConfigCommit, secauth.PermConfigReadSecrets, secauth.PermNetDiag,
	}, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("Token Issue: %v", err)
	}

	h := NewAgentHandler(AgentDependencies{
		Config:       eng,
		Schema:       cs,
		Files:        fm,
		Tokens:       tm,
		BackupSecret: []byte("backup-integrity-key"),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	return &testDeviceNode{eng: eng, cs: cs, fm: fm, srv: srv, tok: tok}
}

func TestDaiDeskMultiTabsDiscoveryTerminalFileJailBulkAndBackup(t *testing.T) {
	ctx := context.Background()
	n1 := spawnTestNode(t, "daiji-branch-01")
	n2 := spawnTestNode(t, "daiji-branch-02")
	n3 := spawnTestNode(t, "daiji-cloud-03")

	ws := NewWorkspace()

	// 1. Offline-LAN MAC Discovery onboarding + Cloud relay tab.
	ws.ConnectFromBeacon(daidiscovery.DeviceBeacon{
		DeviceID: "br01", MAC: "02:64:6a:00:01:01", Hostname: "daiji-branch-01", IPv4: "127.0.0.1", WebPort: 8443,
	}, "deskadmin", "superadmin", n1.tok)
	// Point tab 1 endpoint to httptest URL cleanly for in-memory verification.
	ws.AddTab(DeviceTab{ID: "lan-01", Label: "LAN Branch 01", Mode: ModeOfflineLAN, MAC: "02:64:6a:00:01:01", Endpoint: n1.srv.URL, Token: n1.tok}, true)
	ws.AddTab(DeviceTab{ID: "lan-02", Label: "LAN Branch 02", Mode: ModeOfflineLAN, MAC: "02:64:6a:00:01:02", Endpoint: n2.srv.URL, Token: n2.tok}, false)
	ws.AddTab(DeviceTab{ID: "cld-03", Label: "Cloud Site 03", Mode: ModeCloud, Endpoint: n3.srv.URL, Token: n3.tok}, false)

	tabs, active := ws.ListTabs()
	if len(tabs) < 3 || active != "lan-01" {
		t.Fatalf("unexpected multi-tab state: count=%d active=%s", len(tabs), active)
	}
	if err := ws.CloseTab("lan-02:64:6a:00:01:01"); err == nil {
		// ignore
	}
	_ = ws.SwitchTab("cld-03")
	if _, act := ws.ListTabs(); act != "cld-03" {
		t.Fatalf("expected active tab cld-03, got %s", act)
	}

	// 2. Remote Terminal execution per tab (offline-lan & cloud).
	p1, out1, err := ws.ExecuteRemoteCLI(ctx, "lan-01", "show version")
	if err != nil || !strings.Contains(out1, "DaijiOS") || !strings.Contains(p1, "daiji-branch-01") {
		t.Fatalf("terminal lan-01 failed: err=%v p=%q out=%s", err, p1, out1)
	}
	p3, out3, err := ws.ExecuteRemoteCLI(ctx, "cld-03", "show system.hostname")
	if err != nil || !strings.Contains(out3, "daiji-cloud-03") || !strings.Contains(p3, "daiji-cloud-03") {
		t.Fatalf("terminal cld-03 failed: err=%v p=%q out=%s", err, p3, out3)
	}

	// 3. Jailed File Manager: atomic write, read, list, delete + path traversal guard.
	if err := n1.fm.WriteAtomic("backups/router.rsc", []byte("# DaijiOS config\n")); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	data, err := n1.fm.ReadFile("backups/router.rsc")
	if err != nil || !strings.Contains(string(data), "DaijiOS") {
		t.Fatalf("ReadFile: %v %s", err, data)
	}
	if entries, err := n1.fm.ListFiles("backups"); err != nil || len(entries) != 1 || entries[0].Name != "router.rsc" {
		t.Fatalf("ListFiles: err=%v entries=%+v", err, entries)
	}
	if err := n1.fm.WriteAtomic("../../etc/passwd", []byte("evil")); !errors.Is(err, ErrPathTraversal) {
		t.Fatalf("expected ErrPathTraversal on escape attempt, got %v", err)
	}

	// Symlink escape inside jail must also fail (both list and nested write).
	symPath := filepath.Join(n1.fm.rootAbs, "escape-link")
	_ = os.Symlink("/etc", symPath)
	if _, err := n1.fm.ListFiles("escape-link"); !errors.Is(err, ErrPathTraversal) {
		t.Fatalf("expected ErrPathTraversal on symlink escape, got %v", err)
	}
	if err := n1.fm.WriteAtomic("escape-link/pwned", []byte("evil")); !errors.Is(err, ErrPathTraversal) {
		t.Fatalf("expected ErrPathTraversal on nested symlink write, got %v", err)
	}
	_ = n1.fm.DeleteFile("backups/router.rsc")

	// 4. Concurrent Bulk Config (Dry-run + Live Commit across 3 nodes in both modes).
	targetIDs := []string{"lan-01", "lan-02", "cld-03"}
	dryRes := ws.ApplyBulkConfig(ctx, targetIDs, map[string]any{"system.domain_name": "bulk.daiji.net.id"}, false)
	for _, r := range dryRes {
		if !r.Success || r.Committed || len(r.Diffs) == 0 {
			t.Fatalf("bulk dry-run unexpected result: %+v", r)
		}
	}
	liveRes := ws.ApplyBulkConfig(ctx, targetIDs, map[string]any{"system.domain_name": "bulk.daiji.net.id"}, true)
	for _, r := range liveRes {
		if !r.Success || !r.Committed || r.Revision == "" {
			t.Fatalf("bulk commit unexpected result: %+v", r)
		}
	}

	// 5. Signed Config Backup & Backup-vs-Running Diff (secret redaction + tamper guard).
	backupFile := filepath.Join(t.TempDir(), "branch01.backup.json")
	bkp, err := ExportBackup(n1.eng, n1.cs, []byte("backup-integrity-key"), true, backupFile)
	if err != nil {
		t.Fatalf("ExportBackup: %v", err)
	}
	bkpRaw, _ := os.ReadFile(backupFile)
	if strings.Contains(string(bkpRaw), "$argon2id$") {
		t.Fatalf("redacted backup leaked password_hash")
	}

	// Mutate running config after backup, verify DiffBackupVsRunning detects the drift.
	_ = n1.eng.SetPath("deskadmin", "system.timezone", "Asia/Makassar")
	_, _ = n1.eng.Commit(ctx, "deskadmin", "timezone change", configengine.CommitOptions{})
	diffs, err := DiffBackupVsRunning(n1.eng, n1.cs, []byte("backup-integrity-key"), bkp)
	if err != nil || len(diffs) != 1 || diffs[0].Path != "system.timezone" {
		t.Fatalf("DiffBackupVsRunning unexpected: err=%v diffs=%+v", err, diffs)
	}

	// Tampered backup HMAC is rejected.
	bkp.Hostname = "tampered-host"
	if _, err := DiffBackupVsRunning(n1.eng, n1.cs, []byte("backup-integrity-key"), bkp); !errors.Is(err, ErrTamperedBackup) {
		t.Fatalf("expected ErrTamperedBackup on modified backup, got %v", err)
	}
}

func BenchmarkDaiDeskBulkConfig3Nodes(b *testing.B) {
	ctx := context.Background()
	n1 := spawnTestNode(b, "b-1")
	n2 := spawnTestNode(b, "b-2")
	n3 := spawnTestNode(b, "b-3")
	ws := NewWorkspace()
	ws.AddTab(DeviceTab{ID: "b1", Mode: ModeOfflineLAN, Endpoint: n1.srv.URL, Token: n1.tok}, true)
	ws.AddTab(DeviceTab{ID: "b2", Mode: ModeOfflineLAN, Endpoint: n2.srv.URL, Token: n2.tok}, false)
	ws.AddTab(DeviceTab{ID: "b3", Mode: ModeCloud, Endpoint: n3.srv.URL, Token: n3.tok}, false)
	ids := []string{"b1", "b2", "b3"}
	patch := map[string]any{"system.domain_name": "bench.daiji.local"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := ws.ApplyBulkConfig(ctx, ids, patch, false)
		for _, r := range res {
			if !r.Success {
				b.Fatalf("bulk fail: %+v", r)
			}
		}
	}
}
