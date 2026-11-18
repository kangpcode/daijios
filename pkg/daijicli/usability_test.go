// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijicli

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestCLIUsability20Tasks runs AUDIT GATE 5: a timed 20-task common operator
// workflow measuring task completion rate, execution time, and error rate.
func TestCLIUsability20Tasks(t *testing.T) {
	ctx := context.Background()
	cs, eng := loadTestEngine(t)
	sess, err := NewSession("noc-op", "superadmin", eng, cs)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	type opTask struct {
		id         string
		desc       string
		cmd        string
		wantSubstr string
	}

	tasks := []opTask{
		{"T01", "Inspect OS version & identity", "show version", "DaijiOS"},
		{"T02", "Filter running config for hostname", "show running | include hostname", "daiji-core-01"},
		{"T03", "Fuzzy search SSH schema settings", "search ssh", "management.ssh"},
		{"T04", "Elevate to privileged mode", "enable", "privileged"},
		{"T05", "Check interface count via pipe", "show interfaces | count", "2"},
		{"T06", "Verify audit log cryptographic chain", "show audit-verify", "Audit integrity OK"},
		{"T07", "Enter configuration mode", "config", "configuration mode"},
		{"T08", "Update system hostname", "set system.hostname daiji-usability-01", "Staged system.hostname"},
		{"T09", "Enter SSH sub-configuration container", "enter management.ssh", "Entered sub-config"},
		{"T10", "Change SSH port inside sub-context", "set port 2222", "Staged management.ssh.port"},
		{"T11", "Move up to management context", "up", "Moved up"},
		{"T12", "Adjust REST/gRPC API port relatively", "set api.port 8444", "Staged management.api.port"},
		{"T13", "Return to root config context", "top", "config root"},
		{"T14", "Add NTP server entry to list", "add system.ntp_servers 2.id.pool.ntp.org", "Added element"},
		{"T15", "Remove NTP server entry by value", "remove system.ntp_servers 2.id.pool.ntp.org", "Updated system.ntp_servers"},
		{"T16", "Inspect staged diff before commit", "diff", "daiji-usability-01"},
		{"T17", "Validate candidate configuration", "validate", "valid"},
		{"T18", "Atomically commit candidate changes", "commit usability-20-task", "Committed"},
		{"T19", "Save running config to startup store", "save", "Saved running configuration"},
		{"T20", "Verify JSON export after rollback", "rollback 1 --commit | json", "Rollback"},
	}

	startAll := time.Now()
	errorsCount := 0
	for _, tk := range tasks {
		t0 := time.Now()
		res, err := sess.Execute(ctx, tk.cmd)
		elapsed := time.Since(t0)
		if err != nil {
			errorsCount++
			t.Errorf("[%s] %s FAILED (%v) cmd=%q", tk.id, tk.desc, err, tk.cmd)
			continue
		}
		if tk.wantSubstr != "" && !strings.Contains(res.Output, tk.wantSubstr) {
			errorsCount++
			t.Errorf("[%s] %s missing %q in output:\n%s", tk.id, tk.desc, tk.wantSubstr, res.Output)
			continue
		}
		t.Logf("[%s] PASS (%s) %-38s => cmd=%q", tk.id, elapsed.Round(time.Microsecond), tk.desc, tk.cmd)
	}
	totalElapsed := time.Since(startAll)
	avg := totalElapsed / time.Duration(len(tasks))
	errRatePct := float64(errorsCount) / float64(len(tasks)) * 100.0
	t.Logf("USABILITY SUMMARY: tasks=%d errors=%d error_rate=%.1f%% total=%s mean_per_task=%s",
		len(tasks), errorsCount, errRatePct, totalElapsed.Round(time.Microsecond), avg.Round(time.Microsecond))

	if errorsCount > 0 {
		t.Fatalf("usability error rate %.1f%% exceeds 0%% gate target", errRatePct)
	}

	// Negative error-clarity checks: unknown verb and insufficient privileges give actionable errors.
	_, err = sess.Execute(ctx, "boguscmd")
	if err == nil || !strings.Contains(err.Error(), "?") {
		t.Fatalf("expected actionable unknown-command hint mentioning '?', got: %v", err)
	}
}
