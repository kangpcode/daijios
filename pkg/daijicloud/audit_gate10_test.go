// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijicloud

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestDaijiCloudLoadTest500Devices runs AUDIT GATE 10 Load Test:
// 500 concurrent fleet devices ingesting telemetry and evaluating alert rules under -race.
func TestDaijiCloudLoadTest500Devices(t *testing.T) {
	const fleetSize = 500
	cp := NewControlPlane([]byte("load-test-ztp-secret-key"), []byte("load-test-dr-secret-key"), nil)
	_ = cp.CreateOrganization(Organization{ID: "org-load", Name: "LoadTest Carrier"})
	_ = cp.CreateSite(Site{ID: "site-pop1", OrgID: "org-load", Name: "Mega POP"})
	_ = cp.AddAlertRule(AlertRule{ID: "high-cpu", OrgID: "org-load", Metric: "cpu_percent", Threshold: 85.0, Severity: "warning"})

	for i := 0; i < fleetSize; i++ {
		sn := fmt.Sprintf("LOAD-%04d", i)
		tok, err := cp.CreateZTPClaimToken("org-load", "site-pop1", sn, "isp-cpe", 10*time.Minute)
		if err != nil {
			t.Fatalf("CreateZTPClaimToken: %v", err)
		}
		if _, err := cp.AdoptViaZTP(tok, sn, "02:64:6a:00:00:01", "host-"+sn, "ARM64", "1.1.0"); err != nil {
			t.Fatalf("AdoptViaZTP: %v", err)
		}
	}

	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, fleetSize)
	for i := 0; i < fleetSize; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			devID := fmt.Sprintf("dev-LOAD-%04d", idx)
			cpu := 35.0
			if idx%10 == 0 {
				cpu = 92.5 // triggers 50 alerts concurrently
			}
			if _, err := cp.IngestTelemetry(devID, DeviceTelemetry{
				CPUPercent: cpu, MemPercent: 48.0, RxMbps: 420.5, TxMbps: 185.2, ActiveSessions: 120,
			}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	elapsed := time.Since(start)
	for err := range errs {
		t.Fatalf("concurrent telemetry error: %v", err)
	}

	throughput := float64(fleetSize) / elapsed.Seconds()
	t.Logf("LOAD TEST SUMMARY: devices=%d elapsed=%s throughput=%.0f ingest/sec", fleetSize, elapsed.Round(time.Microsecond), throughput)
}

// TestDaijiCloudDisasterRecoveryAndBackupRestore runs AUDIT GATE 10 DR & Backup-Restore checks:
// validates full cluster snapshot export, tamper detection, full DR restore on fresh node,
// and per-device SHA-256 config backup version restore.
func TestDaijiCloudDisasterRecoveryAndBackupRestore(t *testing.T) {
	ztpSec := []byte("dr-gate-ztp-secret-key")
	drSec := []byte("dr-gate-snapshot-secret-key")
	primary := NewControlPlane(ztpSec, drSec, nil)

	_ = primary.CreateOrganization(Organization{ID: "org-dr", Name: "DR Telecom"})
	_ = primary.CreateSite(Site{ID: "site-dr1", OrgID: "org-dr", Name: "DC Primary"})
	primary.BindOperator(TenantBinding{Actor: "dradmin", OrgID: "org-dr", Role: "superadmin"})

	tok, _ := primary.CreateZTPClaimToken("org-dr", "site-dr1", "DR-GW-01", "core", time.Hour)
	_, _ = primary.AdoptViaZTP(tok, "DR-GW-01", "02:64:6a:99:88:77", "daiji-dr-gw", "x86_64", "1.1.0")

	v1, err := primary.UploadConfigBackup("dev-DR-GW-01", "dradmin", "baseline", map[string]any{"hostname": "daiji-dr-gw", "asn": 65100})
	if err != nil || v1.Version != 1 {
		t.Fatalf("UploadConfigBackup v1: %v", err)
	}
	v2, err := primary.UploadConfigBackup("dev-DR-GW-01", "dradmin", "bgp-update", map[string]any{"hostname": "daiji-dr-gw", "asn": 65200})
	if err != nil || v2.Version != 2 {
		t.Fatalf("UploadConfigBackup v2: %v", err)
	}

	// Export signed DR snapshot.
	t0 := time.Now()
	drSnap, err := primary.ExportDisasterRecoverySnapshot()
	if err != nil || drSnap.HMAC == "" {
		t.Fatalf("ExportDisasterRecoverySnapshot: %v", err)
	}

	// Verify tampered DR snapshot fails before applying.
	badSnap := *drSnap
	badSnap.CreatedAt = "1999-01-01T00:00:00Z"
	standby := NewControlPlane(ztpSec, drSec, nil)
	if err := standby.RestoreDisasterRecoverySnapshot(&badSnap); !errors.Is(err, ErrDRTampered) {
		t.Fatalf("expected ErrDRTampered on modified DR snapshot, got %v", err)
	}

	// Restore valid DR snapshot onto standby ControlPlane & verify parity.
	if err := standby.RestoreDisasterRecoverySnapshot(drSnap); err != nil {
		t.Fatalf("RestoreDisasterRecoverySnapshot: %v", err)
	}
	drDur := time.Since(t0)
	t.Logf("DR BACKUP-RESTORE: orgs=%d sites=%d devices=%d elapsed=%s",
		len(standby.orgs), len(standby.sites), len(standby.devices), drDur.Round(time.Microsecond))

	restoredCfg, err := standby.RestoreConfigVersion("dev-DR-GW-01", 1)
	if err != nil || restoredCfg.Config["asn"].(float64) != 65100 {
		t.Fatalf("per-device RestoreConfigVersion failed: err=%v cfg=%+v", err, restoredCfg)
	}
}

func BenchmarkDaijiCloudTelemetryIngest(b *testing.B) {
	cp := NewControlPlane(nil, nil, nil)
	_ = cp.CreateOrganization(Organization{ID: "o1", Name: "Bench"})
	_ = cp.CreateSite(Site{ID: "s1", OrgID: "o1", Name: "POP"})
	_ = cp.AddAlertRule(AlertRule{ID: "r1", OrgID: "o1", Metric: "cpu_percent", Threshold: 90, Severity: "warn"})
	tok, _ := cp.CreateZTPClaimToken("o1", "s1", "B01", "edge", time.Hour)
	_, _ = cp.AdoptViaZTP(tok, "B01", "02:00:00:00:00:01", "b01", "x86", "1.1.0")
	tel := DeviceTelemetry{CPUPercent: 42.5, MemPercent: 55.0, RxMbps: 300, TxMbps: 120}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cp.IngestTelemetry("dev-B01", tel); err != nil {
			b.Fatal(err)
		}
	}
}
