// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijicloud

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kangpcode/daijios/pkg/secauth"
)

func TestDaijiCloudMultiTenantZTPAlertsCanaryTunnelsAndSDK(t *testing.T) {
	ctx := context.Background()
	cp := NewControlPlane([]byte("ztp-test-hmac-secret-10"), []byte("dr-test-hmac-secret-10"), nil)

	_ = cp.CreateOrganization(Organization{ID: "org-alpha", Name: "Alpha ISP", PlanTier: "enterprise"})
	_ = cp.CreateOrganization(Organization{ID: "org-beta", Name: "Beta Campus", PlanTier: "pro"})
	_ = cp.CreateSite(Site{ID: "site-jkt", OrgID: "org-alpha", Name: "Jakarta POP", Region: "id-west"})
	_ = cp.CreateSite(Site{ID: "site-sby", OrgID: "org-alpha", Name: "Surabaya POP", Region: "id-east"})
	_ = cp.CreateSite(Site{ID: "site-bdg", OrgID: "org-beta", Name: "Bandung Lab", Region: "id-west"})

	// Bind alice to org-alpha only, bob to site-jkt only.
	cp.BindOperator(TenantBinding{Actor: "alice", OrgID: "org-alpha", Role: "superadmin"})
	cp.BindOperator(TenantBinding{Actor: "bob", OrgID: "org-alpha", SiteID: "site-jkt", Role: "operator"})

	tm, _ := secauth.NewTokenManager([]byte("daijicloud-unit-test-token-key"), time.Hour)
	aliceTok, _, _ := tm.Issue("alice", "superadmin", []secauth.Permission{
		secauth.PermConfigRead, secauth.PermConfigWrite, secauth.PermSystemUpdate, secauth.PermAuditRead, secauth.PermNetDiag,
	}, time.Hour, time.Now())
	bobTok, _, _ := tm.Issue("bob", "operator", []secauth.Permission{
		secauth.PermConfigRead, secauth.PermNetDiag,
	}, time.Hour, time.Now())

	srv, err := NewServer(cp, tm)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	sdkAlice := NewClientSDK(ts.URL, aliceTok)

	// 1. Cross-tenant & cross-site isolation check (alice denied on org-beta; bob denied on site-sby).
	if _, err := sdkAlice.ListDevices(ctx, "org-beta", ""); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 cross-tenant IDOR guard for alice->org-beta, got %v", err)
	}
	sdkBob := NewClientSDK(ts.URL, bobTok)
	if _, err := sdkBob.ListDevices(ctx, "org-alpha", "site-sby"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 site-isolation guard for bob->site-sby, got %v", err)
	}

	// 2. ZTP Claim creation via Public SDK & Device Adoption (with tamper + replay rejection).
	serials := []string{"SN-01", "SN-02", "SN-03", "SN-04", "SN-05"}
	for _, sn := range serials {
		ztpTok, err := sdkAlice.CreateZTPClaim(ctx, "org-alpha", "site-jkt", sn, "bng-edge")
		if err != nil {
			t.Fatalf("CreateZTPClaim %s: %v", sn, err)
		}
		if _, err := cp.AdoptViaZTP(ztpTok+"tamper", sn, "02:00:00:00:00:01", "h", "Daiji-ARM", "1.0"); !errors.Is(err, ErrInvalidZTP) {
			t.Fatalf("expected ErrInvalidZTP on tamper")
		}
		dev, err := cp.AdoptViaZTP(ztpTok, sn, "02:00:00:00:00:01", "pop-"+sn, "Daiji-ARM", "1.0.0")
		if err != nil || dev.OrgID != "org-alpha" {
			t.Fatalf("AdoptViaZTP %s failed: %v", sn, err)
		}
		// Replay same ZTP token must fail.
		if _, err := cp.AdoptViaZTP(ztpTok, sn, "02:00:00:00:00:01", "pop-"+sn, "Daiji-ARM", "1.0.0"); !errors.Is(err, ErrInvalidZTP) {
			t.Fatalf("expected ErrInvalidZTP on replay")
		}
	}

	devs, err := sdkAlice.ListDevices(ctx, "org-alpha", "site-jkt")
	if err != nil || len(devs) != 5 {
		t.Fatalf("SDK ListDevices unexpected: err=%v len=%d", err, len(devs))
	}

	// 3. Alert Rules: fire on threshold > 85, auto-resolve on recovery.
	_ = cp.AddAlertRule(AlertRule{ID: "cpu-crit", OrgID: "org-alpha", Name: "High CPU", Metric: "cpu_percent", Threshold: 85.0, Severity: "critical"})
	fired, err := cp.IngestTelemetry("dev-SN-01", DeviceTelemetry{CPUPercent: 93.4, MemPercent: 60})
	if err != nil || len(fired) != 1 || fired[0].Status != "open" {
		t.Fatalf("expected critical CPU alert to fire, got err=%v alerts=%+v", err, fired)
	}
	_, _ = cp.IngestTelemetry("dev-SN-01", DeviceTelemetry{CPUPercent: 22.0, MemPercent: 55})
	if st := cp.alerts["cpu-crit|dev-SN-01"].Status; st != "resolved" {
		t.Fatalf("expected alert auto-resolved after recovery, got %s", st)
	}

	// 4. Secure Remote Tunnel for CGNAT-behind device.
	tun, err := cp.OpenRemoteTunnel("dev-SN-01", "alice")
	if err != nil || !tun.Active || tun.Token == "" {
		t.Fatalf("OpenRemoteTunnel failed: err=%v tun=%+v", err, tun)
	}

	// 5. Staged Canary Fleet Rollout:
	// Case A: Canary fails (>10% threshold) -> auto-halts and skips remaining 80% fleet!
	jobFail, err := sdkAlice.StartCanaryRollout(ctx, "org-alpha", "site-jkt", "1.2.0", "sha256:abcd", 20, 10)
	if err != nil || len(jobFail.CanaryIDs) != 1 || len(jobFail.RestIDs) != 4 || jobFail.Stage != "canary" {
		t.Fatalf("unexpected canary split: err=%v job=%+v", err, jobFail)
	}
	afterFail, err := cp.ReportRolloutResult(jobFail.ID, jobFail.CanaryIDs[0], false)
	if err != nil || afterFail.Stage != "halted_rollback" || afterFail.Results[jobFail.RestIDs[0]] != "skipped_rollback" {
		t.Fatalf("expected halted_rollback protecting fleet, got err=%v job=%+v", err, afterFail)
	}

	// Case B: Canary succeeds -> promotes to Stage 2 fleet -> completes!
	jobOK, err := sdkAlice.StartCanaryRollout(ctx, "org-alpha", "site-jkt", "1.2.1", "sha256:ef01", 20, 10)
	if err != nil {
		t.Fatalf("StartCanaryRollout B: %v", err)
	}
	mid, _ := cp.ReportRolloutResult(jobOK.ID, jobOK.CanaryIDs[0], true)
	if mid.Stage != "fleet" {
		t.Fatalf("expected promotion to stage 'fleet', got %+v", mid)
	}
	for _, rid := range jobOK.RestIDs {
		mid, _ = cp.ReportRolloutResult(jobOK.ID, rid, true)
	}
	if mid.Stage != "completed" {
		t.Fatalf("expected rollout completed, got %+v", mid)
	}

	// 6. Observability: Prometheus /metrics & Traced logs/spans.
	mResp, err := http.Get(ts.URL + "/metrics")
	if err != nil || mResp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics failed: %v %v", err, mResp)
	}
	mRaw, _ := io.ReadAll(mResp.Body)
	_ = mResp.Body.Close()
	if !strings.Contains(string(mRaw), "daijicloud_devices_total 5") || !strings.Contains(string(mRaw), "daijicloud_rollouts_total 2") {
		t.Fatalf("unexpected prometheus metrics:\n%s", string(mRaw))
	}

	trReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/cloud/observability/traces", nil)
	trReq.Header.Set("Authorization", "Bearer "+aliceTok)
	trResp, err := http.DefaultClient.Do(trReq)
	if err != nil || trResp.StatusCode != http.StatusOK {
		t.Fatalf("traces failed: %v %v", err, trResp)
	}
	trRaw, _ := io.ReadAll(trResp.Body)
	_ = trResp.Body.Close()
	if !strings.Contains(string(trRaw), "trace_id") || !strings.Contains(string(trRaw), "Adopted device dev-SN-01") {
		t.Fatalf("unexpected traces/logs: %s", string(trRaw))
	}
}
