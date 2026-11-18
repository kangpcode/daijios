// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijiportal

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kangpcode/daijios/pkg/secauth"
)

func TestDaijiPortalBrandingLicensingMarketplaceUpdatesAndSupport(t *testing.T) {
	curNow := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	portal, err := NewPortal(nil, func() time.Time { return curNow })
	if err != nil {
		t.Fatalf("NewPortal: %v", err)
	}
	tm, _ := secauth.NewTokenManager([]byte("daijiportal-unit-test-secret-key"), time.Hour)
	adminTok, _, _ := tm.Issue("saasadmin", "superadmin", []secauth.Permission{
		secauth.PermConfigRead, secauth.PermConfigWrite, secauth.PermSystemUpdate, secauth.PermNetDiag,
	}, time.Hour, curNow)

	srv, err := NewServer(portal, tm)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. White-label branding per reseller (with XSS rejection & DaijiOS attribution preserved).
	if _, err := portal.SetWhiteLabelBranding(ResellerBranding{
		ResellerID: "bad", OSName: "<script>alert(1)</script>", CustomDomain: "bad.id",
	}); !errors.Is(err, ErrUnsafeInput) {
		t.Fatalf("expected ErrUnsafeInput on XSS branding, got %v", err)
	}
	_, err = portal.SetWhiteLabelBranding(ResellerBranding{
		ResellerID: "res-nusantara", OSName: "NusaNetOS", PortalTitle: "NusaNet Cloud Console",
		CustomDomain: "noc.nusanet.id", LogoURL: "https://cdn.nusanet.id/logo.svg", PrimaryColor: "#0066cc",
	})
	if err != nil {
		t.Fatalf("SetWhiteLabelBranding: %v", err)
	}
	bResp, err := http.Get(ts.URL + "/api/v1/portal/branding?domain=noc.nusanet.id")
	if err != nil || bResp.StatusCode != http.StatusOK {
		t.Fatalf("GET branding failed: %v %v", err, bResp)
	}
	var gotBrand ResellerBranding
	_ = json.NewDecoder(bResp.Body).Decode(&gotBrand)
	_ = bResp.Body.Close()
	if gotBrand.OSName != "NusaNetOS" || !strings.Contains(gotBrand.BrandFooter, "kangpcode") {
		t.Fatalf("unexpected resolved branding: %+v", gotBrand)
	}

	// 2. Free trial once per (orgID, hwID), anti-tamper Ed25519 offline verification & expiry!
	trialLic, err := portal.StartTrial("org-1", "res-nusantara", "HW-ROUTER-001")
	if err != nil || !trialLic.Payload.Trial || trialLic.Payload.Tier != TierPro {
		t.Fatalf("StartTrial failed: %v %+v", err, trialLic)
	}
	if _, err := portal.StartTrial("org-1", "res-nusantara", "HW-ROUTER-001"); !errors.Is(err, ErrTrialAlreadyUsed) {
		t.Fatalf("expected ErrTrialAlreadyUsed on duplicate trial, got %v", err)
	}

	// Verify offline Ed25519 signature succeeds for bound hardware + licensed feature.
	verified, err := VerifyOfflineLicense(portal.PublicKey(), trialLic.OfflineBlob, "HW-ROUTER-001", "pppoe-bng", 3, curNow)
	if err != nil || verified.LicenseID != trialLic.Payload.LicenseID {
		t.Fatalf("VerifyOfflineLicense failed: %v", err)
	}
	// Anti-tamper: flipping 1 char in payload rejects offline signature!
	tampered := strings.Replace(trialLic.OfflineBlob, "ey", "ez", 1)
	if _, err := VerifyOfflineLicense(portal.PublicKey(), tampered, "HW-ROUTER-001", "pppoe-bng", 1, curNow); !errors.Is(err, ErrTamperedLicense) {
		t.Fatalf("expected ErrTamperedLicense on mutated blob, got %v", err)
	}
	// Hardware clone guard & device quota guard & unentitled feature guard.
	if _, err := VerifyOfflineLicense(portal.PublicKey(), trialLic.OfflineBlob, "HW-CLONE-999", "", 1, curNow); !errors.Is(err, ErrHardwareMismatch) {
		t.Fatalf("expected ErrHardwareMismatch, got %v", err)
	}
	if _, err := VerifyOfflineLicense(portal.PublicKey(), trialLic.OfflineBlob, "HW-ROUTER-001", "", 10, curNow); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("expected ErrDeviceLimit, got %v", err)
	}
	if _, err := VerifyOfflineLicense(portal.PublicKey(), trialLic.OfflineBlob, "HW-ROUTER-001", "daijibilling", 1, curNow); !errors.Is(err, ErrFeatureNotLicensed) {
		t.Fatalf("expected ErrFeatureNotLicensed for Enterprise-only feature on Pro trial, got %v", err)
	}

	// 3. Marketplace Purchase -> Enterprise License -> Online Activation + Revocation!
	buyBody := `{"org_id":"org-ent","reseller_id":"res-nusantara","sku_id":"sku-ent","hardware_id":"HW-CORE-88","device_count":10,"months":12}`
	buyReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/portal/licenses/purchase", strings.NewReader(buyBody))
	buyReq.Header.Set("Authorization", "Bearer "+adminTok)
	buyResp, err := http.DefaultClient.Do(buyReq)
	if err != nil || buyResp.StatusCode != http.StatusOK {
		t.Fatalf("purchase failed: %v %v", err, buyResp)
	}
	var buyOut struct {
		Invoice SaaSInvoice   `json:"invoice"`
		License IssuedLicense `json:"license"`
	}
	_ = json.NewDecoder(buyResp.Body).Decode(&buyOut)
	_ = buyResp.Body.Close()
	if !buyOut.Invoice.Paid || buyOut.Invoice.ResellerShare <= 0 {
		t.Fatalf("unexpected purchase invoice: %+v", buyOut.Invoice)
	}

	// Verify online activation passes, then revoke & verify blocked!
	if _, err := portal.ActivateOnline(buyOut.License.Payload.LicenseID, "HW-CORE-88"); err != nil {
		t.Fatalf("ActivateOnline: %v", err)
	}
	_ = portal.RevokeLicense(buyOut.License.Payload.LicenseID)
	if _, err := portal.ActivateOnline(buyOut.License.Payload.LicenseID, "HW-CORE-88"); !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("expected ErrLicenseRevoked after revoke, got %v", err)
	}

	// 4. Signed Update Distribution (stable/beta/lts) + Changelog + Ed25519 Signature Verify!
	relBody, _ := json.Marshal(SignedRelease{
		Version:   "1.2.0-lts",
		Channel:   "lts",
		Changelog: []string{"CVE patch & BGP ECMP optimization"},
		URL:       "https://updates.daijios.dev/1.2.0-lts/daijios.img",
		SHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	relReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/portal/updates", bytes.NewReader(relBody))
	relReq.Header.Set("Authorization", "Bearer "+adminTok)
	relResp, err := http.DefaultClient.Do(relReq)
	if err != nil || relResp.StatusCode != http.StatusOK {
		t.Fatalf("publish release failed: %v %v", err, relResp)
	}
	_ = relResp.Body.Close()

	uResp, _ := http.Get(ts.URL + "/api/v1/portal/updates?channel=lts")
	var rels []SignedRelease
	_ = json.NewDecoder(uResp.Body).Decode(&rels)
	_ = uResp.Body.Close()
	if len(rels) != 1 || !VerifyRelease(portal.PublicKey(), rels[0]) {
		t.Fatalf("signed release verification failed: %+v", rels)
	}

	// 5. Support Ticket + Bilingual Knowledge Base!
	tktReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/portal/tickets", strings.NewReader(`{"org_id":"org-ent","subject":"Need ASN transfer help","priority":"high","body":"Please verify LOA"}`))
	tktReq.Header.Set("Authorization", "Bearer "+adminTok)
	tktResp, err := http.DefaultClient.Do(tktReq)
	if err != nil || tktResp.StatusCode != http.StatusOK {
		t.Fatalf("create ticket failed: %v %v", err, tktResp)
	}
	_ = tktResp.Body.Close()

	kbResp, _ := http.Get(ts.URL + "/api/v1/portal/kb?locale=id&q=ztp")
	kbRaw, _ := io.ReadAll(kbResp.Body)
	_ = kbResp.Body.Close()
	if !strings.Contains(string(kbRaw), "ztp-onboarding-id") {
		t.Fatalf("KB search unexpected: %s", string(kbRaw))
	}
}

func BenchmarkPortalEd25519LicenseSignAndVerify(b *testing.B) {
	now := time.Unix(1700000000, 0).UTC()
	p, _ := NewPortal(nil, func() time.Time { return now })
	payload := LicensePayload{
		LicenseID: "lic-bench", OrgID: "o1", HardwareID: "HW-01",
		Tier: TierEnterprise, MaxDevices: 100, EnabledFeatures: []string{"bgp", "pppoe-bng"},
		IssuedAt: now.Unix(), ExpiresAt: now.AddDate(1, 0, 0).Unix(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blob, err := SignOfflineLicense(p.privKey, payload)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := VerifyOfflineLicense(p.pubKey, blob, "HW-01", "bgp", 50, now); err != nil {
			b.Fatal(err)
		}
	}
}
