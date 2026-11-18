// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijibilling

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kangpcode/daijios/pkg/daijiacs"
	"github.com/kangpcode/daijios/pkg/ispengine"
	"github.com/kangpcode/daijios/pkg/ispplan"
	"github.com/kangpcode/daijios/pkg/secauth"
)

func TestDaijiBillingLifecycleProrataIsolirReactivateWebhooksReconcile(t *testing.T) {
	curNow := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return curNow }

	// Wire live ISP SessionManager + DaijiACS server.
	bngRaw, _ := os.ReadFile(filepath.Join("..", "..", "schema", "examples", "isp-bng-config.json"))
	var bngMap map[string]any
	_ = json.Unmarshal(bngRaw, &bngMap)
	bngCfg, _ := ispplan.ParseConfig(bngMap)
	sessions := ispengine.NewSessionManager(&bngCfg.ISP)
	if _, err := sessions.AuthenticatePPPoE("budi@fiber.daiji", "BudiPass2026!", "aa:bb:cc:11:22:33", curNow); err != nil {
		t.Fatalf("AuthenticatePPPoE: %v", err)
	}

	acsSrv, _ := daijiacs.NewServer(daijiacs.Config{Now: nowFn})
	// Register budi's ONT in ACS via TR-369 USP.
	_, _ = acsSrv.HandleUSPMessage(daijiacs.USPMessage{
		MsgID: "init-1", EndpointID: "ONT-BUDI-01", Manufacturer: "Huawei", Type: "SET",
		Params: map[string]string{"virtual.wifi.ssid": "Budi-Home"},
	})

	eng := NewEngine(Options{
		Sessions:       sessions,
		ACS:            acsSrv,
		MidtransKey:    "Midtrans-Server-Secret-Key-2026",
		XenditToken:    "Xendit-Callback-Secret-Token",
		QRISHMACSecret: "QRIS-HMAC-Secret-2026",
		Now:            nowFn,
	})

	// 1. Add reseller, service plan (Rp 200.000/mo, 11% PPN, 7-day grace, Rp 10.000 late fee).
	if err := eng.AddReseller(Reseller{ID: "res-jkt", Name: "Agen Jakarta", CommissionPct: 10, Active: true}, "admin"); err != nil {
		t.Fatalf("AddReseller: %v", err)
	}
	if err := eng.AddPlan(ServicePlan{
		ID:                "home-50m",
		Name:              "Home Fiber 50M",
		ISPProfileName:    "home-50m",
		DownloadKbps:      50000,
		UploadKbps:        25000,
		MonthlyPriceCents: 200000,
		TaxRatePct:        11,
		GraceDays:         7,
		LateFeeCents:      10000,
	}, "admin"); err != nil {
		t.Fatalf("AddPlan: %v", err)
	}

	// Customer 1 (Fixed-Day, activated Nov 16 -> 15/30 days = 50% prorata = 100.000 - 10.000 discount = 90.000 + 11% tax 9.900 = 99.900).
	if err := eng.AddCustomer(Customer{
		ID:              "cust-001",
		Name:            "Budi Santoso",
		Phone:           "+628123456789",
		Email:           "budi@example.id",
		PPPoEUsername:   "budi@fiber.daiji",
		CPESerial:       "ONT-BUDI-01",
		ResellerID:      "res-jkt",
		PlanID:          "home-50m",
		CycleType:       CycleFixedDay,
		FixedBillingDay: 1,
		ActivatedAt:     curNow,
		DiscountCents:   10000,
	}, "admin"); err != nil {
		t.Fatalf("AddCustomer 1: %v", err)
	}

	// Customer 2 (Anniversary cycle, full 200.000 + 11% tax = 222.000).
	if err := eng.AddCustomer(Customer{
		ID:            "cust-002",
		Name:          "Sari Wijaya",
		Phone:         "+628987654321",
		Email:         "sari@example.id",
		PPPoEUsername: "sari@fiber.daiji",
		ResellerID:    "res-jkt",
		PlanID:        "home-50m",
		CycleType:     CycleAnniversary,
		ActivatedAt:   curNow,
		PPPoEActive:   true,
	}, "admin"); err != nil {
		t.Fatalf("AddCustomer 2: %v", err)
	}

	// Auto-invoice triggered upon PPPoE activation for Budi + monthly batch for Sari (idempotent!).
	inv1, err := eng.OnPPPoESessionActive("budi@fiber.daiji", "pppoe-hook")
	if err != nil || inv1 == nil {
		t.Fatalf("OnPPPoESessionActive failed: %v", err)
	}
	if inv1.ProrataDays != 15 || inv1.SubtotalCents != 100000 || inv1.TaxCents != 9900 || inv1.TotalCents != 99900 || inv1.ResellerCommCents != 9000 {
		t.Fatalf("unexpected prorata/tax/commission math: %+v", inv1)
	}
	batch, err := eng.GenerateMonthlyInvoices("cron")
	if err != nil || len(batch) != 1 || batch[0].TotalCents != 222000 {
		t.Fatalf("expected 1 remaining invoice (Sari=222000), got err=%v batch=%+v", err, batch)
	}
	inv2 := batch[0]

	// 2. Advance clock past grace period (8 days later) -> EnforceOverdueIsolation!
	curNow = curNow.AddDate(0, 0, 8)
	isolated, err := eng.EnforceOverdueIsolation("cron-isolir")
	if err != nil || len(isolated) != 2 {
		t.Fatalf("expected 2 isolated customers, got err=%v list=%v", err, isolated)
	}
	// Verify PPPoE live session throttled to 64/64 kbps & TR-069 ONT billing_status=suspended!
	if live := sessions.ListSessions(); len(live) != 1 || !live[0].Isolated || live[0].DownloadKbps != 64 {
		t.Fatalf("expected isolated CoA session (64kbps), got %+v", live)
	}
	if ont, ok := acsSrv.GetDevice("ONT-BUDI-01", true); !ok || ont.BillingStatus != "suspended" {
		t.Fatalf("expected ACS ONT billing_status=suspended, got %+v", ont)
	}

	// Overdue added 10.000 late fee => inv1.TotalCents now 109.900, inv2.TotalCents now 232.000!
	invsBudi := eng.ListCustomerInvoices("cust-001")
	if invsBudi[0].Status != StatusOverdue || invsBudi[0].TotalCents != 109900 {
		t.Fatalf("expected inv1 overdue 109900, got %+v", invsBudi[0])
	}

	// 3. HTTP Server: Webhooks (Midtrans, Xendit, QRIS), Customer Portal, Financial Report, Reconcile!
	tm, _ := secauth.NewTokenManager([]byte("daijibilling-test-jwt-secret-key"), time.Hour)
	adminTok, _, _ := tm.Issue("billadmin", "superadmin", []secauth.Permission{
		secauth.PermConfigRead, secauth.PermConfigWrite, secauth.PermAuditRead,
	}, time.Hour, curNow)
	srv, err := NewServer(eng, tm, []byte("portal-hmac-secret-test-key"))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Customer Portal checks own invoices & builds QRIS checkout; forged portal token rejected.
	pTok := srv.IssuePortalToken("cust-001")
	badPortalResp, _ := http.Get(ts.URL + "/portal?token=cust-001.bad")
	if badPortalResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on invalid portal token, got %d", badPortalResp.StatusCode)
	}
	_ = badPortalResp.Body.Close()

	chkReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/portal/checkout", strings.NewReader(`{"invoice_id":"`+inv1.ID+`","method":"qris"}`))
	chkReq.Header.Set("X-Portal-Token", pTok)
	chkResp, err := http.DefaultClient.Do(chkReq)
	if err != nil || chkResp.StatusCode != http.StatusOK {
		t.Fatalf("portal checkout failed: %v %v", err, chkResp)
	}
	_ = chkResp.Body.Close()

	// Invalid Midtrans webhook rejected & audited!
	badMT := `{"order_id":"` + inv1.ID + `","status_code":"200","gross_amount":"109900","transaction_status":"settlement","transaction_id":"tx-mt-1","signature_key":"deadbeef"}`
	badMTResp, _ := http.Post(ts.URL+"/webhooks/billing/midtrans", "application/json", strings.NewReader(badMT))
	if badMTResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 bad midtrans signature, got %d", badMTResp.StatusCode)
	}
	_ = badMTResp.Body.Close()

	// Valid Midtrans SHA-512 webhook settles Budi's invoice -> triggers AUTO-REACTIVATION!
	sum512 := sha512.Sum512([]byte(inv1.ID + "200" + "109900" + "Midtrans-Server-Secret-Key-2026"))
	validSig := hex.EncodeToString(sum512[:])
	goodMT := `{"order_id":"` + inv1.ID + `","status_code":"200","gross_amount":"109900","transaction_status":"settlement","transaction_id":"tx-mt-1","signature_key":"` + validSig + `"}`
	goodMTResp, err := http.Post(ts.URL+"/webhooks/billing/midtrans", "application/json", strings.NewReader(goodMT))
	if err != nil || goodMTResp.StatusCode != http.StatusOK {
		t.Fatalf("valid midtrans webhook failed: %v %v", err, goodMTResp)
	}
	_ = goodMTResp.Body.Close()

	// Verify Budi automatically reactivated on PPPoE (50000 kbps) + TR-069 ONT (active)!
	if live := sessions.ListSessions(); len(live) != 1 || live[0].Isolated || live[0].DownloadKbps != 50000 {
		t.Fatalf("expected reactivated PPPoE 50000 kbps, got %+v", live)
	}
	if ont, _ := acsSrv.GetDevice("ONT-BUDI-01", true); ont.BillingStatus != "active" {
		t.Fatalf("expected ACS ONT reactivated, got %+v", ont)
	}

	// Settle Sari's invoice via QRIS HMAC webhook.
	qPayload := []byte(`{"invoice_number":"` + inv2.InvoiceNumber + `","payment_ref":"qris-ref-2","amount_cents":232000}`)
	qMac := hmac.New(sha256.New, []byte("QRIS-HMAC-Secret-2026"))
	_, _ = qMac.Write(qPayload)
	qReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/webhooks/billing/qris", bytes.NewReader(qPayload))
	qReq.Header.Set("X-Daiji-Signature", hex.EncodeToString(qMac.Sum(nil)))
	qResp, err := http.DefaultClient.Do(qReq)
	if err != nil || qResp.StatusCode != http.StatusOK {
		t.Fatalf("valid QRIS webhook failed: %v %v", err, qResp)
	}
	_ = qResp.Body.Close()

	// Verify Cross-Invoice PaymentRef replay fails cleanly.
	if _, err := eng.MarkInvoicePaid(inv2.ID, "midtrans", "tx-mt-1", 232000, "test"); !errors.Is(err, ErrDuplicate) && !errors.Is(err, ErrAlreadyPaid) {
		t.Fatalf("expected replay/paid guard, got %v", err)
	}

	// 4. Verify WhatsApp/SMS/Email Notifications dispatched, Financial Report & Reseller Comm, & Reconciliation.
	if len(eng.ListSentNotifications()) < 9 {
		t.Fatalf("expected WA/SMS/Email notifications across issued/isolated/paid, got %d", len(eng.ListSentNotifications()))
	}

	repReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/billing/report?period=2026-11", nil)
	repReq.Header.Set("Authorization", "Bearer "+adminTok)
	repResp, err := http.DefaultClient.Do(repReq)
	if err != nil || repResp.StatusCode != http.StatusOK {
		t.Fatalf("report HTTP failed: %v %v", err, repResp)
	}
	var rep FinancialReport
	_ = json.NewDecoder(repResp.Body).Decode(&rep)
	_ = repResp.Body.Close()
	if rep.CollectedCents != 341900 || rep.PaidInvoices != 2 || len(rep.Resellers) != 1 || rep.Resellers[0].CommissionCents != 29000 {
		t.Fatalf("unexpected financial report: %+v", rep)
	}

	rec := eng.ReconcilePayments([]ExternalSettlement{
		{PaymentRef: "tx-mt-1", InvoiceNumber: inv1.InvoiceNumber, Method: "midtrans", AmountCents: 109900},
		{PaymentRef: "qris-ref-2", InvoiceNumber: inv2.InvoiceNumber, Method: "qris", AmountCents: 232000},
	})
	if !rec.Balanced || rec.MatchedCount != 2 {
		t.Fatalf("expected balanced reconciliation, got %+v", rec)
	}

	// 5. Verify immutable SHA-256 audit hash chain + tamper detection.
	cnt, err := eng.VerifyAuditChain()
	if err != nil || cnt < 8 {
		t.Fatalf("VerifyAuditChain failed: cnt=%d err=%v", cnt, err)
	}
	eng.mu.Lock()
	eng.auditChain[2].Detail = "tampered-amount"
	eng.mu.Unlock()
	if _, err := eng.VerifyAuditChain(); !errors.Is(err, ErrAuditTampered) {
		t.Fatalf("expected ErrAuditTampered after mutation, got %v", err)
	}
}

func BenchmarkBillingCycleGenerateAndReconcile(b *testing.B) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng := NewEngine(Options{Now: func() time.Time { return now }})
		_ = eng.AddPlan(ServicePlan{ID: "p1", Name: "50M", MonthlyPriceCents: 200000, TaxRatePct: 11}, "bench")
		_ = eng.AddCustomer(Customer{ID: "c1", PlanID: "p1", PPPoEUsername: "u1", PPPoEActive: true, ActivatedAt: now}, "bench")
		invs, err := eng.GenerateMonthlyInvoices("bench")
		if err != nil || len(invs) != 1 {
			b.Fatal(err)
		}
		if _, err := eng.MarkInvoicePaid(invs[0].ID, "va", "ref-1", invs[0].TotalCents, "bench"); err != nil {
			b.Fatal(err)
		}
		_ = eng.GenerateFinancialReport("2026-11")
	}
}
