// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijibilling

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"time"
)

// SentNotification records one dispatched WhatsApp/SMS/Email message.
type SentNotification struct {
	Channel    string `json:"channel"` // whatsapp | sms | email
	Recipient  string `json:"recipient"`
	CustomerID string `json:"customer_id"`
	Event      string `json:"event"`
	Message    string `json:"message"`
	SentAt     string `json:"sent_at"`
}

// NotificationSender delivers outbound notifications (injectable for WhatsApp/SMTP/SMS providers).
type NotificationSender interface {
	Send(n SentNotification) error
}

// CheckoutInfo holds payment gateway instructions returned to the Customer Portal.
type CheckoutInfo struct {
	InvoiceNumber string `json:"invoice_number"`
	Method        string `json:"method"` // midtrans | xendit | qris | va | manual-transfer
	AmountCents   int64  `json:"amount_cents"`
	VANumber      string `json:"va_number,omitempty"`
	QRISPayload   string `json:"qris_payload,omitempty"`
	RedirectURL   string `json:"redirect_url,omitempty"`
	Instructions  string `json:"instructions"`
}

// FinancialReport aggregates ISP revenue, taxes, late fees, and multi-reseller commissions.
type FinancialReport struct {
	Period           string                  `json:"period,omitempty"`
	TotalInvoices    int                     `json:"total_invoices"`
	PaidInvoices     int                     `json:"paid_invoices"`
	OverdueInvoices  int                     `json:"overdue_invoices"`
	GrossBilledCents int64                   `json:"gross_billed_cents"`
	CollectedCents   int64                   `json:"collected_cents"`
	OutstandingCents int64                   `json:"outstanding_cents"`
	TaxTotalCents    int64                   `json:"tax_total_cents"`
	DiscountCents    int64                   `json:"discount_cents"`
	LateFeeCents     int64                   `json:"late_fee_cents"`
	ByMethod         map[string]int64        `json:"by_method"`
	Resellers        []ResellerReportSummary `json:"resellers"`
}

// ResellerReportSummary summarizes commission earnings for one agent/reseller.
type ResellerReportSummary struct {
	ResellerID      string `json:"reseller_id"`
	Name            string `json:"name"`
	InvoicesPaid    int    `json:"invoices_paid"`
	GrossSalesCents int64  `json:"gross_sales_cents"`
	CommissionCents int64  `json:"commission_cents"`
}

// ExternalSettlement models one gateway/bank settlement statement line for reconciliation.
type ExternalSettlement struct {
	PaymentRef    string `json:"payment_ref"`
	InvoiceNumber string `json:"invoice_number"`
	Method        string `json:"method"`
	AmountCents   int64  `json:"amount_cents"`
}

// ReconciliationResult reports ledger-vs-settlement audit outcome.
type ReconciliationResult struct {
	MatchedCount    int      `json:"matched_count"`
	MismatchDetails []string `json:"mismatch_details"`
	MissingInLedger []string `json:"missing_in_ledger"`
	UnsettledInBank []string `json:"unsettled_in_bank"`
	Balanced        bool     `json:"balanced"`
}

// BuildCheckout generates deterministic gateway instructions (QRIS, VA, Midtrans/Xendit, Manual Transfer).
func (e *Engine) BuildCheckout(invoiceID, method string) (CheckoutInfo, error) {
	e.mu.RLock()
	inv, ok := e.invoices[invoiceID]
	e.mu.RUnlock()
	if !ok {
		return CheckoutInfo{}, fmt.Errorf("%w: invoice %q", ErrNotFound, invoiceID)
	}
	switch method {
	case "va":
		return CheckoutInfo{
			InvoiceNumber: inv.InvoiceNumber,
			Method:        "va",
			AmountCents:   inv.TotalCents,
			VANumber:      "88019" + digitsOnly(inv.CustomerID),
			Instructions:  "Transfer tepat sesuai nominal ke Virtual Account DaijiBilling.",
		}, nil
	case "qris":
		return CheckoutInfo{
			InvoiceNumber: inv.InvoiceNumber,
			Method:        "qris",
			AmountCents:   inv.TotalCents,
			QRISPayload:   fmt.Sprintf("00020101021226380015ID.DAIJIBILLING.QR0108%s54%02d%d", inv.InvoiceNumber, len(strconv.FormatInt(inv.TotalCents, 10)), inv.TotalCents),
			Instructions:  "Pindai kode QRIS melalui aplikasi bank atau e-wallet Anda.",
		}, nil
	case "midtrans", "xendit":
		return CheckoutInfo{
			InvoiceNumber: inv.InvoiceNumber,
			Method:        method,
			AmountCents:   inv.TotalCents,
			RedirectURL:   fmt.Sprintf("https://pay.daiji.net.id/%s/%s", method, inv.InvoiceNumber),
			Instructions:  fmt.Sprintf("Selesaikan pembayaran via gateway %s.", method),
		}, nil
	case "manual-transfer":
		return CheckoutInfo{
			InvoiceNumber: inv.InvoiceNumber,
			Method:        "manual-transfer",
			AmountCents:   inv.TotalCents,
			Instructions:  "Transfer ke rekening BCA/BRI DaijiNet & unggah bukti transfer untuk konfirmasi admin.",
		}, nil
	default:
		return CheckoutInfo{}, fmt.Errorf("%w: unsupported payment method %q", ErrInvalidOperation, method)
	}
}

// VerifyMidtransSignature validates Midtrans SHA512(order_id + status_code + gross_amount + server_key).
func VerifyMidtransSignature(orderID, statusCode, grossAmount, serverKey, signatureHex string) bool {
	if serverKey == "" || signatureHex == "" {
		return false
	}
	sum := sha512.Sum512([]byte(orderID + statusCode + grossAmount + serverKey))
	expected := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(signatureHex)) == 1
}

// ProcessMidtransWebhook verifies signature, settles paid statuses, and activates service automatically.
func (e *Engine) ProcessMidtransWebhook(orderID, statusCode, grossAmount, txStatus, txID, sigHex string) (*Invoice, error) {
	if !VerifyMidtransSignature(orderID, statusCode, grossAmount, e.opts.MidtransKey, sigHex) {
		e.recordWebhookReject("midtrans", orderID)
		return nil, ErrInvalidWebhook
	}
	if txStatus != "settlement" && txStatus != "capture" {
		return nil, nil
	}
	amt, err := strconv.ParseInt(grossAmount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid gross_amount %q", ErrAmountMismatch, grossAmount)
	}
	return e.MarkInvoicePaid(orderID, "midtrans", txID, amt, "webhook:midtrans")
}

// ProcessXenditWebhook validates X-Callback-Token and settles paid invoices.
func (e *Engine) ProcessXenditWebhook(callbackToken, invoiceID, status, paymentRef string, amountCents int64) (*Invoice, error) {
	if e.opts.XenditToken == "" || subtle.ConstantTimeCompare([]byte(e.opts.XenditToken), []byte(callbackToken)) != 1 {
		e.recordWebhookReject("xendit", invoiceID)
		return nil, ErrInvalidWebhook
	}
	if status != "PAID" && status != "SETTLED" {
		return nil, nil
	}
	return e.MarkInvoicePaid(invoiceID, "xendit", paymentRef, amountCents, "webhook:xendit")
}

// ProcessQRISWebhook verifies HMAC-SHA256 signature on QRIS/VA aggregator callbacks.
func (e *Engine) ProcessQRISWebhook(rawPayload []byte, sigHex, invoiceID, paymentRef string, amountCents int64) (*Invoice, error) {
	if e.opts.QRISHMACSecret == "" || sigHex == "" {
		e.recordWebhookReject("qris", invoiceID)
		return nil, ErrInvalidWebhook
	}
	mac := hmac.New(sha256.New, []byte(e.opts.QRISHMACSecret))
	_, _ = mac.Write(rawPayload)
	exp := mac.Sum(nil)
	got, err := hex.DecodeString(sigHex)
	if err != nil || !hmac.Equal(got, exp) {
		e.recordWebhookReject("qris", invoiceID)
		return nil, ErrInvalidWebhook
	}
	return e.MarkInvoicePaid(invoiceID, "qris", paymentRef, amountCents, "webhook:qris")
}

func (e *Engine) recordWebhookReject(gw, targetID string) {
	e.mu.Lock()
	e.appendAuditLocked("WEBHOOK_REJECTED", "webhook:"+gw, targetID, "invalid webhook signature/token")
	e.mu.Unlock()
}

// GenerateFinancialReport summarizes revenues, taxes, discounts, late fees, and per-reseller commissions.
func (e *Engine) GenerateFinancialReport(period string) FinancialReport {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rep := FinancialReport{
		Period:   period,
		ByMethod: make(map[string]int64),
	}
	resMap := make(map[string]*ResellerReportSummary)
	for id, r := range e.resellers {
		resMap[id] = &ResellerReportSummary{ResellerID: id, Name: r.Name}
	}

	for _, inv := range e.invoices {
		if period != "" && inv.BillingPeriod != period {
			continue
		}
		rep.TotalInvoices++
		rep.GrossBilledCents += inv.TotalCents
		rep.TaxTotalCents += inv.TaxCents
		rep.DiscountCents += inv.DiscountCents
		rep.LateFeeCents += inv.LateFeeCents

		if inv.Status == StatusPaid {
			rep.PaidInvoices++
			rep.CollectedCents += inv.PaidCents
			rep.ByMethod[inv.PaymentMethod] += inv.PaidCents
			if inv.ResellerID != "" {
				if rs, ok := resMap[inv.ResellerID]; ok {
					rs.InvoicesPaid++
					rs.GrossSalesCents += inv.PaidCents
					rs.CommissionCents += inv.ResellerCommCents
				}
			}
		} else if inv.Status != StatusVoid {
			rep.OutstandingCents += inv.TotalCents
			if inv.Status == StatusOverdue {
				rep.OverdueInvoices++
			}
		}
	}

	keys := make([]string, 0, len(resMap))
	for k := range resMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		rep.Resellers = append(rep.Resellers, *resMap[k])
	}
	return rep
}

// ReconcilePayments cross-checks external gateway/bank settlements against DaijiBilling paid invoices.
func (e *Engine) ReconcilePayments(settlements []ExternalSettlement) ReconciliationResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	res := ReconciliationResult{
		MismatchDetails: []string{},
		MissingInLedger: []string{},
		UnsettledInBank: []string{},
	}
	seenInv := make(map[string]bool)
	for _, st := range settlements {
		inv, ok := e.invoices[st.InvoiceNumber]
		if !ok || inv.Status != StatusPaid {
			res.MissingInLedger = append(res.MissingInLedger, st.InvoiceNumber)
			continue
		}
		seenInv[inv.InvoiceNumber] = true
		if inv.PaidCents != st.AmountCents {
			res.MismatchDetails = append(res.MismatchDetails, fmt.Sprintf("%s: ledger=%d bank=%d", inv.InvoiceNumber, inv.PaidCents, st.AmountCents))
			continue
		}
		res.MatchedCount++
	}
	for _, inv := range e.invoices {
		if inv.Status == StatusPaid && !seenInv[inv.InvoiceNumber] {
			res.UnsettledInBank = append(res.UnsettledInBank, inv.InvoiceNumber)
		}
	}
	sort.Strings(res.MissingInLedger)
	sort.Strings(res.UnsettledInBank)
	sort.Strings(res.MismatchDetails)
	res.Balanced = len(res.MismatchDetails) == 0 && len(res.MissingInLedger) == 0 && len(res.UnsettledInBank) == 0
	return res
}

func (e *Engine) notifyCustomer(customerID, event, message string) {
	e.mu.RLock()
	c, ok := e.customers[customerID]
	if !ok {
		e.mu.RUnlock()
		return
	}
	custCopy := *c
	nowStr := e.opts.Now().UTC().Format(time.RFC3339)
	e.mu.RUnlock()

	channels := [][2]string{}
	if custCopy.Phone != "" {
		channels = append(channels, [2]string{"whatsapp", custCopy.Phone}, [2]string{"sms", custCopy.Phone})
	}
	if custCopy.Email != "" {
		channels = append(channels, [2]string{"email", custCopy.Email})
	}

	var batch []SentNotification
	for _, ch := range channels {
		n := SentNotification{
			Channel:    ch[0],
			Recipient:  ch[1],
			CustomerID: customerID,
			Event:      event,
			Message:    message,
			SentAt:     nowStr,
		}
		if e.opts.Notifier != nil {
			_ = e.opts.Notifier.Send(n)
		}
		batch = append(batch, n)
	}

	e.mu.Lock()
	e.sentNotifs = append(e.sentNotifs, batch...)
	e.mu.Unlock()
}

// ListSentNotifications returns recorded notifications (WhatsApp/SMS/Email).
func (e *Engine) ListSentNotifications() []SentNotification {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]SentNotification(nil), e.sentNotifs...)
}

func digitsOnly(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b = append(b, s[i])
		}
	}
	if len(b) == 0 {
		return "0001"
	}
	return string(b)
}
