// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package daijibilling implements DaijiBilling: ISP PPPoE/Hotspot subscription
// billing with fixed-day & anniversary cycles, prorata calculation, automated
// invoicing (taxes/discounts/late fees), RADIUS CoA & TR-069 auto-isolir and
// auto-reactivation, Midtrans/Xendit/QRIS/VA/manual webhooks, multi-reseller
// accounting, customer portal, financial reports, reconciliation, and an
// immutable SHA-256 hash-chained transaction audit ledger.
package daijibilling

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/kangpcode/daijios/pkg/daijiacs"
	"github.com/kangpcode/daijios/pkg/ispengine"
)

var (
	ErrNotFound         = errors.New("billing record not found")
	ErrDuplicate        = errors.New("duplicate billing identifier")
	ErrAlreadyPaid      = errors.New("invoice already settled")
	ErrAmountMismatch   = errors.New("payment amount does not match invoice total")
	ErrInvalidWebhook   = errors.New("webhook authentication signature invalid")
	ErrAuditTampered    = errors.New("billing audit trail hash chain tampered")
	ErrInvalidOperation = errors.New("invalid billing state or parameters")
)

type CycleType string

const (
	CycleFixedDay    CycleType = "fixed-day"
	CycleAnniversary CycleType = "anniversary"
)

type InvoiceStatus string

const (
	StatusUnpaid  InvoiceStatus = "unpaid"
	StatusPaid    InvoiceStatus = "paid"
	StatusOverdue InvoiceStatus = "overdue"
	StatusVoid    InvoiceStatus = "void"
)

// Reseller models an ISP agent/partner earning percentage commission per collected invoice.
type Reseller struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	CommissionPct int64  `json:"commission_pct"` // integer percentage 0..50
	BalanceCents  int64  `json:"balance_cents"`
	Active        bool   `json:"active"`
}

// ServicePlan defines an internet package billed monthly (integer currency units to prevent rounding drift).
type ServicePlan struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	ISPProfileName    string `json:"isp_profile_name"`
	DownloadKbps      int    `json:"download_kbps"`
	UploadKbps        int    `json:"upload_kbps"`
	MonthlyPriceCents int64  `json:"monthly_price_cents"`
	TaxRatePct        int64  `json:"tax_rate_pct"` // e.g., 11 for PPN 11%
	GraceDays         int    `json:"grace_days"`
	LateFeeCents      int64  `json:"late_fee_cents"`
}

// Customer represents one PPPoE/Hotspot subscriber managed by DaijiBilling.
type Customer struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Phone           string    `json:"phone"`
	Email           string    `json:"email"`
	PPPoEUsername   string    `json:"pppoe_username"`
	CPESerial       string    `json:"cpe_serial,omitempty"`
	ResellerID      string    `json:"reseller_id,omitempty"`
	PlanID          string    `json:"plan_id"`
	CycleType       CycleType `json:"cycle_type"`
	FixedBillingDay int       `json:"fixed_billing_day,omitempty"` // 1..28
	ActivatedAt     time.Time `json:"activated_at"`
	DiscountCents   int64     `json:"discount_cents,omitempty"`
	PPPoEActive     bool      `json:"pppoe_active"`
	Status          string    `json:"status"` // active | isolated | suspended
}

// Invoice captures one monthly billing statement including prorata, discount, late fee, and tax.
type Invoice struct {
	ID                string        `json:"id"`
	InvoiceNumber     string        `json:"invoice_number"`
	CustomerID        string        `json:"customer_id"`
	CustomerName      string        `json:"customer_name"`
	ResellerID        string        `json:"reseller_id,omitempty"`
	BillingPeriod     string        `json:"billing_period"` // YYYY-MM
	PeriodStart       time.Time     `json:"period_start"`
	PeriodEnd         time.Time     `json:"period_end"`
	DueDate           time.Time     `json:"due_date"`
	ProrataDays       int           `json:"prorata_days"`
	CycleTotalDays    int           `json:"cycle_total_days"`
	SubtotalCents     int64         `json:"subtotal_cents"`
	DiscountCents     int64         `json:"discount_cents"`
	LateFeeCents      int64         `json:"late_fee_cents"`
	TaxCents          int64         `json:"tax_cents"`
	TotalCents        int64         `json:"total_cents"`
	ResellerCommCents int64         `json:"reseller_comm_cents"`
	PaidCents         int64         `json:"paid_cents"`
	Status            InvoiceStatus `json:"status"`
	PaymentMethod     string        `json:"payment_method,omitempty"`
	PaymentRef        string        `json:"payment_ref,omitempty"`
	CreatedAt         time.Time     `json:"created_at"`
	PaidAt            *time.Time    `json:"paid_at,omitempty"`
}

// AuditRecord forms an immutable SHA-256 hash-chained billing transaction log entry.
type AuditRecord struct {
	Seq       uint64 `json:"seq"`
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Actor     string `json:"actor"`
	TargetID  string `json:"target_id"`
	Detail    string `json:"detail"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

// Options wires external payment secrets and live OS/ISP integration subsystems.
type Options struct {
	Sessions         *ispengine.SessionManager
	ACS              *daijiacs.Server
	Notifier         NotificationSender
	MidtransKey      string
	XenditToken      string
	QRISHMACSecret   string
	Now              func() time.Time
}

// Engine manages customers, plans, automated billing, CoA/ACS isolir, gateways, and ledger.
type Engine struct {
	mu           sync.RWMutex
	opts         Options
	resellers    map[string]*Reseller
	plans        map[string]*ServicePlan
	customers    map[string]*Customer
	byPPPoE      map[string]string // username -> customerID
	invoices     map[string]*Invoice
	periodIndex  map[string]string // customerID|YYYY-MM -> invoiceID
	paymentRefs  map[string]string // paymentRef -> invoiceID
	invSeq       uint64
	auditChain   []AuditRecord
	sentNotifs   []SentNotification
}

// NewEngine initializes a DaijiBilling core engine.
func NewEngine(opts Options) *Engine {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Engine{
		opts:        opts,
		resellers:   make(map[string]*Reseller),
		plans:       make(map[string]*ServicePlan),
		customers:   make(map[string]*Customer),
		byPPPoE:     make(map[string]string),
		invoices:    make(map[string]*Invoice),
		periodIndex: make(map[string]string),
		paymentRefs: make(map[string]string),
	}
}

// AddReseller registers a partner/agent for commission tracking.
func (e *Engine) AddReseller(r Reseller, actor string) error {
	if r.ID == "" || r.CommissionPct < 0 || r.CommissionPct > 50 {
		return fmt.Errorf("%w: reseller id and 0..50%% commission required", ErrInvalidOperation)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.resellers[r.ID]; exists {
		return ErrDuplicate
	}
	cp := r
	e.resellers[r.ID] = &cp
	e.appendAuditLocked("RESELLER_ADDED", actor, r.ID, fmt.Sprintf("name=%s comm=%d%%", r.Name, r.CommissionPct))
	return nil
}

// AddPlan registers a monthly billing service package.
func (e *Engine) AddPlan(p ServicePlan, actor string) error {
	if p.ID == "" || p.MonthlyPriceCents <= 0 {
		return fmt.Errorf("%w: plan id and monthly_price_cents > 0 required", ErrInvalidOperation)
	}
	if p.GraceDays <= 0 {
		p.GraceDays = 7
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.plans[p.ID]; exists {
		return ErrDuplicate
	}
	cp := p
	e.plans[p.ID] = &cp
	e.appendAuditLocked("PLAN_ADDED", actor, p.ID, fmt.Sprintf("name=%s price=%d tax=%d%%", p.Name, p.MonthlyPriceCents, p.TaxRatePct))
	return nil
}

// AddCustomer registers a subscriber and indexes their PPPoE username.
func (e *Engine) AddCustomer(c Customer, actor string) error {
	if c.ID == "" || c.PlanID == "" || c.PPPoEUsername == "" {
		return fmt.Errorf("%w: customer id, plan_id, and pppoe_username required", ErrInvalidOperation)
	}
	if c.CycleType == "" {
		c.CycleType = CycleFixedDay
	}
	if c.CycleType == CycleFixedDay && (c.FixedBillingDay < 1 || c.FixedBillingDay > 28) {
		c.FixedBillingDay = 1
	}
	if c.Status == "" {
		c.Status = "active"
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.plans[c.PlanID]; !ok {
		return fmt.Errorf("%w: unknown plan %q", ErrNotFound, c.PlanID)
	}
	if c.ResellerID != "" {
		if _, ok := e.resellers[c.ResellerID]; !ok {
			return fmt.Errorf("%w: unknown reseller %q", ErrNotFound, c.ResellerID)
		}
	}
	if _, exists := e.customers[c.ID]; exists {
		return ErrDuplicate
	}
	if c.ActivatedAt.IsZero() {
		c.ActivatedAt = e.opts.Now().UTC()
	}
	cp := c
	e.customers[c.ID] = &cp
	e.byPPPoE[c.PPPoEUsername] = c.ID
	e.appendAuditLocked("CUSTOMER_CREATED", actor, c.ID, fmt.Sprintf("pppoe=%s plan=%s cycle=%s", c.PPPoEUsername, c.PlanID, c.CycleType))
	return nil
}

// OnPPPoESessionActive marks PPPoE active and automatically issues an invoice for the current cycle if not yet billed.
func (e *Engine) OnPPPoESessionActive(pppoeUsername string, actor string) (*Invoice, error) {
	now := e.opts.Now().UTC()
	e.mu.Lock()
	cid, ok := e.byPPPoE[pppoeUsername]
	if !ok {
		e.mu.Unlock()
		return nil, fmt.Errorf("%w: pppoe user %q", ErrNotFound, pppoeUsername)
	}
	e.customers[cid].PPPoEActive = true
	inv, err := e.issueInvoiceForCustomerLocked(e.customers[cid], now, actor)
	e.mu.Unlock()
	if err == nil && inv != nil {
		e.notifyCustomer(cid, "invoice_issued", fmt.Sprintf("Tagihan %s sebesar %d telah terbit (jatuh tempo %s)", inv.InvoiceNumber, inv.TotalCents, inv.DueDate.Format("2006-01-02")))
	}
	return inv, err
}

// GenerateMonthlyInvoices issues idempotent monthly invoices for all active PPPoE customers in the cycle of now.
func (e *Engine) GenerateMonthlyInvoices(actor string) ([]Invoice, error) {
	now := e.opts.Now().UTC()
	e.mu.Lock()
	var issued []Invoice
	ids := make([]string, 0, len(e.customers))
	for id := range e.customers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, cid := range ids {
		c := e.customers[cid]
		if !c.PPPoEActive || c.Status == "suspended" {
			continue
		}
		inv, err := e.issueInvoiceForCustomerLocked(c, now, actor)
		if err != nil {
			e.mu.Unlock()
			return nil, err
		}
		if inv != nil {
			issued = append(issued, *inv)
		}
	}
	e.mu.Unlock()

	for _, inv := range issued {
		e.notifyCustomer(inv.CustomerID, "invoice_issued", fmt.Sprintf("Invoice %s terbit: %d (jatuh tempo %s)", inv.InvoiceNumber, inv.TotalCents, inv.DueDate.Format("2006-01-02")))
	}
	return issued, nil
}

func (e *Engine) issueInvoiceForCustomerLocked(c *Customer, now time.Time, actor string) (*Invoice, error) {
	periodKey := now.Format("2006-01")
	idxKey := c.ID + "|" + periodKey
	if _, already := e.periodIndex[idxKey]; already {
		return nil, nil
	}
	plan := e.plans[c.PlanID]

	pStart, pEnd, dueDate := computeBillingWindow(c, plan, now)
	totalDays := int(pEnd.Sub(pStart).Hours()/24) + 1
	if totalDays <= 0 {
		totalDays = 30
	}
	activeStart := pStart
	if c.ActivatedAt.After(pStart) && !c.ActivatedAt.After(pEnd) {
		activeStart = time.Date(c.ActivatedAt.Year(), c.ActivatedAt.Month(), c.ActivatedAt.Day(), 0, 0, 0, 0, time.UTC)
	}
	prorataDays := int(pEnd.Sub(activeStart).Hours()/24) + 1
	if prorataDays > totalDays {
		prorataDays = totalDays
	}
	if prorataDays < 1 {
		prorataDays = 1
	}

	// Deterministic integer math for prorata, discount, tax, and reseller commission.
	subtotal := (plan.MonthlyPriceCents * int64(prorataDays)) / int64(totalDays)
	disc := c.DiscountCents
	if disc > subtotal {
		disc = subtotal
	}
	taxable := subtotal - disc
	tax := (taxable * plan.TaxRatePct) / 100
	total := taxable + tax

	var comm int64
	if c.ResellerID != "" {
		if res, ok := e.resellers[c.ResellerID]; ok && res.Active {
			comm = (taxable * res.CommissionPct) / 100
		}
	}

	e.invSeq++
	invNo := fmt.Sprintf("INV-%s-%06d", now.Format("200601"), e.invSeq)
	inv := &Invoice{
		ID:                invNo,
		InvoiceNumber:     invNo,
		CustomerID:        c.ID,
		CustomerName:      c.Name,
		ResellerID:        c.ResellerID,
		BillingPeriod:     periodKey,
		PeriodStart:       pStart,
		PeriodEnd:         pEnd,
		DueDate:           dueDate,
		ProrataDays:       prorataDays,
		CycleTotalDays:    totalDays,
		SubtotalCents:     subtotal,
		DiscountCents:     disc,
		TaxCents:          tax,
		TotalCents:        total,
		ResellerCommCents: comm,
		Status:            StatusUnpaid,
		CreatedAt:         now,
	}
	e.invoices[inv.ID] = inv
	e.periodIndex[idxKey] = inv.ID
	e.appendAuditLocked("INVOICE_ISSUED", actor, inv.ID, fmt.Sprintf("cust=%s prorata=%d/%d total=%d", c.ID, prorataDays, totalDays, total))
	cp := *inv
	return &cp, nil
}

func computeBillingWindow(c *Customer, plan *ServicePlan, now time.Time) (start, end, due time.Time) {
	y, m, _ := now.Date()
	if c.CycleType == CycleAnniversary {
		anchorDay := c.ActivatedAt.Day()
		if anchorDay > 28 {
			anchorDay = 28
		}
		start = time.Date(y, m, anchorDay, 0, 0, 0, 0, time.UTC)
		end = start.AddDate(0, 1, -1)
		due = start.AddDate(0, 0, plan.GraceDays)
		return start, end, due
	}
	// Fixed-day cycle: standard calendar month or configured billing day.
	start = time.Date(y, m, 1, 0, 0, 0, 0, time.UTC)
	end = start.AddDate(0, 1, -1)
	billDay := c.FixedBillingDay
	if billDay < 1 || billDay > 28 {
		billDay = 1
	}
	dueBase := time.Date(y, m, billDay, 0, 0, 0, 0, time.UTC)
	if c.ActivatedAt.After(dueBase) {
		actDay := time.Date(c.ActivatedAt.Year(), c.ActivatedAt.Month(), c.ActivatedAt.Day(), 0, 0, 0, 0, time.UTC)
		dueBase = actDay
	}
	due = dueBase.AddDate(0, 0, plan.GraceDays)
	return start, end, due
}

// EnforceOverdueIsolation scans unpaid invoices past due date, applies late fees once,
// and triggers automatic PPPoE CoA ("ISOLIR") + TR-069 ACS suspension.
func (e *Engine) EnforceOverdueIsolation(actor string) ([]string, error) {
	now := e.opts.Now().UTC()
	e.mu.Lock()
	var isolatedCusts []string
	var notifyQueue [][2]string

	invIDs := make([]string, 0, len(e.invoices))
	for id := range e.invoices {
		invIDs = append(invIDs, id)
	}
	sort.Strings(invIDs)

	for _, id := range invIDs {
		inv := e.invoices[id]
		if inv.Status == StatusPaid || inv.Status == StatusVoid {
			continue
		}
		if !now.After(inv.DueDate) {
			continue
		}
		c := e.customers[inv.CustomerID]
		plan := e.plans[c.PlanID]

		if inv.Status == StatusUnpaid {
			inv.Status = StatusOverdue
			if plan.LateFeeCents > 0 && inv.LateFeeCents == 0 {
				inv.LateFeeCents = plan.LateFeeCents
				inv.TotalCents += plan.LateFeeCents
				e.appendAuditLocked("LATE_FEE_APPLIED", actor, inv.ID, fmt.Sprintf("fee=%d new_total=%d", plan.LateFeeCents, inv.TotalCents))
			}
		}

		if c.Status != "isolated" {
			c.Status = "isolated"
			e.applyIsolationHooksLocked(c, true, actor)
			isolatedCusts = append(isolatedCusts, c.ID)
			notifyQueue = append(notifyQueue, [2]string{c.ID, fmt.Sprintf("Layanan %s terisolir karena tagihan %s jatuh tempo (%d)", c.PPPoEUsername, inv.InvoiceNumber, inv.TotalCents)})
		}
	}
	e.mu.Unlock()

	for _, n := range notifyQueue {
		e.notifyCustomer(n[0], "service_isolated", n[1])
	}
	return isolatedCusts, nil
}

// MarkInvoicePaid settles an invoice idempotently, credits reseller balance,
// and triggers automatic PPPoE/TR-069 reactivation if the customer was isolated.
func (e *Engine) MarkInvoicePaid(invoiceID, method, paymentRef string, amountCents int64, actor string) (*Invoice, error) {
	now := e.opts.Now().UTC()
	e.mu.Lock()
	inv, ok := e.invoices[invoiceID]
	if !ok {
		e.mu.Unlock()
		return nil, fmt.Errorf("%w: invoice %q", ErrNotFound, invoiceID)
	}
	if paymentRef != "" {
		if prevInv, seen := e.paymentRefs[paymentRef]; seen {
			if prevInv == invoiceID {
				cp := *inv
				e.mu.Unlock()
				return &cp, nil
			}
			e.mu.Unlock()
			return nil, fmt.Errorf("%w: payment reference %q already applied to %s", ErrDuplicate, paymentRef, prevInv)
		}
	}
	if inv.Status == StatusPaid {
		e.mu.Unlock()
		return nil, ErrAlreadyPaid
	}
	if amountCents != inv.TotalCents {
		e.mu.Unlock()
		return nil, fmt.Errorf("%w: got %d want %d", ErrAmountMismatch, amountCents, inv.TotalCents)
	}

	inv.Status = StatusPaid
	inv.PaidCents = amountCents
	inv.PaymentMethod = method
	inv.PaymentRef = paymentRef
	inv.PaidAt = &now
	if paymentRef != "" {
		e.paymentRefs[paymentRef] = inv.ID
	}

	if inv.ResellerID != "" && inv.ResellerCommCents > 0 {
		if res, ok := e.resellers[inv.ResellerID]; ok {
			res.BalanceCents += inv.ResellerCommCents
		}
	}

	e.appendAuditLocked("PAYMENT_SETTLED", actor, inv.ID, fmt.Sprintf("method=%s ref=%s amount=%d", method, paymentRef, amountCents))

	c := e.customers[inv.CustomerID]
	reactivated := false
	if c != nil && c.Status == "isolated" {
		// Check no other overdue invoices remain before reactivating.
		hasOverdue := false
		for _, other := range e.invoices {
			if other.CustomerID == c.ID && other.Status == StatusOverdue {
				hasOverdue = true
				break
			}
		}
		if !hasOverdue {
			c.Status = "active"
			e.applyIsolationHooksLocked(c, false, actor)
			reactivated = true
		}
	}
	cp := *inv
	e.mu.Unlock()

	msg := fmt.Sprintf("Pembayaran %s sebesar %d diterima via %s.", cp.InvoiceNumber, amountCents, method)
	if reactivated {
		msg += " Layanan internet telah aktif kembali."
	}
	e.notifyCustomer(cp.CustomerID, "payment_confirmed", msg)
	return &cp, nil
}

func (e *Engine) applyIsolationHooksLocked(c *Customer, isolate bool, actor string) {
	if e.opts.Sessions != nil {
		pkt := &ispengine.RADIUSPacket{Code: ispengine.CodeCoARequest}
		pkt.AddString(ispengine.AttrUserName, c.PPPoEUsername)
		if isolate {
			pkt.AddString(ispengine.AttrFilterID, "ISOLIR")
		} else {
			pkt.AddString(ispengine.AttrFilterID, "ACTIVE")
			if plan, ok := e.plans[c.PlanID]; ok && plan.UploadKbps > 0 && plan.DownloadKbps > 0 {
				pkt.AddDaijiRateLimit(fmt.Sprintf("%d/%d", plan.UploadKbps, plan.DownloadKbps))
			}
		}
		_, _ = e.opts.Sessions.HandleCoAPacket(pkt)
	}
	if e.opts.ACS != nil && c.CPESerial != "" {
		act := "activate"
		if isolate {
			act = "suspend"
		}
		_, _ = e.opts.ACS.ApplyBillingAction(c.CPESerial, act)
	}
	actionName := "AUTO_REACTIVATED"
	if isolate {
		actionName = "AUTO_ISOLATED"
	}
	e.appendAuditLocked(actionName, actor, c.ID, fmt.Sprintf("pppoe=%s cpe=%s", c.PPPoEUsername, c.CPESerial))
}

func (e *Engine) appendAuditLocked(action, actor, targetID, detail string) {
	seq := uint64(len(e.auditChain)) + 1
	prev := stringsGenesisHash()
	if seq > 1 {
		prev = e.auditChain[len(e.auditChain)-1].Hash
	}
	ts := e.opts.Now().UTC().Format(time.RFC3339Nano)
	rec := AuditRecord{
		Seq:       seq,
		Timestamp: ts,
		Action:    action,
		Actor:     actor,
		TargetID:  targetID,
		Detail:    detail,
		PrevHash:  prev,
	}
	rec.Hash = computeAuditHash(rec)
	e.auditChain = append(e.auditChain, rec)
}

func computeAuditHash(r AuditRecord) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%s|%s|%s|%s|%s|%s", r.Seq, r.Timestamp, r.Action, r.Actor, r.TargetID, r.Detail, r.PrevHash)
	return hex.EncodeToString(h.Sum(nil))
}

func stringsGenesisHash() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

// VerifyAuditChain checks the entire billing ledger hash chain for immutability.
func (e *Engine) VerifyAuditChain() (int, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	prev := stringsGenesisHash()
	for _, r := range e.auditChain {
		if r.PrevHash != prev || computeAuditHash(r) != r.Hash {
			return 0, fmt.Errorf("%w: corruption at seq=%d", ErrAuditTampered, r.Seq)
		}
		prev = r.Hash
	}
	return len(e.auditChain), nil
}

// GetCustomer returns a snapshot copy of customer state.
func (e *Engine) GetCustomer(id string) (Customer, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	c, ok := e.customers[id]
	if !ok {
		return Customer{}, false
	}
	return *c, true
}

// ListCustomerInvoices returns all invoices belonging to customerID sorted newest first.
func (e *Engine) ListCustomerInvoices(customerID string) []Invoice {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []Invoice
	for _, inv := range e.invoices {
		if customerID == "" || inv.CustomerID == customerID {
			out = append(out, *inv)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].InvoiceNumber > out[j].InvoiceNumber })
	return out
}
