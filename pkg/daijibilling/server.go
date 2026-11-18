// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijibilling

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

// Server exposes DaijiBilling Admin/Reseller APIs, payment webhooks, and the Customer Portal.
type Server struct {
	engine       *Engine
	tokens       *secauth.TokenManager
	rbac         *secauth.RBACPolicy
	portalSecret []byte
	mux          *http.ServeMux
}

// NewServer constructs an HTTP router for DaijiBilling.
func NewServer(eng *Engine, tokens *secauth.TokenManager, portalSecret []byte) (*Server, error) {
	if eng == nil {
		return nil, fmt.Errorf("billing engine is required")
	}
	if tokens == nil {
		tm, err := secauth.NewTokenManager([]byte("daijibilling-default-token-key-p9"), 12*time.Hour)
		if err != nil {
			return nil, err
		}
		tokens = tm
	}
	if len(portalSecret) < 16 {
		portalSecret = []byte("daijibilling-portal-secret-phase9")
	}
	s := &Server{
		engine:       eng,
		tokens:       tokens,
		rbac:         secauth.NewDefaultRBACPolicy(true),
		portalSecret: append([]byte(nil), portalSecret...),
		mux:          http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

// IssuePortalToken mints a customer-scoped portal token bound exclusively to customerID.
func (s *Server) IssuePortalToken(customerID string) string {
	mac := hmac.New(sha256.New, s.portalSecret)
	_, _ = mac.Write([]byte("portal|" + customerID))
	return customerID + "." + hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) verifyPortalToken(tok string) (string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 2 || parts[0] == "" {
		return "", false
	}
	expected := s.IssuePortalToken(parts[0])
	if hmac.Equal([]byte(tok), []byte(expected)) {
		return parts[0], true
	}
	return "", false
}

// Handler returns the configured HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	// Customer Portal endpoints
	s.mux.HandleFunc("/portal", s.handlePortalPage)
	s.mux.HandleFunc("/portal/invoices", s.handlePortalInvoices)
	s.mux.HandleFunc("/portal/checkout", s.handlePortalCheckout)

	// Payment Gateway Webhooks
	s.mux.HandleFunc("/webhooks/billing/midtrans", s.handleMidtransWebhook)
	s.mux.HandleFunc("/webhooks/billing/xendit", s.handleXenditWebhook)
	s.mux.HandleFunc("/webhooks/billing/qris", s.handleQRISWebhook)

	// Admin & Reseller APIs
	s.mux.HandleFunc("/api/v1/billing/invoices/generate", s.requirePerm(secauth.PermConfigWrite, func(w http.ResponseWriter, r *http.Request, c *secauth.TokenClaims) {
		list, err := s.engine.GenerateMonthlyInvoices(c.Subject)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, list)
	}))
	s.mux.HandleFunc("/api/v1/billing/enforce-overdue", s.requirePerm(secauth.PermConfigWrite, func(w http.ResponseWriter, r *http.Request, c *secauth.TokenClaims) {
		isolated, err := s.engine.EnforceOverdueIsolation(c.Subject)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"isolated_customers": isolated})
	}))
	s.mux.HandleFunc("/api/v1/billing/manual-confirm", s.requirePerm(secauth.PermConfigWrite, func(w http.ResponseWriter, r *http.Request, c *secauth.TokenClaims) {
		var req struct {
			InvoiceID   string `json:"invoice_id"`
			BankRef     string `json:"bank_ref"`
			AmountCents int64  `json:"amount_cents"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		inv, err := s.engine.MarkInvoicePaid(req.InvoiceID, "manual-transfer", req.BankRef, req.AmountCents, c.Subject)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, inv)
	}))
	s.mux.HandleFunc("/api/v1/billing/report", s.requirePerm(secauth.PermAuditRead, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
		writeJSON(w, http.StatusOK, s.engine.GenerateFinancialReport(r.URL.Query().Get("period")))
	}))
	s.mux.HandleFunc("/api/v1/billing/reconcile", s.requirePerm(secauth.PermAuditRead, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
		var stmts []ExternalSettlement
		if err := json.NewDecoder(io.LimitReader(r.Body, 256*1024)).Decode(&stmts); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		writeJSON(w, http.StatusOK, s.engine.ReconcilePayments(stmts))
	}))
	s.mux.HandleFunc("/api/v1/billing/audit-verify", s.requirePerm(secauth.PermAuditRead, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
		cnt, err := s.engine.VerifyAuditChain()
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"verified_entries": cnt, "status": "ok"})
	}))
}

func (s *Server) handlePortalPage(w http.ResponseWriter, r *http.Request) {
	cid, ok := s.verifyPortalToken(r.URL.Query().Get("token"))
	if !ok {
		http.Error(w, "invalid or missing customer portal token", http.StatusUnauthorized)
		return
	}
	cust, exists := s.engine.GetCustomer(cid)
	if !exists {
		http.Error(w, "customer not found", http.StatusNotFound)
		return
	}
	invs := s.engine.ListCustomerInvoices(cid)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	fmt.Fprintf(w, "<!DOCTYPE html><html lang=\"id\"><head><meta charset=\"utf-8\"><title>Portal Pelanggan — DaijiBilling</title></head><body><h1>Portal Pelanggan %s</h1><p>%s | Status: <strong>%s</strong></p><ul>",
		html.EscapeString(cust.Name), html.EscapeString(sysinfo.BrandBanner), html.EscapeString(cust.Status))
	for _, inv := range invs {
		fmt.Fprintf(w, "<li>%s — Total: %d — Status: %s</li>", html.EscapeString(inv.InvoiceNumber), inv.TotalCents, html.EscapeString(string(inv.Status)))
	}
	io.WriteString(w, "</ul></body></html>")
}

func (s *Server) handlePortalInvoices(w http.ResponseWriter, r *http.Request) {
	cid, ok := s.verifyPortalToken(r.Header.Get("X-Portal-Token"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid portal token"})
		return
	}
	cust, _ := s.engine.GetCustomer(cid)
	writeJSON(w, http.StatusOK, map[string]any{
		"customer": cust,
		"invoices": s.engine.ListCustomerInvoices(cid),
	})
}

func (s *Server) handlePortalCheckout(w http.ResponseWriter, r *http.Request) {
	cid, ok := s.verifyPortalToken(r.Header.Get("X-Portal-Token"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid portal token"})
		return
	}
	var req struct {
		InvoiceID string `json:"invoice_id"`
		Method    string `json:"method"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	invs := s.engine.ListCustomerInvoices(cid)
	owned := false
	for _, inv := range invs {
		if inv.ID == req.InvoiceID {
			owned = true
			break
		}
	}
	if !owned {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invoice belongs to another customer"})
		return
	}
	chk, err := s.engine.BuildCheckout(req.InvoiceID, req.Method)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, chk)
}

func (s *Server) handleMidtransWebhook(w http.ResponseWriter, r *http.Request) {
	var p struct {
		OrderID           string `json:"order_id"`
		StatusCode        string `json:"status_code"`
		GrossAmount       string `json:"gross_amount"`
		TransactionStatus string `json:"transaction_status"`
		TransactionID     string `json:"transaction_id"`
		SignatureKey      string `json:"signature_key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 32*1024)).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	inv, err := s.engine.ProcessMidtransWebhook(p.OrderID, p.StatusCode, p.GrossAmount, p.TransactionStatus, p.TransactionID, p.SignatureKey)
	if err != nil {
		code := http.StatusBadRequest
		if err == ErrInvalidWebhook {
			code = http.StatusUnauthorized
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "invoice": inv})
}

func (s *Server) handleXenditWebhook(w http.ResponseWriter, r *http.Request) {
	var p struct {
		ExternalID string `json:"external_id"`
		Status     string `json:"status"`
		PaymentID  string `json:"payment_id"`
		Amount     int64  `json:"amount"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 32*1024)).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	inv, err := s.engine.ProcessXenditWebhook(r.Header.Get("X-Callback-Token"), p.ExternalID, p.Status, p.PaymentID, p.Amount)
	if err != nil {
		code := http.StatusBadRequest
		if err == ErrInvalidWebhook {
			code = http.StatusUnauthorized
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "invoice": inv})
}

func (s *Server) handleQRISWebhook(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 32*1024))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body failed"})
		return
	}
	var p struct {
		InvoiceNumber string `json:"invoice_number"`
		PaymentRef    string `json:"payment_ref"`
		AmountCents   int64  `json:"amount_cents"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	inv, err := s.engine.ProcessQRISWebhook(raw, r.Header.Get("X-Daiji-Signature"), p.InvoiceNumber, p.PaymentRef, p.AmountCents)
	if err != nil {
		code := http.StatusBadRequest
		if err == ErrInvalidWebhook {
			code = http.StatusUnauthorized
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "invoice": inv})
}

func (s *Server) requirePerm(perm secauth.Permission, next func(http.ResponseWriter, *http.Request, *secauth.TokenClaims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		tok := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
		claims, err := s.tokens.Verify(tok, perm, time.Now())
		if err != nil {
			code := http.StatusUnauthorized
			if strings.Contains(err.Error(), "scope") {
				code = http.StatusForbidden
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if err := s.rbac.Authorize(claims.Role, perm); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		next(w, r, claims)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
