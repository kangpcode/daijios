// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijiportal

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

// Server exposes DaijiPortal central SaaS REST endpoints.
type Server struct {
	portal *Portal
	tokens *secauth.TokenManager
	rbac   *secauth.RBACPolicy
	mux    *http.ServeMux
}

// NewServer constructs an HTTP API server wrapping Portal.
func NewServer(portal *Portal, tokens *secauth.TokenManager) (*Server, error) {
	if portal == nil {
		return nil, errors.New("portal required")
	}
	if tokens == nil {
		tm, err := secauth.NewTokenManager([]byte("daijiportal-default-jwt-key-phase11"), 12*time.Hour)
		if err != nil {
			return nil, err
		}
		tokens = tm
	}
	s := &Server{
		portal: portal,
		tokens: tokens,
		rbac:   secauth.NewDefaultRBACPolicy(true),
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

// Handler returns the HTTP router.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/v1/portal/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":     "ok",
			"brand":      sysinfo.BrandBanner,
			"public_key": hex.EncodeToString(s.portal.PublicKey()),
		})
	})

	s.mux.HandleFunc("/api/v1/portal/branding", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			domain := r.URL.Query().Get("domain")
			if domain == "" {
				domain = r.Host
			}
			writeJSON(w, http.StatusOK, s.portal.ResolveBrandingByHost(domain))
			return
		}
		s.requirePerm(secauth.PermConfigWrite, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
			var b ResellerBranding
			if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&b); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			saved, err := s.portal.SetWhiteLabelBranding(b)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, saved)
		})(w, r)
	})

	s.mux.HandleFunc("/api/v1/portal/marketplace", func(w http.ResponseWriter, r *http.Request) {
		s.portal.mu.RLock()
		skus := make([]MarketplaceSKU, 0, len(s.portal.skus))
		for _, k := range s.portal.skus {
			skus = append(skus, k)
		}
		s.portal.mu.RUnlock()
		sort.Slice(skus, func(i, j int) bool { return skus[i].ID < skus[j].ID })
		writeJSON(w, http.StatusOK, skus)
	})

	s.mux.HandleFunc("/api/v1/portal/licenses/trial", s.requirePerm(secauth.PermConfigWrite, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
		var req struct {
			OrgID      string `json:"org_id"`
			ResellerID string `json:"reseller_id"`
			HardwareID string `json:"hardware_id"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		lic, err := s.portal.StartTrial(req.OrgID, req.ResellerID, req.HardwareID)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, lic)
	}))

	s.mux.HandleFunc("/api/v1/portal/licenses/purchase", s.requirePerm(secauth.PermConfigWrite, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
		var req struct {
			OrgID       string `json:"org_id"`
			ResellerID  string `json:"reseller_id"`
			SKUID       string `json:"sku_id"`
			HardwareID  string `json:"hardware_id"`
			DeviceCount int    `json:"device_count"`
			Months      int    `json:"months"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		inv, lic, err := s.portal.PurchaseLicense(req.OrgID, req.ResellerID, req.SKUID, req.HardwareID, req.DeviceCount, req.Months)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"invoice": inv, "license": lic})
	}))

	s.mux.HandleFunc("/api/v1/portal/licenses/activate-online", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			LicenseID  string `json:"license_id"`
			HardwareID string `json:"hardware_id"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		lic, err := s.portal.ActivateOnline(req.LicenseID, req.HardwareID)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, lic)
	})

	s.mux.HandleFunc("/api/v1/portal/updates", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, s.portal.ListReleases(r.URL.Query().Get("channel")))
			return
		}
		s.requirePerm(secauth.PermSystemUpdate, func(w http.ResponseWriter, r *http.Request, _ *secauth.TokenClaims) {
			var rel SignedRelease
			if err := json.NewDecoder(io.LimitReader(r.Body, 32*1024)).Decode(&rel); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			pub, err := s.portal.PublishRelease(rel)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, pub)
		})(w, r)
	})

	s.mux.HandleFunc("/api/v1/portal/tickets", s.requirePerm(secauth.PermNetDiag, func(w http.ResponseWriter, r *http.Request, claims *secauth.TokenClaims) {
		var req struct {
			OrgID      string `json:"org_id"`
			ResellerID string `json:"reseller_id"`
			Subject    string `json:"subject"`
			Priority   string `json:"priority"`
			Body       string `json:"body"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		tk := s.portal.CreateTicket(req.OrgID, req.ResellerID, claims.Subject, req.Subject, req.Priority, req.Body)
		writeJSON(w, http.StatusOK, tk)
	}))

	s.mux.HandleFunc("/api/v1/portal/kb", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.portal.SearchKB(r.URL.Query().Get("q"), r.URL.Query().Get("locale")))
	})
}

func (s *Server) requirePerm(perm secauth.Permission, next func(http.ResponseWriter, *http.Request, *secauth.TokenClaims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		tok := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
		claims, err := s.tokens.Verify(tok, perm, s.portal.nowFn())
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
