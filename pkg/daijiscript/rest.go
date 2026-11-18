// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijiscript

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/ispengine"
	"github.com/kangpcode/daijios/pkg/isptools"
	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

// APIDependencies supplies authenticated DaijiOS runtime subsystems to the REST API.
type APIDependencies struct {
	Config   *configengine.Engine
	Sessions *ispengine.SessionManager
	MultiWAN *ispengine.MultiWANMonitor
	Torch    *isptools.TorchAggregator
	Tokens   *secauth.TokenManager
	RBAC     *secauth.RBACPolicy
	Now      func() time.Time
}

// NewRESTHandler constructs the Phase 3 DaijiOS control & ISP telemetry REST API router.
func NewRESTHandler(deps APIDependencies) http.Handler {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.RBAC == nil {
		deps.RBAC = secauth.NewDefaultRBACPolicy(true)
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"product": sysinfo.ProductName,
			"brand":   sysinfo.BrandBanner,
			"version": sysinfo.Version,
		})
	})

	requireAuth := func(perm secauth.Permission, next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			hdr := r.Header.Get("Authorization")
			if !strings.HasPrefix(hdr, "Bearer ") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
				return
			}
			tok := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
			if deps.Tokens == nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "token manager unavailable"})
				return
			}
			claims, err := deps.Tokens.Verify(tok, perm, deps.Now())
			if err != nil {
				code := http.StatusUnauthorized
				if strings.Contains(err.Error(), "scope") {
					code = http.StatusForbidden
				}
				writeJSON(w, code, map[string]string{"error": err.Error()})
				return
			}
			if err := deps.RBAC.Authorize(claims.Role, perm); err != nil {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
				return
			}
			next(w, r)
		}
	}

	mux.HandleFunc("/api/v1/config/running", requireAuth(secauth.PermConfigRead, func(w http.ResponseWriter, r *http.Request) {
		if deps.Config == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config engine unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, deps.Config.GetRunning(true))
	}))

	mux.HandleFunc("/api/v1/isp/sessions", requireAuth(secauth.PermNetDiag, func(w http.ResponseWriter, r *http.Request) {
		if deps.Sessions == nil {
			writeJSON(w, http.StatusOK, []any{})
			return
		}
		writeJSON(w, http.StatusOK, deps.Sessions.ListSessions())
	}))

	mux.HandleFunc("/api/v1/isp/wans", requireAuth(secauth.PermNetDiag, func(w http.ResponseWriter, r *http.Request) {
		if deps.MultiWAN == nil {
			writeJSON(w, http.StatusOK, []any{})
			return
		}
		writeJSON(w, http.StatusOK, deps.MultiWAN.Snapshot())
	}))

	mux.HandleFunc("/api/v1/isp/torch", requireAuth(secauth.PermNetDiag, func(w http.ResponseWriter, r *http.Request) {
		if deps.Torch == nil {
			writeJSON(w, http.StatusOK, []any{})
			return
		}
		writeJSON(w, http.StatusOK, deps.Torch.Snapshot(5.0, 50))
	}))

	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
