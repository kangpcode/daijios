// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijiportal

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// FuzzOfflineLicenseAndAPI fuzzes DJLIC1 Ed25519 license blobs and DaijiPortal REST JSON endpoints.
func FuzzOfflineLicenseAndAPI(f *testing.F) {
	portal, err := NewPortal(nil, func() time.Time { return time.Unix(1795043731, 0).UTC() })
	if err != nil {
		f.Fatalf("NewPortal: %v", err)
	}
	_, lic, err := portal.PurchaseLicense("org-fuzz", "official", "sku-ent", "HW-FUZZ-1", 5, 1)
	if err != nil {
		f.Fatalf("PurchaseLicense: %v", err)
	}
	srv, err := NewServer(portal, nil)
	if err != nil {
		f.Fatalf("NewServer: %v", err)
	}

	f.Add(lic.OfflineBlob, []byte(`{"license_id":"lic-1","hardware_id":"HW-1"}`))
	f.Add("DJLIC1.abc.def", []byte(`{bad json`))
	f.Add("", []byte{})

	now := time.Unix(1795043731, 0).UTC()
	f.Fuzz(func(t *testing.T, blob string, body []byte) {
		if len(blob) > 4096 || len(body) > 8192 {
			return
		}
		_, _ = VerifyOfflineLicense(portal.PublicKey(), blob, "HW-FUZZ-1", "bgp", 1, now)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/portal/licenses/activate-online", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
	})
}
