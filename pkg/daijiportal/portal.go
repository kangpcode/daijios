// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijiportal

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kangpcode/daijios/pkg/sysinfo"
)

var (
	ErrTrialAlreadyUsed = errors.New("free trial already consumed for this organization or hardware")
	ErrNotFound         = errors.New("portal record not found")
	ErrUnsafeInput      = errors.New("unsafe URL or script content rejected")
)

// ResellerBranding defines white-label OS/Portal identity for a partner/reseller.
type ResellerBranding struct {
	ResellerID   string `json:"reseller_id"`
	OSName       string `json:"os_name"`
	PortalTitle  string `json:"portal_title"`
	CustomDomain string `json:"custom_domain"`
	LogoURL      string `json:"logo_url,omitempty"`
	PrimaryColor string `json:"primary_color"`
	AccentColor  string `json:"accent_color"`
	BrandFooter  string `json:"brand_footer"` // preserves DaijiOS attribution
}

// MarketplaceSKU defines one purchasable subscription tier or feature pack.
type MarketplaceSKU struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	Tier            LicenseTier `json:"tier"`
	PricePerDevice  int64       `json:"price_per_device_cents"`
	BaseMonthly     int64       `json:"base_monthly_cents"`
	IncludedFeats   []string    `json:"included_features"`
}

// SaaSInvoice records a license purchase or subscription renewal.
type SaaSInvoice struct {
	ID            string `json:"id"`
	OrgID         string `json:"org_id"`
	ResellerID    string `json:"reseller_id,omitempty"`
	SKUID         string `json:"sku_id"`
	DeviceCount   int    `json:"device_count"`
	TotalCents    int64  `json:"total_cents"`
	ResellerShare int64  `json:"reseller_share_cents"`
	Paid          bool   `json:"paid"`
	LicenseID     string `json:"license_id,omitempty"`
	CreatedAt     string `json:"created_at"`
}

// SaaSTenant tracks an organization onboarded inside DaijiPortal.
type SaaSTenant struct {
	OrgID      string `json:"org_id"`
	Name       string `json:"name"`
	ResellerID string `json:"reseller_id,omitempty"`
	ActiveTier string `json:"active_tier"`
}

// TicketReply records one message on a support ticket.
type TicketReply struct {
	Author string `json:"author"`
	Body   string `json:"body"`
	At     string `json:"at"`
}

// SupportTicket tracks tenant/reseller support requests.
type SupportTicket struct {
	ID         string        `json:"id"`
	OrgID      string        `json:"org_id"`
	ResellerID string        `json:"reseller_id,omitempty"`
	Author     string        `json:"author"`
	Subject    string        `json:"subject"`
	Priority   string        `json:"priority"` // low | normal | high | critical
	Status     string        `json:"status"`   // open | answered | closed
	Replies    []TicketReply `json:"replies"`
	CreatedAt  string        `json:"created_at"`
}

// KBArticle stores bilingual documentation entries in DaijiPortal's Knowledge Base.
type KBArticle struct {
	Slug     string   `json:"slug"`
	Title    string   `json:"title"`
	Category string   `json:"category"`
	Locale   string   `json:"locale"` // id | en
	Body     string   `json:"body"`
	Tags     []string `json:"tags"`
}

// Portal manages DaijiPortal SaaS state: branding, licenses, marketplace, releases, tickets, & KB.
type Portal struct {
	mu          sync.RWMutex
	privKey     ed25519.PrivateKey
	pubKey      ed25519.PublicKey
	brandings   map[string]ResellerBranding // resellerID -> branding
	domainIndex map[string]string           // domain -> resellerID
	tenants     map[string]SaaSTenant
	skus        map[string]MarketplaceSKU
	licenses    map[string]*IssuedLicense
	trialsUsed  map[string]bool // orgID|hwID
	invoices    map[string]SaaSInvoice
	releases    []SignedRelease
	tickets     map[string]*SupportTicket
	kb          map[string]KBArticle
	nowFn       func() time.Time
}

// NewPortal initializes a DaijiPortal SaaS hub with Ed25519 keypair, default SKUs, & starter KB articles.
func NewPortal(priv ed25519.PrivateKey, nowFn func() time.Time) (*Portal, error) {
	if nowFn == nil {
		nowFn = time.Now
	}
	var pub ed25519.PublicKey
	if len(priv) == 0 {
		var err error
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	} else if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key length")
	} else {
		pub = priv.Public().(ed25519.PublicKey)
	}

	p := &Portal{
		privKey:     priv,
		pubKey:      pub,
		brandings:   make(map[string]ResellerBranding),
		domainIndex: make(map[string]string),
		tenants:     make(map[string]SaaSTenant),
		skus:        make(map[string]MarketplaceSKU),
		licenses:    make(map[string]*IssuedLicense),
		trialsUsed:  make(map[string]bool),
		invoices:    make(map[string]SaaSInvoice),
		tickets:     make(map[string]*SupportTicket),
		kb:          make(map[string]KBArticle),
		nowFn:       nowFn,
	}
	p.seedDefaults()
	return p, nil
}

// PublicKey returns the Ed25519 verification key embedded in DaijiOS appliances for offline validation.
func (p *Portal) PublicKey() ed25519.PublicKey {
	return p.pubKey
}

func (p *Portal) seedDefaults() {
	p.skus["sku-free"] = MarketplaceSKU{
		ID: "sku-free", Name: "DaijiOS Free Starter", Tier: TierFree,
		IncludedFeats: []string{"routing-core", "firewall-basic", "daiweb"},
	}
	p.skus["sku-pro"] = MarketplaceSKU{
		ID: "sku-pro", Name: "DaijiOS Pro ISP/Campus", Tier: TierPro, BaseMonthly: 150000, PricePerDevice: 25000,
		IncludedFeats: []string{"routing-core", "firewall-basic", "daiweb", "bgp", "pppoe-bng", "ac-wireless", "tr069-acs"},
	}
	p.skus["sku-ent"] = MarketplaceSKU{
		ID: "sku-ent", Name: "DaijiOS Enterprise Carrier", Tier: TierEnterprise, BaseMonthly: 500000, PricePerDevice: 40000,
		IncludedFeats: []string{"routing-core", "firewall-basic", "daiweb", "bgp", "pppoe-bng", "ac-wireless", "tr069-acs", "daijibilling", "multi-tenant"},
	}
	p.kb["ztp-onboarding-id"] = KBArticle{
		Slug: "ztp-onboarding-id", Title: "Panduan Zero-Touch Provisioning DaijiOS", Category: "Onboarding", Locale: "id",
		Body: "Gunakan token ZTP dari DaijiCloud untuk mengadopsi router/AP baru secara otomatis.", Tags: []string{"ztp", "cloud"},
	}
	p.kb["license-offline-en"] = KBArticle{
		Slug: "license-offline-en", Title: "Offline Ed25519 License Activation Guide", Category: "Licensing", Locale: "en",
		Body: "Export the HardwareID from daiji-ctl and import the signed DJLIC1 activation certificate.", Tags: []string{"license", "offline"},
	}
}

// SetWhiteLabelBranding configures reseller branding while preserving DaijiOS attribution and sanitizing URLs/XSS.
func (p *Portal) SetWhiteLabelBranding(b ResellerBranding) (ResellerBranding, error) {
	if b.ResellerID == "" || b.OSName == "" || b.CustomDomain == "" {
		return ResellerBranding{}, errors.New("reseller_id, os_name, and custom_domain required")
	}
	for _, s := range []string{b.OSName, b.PortalTitle, b.PrimaryColor, b.AccentColor, b.CustomDomain} {
		if strings.ContainsAny(s, "<>\"") {
			return ResellerBranding{}, fmt.Errorf("%w: HTML/script characters forbidden", ErrUnsafeInput)
		}
	}
	if b.LogoURL != "" {
		u, err := url.ParseRequestURI(b.LogoURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return ResellerBranding{}, fmt.Errorf("%w: logo_url must be https:// or http://", ErrUnsafeInput)
		}
	}
	b.BrandFooter = sysinfo.BrandBanner

	p.mu.Lock()
	defer p.mu.Unlock()
	p.brandings[b.ResellerID] = b
	p.domainIndex[strings.ToLower(b.CustomDomain)] = b.ResellerID
	return b, nil
}

// ResolveBrandingByHost returns customized reseller branding for domain, or canonical DaijiOS default.
func (p *Portal) ResolveBrandingByHost(host string) ResellerBranding {
	p.mu.RLock()
	defer p.mu.RUnlock()
	clean := strings.ToLower(strings.Split(host, ":")[0])
	if rid, ok := p.domainIndex[clean]; ok {
		return p.brandings[rid]
	}
	return ResellerBranding{
		ResellerID:   "official",
		OSName:       "DaijiOS",
		PortalTitle:  "DaijiPortal — Official Ecosystem Console",
		CustomDomain: "portal.daijios.dev",
		PrimaryColor: "#18c996",
		AccentColor:  "#0b0f14",
		BrandFooter:  sysinfo.BrandBanner,
	}
}

// StartTrial mints a single non-repeatable 14-day Pro license bound to (orgID, hardwareID).
func (p *Portal) StartTrial(orgID, resellerID, hardwareID string) (*IssuedLicense, error) {
	if orgID == "" || hardwareID == "" {
		return nil, errors.New("org_id and hardware_id required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	tKey := orgID + "|" + strings.ToLower(hardwareID)
	if p.trialsUsed[tKey] {
		return nil, ErrTrialAlreadyUsed
	}
	p.trialsUsed[tKey] = true

	now := p.nowFn().UTC()
	payload := LicensePayload{
		LicenseID:       newID("lic"),
		OrgID:           orgID,
		ResellerID:      resellerID,
		HardwareID:      hardwareID,
		Tier:            TierPro,
		MaxDevices:      5,
		EnabledFeatures: append([]string(nil), p.skus["sku-pro"].IncludedFeats...),
		Trial:           true,
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.Add(14 * 24 * time.Hour).Unix(),
	}
	blob, err := SignOfflineLicense(p.privKey, payload)
	if err != nil {
		return nil, err
	}
	lic := &IssuedLicense{Payload: payload, OfflineBlob: blob}
	p.licenses[payload.LicenseID] = lic
	p.tenants[orgID] = SaaSTenant{OrgID: orgID, Name: orgID, ResellerID: resellerID, ActiveTier: string(TierPro) + "-trial"}
	cp := *lic
	return &cp, nil
}

// PurchaseLicense creates a paid marketplace invoice and mints the corresponding Ed25519 license.
func (p *Portal) PurchaseLicense(orgID, resellerID, skuID, hardwareID string, deviceCount, months int) (*SaaSInvoice, *IssuedLicense, error) {
	if deviceCount <= 0 {
		deviceCount = 1
	}
	if months <= 0 {
		months = 1
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	sku, ok := p.skus[skuID]
	if !ok {
		return nil, nil, fmt.Errorf("%w: SKU %q", ErrNotFound, skuID)
	}

	now := p.nowFn().UTC()
	total := (sku.BaseMonthly + int64(deviceCount)*sku.PricePerDevice) * int64(months)
	var share int64
	if resellerID != "" && resellerID != "official" {
		share = (total * 20) / 100 // 20% partner margin
	}

	payload := LicensePayload{
		LicenseID:       newID("lic"),
		OrgID:           orgID,
		ResellerID:      resellerID,
		HardwareID:      hardwareID,
		Tier:            sku.Tier,
		MaxDevices:      deviceCount,
		EnabledFeatures: append([]string(nil), sku.IncludedFeats...),
		Trial:           false,
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.AddDate(0, months, 0).Unix(),
	}
	blob, err := SignOfflineLicense(p.privKey, payload)
	if err != nil {
		return nil, nil, err
	}
	lic := &IssuedLicense{Payload: payload, OfflineBlob: blob}
	p.licenses[payload.LicenseID] = lic

	inv := SaaSInvoice{
		ID:            newID("saasinv"),
		OrgID:         orgID,
		ResellerID:    resellerID,
		SKUID:         skuID,
		DeviceCount:   deviceCount,
		TotalCents:    total,
		ResellerShare: share,
		Paid:          true,
		LicenseID:     payload.LicenseID,
		CreatedAt:     now.Format(time.RFC3339),
	}
	p.invoices[inv.ID] = inv
	p.tenants[orgID] = SaaSTenant{OrgID: orgID, Name: orgID, ResellerID: resellerID, ActiveTier: string(sku.Tier)}
	licCopy := *lic
	return &inv, &licCopy, nil
}

// ActivateOnline checks live revocation status for a license ID and returns the signed certificate.
func (p *Portal) ActivateOnline(licenseID, hardwareID string) (IssuedLicense, error) {
	p.mu.RLock()
	lic, ok := p.licenses[licenseID]
	p.mu.RUnlock()
	if !ok {
		return IssuedLicense{}, fmt.Errorf("%w: license %q", ErrNotFound, licenseID)
	}
	if lic.Revoked {
		return IssuedLicense{}, ErrLicenseRevoked
	}
	if _, err := VerifyOfflineLicense(p.pubKey, lic.OfflineBlob, hardwareID, "", 1, p.nowFn()); err != nil {
		return IssuedLicense{}, err
	}
	return *lic, nil
}

// RevokeLicense blacklists a compromised or refunded license against future online activations.
func (p *Portal) RevokeLicense(licenseID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	lic, ok := p.licenses[licenseID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, licenseID)
	}
	lic.Revoked = true
	return nil
}

// PublishRelease signs and publishes a DaijiOS software/firmware release to stable/beta/lts channels.
func (p *Portal) PublishRelease(r SignedRelease) (SignedRelease, error) {
	if r.Channel != "stable" && r.Channel != "beta" && r.Channel != "lts" {
		return SignedRelease{}, errors.New("channel must be stable, beta, or lts")
	}
	u, err := url.ParseRequestURI(r.URL)
	if err != nil || u.Scheme != "https" {
		return SignedRelease{}, fmt.Errorf("%w: release URL must use https://", ErrUnsafeInput)
	}
	r.PublishedAt = p.nowFn().UTC().Format(time.RFC3339)
	if err := SignRelease(p.privKey, &r); err != nil {
		return SignedRelease{}, err
	}
	p.mu.Lock()
	p.releases = append([]SignedRelease{r}, p.releases...)
	p.mu.Unlock()
	return r, nil
}

// ListReleases returns signed releases filtered by update channel.
func (p *Portal) ListReleases(channel string) []SignedRelease {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var out []SignedRelease
	for _, r := range p.releases {
		if channel == "" || r.Channel == channel {
			out = append(out, r)
		}
	}
	return out
}

// CreateTicket opens a tenant/reseller support ticket.
func (p *Portal) CreateTicket(orgID, resellerID, author, subject, priority, body string) SupportTicket {
	nowStr := p.nowFn().UTC().Format(time.RFC3339)
	tk := &SupportTicket{
		ID:         newID("tkt"),
		OrgID:      orgID,
		ResellerID: resellerID,
		Author:     author,
		Subject:    subject,
		Priority:   priority,
		Status:     "open",
		Replies:    []TicketReply{{Author: author, Body: body, At: nowStr}},
		CreatedAt:  nowStr,
	}
	p.mu.Lock()
	p.tickets[tk.ID] = tk
	p.mu.Unlock()
	return *tk
}

// SearchKB searches the Knowledge Base articles matching query and optional locale.
func (p *Portal) SearchKB(query, locale string) []KBArticle {
	p.mu.RLock()
	defer p.mu.RUnlock()
	q := strings.ToLower(strings.TrimSpace(query))
	var out []KBArticle
	for _, a := range p.kb {
		if locale != "" && a.Locale != locale {
			continue
		}
		if q == "" || strings.Contains(strings.ToLower(a.Title+" "+a.Body+" "+strings.Join(a.Tags, " ")), q) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out
}
