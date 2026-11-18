// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package daijiportal implements DaijiPortal (Central SaaS):
// white-label reseller branding, Ed25519-signed online & offline licensing
// (Free/Pro/Enterprise tiers, per-device/per-feature caps, anti-tamper & hardware binding),
// marketplace/subscriptions/trials/invoices, signed firmware/update channels
// (stable/beta/LTS + changelogs), tenant/reseller CRM, support tickets, and KB.
package daijiportal

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

type LicenseTier string

const (
	TierFree       LicenseTier = "free"
	TierPro        LicenseTier = "pro"
	TierEnterprise LicenseTier = "enterprise"
)

var (
	ErrTamperedLicense    = errors.New("license Ed25519 signature verification failed")
	ErrLicenseExpired     = errors.New("license has expired")
	ErrLicenseRevoked     = errors.New("license has been revoked")
	ErrHardwareMismatch   = errors.New("license hardware fingerprint mismatch")
	ErrFeatureNotLicensed = errors.New("feature not enabled in current license tier")
	ErrDeviceLimit        = errors.New("device count exceeds licensed quota")
)

// LicensePayload holds signed entitlement claims inside a DJLIC1 certificate.
type LicensePayload struct {
	LicenseID       string      `json:"license_id"`
	OrgID           string      `json:"org_id"`
	ResellerID      string      `json:"reseller_id,omitempty"`
	HardwareID      string      `json:"hardware_id"` // bound board serial/MAC hash for anti-clone
	Tier            LicenseTier `json:"tier"`
	MaxDevices      int         `json:"max_devices"`
	EnabledFeatures []string    `json:"enabled_features"`
	Trial           bool        `json:"trial"`
	IssuedAt        int64       `json:"issued_at"`
	ExpiresAt       int64       `json:"expires_at"`
}

// IssuedLicense pairs parsed metadata with its portable offline activation token (`DJLIC1...`).
type IssuedLicense struct {
	Payload     LicensePayload `json:"payload"`
	OfflineBlob string         `json:"offline_blob"`
	Revoked     bool           `json:"revoked"`
}

// SignOfflineLicense serializes payload canonically and signs it with Ed25519.
func SignOfflineLicense(priv ed25519.PrivateKey, p LicensePayload) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("invalid ed25519 private key")
	}
	slices.Sort(p.EnabledFeatures)
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	b64Payload := base64.RawURLEncoding.EncodeToString(raw)
	sig := ed25519.Sign(priv, []byte(b64Payload))
	return "DJLIC1." + b64Payload + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyOfflineLicense validates Ed25519 anti-tamper signature, expiry, hardware ID, device count, and optional feature.
func VerifyOfflineLicense(pub ed25519.PublicKey, blob, expectedHardwareID, requiredFeature string, currentDevices int, now time.Time) (LicensePayload, error) {
	if len(pub) != ed25519.PublicKeySize {
		return LicensePayload{}, ErrTamperedLicense
	}
	parts := strings.Split(strings.TrimSpace(blob), ".")
	if len(parts) != 3 || parts[0] != "DJLIC1" {
		return LicensePayload{}, ErrTamperedLicense
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[1]), sigBytes) {
		return LicensePayload{}, ErrTamperedLicense
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return LicensePayload{}, ErrTamperedLicense
	}
	var p LicensePayload
	if err := json.Unmarshal(rawPayload, &p); err != nil {
		return LicensePayload{}, ErrTamperedLicense
	}
	if p.ExpiresAt > 0 && now.UTC().Unix() > p.ExpiresAt {
		return LicensePayload{}, ErrLicenseExpired
	}
	if p.HardwareID != "" && expectedHardwareID != "" && !strings.EqualFold(p.HardwareID, expectedHardwareID) {
		return LicensePayload{}, fmt.Errorf("%w: bound=%s got=%s", ErrHardwareMismatch, p.HardwareID, expectedHardwareID)
	}
	if p.MaxDevices > 0 && currentDevices > p.MaxDevices {
		return LicensePayload{}, fmt.Errorf("%w: used=%d max=%d", ErrDeviceLimit, currentDevices, p.MaxDevices)
	}
	if requiredFeature != "" && !slices.Contains(p.EnabledFeatures, requiredFeature) {
		return LicensePayload{}, fmt.Errorf("%w: %s (tier=%s)", ErrFeatureNotLicensed, requiredFeature, p.Tier)
	}
	return p, nil
}

// SignedRelease represents an update package metadata entry verified via Ed25519.
type SignedRelease struct {
	Version    string   `json:"version"`
	Channel    string   `json:"channel"` // stable | beta | lts
	Changelog  []string `json:"changelog"`
	URL        string   `json:"url"`
	SHA256     string   `json:"sha256"`
	Signature  string   `json:"ed25519_sig"`
	PublishedAt string  `json:"published_at"`
}

// SignRelease signs canonical release metadata with DaijiPortal's Ed25519 private key.
func SignRelease(priv ed25519.PrivateKey, r *SignedRelease) error {
	if len(priv) != ed25519.PrivateKeySize || r == nil {
		return errors.New("valid ed25519 key and release required")
	}
	digest := releaseSigningDigest(*r)
	r.Signature = hex.EncodeToString(ed25519.Sign(priv, digest))
	return nil
}

// VerifyRelease checks Ed25519 authenticity over a published release entry.
func VerifyRelease(pub ed25519.PublicKey, r SignedRelease) bool {
	if len(pub) != ed25519.PublicKeySize || r.Signature == "" {
		return false
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, releaseSigningDigest(r), sig)
}

func releaseSigningDigest(r SignedRelease) []byte {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s", r.Version, r.Channel, r.URL, r.SHA256)
	sum := h.Sum(nil)
	return sum
}

func newID(prefix string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return prefix + "-" + hex.EncodeToString(b[:])
}
