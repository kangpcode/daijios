// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package daijirelease implements Phase 12 Release Engineering & Operations utilities:
// reproducible SHA256SUMS + Ed25519-signed LTS release manifests, 72-hour accelerated
// ecosystem soak verification, and throughput/PPS/latency operational probes.
package daijirelease

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/kangpcode/daijios/pkg/sysinfo"
)

var (
	ErrManifestSignature = errors.New("release manifest Ed25519 verification failed")
	ErrChecksumMismatch  = errors.New("artifact SHA-256 checksum mismatch")
)

// ArtifactDigest stores SHA-256 integrity metadata for one compiled DaijiOS binary.
type ArtifactDigest struct {
	Name   string `json:"name"`
	Arch   string `json:"arch"`
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
}

// LTSSupportPolicy declares the support lifecycle of an LTS release stream.
type LTSSupportPolicy struct {
	Channel            string `json:"channel"`
	ActiveUntil        string `json:"active_until"`
	SecurityUntil      string `json:"security_until"`
	DisclosureWindow   string `json:"disclosure_window"`
	BugBountyAvailable bool   `json:"bug_bounty_available"`
}

// ReleaseManifest describes one signed, reproducible DaijiOS ecosystem release bundle.
type ReleaseManifest struct {
	Brand       string           `json:"brand"`
	Version     string           `json:"version"`
	GeneratedAt string           `json:"generated_at"`
	GoVersion   string           `json:"go_version"`
	LTS         LTSSupportPolicy `json:"lts_policy"`
	Artifacts   []ArtifactDigest `json:"artifacts"`
	PublicKey   string           `json:"ed25519_pub_hex,omitempty"`
	Signature   string           `json:"ed25519_sig_hex,omitempty"`
}

// BuildManifest scans artifactDir (e.g. bin/dist) and hashes every non-manifest regular binary deterministically.
func BuildManifest(artifactDir, version, goVer string, now time.Time) (*ReleaseManifest, error) {
	entries, err := os.ReadDir(artifactDir)
	if err != nil {
		return nil, fmt.Errorf("read artifact dir %s: %w", artifactDir, err)
	}
	if version == "" {
		version = sysinfo.Version
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var arts []ArtifactDigest
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if name == "SHA256SUMS" || strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".sig") {
			continue
		}
		full := filepath.Join(artifactDir, name)
		sum, sz, err := sha256File(full)
		if err != nil {
			return nil, err
		}
		arts = append(arts, ArtifactDigest{
			Name:   name,
			Arch:   detectArchSuffix(name),
			Size:   sz,
			SHA256: sum,
		})
	}
	sort.Slice(arts, func(i, j int) bool { return arts[i].Name < arts[j].Name })

	return &ReleaseManifest{
		Brand:       sysinfo.BrandBanner,
		Version:     version,
		GeneratedAt: now.UTC().Format(time.RFC3339),
		GoVersion:   goVer,
		LTS: LTSSupportPolicy{
			Channel:            "lts",
			ActiveUntil:        now.UTC().AddDate(3, 0, 0).Format("2006-01-02"),
			SecurityUntil:      now.UTC().AddDate(4, 0, 0).Format("2006-01-02"),
			DisclosureWindow:   "90 days coordinated disclosure",
			BugBountyAvailable: true,
		},
		Artifacts: arts,
	}, nil
}

// SignManifest computes the canonical digest over manifest metadata and signs it with Ed25519.
func SignManifest(priv ed25519.PrivateKey, m *ReleaseManifest) error {
	if len(priv) != ed25519.PrivateKeySize || m == nil {
		return errors.New("valid ed25519 private key and manifest required")
	}
	pub := priv.Public().(ed25519.PublicKey)
	m.PublicKey = hex.EncodeToString(pub)
	digest := manifestDigest(*m)
	m.Signature = hex.EncodeToString(ed25519.Sign(priv, digest))
	return nil
}

// VerifyManifest validates the Ed25519 signature embedded in ReleaseManifest.
func VerifyManifest(pub ed25519.PublicKey, m ReleaseManifest) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrManifestSignature
	}
	sig, err := hex.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrManifestSignature
	}
	if !ed25519.Verify(pub, manifestDigest(m), sig) {
		return ErrManifestSignature
	}
	return nil
}

// WriteSHA256SUMS formats canonical GNU coreutils-compatible checksum lines (`<sha256>  <name>`).
func WriteSHA256SUMS(path string, arts []ArtifactDigest) error {
	sorted := slices.Clone(arts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	for _, a := range sorted {
		fmt.Fprintf(&b, "%s  %s\n", a.SHA256, a.Name)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// VerifySHA256SUMS verifies every file listed in SHA256SUMS against files inside artifactDir.
func VerifySHA256SUMS(artifactDir, sumsPath string) (int, error) {
	raw, err := os.ReadFile(sumsPath)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return count, fmt.Errorf("%w: malformed line %q", ErrChecksumMismatch, line)
		}
		expected, name := fields[0], filepath.Base(fields[1])
		actual, _, err := sha256File(filepath.Join(artifactDir, name))
		if err != nil {
			return count, err
		}
		if !strings.EqualFold(expected, actual) {
			return count, fmt.Errorf("%w: %s expected=%s actual=%s", ErrChecksumMismatch, name, expected, actual)
		}
		count++
	}
	return count, nil
}

// SaveManifestJSON writes indented release manifest JSON to disk.
func SaveManifestJSON(path string, m *ReleaseManifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func sha256File(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func detectArchSuffix(name string) string {
	for _, a := range []string{"amd64", "arm64", "armv7", "mips64le", "mipsel"} {
		if strings.HasSuffix(name, "-"+a) {
			return a
		}
	}
	return "unknown"
}

func manifestDigest(m ReleaseManifest) []byte {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|", m.Brand, m.Version, m.GeneratedAt, m.GoVersion)
	for _, a := range m.Artifacts {
		fmt.Fprintf(h, "%s:%d:%s;", a.Name, a.Size, a.SHA256)
	}
	return h.Sum(nil)
}

// GenerateSigningKeypairPEM creates a persistent Ed25519 release signing keypair on disk
// using PKCS#8 PEM (`0600`) for private key and PKIX SPKI PEM (`0644`) for public key.
func GenerateSigningKeypairPEM(privPath, pubPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		return nil, nil, err
	}
	if pubPath != "" {
		spki, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, nil, err
		}
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
		if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
			return nil, nil, err
		}
	}
	return pub, priv, nil
}

// LoadPrivateKeyPEM reads an Ed25519 private key from PKCS#8 PEM or hex-encoded seed/key file.
func LoadPrivateKeyPEM(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if blk, _ := pem.Decode(raw); blk != nil {
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pkcs8 key %s: %w", path, err)
		}
		priv, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key %s is not Ed25519", path)
		}
		return priv, nil
	}
	hexBytes, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("invalid private key format in %s", path)
	}
	switch len(hexBytes) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(hexBytes), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(hexBytes), nil
	default:
		return nil, fmt.Errorf("unexpected Ed25519 key size %d in %s", len(hexBytes), path)
	}
}

// LoadPublicKeyPEM reads a pinned Ed25519 public key from PKIX PEM or hex-encoded file.
func LoadPublicKeyPEM(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if blk, _ := pem.Decode(raw); blk != nil {
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pkix public key %s: %w", path, err)
		}
		pub, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key %s is not Ed25519", path)
		}
		return pub, nil
	}
	hexBytes, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(hexBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key in %s", path)
	}
	return ed25519.PublicKey(hexBytes), nil
}
