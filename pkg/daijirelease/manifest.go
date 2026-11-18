// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package daijirelease implements Phase 12 Release Engineering & Operations utilities:
// reproducible SHA256SUMS + Ed25519-signed LTS release manifests, 72-hour accelerated
// ecosystem soak verification, and throughput/PPS/latency operational probes.
package daijirelease

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
