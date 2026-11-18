// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package pkgmgr implements the DaijiOS modular package system (.dpk):
// Ed25519 signed package manifests, SHA-256 integrity checks, path-traversal guards,
// semver dependency resolution with cycle detection, conflict checks, and safe removal.
package pkgmgr

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kangpcode/daijios/pkg/fsatomic"
)

var (
	ErrUntrustedKey      = errors.New("unknown or untrusted package signing key")
	ErrInvalidSignature  = errors.New("package Ed25519 signature verification failed")
	ErrChecksumMismatch  = errors.New("package SHA-256 checksum mismatch")
	ErrArchMismatch      = errors.New("package architecture incompatible with target host")
	ErrDependencyMissing = errors.New("required package dependency not found")
	ErrDependencyCycle   = errors.New("dependency cycle detected")
	ErrPackageConflict   = errors.New("package conflict detected")
	ErrEssentialPackage  = errors.New("cannot remove essential core package")
	ErrReverseDependency = errors.New("package is required by other installed packages")
	ErrUnsafePath        = errors.New("unsafe file path in package manifest")
)

// Tier classifies modular OS capabilities.
type Tier string

const (
	TierCore       Tier = "core"
	TierRouting    Tier = "routing"
	TierSecurity   Tier = "security"
	TierISP        Tier = "isp"
	TierWireless   Tier = "wireless"
	TierManagement Tier = "management"
)

// Dependency declares a package dependency with an optional semver constraint (>=1.2.0, =1.0.0, etc.).
type Dependency struct {
	Name       string `json:"name"`
	Constraint string `json:"constraint,omitempty"`
}

// PackageFile declares one file included inside a .dpk payload.
type PackageFile struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

// Manifest is the signed descriptor for a modular DaijiOS .dpk package.
type Manifest struct {
	Name          string        `json:"name"`
	Version       string        `json:"version"`
	Arch          string        `json:"arch"`
	Tier          Tier          `json:"tier"`
	Essential     bool          `json:"essential"`
	Description   string        `json:"description"`
	License       string        `json:"license"`
	Depends       []Dependency  `json:"depends,omitempty"`
	Conflicts     []string      `json:"conflicts,omitempty"`
	Provides      []string      `json:"provides,omitempty"`
	Files         []PackageFile `json:"files,omitempty"`
	PayloadSHA256 string        `json:"payload_sha256"`
	KeyID         string        `json:"key_id"`
	Signature     string        `json:"signature"`
}

type signableManifest struct {
	Name          string        `json:"name"`
	Version       string        `json:"version"`
	Arch          string        `json:"arch"`
	Tier          Tier          `json:"tier"`
	Essential     bool          `json:"essential"`
	Description   string        `json:"description"`
	License       string        `json:"license"`
	Depends       []Dependency  `json:"depends,omitempty"`
	Conflicts     []string      `json:"conflicts,omitempty"`
	Provides      []string      `json:"provides,omitempty"`
	Files         []PackageFile `json:"files,omitempty"`
	PayloadSHA256 string        `json:"payload_sha256"`
	KeyID         string        `json:"key_id"`
}

// PackageBundle pairs a signed Manifest with its raw archive bytes.
type PackageBundle struct {
	Manifest Manifest
	Payload  []byte
}

// InstalledPackage tracks an installed module in the local package database.
type InstalledPackage struct {
	Manifest    Manifest  `json:"manifest"`
	InstalledAt time.Time `json:"installed_at"`
}

// Store manages the installed DaijiOS package database and trusted Ed25519 keyring.
type Store struct {
	dbPath      string
	hostArch    string
	trustedKeys map[string]ed25519.PublicKey
	installed   map[string]InstalledPackage
}

// SignManifest computes the payload SHA-256 and signs the manifest using Ed25519.
func SignManifest(m *Manifest, payload []byte, keyID string, priv ed25519.PrivateKey) error {
	if m == nil {
		return errors.New("manifest is nil")
	}
	sum := sha256.Sum256(payload)
	m.PayloadSHA256 = hex.EncodeToString(sum[:])
	m.KeyID = keyID
	raw, err := canonicalSignBytes(m)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, raw)
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

func canonicalSignBytes(m *Manifest) ([]byte, error) {
	s := signableManifest{
		Name:          m.Name,
		Version:       m.Version,
		Arch:          m.Arch,
		Tier:          m.Tier,
		Essential:     m.Essential,
		Description:   m.Description,
		License:       m.License,
		Depends:       m.Depends,
		Conflicts:     m.Conflicts,
		Provides:      m.Provides,
		Files:         m.Files,
		PayloadSHA256: m.PayloadSHA256,
		KeyID:         m.KeyID,
	}
	return json.Marshal(s)
}

// OpenStore initializes or loads the package store at dbPath.
func OpenStore(dbPath, hostArch string, trustedKeys map[string]ed25519.PublicKey) (*Store, error) {
	if dbPath == "" || hostArch == "" {
		return nil, errors.New("dbPath and hostArch are required")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, err
	}
	keysCopy := make(map[string]ed25519.PublicKey, len(trustedKeys))
	for k, v := range trustedKeys {
		keysCopy[k] = v
	}
	s := &Store{
		dbPath:      dbPath,
		hostArch:    hostArch,
		trustedKeys: keysCopy,
		installed:   make(map[string]InstalledPackage),
	}
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	var list []InstalledPackage
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("parse package db: %w", err)
	}
	for _, pkg := range list {
		s.installed[pkg.Manifest.Name] = pkg
	}
	return s, nil
}

// VerifyBundle checks Ed25519 signature, payload SHA-256, arch, semver, and file path safety.
func (s *Store) VerifyBundle(b PackageBundle) error {
	m := b.Manifest
	if m.Name == "" || m.Version == "" {
		return errors.New("manifest missing name or version")
	}
	if _, err := parseSemVer(m.Version); err != nil {
		return fmt.Errorf("invalid manifest semver %q: %w", m.Version, err)
	}
	if m.Arch != "all" && m.Arch != "noarch" && m.Arch != s.hostArch {
		return fmt.Errorf("%w: package=%s host=%s", ErrArchMismatch, m.Arch, s.hostArch)
	}
	pub, ok := s.trustedKeys[m.KeyID]
	if !ok {
		return fmt.Errorf("%w: key_id=%q", ErrUntrustedKey, m.KeyID)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("%w: malformed base64", ErrInvalidSignature)
	}
	raw, err := canonicalSignBytes(&m)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, raw, sigBytes) {
		return ErrInvalidSignature
	}
	sum := sha256.Sum256(b.Payload)
	actualHex := hex.EncodeToString(sum[:])
	if !strings.EqualFold(actualHex, m.PayloadSHA256) {
		return fmt.Errorf("%w: expected %s got %s", ErrChecksumMismatch, m.PayloadSHA256, actualHex)
	}
	for _, f := range m.Files {
		if err := validatePackageFilePath(f.Path); err != nil {
			return err
		}
	}
	return nil
}

// Install verifies and installs targetName (plus dependencies from repo) in topological order.
func (s *Store) Install(targetName string, repo map[string]PackageBundle) ([]string, error) {
	order, err := s.ResolveInstallOrder(targetName, repo)
	if err != nil {
		return nil, err
	}
	var newlyInstalled []string
	for _, name := range order {
		if inst, exists := s.installed[name]; exists {
			cand, inRepo := repo[name]
			if !inRepo || inst.Manifest.Version == cand.Manifest.Version {
				continue
			}
		}
		bundle, ok := repo[name]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrDependencyMissing, name)
		}
		if err := s.VerifyBundle(bundle); err != nil {
			return nil, fmt.Errorf("verify %s: %w", name, err)
		}
		s.installed[name] = InstalledPackage{
			Manifest:    bundle.Manifest,
			InstalledAt: time.Now().UTC(),
		}
		newlyInstalled = append(newlyInstalled, fmt.Sprintf("%s@%s", bundle.Manifest.Name, bundle.Manifest.Version))
	}
	if err := s.persist(); err != nil {
		return nil, err
	}
	return newlyInstalled, nil
}

// ResolveInstallOrder computes a dependency-first topological installation plan and checks conflicts/cycles.
func (s *Store) ResolveInstallOrder(targetName string, repo map[string]PackageBundle) ([]string, error) {
	const (
		unvisited = 0
		visiting  = 1
		visited   = 2
	)
	state := make(map[string]int)
	var order []string

	lookup := func(name string) (Manifest, bool) {
		if b, ok := repo[name]; ok {
			return b.Manifest, true
		}
		if inst, ok := s.installed[name]; ok {
			return inst.Manifest, true
		}
		return Manifest{}, false
	}

	var dfs func(name string) error
	dfs = func(name string) error {
		switch state[name] {
		case visiting:
			return fmt.Errorf("%w: involving %s", ErrDependencyCycle, name)
		case visited:
			return nil
		}
		state[name] = visiting

		m, ok := lookup(name)
		if !ok {
			return fmt.Errorf("%w: %s", ErrDependencyMissing, name)
		}
		if m.Arch != "all" && m.Arch != "noarch" && m.Arch != s.hostArch {
			return fmt.Errorf("%w: %s (%s != %s)", ErrArchMismatch, m.Name, m.Arch, s.hostArch)
		}
		// Check conflicts against already installed packages and packages planned so far.
		for _, conflict := range m.Conflicts {
			if _, hit := s.installed[conflict]; hit {
				return fmt.Errorf("%w: %s conflicts with installed %s", ErrPackageConflict, m.Name, conflict)
			}
			for _, planned := range order {
				if planned == conflict {
					return fmt.Errorf("%w: %s conflicts with %s", ErrPackageConflict, m.Name, conflict)
				}
			}
		}
		for _, inst := range s.installed {
			for _, c := range inst.Manifest.Conflicts {
				if c == m.Name {
					return fmt.Errorf("%w: installed %s conflicts with %s", ErrPackageConflict, inst.Manifest.Name, m.Name)
				}
			}
		}

		for _, dep := range m.Depends {
			depManifest, found := lookup(dep.Name)
			if !found {
				return fmt.Errorf("%w: %s requires %s", ErrDependencyMissing, m.Name, dep.Name)
			}
			if dep.Constraint != "" {
				ok, err := satisfiesConstraint(depManifest.Version, dep.Constraint)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("%w: %s requires %s %s (got %s)",
						ErrDependencyMissing, m.Name, dep.Name, dep.Constraint, depManifest.Version)
				}
			}
			if err := dfs(dep.Name); err != nil {
				return err
			}
		}

		state[name] = visited
		order = append(order, name)
		return nil
	}

	if err := dfs(targetName); err != nil {
		return nil, err
	}
	return order, nil
}

// Remove uninstalls a package after checking essential protection and reverse dependencies.
func (s *Store) Remove(name string) error {
	pkg, ok := s.installed[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrDependencyMissing, name)
	}
	if pkg.Manifest.Essential {
		return fmt.Errorf("%w: %s", ErrEssentialPackage, name)
	}
	var rdeps []string
	for otherName, other := range s.installed {
		if otherName == name {
			continue
		}
		for _, dep := range other.Manifest.Depends {
			if dep.Name == name {
				rdeps = append(rdeps, otherName)
			}
		}
	}
	sort.Strings(rdeps)
	if len(rdeps) > 0 {
		return fmt.Errorf("%w: %s is needed by [%s]", ErrReverseDependency, name, strings.Join(rdeps, ", "))
	}
	delete(s.installed, name)
	return s.persist()
}

// List returns all installed packages sorted by name.
func (s *Store) List() []InstalledPackage {
	out := make([]InstalledPackage, 0, len(s.installed))
	for _, pkg := range s.installed {
		out = append(out, pkg)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Manifest.Name < out[j].Manifest.Name
	})
	return out
}

func (s *Store) persist() error {
	return fsatomic.WriteJSONAtomic(s.dbPath, s.List())
}

func validatePackageFilePath(p string) error {
	if p == "" {
		return fmt.Errorf("%w: empty path", ErrUnsafePath)
	}
	if strings.Contains(p, "\x00") {
		return fmt.Errorf("%w: null byte in path %q", ErrUnsafePath, p)
	}
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return fmt.Errorf("%w: traversal segment '..' in %q", ErrUnsafePath, p)
		}
	}
	cleaned := filepath.ToSlash(filepath.Clean(p))
	if !strings.HasPrefix(cleaned, "/") {
		return fmt.Errorf("%w: package file path must be absolute rootfs path, got %q", ErrUnsafePath, p)
	}
	return nil
}

type semVer struct {
	major int
	minor int
	patch int
}

func parseSemVer(v string) (semVer, error) {
	core := strings.SplitN(strings.SplitN(v, "+", 2)[0], "-", 2)[0]
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semVer{}, fmt.Errorf("expected MAJOR.MINOR.PATCH, got %q", v)
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	pat, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || maj < 0 || min < 0 || pat < 0 {
		return semVer{}, fmt.Errorf("non-numeric semver %q", v)
	}
	return semVer{major: maj, minor: min, patch: pat}, nil
}

func compareSemVer(a, b semVer) int {
	if a.major != b.major {
		if a.major < b.major {
			return -1
		}
		return 1
	}
	if a.minor != b.minor {
		if a.minor < b.minor {
			return -1
		}
		return 1
	}
	if a.patch != b.patch {
		if a.patch < b.patch {
			return -1
		}
		return 1
	}
	return 0
}

func satisfiesConstraint(actual, constraint string) (bool, error) {
	actV, err := parseSemVer(actual)
	if err != nil {
		return false, err
	}
	op := "="
	verStr := strings.TrimSpace(constraint)
	for _, candOp := range []string{">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(verStr, candOp) {
			op = candOp
			verStr = strings.TrimSpace(strings.TrimPrefix(verStr, candOp))
			break
		}
	}
	reqV, err := parseSemVer(verStr)
	if err != nil {
		return false, err
	}
	cmp := compareSemVer(actV, reqV)
	switch op {
	case ">=":
		return cmp >= 0, nil
	case "<=":
		return cmp <= 0, nil
	case ">":
		return cmp > 0, nil
	case "<":
		return cmp < 0, nil
	default:
		return cmp == 0, nil
	}
}
