// SPDX-License-Identifier: Apache-2.0
package pkgmgr

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
)

func makeSignedBundle(t *testing.T, keyID string, priv ed25519.PrivateKey, m Manifest, payload []byte) PackageBundle {
	t.Helper()
	if err := SignManifest(&m, payload, keyID, priv); err != nil {
		t.Fatal(err)
	}
	return PackageBundle{Manifest: m, Payload: payload}
}

func TestModularPackageLifecycleAndSecurity(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"daiji-release-2026": pub}

	store, err := OpenStore(filepath.Join(t.TempDir(), "installed.json"), "x86_64", keys)
	if err != nil {
		t.Fatal(err)
	}

	repo := map[string]PackageBundle{
		"daiji-core": makeSignedBundle(t, "daiji-release-2026", priv, Manifest{
			Name:        "daiji-core",
			Version:     "1.0.0",
			Arch:        "x86_64",
			Tier:        TierCore,
			Essential:   true,
			License:     "Apache-2.0",
			Description: "DaijiOS core config/schema runtime",
			Files:       []PackageFile{{Path: "/usr/bin/daiji-ctl", Mode: 0o755}},
		}, []byte("core-binary-bytes")),
		"daiji-routing-frr": makeSignedBundle(t, "daiji-release-2026", priv, Manifest{
			Name:        "daiji-routing-frr",
			Version:     "1.2.0",
			Arch:        "x86_64",
			Tier:        TierRouting,
			License:     "GPL-2.0-or-later",
			Description: "FRRouting BGP/OSPF/IS-IS control plane adapter",
			Depends:     []Dependency{{Name: "daiji-core", Constraint: ">=1.0.0"}},
		}, []byte("frr-bundle")),
		"daiji-isp-pppoe": makeSignedBundle(t, "daiji-release-2026", priv, Manifest{
			Name:        "daiji-isp-pppoe",
			Version:     "1.0.0",
			Arch:        "x86_64",
			Tier:        TierISP,
			License:     "Apache-2.0",
			Depends:     []Dependency{{Name: "daiji-routing-frr", Constraint: ">=1.1.0"}},
		}, []byte("pppoe-bundle")),
	}

	// Installing daiji-isp-pppoe pulls transitive dependencies in order.
	installed, err := store.Install("daiji-isp-pppoe", repo)
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}
	if len(installed) != 3 || installed[0] != "daiji-core@1.0.0" || installed[2] != "daiji-isp-pppoe@1.0.0" {
		t.Fatalf("unexpected topological install order: %v", installed)
	}

	// Essential package removal must be blocked.
	if err := store.Remove("daiji-core"); !errors.Is(err, ErrEssentialPackage) {
		t.Fatalf("expected ErrEssentialPackage, got %v", err)
	}
	// Reverse dependency removal must be blocked while daiji-isp-pppoe depends on it.
	if err := store.Remove("daiji-routing-frr"); !errors.Is(err, ErrReverseDependency) {
		t.Fatalf("expected ErrReverseDependency, got %v", err)
	}
	// Removing leaf first, then routing succeeds.
	if err := store.Remove("daiji-isp-pppoe"); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("daiji-routing-frr"); err != nil {
		t.Fatal(err)
	}
}

func TestTamperedAndCycleAndTraversalRejection(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	store, err := OpenStore(filepath.Join(t.TempDir(), "installed.json"), "arm64", map[string]ed25519.PublicKey{"k1": pub})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Tampered payload rejected.
	tampered := makeSignedBundle(t, "k1", priv, Manifest{
		Name:    "mod-a",
		Version: "1.0.0",
		Arch:    "arm64",
		Tier:    TierSecurity,
		License: "Apache-2.0",
	}, []byte("clean-bytes"))
	tampered.Payload = []byte("evil-bytes")
	if err := store.VerifyBundle(tampered); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch, got %v", err)
	}

	// 2. Tampered manifest signature rejected.
	badSig := makeSignedBundle(t, "k1", priv, Manifest{
		Name:    "mod-b",
		Version: "1.0.0",
		Arch:    "arm64",
		Tier:    TierSecurity,
		License: "Apache-2.0",
	}, []byte("ok"))
	badSig.Manifest.Version = "9.9.9"
	if err := store.VerifyBundle(badSig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}

	// 3. Path traversal rejected.
	traversal := makeSignedBundle(t, "k1", priv, Manifest{
		Name:    "mod-trav",
		Version: "1.0.0",
		Arch:    "arm64",
		Tier:    TierCore,
		License: "Apache-2.0",
		Files:   []PackageFile{{Path: "/etc/../../shadow", Mode: 0o644}},
	}, []byte("x"))
	if err := store.VerifyBundle(traversal); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("expected ErrUnsafePath, got %v", err)
	}

	// 4. Dependency cycle rejected.
	cycleRepo := map[string]PackageBundle{
		"pkg-a": makeSignedBundle(t, "k1", priv, Manifest{
			Name: "pkg-a", Version: "1.0.0", Arch: "arm64", Tier: TierCore, License: "Apache-2.0",
			Depends: []Dependency{{Name: "pkg-b"}},
		}, []byte("a")),
		"pkg-b": makeSignedBundle(t, "k1", priv, Manifest{
			Name: "pkg-b", Version: "1.0.0", Arch: "arm64", Tier: TierCore, License: "Apache-2.0",
			Depends: []Dependency{{Name: "pkg-a"}},
		}, []byte("b")),
	}
	if _, err := store.Install("pkg-a", cycleRepo); !errors.Is(err, ErrDependencyCycle) {
		t.Fatalf("expected ErrDependencyCycle, got %v", err)
	}
}
