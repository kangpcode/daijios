// SPDX-License-Identifier: Apache-2.0
package abupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestABUpdateHappyPathAndManualRollback(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	slotFiles := map[SlotID][]byte{}

	mgr, err := NewManager(Options{
		Backend:        FileEnvBackend{Path: filepath.Join(dir, "bootenv.json")},
		HostArch:       "x86_64",
		HostBoard:      "daiji-chr",
		InitialVersion: "1.0.0",
		TrustedKeys:    map[string]ed25519.PublicKey{"release-1": pub},
		SlotWriter: func(slot SlotID) (io.WriteCloser, error) {
			p := filepath.Join(dir, "slot-"+string(slot)+".img")
			return os.Create(p)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = slotFiles

	img := []byte("squashfs-daijios-v1.1.0-kernel-rootfs")
	manifest := FirmwareManifest{
		Version:       "1.1.0",
		Arch:          "x86_64",
		Board:         "daiji-chr",
		Channel:       "stable",
		SecurityEpoch: 2,
	}
	if err := SignFirmware(&manifest, img, "release-1", priv); err != nil {
		t.Fatal(err)
	}

	target, err := mgr.StageUpdate(manifest, bytes.NewReader(img))
	if err != nil {
		t.Fatalf("StageUpdate failed: %v", err)
	}
	if target != SlotB {
		t.Fatalf("expected staging into inactive SlotB, got %s", target)
	}

	if _, err := mgr.ActivateStaged(); err != nil {
		t.Fatal(err)
	}

	dec, err := mgr.NextBoot()
	if err != nil {
		t.Fatal(err)
	}
	if dec.SelectedSlot != SlotB || !dec.TryingUpdate || dec.Attempt != 1 {
		t.Fatalf("unexpected boot decision: %+v", dec)
	}

	if err := mgr.ConfirmBootHealth(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	env, _ := mgr.Status()
	if env.ActiveSlot != SlotB || env.Slots[SlotB].State != SlotGood || env.SecurityEpoch != 2 {
		t.Fatalf("unexpected confirmed BootEnv: %+v", env)
	}

	// Manual rollback back to SlotA (which is still SlotGood).
	rbSlot, err := mgr.ManualRollback()
	if err != nil {
		t.Fatalf("ManualRollback failed: %v", err)
	}
	if rbSlot != SlotA {
		t.Fatalf("expected rollback to SlotA, got %s", rbSlot)
	}
}

func TestABAutoRollbackOnBootFailuresAndHealthCheckFailure(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	mgr, err := NewManager(Options{
		Backend:        FileEnvBackend{Path: filepath.Join(dir, "bootenv.json")},
		HostArch:       "mipsel",
		HostBoard:      "mt7621",
		InitialVersion: "1.0.0",
		TrustedKeys:    map[string]ed25519.PublicKey{"k1": pub},
	})
	if err != nil {
		t.Fatal(err)
	}

	img := []byte("bad-kernel-hangs-on-boot")
	m := FirmwareManifest{
		Version:       "1.2.0",
		Arch:          "mipsel",
		Board:         "mt7621",
		Channel:       "stable",
		SecurityEpoch: 2,
	}
	_ = SignFirmware(&m, img, "k1", priv)

	if _, err := mgr.StageUpdate(m, bytes.NewReader(img)); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.ActivateStaged(); err != nil {
		t.Fatal(err)
	}

	// Simulate 3 failed reboots (attempt 1..3), then 4th NextBoot triggers bootloader auto-rollback.
	for i := 1; i <= 3; i++ {
		d, err := mgr.NextBoot()
		if err != nil {
			t.Fatal(err)
		}
		if d.SelectedSlot != SlotB || d.AutoRolledBack {
			t.Fatalf("attempt %d unexpected decision: %+v", i, d)
		}
	}
	fallback, err := mgr.NextBoot()
	if err != nil {
		t.Fatal(err)
	}
	if !fallback.AutoRolledBack || fallback.SelectedSlot != SlotA {
		t.Fatalf("expected automatic rollback to SlotA after 3 failures, got: %+v", fallback)
	}

	// Test healthcheck failure rollback on a new staged update.
	img2 := []byte("boots-but-configd-crashes")
	m2 := FirmwareManifest{
		Version:       "1.3.0",
		Arch:          "mipsel",
		Board:         "mt7621",
		Channel:       "stable",
		SecurityEpoch: 2,
	}
	_ = SignFirmware(&m2, img2, "k1", priv)
	_, _ = mgr.StageUpdate(m2, bytes.NewReader(img2))
	_, _ = mgr.ActivateStaged()
	_, _ = mgr.NextBoot()

	hcErr := mgr.ConfirmBootHealth(context.Background(), func(context.Context) error {
		return errors.New("daiji-configd healthcheck timeout")
	})
	if hcErr == nil {
		t.Fatal("expected health check failure")
	}
	env, _ := mgr.Status()
	if env.ActiveSlot != SlotA || env.Slots[SlotB].State != SlotFailed {
		t.Fatalf("expected rollback to SlotA and SlotB marked failed, got: %+v", env)
	}
}

func TestABRejectsDowngradeAndTamperedImage(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	mgr, _ := NewManager(Options{
		Backend:     FileEnvBackend{Path: filepath.Join(dir, "bootenv.json")},
		HostArch:    "arm64",
		TrustedKeys: map[string]ed25519.PublicKey{"k1": pub},
	})

	// Bump device security epoch to 5 via confirmed update.
	good := []byte("v2")
	mg := FirmwareManifest{Version: "2.0.0", Arch: "arm64", SecurityEpoch: 5}
	_ = SignFirmware(&mg, good, "k1", priv)
	_, _ = mgr.StageUpdate(mg, bytes.NewReader(good))
	_, _ = mgr.ActivateStaged()
	_, _ = mgr.NextBoot()
	_ = mgr.ConfirmBootHealth(context.Background(), nil)

	// Attempt downgrade to epoch 3 must be blocked.
	old := []byte("v1-vuln")
	mo := FirmwareManifest{Version: "1.5.0", Arch: "arm64", SecurityEpoch: 3}
	_ = SignFirmware(&mo, old, "k1", priv)
	if _, err := mgr.StageUpdate(mo, bytes.NewReader(old)); !errors.Is(err, ErrDowngradeBlocked) {
		t.Fatalf("expected ErrDowngradeBlocked, got %v", err)
	}

	// Corrupted payload must fail SHA-256 check.
	m6 := FirmwareManifest{Version: "2.1.0", Arch: "arm64", SecurityEpoch: 6}
	_ = SignFirmware(&m6, []byte("expected-firmware"), "k1", priv)
	if _, err := mgr.StageUpdate(m6, bytes.NewReader([]byte("corrupted-payload"))); !errors.Is(err, ErrImageCorrupted) {
		t.Fatalf("expected ErrImageCorrupted, got %v", err)
	}
}
