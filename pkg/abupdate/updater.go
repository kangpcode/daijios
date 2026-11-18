// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package abupdate implements the DaijiOS A/B atomic firmware update engine:
// Ed25519 signature verification, anti-downgrade security epoch checks,
// streaming SHA-256 verification into inactive slots, bootloader try-boot counter,
// health-gate confirmation, and automatic rollback on failed boot/healthcheck.
package abupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kangpcode/daijios/pkg/fsatomic"
)

var (
	ErrUntrustedKey      = errors.New("untrusted firmware signing key")
	ErrInvalidSignature  = errors.New("firmware Ed25519 signature invalid")
	ErrDowngradeBlocked  = errors.New("firmware security epoch older than minimum allowed")
	ErrPlatformMismatch  = errors.New("firmware arch or board incompatible")
	ErrImageCorrupted    = errors.New("firmware image SHA-256 mismatch")
	ErrNoStagedUpdate    = errors.New("no staged update ready in inactive slot")
	ErrRollbackUnavailable = errors.New("no healthy fallback slot available for rollback")
)

type SlotID string

const (
	SlotA SlotID = "A"
	SlotB SlotID = "B"
)

type SlotState string

const (
	SlotEmpty   SlotState = "empty"
	SlotStaged  SlotState = "staged"
	SlotTryBoot SlotState = "try_boot"
	SlotGood    SlotState = "good"
	SlotFailed  SlotState = "failed"
)

// SlotInfo captures the metadata stored per A/B partition slot.
type SlotInfo struct {
	ID            SlotID    `json:"id"`
	Version       string    `json:"version"`
	ImageSHA256   string    `json:"image_sha256"`
	SecurityEpoch uint64    `json:"security_epoch"`
	State         SlotState `json:"state"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

// BootEnv persists bootloader A/B slot state across reboots (GRUB env / U-Boot env abstraction).
type BootEnv struct {
	ActiveSlot    SlotID              `json:"active_slot"`
	LastGoodSlot  SlotID              `json:"last_good_slot"`
	PendingSlot   SlotID              `json:"pending_slot,omitempty"`
	BootAttempts  int                 `json:"boot_attempts"`
	MaxAttempts   int                 `json:"max_attempts"`
	SecurityEpoch uint64              `json:"security_epoch"`
	Slots         map[SlotID]SlotInfo `json:"slots"`
}

// FirmwareManifest is the signed metadata header for an A/B OS image bundle.
type FirmwareManifest struct {
	Version       string `json:"version"`
	Arch          string `json:"arch"`
	Board         string `json:"board"`
	Channel       string `json:"channel"`
	SecurityEpoch uint64 `json:"security_epoch"`
	ImageSize     int64  `json:"image_size"`
	ImageSHA256   string `json:"image_sha256"`
	KeyID         string `json:"key_id"`
	Signature     string `json:"signature"`
}

type signableFirmwareManifest struct {
	Version       string `json:"version"`
	Arch          string `json:"arch"`
	Board         string `json:"board"`
	Channel       string `json:"channel"`
	SecurityEpoch uint64 `json:"security_epoch"`
	ImageSize     int64  `json:"image_size"`
	ImageSHA256   string `json:"image_sha256"`
	KeyID         string `json:"key_id"`
}

// BootDecision describes which slot the bootloader selects on power-on/reboot.
type BootDecision struct {
	SelectedSlot   SlotID `json:"selected_slot"`
	TryingUpdate   bool   `json:"trying_update"`
	AutoRolledBack bool   `json:"auto_rolled_back"`
	Attempt        int    `json:"attempt"`
	Reason         string `json:"reason"`
}

// EnvBackend abstracts persistent bootloader environment storage (file, GRUB env, U-Boot fw_setenv).
type EnvBackend interface {
	Load() (*BootEnv, error)
	Save(env *BootEnv) error
}

// FileEnvBackend stores BootEnv atomically in a JSON file (used in tests and virtual/container hosts).
type FileEnvBackend struct {
	Path string
}

func (f FileEnvBackend) Load() (*BootEnv, error) {
	raw, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	var env BootEnv
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

func (f FileEnvBackend) Save(env *BootEnv) error {
	return fsatomic.WriteJSONAtomic(f.Path, env)
}

// SlotWriter opens a writable sink for staging a firmware image into the target slot.
type SlotWriter func(slot SlotID) (io.WriteCloser, error)

// SignFirmware computes SHA-256 and signs FirmwareManifest with Ed25519.
func SignFirmware(m *FirmwareManifest, image []byte, keyID string, priv ed25519.PrivateKey) error {
	sum := sha256.Sum256(image)
	m.ImageSHA256 = hex.EncodeToString(sum[:])
	m.ImageSize = int64(len(image))
	m.KeyID = keyID
	raw, err := canonicalFirmwareSignBytes(m)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, raw)
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

func canonicalFirmwareSignBytes(m *FirmwareManifest) ([]byte, error) {
	return json.Marshal(signableFirmwareManifest{
		Version:       m.Version,
		Arch:          m.Arch,
		Board:         m.Board,
		Channel:       m.Channel,
		SecurityEpoch: m.SecurityEpoch,
		ImageSize:     m.ImageSize,
		ImageSHA256:   m.ImageSHA256,
		KeyID:         m.KeyID,
	})
}

// Manager orchestrates A/B system updates and safe rollback.
type Manager struct {
	backend     EnvBackend
	hostArch    string
	hostBoard   string
	trustedKeys map[string]ed25519.PublicKey
	slotWriter  SlotWriter
}

// Options configures the A/B update Manager.
type Options struct {
	Backend        EnvBackend
	HostArch       string
	HostBoard      string
	TrustedKeys    map[string]ed25519.PublicKey
	SlotWriter     SlotWriter
	InitialVersion string
}

// NewManager initializes the A/B update manager and ensures initial BootEnv exists.
func NewManager(opts Options) (*Manager, error) {
	if opts.Backend == nil || opts.HostArch == "" {
		return nil, errors.New("Backend and HostArch are required")
	}
	keys := make(map[string]ed25519.PublicKey, len(opts.TrustedKeys))
	for k, v := range opts.TrustedKeys {
		keys[k] = v
	}
	m := &Manager{
		backend:     opts.Backend,
		hostArch:    opts.HostArch,
		hostBoard:   opts.HostBoard,
		trustedKeys: keys,
		slotWriter:  opts.SlotWriter,
	}
	if _, err := opts.Backend.Load(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		initVer := opts.InitialVersion
		if initVer == "" {
			initVer = "0.1.0-phase0"
		}
		env := &BootEnv{
			ActiveSlot:    SlotA,
			LastGoodSlot:  SlotA,
			MaxAttempts:   3,
			SecurityEpoch: 1,
			Slots: map[SlotID]SlotInfo{
				SlotA: {ID: SlotA, Version: initVer, SecurityEpoch: 1, State: SlotGood, UpdatedAt: time.Now().UTC()},
				SlotB: {ID: SlotB, State: SlotEmpty},
			},
		}
		if err := opts.Backend.Save(env); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// Status returns the current persisted BootEnv.
func (m *Manager) Status() (*BootEnv, error) {
	return m.backend.Load()
}

// InactiveSlot returns the slot that is NOT currently active.
func (env *BootEnv) InactiveSlot() SlotID {
	if env.ActiveSlot == SlotA {
		return SlotB
	}
	return SlotA
}

// VerifyManifest verifies signature, platform compatibility, and anti-downgrade security epoch.
func (m *Manager) VerifyManifest(manifest FirmwareManifest, env *BootEnv) error {
	if manifest.Arch != m.hostArch {
		return fmt.Errorf("%w: manifest arch %q != host %q", ErrPlatformMismatch, manifest.Arch, m.hostArch)
	}
	if m.hostBoard != "" && manifest.Board != "" && manifest.Board != "generic" && manifest.Board != m.hostBoard {
		return fmt.Errorf("%w: manifest board %q != host %q", ErrPlatformMismatch, manifest.Board, m.hostBoard)
	}
	if manifest.SecurityEpoch < env.SecurityEpoch {
		return fmt.Errorf("%w: image epoch %d < device epoch %d",
			ErrDowngradeBlocked, manifest.SecurityEpoch, env.SecurityEpoch)
	}
	pub, ok := m.trustedKeys[manifest.KeyID]
	if !ok {
		return fmt.Errorf("%w: key_id=%q", ErrUntrustedKey, manifest.KeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil {
		return fmt.Errorf("%w: invalid base64", ErrInvalidSignature)
	}
	raw, err := canonicalFirmwareSignBytes(&manifest)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, raw, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// StageUpdate verifies manifest signature, streams image into the inactive slot,
// verifies SHA-256 checksum, and marks the inactive slot as staged.
func (m *Manager) StageUpdate(manifest FirmwareManifest, imageReader io.Reader) (SlotID, error) {
	env, err := m.backend.Load()
	if err != nil {
		return "", err
	}
	if err := m.VerifyManifest(manifest, env); err != nil {
		return "", err
	}

	target := env.InactiveSlot()
	hasher := sha256.New()
	var written int64

	if m.slotWriter != nil {
		w, err := m.slotWriter(target)
		if err != nil {
			return "", fmt.Errorf("open slot %s writer: %w", target, err)
		}
		tee := io.TeeReader(imageReader, hasher)
		written, err = io.Copy(w, tee)
		closeErr := w.Close()
		if err != nil {
			return "", fmt.Errorf("write slot %s: %w", target, err)
		}
		if closeErr != nil {
			return "", fmt.Errorf("close slot %s: %w", target, closeErr)
		}
	} else {
		written, err = io.Copy(hasher, imageReader)
		if err != nil {
			return "", err
		}
	}

	if manifest.ImageSize <= 0 {
		return "", fmt.Errorf("%w: firmware image_size must be positive", ErrImageCorrupted)
	}
	if written != manifest.ImageSize {
		return "", fmt.Errorf("%w: expected %d bytes, got %d", ErrImageCorrupted, manifest.ImageSize, written)
	}
	actualHex := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actualHex, manifest.ImageSHA256) {
		env.Slots[target] = SlotInfo{ID: target, State: SlotFailed, UpdatedAt: time.Now().UTC()}
		_ = m.backend.Save(env)
		return "", fmt.Errorf("%w: expected %s got %s", ErrImageCorrupted, manifest.ImageSHA256, actualHex)
	}

	env.Slots[target] = SlotInfo{
		ID:            target,
		Version:       manifest.Version,
		ImageSHA256:   actualHex,
		SecurityEpoch: manifest.SecurityEpoch,
		State:         SlotStaged,
		UpdatedAt:     time.Now().UTC(),
	}
	if err := m.backend.Save(env); err != nil {
		return "", err
	}
	return target, nil
}

// ActivateStaged schedules the staged inactive slot for trial boot on next reboot.
func (m *Manager) ActivateStaged() (SlotID, error) {
	env, err := m.backend.Load()
	if err != nil {
		return "", err
	}
	target := env.InactiveSlot()
	info, ok := env.Slots[target]
	if !ok || info.State != SlotStaged {
		return "", ErrNoStagedUpdate
	}
	info.State = SlotTryBoot
	env.Slots[target] = info
	env.PendingSlot = target
	env.BootAttempts = 0
	if env.MaxAttempts <= 0 {
		env.MaxAttempts = 3
	}
	if err := m.backend.Save(env); err != nil {
		return "", err
	}
	return target, nil
}

// NextBoot executes bootloader slot-selection logic, enforcing automatic fallback
// if PendingSlot failed MaxAttempts consecutive boot attempts.
func (m *Manager) NextBoot() (BootDecision, error) {
	env, err := m.backend.Load()
	if err != nil {
		return BootDecision{}, err
	}
	if env.PendingSlot == "" {
		return BootDecision{
			SelectedSlot: env.ActiveSlot,
			Reason:       "normal boot from verified slot",
		}, nil
	}

	pending := env.PendingSlot
	if env.BootAttempts >= env.MaxAttempts {
		info := env.Slots[pending]
		info.State = SlotFailed
		env.Slots[pending] = info
		env.PendingSlot = ""
		env.BootAttempts = 0
		env.ActiveSlot = env.LastGoodSlot
		if err := m.backend.Save(env); err != nil {
			return BootDecision{}, err
		}
		return BootDecision{
			SelectedSlot:   env.LastGoodSlot,
			AutoRolledBack: true,
			Reason:         fmt.Sprintf("slot %s exceeded max boot attempts (%d); reverted to %s", pending, env.MaxAttempts, env.LastGoodSlot),
		}, nil
	}

	env.BootAttempts++
	env.ActiveSlot = pending
	if err := m.backend.Save(env); err != nil {
		return BootDecision{}, err
	}
	return BootDecision{
		SelectedSlot: pending,
		TryingUpdate: true,
		Attempt:      env.BootAttempts,
		Reason:       fmt.Sprintf("trial boot slot %s (attempt %d/%d)", pending, env.BootAttempts, env.MaxAttempts),
	}, nil
}

// ConfirmBootHealth runs post-boot subsystem checks. If healthy, commits the trial slot as good;
// if unhealthy, marks the trial slot failed and switches ActiveSlot back to LastGoodSlot.
func (m *Manager) ConfirmBootHealth(ctx context.Context, healthCheck func(context.Context) error) error {
	env, err := m.backend.Load()
	if err != nil {
		return err
	}
	if healthCheck != nil {
		if hcErr := healthCheck(ctx); hcErr != nil {
			if env.PendingSlot != "" {
				bad := env.Slots[env.PendingSlot]
				bad.State = SlotFailed
				env.Slots[env.PendingSlot] = bad
				env.PendingSlot = ""
				env.BootAttempts = 0
				env.ActiveSlot = env.LastGoodSlot
				_ = m.backend.Save(env)
			}
			return fmt.Errorf("boot health check failed (reverted active slot to %s): %w", env.LastGoodSlot, hcErr)
		}
	}

	activeInfo := env.Slots[env.ActiveSlot]
	activeInfo.State = SlotGood
	activeInfo.UpdatedAt = time.Now().UTC()
	env.Slots[env.ActiveSlot] = activeInfo
	if activeInfo.SecurityEpoch > env.SecurityEpoch {
		env.SecurityEpoch = activeInfo.SecurityEpoch
	}
	env.LastGoodSlot = env.ActiveSlot
	env.PendingSlot = ""
	env.BootAttempts = 0
	return m.backend.Save(env)
}

// ManualRollback switches boot target back to the standby good slot (or LastGoodSlot if pending).
func (m *Manager) ManualRollback() (SlotID, error) {
	env, err := m.backend.Load()
	if err != nil {
		return "", err
	}
	var target SlotID
	if env.PendingSlot != "" && env.LastGoodSlot != "" && env.Slots[env.LastGoodSlot].State == SlotGood {
		bad := env.Slots[env.PendingSlot]
		bad.State = SlotFailed
		env.Slots[env.PendingSlot] = bad
		target = env.LastGoodSlot
	} else {
		other := env.InactiveSlot()
		if info, ok := env.Slots[other]; ok && info.State == SlotGood {
			target = other
		}
	}
	if target == "" {
		return "", ErrRollbackUnavailable
	}
	env.PendingSlot = ""
	env.BootAttempts = 0
	env.ActiveSlot = target
	env.LastGoodSlot = target
	if err := m.backend.Save(env); err != nil {
		return "", err
	}
	return target, nil
}
