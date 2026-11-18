// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package configengine implements the DaijiOS transactional configuration store:
// candidate/running/startup datastores, schema validation, structural diff,
// atomic commit, deadman commit-confirm with crash recovery, revision rollback,
// safe-mode boot fallback, backward-compatible migration, and hash-chained audit logs.
package configengine

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kangpcode/daijios/pkg/fsatomic"
	"github.com/kangpcode/daijios/pkg/schema"
)

var (
	ErrLockedByOther      = errors.New("candidate configuration is locked by another actor")
	ErrConfirmPending     = errors.New("a commit-confirm is already pending confirmation or rollback")
	ErrNoPendingConfirm   = errors.New("no commit-confirm is currently pending")
	ErrRevisionNotFound   = errors.New("configuration revision not found")
	ErrRevisionCorrupted  = errors.New("configuration revision checksum verification failed")
	ErrAuditChainTampered = errors.New("audit log hash chain verification failed")
)

// SemanticValidator allows Phase 1+ subsystems to inject cross-field invariants
// (e.g. overlapping interface subnets or duplicate bridge ports) beyond JSON Schema.
type SemanticValidator func(cfg map[string]any) error

// Options configures the DaijiOS configuration engine.
type Options struct {
	BaseDir           string
	Schema            *schema.CompiledSchema
	Applier           Applier
	Migrator          *Migrator
	SemanticValidator SemanticValidator
	BootstrapConfig   map[string]any
	SafeModeConfig    map[string]any
	ColdBoot          bool
	MaxFailedBoots    int
	Now               func() time.Time
}

// CommitOptions controls commit behavior.
type CommitOptions struct {
	SaveStartup bool
	AllowEmpty  bool
}

// RevisionRecord is an immutable historical configuration snapshot.
type RevisionRecord struct {
	ID            string         `json:"id"`
	Seq           int            `json:"seq"`
	Timestamp     time.Time      `json:"timestamp"`
	Actor         string         `json:"actor"`
	Message       string         `json:"message"`
	ParentID      string         `json:"parent_id,omitempty"`
	SchemaVersion string         `json:"schema_version"`
	ConfigSHA256  string         `json:"config_sha256"`
	Config        map[string]any `json:"config"`
}

// PendingConfirm captures persistent commit-confirm deadman timer state.
type PendingConfirm struct {
	Token              string `json:"token"`
	Actor              string `json:"actor"`
	Message            string `json:"message"`
	TargetRevisionID   string `json:"target_revision_id"`
	RollbackRevisionID string `json:"rollback_revision_id"`
	DeadlineUnixNano   int64  `json:"deadline_unix_nano"`
}

// EditLock represents an exclusive advisory/enforced lock on candidate edits.
type EditLock struct {
	Actor     string    `json:"actor"`
	ExpiresAt time.Time `json:"expires_at"`
}

// BootState tracks consecutive unsuccessful boots for safe-mode fallback.
type BootState struct {
	FailedBoots int  `json:"failed_boots"`
	SafeMode    bool `json:"safe_mode"`
}

// AuditEntry is an immutable, hash-chained audit trail record.
type AuditEntry struct {
	Seq       int64       `json:"seq"`
	Timestamp string      `json:"timestamp"`
	Actor     string      `json:"actor"`
	Action    string      `json:"action"`
	Revision  string      `json:"revision,omitempty"`
	Details   string      `json:"details,omitempty"`
	Diffs     []DiffEntry `json:"diffs,omitempty"`
	PrevHash  string      `json:"prev_hash"`
	EntryHash string      `json:"entry_hash"`
}

// CommitResult summarizes the outcome of Commit, CommitConfirm, or Rollback.
type CommitResult struct {
	Changed        bool           `json:"changed"`
	Revision       RevisionRecord `json:"revision"`
	Diffs          []DiffEntry    `json:"diffs"`
	ConfirmPending bool           `json:"confirm_pending"`
	ConfirmDeadline time.Time     `json:"confirm_deadline,omitempty"`
	SavedStartup   bool           `json:"saved_startup"`
}

// Engine manages candidate, running, startup, revisions, commit-confirm, and audit logs.
type Engine struct {
	mu                sync.Mutex
	baseDir           string
	schema            *schema.CompiledSchema
	applier           Applier
	migrator          *Migrator
	semanticValidator SemanticValidator
	maxFailedBoots    int
	nowFn             func() time.Time

	running        map[string]any
	candidate      map[string]any
	startup        map[string]any
	currentRevID   string
	nextRevSeq     int
	lock           *EditLock
	pendingConfirm *PendingConfirm
	confirmTimer   *time.Timer
	bootState      BootState
	lastAuditHash  string
	auditSeq       int64
	closed         bool
}

// Open initializes or recovers the configuration engine from disk.
func Open(ctx context.Context, opts Options) (*Engine, error) {
	if opts.BaseDir == "" {
		return nil, errors.New("BaseDir is required")
	}
	if opts.Schema == nil {
		return nil, errors.New("Schema is required")
	}
	if opts.Applier == nil {
		opts.Applier = NoopApplier{}
	}
	if opts.MaxFailedBoots <= 0 {
		opts.MaxFailedBoots = 3
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	revDir := filepath.Join(opts.BaseDir, "revisions")
	if err := os.MkdirAll(revDir, 0o700); err != nil {
		return nil, fmt.Errorf("create config store dir: %w", err)
	}

	e := &Engine{
		baseDir:           opts.BaseDir,
		schema:            opts.Schema,
		applier:           opts.Applier,
		migrator:          opts.Migrator,
		semanticValidator: opts.SemanticValidator,
		maxFailedBoots:    opts.MaxFailedBoots,
		nowFn:             opts.Now,
	}

	if err := e.loadAuditTail(); err != nil {
		return nil, err
	}
	if err := e.scanRevisions(); err != nil {
		return nil, err
	}
	if err := e.loadBootState(); err != nil {
		return nil, err
	}

	startupPath := filepath.Join(e.baseDir, "startup.json")
	runningPath := filepath.Join(e.baseDir, "running.json")
	candidatePath := filepath.Join(e.baseDir, "candidate.json")

	startupCfg, err := readJSONMap(startupPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read startup config: %w", err)
		}
		if opts.BootstrapConfig == nil {
			return nil, errors.New("startup.json missing and no BootstrapConfig provided")
		}
		startupCfg = deepCopyMap(opts.BootstrapConfig)
		if err := e.validateConfig(startupCfg); err != nil {
			return nil, fmt.Errorf("invalid BootstrapConfig: %w", err)
		}
		if err := writeJSONAtomic(startupPath, startupCfg); err != nil {
			return nil, err
		}
		if err := writeJSONAtomic(runningPath, startupCfg); err != nil {
			return nil, err
		}
		rev, err := e.saveRevisionLocked("system", "initial bootstrap configuration", "", startupCfg)
		if err != nil {
			return nil, err
		}
		e.currentRevID = rev.ID
		_ = e.appendAuditLocked("system", "BOOTSTRAP", rev.ID, "Initialized startup and running config", nil)
	} else if e.migrator != nil && e.schema.Root.SchemaVersion != "" {
		curVer, _ := startupCfg["schema_version"].(string)
		if curVer != e.schema.Root.SchemaVersion {
			// Backup pre-migration startup config before upgrading.
			backupPath := filepath.Join(e.baseDir, fmt.Sprintf("startup.pre-migration.%s.bak.json", curVer))
			_ = writeJSONAtomic(backupPath, startupCfg)
			migrated, steps, err := e.migrator.Migrate(startupCfg, e.schema.Root.SchemaVersion)
			if err != nil {
				return nil, fmt.Errorf("startup schema migration failed: %w", err)
			}
			if err := e.validateConfig(migrated); err != nil {
				return nil, fmt.Errorf("migrated startup config failed validation: %w", err)
			}
			startupCfg = migrated
			if err := writeJSONAtomic(startupPath, startupCfg); err != nil {
				return nil, err
			}
			_ = e.appendAuditLocked("system", "SCHEMA_MIGRATE", "", "Migrated startup config: "+strings.Join(steps, ", "), nil)
		}
	}

	e.startup = deepCopyMap(startupCfg)

	if opts.ColdBoot {
		// On OS boot, increment failed boot counter until MarkBootHealthy is called.
		e.bootState.FailedBoots++
		if e.bootState.FailedBoots >= e.maxFailedBoots {
			e.bootState.SafeMode = true
			safeCfg := opts.SafeModeConfig
			if safeCfg == nil {
				safeCfg = buildDefaultSafeModeConfig(startupCfg)
			}
			if err := e.validateConfig(safeCfg); err != nil {
				return nil, fmt.Errorf("safe-mode config invalid: %w", err)
			}
			e.running = deepCopyMap(safeCfg)
			e.candidate = deepCopyMap(safeCfg)
			_ = os.Remove(filepath.Join(e.baseDir, "confirm_pending.json"))
			_ = writeJSONAtomic(runningPath, e.running)
			_ = writeJSONAtomic(candidatePath, e.candidate)
			_ = writeJSONAtomic(filepath.Join(e.baseDir, "boot_state.json"), e.bootState)
			_ = e.appendAuditLocked("system", "SAFE_MODE_ENTERED", "",
				fmt.Sprintf("Failed boot threshold reached (%d/%d)", e.bootState.FailedBoots, e.maxFailedBoots), nil)
			return e, nil
		}
		e.bootState.SafeMode = false
		_ = writeJSONAtomic(filepath.Join(e.baseDir, "boot_state.json"), e.bootState)
		e.running = deepCopyMap(startupCfg)
		e.candidate = deepCopyMap(e.running)
		_ = writeJSONAtomic(runningPath, e.running)
		_ = writeJSONAtomic(candidatePath, e.candidate)
	} else {
		runCfg, err := readJSONMap(runningPath)
		if err != nil {
			runCfg = deepCopyMap(startupCfg)
			_ = writeJSONAtomic(runningPath, runCfg)
		}
		e.running = runCfg
		candCfg, err := readJSONMap(candidatePath)
		if err != nil {
			candCfg = deepCopyMap(e.running)
			_ = writeJSONAtomic(candidatePath, candCfg)
		}
		e.candidate = candCfg
	}

	_ = e.loadLock()
	if err := e.recoverPendingConfirmLocked(ctx); err != nil {
		return nil, err
	}
	return e, nil
}

// Close stops background timers cleanly on daemon shutdown.
func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	if e.confirmTimer != nil {
		e.confirmTimer.Stop()
		e.confirmTimer = nil
	}
}

// SafeMode reports whether the engine booted into recovery safe-mode.
func (e *Engine) SafeMode() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.bootState.SafeMode
}

// MarkBootHealthy resets the failed-boot watchdog counter once control & mgmt planes stabilize.
func (e *Engine) MarkBootHealthy(actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bootState.FailedBoots = 0
	e.bootState.SafeMode = false
	if err := writeJSONAtomic(filepath.Join(e.baseDir, "boot_state.json"), e.bootState); err != nil {
		return err
	}
	return e.appendAuditLocked(actor, "BOOT_HEALTHY", e.currentRevID, "Reset failed-boot counter", nil)
}

// GetRunning returns a deep copy of the active running config.
func (e *Engine) GetRunning(redactSecrets bool) map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := deepCopyMap(e.running)
	if redactSecrets {
		e.redactMap(cp, "")
	}
	return cp
}

// GetCandidate returns a deep copy of the candidate config.
func (e *Engine) GetCandidate(redactSecrets bool) map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := deepCopyMap(e.candidate)
	if redactSecrets {
		e.redactMap(cp, "")
	}
	return cp
}

// GetStartup returns a deep copy of the persisted startup config.
func (e *Engine) GetStartup(redactSecrets bool) map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := deepCopyMap(e.startup)
	if redactSecrets {
		e.redactMap(cp, "")
	}
	return cp
}

// CurrentRevisionID returns the ID of the currently active revision.
func (e *Engine) CurrentRevisionID() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.currentRevID
}

// PendingConfirmStatus returns a copy of any active commit-confirm state.
func (e *Engine) PendingConfirmStatus() *PendingConfirm {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pendingConfirm == nil {
		return nil
	}
	cp := *e.pendingConfirm
	return &cp
}

// Lock acquires an exclusive edit lock on the candidate datastore.
func (e *Engine) Lock(actor string, ttl time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if actor == "" {
		return errors.New("actor is required")
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	now := e.nowFn()
	if e.lock != nil && e.lock.Actor != actor && now.Before(e.lock.ExpiresAt) {
		return fmt.Errorf("%w: locked by %s until %s", ErrLockedByOther, e.lock.Actor, e.lock.ExpiresAt.Format(time.RFC3339))
	}
	e.lock = &EditLock{
		Actor:     actor,
		ExpiresAt: now.Add(ttl),
	}
	return writeJSONAtomic(filepath.Join(e.baseDir, "lock.json"), e.lock)
}

// Unlock releases the candidate lock held by actor.
func (e *Engine) Unlock(actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lock == nil {
		return nil
	}
	if e.lock.Actor != actor && e.nowFn().Before(e.lock.ExpiresAt) {
		return fmt.Errorf("%w: held by %s", ErrLockedByOther, e.lock.Actor)
	}
	e.lock = nil
	_ = os.Remove(filepath.Join(e.baseDir, "lock.json"))
	return nil
}

// SetCandidate replaces the full candidate configuration after checking edit locks.
func (e *Engine) SetCandidate(actor string, cfg map[string]any) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.checkLockLocked(actor); err != nil {
		return err
	}
	e.candidate = deepCopyMap(cfg)
	return writeJSONAtomic(filepath.Join(e.baseDir, "candidate.json"), e.candidate)
}

// SetPath sets a dot-separated configuration key inside the candidate datastore.
func (e *Engine) SetPath(actor, dotPath string, val any) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.checkLockLocked(actor); err != nil {
		return err
	}
	if err := setDotPath(e.candidate, dotPath, deepCopyValue(val)); err != nil {
		return err
	}
	return writeJSONAtomic(filepath.Join(e.baseDir, "candidate.json"), e.candidate)
}

// UnsetPath deletes a dot-separated configuration key inside the candidate datastore.
func (e *Engine) UnsetPath(actor, dotPath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.checkLockLocked(actor); err != nil {
		return err
	}
	if err := unsetDotPath(e.candidate, dotPath); err != nil {
		return err
	}
	return writeJSONAtomic(filepath.Join(e.baseDir, "candidate.json"), e.candidate)
}

// DiscardCandidate resets candidate back to the current running configuration.
func (e *Engine) DiscardCandidate(actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.checkLockLocked(actor); err != nil {
		return err
	}
	e.candidate = deepCopyMap(e.running)
	return writeJSONAtomic(filepath.Join(e.baseDir, "candidate.json"), e.candidate)
}

// ValidateCandidate validates the staged candidate configuration without applying it.
func (e *Engine) ValidateCandidate() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.validateConfig(e.candidate)
}

// DiffCandidate computes structural differences between running and candidate.
func (e *Engine) DiffCandidate() []DiffEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	return ComputeDiff(e.running, e.candidate)
}

// Commit validates candidate, applies it transactionally via Applier, and records an immutable revision.
func (e *Engine) Commit(ctx context.Context, actor, message string, opts CommitOptions) (*CommitResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.commitLocked(ctx, actor, message, opts)
}

func (e *Engine) commitLocked(ctx context.Context, actor, message string, opts CommitOptions) (*CommitResult, error) {
	if err := e.checkLockLocked(actor); err != nil {
		return nil, err
	}
	if e.pendingConfirm != nil {
		return nil, ErrConfirmPending
	}
	if err := e.validateConfig(e.candidate); err != nil {
		return nil, err
	}
	diffs := ComputeDiff(e.running, e.candidate)
	if len(diffs) == 0 && !opts.AllowEmpty {
		rev, err := e.loadRevisionLocked(e.currentRevID)
		if err != nil {
			rev = RevisionRecord{ID: e.currentRevID, Config: deepCopyMap(e.running)}
		}
		return &CommitResult{Changed: false, Revision: rev}, nil
	}

	if err := e.applier.Plan(ctx, deepCopyMap(e.running), deepCopyMap(e.candidate), diffs); err != nil {
		_ = e.appendAuditLocked(actor, "COMMIT_PLAN_FAILED", e.currentRevID, err.Error(), RedactDiff(diffs, e.schema.IsSecretPath))
		return nil, fmt.Errorf("commit pre-flight plan failed: %w", err)
	}

	prevRunning := deepCopyMap(e.running)
	targetCandidate := deepCopyMap(e.candidate)

	if err := e.applier.Apply(ctx, targetCandidate, diffs); err != nil {
		inv := InvertDiff(diffs)
		rbErr := e.applier.Apply(ctx, prevRunning, inv)
		_ = e.appendAuditLocked(actor, "COMMIT_APPLY_FAILED_ROLLED_BACK", e.currentRevID,
			fmt.Sprintf("apply_err=%v rollback_err=%v", err, rbErr), RedactDiff(diffs, e.schema.IsSecretPath))
		if rbErr != nil {
			return nil, fmt.Errorf("commit apply failed (%v) AND compensating rollback failed (%w)", err, rbErr)
		}
		return nil, fmt.Errorf("commit apply failed (automatically rolled back): %w", err)
	}

	rev, err := e.saveRevisionLocked(actor, message, e.currentRevID, targetCandidate)
	if err != nil {
		return nil, err
	}
	e.running = targetCandidate
	e.currentRevID = rev.ID
	if err := writeJSONAtomic(filepath.Join(e.baseDir, "running.json"), e.running); err != nil {
		return nil, err
	}
	savedStartup := false
	if opts.SaveStartup {
		e.startup = deepCopyMap(e.running)
		if err := writeJSONAtomic(filepath.Join(e.baseDir, "startup.json"), e.startup); err != nil {
			return nil, err
		}
		savedStartup = true
	}
	_ = e.appendAuditLocked(actor, "COMMIT", rev.ID, message, RedactDiff(diffs, e.schema.IsSecretPath))
	return &CommitResult{
		Changed:      true,
		Revision:     rev,
		Diffs:        diffs,
		SavedStartup: savedStartup,
	}, nil
}

// CommitConfirm applies candidate changes and starts a persistent deadman auto-rollback timer.
// Unless Confirm(actor) is invoked before timeout, running configuration automatically reverts.
func (e *Engine) CommitConfirm(ctx context.Context, actor, message string, timeout time.Duration) (*CommitResult, error) {
	if timeout <= 0 {
		return nil, errors.New("confirm timeout must be > 0")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	rollbackRevID := e.currentRevID
	res, err := e.commitLocked(ctx, actor, message+" [confirm-pending]", CommitOptions{})
	if err != nil {
		return nil, err
	}
	if !res.Changed {
		return res, nil
	}

	deadline := e.nowFn().Add(timeout)
	token := newToken()
	pending := &PendingConfirm{
		Token:              token,
		Actor:              actor,
		Message:            message,
		TargetRevisionID:   res.Revision.ID,
		RollbackRevisionID: rollbackRevID,
		DeadlineUnixNano:   deadline.UnixNano(),
	}
	if err := writeJSONAtomic(filepath.Join(e.baseDir, "confirm_pending.json"), pending); err != nil {
		// Never leave an unconfirmed commit active without persistent deadman tracking.
		if rec, loadErr := e.loadRevisionLocked(rollbackRevID); loadErr == nil {
			_, _ = e.applyRollbackLocked(ctx, "watchdog", rec, "COMMIT_CONFIRM_PERSIST_FAILED_ROLLBACK",
				"Failed to persist confirm_pending.json; reverted safely")
		}
		return nil, err
	}
	e.pendingConfirm = pending
	e.armConfirmTimerLocked(token, timeout)

	_ = e.appendAuditLocked(actor, "COMMIT_CONFIRM_STARTED", res.Revision.ID,
		fmt.Sprintf("rollback_to=%s deadline=%s", rollbackRevID, deadline.Format(time.RFC3339)), nil)

	res.ConfirmPending = true
	res.ConfirmDeadline = deadline
	return res, nil
}

// Confirm finalizes an active CommitConfirm and cancels the deadman rollback timer.
func (e *Engine) Confirm(actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pendingConfirm == nil {
		return ErrNoPendingConfirm
	}
	targetRev := e.pendingConfirm.TargetRevisionID
	if e.confirmTimer != nil {
		e.confirmTimer.Stop()
		e.confirmTimer = nil
	}
	e.pendingConfirm = nil
	_ = os.Remove(filepath.Join(e.baseDir, "confirm_pending.json"))
	return e.appendAuditLocked(actor, "COMMIT_CONFIRMED", targetRev, "Confirmed pending commit", nil)
}

// SaveStartup persists the current running configuration to non-volatile startup storage.
func (e *Engine) SaveStartup(actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.startup = deepCopyMap(e.running)
	if err := writeJSONAtomic(filepath.Join(e.baseDir, "startup.json"), e.startup); err != nil {
		return err
	}
	return e.appendAuditLocked(actor, "SAVE_STARTUP", e.currentRevID, "Persisted running config to startup", nil)
}

// Rollback restores a historical revision into candidate (commitNow=false) or commits it immediately (commitNow=true).
// revRef supports exact ID ("rev-000001") or relative offset ("0"=current, "1"=previous, etc.).
func (e *Engine) Rollback(ctx context.Context, actor, revRef string, commitNow bool) (*CommitResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.checkLockLocked(actor); err != nil {
		return nil, err
	}

	targetID, err := e.resolveRevisionRefLocked(revRef)
	if err != nil {
		return nil, err
	}
	rec, err := e.loadRevisionLocked(targetID)
	if err != nil {
		return nil, err
	}
	if !commitNow {
		e.candidate = deepCopyMap(rec.Config)
		if err := writeJSONAtomic(filepath.Join(e.baseDir, "candidate.json"), e.candidate); err != nil {
			return nil, err
		}
		_ = e.appendAuditLocked(actor, "ROLLBACK_STAGED", rec.ID, "Loaded revision into candidate", nil)
		return &CommitResult{Changed: false, Revision: rec}, nil
	}

	// Cancel pending confirm timer if operator explicitly rolls back.
	if e.pendingConfirm != nil {
		if e.confirmTimer != nil {
			e.confirmTimer.Stop()
			e.confirmTimer = nil
		}
		e.pendingConfirm = nil
		_ = os.Remove(filepath.Join(e.baseDir, "confirm_pending.json"))
	}

	return e.applyRollbackLocked(ctx, actor, rec, "ROLLBACK", fmt.Sprintf("Rolled back to %s", rec.ID))
}

// ListRevisions returns metadata of stored immutable revisions sorted newest-first.
func (e *Engine) ListRevisions() ([]RevisionRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.listRevisionsLocked()
}

// VerifyAuditLog verifies every SHA-256 hash link in audit.jsonl.
func (e *Engine) VerifyAuditLog() (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	auditPath := filepath.Join(e.baseDir, "audit.jsonl")
	f, err := os.Open(auditPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	expectedPrev := strings.Repeat("0", 64)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return count, fmt.Errorf("%w: malformed entry at line %d: %v", ErrAuditChainTampered, count+1, err)
		}
		if entry.PrevHash != expectedPrev {
			return count, fmt.Errorf("%w: broken PrevHash at seq %d", ErrAuditChainTampered, entry.Seq)
		}
		calc := computeAuditHash(entry)
		if entry.EntryHash != calc {
			return count, fmt.Errorf("%w: EntryHash mismatch at seq %d", ErrAuditChainTampered, entry.Seq)
		}
		expectedPrev = entry.EntryHash
		count++
	}
	if err := scanner.Err(); err != nil {
		return count, err
	}
	return count, nil
}

func (e *Engine) armConfirmTimerLocked(token string, d time.Duration) {
	if e.confirmTimer != nil {
		e.confirmTimer.Stop()
	}
	e.confirmTimer = time.AfterFunc(d, func() {
		e.handleConfirmTimeout(token)
	})
}

func (e *Engine) handleConfirmTimeout(token string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.pendingConfirm == nil || e.pendingConfirm.Token != token {
		return
	}
	rbID := e.pendingConfirm.RollbackRevisionID
	e.pendingConfirm = nil
	e.confirmTimer = nil
	_ = os.Remove(filepath.Join(e.baseDir, "confirm_pending.json"))

	rec, err := e.loadRevisionLocked(rbID)
	if err != nil {
		_ = e.appendAuditLocked("watchdog", "AUTO_ROLLBACK_ERROR", rbID, err.Error(), nil)
		return
	}
	_, _ = e.applyRollbackLocked(context.Background(), "watchdog", rec, "AUTO_ROLLBACK_CONFIRM_TIMEOUT",
		fmt.Sprintf("Commit-confirm expired; automatically reverted to %s", rbID))
}

func (e *Engine) recoverPendingConfirmLocked(ctx context.Context) error {
	pendingPath := filepath.Join(e.baseDir, "confirm_pending.json")
	raw, err := os.ReadFile(pendingPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var pc PendingConfirm
	if err := json.Unmarshal(raw, &pc); err != nil {
		return fmt.Errorf("parse pending confirm state: %w", err)
	}
	now := e.nowFn()
	deadline := time.Unix(0, pc.DeadlineUnixNano)
	if !now.Before(deadline) {
		_ = os.Remove(pendingPath)
		rec, err := e.loadRevisionLocked(pc.RollbackRevisionID)
		if err != nil {
			return err
		}
		_, err = e.applyRollbackLocked(ctx, "crash-recovery", rec, "AUTO_ROLLBACK_CRASH_RECOVERY",
			fmt.Sprintf("Expired pending confirm found on startup; reverted to %s", pc.RollbackRevisionID))
		return err
	}
	e.pendingConfirm = &pc
	e.armConfirmTimerLocked(pc.Token, deadline.Sub(now))
	return nil
}

func (e *Engine) applyRollbackLocked(ctx context.Context, actor string, target RevisionRecord, auditAction, msg string) (*CommitResult, error) {
	targetCfg := deepCopyMap(target.Config)
	diffs := ComputeDiff(e.running, targetCfg)
	if err := e.applier.Apply(ctx, targetCfg, diffs); err != nil {
		_ = e.appendAuditLocked(actor, auditAction+"_FAILED", target.ID, err.Error(), nil)
		return nil, fmt.Errorf("rollback apply failed: %w", err)
	}
	newRev, err := e.saveRevisionLocked(actor, msg, e.currentRevID, targetCfg)
	if err != nil {
		return nil, err
	}
	e.running = deepCopyMap(targetCfg)
	e.candidate = deepCopyMap(targetCfg)
	e.currentRevID = newRev.ID
	if err := writeJSONAtomic(filepath.Join(e.baseDir, "running.json"), e.running); err != nil {
		return nil, err
	}
	if err := writeJSONAtomic(filepath.Join(e.baseDir, "candidate.json"), e.candidate); err != nil {
		return nil, err
	}
	_ = e.appendAuditLocked(actor, auditAction, newRev.ID, msg, RedactDiff(diffs, e.schema.IsSecretPath))
	return &CommitResult{
		Changed:  len(diffs) > 0,
		Revision: newRev,
		Diffs:    diffs,
	}, nil
}

func (e *Engine) validateConfig(cfg map[string]any) error {
	if err := e.schema.Validate(cfg); err != nil {
		return err
	}
	if e.semanticValidator != nil {
		if err := e.semanticValidator(deepCopyMap(cfg)); err != nil {
			return fmt.Errorf("semantic validation failed: %w", err)
		}
	}
	return nil
}

func (e *Engine) checkLockLocked(actor string) error {
	if e.lock == nil {
		return nil
	}
	if e.nowFn().After(e.lock.ExpiresAt) {
		e.lock = nil
		_ = os.Remove(filepath.Join(e.baseDir, "lock.json"))
		return nil
	}
	if e.lock.Actor != actor {
		return fmt.Errorf("%w: locked by %s", ErrLockedByOther, e.lock.Actor)
	}
	return nil
}

func (e *Engine) saveRevisionLocked(actor, message, parentID string, cfg map[string]any) (RevisionRecord, error) {
	e.nextRevSeq++
	id := fmt.Sprintf("rev-%06d", e.nextRevSeq)
	ver, _ := cfg["schema_version"].(string)
	digest, err := hashCanonicalJSON(cfg)
	if err != nil {
		return RevisionRecord{}, err
	}
	rec := RevisionRecord{
		ID:            id,
		Seq:           e.nextRevSeq,
		Timestamp:     e.nowFn().UTC(),
		Actor:         actor,
		Message:       message,
		ParentID:      parentID,
		SchemaVersion: ver,
		ConfigSHA256:  digest,
		Config:        deepCopyMap(cfg),
	}
	path := filepath.Join(e.baseDir, "revisions", id+".json")
	if err := writeJSONAtomic(path, rec); err != nil {
		return RevisionRecord{}, err
	}
	return rec, nil
}

func (e *Engine) loadRevisionLocked(id string) (RevisionRecord, error) {
	path := filepath.Join(e.baseDir, "revisions", id+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return RevisionRecord{}, fmt.Errorf("%w: %s", ErrRevisionNotFound, id)
		}
		return RevisionRecord{}, err
	}
	var rec RevisionRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return RevisionRecord{}, err
	}
	digest, err := hashCanonicalJSON(rec.Config)
	if err != nil || digest != rec.ConfigSHA256 {
		return RevisionRecord{}, fmt.Errorf("%w: %s", ErrRevisionCorrupted, id)
	}
	return rec, nil
}

func (e *Engine) listRevisionsLocked() ([]RevisionRecord, error) {
	entries, err := os.ReadDir(filepath.Join(e.baseDir, "revisions"))
	if err != nil {
		return nil, err
	}
	var recs []RevisionRecord
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(ent.Name(), ".json")
		rec, err := e.loadRevisionLocked(id)
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	sort.Slice(recs, func(i, j int) bool {
		return recs[i].Seq > recs[j].Seq
	})
	return recs, nil
}

func (e *Engine) resolveRevisionRefLocked(revRef string) (string, error) {
	if strings.HasPrefix(revRef, "rev-") {
		return revRef, nil
	}
	offset, err := strconv.Atoi(revRef)
	if err != nil || offset < 0 {
		return "", fmt.Errorf("%w: invalid reference %q", ErrRevisionNotFound, revRef)
	}
	recs, err := e.listRevisionsLocked()
	if err != nil {
		return "", err
	}
	if offset >= len(recs) {
		return "", fmt.Errorf("%w: offset %d out of range (%d revisions)", ErrRevisionNotFound, offset, len(recs))
	}
	return recs[offset].ID, nil
}

func (e *Engine) scanRevisions() error {
	entries, err := os.ReadDir(filepath.Join(e.baseDir, "revisions"))
	if err != nil {
		return err
	}
	maxSeq := 0
	var maxID string
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasPrefix(name, "rev-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		numStr := strings.TrimSuffix(strings.TrimPrefix(name, "rev-"), ".json")
		seq, err := strconv.Atoi(numStr)
		if err == nil && seq > maxSeq {
			maxSeq = seq
			maxID = strings.TrimSuffix(name, ".json")
		}
	}
	e.nextRevSeq = maxSeq
	e.currentRevID = maxID
	return nil
}

func (e *Engine) loadBootState() error {
	raw, err := os.ReadFile(filepath.Join(e.baseDir, "boot_state.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return json.Unmarshal(raw, &e.bootState)
}

func (e *Engine) loadLock() error {
	raw, err := os.ReadFile(filepath.Join(e.baseDir, "lock.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var l EditLock
	if err := json.Unmarshal(raw, &l); err != nil {
		return err
	}
	if e.nowFn().Before(l.ExpiresAt) {
		e.lock = &l
	}
	return nil
}

func (e *Engine) loadAuditTail() error {
	auditPath := filepath.Join(e.baseDir, "audit.jsonl")
	e.lastAuditHash = strings.Repeat("0", 64)
	f, err := os.Open(auditPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return fmt.Errorf("corrupt audit tail: %w", err)
		}
		e.lastAuditHash = entry.EntryHash
		e.auditSeq = entry.Seq
	}
	return scanner.Err()
}

func (e *Engine) appendAuditLocked(actor, action, revID, details string, diffs []DiffEntry) error {
	e.auditSeq++
	entry := AuditEntry{
		Seq:       e.auditSeq,
		Timestamp: e.nowFn().UTC().Format(time.RFC3339Nano),
		Actor:     actor,
		Action:    action,
		Revision:  revID,
		Details:   details,
		Diffs:     diffs,
		PrevHash:  e.lastAuditHash,
	}
	entry.EntryHash = computeAuditHash(entry)
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	auditPath := filepath.Join(e.baseDir, "audit.jsonl")
	f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	e.lastAuditHash = entry.EntryHash
	return nil
}

func computeAuditHash(entry AuditEntry) string {
	copyForHash := entry
	copyForHash.EntryHash = ""
	b, _ := json.Marshal(copyForHash)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (e *Engine) redactMap(m map[string]any, prefix string) {
	for k, v := range m {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		if e.schema.IsSecretPath(path) {
			m[k] = "***REDACTED***"
			continue
		}
		switch sub := v.(type) {
		case map[string]any:
			e.redactMap(sub, path)
		case []any:
			for idx, elem := range sub {
				if elemMap, ok := elem.(map[string]any); ok {
					e.redactMap(elemMap, fmt.Sprintf("%s[%d]", path, idx))
				}
			}
		}
	}
}

func setDotPath(root map[string]any, dotPath string, val any) error {
	parts := strings.Split(dotPath, ".")
	if len(parts) == 0 || dotPath == "" {
		return errors.New("empty config path")
	}
	cur := root
	for i := 0; i < len(parts)-1; i++ {
		seg := parts[i]
		next, exists := cur[seg]
		if !exists {
			child := make(map[string]any)
			cur[seg] = child
			cur = child
			continue
		}
		childMap, ok := next.(map[string]any)
		if !ok {
			return fmt.Errorf("path segment %q is not an object", seg)
		}
		cur = childMap
	}
	cur[parts[len(parts)-1]] = val
	return nil
}

func unsetDotPath(root map[string]any, dotPath string) error {
	parts := strings.Split(dotPath, ".")
	if len(parts) == 0 || dotPath == "" {
		return errors.New("empty config path")
	}
	cur := root
	for i := 0; i < len(parts)-1; i++ {
		next, exists := cur[parts[i]]
		if !exists {
			return nil
		}
		childMap, ok := next.(map[string]any)
		if !ok {
			return fmt.Errorf("path segment %q is not an object", parts[i])
		}
		cur = childMap
	}
	delete(cur, parts[len(parts)-1])
	return nil
}

func buildDefaultSafeModeConfig(startup map[string]any) map[string]any {
	ver, _ := startup["schema_version"].(string)
	if ver == "" {
		ver = "1.0.0"
	}
	return map[string]any{
		"schema_version": ver,
		"system": map[string]any{
			"hostname":    "daiji-safemode",
			"timezone":    "UTC",
			"motd_banner": "DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi) [SAFE-MODE]",
			"watchdog": map[string]any{
				"enabled":          true,
				"timeout_sec":      30,
				"max_failed_boots": 3,
			},
		},
		"management": map[string]any{
			"ssh":    map[string]any{"enabled": true, "port": 22, "password_auth": false},
			"api":    map[string]any{"enabled": true, "port": 8443, "tls_enabled": true},
			"daiweb": map[string]any{"enabled": true, "port": 443, "theme": "daiji-dark"},
		},
		"updates": map[string]any{
			"channel":             "stable",
			"auto_check":          false,
			"require_signature":   true,
			"confirm_timeout_sec": 180,
		},
	}
}

func hashCanonicalJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func readJSONMap(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func writeJSONAtomic(path string, v any) error {
	return fsatomic.WriteJSONAtomic(path, v)
}

func deepCopyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func deepCopyValue(v any) any {
	if v == nil {
		return nil
	}
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func newToken() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}
