// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package daidesk implements the DaiDesk Desktop management engine:
// multi-device tab workspace, L2 MAC-discovery session onboarding (DJDP1),
// remote terminal execution, jailed atomic file manager, concurrent fleet bulk
// configuration (dry-run & commit), signed config backups/diffs, and support
// for both offline/LAN-only and DaijiCloud modes.
package daidesk

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/daidiscovery"
	"github.com/kangpcode/daijios/pkg/daijicli"
	"github.com/kangpcode/daijios/pkg/fsatomic"
	"github.com/kangpcode/daijios/pkg/schema"
	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

const MaxUploadBytes = 1024 * 1024

var (
	ErrPathTraversal  = errors.New("path traversal or symlink escape blocked by file jail")
	ErrTamperedBackup = errors.New("config backup HMAC integrity verification failed")
	ErrTabNotFound    = errors.New("device tab not found")
)

// AccessMode distinguishes Offline/LAN-only direct management from DaijiCloud relay.
type AccessMode string

const (
	ModeOfflineLAN AccessMode = "offline-lan"
	ModeCloud      AccessMode = "cloud"
)

// DeviceTab represents one open managed DaijiOS device tab in DaiDesk.
type DeviceTab struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Mode       AccessMode `json:"mode"`
	MAC        string     `json:"mac,omitempty"`
	Endpoint   string     `json:"endpoint"`
	Token      string     `json:"-"` // bearer token kept out of exported tab metadata
	Actor      string     `json:"actor"`
	Role       string     `json:"role"`
	LastPrompt string     `json:"last_prompt,omitempty"`
	TermLog    []string   `json:"term_log,omitempty"`
}

// FileEntry describes one file or directory inside a jailed router storage root.
type FileEntry struct {
	Name    string `json:"name"`
	RelPath string `json:"rel_path"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time"`
}

// ConfigBackup is a deterministic, HMAC-integrity-checked snapshot of device config.
type ConfigBackup struct {
	Brand         string         `json:"brand"`
	SchemaVersion string         `json:"schema_version"`
	Hostname      string         `json:"hostname"`
	Redacted      bool           `json:"redacted"`
	CreatedAt     string         `json:"created_at"`
	HMAC          string         `json:"hmac"`
	Config        map[string]any `json:"config"`
}

// BulkTargetResult captures the per-device outcome of a concurrent Bulk Config operation.
type BulkTargetResult struct {
	TabID     string                   `json:"tab_id"`
	Label     string                   `json:"label"`
	Mode      AccessMode               `json:"mode"`
	Success   bool                     `json:"success"`
	Committed bool                     `json:"committed"`
	Revision  string                   `json:"revision,omitempty"`
	Diffs     []configengine.DiffEntry `json:"diffs,omitempty"`
	Error     string                   `json:"error,omitempty"`
}

// Workspace manages active multi-device tabs in DaiDesk (offline-lan & cloud).
type Workspace struct {
	mu         sync.RWMutex
	tabs       map[string]*DeviceTab
	order      []string
	activeID   string
	httpClient *http.Client
}

// NewWorkspace constructs a multi-device desktop control workspace.
func NewWorkspace() *Workspace {
	return &Workspace{
		tabs:       make(map[string]*DeviceTab),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// AddTab inserts or updates a managed device tab and optionally selects it.
func (w *Workspace) AddTab(tab DeviceTab, makeActive bool) {
	if tab.ID == "" {
		tab.ID = tab.MAC
		if tab.ID == "" {
			tab.ID = tab.Endpoint
		}
	}
	if tab.Label == "" {
		tab.Label = tab.ID
	}
	if tab.Mode == "" {
		tab.Mode = ModeOfflineLAN
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if _, exists := w.tabs[tab.ID]; !exists {
		w.order = append(w.order, tab.ID)
	}
	cp := tab
	w.tabs[tab.ID] = &cp
	if makeActive || w.activeID == "" {
		w.activeID = tab.ID
	}
}

// ConnectFromBeacon opens an offline-LAN tab directly from an L2 DJDP1 discovery beacon.
func (w *Workspace) ConnectFromBeacon(b daidiscovery.DeviceBeacon, actor, role, token string) DeviceTab {
	port := b.WebPort
	if port <= 0 {
		port = 8443
	}
	ep := fmt.Sprintf("http://%s:%d", b.IPv4, port)
	id := strings.ToLower(b.MAC)
	if id == "" {
		id = b.DeviceID
	}
	tab := DeviceTab{
		ID:       "lan-" + id,
		Label:    fmt.Sprintf("%s (%s)", b.Hostname, b.MAC),
		Mode:     ModeOfflineLAN,
		MAC:      b.MAC,
		Endpoint: ep,
		Token:    token,
		Actor:    actor,
		Role:     role,
	}
	w.AddTab(tab, true)
	return tab
}

// SwitchTab changes the focused device tab.
func (w *Workspace) SwitchTab(tabID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.tabs[tabID]; !ok {
		return fmt.Errorf("%w: %q", ErrTabNotFound, tabID)
	}
	w.activeID = tabID
	return nil
}

// CloseTab removes a device tab and shifts focus cleanly if needed.
func (w *Workspace) CloseTab(tabID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.tabs[tabID]; !ok {
		return fmt.Errorf("%w: %q", ErrTabNotFound, tabID)
	}
	delete(w.tabs, tabID)
	kept := make([]string, 0, len(w.order))
	for _, id := range w.order {
		if id != tabID {
			kept = append(kept, id)
		}
	}
	w.order = kept
	if w.activeID == tabID {
		if len(kept) > 0 {
			w.activeID = kept[0]
		} else {
			w.activeID = ""
		}
	}
	return nil
}

// ListTabs returns open tabs in deterministic insertion order.
func (w *Workspace) ListTabs() ([]DeviceTab, string) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]DeviceTab, 0, len(w.order))
	for _, id := range w.order {
		if t, ok := w.tabs[id]; ok {
			out = append(out, *t)
		}
	}
	return out, w.activeID
}

// ExecuteRemoteCLI executes a DaijiOS CLI command on the target tab's agent endpoint.
func (w *Workspace) ExecuteRemoteCLI(ctx context.Context, tabID, cmdLine string) (prompt string, output string, err error) {
	tab, err := w.getTab(tabID)
	if err != nil {
		return "", "", err
	}
	body, _ := json.Marshal(map[string]string{"cmd": cmdLine})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(tab.Endpoint, "/")+"/api/v1/daidesk/cli", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if tab.Token != "" {
		req.Header.Set("Authorization", "Bearer "+tab.Token)
	}
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var parsed struct {
		Prompt string `json:"prompt"`
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&parsed)
	if resp.StatusCode >= 400 {
		return parsed.Prompt, "", fmt.Errorf("remote CLI error (%d): %s", resp.StatusCode, parsed.Error)
	}

	w.mu.Lock()
	if cur, ok := w.tabs[tabID]; ok {
		cur.LastPrompt = parsed.Prompt
		cur.TermLog = append(cur.TermLog, parsed.Prompt+cmdLine, parsed.Output)
	}
	w.mu.Unlock()
	return parsed.Prompt, parsed.Output, nil
}

// ApplyBulkConfig concurrently pushes dot-path config patches across all tabIDs (supporting dry-run preview).
func (w *Workspace) ApplyBulkConfig(ctx context.Context, tabIDs []string, patches map[string]any, commit bool) []BulkTargetResult {
	results := make([]BulkTargetResult, len(tabIDs))
	var wg sync.WaitGroup
	for i, tid := range tabIDs {
		wg.Add(1)
		go func(idx int, id string) {
			defer wg.Done()
			results[idx] = w.applyOneTarget(ctx, id, patches, commit)
		}(i, tid)
	}
	wg.Wait()
	return results
}

func (w *Workspace) applyOneTarget(ctx context.Context, tabID string, patches map[string]any, commit bool) BulkTargetResult {
	tab, err := w.getTab(tabID)
	if err != nil {
		return BulkTargetResult{TabID: tabID, Error: err.Error()}
	}
	payload, _ := json.Marshal(map[string]any{
		"patches": patches,
		"commit":  commit,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(tab.Endpoint, "/")+"/api/v1/daidesk/config/patch", bytes.NewReader(payload))
	if err != nil {
		return BulkTargetResult{TabID: tabID, Label: tab.Label, Mode: tab.Mode, Error: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	if tab.Token != "" {
		req.Header.Set("Authorization", "Bearer "+tab.Token)
	}
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return BulkTargetResult{TabID: tabID, Label: tab.Label, Mode: tab.Mode, Error: err.Error()}
	}
	defer resp.Body.Close()

	var body struct {
		Committed bool                     `json:"committed"`
		Revision  string                   `json:"revision"`
		Diffs     []configengine.DiffEntry `json:"diffs"`
		Error     string                   `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode >= 400 {
		return BulkTargetResult{TabID: tabID, Label: tab.Label, Mode: tab.Mode, Error: body.Error}
	}
	return BulkTargetResult{
		TabID:     tabID,
		Label:     tab.Label,
		Mode:      tab.Mode,
		Success:   true,
		Committed: body.Committed,
		Revision:  body.Revision,
		Diffs:     body.Diffs,
	}
}

func (w *Workspace) getTab(tabID string) (DeviceTab, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	t, ok := w.tabs[tabID]
	if !ok {
		return DeviceTab{}, fmt.Errorf("%w: %q", ErrTabNotFound, tabID)
	}
	return *t, nil
}

// FileManager enforces a strict root jail over managed device files.
type FileManager struct {
	rootAbs string
}

// NewFileManager initializes a jailed file manager rooted at rootDir.
func NewFileManager(rootDir string) (*FileManager, error) {
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, err
	}
	realRoot, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	return &FileManager{rootAbs: realRoot}, nil
}

func (fm *FileManager) resolveSafe(relPath string) (string, error) {
	if strings.ContainsRune(relPath, '\x00') {
		return "", ErrPathTraversal
	}
	trimmed := strings.TrimSpace(relPath)
	for _, seg := range strings.Split(filepath.ToSlash(trimmed), "/") {
		if seg == ".." {
			return "", ErrPathTraversal
		}
	}
	cleaned := filepath.Clean("/" + trimmed)
	joined := filepath.Join(fm.rootAbs, cleaned)
	relCheck, err := filepath.Rel(fm.rootAbs, joined)
	if err != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(os.PathSeparator)) {
		return "", ErrPathTraversal
	}

	// Verify nearest existing ancestor does not symlink outside rootAbs.
	cur := joined
	for {
		if _, err := os.Lstat(cur); err == nil {
			realCur, err := filepath.EvalSymlinks(cur)
			if err != nil {
				return "", err
			}
			r2, err := filepath.Rel(fm.rootAbs, realCur)
			if err != nil || r2 == ".." || strings.HasPrefix(r2, ".."+string(os.PathSeparator)) {
				return "", ErrPathTraversal
			}
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return joined, nil
}

// ListFiles lists entries within relDir cleanly inside the jail.
func (fm *FileManager) ListFiles(relDir string) ([]FileEntry, error) {
	target, err := fm.resolveSafe(relDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return nil, err
	}
	out := make([]FileEntry, 0, len(entries))
	for _, de := range entries {
		info, err := de.Info()
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(fm.rootAbs, filepath.Join(target, de.Name()))
		out = append(out, FileEntry{
			Name:    de.Name(),
			RelPath: filepath.ToSlash(rel),
			Size:    info.Size(),
			IsDir:   de.IsDir(),
			ModTime: info.ModTime().UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// WriteAtomic writes data safely inside the jail using temp + 0600 + fsync + rename.
func (fm *FileManager) WriteAtomic(relPath string, data []byte) error {
	if len(data) > MaxUploadBytes {
		return fmt.Errorf("upload exceeds max size %d bytes", MaxUploadBytes)
	}
	target, err := fm.resolveSafe(relPath)
	if err != nil {
		return err
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".daijifile-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// ReadFile reads one jailed file.
func (fm *FileManager) ReadFile(relPath string) ([]byte, error) {
	target, err := fm.resolveSafe(relPath)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(target)
}

// DeleteFile deletes one jailed regular file.
func (fm *FileManager) DeleteFile(relPath string) error {
	target, err := fm.resolveSafe(relPath)
	if err != nil {
		return err
	}
	if target == fm.rootAbs {
		return ErrPathTraversal
	}
	return os.Remove(target)
}

// ExportBackup exports running configuration into a signed ConfigBackup and optional file path.
func ExportBackup(eng *configengine.Engine, cs *schema.CompiledSchema, signingKey []byte, redactSecrets bool, outFile string) (*ConfigBackup, error) {
	if eng == nil || cs == nil {
		return nil, errors.New("config engine and schema are required")
	}
	cfg := eng.GetRunning(redactSecrets)
	hostname := "daiji"
	if sysMap, ok := cfg["system"].(map[string]any); ok {
		if h, ok := sysMap["hostname"].(string); ok && h != "" {
			hostname = h
		}
	}
	b := &ConfigBackup{
		Brand:         sysinfo.BrandBanner,
		SchemaVersion: cs.Root.SchemaVersion,
		Hostname:      hostname,
		Redacted:      redactSecrets,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		Config:        cfg,
	}
	b.HMAC = computeBackupHMAC(signingKey, b)
	if outFile != "" {
		if err := fsatomic.WriteJSONAtomic(outFile, b); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// DiffBackupVsRunning verifies backup HMAC integrity and computes secret-redacted diffs against active running state.
func DiffBackupVsRunning(eng *configengine.Engine, cs *schema.CompiledSchema, signingKey []byte, backup *ConfigBackup) ([]configengine.DiffEntry, error) {
	if eng == nil || cs == nil || backup == nil {
		return nil, errors.New("engine, schema, and backup are required")
	}
	if len(signingKey) > 0 {
		expected := computeBackupHMAC(signingKey, backup)
		gotB, err := hex.DecodeString(backup.HMAC)
		expB, _ := hex.DecodeString(expected)
		if err != nil || !hmac.Equal(gotB, expB) {
			return nil, ErrTamperedBackup
		}
	}
	running := eng.GetRunning(backup.Redacted)
	diffs := configengine.ComputeDiff(backup.Config, running)
	return configengine.RedactDiff(diffs, cs.IsSecretPath), nil
}

func computeBackupHMAC(key []byte, b *ConfigBackup) string {
	rawCfg, _ := json.Marshal(b.Config)
	h := hmac.New(sha256.New, key)
	fmt.Fprintf(h, "%s|%s|%v|%s|", b.SchemaVersion, b.Hostname, b.Redacted, b.CreatedAt)
	_, _ = h.Write(rawCfg)
	return hex.EncodeToString(h.Sum(nil))
}

// AgentDependencies wires router-side handlers consumed by DaiDesk desktop workspaces.
type AgentDependencies struct {
	Config       *configengine.Engine
	Schema       *schema.CompiledSchema
	Files        *FileManager
	Tokens       *secauth.TokenManager
	RBAC         *secauth.RBACPolicy
	BackupSecret []byte
}

// NewAgentHandler builds the DaiDesk device-side REST handler (files, remote CLI, bulk patch, backup/diff).
func NewAgentHandler(deps AgentDependencies) http.Handler {
	if deps.RBAC == nil {
		deps.RBAC = secauth.NewDefaultRBACPolicy(true)
	}
	if len(deps.BackupSecret) == 0 {
		deps.BackupSecret = []byte("daijios-daidesk-backup-hmac-key")
	}
	mux := http.NewServeMux()
	cliSessions := make(map[string]*daijicli.Session)
	var cliMu sync.Mutex

	requirePerm := func(perm secauth.Permission, next func(http.ResponseWriter, *http.Request, *secauth.TokenClaims)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			hdr := r.Header.Get("Authorization")
			if !strings.HasPrefix(hdr, "Bearer ") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
				return
			}
			tok := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
			claims, err := deps.Tokens.Verify(tok, perm, time.Now())
			if err != nil {
				code := http.StatusUnauthorized
				if strings.Contains(err.Error(), "scope") {
					code = http.StatusForbidden
				}
				writeJSON(w, code, map[string]string{"error": err.Error()})
				return
			}
			if err := deps.RBAC.Authorize(claims.Role, perm); err != nil {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
				return
			}
			next(w, r, claims)
		}
	}

	mux.HandleFunc("/api/v1/daidesk/cli", requirePerm(secauth.PermNetDiag, func(w http.ResponseWriter, r *http.Request, claims *secauth.TokenClaims) {
		var req struct {
			Cmd string `json:"cmd"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		cliMu.Lock()
		sess, ok := cliSessions[claims.TokenID]
		if !ok {
			var err error
			sess, err = daijicli.NewSession(claims.Subject, claims.Role, deps.Config, deps.Schema)
			if err != nil {
				cliMu.Unlock()
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			cliSessions[claims.TokenID] = sess
		}
		res, execErr := sess.Execute(r.Context(), req.Cmd)
		prompt := sess.Prompt()
		cliMu.Unlock()
		if execErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"prompt": prompt, "error": execErr.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"prompt": prompt, "output": res.Output})
	}))

	mux.HandleFunc("/api/v1/daidesk/config/patch", requirePerm(secauth.PermConfigWrite, func(w http.ResponseWriter, r *http.Request, claims *secauth.TokenClaims) {
		var req struct {
			Patches map[string]any `json:"patches"`
			Commit  bool           `json:"commit"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.Commit {
			if err := deps.RBAC.Authorize(claims.Role, secauth.PermConfigCommit); err != nil {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
				return
			}
		}
		keys := make([]string, 0, len(req.Patches))
		for k := range req.Patches {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := deps.Config.SetPath(claims.Subject, k, req.Patches[k]); err != nil {
				_ = deps.Config.DiscardCandidate(claims.Subject)
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
		}
		if err := deps.Config.ValidateCandidate(); err != nil {
			_ = deps.Config.DiscardCandidate(claims.Subject)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		safeDiffs := configengine.RedactDiff(deps.Config.DiffCandidate(), deps.Schema.IsSecretPath)
		if !req.Commit {
			_ = deps.Config.DiscardCandidate(claims.Subject)
			writeJSON(w, http.StatusOK, map[string]any{"committed": false, "diffs": safeDiffs})
			return
		}
		res, err := deps.Config.Commit(r.Context(), claims.Subject, "daidesk bulk config", configengine.CommitOptions{})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"committed": true, "revision": res.Revision.ID, "diffs": safeDiffs})
	}))

	mux.HandleFunc("/api/v1/daidesk/backup", requirePerm(secauth.PermConfigRead, func(w http.ResponseWriter, r *http.Request, claims *secauth.TokenClaims) {
		redact := deps.RBAC.Authorize(claims.Role, secauth.PermConfigReadSecrets) != nil
		b, err := ExportBackup(deps.Config, deps.Schema, deps.BackupSecret, redact, "")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, b)
	}))

	mux.HandleFunc("/api/v1/daidesk/files", requirePerm(secauth.PermConfigRead, func(w http.ResponseWriter, r *http.Request, claims *secauth.TokenClaims) {
		if deps.Files == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "file manager disabled"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			if target := r.URL.Query().Get("download"); target != "" {
				data, err := deps.Files.ReadFile(target)
				if err != nil {
					code := http.StatusNotFound
					if errors.Is(err, ErrPathTraversal) {
						code = http.StatusForbidden
					}
					writeJSON(w, code, map[string]string{"error": err.Error()})
					return
				}
				writeJSON(w, http.StatusOK, map[string]string{"path": target, "content_b64": base64.StdEncoding.EncodeToString(data)})
				return
			}
			list, err := deps.Files.ListFiles(r.URL.Query().Get("dir"))
			if err != nil {
				code := http.StatusBadRequest
				if errors.Is(err, ErrPathTraversal) {
					code = http.StatusForbidden
				}
				writeJSON(w, code, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, list)
		case http.MethodPost:
			if err := deps.RBAC.Authorize(claims.Role, secauth.PermConfigWrite); err != nil {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
				return
			}
			var req struct {
				Path       string `json:"path"`
				ContentB64 string `json:"content_b64"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 2*MaxUploadBytes)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid upload JSON"})
				return
			}
			raw, err := base64.StdEncoding.DecodeString(req.ContentB64)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid base64 payload"})
				return
			}
			if err := deps.Files.WriteAtomic(req.Path, raw); err != nil {
				code := http.StatusBadRequest
				if errors.Is(err, ErrPathTraversal) {
					code = http.StatusForbidden
				}
				writeJSON(w, code, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"uploaded": req.Path, "bytes": len(raw)})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "unsupported method"})
		}
	}))

	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
