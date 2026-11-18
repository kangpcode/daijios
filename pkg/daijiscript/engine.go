// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package daijiscript implements the sandboxed DaijiScript automation DSL,
// interval scheduler, event-hook bus, HMAC-SHA256 signed webhook dispatcher,
// and authenticated REST API handler for DaijiOS.
package daijiscript

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kangpcode/daijios/pkg/ispplan"
)

var (
	ErrPermissionDenied = errors.New("script lacks required DaijiScript permission")
	ErrStepLimit        = errors.New("DaijiScript exceeded maximum execution step limit")
	ErrWebhookSSRF      = errors.New("webhook URL blocked by SSRF protection")
)

// ScriptHostCallbacks binds DaijiScript built-in actions safely to DaijiOS subsystems.
type ScriptHostCallbacks struct {
	OnLog         func(msg string)
	OnSetConfig   func(dotPath, value string) error
	OnKickPPPoE   func(target string) error
	OnSetWANState func(wanName string, enabled bool) error
	OnEmitWebhook func(ctx context.Context, webhookName, event string, data map[string]any) error
}

// ExecutionResult captures logs and action counts from running one DaijiScript.
type ExecutionResult struct {
	ScriptName string   `json:"script_name"`
	Steps      int      `json:"steps"`
	Logs       []string `json:"logs"`
}

// RunScript executes a sandboxed DaijiScript within bounded steps and explicit permissions.
func RunScript(ctx context.Context, def ispplan.DaijiScriptDef, env map[string]string, host ScriptHostCallbacks) (*ExecutionResult, error) {
	if !def.Enabled {
		return &ExecutionResult{ScriptName: def.Name}, nil
	}
	timeout := time.Duration(def.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	perms := make(map[string]bool, len(def.Permissions))
	for _, p := range def.Permissions {
		perms[p] = true
	}
	vars := make(map[string]string, len(env))
	for k, v := range env {
		vars[k] = v
	}

	lines := strings.Split(def.Source, "\n")
	res := &ExecutionResult{ScriptName: def.Name}
	const maxSteps = 1000

	// Stack tracks active conditional blocks: true means execute current branch.
	condStack := []bool{true}
	isActive := func() bool {
		for _, ok := range condStack {
			if !ok {
				return false
			}
		}
		return true
	}

	for _, rawLine := range lines {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		res.Steps++
		if res.Steps > maxSteps {
			return res, ErrStepLimit
		}

		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		tokens := splitArgs(line)
		if len(tokens) == 0 {
			continue
		}
		op := tokens[0]

		switch op {
		case "if":
			condOK := evaluateCond(tokens[1:], vars)
			condStack = append(condStack, condOK)
			continue
		case "else":
			if len(condStack) <= 1 {
				return res, errors.New("unexpected 'else' without matching 'if'")
			}
			condStack[len(condStack)-1] = !condStack[len(condStack)-1]
			continue
		case "endif":
			if len(condStack) <= 1 {
				return res, errors.New("unexpected 'endif' without matching 'if'")
			}
			condStack = condStack[:len(condStack)-1]
			continue
		}

		if !isActive() {
			continue
		}

		switch op {
		case "let":
			// Syntax: let var = "value"
			if len(tokens) < 4 || tokens[2] != "=" {
				return res, fmt.Errorf("invalid let syntax: %q", line)
			}
			vars[tokens[1]] = resolveToken(tokens[3], vars)
		case "log":
			msg := strings.TrimPrefix(line, "log")
			msg = strings.TrimSpace(msg)
			msg = unquote(resolveToken(msg, vars))
			res.Logs = append(res.Logs, msg)
			if host.OnLog != nil {
				host.OnLog(msg)
			}
		case "set_config":
			if !perms["write"] {
				return res, fmt.Errorf("%w: set_config requires 'write'", ErrPermissionDenied)
			}
			if len(tokens) < 3 {
				return res, fmt.Errorf("set_config requires <path> <value>")
			}
			if host.OnSetConfig != nil {
				if err := host.OnSetConfig(tokens[1], resolveToken(tokens[2], vars)); err != nil {
					return res, err
				}
			}
		case "kick_pppoe":
			if !perms["net"] {
				return res, fmt.Errorf("%w: kick_pppoe requires 'net'", ErrPermissionDenied)
			}
			if len(tokens) < 2 {
				return res, errors.New("kick_pppoe requires target username/session")
			}
			if host.OnKickPPPoE != nil {
				if err := host.OnKickPPPoE(resolveToken(tokens[1], vars)); err != nil {
					return res, err
				}
			}
		case "enable_wan", "disable_wan":
			if !perms["net"] {
				return res, fmt.Errorf("%w: %s requires 'net'", ErrPermissionDenied, op)
			}
			if len(tokens) < 2 {
				return res, fmt.Errorf("%s requires WAN name", op)
			}
			if host.OnSetWANState != nil {
				if err := host.OnSetWANState(resolveToken(tokens[1], vars), op == "enable_wan"); err != nil {
					return res, err
				}
			}
		case "emit_webhook":
			if !perms["net"] && !perms["read"] {
				return res, fmt.Errorf("%w: emit_webhook requires 'net' or 'read'", ErrPermissionDenied)
			}
			if len(tokens) < 3 {
				return res, errors.New("emit_webhook requires <webhook> <event>")
			}
			if host.OnEmitWebhook != nil {
				payload := map[string]any{"script": def.Name, "vars": vars}
				if err := host.OnEmitWebhook(ctx, resolveToken(tokens[1], vars), resolveToken(tokens[2], vars), payload); err != nil {
					return res, err
				}
			}
		default:
			return res, fmt.Errorf("unknown DaijiScript instruction %q", op)
		}
	}
	return res, nil
}

// WebhookDispatcher sends HMAC-SHA256 signed webhook HTTP POST events with SSRF protection.
type WebhookDispatcher struct {
	Client               *http.Client
	AllowLoopbackForTest bool
}

func (w *WebhookDispatcher) Dispatch(ctx context.Context, target ispplan.WebhookTarget, event string, data map[string]any) error {
	if !target.Enabled {
		return nil
	}
	if err := validateWebhookURL(target.URL, w.AllowLoopbackForTest); err != nil {
		return err
	}
	bodyObj := map[string]any{
		"event":     event,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"payload":   data,
	}
	body, err := json.Marshal(bodyObj)
	if err != nil {
		return err
	}

	mac := hmac.New(sha256.New, []byte(target.Secret))
	_, _ = mac.Write(body)
	sigHex := hex.EncodeToString(mac.Sum(nil))

	timeout := time.Duration(target.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	attempts := target.RetryCount + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "DaijiOS-Webhook/1.0")
		req.Header.Set("X-Daiji-Event", event)
		req.Header.Set("X-Daiji-Signature", "sha256="+sigHex)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return lastErr
}

func validateWebhookURL(rawURL string, allowLoopback bool) error {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return fmt.Errorf("%w: invalid url %q", ErrWebhookSSRF, rawURL)
	}
	host := strings.ToLower(u.Hostname())
	if host == "metadata.google.internal" {
		return fmt.Errorf("%w: cloud metadata host blocked", ErrWebhookSSRF)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("%w: link-local/multicast IP %s blocked", ErrWebhookSSRF, ip)
		}
		if ip.IsLoopback() && !allowLoopback {
			return fmt.Errorf("%w: loopback IP %s blocked", ErrWebhookSSRF, ip)
		}
	}
	return nil
}

// AutomationEngine orchestrates scheduled DaijiScripts and event hooks.
type AutomationEngine struct {
	mu       sync.Mutex
	scripts  map[string]ispplan.DaijiScriptDef
	webhooks map[string]ispplan.WebhookTarget
	hooks    []ispplan.EventHook
	scheds   []ispplan.ScriptSchedule
	lastRun  map[string]time.Time
	host     ScriptHostCallbacks
	disp     *WebhookDispatcher
}

func NewAutomationEngine(cfg ispplan.AutomationBlock, host ScriptHostCallbacks, disp *WebhookDispatcher) *AutomationEngine {
	if disp == nil {
		disp = &WebhookDispatcher{}
	}
	ae := &AutomationEngine{
		scripts:  make(map[string]ispplan.DaijiScriptDef),
		webhooks: make(map[string]ispplan.WebhookTarget),
		hooks:    append([]ispplan.EventHook(nil), cfg.EventHooks...),
		scheds:   append([]ispplan.ScriptSchedule(nil), cfg.Schedules...),
		lastRun:  make(map[string]time.Time),
		host:     host,
		disp:     disp,
	}
	for _, s := range cfg.Scripts {
		ae.scripts[s.Name] = s
	}
	for _, w := range cfg.Webhooks {
		ae.webhooks[w.Name] = w
	}
	if ae.host.OnEmitWebhook == nil {
		ae.host.OnEmitWebhook = func(ctx context.Context, whName, ev string, data map[string]any) error {
			ae.mu.Lock()
			wh, ok := ae.webhooks[whName]
			ae.mu.Unlock()
			if !ok {
				return fmt.Errorf("webhook %q not found", whName)
			}
			return ae.disp.Dispatch(ctx, wh, ev, data)
		}
	}
	return ae
}

// Tick evaluates scheduled scripts at timestamp now.
func (ae *AutomationEngine) Tick(ctx context.Context, now time.Time) ([]ExecutionResult, error) {
	ae.mu.Lock()
	var due []ispplan.ScriptSchedule
	for _, sch := range ae.scheds {
		if !sch.Enabled {
			continue
		}
		last, ran := ae.lastRun[sch.Name]
		if !ran || now.Sub(last) >= time.Duration(sch.IntervalSec)*time.Second {
			due = append(due, sch)
			ae.lastRun[sch.Name] = now
		}
	}
	ae.mu.Unlock()

	var results []ExecutionResult
	for _, sch := range due {
		ae.mu.Lock()
		sc, ok := ae.scripts[sch.ScriptName]
		ae.mu.Unlock()
		if !ok {
			continue
		}
		res, err := RunScript(ctx, sc, map[string]string{"schedule": sch.Name}, ae.host)
		if err != nil {
			return results, err
		}
		results = append(results, *res)
	}
	return results, nil
}

// TriggerEvent runs matching event_hooks (script and/or webhook) for eventName.
func (ae *AutomationEngine) TriggerEvent(ctx context.Context, eventName string, vars map[string]string) error {
	ae.mu.Lock()
	hooks := append([]ispplan.EventHook(nil), ae.hooks...)
	ae.mu.Unlock()

	for _, h := range hooks {
		if !h.Enabled || h.Event != eventName {
			continue
		}
		if h.ScriptName != "" {
			ae.mu.Lock()
			sc, ok := ae.scripts[h.ScriptName]
			ae.mu.Unlock()
			if ok {
				if _, err := RunScript(ctx, sc, vars, ae.host); err != nil {
					return err
				}
			}
		}
		if h.WebhookName != "" {
			ae.mu.Lock()
			wh, ok := ae.webhooks[h.WebhookName]
			ae.mu.Unlock()
			if ok {
				data := map[string]any{"hook": h.Name, "vars": vars}
				if err := ae.disp.Dispatch(ctx, wh, eventName, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func splitArgs(line string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' {
			inQuote = !inQuote
			cur.WriteByte(c)
			continue
		}
		if !inQuote && (c == ' ' || c == '\t') {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func resolveToken(tok string, vars map[string]string) string {
	if strings.HasPrefix(tok, "$") {
		if v, ok := vars[strings.TrimPrefix(tok, "$")]; ok {
			return v
		}
	}
	return unquote(tok)
}

func evaluateCond(tokens []string, vars map[string]string) bool {
	if len(tokens) < 3 {
		return false
	}
	left := resolveToken(tokens[0], vars)
	op := tokens[1]
	right := resolveToken(tokens[2], vars)
	switch op {
	case "==":
		return left == right
	case "!=":
		return left != right
	default:
		return false
	}
}
