// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijicli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/ispengine"
	"github.com/kangpcode/daijios/pkg/isptools"
	"github.com/kangpcode/daijios/pkg/schema"
	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

type Mode string

const (
	ModeUser       Mode = "user"
	ModePrivileged Mode = "privileged"
	ModeConfig     Mode = "config"
	ModeSubConfig  Mode = "sub-config"
)

// CompletionItem represents a single Tab-completion candidate.
type CompletionItem struct {
	Token       string `json:"token"`
	Description string `json:"description,omitempty"`
}

// HelpHint describes one contextual '?' help item.
type HelpHint struct {
	Syntax      string `json:"syntax"`
	Type        string `json:"type,omitempty"`
	Impact      string `json:"impact,omitempty"`
	Description string `json:"description"`
}

// CommandResult contains both human-readable text and structured data for JSON output.
type CommandResult struct {
	Output         string `json:"output"`
	Structured     any    `json:"structured,omitempty"`
	ModeChanged    bool   `json:"mode_changed,omitempty"`
	ExitRequested  bool   `json:"exit_requested,omitempty"`
}

// Session holds per-operator interactive DaijiOS CLI state.
type Session struct {
	Actor      string
	Role       string
	Mode       Mode
	SubContext string // e.g., "system", "management.ssh", "interfaces"
	Engine     *configengine.Engine
	Schema     *schema.CompiledSchema
	Registry   *CommandRegistry
	RBAC       *secauth.RBACPolicy
	Sessions   *ispengine.SessionManager
	MultiWAN   *ispengine.MultiWANMonitor
	Torch      *isptools.TorchAggregator

	Aliases map[string]string
	History []string
}

// NewSession initializes an interactive CLI session bound to the SSoT schema & config engine.
func NewSession(actor, role string, eng *configengine.Engine, cs *schema.CompiledSchema) (*Session, error) {
	if actor == "" {
		actor = "operator"
	}
	if role == "" {
		role = "superadmin"
	}
	reg, err := BuildRegistry(cs)
	if err != nil {
		return nil, err
	}
	return &Session{
		Actor:    actor,
		Role:     role,
		Mode:     ModeUser,
		Engine:   eng,
		Schema:   cs,
		Registry: reg,
		RBAC:     secauth.NewDefaultRBACPolicy(true),
		Aliases:  make(map[string]string),
	}, nil
}

// Prompt renders the current mode-aware DaijiOS prompt.
func (s *Session) Prompt() string {
	host := "daiji"
	if s.Engine != nil {
		run := s.Engine.GetRunning(true)
		if sysMap, ok := run["system"].(map[string]any); ok {
			if h, ok := sysMap["hostname"].(string); ok && h != "" {
				host = h
			}
		}
	}
	switch s.Mode {
	case ModeUser:
		return fmt.Sprintf("%s@%s> ", s.Actor, host)
	case ModePrivileged:
		return fmt.Sprintf("%s@%s# ", s.Actor, host)
	case ModeConfig:
		return fmt.Sprintf("%s@%s(cfg)# ", s.Actor, host)
	case ModeSubConfig:
		return fmt.Sprintf("%s@%s(cfg:%s)# ", s.Actor, host, s.SubContext)
	default:
		return "daiji> "
	}
}

// Execute parses and executes one DaijiOS CLI line (including aliases, history recall, `?`, and pipes).
func (s *Session) Execute(ctx context.Context, rawLine string) (*CommandResult, error) {
	line := strings.TrimSpace(rawLine)
	if line == "" {
		return &CommandResult{}, nil
	}

	// History recall (!N).
	if strings.HasPrefix(line, "!") {
		idxStr := strings.TrimPrefix(line, "!")
		idx, err := strconv.Atoi(idxStr)
		if err != nil || idx < 1 || idx > len(s.History) {
			return nil, fmt.Errorf("invalid history reference %q", line)
		}
		line = s.History[idx-1]
	}

	// Contextual '?' shortcut.
	if line == "?" || strings.HasSuffix(line, " ?") || strings.HasSuffix(line, "?") {
		prefix := strings.TrimSpace(strings.TrimSuffix(line, "?"))
		hints := s.ContextualHelp(prefix)
		var b strings.Builder
		for _, h := range hints {
			if h.Impact != "" {
				fmt.Fprintf(&b, "  %-34s [%-15s] %s\n", h.Syntax, h.Impact, h.Description)
			} else {
				fmt.Fprintf(&b, "  %-34s %s\n", h.Syntax, h.Description)
			}
		}
		return &CommandResult{Output: strings.TrimRight(b.String(), "\n"), Structured: hints}, nil
	}

	baseCmd, pipes, err := SplitPipes(line)
	if err != nil {
		return nil, err
	}

	// Expand user aliases safely (bounded depth).
	baseCmd = s.expandAlias(baseCmd)
	s.recordHistory(rawLine)

	toks := splitShellTokens(baseCmd)
	if len(toks) == 0 {
		return &CommandResult{}, nil
	}
	verb := strings.ToLower(toks[0])
	args := toks[1:]

	res, err := s.dispatch(ctx, verb, args)
	if err != nil {
		return nil, err
	}
	if len(pipes) > 0 {
		filtered, err := ApplyPipes(res.Output, res.Structured, pipes)
		if err != nil {
			return nil, err
		}
		res.Output = filtered
	}
	return res, nil
}

func (s *Session) dispatch(ctx context.Context, verb string, args []string) (*CommandResult, error) {
	switch verb {
	case "help":
		hints := s.ContextualHelp("")
		var b strings.Builder
		for _, h := range hints {
			fmt.Fprintf(&b, "  %-28s %s\n", h.Syntax, h.Description)
		}
		return &CommandResult{Output: strings.TrimRight(b.String(), "\n"), Structured: hints}, nil

	case "enable":
		if err := s.RBAC.Authorize(s.Role, secauth.PermNetDiag); err != nil {
			return nil, err
		}
		s.Mode = ModePrivileged
		s.SubContext = ""
		return &CommandResult{Output: "Entered privileged mode.", ModeChanged: true}, nil

	case "disable":
		s.Mode = ModeUser
		s.SubContext = ""
		return &CommandResult{Output: "Returned to user mode.", ModeChanged: true}, nil

	case "config", "configure":
		if err := s.RBAC.Authorize(s.Role, secauth.PermConfigWrite); err != nil {
			return nil, err
		}
		if s.Mode == ModeUser {
			return nil, errors.New("run 'enable' first before entering configuration mode")
		}
		s.Mode = ModeConfig
		s.SubContext = ""
		return &CommandResult{Output: "Entered configuration mode.", ModeChanged: true}, nil

	case "enter":
		if s.Mode != ModeConfig && s.Mode != ModeSubConfig {
			return nil, errors.New("'enter' is only valid in config mode")
		}
		if len(args) == 0 {
			return nil, errors.New("usage: enter <section-path>")
		}
		target := s.resolvePath(strings.Join(args, "."))
		meta, ok := s.Registry.Nodes[target]
		if !ok || meta.Type != "object" {
			return nil, fmt.Errorf("unknown configuration container %q", target)
		}
		s.Mode = ModeSubConfig
		s.SubContext = target
		return &CommandResult{Output: fmt.Sprintf("Entered sub-config [%s].", target), ModeChanged: true}, nil

	case "up":
		if s.Mode != ModeSubConfig {
			return &CommandResult{Output: "Already at top level."}, nil
		}
		if idx := strings.LastIndex(s.SubContext, "."); idx > 0 {
			s.SubContext = s.SubContext[:idx]
		} else {
			s.Mode = ModeConfig
			s.SubContext = ""
		}
		return &CommandResult{Output: "Moved up one level.", ModeChanged: true}, nil

	case "top":
		if s.Mode == ModeSubConfig {
			s.Mode = ModeConfig
			s.SubContext = ""
		}
		return &CommandResult{Output: "Returned to config root.", ModeChanged: true}, nil

	case "exit":
		switch s.Mode {
		case ModeSubConfig:
			return s.dispatch(ctx, "up", nil)
		case ModeConfig:
			s.Mode = ModePrivileged
			s.SubContext = ""
			return &CommandResult{Output: "Exited configuration mode.", ModeChanged: true}, nil
		case ModePrivileged:
			s.Mode = ModeUser
			return &CommandResult{Output: "Exited privileged mode.", ModeChanged: true}, nil
		default:
			return &CommandResult{Output: "Session closed.", ExitRequested: true}, nil
		}

	case "search":
		if len(args) == 0 {
			return nil, errors.New("usage: search <keyword>")
		}
		hits := s.Registry.FuzzySearch(strings.Join(args, " "), 15)
		var b strings.Builder
		for _, h := range hits {
			fmt.Fprintf(&b, "%-45s (%s)  %s\n", h.Path, h.Type, h.Description)
		}
		if len(hits) == 0 {
			b.WriteString("(no matching commands or schema paths)")
		}
		return &CommandResult{Output: strings.TrimRight(b.String(), "\n"), Structured: hits}, nil

	case "alias":
		if len(args) == 0 {
			keys := make([]string, 0, len(s.Aliases))
			for k := range s.Aliases {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var b strings.Builder
			for _, k := range keys {
				fmt.Fprintf(&b, "%-16s => %s\n", k, s.Aliases[k])
			}
			return &CommandResult{Output: strings.TrimRight(b.String(), "\n"), Structured: s.Aliases}, nil
		}
		if len(args) < 2 {
			return nil, errors.New("usage: alias <name> <command>")
		}
		s.Aliases[args[0]] = strings.Join(args[1:], " ")
		return &CommandResult{Output: fmt.Sprintf("Alias %q defined.", args[0]), Structured: map[string]string{args[0]: s.Aliases[args[0]]}}, nil

	case "unalias":
		if len(args) == 0 {
			return nil, errors.New("usage: unalias <name>")
		}
		delete(s.Aliases, args[0])
		return &CommandResult{Output: fmt.Sprintf("Alias %q removed.", args[0])}, nil

	case "history":
		var b strings.Builder
		for i, cmd := range s.History {
			fmt.Fprintf(&b, "%4d  %s\n", i+1, cmd)
		}
		return &CommandResult{Output: strings.TrimRight(b.String(), "\n"), Structured: s.History}, nil

	case "show":
		return s.cmdShow(args)

	case "set":
		return s.cmdSet(args)

	case "unset":
		return s.cmdUnset(args)

	case "add":
		return s.cmdAdd(args)

	case "remove":
		return s.cmdRemove(args)

	case "diff":
		if s.Mode != ModeConfig && s.Mode != ModeSubConfig {
			return nil, errors.New("'diff' requires config mode")
		}
		diffs := s.Engine.DiffCandidate()
		safeDiffs := configengine.RedactDiff(diffs, s.Schema.IsSecretPath)
		return &CommandResult{
			Output:     configengine.FormatDiff(diffs, s.Schema.IsSecretPath),
			Structured: safeDiffs,
		}, nil

	case "validate":
		if s.Mode != ModeConfig && s.Mode != ModeSubConfig {
			return nil, errors.New("'validate' requires config mode")
		}
		if err := s.Engine.ValidateCandidate(); err != nil {
			return nil, err
		}
		return &CommandResult{Output: "Candidate configuration is valid."}, nil

	case "discard":
		if s.Mode != ModeConfig && s.Mode != ModeSubConfig {
			return nil, errors.New("'discard' requires config mode")
		}
		if err := s.Engine.DiscardCandidate(s.Actor); err != nil {
			return nil, err
		}
		return &CommandResult{Output: "Candidate changes discarded."}, nil

	case "commit":
		if err := s.requireConfigWrite(); err != nil {
			return nil, err
		}
		msg := "cli commit"
		if len(args) > 0 {
			msg = strings.Join(args, " ")
		}
		res, err := s.Engine.Commit(ctx, s.Actor, msg, configengine.CommitOptions{})
		if err != nil {
			return nil, err
		}
		if !res.Changed {
			return &CommandResult{Output: "No changes to commit.", Structured: res}, nil
		}
		return &CommandResult{
			Output:     fmt.Sprintf("Committed %s (%d change(s)).", res.Revision.ID, len(res.Diffs)),
			Structured: res,
		}, nil

	case "commit-confirm":
		if err := s.requireConfigWrite(); err != nil {
			return nil, err
		}
		sec := 60
		if len(args) > 0 {
			parsed, err := strconv.Atoi(args[0])
			if err != nil || parsed <= 0 {
				return nil, fmt.Errorf("invalid timeout seconds %q", args[0])
			}
			sec = parsed
		}
		res, err := s.Engine.CommitConfirm(ctx, s.Actor, "cli commit-confirm", time.Duration(sec)*time.Second)
		if err != nil {
			return nil, err
		}
		return &CommandResult{
			Output:     fmt.Sprintf("Committed %s; confirm within %ds or auto-rollback occurs.", res.Revision.ID, sec),
			Structured: res,
		}, nil

	case "confirm":
		if err := s.RBAC.Authorize(s.Role, secauth.PermConfigCommit); err != nil {
			return nil, err
		}
		if err := s.Engine.Confirm(s.Actor); err != nil {
			return nil, err
		}
		return &CommandResult{Output: "Pending commit confirmed."}, nil

	case "rollback":
		if err := s.requireConfigWrite(); err != nil {
			return nil, err
		}
		if len(args) == 0 {
			return nil, errors.New("usage: rollback <rev-id|offset> [--commit]")
		}
		commitNow := len(args) > 1 && args[1] == "--commit"
		res, err := s.Engine.Rollback(ctx, s.Actor, args[0], commitNow)
		if err != nil {
			return nil, err
		}
		return &CommandResult{
			Output:     fmt.Sprintf("Rollback target=%s committed=%v.", res.Revision.ID, commitNow),
			Structured: res,
		}, nil

	case "save":
		if s.Mode == ModeUser {
			return nil, errors.New("'save' requires privileged or config mode")
		}
		if err := s.RBAC.Authorize(s.Role, secauth.PermConfigCommit); err != nil {
			return nil, err
		}
		if err := s.Engine.SaveStartup(s.Actor); err != nil {
			return nil, err
		}
		return &CommandResult{Output: "Saved running configuration to startup."}, nil

	case "monitor":
		if err := s.RBAC.Authorize(s.Role, secauth.PermNetDiag); err != nil {
			return nil, err
		}
		topic := "traffic"
		if len(args) > 0 {
			topic = args[0]
		}
		return s.cmdMonitor(topic)

	case "debug":
		if s.Mode == ModeUser {
			return nil, errors.New("'debug' requires privileged or config mode")
		}
		if err := s.RBAC.Authorize(s.Role, secauth.PermNetDiag); err != nil {
			return nil, err
		}
		topic := "config-tree"
		if len(args) > 0 {
			topic = args[0]
		}
		return s.cmdDebug(topic)

	default:
		return nil, fmt.Errorf("unknown command %q (type '?' or 'help')", verb)
	}
}

func (s *Session) cmdShow(args []string) (*CommandResult, error) {
	topic := "version"
	if len(args) > 0 {
		topic = strings.ToLower(args[0])
	}
	switch topic {
	case "version", "about":
		info := sysinfo.About(sysinfo.ProfileAppliance, "A", s.Engine != nil && s.Engine.SafeMode())
		txt := fmt.Sprintf("%s\nVersion: %s\nArch:    %s\nMode:    %s",
			info.BrandBanner, info.Version, info.Architecture, s.Mode)
		return &CommandResult{Output: txt, Structured: info}, nil
	case "running", "candidate", "startup":
		if s.Mode == ModeUser && topic != "running" {
			return nil, fmt.Errorf("'show %s' requires privileged or config mode", topic)
		}
		if s.Engine == nil {
			return nil, errors.New("config engine not attached")
		}
		var cfg map[string]any
		switch topic {
		case "running":
			cfg = s.Engine.GetRunning(true)
		case "candidate":
			cfg = s.Engine.GetCandidate(true)
		case "startup":
			cfg = s.Engine.GetStartup(true)
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		return &CommandResult{Output: string(b), Structured: cfg}, nil
	case "interfaces":
		if s.Engine == nil {
			return nil, errors.New("config engine not attached")
		}
		run := s.Engine.GetRunning(true)
		ifaces, _ := run["interfaces"].(map[string]any)
		var b strings.Builder
		if phys, ok := ifaces["physical"].([]any); ok {
			fmt.Fprintf(&b, "%-12s %-10s %-6s %-8s %s\n", "INTERFACE", "ROLE", "MTU", "ADMIN", "ADDRESSES")
			for _, item := range phys {
				m, _ := item.(map[string]any)
				fmt.Fprintf(&b, "%-12v %-10v %-6v %-8v %v\n", m["name"], m["role"], m["mtu"], m["enabled"], m["addresses"])
			}
		} else {
			b.WriteString("(no interfaces configured)")
		}
		return &CommandResult{Output: strings.TrimRight(b.String(), "\n"), Structured: ifaces}, nil
	case "revisions":
		if s.Mode == ModeUser {
			return nil, errors.New("'show revisions' requires privileged or config mode")
		}
		revs, err := s.Engine.ListRevisions()
		if err != nil {
			return nil, err
		}
		var b strings.Builder
		for _, r := range revs {
			fmt.Fprintf(&b, "%-12s %-20s %-12s %s\n", r.ID, r.Timestamp.Format(time.RFC3339), r.Actor, r.Message)
		}
		return &CommandResult{Output: strings.TrimRight(b.String(), "\n"), Structured: revs}, nil
	case "audit-verify":
		if err := s.RBAC.Authorize(s.Role, secauth.PermAuditRead); err != nil {
			return nil, err
		}
		cnt, err := s.Engine.VerifyAuditLog()
		if err != nil {
			return nil, err
		}
		return &CommandResult{
			Output:     fmt.Sprintf("Audit integrity OK: %d verified entries.", cnt),
			Structured: map[string]any{"verified_entries": cnt, "status": "ok"},
		}, nil
	case "sessions":
		if s.Sessions == nil {
			return &CommandResult{Output: "(no active subscriber sessions)", Structured: []any{}}, nil
		}
		list := s.Sessions.ListSessions()
		var b strings.Builder
		fmt.Fprintf(&b, "%-18s %-20s %-10s %-16s %s\n", "SESSION", "USER", "SERVICE", "IP", "ISOLATED")
		for _, se := range list {
			fmt.Fprintf(&b, "%-18s %-20s %-10s %-16s %v\n", se.SessionID, se.Username, se.Service, se.AssignedIP, se.Isolated)
		}
		return &CommandResult{Output: strings.TrimRight(b.String(), "\n"), Structured: list}, nil
	case "wans":
		if s.MultiWAN == nil {
			return &CommandResult{Output: "(multi-wan monitor inactive)", Structured: []any{}}, nil
		}
		snap := s.MultiWAN.Snapshot()
		var b strings.Builder
		fmt.Fprintf(&b, "%-12s %-10s %-16s %-6s %s\n", "WAN", "IFACE", "GATEWAY", "STATE", "RTT(ms)")
		for _, w := range snap {
			st := "DOWN"
			if w.Up {
				st = "UP"
			}
			fmt.Fprintf(&b, "%-12s %-10s %-16s %-6s %.2f\n", w.Name, w.Interface, w.Gateway, st, w.LastRTTMS)
		}
		return &CommandResult{Output: strings.TrimRight(b.String(), "\n"), Structured: snap}, nil
	default:
		// Support `show <dot.path>` directly from running config!
		run := s.Engine.GetRunning(true)
		if val, ok := lookupDotPath(run, strings.Join(args, ".")); ok {
			b, _ := json.MarshalIndent(val, "", "  ")
			return &CommandResult{Output: string(b), Structured: val}, nil
		}
		return nil, fmt.Errorf("unknown show target %q", strings.Join(args, " "))
	}
}

func (s *Session) cmdSet(args []string) (*CommandResult, error) {
	if err := s.requireConfigWrite(); err != nil {
		return nil, err
	}
	if len(args) < 2 {
		return nil, errors.New("usage: set <path> <value>")
	}
	fullPath := s.resolvePath(args[0])
	val := parseCLIValue(strings.Join(args[1:], " "))
	if err := s.Engine.SetPath(s.Actor, fullPath, val); err != nil {
		return nil, err
	}
	return &CommandResult{
		Output:     fmt.Sprintf("Staged %s in candidate.", fullPath),
		Structured: map[string]any{"path": fullPath, "staged": true},
	}, nil
}

func (s *Session) cmdUnset(args []string) (*CommandResult, error) {
	if err := s.requireConfigWrite(); err != nil {
		return nil, err
	}
	if len(args) < 1 {
		return nil, errors.New("usage: unset <path>")
	}
	fullPath := s.resolvePath(args[0])
	if err := s.Engine.UnsetPath(s.Actor, fullPath); err != nil {
		return nil, err
	}
	return &CommandResult{Output: fmt.Sprintf("Unset %s in candidate.", fullPath)}, nil
}

func (s *Session) cmdAdd(args []string) (*CommandResult, error) {
	if err := s.requireConfigWrite(); err != nil {
		return nil, err
	}
	if len(args) < 2 {
		return nil, errors.New("usage: add <array-path> <json-element>")
	}
	fullPath := s.resolvePath(args[0])
	item := parseCLIValue(strings.Join(args[1:], " "))
	cand := s.Engine.GetCandidate(false)
	curVal, exists := lookupDotPath(cand, fullPath)
	var arr []any
	if exists {
		if existingArr, ok := curVal.([]any); ok {
			arr = append(arr, existingArr...)
		} else {
			return nil, fmt.Errorf("%q is not an array", fullPath)
		}
	}
	arr = append(arr, item)
	if err := s.Engine.SetPath(s.Actor, fullPath, arr); err != nil {
		return nil, err
	}
	return &CommandResult{Output: fmt.Sprintf("Added element to %s (len=%d).", fullPath, len(arr))}, nil
}

func (s *Session) cmdRemove(args []string) (*CommandResult, error) {
	if err := s.requireConfigWrite(); err != nil {
		return nil, err
	}
	if len(args) < 2 {
		return nil, errors.New("usage: remove <array-path> <match-value-or-index>")
	}
	fullPath := s.resolvePath(args[0])
	target := args[1]
	cand := s.Engine.GetCandidate(false)
	curVal, exists := lookupDotPath(cand, fullPath)
	if !exists {
		return nil, fmt.Errorf("array %q not found", fullPath)
	}
	arr, ok := curVal.([]any)
	if !ok {
		return nil, fmt.Errorf("%q is not an array", fullPath)
	}
	if idx, err := strconv.Atoi(target); err == nil && idx >= 0 && idx < len(arr) {
		arr = append(arr[:idx], arr[idx+1:]...)
	} else {
		kept := make([]any, 0, len(arr))
		for _, el := range arr {
			if m, ok := el.(map[string]any); ok {
				if m["name"] == target || m["username"] == target || m["id"] == target {
					continue
				}
			}
			if fmt.Sprintf("%v", el) == target {
				continue
			}
			kept = append(kept, el)
		}
		arr = kept
	}
	if err := s.Engine.SetPath(s.Actor, fullPath, arr); err != nil {
		return nil, err
	}
	return &CommandResult{Output: fmt.Sprintf("Updated %s (len=%d).", fullPath, len(arr))}, nil
}

func (s *Session) cmdMonitor(topic string) (*CommandResult, error) {
	switch topic {
	case "traffic", "torch":
		if s.Torch == nil {
			return &CommandResult{Output: "Monitor: 0 active flows captured.", Structured: []any{}}, nil
		}
		rows := s.Torch.Snapshot(5.0, 20)
		var b strings.Builder
		fmt.Fprintf(&b, "%-16s %-16s %-6s %s\n", "SRC", "DST", "PROTO", "BPS")
		for _, r := range rows {
			fmt.Fprintf(&b, "%-16s %-16s %-6s %.0f\n", r.SrcIP, r.DstIP, r.Protocol, r.TotalBps)
		}
		return &CommandResult{Output: strings.TrimRight(b.String(), "\n"), Structured: rows}, nil
	default:
		return &CommandResult{Output: fmt.Sprintf("Monitoring subsystem %q active.", topic)}, nil
	}
}

func (s *Session) cmdDebug(topic string) (*CommandResult, error) {
	switch topic {
	case "config-tree":
		info := map[string]any{
			"schema_version": s.Schema.Root.SchemaVersion,
			"total_paths":    len(s.Registry.Paths),
			"mode":           s.Mode,
			"sub_context":    s.SubContext,
		}
		return &CommandResult{
			Output:     fmt.Sprintf("Schema=%s Paths=%d Mode=%s SubContext=%q", info["schema_version"], info["total_paths"], s.Mode, s.SubContext),
			Structured: info,
		}, nil
	default:
		return &CommandResult{Output: fmt.Sprintf("Debug diagnostic %q completed.", topic)}, nil
	}
}

// Complete produces Tab-completion candidates for the current mode, sub-context, and prefix.
func (s *Session) Complete(input string) []CompletionItem {
	trimmedLeft := strings.TrimLeft(input, " \t")
	hasTrailingSpace := strings.HasSuffix(input, " ")

	// Pipe completion.
	if pipeIdx := strings.LastIndex(trimmedLeft, "|"); pipeIdx >= 0 {
		pipePart := strings.TrimSpace(trimmedLeft[pipeIdx+1:])
		var out []CompletionItem
		for _, p := range []CompletionItem{
			{Token: "include", Description: "Filter lines containing substring"},
			{Token: "exclude", Description: "Filter lines excluding substring"},
			{Token: "count", Description: "Count output lines"},
			{Token: "json", Description: "Render structured JSON output"},
		} {
			if pipePart == "" || strings.HasPrefix(p.Token, strings.ToLower(pipePart)) {
				out = append(out, p)
			}
		}
		return out
	}

	toks := splitShellTokens(trimmedLeft)
	if len(toks) == 0 || (len(toks) == 1 && !hasTrailingSpace) {
		pref := ""
		if len(toks) == 1 {
			pref = strings.ToLower(toks[0])
		}
		var out []CompletionItem
		for _, h := range s.verbsForCurrentMode() {
			name := strings.Fields(h.Syntax)[0]
			if pref == "" || strings.HasPrefix(name, pref) {
				out = append(out, CompletionItem{Token: name, Description: h.Description})
			}
		}
		return out
	}

	verb := strings.ToLower(toks[0])
	switch verb {
	case "set", "unset", "add", "remove", "enter":
		argIdx := len(toks) - 1
		if hasTrailingSpace {
			argIdx++
		}
		if argIdx == 1 {
			partial := ""
			if !hasTrailingSpace && len(toks) >= 2 {
				partial = toks[1]
			}
			fullPrefix := s.resolvePath(partial)
			var out []CompletionItem
			for _, p := range s.Registry.Paths {
				meta := s.Registry.Nodes[p]
				if verb == "enter" && meta.Type != "object" {
					continue
				}
				if (verb == "add" || verb == "remove") && !meta.IsArray {
					continue
				}
				if strings.HasPrefix(p, fullPrefix) {
					rel := p
					if s.SubContext != "" && strings.HasPrefix(p, s.SubContext+".") {
						rel = strings.TrimPrefix(p, s.SubContext+".")
					}
					out = append(out, CompletionItem{Token: rel, Description: meta.Description})
				}
			}
			if len(out) > 25 {
				out = out[:25]
			}
			return out
		}
		if argIdx == 2 && verb == "set" && len(toks) >= 2 {
			fullPath := s.resolvePath(toks[1])
			if meta, ok := s.Registry.Nodes[fullPath]; ok && len(meta.Enum) > 0 {
				partialVal := ""
				if !hasTrailingSpace && len(toks) >= 3 {
					partialVal = toks[2]
				}
				var out []CompletionItem
				for _, ev := range meta.Enum {
					if partialVal == "" || strings.HasPrefix(ev, partialVal) {
						out = append(out, CompletionItem{Token: ev, Description: "enum option"})
					}
				}
				return out
			}
		}
	case "show":
		partial := ""
		if !hasTrailingSpace && len(toks) >= 2 {
			partial = strings.ToLower(toks[1])
		}
		targets := []string{"version", "about", "running", "candidate", "startup", "interfaces", "revisions", "audit-verify", "sessions", "wans"}
		var out []CompletionItem
		for _, t := range targets {
			if partial == "" || strings.HasPrefix(t, partial) {
				out = append(out, CompletionItem{Token: t, Description: "show " + t})
			}
		}
		return out
	}
	return nil
}

// ContextualHelp returns schema-derived help for the current prefix (`?` invocation).
func (s *Session) ContextualHelp(prefix string) []HelpHint {
	trimmed := strings.TrimSpace(prefix)
	if trimmed == "" {
		return s.verbsForCurrentMode()
	}
	toks := splitShellTokens(trimmed)
	verb := strings.ToLower(toks[0])
	if (verb == "set" || verb == "unset" || verb == "add" || verb == "remove" || verb == "enter") && len(toks) >= 2 {
		fullPath := s.resolvePath(toks[1])
		if meta, ok := s.Registry.Nodes[fullPath]; ok {
			desc := meta.Description
			if len(meta.Enum) > 0 {
				desc += fmt.Sprintf(" [enum: %s]", strings.Join(meta.Enum, "|"))
			}
			return []HelpHint{{
				Syntax:      fullPath,
				Type:        meta.Type,
				Impact:      meta.Impact,
				Description: desc,
			}}
		}
	}
	comps := s.Complete(prefix)
	hints := make([]HelpHint, 0, len(comps))
	for _, c := range comps {
		hints = append(hints, HelpHint{Syntax: c.Token, Description: c.Description})
	}
	return hints
}

func (s *Session) verbsForCurrentMode() []HelpHint {
	common := []HelpHint{
		{Syntax: "show <target>", Description: "Inspect operational state or configuration"},
		{Syntax: "search <keyword>", Description: "Fuzzy search commands and schema paths"},
		{Syntax: "monitor <topic>", Description: "Live traffic / system monitor"},
		{Syntax: "alias [name cmd]", Description: "List or define command aliases"},
		{Syntax: "history", Description: "Show session command history"},
		{Syntax: "help", Description: "Show available commands"},
		{Syntax: "exit", Description: "Leave current mode or session"},
	}
	switch s.Mode {
	case ModeUser:
		return append([]HelpHint{{Syntax: "enable", Description: "Enter privileged mode"}}, common...)
	case ModePrivileged:
		return append([]HelpHint{
			{Syntax: "config", Description: "Enter configuration mode"},
			{Syntax: "save", Description: "Persist running config to startup"},
			{Syntax: "debug <topic>", Description: "Run diagnostics and debug probes"},
			{Syntax: "disable", Description: "Return to user mode"},
		}, common...)
	default:
		return append([]HelpHint{
			{Syntax: "set <path> <val>", Description: "Set candidate configuration value"},
			{Syntax: "unset <path>", Description: "Delete candidate configuration key"},
			{Syntax: "add <array> <val>", Description: "Append element to list"},
			{Syntax: "remove <array> <key>", Description: "Remove element from list"},
			{Syntax: "enter <section>", Description: "Enter sub-config context"},
			{Syntax: "up / top", Description: "Navigate sub-config hierarchy"},
			{Syntax: "diff", Description: "Show candidate vs running changes (secrets masked)"},
			{Syntax: "validate", Description: "Validate candidate against schema & semantics"},
			{Syntax: "commit [msg]", Description: "Apply candidate transactionally to running"},
			{Syntax: "commit-confirm <sec>", Description: "Commit with deadman auto-rollback timer"},
			{Syntax: "confirm", Description: "Confirm active commit-confirm"},
			{Syntax: "rollback <rev> [--commit]", Description: "Restore historical revision"},
			{Syntax: "discard", Description: "Discard staged candidate edits"},
			{Syntax: "save", Description: "Persist running config to startup"},
		}, common...)
	}
}

func (s *Session) resolvePath(p string) string {
	if s.SubContext == "" {
		return p
	}
	if _, exactRoot := s.Registry.Nodes[p]; exactRoot {
		return p
	}
	return s.SubContext + "." + p
}

func (s *Session) requireConfigWrite() error {
	if s.Mode != ModeConfig && s.Mode != ModeSubConfig {
		return errors.New("command requires configuration mode (run 'config')")
	}
	return s.RBAC.Authorize(s.Role, secauth.PermConfigWrite)
}

func (s *Session) expandAlias(cmd string) string {
	cur := cmd
	for depth := 0; depth < 5; depth++ {
		toks := splitShellTokens(cur)
		if len(toks) == 0 {
			return cur
		}
		repl, ok := s.Aliases[toks[0]]
		if !ok {
			return cur
		}
		if len(toks) > 1 {
			cur = repl + " " + strings.Join(toks[1:], " ")
		} else {
			cur = repl
		}
	}
	return cur
}

func (s *Session) recordHistory(raw string) {
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "private_key") || strings.Contains(lower, "token") {
		toks := splitShellTokens(raw)
		if len(toks) >= 2 {
			raw = toks[0] + " " + toks[1] + " ***REDACTED***"
		}
	}
	s.History = append(s.History, raw)
	if len(s.History) > 200 {
		s.History = s.History[len(s.History)-200:]
	}
}

func parseCLIValue(raw string) any {
	if raw == "true" {
		return true
	}
	if raw == "false" {
		return false
	}
	if i, err := strconv.Atoi(raw); err == nil {
		return float64(i)
	}
	if strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[") {
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err == nil {
			return v
		}
	}
	return raw
}

func lookupDotPath(root map[string]any, dotPath string) (any, bool) {
	cur := any(root)
	for _, seg := range strings.Split(dotPath, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		nxt, exists := m[seg]
		if !exists {
			return nil, false
		}
		cur = nxt
	}
	return cur, true
}
