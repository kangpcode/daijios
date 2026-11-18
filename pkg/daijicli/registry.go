// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package daijicli implements the original DaijiOS CLI engine derived directly
// from the Single Source of Truth schema (schema/daijios.schema.json):
// hierarchical modes (user/privileged/config/sub-config), tab-completion,
// '?' contextual help, fuzzy search, command history, aliases, output pipes,
// and dual human-readable/JSON formatting.
package daijicli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kangpcode/daijios/pkg/schema"
)

// SchemaNodeMeta describes one addressable configuration leaf or container in the CLI tree.
type SchemaNodeMeta struct {
	DotPath     string   `json:"dot_path"`
	CLIPath     string   `json:"cli_path,omitempty"`
	Type        string   `json:"type"`
	Format      string   `json:"format,omitempty"`
	Enum        []string `json:"enum,omitempty"`
	Default     any      `json:"default,omitempty"`
	Secret      bool     `json:"secret,omitempty"`
	RBAC        string   `json:"rbac,omitempty"`
	Impact      string   `json:"impact,omitempty"`
	Description string   `json:"description,omitempty"`
	IsArray     bool     `json:"is_array,omitempty"`
	Children    []string `json:"children,omitempty"`
}

// CommandRegistry holds the full schema-derived CLI path catalog and static verb specs.
type CommandRegistry struct {
	Nodes map[string]SchemaNodeMeta
	Paths []string
}

// BuildRegistry walks cs (SSoT schema) to produce a synchronized CLI command & path schema.
func BuildRegistry(cs *schema.CompiledSchema) (*CommandRegistry, error) {
	if cs == nil || cs.Root == nil {
		return nil, fmt.Errorf("compiled schema is required")
	}
	reg := &CommandRegistry{
		Nodes: make(map[string]SchemaNodeMeta),
	}
	if err := walkSchemaNode(cs, cs.Root, "", reg, 0); err != nil {
		return nil, err
	}
	sort.Strings(reg.Paths)
	return reg, nil
}

func walkSchemaNode(cs *schema.CompiledSchema, n *schema.Node, dotPath string, reg *CommandRegistry, depth int) error {
	if n == nil || depth > 24 {
		return nil
	}
	eff, err := resolveEffective(cs.Root, n, 0)
	if err != nil {
		return err
	}

	if dotPath != "" {
		var enumStrs []string
		for _, ev := range eff.Enum {
			enumStrs = append(enumStrs, fmt.Sprintf("%v", ev))
		}
		var children []string
		for k := range eff.Properties {
			children = append(children, k)
		}
		sort.Strings(children)
		reg.Nodes[dotPath] = SchemaNodeMeta{
			DotPath:     dotPath,
			CLIPath:     eff.CLIPath,
			Type:        eff.Type,
			Format:      eff.Format,
			Enum:        enumStrs,
			Default:     eff.Default,
			Secret:      eff.Secret,
			RBAC:        eff.RBAC,
			Impact:      eff.Impact,
			Description: eff.Description,
			IsArray:     eff.Type == "array",
			Children:    children,
		}
		reg.Paths = append(reg.Paths, dotPath)
	}

	keys := make([]string, 0, len(eff.Properties))
	for k := range eff.Properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		childPath := k
		if dotPath != "" {
			childPath = dotPath + "." + k
		}
		if err := walkSchemaNode(cs, eff.Properties[k], childPath, reg, depth+1); err != nil {
			return err
		}
	}
	if eff.Items != nil && dotPath != "" {
		if err := walkSchemaNode(cs, eff.Items, dotPath+"[*]", reg, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func resolveEffective(root, n *schema.Node, depth int) (*schema.Node, error) {
	if n == nil || n.Ref == "" {
		return n, nil
	}
	if depth > 16 {
		return nil, fmt.Errorf("$ref cycle at %q", n.Ref)
	}
	const pfx = "#/$defs/"
	if !strings.HasPrefix(n.Ref, pfx) {
		return n, nil
	}
	target, ok := root.Defs[strings.TrimPrefix(n.Ref, pfx)]
	if !ok {
		return n, nil
	}
	resolved, err := resolveEffective(root, target, depth+1)
	if err != nil {
		return nil, err
	}
	merged := *resolved
	if n.Description != "" {
		merged.Description = n.Description
	}
	if n.Default != nil {
		merged.Default = n.Default
	}
	if n.CLIPath != "" {
		merged.CLIPath = n.CLIPath
	}
	if n.Secret {
		merged.Secret = true
	}
	if n.RBAC != "" {
		merged.RBAC = n.RBAC
	}
	if n.Impact != "" {
		merged.Impact = n.Impact
	}
	return &merged, nil
}

// FuzzyResult represents one ranked fuzzy search match across CLI paths & verbs.
type FuzzyResult struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Score       int    `json:"score"`
}

// FuzzySearch finds schema paths matching query using substring and ordered subsequence scoring.
func (r *CommandRegistry) FuzzySearch(query string, limit int) []FuzzyResult {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	var hits []FuzzyResult
	for _, p := range r.Paths {
		meta := r.Nodes[p]
		score := fuzzyScore(q, strings.ToLower(p), strings.ToLower(meta.Description))
		if score > 0 {
			hits = append(hits, FuzzyResult{
				Path:        p,
				Type:        meta.Type,
				Description: meta.Description,
				Score:       score,
			})
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].Path < hits[j].Path
	})
	if limit > 0 && len(hits) > limit {
		hits = hits[:limit]
	}
	return hits
}

func fuzzyScore(q, path, desc string) int {
	if path == q {
		return 1000
	}
	if strings.HasSuffix(path, "."+q) || strings.HasPrefix(path, q) {
		return 700 - len(path)
	}
	if strings.Contains(path, q) {
		return 500 - len(path)
	}
	if subseqMatch(q, path) {
		return 250 - len(path)
	}
	if desc != "" && strings.Contains(desc, q) {
		return 150
	}
	return 0
}

func subseqMatch(needle, hay string) bool {
	ni := 0
	for hi := 0; hi < len(hay) && ni < len(needle); hi++ {
		if hay[hi] == needle[ni] {
			ni++
		}
	}
	return ni == len(needle)
}

// ModeSpec describes one interactive CLI hierarchy mode.
type ModeSpec struct {
	Name        Mode   `json:"name"`
	Prompt      string `json:"prompt_suffix"`
	MinRole     string `json:"min_role"`
	Description string `json:"description"`
}

// VerbSpec defines one canonical DaijiOS CLI verb.
type VerbSpec struct {
	Name        string   `json:"name"`
	Modes       []Mode   `json:"modes"`
	Syntax      string   `json:"syntax"`
	Description string   `json:"description"`
	Pipes       []string `json:"pipes_supported,omitempty"`
}

// PipeSpec describes a post-processing output pipe operator.
type PipeSpec struct {
	Op          string `json:"op"`
	Syntax      string `json:"syntax"`
	Description string `json:"description"`
}

// CommandSchemaDocument represents the formal CLI command schema synced with SSoT.
type CommandSchemaDocument struct {
	Brand         string                  `json:"brand"`
	SchemaVersion string                  `json:"schema_version"`
	Modes         []ModeSpec              `json:"modes"`
	Verbs         []VerbSpec              `json:"verbs"`
	Pipes         []PipeSpec              `json:"pipes"`
	CLIMappings   []schema.CLICommandSpec `json:"cli_mappings"`
	PathCount     int                     `json:"path_count"`
	Paths         []SchemaNodeMeta        `json:"paths"`
}

// BuildCommandSchema generates a deterministic CLI command schema synchronized with cs.
func BuildCommandSchema(cs *schema.CompiledSchema) (*CommandSchemaDocument, error) {
	reg, err := BuildRegistry(cs)
	if err != nil {
		return nil, err
	}
	cliSpecs, err := cs.ExtractCLISpec()
	if err != nil {
		return nil, err
	}
	nodes := make([]SchemaNodeMeta, 0, len(reg.Paths))
	for _, p := range reg.Paths {
		nodes = append(nodes, reg.Nodes[p])
	}
	return &CommandSchemaDocument{
		Brand:         "DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)",
		SchemaVersion: cs.Root.SchemaVersion,
		Modes: []ModeSpec{
			{Name: ModeUser, Prompt: "> ", MinRole: "readonly", Description: "Read-only operational inspection"},
			{Name: ModePrivileged, Prompt: "# ", MinRole: "operator", Description: "Privileged diagnostics, save, and configuration entry"},
			{Name: ModeConfig, Prompt: "(cfg)# ", MinRole: "netadmin", Description: "Transactional candidate configuration staging & commit"},
			{Name: ModeSubConfig, Prompt: "(cfg:<ctx>)# ", MinRole: "netadmin", Description: "Scoped container sub-configuration mode"},
		},
		Verbs: []VerbSpec{
			{Name: "show", Modes: []Mode{ModeUser, ModePrivileged, ModeConfig, ModeSubConfig}, Syntax: "show <version|about|running|candidate|startup|interfaces|revisions|audit-verify|sessions|wans|dot.path>", Description: "Inspect operational state or configuration", Pipes: []string{"include", "exclude", "count", "json"}},
			{Name: "set", Modes: []Mode{ModeConfig, ModeSubConfig}, Syntax: "set <path> <value>", Description: "Set candidate configuration value"},
			{Name: "unset", Modes: []Mode{ModeConfig, ModeSubConfig}, Syntax: "unset <path>", Description: "Remove candidate configuration leaf or container"},
			{Name: "add", Modes: []Mode{ModeConfig, ModeSubConfig}, Syntax: "add <array-path> <element>", Description: "Append element to list node"},
			{Name: "remove", Modes: []Mode{ModeConfig, ModeSubConfig}, Syntax: "remove <array-path> <key|index>", Description: "Remove element from list node"},
			{Name: "diff", Modes: []Mode{ModeConfig, ModeSubConfig}, Syntax: "diff", Description: "Show candidate vs running diff with secret redaction", Pipes: []string{"include", "exclude", "count", "json"}},
			{Name: "validate", Modes: []Mode{ModeConfig, ModeSubConfig}, Syntax: "validate", Description: "Validate candidate against SSoT JSON & semantic validators"},
			{Name: "commit", Modes: []Mode{ModeConfig, ModeSubConfig}, Syntax: "commit [message]", Description: "Atomically apply candidate to running config", Pipes: []string{"json"}},
			{Name: "commit-confirm", Modes: []Mode{ModeConfig, ModeSubConfig}, Syntax: "commit-confirm [seconds]", Description: "Commit with deadman auto-rollback timer", Pipes: []string{"json"}},
			{Name: "confirm", Modes: []Mode{ModeConfig, ModeSubConfig}, Syntax: "confirm", Description: "Disarm active commit-confirm timer"},
			{Name: "rollback", Modes: []Mode{ModeConfig, ModeSubConfig}, Syntax: "rollback <rev-id|offset> [--commit]", Description: "Restore configuration revision", Pipes: []string{"json"}},
			{Name: "discard", Modes: []Mode{ModeConfig, ModeSubConfig}, Syntax: "discard", Description: "Discard staged candidate edits"},
			{Name: "save", Modes: []Mode{ModePrivileged, ModeConfig, ModeSubConfig}, Syntax: "save", Description: "Persist running configuration to startup"},
			{Name: "monitor", Modes: []Mode{ModeUser, ModePrivileged, ModeConfig, ModeSubConfig}, Syntax: "monitor <traffic|torch|topic>", Description: "Stream real-time diagnostic snapshot", Pipes: []string{"include", "exclude", "count", "json"}},
			{Name: "debug", Modes: []Mode{ModePrivileged, ModeConfig, ModeSubConfig}, Syntax: "debug <config-tree|topic>", Description: "Run internal subsystem diagnostic probes", Pipes: []string{"include", "exclude", "count", "json"}},
			{Name: "search", Modes: []Mode{ModeUser, ModePrivileged, ModeConfig, ModeSubConfig}, Syntax: "search <keyword>", Description: "Fuzzy search schema paths and descriptions", Pipes: []string{"include", "exclude", "count", "json"}},
			{Name: "enter", Modes: []Mode{ModeConfig, ModeSubConfig}, Syntax: "enter <container-path>", Description: "Descend into sub-config container"},
			{Name: "up", Modes: []Mode{ModeSubConfig}, Syntax: "up", Description: "Move up one sub-config hierarchy level"},
			{Name: "top", Modes: []Mode{ModeSubConfig}, Syntax: "top", Description: "Return directly to root config mode"},
			{Name: "enable", Modes: []Mode{ModeUser}, Syntax: "enable", Description: "Elevate from user mode to privileged mode"},
			{Name: "disable", Modes: []Mode{ModePrivileged}, Syntax: "disable", Description: "Drop from privileged mode to user mode"},
			{Name: "config", Modes: []Mode{ModePrivileged}, Syntax: "config", Description: "Enter transactional configuration mode"},
			{Name: "alias", Modes: []Mode{ModeUser, ModePrivileged, ModeConfig, ModeSubConfig}, Syntax: "alias [name command...]", Description: "List or define operator command aliases", Pipes: []string{"include", "count", "json"}},
			{Name: "unalias", Modes: []Mode{ModeUser, ModePrivileged, ModeConfig, ModeSubConfig}, Syntax: "unalias <name>", Description: "Delete a user command alias"},
			{Name: "history", Modes: []Mode{ModeUser, ModePrivileged, ModeConfig, ModeSubConfig}, Syntax: "history", Description: "Display session command history (secrets redacted)", Pipes: []string{"include", "exclude", "count", "json"}},
			{Name: "help", Modes: []Mode{ModeUser, ModePrivileged, ModeConfig, ModeSubConfig}, Syntax: "help", Description: "Show available verbs for active mode", Pipes: []string{"include", "exclude", "count", "json"}},
			{Name: "exit", Modes: []Mode{ModeUser, ModePrivileged, ModeConfig, ModeSubConfig}, Syntax: "exit", Description: "Step up mode hierarchy or exit session"},
		},
		Pipes: []PipeSpec{
			{Op: "include", Syntax: "| include <substring>", Description: "Retain lines matching case-insensitive substring"},
			{Op: "exclude", Syntax: "| exclude <substring>", Description: "Drop lines matching case-insensitive substring"},
			{Op: "count", Syntax: "| count", Description: "Count non-empty output lines"},
			{Op: "json", Syntax: "| json", Description: "Format command structured result as indented JSON"},
		},
		CLIMappings: cliSpecs,
		PathCount:   len(nodes),
		Paths:       nodes,
	}, nil
}
