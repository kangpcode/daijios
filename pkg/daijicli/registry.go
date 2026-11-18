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
