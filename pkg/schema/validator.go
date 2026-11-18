// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package schema implements the Single Source of Truth (SSoT) JSON Schema 2020-12
// validator and metadata projector for DaijiOS CLI, DaiWeb, Daimo, DaiDesk, and API.
package schema

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	semverRe   = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-.]+)?(?:\+[0-9A-Za-z-.]+)?$`)
	hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	arrayIdxRe = regexp.MustCompile(`\[\d+\]`)
)

// UIMeta captures x-daiji-ui rendering hints shared across DaiWeb, Daimo, and DaiDesk.
type UIMeta struct {
	Group  string `json:"group,omitempty"`
	Widget string `json:"widget,omitempty"`
	Label  string `json:"label,omitempty"`
}

// Node represents a compiled JSON Schema 2020-12 node with DaijiOS SSoT extensions.
type Node struct {
	Schema               string           `json:"$schema,omitempty"`
	ID                   string           `json:"$id,omitempty"`
	Ref                  string           `json:"$ref,omitempty"`
	Title                string           `json:"title,omitempty"`
	Description          string           `json:"description,omitempty"`
	Type                 string           `json:"type,omitempty"`
	Properties           map[string]*Node `json:"properties,omitempty"`
	Required             []string         `json:"required,omitempty"`
	AdditionalProperties *bool            `json:"additionalProperties,omitempty"`
	Items                *Node            `json:"items,omitempty"`
	MinItems             *int             `json:"minItems,omitempty"`
	MaxItems             *int             `json:"maxItems,omitempty"`
	Enum                 []any            `json:"enum,omitempty"`
	Default              any              `json:"default,omitempty"`
	Minimum              *float64         `json:"minimum,omitempty"`
	Maximum              *float64         `json:"maximum,omitempty"`
	MinLength            *int             `json:"minLength,omitempty"`
	MaxLength            *int             `json:"maxLength,omitempty"`
	Pattern              string           `json:"pattern,omitempty"`
	Format               string           `json:"format,omitempty"`
	Defs                 map[string]*Node `json:"$defs,omitempty"`

	// DaijiOS SSoT annotations
	SchemaVersion string  `json:"x-daiji-schema-version,omitempty"`
	YANGModule    string  `json:"x-daiji-yang-module,omitempty"`
	YANGPath      string  `json:"x-daiji-yang-path,omitempty"`
	CLIPath       string  `json:"x-daiji-cli,omitempty"`
	UI            *UIMeta `json:"x-daiji-ui,omitempty"`
	Secret        bool    `json:"x-daiji-secret,omitempty"`
	RBAC          string  `json:"x-daiji-rbac,omitempty"`
	Impact        string  `json:"x-daiji-impact,omitempty"`

	compiledPattern *regexp.Regexp
}

// ValidationIssue describes one concrete schema violation.
type ValidationIssue struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (v ValidationIssue) Error() string {
	return fmt.Sprintf("%s: %s", v.Path, v.Message)
}

// ValidationError aggregates all schema validation violations.
type ValidationError struct {
	Issues []ValidationIssue `json:"issues"`
}

func (e *ValidationError) Error() string {
	if len(e.Issues) == 0 {
		return "validation failed"
	}
	parts := make([]string, 0, len(e.Issues))
	for _, iss := range e.Issues {
		parts = append(parts, iss.Error())
	}
	return fmt.Sprintf("schema validation failed (%d issue(s)): %s", len(e.Issues), strings.Join(parts, "; "))
}

// CLICommandSpec is derived directly from schema x-daiji-cli metadata.
type CLICommandSpec struct {
	CLIPath     string   `json:"cli_path"`
	ConfigPath  string   `json:"config_path"`
	Type        string   `json:"type"`
	Format      string   `json:"format,omitempty"`
	Enum        []string `json:"enum,omitempty"`
	Default     any      `json:"default,omitempty"`
	Required    bool     `json:"required"`
	Secret      bool     `json:"secret,omitempty"`
	RBAC        string   `json:"rbac,omitempty"`
	Impact      string   `json:"impact,omitempty"`
	Description string   `json:"description,omitempty"`
}

// UIFieldSpec is derived directly from schema x-daiji-ui metadata for Web/Mobile/Desktop UIs.
type UIFieldSpec struct {
	Path        string   `json:"path"`
	Group       string   `json:"group"`
	Widget      string   `json:"widget"`
	Label       string   `json:"label"`
	Type        string   `json:"type"`
	Enum        []string `json:"enum,omitempty"`
	Default     any      `json:"default,omitempty"`
	Required    bool     `json:"required"`
	Secret      bool     `json:"secret,omitempty"`
	RBAC        string   `json:"rbac,omitempty"`
	Impact      string   `json:"impact,omitempty"`
	Min         *float64 `json:"min,omitempty"`
	Max         *float64 `json:"max,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	Description string   `json:"description,omitempty"`
}

// CompiledSchema holds the compiled schema AST and pre-indexed SSoT projections.
type CompiledSchema struct {
	Root        *Node
	secretGlobs map[string]struct{}
}

// LoadFile reads and compiles a JSON Schema file from disk.
func LoadFile(path string) (*CompiledSchema, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read schema %q: %w", path, err)
	}
	return Compile(raw)
}

// Compile parses and compiles raw JSON Schema bytes.
func Compile(raw []byte) (*CompiledSchema, error) {
	var root Node
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse schema json: %w", err)
	}
	cs := &CompiledSchema{
		Root:        &root,
		secretGlobs: make(map[string]struct{}),
	}
	if err := cs.compileNode(&root, ""); err != nil {
		return nil, err
	}
	cs.indexSecrets(&root, "", 0)
	return cs, nil
}

func (cs *CompiledSchema) compileNode(n *Node, path string) error {
	if n == nil {
		return nil
	}
	if n.Pattern != "" {
		re, err := regexp.Compile(n.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern at %q (%q): %w", path, n.Pattern, err)
		}
		n.compiledPattern = re
	}
	for name, def := range n.Defs {
		if err := cs.compileNode(def, "#/$defs/"+name); err != nil {
			return err
		}
	}
	for k, prop := range n.Properties {
		childPath := k
		if path != "" {
			childPath = path + "." + k
		}
		if err := cs.compileNode(prop, childPath); err != nil {
			return err
		}
	}
	if n.Items != nil {
		if err := cs.compileNode(n.Items, path+"[*]"); err != nil {
			return err
		}
	}
	return nil
}

func (cs *CompiledSchema) resolveRef(ref string) (*Node, error) {
	const prefix = "#/$defs/"
	if !strings.HasPrefix(ref, prefix) {
		return nil, fmt.Errorf("unsupported $ref %q (only local #/$defs/ supported)", ref)
	}
	name := strings.TrimPrefix(ref, prefix)
	target, ok := cs.Root.Defs[name]
	if !ok {
		return nil, fmt.Errorf("unresolved $ref %q", ref)
	}
	return target, nil
}

func (cs *CompiledSchema) effectiveNode(n *Node, depth int) (*Node, error) {
	if n == nil {
		return nil, nil
	}
	if n.Ref == "" {
		return n, nil
	}
	if depth > 16 {
		return nil, fmt.Errorf("$ref cycle depth exceeded at %q", n.Ref)
	}
	target, err := cs.resolveRef(n.Ref)
	if err != nil {
		return nil, err
	}
	resolved, err := cs.effectiveNode(target, depth+1)
	if err != nil {
		return nil, err
	}
	// Merge Draft 2020-12 sibling Daiji metadata over the referenced target.
	merged := *resolved
	if n.Title != "" {
		merged.Title = n.Title
	}
	if n.Description != "" {
		merged.Description = n.Description
	}
	if n.Default != nil {
		merged.Default = n.Default
	}
	if n.CLIPath != "" {
		merged.CLIPath = n.CLIPath
	}
	if n.UI != nil {
		merged.UI = n.UI
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

func (cs *CompiledSchema) indexSecrets(n *Node, path string, depth int) {
	if n == nil || depth > 24 {
		return
	}
	eff, err := cs.effectiveNode(n, 0)
	if err != nil || eff == nil {
		return
	}
	if eff.Secret && path != "" {
		cs.secretGlobs[path] = struct{}{}
	}
	for k, prop := range eff.Properties {
		childPath := k
		if path != "" {
			childPath = path + "." + k
		}
		cs.indexSecrets(prop, childPath, depth+1)
	}
	if eff.Items != nil {
		cs.indexSecrets(eff.Items, path+"[*]", depth+1)
	}
}

// IsSecretPath checks whether a concrete config dot-path (e.g. system.users[0].password_hash)
// corresponds to a schema node marked x-daiji-secret: true.
func (cs *CompiledSchema) IsSecretPath(path string) bool {
	if cs == nil {
		return false
	}
	normalized := arrayIdxRe.ReplaceAllString(path, "[*]")
	_, ok := cs.secretGlobs[normalized]
	return ok
}

// SecretPatterns returns a sorted list of normalized secret path patterns.
func (cs *CompiledSchema) SecretPatterns() []string {
	out := make([]string, 0, len(cs.secretGlobs))
	for p := range cs.secretGlobs {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ValidateJSON validates raw JSON configuration bytes against the compiled schema.
func (cs *CompiledSchema) ValidateJSON(raw []byte) error {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return &ValidationError{
			Issues: []ValidationIssue{{Path: "$", Message: fmt.Sprintf("invalid JSON: %v", err)}},
		}
	}
	return cs.Validate(doc)
}

// Validate checks an unmarshaled Go structure (map[string]any, etc.) against the schema.
func (cs *CompiledSchema) Validate(doc any) error {
	var issues []ValidationIssue
	cs.validateValue(cs.Root, doc, "$", &issues, 0)
	if len(issues) > 0 {
		return &ValidationError{Issues: issues}
	}
	return nil
}

func (cs *CompiledSchema) validateValue(n *Node, val any, path string, issues *[]ValidationIssue, depth int) {
	if n == nil {
		return
	}
	if depth > 64 {
		*issues = append(*issues, ValidationIssue{Path: path, Message: "max nesting depth exceeded"})
		return
	}
	eff, err := cs.effectiveNode(n, 0)
	if err != nil {
		*issues = append(*issues, ValidationIssue{Path: path, Message: err.Error()})
		return
	}

	if len(eff.Enum) > 0 && !containsEnum(eff.Enum, val) {
		*issues = append(*issues, ValidationIssue{
			Path:    path,
			Message: fmt.Sprintf("value %v is not in allowed enum %v", val, eff.Enum),
		})
	}

	switch eff.Type {
	case "object":
		obj, ok := val.(map[string]any)
		if !ok {
			*issues = append(*issues, ValidationIssue{Path: path, Message: fmt.Sprintf("expected object, got %T", val)})
			return
		}
		for _, req := range eff.Required {
			if _, exists := obj[req]; !exists {
				*issues = append(*issues, ValidationIssue{
					Path:    joinPath(path, req),
					Message: "required field is missing",
				})
			}
		}
		// Sort keys for deterministic issue ordering.
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			childVal := obj[k]
			propSchema, known := eff.Properties[k]
			if !known {
				if eff.AdditionalProperties != nil && !*eff.AdditionalProperties {
					*issues = append(*issues, ValidationIssue{
						Path:    joinPath(path, k),
						Message: "unknown property is not permitted (additionalProperties=false)",
					})
				}
				continue
			}
			cs.validateValue(propSchema, childVal, joinPath(path, k), issues, depth+1)
		}

	case "array":
		arr, ok := toAnySlice(val)
		if !ok {
			*issues = append(*issues, ValidationIssue{Path: path, Message: fmt.Sprintf("expected array, got %T", val)})
			return
		}
		if eff.MinItems != nil && len(arr) < *eff.MinItems {
			*issues = append(*issues, ValidationIssue{
				Path:    path,
				Message: fmt.Sprintf("array length %d is less than minItems %d", len(arr), *eff.MinItems),
			})
		}
		if eff.MaxItems != nil && len(arr) > *eff.MaxItems {
			*issues = append(*issues, ValidationIssue{
				Path:    path,
				Message: fmt.Sprintf("array length %d exceeds maxItems %d", len(arr), *eff.MaxItems),
			})
		}
		if eff.Items != nil {
			for idx, item := range arr {
				cs.validateValue(eff.Items, item, fmt.Sprintf("%s[%d]", path, idx), issues, depth+1)
			}
		}

	case "string":
		s, ok := val.(string)
		if !ok {
			*issues = append(*issues, ValidationIssue{Path: path, Message: fmt.Sprintf("expected string, got %T", val)})
			return
		}
		runeLen := len([]rune(s))
		if eff.MinLength != nil && runeLen < *eff.MinLength {
			*issues = append(*issues, ValidationIssue{
				Path:    path,
				Message: fmt.Sprintf("length %d is less than minLength %d", runeLen, *eff.MinLength),
			})
		}
		if eff.MaxLength != nil && runeLen > *eff.MaxLength {
			*issues = append(*issues, ValidationIssue{
				Path:    path,
				Message: fmt.Sprintf("length %d exceeds maxLength %d", runeLen, *eff.MaxLength),
			})
		}
		if eff.compiledPattern != nil && !eff.compiledPattern.MatchString(s) {
			*issues = append(*issues, ValidationIssue{
				Path:    path,
				Message: fmt.Sprintf("value %q does not match pattern %q", s, eff.Pattern),
			})
		}
		if eff.Format != "" {
			if err := validateFormat(eff.Format, s); err != nil {
				*issues = append(*issues, ValidationIssue{Path: path, Message: err.Error()})
			}
		}

	case "integer":
		num, isInt, ok := asNumber(val)
		if !ok || !isInt {
			*issues = append(*issues, ValidationIssue{Path: path, Message: fmt.Sprintf("expected integer, got %v (%T)", val, val)})
			return
		}
		if eff.Minimum != nil && num < *eff.Minimum {
			*issues = append(*issues, ValidationIssue{
				Path:    path,
				Message: fmt.Sprintf("value %v is less than minimum %v", num, *eff.Minimum),
			})
		}
		if eff.Maximum != nil && num > *eff.Maximum {
			*issues = append(*issues, ValidationIssue{
				Path:    path,
				Message: fmt.Sprintf("value %v exceeds maximum %v", num, *eff.Maximum),
			})
		}

	case "number":
		num, _, ok := asNumber(val)
		if !ok {
			*issues = append(*issues, ValidationIssue{Path: path, Message: fmt.Sprintf("expected number, got %T", val)})
			return
		}
		if eff.Minimum != nil && num < *eff.Minimum {
			*issues = append(*issues, ValidationIssue{
				Path:    path,
				Message: fmt.Sprintf("value %v is less than minimum %v", num, *eff.Minimum),
			})
		}
		if eff.Maximum != nil && num > *eff.Maximum {
			*issues = append(*issues, ValidationIssue{
				Path:    path,
				Message: fmt.Sprintf("value %v exceeds maximum %v", num, *eff.Maximum),
			})
		}

	case "boolean":
		if _, ok := val.(bool); !ok {
			*issues = append(*issues, ValidationIssue{Path: path, Message: fmt.Sprintf("expected boolean, got %T", val)})
		}
	}
}

func validateFormat(format, val string) error {
	switch format {
	case "ipv4":
		addr, err := netip.ParseAddr(val)
		if err != nil || !addr.Is4() {
			return fmt.Errorf("invalid ipv4 address %q", val)
		}
	case "ipv6":
		addr, err := netip.ParseAddr(val)
		if err != nil || !addr.Is6() {
			return fmt.Errorf("invalid ipv6 address %q", val)
		}
	case "ip":
		if _, err := netip.ParseAddr(val); err != nil {
			return fmt.Errorf("invalid IPv4/IPv6 address %q", val)
		}
	case "cidr":
		if _, err := netip.ParsePrefix(val); err != nil {
			return fmt.Errorf("invalid CIDR prefix %q", val)
		}
	case "cidr4":
		pfx, err := netip.ParsePrefix(val)
		if err != nil || !pfx.Addr().Is4() {
			return fmt.Errorf("invalid IPv4 CIDR prefix %q", val)
		}
	case "cidr6":
		pfx, err := netip.ParsePrefix(val)
		if err != nil || !pfx.Addr().Is6() {
			return fmt.Errorf("invalid IPv6 CIDR prefix %q", val)
		}
	case "mac":
		if _, err := net.ParseMAC(val); err != nil {
			return fmt.Errorf("invalid MAC address %q", val)
		}
	case "hostname":
		if len(val) == 0 || len(val) > 253 || !hostnameRe.MatchString(val) {
			return fmt.Errorf("invalid RFC 1123 hostname %q", val)
		}
	case "semver":
		if !semverRe.MatchString(val) {
			return fmt.Errorf("invalid semantic version %q", val)
		}
	case "uri":
		u, err := url.ParseRequestURI(val)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("invalid URI %q", val)
		}
	case "date-time":
		if _, err := time.Parse(time.RFC3339, val); err != nil {
			return fmt.Errorf("invalid RFC3339 date-time %q", val)
		}
	}
	return nil
}

// ExtractCLISpec projects the Single Source of Truth schema into a deterministic CLI command tree.
func (cs *CompiledSchema) ExtractCLISpec() ([]CLICommandSpec, error) {
	var specs []CLICommandSpec
	if err := cs.walkSpecs(cs.Root, "", false, func(eff *Node, cfgPath string, req bool) {
		if eff.CLIPath == "" {
			return
		}
		specs = append(specs, CLICommandSpec{
			CLIPath:     eff.CLIPath,
			ConfigPath:  cfgPath,
			Type:        eff.Type,
			Format:      eff.Format,
			Enum:        stringifyEnum(eff.Enum),
			Default:     eff.Default,
			Required:    req,
			Secret:      eff.Secret,
			RBAC:        eff.RBAC,
			Impact:      eff.Impact,
			Description: eff.Description,
		})
	}, 0); err != nil {
		return nil, err
	}
	sort.Slice(specs, func(i, j int) bool {
		return specs[i].CLIPath < specs[j].CLIPath
	})
	return specs, nil
}

// ExtractUISchema projects the schema into UI form metadata for DaiWeb, Daimo, and DaiDesk.
func (cs *CompiledSchema) ExtractUISchema() ([]UIFieldSpec, error) {
	var fields []UIFieldSpec
	if err := cs.walkSpecs(cs.Root, "", false, func(eff *Node, cfgPath string, req bool) {
		if eff.UI == nil {
			return
		}
		fields = append(fields, UIFieldSpec{
			Path:        cfgPath,
			Group:       eff.UI.Group,
			Widget:      eff.UI.Widget,
			Label:       eff.UI.Label,
			Type:        eff.Type,
			Enum:        stringifyEnum(eff.Enum),
			Default:     eff.Default,
			Required:    req,
			Secret:      eff.Secret,
			RBAC:        eff.RBAC,
			Impact:      eff.Impact,
			Min:         eff.Minimum,
			Max:         eff.Maximum,
			Pattern:     eff.Pattern,
			Description: eff.Description,
		})
	}, 0); err != nil {
		return nil, err
	}
	sort.Slice(fields, func(i, j int) bool {
		if fields[i].Group != fields[j].Group {
			return fields[i].Group < fields[j].Group
		}
		return fields[i].Path < fields[j].Path
	})
	return fields, nil
}

// ExtractOpenAPISpec generates an OpenAPI 3.1.0 document backed directly by this schema.
func (cs *CompiledSchema) ExtractOpenAPISpec() map[string]any {
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "DaijiOS Control Plane API",
			"version": cs.Root.SchemaVersion,
			"x-brand": "DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)",
		},
		"paths": map[string]any{
			"/api/v1/config/running": map[string]any{
				"get": map[string]any{
					"summary": "Read active running configuration (secrets redacted for non-superadmin)",
					"responses": map[string]any{
						"200": map[string]any{"description": "Active DaijiOS configuration"},
					},
				},
			},
			"/api/v1/config/candidate": map[string]any{
				"put": map[string]any{
					"summary": "Stage candidate configuration validated against DaijiOS unified schema",
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{"$ref": "#/components/schemas/DaijiConfig"},
							},
						},
					},
				},
			},
			"/api/v1/config/commit": map[string]any{
				"post": map[string]any{
					"summary": "Validate, diff, and transactionally commit candidate to running",
				},
			},
			"/api/v1/config/commit-confirm": map[string]any{
				"post": map[string]any{
					"summary": "Transactional commit with persistent deadman auto-rollback timer",
				},
			},
			"/api/v1/config/rollback": map[string]any{
				"post": map[string]any{
					"summary": "Restore candidate or running state to an immutable historical revision",
				},
			},
		},
		"components": map[string]any{
			"schemas": map[string]any{
				"DaijiConfig": cs.Root,
			},
		},
	}
}

func (cs *CompiledSchema) walkSpecs(n *Node, path string, req bool, fn func(*Node, string, bool), depth int) error {
	if n == nil || depth > 24 {
		return nil
	}
	eff, err := cs.effectiveNode(n, 0)
	if err != nil {
		return err
	}
	if path != "" {
		fn(eff, path, req)
	}
	reqSet := make(map[string]bool, len(eff.Required))
	for _, r := range eff.Required {
		reqSet[r] = true
	}
	keys := make([]string, 0, len(eff.Properties))
	for k := range eff.Properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		childPath := k
		if path != "" {
			childPath = path + "." + k
		}
		if err := cs.walkSpecs(eff.Properties[k], childPath, reqSet[k], fn, depth+1); err != nil {
			return err
		}
	}
	if eff.Items != nil {
		if err := cs.walkSpecs(eff.Items, path+"[*]", false, fn, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func joinPath(base, key string) string {
	if base == "$" || base == "" {
		return key
	}
	return base + "." + key
}

func containsEnum(allowed []any, val any) bool {
	for _, a := range allowed {
		if fmt.Sprintf("%v", a) == fmt.Sprintf("%v", val) {
			return true
		}
	}
	return false
}

func stringifyEnum(allowed []any) []string {
	if len(allowed) == 0 {
		return nil
	}
	out := make([]string, 0, len(allowed))
	for _, a := range allowed {
		out = append(out, fmt.Sprintf("%v", a))
	}
	return out
}

func asNumber(v any) (float64, bool, bool) {
	switch x := v.(type) {
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return 0, false, false
		}
		return x, math.Trunc(x) == x, true
	case int:
		return float64(x), true, true
	case int64:
		return float64(x), true, true
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return 0, false, false
		}
		if _, err := strconv.ParseInt(x.String(), 10, 64); err == nil {
			return f, true, true
		}
		return f, math.Trunc(f) == f, true
	default:
		return 0, false, false
	}
}

func toAnySlice(v any) ([]any, bool) {
	switch s := v.(type) {
	case []any:
		return s, true
	case []string:
		out := make([]any, len(s))
		for i, item := range s {
			out[i] = item
		}
		return out, true
	default:
		return nil, false
	}
}
