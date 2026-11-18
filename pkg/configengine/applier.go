// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package configengine

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// DiffOp represents a structural configuration change operation.
type DiffOp string

const (
	DiffAdd    DiffOp = "add"
	DiffUpdate DiffOp = "update"
	DiffDelete DiffOp = "delete"
)

// DiffEntry describes a single atomic change between two configuration trees.
type DiffEntry struct {
	Path     string `json:"path"`
	Op       DiffOp `json:"op"`
	OldValue any    `json:"old_value,omitempty"`
	NewValue any    `json:"new_value,omitempty"`
}

// Applier translates committed configuration differences into actual system/control-plane state.
// Implementations in Phase 1+ (netlink, FRR, nftables, hostapd) MUST be idempotent.
type Applier interface {
	Plan(ctx context.Context, current, target map[string]any, diffs []DiffEntry) error
	Apply(ctx context.Context, target map[string]any, diffs []DiffEntry) error
}

// NoopApplier validates planning/commit flows without mutating host networking.
type NoopApplier struct{}

func (NoopApplier) Plan(context.Context, map[string]any, map[string]any, []DiffEntry) error {
	return nil
}

func (NoopApplier) Apply(context.Context, map[string]any, []DiffEntry) error {
	return nil
}

// ComputeDiff deterministically computes structural differences from oldCfg to newCfg.
func ComputeDiff(oldCfg, newCfg map[string]any) []DiffEntry {
	var diffs []DiffEntry
	diffValues("", oldCfg, newCfg, &diffs)
	sort.Slice(diffs, func(i, j int) bool {
		return diffs[i].Path < diffs[j].Path
	})
	return diffs
}

// InvertDiff produces the compensating inverse diff for transactional rollback.
func InvertDiff(diffs []DiffEntry) []DiffEntry {
	inv := make([]DiffEntry, len(diffs))
	for i, d := range diffs {
		revIdx := len(diffs) - 1 - i
		switch d.Op {
		case DiffAdd:
			inv[revIdx] = DiffEntry{Path: d.Path, Op: DiffDelete, OldValue: d.NewValue}
		case DiffDelete:
			inv[revIdx] = DiffEntry{Path: d.Path, Op: DiffAdd, NewValue: d.OldValue}
		case DiffUpdate:
			inv[revIdx] = DiffEntry{Path: d.Path, Op: DiffUpdate, OldValue: d.NewValue, NewValue: d.OldValue}
		}
	}
	return inv
}

// RedactDiff masks sensitive values identified by secretCheck before printing or logging.
func RedactDiff(diffs []DiffEntry, secretCheck func(path string) bool) []DiffEntry {
	out := make([]DiffEntry, len(diffs))
	for i, d := range diffs {
		cp := d
		if secretCheck != nil && secretCheck(d.Path) {
			if cp.OldValue != nil {
				cp.OldValue = "***REDACTED***"
			}
			if cp.NewValue != nil {
				cp.NewValue = "***REDACTED***"
			}
		}
		out[i] = cp
	}
	return out
}

// FormatDiff renders human-readable Junos/DaijiOS style configuration diffs.
func FormatDiff(diffs []DiffEntry, secretCheck func(path string) bool) string {
	if len(diffs) == 0 {
		return "(no changes)"
	}
	safe := RedactDiff(diffs, secretCheck)
	var b strings.Builder
	for _, d := range safe {
		switch d.Op {
		case DiffAdd:
			fmt.Fprintf(&b, "+ %s = %s\n", d.Path, compactJSON(d.NewValue))
		case DiffDelete:
			fmt.Fprintf(&b, "- %s = %s\n", d.Path, compactJSON(d.OldValue))
		case DiffUpdate:
			fmt.Fprintf(&b, "~ %s: %s -> %s\n", d.Path, compactJSON(d.OldValue), compactJSON(d.NewValue))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func diffValues(path string, oldVal, newVal any, diffs *[]DiffEntry) {
	if deepEqualJSON(oldVal, newVal) {
		return
	}

	oldMap, oldIsMap := oldVal.(map[string]any)
	newMap, newIsMap := newVal.(map[string]any)
	if oldIsMap && newIsMap {
		seen := make(map[string]struct{}, len(oldMap)+len(newMap))
		for k := range oldMap {
			seen[k] = struct{}{}
		}
		for k := range newMap {
			seen[k] = struct{}{}
		}
		keys := make([]string, 0, len(seen))
		for k := range seen {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			childPath := k
			if path != "" {
				childPath = path + "." + k
			}
			ov, okOld := oldMap[k]
			nv, okNew := newMap[k]
			switch {
			case !okOld && okNew:
				*diffs = append(*diffs, DiffEntry{Path: childPath, Op: DiffAdd, NewValue: deepCopyValue(nv)})
			case okOld && !okNew:
				*diffs = append(*diffs, DiffEntry{Path: childPath, Op: DiffDelete, OldValue: deepCopyValue(ov)})
			default:
				diffValues(childPath, ov, nv, diffs)
			}
		}
		return
	}

	oldSlice, oldIsSlice := oldVal.([]any)
	newSlice, newIsSlice := newVal.([]any)
	if oldIsSlice && newIsSlice {
		maxLen := len(oldSlice)
		if len(newSlice) > maxLen {
			maxLen = len(newSlice)
		}
		for i := 0; i < maxLen; i++ {
			elemPath := fmt.Sprintf("%s[%d]", path, i)
			switch {
			case i >= len(oldSlice):
				*diffs = append(*diffs, DiffEntry{Path: elemPath, Op: DiffAdd, NewValue: deepCopyValue(newSlice[i])})
			case i >= len(newSlice):
				*diffs = append(*diffs, DiffEntry{Path: elemPath, Op: DiffDelete, OldValue: deepCopyValue(oldSlice[i])})
			default:
				diffValues(elemPath, oldSlice[i], newSlice[i], diffs)
			}
		}
		return
	}

	*diffs = append(*diffs, DiffEntry{
		Path:     path,
		Op:       DiffUpdate,
		OldValue: deepCopyValue(oldVal),
		NewValue: deepCopyValue(newVal),
	})
}

func deepEqualJSON(a, b any) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ja) == string(jb)
}

func compactJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}
