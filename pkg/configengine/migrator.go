// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package configengine

import (
	"fmt"
	"strings"
)

// MigrationFunc upgrades a configuration map from one schema version to the next.
type MigrationFunc func(cfg map[string]any) (map[string]any, error)

type migrationEdge struct {
	From string
	To   string
	Fn   MigrationFunc
}

// Migrator maintains backward-compatible configuration upgrade paths across DaijiOS releases.
type Migrator struct {
	edges map[string][]migrationEdge
}

// NewMigrator creates an empty schema migration registry.
func NewMigrator() *Migrator {
	return &Migrator{
		edges: make(map[string][]migrationEdge),
	}
}

// Register adds a deterministic migration step from `fromVersion` to `toVersion`.
func (m *Migrator) Register(fromVersion, toVersion string, fn MigrationFunc) error {
	if fromVersion == "" || toVersion == "" || fromVersion == toVersion {
		return fmt.Errorf("invalid migration versions %q -> %q", fromVersion, toVersion)
	}
	if fn == nil {
		return fmt.Errorf("migration function cannot be nil")
	}
	m.edges[fromVersion] = append(m.edges[fromVersion], migrationEdge{
		From: fromVersion,
		To:   toVersion,
		Fn:   fn,
	})
	return nil
}

// Migrate upgrades cfg to targetVersion by finding the shortest registered migration path.
func (m *Migrator) Migrate(cfg map[string]any, targetVersion string) (map[string]any, []string, error) {
	cur := deepCopyMap(cfg)
	curVer, _ := cur["schema_version"].(string)
	curVer = strings.TrimSpace(curVer)
	if curVer == "" {
		curVer = "0.9.0"
	}
	if curVer == targetVersion {
		return cur, nil, nil
	}

	path, err := m.findPath(curVer, targetVersion)
	if err != nil {
		return nil, nil, err
	}

	steps := make([]string, 0, len(path))
	for _, edge := range path {
		next, err := edge.Fn(deepCopyMap(cur))
		if err != nil {
			return nil, steps, fmt.Errorf("migration %s -> %s failed: %w", edge.From, edge.To, err)
		}
		next["schema_version"] = edge.To
		cur = next
		steps = append(steps, fmt.Sprintf("%s->%s", edge.From, edge.To))
	}
	return cur, steps, nil
}

func (m *Migrator) findPath(start, goal string) ([]migrationEdge, error) {
	type node struct {
		ver  string
		path []migrationEdge
	}
	visited := map[string]bool{start: true}
	queue := []node{{ver: start}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, edge := range m.edges[cur.ver] {
			if visited[edge.To] {
				continue
			}
			nextPath := make([]migrationEdge, len(cur.path)+1)
			copy(nextPath, cur.path)
			nextPath[len(cur.path)] = edge
			if edge.To == goal {
				return nextPath, nil
			}
			visited[edge.To] = true
			queue = append(queue, node{ver: edge.To, path: nextPath})
		}
	}
	return nil, fmt.Errorf("no backward-compatible migration path from %q to %q", start, goal)
}
