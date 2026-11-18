// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package netreconcile implements the idempotent Phase 1 control-plane & kernel
// reconciliation engine (configengine.Applier) for interfaces, IP services,
// FRRouting, Kea/dnsmasq, keepalived, chrony, and switching.
package netreconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/kangpcode/daijios/pkg/fsatomic"
)

// SystemDriver abstracts Linux kernel commands, daemon config files, and service reloads.
type SystemDriver interface {
	Exec(ctx context.Context, bin string, args ...string) error
	WriteFile(path string, content []byte, mode os.FileMode) (changed bool, err error)
	ReloadService(ctx context.Context, service string) error
	LinkExists(name string) bool
	LoadManagedState() (*ManagedState, error)
	SaveManagedState(st *ManagedState) error
}

// ManagedState tracks virtual network objects created by DaijiOS so deletions are cleaned up safely.
type ManagedState struct {
	VRFs         []string `json:"vrfs,omitempty"`
	Bondings     []string `json:"bondings,omitempty"`
	VLANs        []string `json:"vlans,omitempty"`
	Bridges      []string `json:"bridges,omitempty"`
	Veths        []string `json:"veths,omitempty"`
	Tunnels      []string `json:"tunnels,omitempty"`
	PolicyRules  []string `json:"policy_rules,omitempty"`
	StaticRoutes []string `json:"static_routes,omitempty"`
}

// LinuxDriver executes real iproute2, tc, sysctl, mstpctl, and s6-rc/systemctl operations on Linux.
type LinuxDriver struct {
	StatePath string
	DryRun    bool
}

func (l *LinuxDriver) Exec(ctx context.Context, bin string, args ...string) error {
	if l.DryRun {
		return nil
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("exec %s %s failed: %w (%s)", bin, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}

func (l *LinuxDriver) WriteFile(path string, content []byte, mode os.FileMode) (bool, error) {
	if existing, err := os.ReadFile(path); err == nil {
		if sha256.Sum256(existing) == sha256.Sum256(content) {
			return false, nil
		}
	}
	if l.DryRun {
		return true, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return false, err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return false, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return false, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return false, err
	}
	return true, nil
}

func (l *LinuxDriver) ReloadService(ctx context.Context, service string) error {
	if l.DryRun {
		return nil
	}
	// Prefer s6-svc (DaijiOS init) and fallback cleanly to systemctl/killall -HUP.
	s6Dir := filepath.Join("/run/service", service)
	if _, err := os.Stat(s6Dir); err == nil {
		return l.Exec(ctx, "s6-svc", "-h", s6Dir)
	}
	return l.Exec(ctx, "systemctl", "reload-or-restart", service)
}

func (l *LinuxDriver) LinkExists(name string) bool {
	_, err := os.Stat(filepath.Join("/sys/class/net", name))
	return err == nil
}

func (l *LinuxDriver) LoadManagedState() (*ManagedState, error) {
	if l.StatePath == "" {
		return &ManagedState{}, nil
	}
	raw, err := os.ReadFile(l.StatePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &ManagedState{}, nil
		}
		return nil, err
	}
	var st ManagedState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (l *LinuxDriver) SaveManagedState(st *ManagedState) error {
	if l.StatePath == "" || l.DryRun {
		return nil
	}
	return fsatomic.WriteJSONAtomic(l.StatePath, st)
}

// SimulatedDriver is an in-memory stateful kernel & daemon simulator for deterministic
// non-privileged verification of command generation, ordering, idempotency, and cleanup.
type SimulatedDriver struct {
	mu             sync.Mutex
	Links          map[string]string
	Files          map[string]string
	FileHashes     map[string]string
	Commands       []string
	ServiceReloads map[string]int
	State          ManagedState
	FailOnCommand  string
}

// NewSimulatedDriver creates a simulator pre-seeded with physical host NICs (e.g. eth0..eth4).
func NewSimulatedDriver(physicalNICs ...string) *SimulatedDriver {
	links := make(map[string]string, len(physicalNICs))
	for _, nic := range physicalNICs {
		links[nic] = "physical"
	}
	return &SimulatedDriver{
		Links:          links,
		Files:          make(map[string]string),
		FileHashes:     make(map[string]string),
		ServiceReloads: make(map[string]int),
	}
}

func (s *SimulatedDriver) Exec(_ context.Context, bin string, args ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cmdLine := bin + " " + strings.Join(args, " ")
	if s.FailOnCommand != "" && strings.Contains(cmdLine, s.FailOnCommand) {
		return fmt.Errorf("simulated execution failure on %q", cmdLine)
	}
	s.Commands = append(s.Commands, cmdLine)

	// Simulate kernel link lifecycle invariants (reject duplicate `ip link add`).
	if bin == "ip" && len(args) >= 3 && args[0] == "link" {
		switch args[1] {
		case "add":
			name := extractIPArgName(args[2:])
			if name != "" {
				if _, exists := s.Links[name]; exists {
					return fmt.Errorf("RTNETLINK answers: File exists (%s)", name)
				}
				s.Links[name] = "virtual"
			}
			for i := 0; i < len(args)-1; i++ {
				if args[i] == "peer" && i+1 < len(args) {
					peer := args[i+1]
					if args[i+1] == "name" && i+2 < len(args) {
						peer = args[i+2]
					}
					s.Links[peer] = "veth-peer"
				}
			}
		case "del":
			if len(args) >= 3 {
				delete(s.Links, args[2])
			}
		}
	}
	return nil
}

func extractIPArgName(rest []string) string {
	for i := 0; i < len(rest); i++ {
		if (rest[i] == "name" || rest[i] == "dev") && i+1 < len(rest) {
			return rest[i+1]
		}
	}
	if len(rest) > 0 && rest[0] != "link" && rest[0] != "type" {
		return rest[0]
	}
	return ""
}

func (s *SimulatedDriver) WriteFile(path string, content []byte, _ os.FileMode) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sum := sha256.Sum256(content)
	hexSum := hex.EncodeToString(sum[:])
	if prev, ok := s.FileHashes[path]; ok && prev == hexSum {
		return false, nil
	}
	s.FileHashes[path] = hexSum
	s.Files[path] = string(content)
	return true, nil
}

func (s *SimulatedDriver) ReloadService(_ context.Context, service string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ServiceReloads[service]++
	return nil
}

func (s *SimulatedDriver) LinkExists(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.Links[name]
	return ok
}

func (s *SimulatedDriver) LoadManagedState() (*ManagedState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := s.State
	return &cp, nil
}

func (s *SimulatedDriver) SaveManagedState(st *ManagedState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = *st
	return nil
}
