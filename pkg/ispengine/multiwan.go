// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package ispengine

import (
	"fmt"
	"sort"
	"sync"

	"github.com/kangpcode/daijios/pkg/ispplan"
)

// WANStatus captures live health and probe counters for one WAN link.
type WANStatus struct {
	Name             string          `json:"name"`
	Interface        string          `json:"interface"`
	Gateway          string          `json:"gateway"`
	Weight           int             `json:"weight"`
	Distance         int             `json:"distance"`
	Up               bool            `json:"up"`
	ConsecutiveFails int             `json:"consecutive_fails"`
	ConsecutiveOKs   int             `json:"consecutive_oks"`
	LastRTTMS        float64         `json:"last_rtt_ms"`
	TargetResults    map[string]bool `json:"target_results"`
}

// WANTransition describes an emitted Multi-WAN state change event.
type WANTransition struct {
	WANName string `json:"wan_name"`
	Event   string `json:"event"` // "wan-up" or "wan-down"
}

// MultiWANMonitor tracks recursive/netwatch reachability and computes active failover/LB routes.
type MultiWANMonitor struct {
	mu     sync.Mutex
	cfg    ispplan.MultiWANBlock
	links  map[string]ispplan.MultiWANLink
	status map[string]*WANStatus
}

func NewMultiWANMonitor(cfg ispplan.MultiWANBlock) *MultiWANMonitor {
	m := &MultiWANMonitor{
		cfg:    cfg,
		links:  make(map[string]ispplan.MultiWANLink),
		status: make(map[string]*WANStatus),
	}
	for _, w := range cfg.WANs {
		if !w.Enabled {
			continue
		}
		m.links[w.Name] = w
		targets := make(map[string]bool, len(w.CheckTargets))
		for _, t := range w.CheckTargets {
			targets[t] = true
		}
		m.status[w.Name] = &WANStatus{
			Name:          w.Name,
			Interface:     w.Interface,
			Gateway:       w.Gateway,
			Weight:        w.Weight,
			Distance:      w.Distance,
			Up:            true,
			TargetResults: targets,
		}
	}
	return m
}

// RecordProbe ingests one probe result for (wanName, target) and applies anti-flap hysteresis.
// A link transitions DOWN only when ALL check_targets fail >= fail_threshold times.
func (m *MultiWANMonitor) RecordProbe(wanName, target string, rttMS float64, ok bool) *WANTransition {
	m.mu.Lock()
	defer m.mu.Unlock()

	link, exists := m.links[wanName]
	st, okSt := m.status[wanName]
	if !exists || !okSt {
		return nil
	}
	st.TargetResults[target] = ok
	if ok {
		st.LastRTTMS = rttMS
	}

	anyTargetUp := false
	for _, up := range st.TargetResults {
		if up {
			anyTargetUp = true
			break
		}
	}

	failThresh := link.FailThreshold
	if failThresh <= 0 {
		failThresh = 3
	}
	recThresh := link.RecoverThreshold
	if recThresh <= 0 {
		recThresh = 2
	}

	if !anyTargetUp {
		st.ConsecutiveOKs = 0
		st.ConsecutiveFails++
		if st.Up && st.ConsecutiveFails >= failThresh {
			st.Up = false
			return &WANTransition{WANName: wanName, Event: "wan-down"}
		}
	} else {
		st.ConsecutiveFails = 0
		st.ConsecutiveOKs++
		if !st.Up && st.ConsecutiveOKs >= recThresh {
			st.Up = true
			return &WANTransition{WANName: wanName, Event: "wan-up"}
		}
	}
	return nil
}

// ActiveDefaultRouteArgs computes the Linux `ip route replace default` arguments across UP WANs.
func (m *MultiWANMonitor) ActiveDefaultRouteArgs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var candidates []*WANStatus
	for _, st := range m.status {
		if st.Up {
			candidates = append(candidates, st)
		}
	}
	// Emergency fallback if all WANs fail simultaneously so management/recovery isn't blackholed.
	if len(candidates) == 0 {
		for _, st := range m.status {
			candidates = append(candidates, st)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Distance != candidates[j].Distance {
			return candidates[i].Distance < candidates[j].Distance
		}
		return candidates[i].Name < candidates[j].Name
	})
	if len(candidates) == 0 {
		return nil
	}

	if m.cfg.Mode == "failover" || len(candidates) == 1 {
		best := candidates[0]
		return []string{"route", "replace", "default", "via", best.Gateway, "dev", best.Interface}
	}

	args := []string{"route", "replace", "default"}
	for _, c := range candidates {
		w := c.Weight
		if w <= 0 {
			w = 1
		}
		args = append(args, "nexthop", "via", c.Gateway, "dev", c.Interface, "weight", fmt.Sprintf("%d", w))
	}
	return args
}

// Snapshot returns sorted WAN health states.
func (m *MultiWANMonitor) Snapshot() []WANStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]WANStatus, 0, len(m.status))
	for _, st := range m.status {
		cp := *st
		cp.TargetResults = make(map[string]bool, len(st.TargetResults))
		for k, v := range st.TargetResults {
			cp.TargetResults[k] = v
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
