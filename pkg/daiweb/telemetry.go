// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daiweb

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/ispengine"
	"github.com/kangpcode/daijios/pkg/isptools"
	"github.com/kangpcode/daijios/pkg/sysinfo"
	"github.com/kangpcode/daijios/pkg/wlanctrl"
)

// TelemetryEvent describes a single event/alarm row shown in DaiWeb.
type TelemetryEvent struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// TelemetrySnapshot holds real-time KPI metrics pushed over /ws/telemetry.
type TelemetrySnapshot struct {
	Brand          string                `json:"brand"`
	Version        string                `json:"version"`
	Architecture   string                `json:"architecture"`
	Hostname       string                `json:"hostname"`
	Theme          string                `json:"theme"`
	UptimeSec      int64                 `json:"uptime_sec"`
	CPUPercent     float64               `json:"cpu_percent"`
	MemUsedMB      uint64                `json:"mem_used_mb"`
	MemTotalMB     uint64                `json:"mem_total_mb"`
	RxMbps         float64               `json:"rx_mbps"`
	TxMbps         float64               `json:"tx_mbps"`
	ActiveSessions int                   `json:"active_sessions"`
	WANs           []ispengine.WANStatus `json:"wans,omitempty"`
	Alarms         []string              `json:"alarms"`
	Events         []TelemetryEvent      `json:"events"`
	Timestamp      string                `json:"timestamp"`
}

// TopologyNode models one visual node inside the interactive DaiWeb topology SVG.
type TopologyNode struct {
	ID      string         `json:"id"`
	Label   string         `json:"label"`
	Kind    string         `json:"kind"` // core | interface | bridge | wan | ap | vpn
	Up      bool           `json:"up"`
	Details map[string]any `json:"details,omitempty"`
}

// TopologyEdge connects two topology nodes.
type TopologyEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// TopologyGraph is returned by /api/v1/topology.
type TopologyGraph struct {
	Nodes []TopologyNode `json:"nodes"`
	Edges []TopologyEdge `json:"edges"`
}

// CollectTelemetrySnapshot aggregates CPU, RAM, Torch traffic, sessions, Multi-WAN, and alarms.
func CollectTelemetrySnapshot(
	eng *configengine.Engine,
	sessions *ispengine.SessionManager,
	multiWAN *ispengine.MultiWANMonitor,
	torch *isptools.TorchAggregator,
	bootTime time.Time,
	now time.Time,
) TelemetrySnapshot {
	hostname := "daiji"
	theme := "daiji-dark"
	if eng != nil {
		run := eng.GetRunning(true)
		if sysMap, ok := run["system"].(map[string]any); ok {
			if h, ok := sysMap["hostname"].(string); ok && h != "" {
				hostname = h
			}
		}
		if mgmt, ok := run["management"].(map[string]any); ok {
			if dw, ok := mgmt["daiweb"].(map[string]any); ok {
				if th, ok := dw["theme"].(string); ok && th != "" {
					theme = th
				}
			}
		}
	}

	cpuPct, memUsed, memTotal := readHostMetrics()

	var rxBps, txBps float64
	if torch != nil {
		for _, r := range torch.Snapshot(5.0, 50) {
			rxBps += float64(r.RxBytes) * 8 / 5.0
			txBps += float64(r.TxBytes) * 8 / 5.0
		}
	}

	activeSess := 0
	if sessions != nil {
		activeSess = len(sessions.ListSessions())
	}

	alarms := []string{}
	var wans []ispengine.WANStatus
	if multiWAN != nil {
		wans = multiWAN.Snapshot()
		for _, w := range wans {
			if !w.Up {
				alarms = append(alarms, fmt.Sprintf("WAN link %s (%s) is DOWN", w.Name, w.Interface))
			}
		}
	}

	events := []TelemetryEvent{
		{Time: now.Format("15:04:05"), Level: "info", Message: fmt.Sprintf("DaiWeb telemetry healthy on %s", hostname)},
	}
	if eng != nil {
		if revs, err := eng.ListRevisions(); err == nil && len(revs) > 0 {
			latest := revs[0]
			events = append(events, TelemetryEvent{
				Time:    latest.Timestamp.Format("15:04:05"),
				Level:   "audit",
				Message: fmt.Sprintf("Revision %s by %s: %s", latest.ID, latest.Actor, latest.Message),
			})
		}
	}
	for _, al := range alarms {
		events = append(events, TelemetryEvent{Time: now.Format("15:04:05"), Level: "warn", Message: al})
	}

	uptime := int64(now.Sub(bootTime).Seconds())
	if uptime < 0 {
		uptime = 0
	}

	return TelemetrySnapshot{
		Brand:          sysinfo.BrandBanner,
		Version:        sysinfo.Version,
		Architecture:   sysinfo.NormalizeArch(runtime.GOARCH),
		Hostname:       hostname,
		Theme:          theme,
		UptimeSec:      uptime,
		CPUPercent:     cpuPct,
		MemUsedMB:      memUsed,
		MemTotalMB:     memTotal,
		RxMbps:         rxBps / 1_000_000.0,
		TxMbps:         txBps / 1_000_000.0,
		ActiveSessions: activeSess,
		WANs:           wans,
		Alarms:         alarms,
		Events:         events,
		Timestamp:      now.UTC().Format(time.RFC3339),
	}
}

// BuildTopologyGraph projects the active running SSoT config and runtime health into an interactive graph.
func BuildTopologyGraph(eng *configengine.Engine, multiWAN *ispengine.MultiWANMonitor, ac *wlanctrl.ACController) TopologyGraph {
	hostname := "daiji-core"
	var run map[string]any
	if eng != nil {
		run = eng.GetRunning(true)
		if sysMap, ok := run["system"].(map[string]any); ok {
			if h, ok := sysMap["hostname"].(string); ok && h != "" {
				hostname = h
			}
		}
	}

	nodes := []TopologyNode{{
		ID:      "core",
		Label:   hostname,
		Kind:    "core",
		Up:      true,
		Details: map[string]any{"version": sysinfo.Version, "arch": sysinfo.NormalizeArch(runtime.GOARCH)},
	}}
	var edges []TopologyEdge

	if run != nil {
		if ifaces, ok := run["interfaces"].(map[string]any); ok {
			if phys, ok := ifaces["physical"].([]any); ok {
				for _, item := range phys {
					m, _ := item.(map[string]any)
					name := fmt.Sprintf("%v", m["name"])
					nid := "if:" + name
					up, _ := m["enabled"].(bool)
					nodes = append(nodes, TopologyNode{ID: nid, Label: name, Kind: "interface", Up: up, Details: m})
					edges = append(edges, TopologyEdge{From: "core", To: nid, Kind: fmt.Sprintf("%v", m["role"])})
				}
			}
			if brs, ok := ifaces["bridges"].([]any); ok {
				for _, item := range brs {
					m, _ := item.(map[string]any)
					name := fmt.Sprintf("%v", m["name"])
					nid := "br:" + name
					up, _ := m["enabled"].(bool)
					nodes = append(nodes, TopologyNode{ID: nid, Label: name, Kind: "bridge", Up: up, Details: m})
					edges = append(edges, TopologyEdge{From: "core", To: nid, Kind: "bridge"})
				}
			}
		}
		if vpnMap, ok := run["vpn"].(map[string]any); ok {
			if wgs, ok := vpnMap["wireguard"].([]any); ok {
				for _, item := range wgs {
					m, _ := item.(map[string]any)
					name := fmt.Sprintf("%v", m["interface"])
					nid := "wg:" + name
					up, _ := m["enabled"].(bool)
					nodes = append(nodes, TopologyNode{
						ID:      nid,
						Label:   name,
						Kind:    "vpn",
						Up:      up,
						Details: map[string]any{"interface": name, "listen_port": m["listen_port"], "addresses": m["addresses"]},
					})
					edges = append(edges, TopologyEdge{From: "core", To: nid, Kind: "wireguard"})
				}
			}
		}
	}

	if multiWAN != nil {
		for _, w := range multiWAN.Snapshot() {
			nid := "wan:" + w.Name
			nodes = append(nodes, TopologyNode{
				ID:    nid,
				Label: w.Name,
				Kind:  "wan",
				Up:    w.Up,
				Details: map[string]any{
					"interface": w.Interface,
					"gateway":   w.Gateway,
					"rtt_ms":    w.LastRTTMS,
					"up":        w.Up,
				},
			})
			edges = append(edges, TopologyEdge{From: "core", To: nid, Kind: "uplink"})
		}
	}

	if ac != nil {
		for _, ap := range ac.ListAPs() {
			nid := "ap:" + ap.Name
			nodes = append(nodes, TopologyNode{
				ID:      nid,
				Label:   ap.Name,
				Kind:    "ap",
				Up:      ap.Online,
				Details: map[string]any{"mac": ap.MAC, "model": ap.Model, "ch2g": ap.Ch2G, "ch5g": ap.Ch5G, "clients": ap.Clients},
			})
			edges = append(edges, TopologyEdge{From: "core", To: nid, Kind: "capwap"})
		}
	}

	return TopologyGraph{Nodes: nodes, Edges: edges}
}

func readHostMetrics() (cpuPct float64, memUsedMB, memTotalMB uint64) {
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		var totalKB, availKB uint64
		for _, ln := range strings.Split(string(raw), "\n") {
			f := strings.Fields(ln)
			if len(f) < 2 {
				continue
			}
			v, _ := strconv.ParseUint(f[1], 10, 64)
			switch f[0] {
			case "MemTotal:":
				totalKB = v
			case "MemAvailable:":
				availKB = v
			}
		}
		if totalKB > 0 {
			memTotalMB = totalKB / 1024
			if totalKB >= availKB {
				memUsedMB = (totalKB - availKB) / 1024
			}
		}
	}
	if memTotalMB == 0 {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		memUsedMB = ms.Alloc / (1024 * 1024)
		memTotalMB = 256
	}

	if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(raw))
		if len(f) > 0 {
			if load1, err := strconv.ParseFloat(f[0], 64); err == nil {
				pct := (load1 / float64(max(1, runtime.NumCPU()))) * 100.0
				if pct > 100 {
					pct = 100
				}
				cpuPct = pct
			}
		}
	}
	return cpuPct, memUsedMB, memTotalMB
}
