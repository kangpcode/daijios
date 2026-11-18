// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package wlanctrl

import (
	"sort"
	"strings"

	"github.com/kangpcode/daijios/pkg/wlanplan"
)

// MeshBackhaulLink models a measured wireless backhaul link between two Mesh APs.
type MeshBackhaulLink struct {
	FromMAC string
	ToMAC   string
	RSSIDBm int
	Alive   bool
}

// MeshHopAssignment represents one node's active parent uplink and hop depth from a Mesh root.
type MeshHopAssignment struct {
	APMAC     string `json:"ap_mac"`
	APName    string `json:"ap_name"`
	Role      string `json:"role"`
	ParentMAC string `json:"parent_mac,omitempty"`
	HopCount  int    `json:"hop_count"`
	PathRSSI  int    `json:"min_path_rssi_dbm"`
}

// SolveMeshTopology builds a loop-free, self-healing Mesh tree honoring max_hops and highest backhaul RSSI.
func SolveMeshTopology(aps []wlanplan.ManagedAP, links []MeshBackhaulLink, maxHops int) []MeshHopAssignment {
	if maxHops <= 0 {
		maxHops = 4
	}
	apByMAC := make(map[string]wlanplan.ManagedAP)
	dist := make(map[string]int)
	hops := make(map[string]int)
	parent := make(map[string]string)

	for _, ap := range aps {
		if !ap.Enabled || ap.MeshRole == "disabled" {
			continue
		}
		mac := strings.ToLower(ap.MAC)
		apByMAC[mac] = ap
		if ap.MeshRole == "root" {
			dist[mac] = 0 // Cost 0 at root
			hops[mac] = 0
		} else {
			dist[mac] = 1 << 28
			hops[mac] = 1 << 20
		}
	}

	// Build undirected alive backhaul adjacency list; cost = max(1, -RSSI).
	type edge struct {
		to   string
		cost int
		rssi int
	}
	adj := make(map[string][]edge)
	for _, l := range links {
		if !l.Alive {
			continue
		}
		a, b := strings.ToLower(l.FromMAC), strings.ToLower(l.ToMAC)
		c := -l.RSSIDBm
		if c < 1 {
			c = 1
		}
		adj[a] = append(adj[a], edge{to: b, cost: c, rssi: l.RSSIDBm})
		adj[b] = append(adj[b], edge{to: a, cost: c, rssi: l.RSSIDBm})
	}

	// Bellman-Ford / relaxation bounded by maxHops ensures loop-free optimal SNR tree.
	for step := 0; step < len(apByMAC); step++ {
		changed := false
		for u, d := range dist {
			if d >= (1<<27) || hops[u] >= maxHops {
				continue
			}
			for _, e := range adj[u] {
				if _, valid := apByMAC[e.to]; !valid {
					continue
				}
				candCost := d + e.cost
				if candCost < dist[e.to] {
					dist[e.to] = candCost
					hops[e.to] = hops[u] + 1
					parent[e.to] = u
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}

	out := make([]MeshHopAssignment, 0, len(apByMAC))
	for mac, ap := range apByMAC {
		h := hops[mac]
		if h >= (1 << 19) {
			h = -1 // Unreachable
		}
		out = append(out, MeshHopAssignment{
			APMAC:     mac,
			APName:    ap.Name,
			Role:      ap.MeshRole,
			ParentMAC: parent[mac],
			HopCount:  h,
			PathRSSI:  -dist[mac],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].APMAC < out[j].APMAC })
	return out
}
