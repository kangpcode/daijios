// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package wlanctrl

import (
	"sort"
	"strings"

	"github.com/kangpcode/daijios/pkg/wlanplan"
)

// NeighborScan represents one AP observing a neighbor AP's RF signal strength.
type NeighborScan struct {
	ReporterMAC string
	NeighborMAC string
	Band        string // "2.4ghz" or "5ghz"
	RSSIDBm     int
}

// RFPlan holds the computed RRM Auto-Channel & Auto-Power assignments for one AP.
type RFPlan struct {
	MAC       string `json:"mac"`
	Name      string `json:"name"`
	Channel2G int    `json:"channel_2g"`
	Channel5G int    `json:"channel_5g"`
	Power2G   int    `json:"power_2g_dbm"`
	Power5G   int    `json:"power_5g_dbm"`
}

// OptimizeRF runs RRM graph-coloring channel assignment and TPC auto-power calibration.
func OptimizeRF(aps []wlanplan.ManagedAP, rf wlanplan.WLANRFProfile, scans []NeighborScan) []RFPlan {
	allowed2G := rf.AutoChannel.Allowed2GChannels
	if len(allowed2G) == 0 {
		allowed2G = []int{1, 6, 11}
	}
	allowed5G := rf.AutoChannel.Allowed5GChannels
	if len(allowed5G) == 0 {
		allowed5G = []int{36, 40, 44, 48, 149, 153, 157, 161}
	}
	minPwr := rf.AutoPower.MinTxDBm
	if minPwr <= 0 {
		minPwr = 10
	}
	maxPwr := rf.AutoPower.MaxTxDBm
	if maxPwr < minPwr {
		maxPwr = 20
	}
	targetRSSI := rf.AutoPower.TargetCoverageRSSIDBm
	if targetRSSI == 0 {
		targetRSSI = -68
	}

	// Build symmetric neighbor RSSI adjacency map.
	adj := make(map[string]map[string]int)
	addEdge := func(a, b string, rssi int) {
		a, b = strings.ToLower(a), strings.ToLower(b)
		if a == b {
			return
		}
		if adj[a] == nil {
			adj[a] = make(map[string]int)
		}
		if prev, ok := adj[a][b]; !ok || rssi > prev {
			adj[a][b] = rssi
		}
	}
	for _, sc := range scans {
		addEdge(sc.ReporterMAC, sc.NeighborMAC, sc.RSSIDBm)
		addEdge(sc.NeighborMAC, sc.ReporterMAC, sc.RSSIDBm)
	}

	sortedAPs := append([]wlanplan.ManagedAP(nil), aps...)
	sort.Slice(sortedAPs, func(i, j int) bool { return strings.ToLower(sortedAPs[i].MAC) < strings.ToLower(sortedAPs[j].MAC) })

	assigned2G := make(map[string]int)
	assigned5G := make(map[string]int)
	plans := make([]RFPlan, 0, len(sortedAPs))

	pickBestChannel := func(mac string, candidates []int, assigned map[string]int) int {
		bestCh := candidates[0]
		bestScore := 1 << 30
		for _, ch := range candidates {
			penalty := 0
			for nb, rssi := range adj[mac] {
				if nbCh, ok := assigned[nb]; ok && nbCh == ch {
					weight := 100 + rssi
					if weight < 1 {
						weight = 1
					}
					penalty += weight * 100
				}
			}
			// Cold-start tie-breaker: spread APs across orthogonal channels even before scans arrive.
			for _, usedCh := range assigned {
				if usedCh == ch {
					penalty++
				}
			}
			if penalty < bestScore {
				bestScore = penalty
				bestCh = ch
			}
		}
		return bestCh
	}

	for _, ap := range sortedAPs {
		if !ap.Enabled {
			continue
		}
		mac := strings.ToLower(ap.MAC)
		ch2 := ap.Radio2GChannel
		if ch2 == 0 {
			ch2 = pickBestChannel(mac, allowed2G, assigned2G)
		}
		assigned2G[mac] = ch2

		ch5 := ap.Radio5GChannel
		if ch5 == 0 {
			ch5 = pickBestChannel(mac, allowed5G, assigned5G)
		}
		assigned5G[mac] = ch5

		// TPC: compute max neighbor RSSI to calibrate transmit power against overlap.
		maxNeighborRSSI := -95
		for _, rssi := range adj[mac] {
			if rssi > maxNeighborRSSI {
				maxNeighborRSSI = rssi
			}
		}
		midPwr := (minPwr + maxPwr) / 2
		calPwr := midPwr
		if rf.AutoPower.Enabled {
			if maxNeighborRSSI > targetRSSI+8 {
				calPwr = minPwr // High neighbor overlap -> reduce Tx power to shrink cell overlap.
			} else if maxNeighborRSSI < targetRSSI-10 {
				calPwr = maxPwr // Sparse neighbors -> boost Tx power for coverage.
			}
		}
		pwr2 := calPwr
		if ap.TxPower2GDBm > 0 {
			pwr2 = ap.TxPower2GDBm
		}
		pwr5 := calPwr
		if ap.TxPower5GDBm > 0 {
			pwr5 = ap.TxPower5GDBm
		}

		plans = append(plans, RFPlan{
			MAC:       mac,
			Name:      ap.Name,
			Channel2G: ch2,
			Channel5G: ch5,
			Power2G:   pwr2,
			Power5G:   pwr5,
		})
	}
	return plans
}
