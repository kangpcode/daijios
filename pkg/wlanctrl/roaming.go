// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package wlanctrl

import (
	"strings"
	"sync"

	"github.com/kangpcode/daijios/pkg/wlanplan"
)

// SteerDecision describes whether a client probing 2.4GHz should be steered to 5GHz.
type SteerDecision struct {
	AllowAssoc  bool   `json:"allow_assoc"`
	SteerToBand string `json:"steer_to_band,omitempty"`
	Reason      string `json:"reason"`
}

// BandSteerAdvisor tracks dual-band capabilities and prevents legacy/weak clients from starvation.
type BandSteerAdvisor struct {
	mu           sync.Mutex
	cfg          wlanplan.BandSteeringConfig
	seen5G       map[string]bool
	rejectCount  map[string]int
}

func NewBandSteerAdvisor(cfg wlanplan.BandSteeringConfig) *BandSteerAdvisor {
	if cfg.Prefer5GHzRSSI == 0 {
		cfg.Prefer5GHzRSSI = -70
	}
	if cfg.Max2GRejects <= 0 {
		cfg.Max2GRejects = 3
	}
	return &BandSteerAdvisor{
		cfg:         cfg,
		seen5G:      make(map[string]bool),
		rejectCount: make(map[string]int),
	}
}

func (b *BandSteerAdvisor) Record5GHzProbe(clientMAC string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seen5G[strings.ToLower(clientMAC)] = true
}

// Evaluate2GHzAssoc decides whether to withhold 2.4GHz association to steer capable clients to 5GHz.
func (b *BandSteerAdvisor) Evaluate2GHzAssoc(clientMAC string, rssi2GDBm int) SteerDecision {
	if !b.cfg.Enabled {
		return SteerDecision{AllowAssoc: true, Reason: "band steering disabled"}
	}
	mac := strings.ToLower(clientMAC)
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.seen5G[mac] {
		return SteerDecision{AllowAssoc: true, Reason: "2.4GHz-only or 5GHz unverified client"}
	}
	if rssi2GDBm < b.cfg.Prefer5GHzRSSI {
		return SteerDecision{AllowAssoc: true, Reason: "weak signal; keep 2.4GHz range fallback"}
	}
	if b.rejectCount[mac] >= b.cfg.Max2GRejects {
		return SteerDecision{AllowAssoc: true, Reason: "max 2.4GHz steering attempts reached; fallback allowed"}
	}
	b.rejectCount[mac]++
	return SteerDecision{
		AllowAssoc:  false,
		SteerToBand: "5ghz",
		Reason:      "dual-band strong signal; steering client to 5GHz",
	}
}

// NeighborCandidate represents an 802.11k neighbor report candidate for 802.11v BTM roaming.
type NeighborCandidate struct {
	APMAC   string
	BSSID   string
	Channel int
	RSSIDBm int
}

// BTMRecommendation suggests an 802.11v BSS Transition target when current RSSI degrades.
type BTMRecommendation struct {
	ShouldRoam bool   `json:"should_roam"`
	TargetAP   string `json:"target_ap,omitempty"`
	TargetCh   int    `json:"target_channel,omitempty"`
	Reason     string `json:"reason"`
}

// RecommendBTM evaluates whether an 802.11v BSS Transition frame should steer a roaming client.
func RecommendBTM(currentAP string, currentRSSI int, candidates []NeighborCandidate) BTMRecommendation {
	const roamTriggerRSSI = -72
	const minHysteresisDB = 8
	if currentRSSI > roamTriggerRSSI {
		return BTMRecommendation{ShouldRoam: false, Reason: "current AP RSSI above roam trigger"}
	}
	var best *NeighborCandidate
	for i := range candidates {
		c := &candidates[i]
		if strings.EqualFold(c.APMAC, currentAP) {
			continue
		}
		if c.RSSIDBm >= currentRSSI+minHysteresisDB {
			if best == nil || c.RSSIDBm > best.RSSIDBm {
				best = c
			}
		}
	}
	if best == nil {
		return BTMRecommendation{ShouldRoam: false, Reason: "no neighbor exceeds +8 dB roam hysteresis"}
	}
	return BTMRecommendation{
		ShouldRoam: true,
		TargetAP:   best.APMAC,
		TargetCh:   best.Channel,
		Reason:     "802.11v BTM roam to stronger neighbor AP",
	}
}
