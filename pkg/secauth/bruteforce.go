// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package secauth

import (
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// BruteForcePolicy defines sliding-window auth failure limits and ban durations.
type BruteForcePolicy struct {
	Enabled       bool
	MaxAttempts   int
	Window        time.Duration
	BanDuration   time.Duration
	Whitelist     []netip.Prefix
	NFTTable      string
	NFTSetV4      string
	NFTSetV6      string
}

// BanDecision reports whether an IP is newly or currently banned and emits the nft command.
type BanDecision struct {
	Banned     bool
	NewlyBanned bool
	ExpiresAt  time.Time
	NFTCmdArgs []string
}

// BruteForceGuard tracks per-source authentication failures in bounded sliding windows.
type BruteForceGuard struct {
	mu       sync.Mutex
	policy   BruteForcePolicy
	attempts map[netip.Addr][]time.Time
	bans     map[netip.Addr]time.Time
}

func NewBruteForceGuard(p BruteForcePolicy) *BruteForceGuard {
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = 5
	}
	if p.Window <= 0 {
		p.Window = 5 * time.Minute
	}
	if p.BanDuration <= 0 {
		p.BanDuration = time.Hour
	}
	if p.NFTTable == "" {
		p.NFTTable = "inet daiji_filter"
	}
	if p.NFTSetV4 == "" {
		p.NFTSetV4 = "daiji_ban_v4"
	}
	if p.NFTSetV6 == "" {
		p.NFTSetV6 = "daiji_ban_v6"
	}
	return &BruteForceGuard{
		policy:   p,
		attempts: make(map[netip.Addr][]time.Time),
		bans:     make(map[netip.Addr]time.Time),
	}
}

// IsBanned returns whether srcIP is currently banned (never banning whitelisted subnets).
func (g *BruteForceGuard) IsBanned(srcIP netip.Addr, now time.Time) bool {
	if !g.policy.Enabled || g.isWhitelisted(srcIP) {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	exp, ok := g.bans[srcIP]
	if !ok {
		return false
	}
	if !now.Before(exp) {
		delete(g.bans, srcIP)
		return false
	}
	return true
}

// RecordFailure logs an authentication failure and triggers a timed nftables ban if threshold reached.
func (g *BruteForceGuard) RecordFailure(srcIP netip.Addr, now time.Time) BanDecision {
	if !g.policy.Enabled || !srcIP.IsValid() || g.isWhitelisted(srcIP) {
		return BanDecision{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if exp, ok := g.bans[srcIP]; ok && now.Before(exp) {
		return BanDecision{Banned: true, ExpiresAt: exp}
	}

	cutoff := now.Add(-g.policy.Window)
	prev := g.attempts[srcIP]
	kept := prev[:0]
	for _, ts := range prev {
		if !ts.Before(cutoff) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, now)
	g.attempts[srcIP] = kept

	if len(kept) < g.policy.MaxAttempts {
		return BanDecision{}
	}

	exp := now.Add(g.policy.BanDuration)
	g.bans[srcIP] = exp
	delete(g.attempts, srcIP)

	setName := g.policy.NFTSetV4
	if srcIP.Is6() {
		setName = g.policy.NFTSetV6
	}
	banSec := int(g.policy.BanDuration.Seconds())
	elem := fmt.Sprintf("{ %s timeout %ds }", srcIP.String(), banSec)
	return BanDecision{
		Banned:      true,
		NewlyBanned: true,
		ExpiresAt:   exp,
		NFTCmdArgs:  []string{"add", "element", "inet", "daiji_filter", setName, elem},
	}
}

// RecordSuccess clears failure attempts after successful login.
func (g *BruteForceGuard) RecordSuccess(srcIP netip.Addr) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.attempts, srcIP)
}

func (g *BruteForceGuard) isWhitelisted(ip netip.Addr) bool {
	for _, pfx := range g.policy.Whitelist {
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}
