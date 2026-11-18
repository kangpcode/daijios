// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package wlanctrl implements the DaijiOS Wireless Controller (AC) runtime:
// zero-touch AP discovery/onboarding, RRM Auto-Channel & Auto-Power optimization,
// Band Steering, 802.11k/v/r Roaming advisor, and self-healing Mesh topology solver.
package wlanctrl

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kangpcode/daijios/pkg/wlanplan"
)

var (
	ErrAdoptRejected = errors.New("AP onboarding rejected by AC policy")
	ErrUnknownAP     = errors.New("access point not found in AC inventory")
)

type APStatus struct {
	MAC          string    `json:"mac"`
	Name         string    `json:"name"`
	Serial       string    `json:"serial"`
	Model        string    `json:"model"`
	APGroup      string    `json:"ap_group"`
	IP           string    `json:"ip"`
	MeshRole     string    `json:"mesh_role"`
	Online       bool      `json:"online"`
	Adopted      bool      `json:"adopted"`
	Channel2G    int       `json:"channel_2g"`
	Channel5G    int       `json:"channel_5g"`
	TxPower2GDBm int       `json:"tx_power_2g_dbm"`
	TxPower5GDBm int       `json:"tx_power_5g_dbm"`
	ClientCount  int       `json:"client_count"`
	LastSeen     time.Time `json:"last_seen"`
}

type AdoptRequest struct {
	MAC    string
	Serial string
	Model  string
	IP     string
	Token  string
}

// ComputeOnboardingToken derives a deterministic HMAC-SHA256 ZTP onboarding token for an AP serial/MAC.
func ComputeOnboardingToken(masterSecret, mac, serial string) string {
	h := hmac.New(sha256.New, []byte(masterSecret))
	_, _ = h.Write([]byte(strings.ToLower(mac) + "|" + serial))
	return hex.EncodeToString(h.Sum(nil))
}

// ACController manages adopted AP lifecycle and telemetry.
type ACController struct {
	mu      sync.Mutex
	cfg     wlanplan.WirelessBlock
	aps     map[string]*APStatus
	nowFn   func() time.Time
}

func NewACController(cfg wlanplan.WirelessBlock, nowFn func() time.Time) *ACController {
	if nowFn == nil {
		nowFn = time.Now
	}
	ac := &ACController{
		cfg:   cfg,
		aps:   make(map[string]*APStatus),
		nowFn: nowFn,
	}
	for _, ap := range cfg.APs {
		norm := strings.ToLower(ap.MAC)
		ac.aps[norm] = &APStatus{
			MAC:          norm,
			Name:         ap.Name,
			Serial:       ap.Serial,
			Model:        ap.Model,
			APGroup:      ap.APGroup,
			MeshRole:     ap.MeshRole,
			Adopted:      true,
			Channel2G:    ap.Radio2GChannel,
			Channel5G:    ap.Radio5GChannel,
			TxPower2GDBm: ap.TxPower2GDBm,
			TxPower5GDBm: ap.TxPower5GDBm,
		}
	}
	return ac
}

// DiscoverAndAdopt processes a CAPWAP/DTLS AP join request using AC auto-adopt policy.
func (ac *ACController) DiscoverAndAdopt(req AdoptRequest) (*APStatus, error) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	normMAC := strings.ToLower(strings.TrimSpace(req.MAC))
	if normMAC == "" {
		return nil, fmt.Errorf("%w: empty MAC", ErrAdoptRejected)
	}

	if existing, ok := ac.aps[normMAC]; ok && existing.Adopted {
		existing.IP = req.IP
		existing.Online = true
		existing.LastSeen = ac.nowFn().UTC()
		if existing.Serial == "" {
			existing.Serial = req.Serial
		}
		if existing.Model == "" {
			existing.Model = req.Model
		}
		cp := *existing
		return &cp, nil
	}

	switch ac.cfg.Controller.AutoAdoptPolicy {
	case "manual", "whitelist":
		return nil, fmt.Errorf("%w: AP %s is not pre-provisioned under policy %s",
			ErrAdoptRejected, normMAC, ac.cfg.Controller.AutoAdoptPolicy)
	case "zero-touch-token":
		expected := ComputeOnboardingToken(ac.cfg.Controller.OnboardingToken, normMAC, req.Serial)
		if !hmac.Equal([]byte(req.Token), []byte(expected)) {
			return nil, fmt.Errorf("%w: invalid zero-touch onboarding token for %s", ErrAdoptRejected, normMAC)
		}
		grp := ac.cfg.Controller.DefaultAPGroup
		if grp == "" && len(ac.cfg.APGroups) > 0 {
			grp = ac.cfg.APGroups[0].Name
		}
		st := &APStatus{
			MAC:      normMAC,
			Name:     "ap-" + strings.ReplaceAll(normMAC, ":", "")[6:],
			Serial:   req.Serial,
			Model:    req.Model,
			APGroup:  grp,
			IP:       req.IP,
			MeshRole: "disabled",
			Online:   true,
			Adopted:  true,
			LastSeen: ac.nowFn().UTC(),
		}
		ac.aps[normMAC] = st
		cp := *st
		return &cp, nil
	default:
		return nil, fmt.Errorf("%w: unsupported adopt policy %q", ErrAdoptRejected, ac.cfg.Controller.AutoAdoptPolicy)
	}
}

// RecordHeartbeat updates live client count and online timestamp for an adopted AP.
func (ac *ACController) RecordHeartbeat(mac string, clients int) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	normMAC := strings.ToLower(mac)
	ap, ok := ac.aps[normMAC]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownAP, mac)
	}
	ap.Online = true
	ap.ClientCount = clients
	ap.LastSeen = ac.nowFn().UTC()
	return nil
}

// Inventory returns sorted AP states.
func (ac *ACController) Inventory() []APStatus {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	out := make([]APStatus, 0, len(ac.aps))
	for _, ap := range ac.aps {
		out = append(out, *ap)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}
