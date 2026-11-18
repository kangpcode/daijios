// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package ispengine

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kangpcode/daijios/pkg/ispplan"
)

var (
	ErrAuthFailed      = errors.New("subscriber authentication failed")
	ErrAccountDisabled = errors.New("subscriber account disabled")
	ErrMACMismatch     = errors.New("caller MAC binding mismatch")
	ErrSessionLimit    = errors.New("maximum concurrent sessions reached")
	ErrVoucherInvalid  = errors.New("hotspot voucher invalid or exhausted")
)

// SubscriberSession models an active PPPoE, IPoE, or Hotspot session.
type SubscriberSession struct {
	SessionID         string    `json:"session_id"`
	Username          string    `json:"username"`
	Service           string    `json:"service"`
	CallingMAC        string    `json:"calling_mac"`
	AssignedIP        string    `json:"assigned_ip"`
	Profile           string    `json:"profile"`
	DownloadKbps      int       `json:"download_kbps"`
	UploadKbps        int       `json:"upload_kbps"`
	Isolated          bool      `json:"isolated"`
	DataLimitMB       int       `json:"data_limit_mb"`
	InputBytes        uint64    `json:"input_bytes"`
	OutputBytes       uint64    `json:"output_bytes"`
	SessionTimeoutSec int       `json:"session_timeout_sec"`
	StartedAt         time.Time `json:"started_at"`
	LastAccountingAt  time.Time `json:"last_accounting_at"`
}

// SessionManager handles subscriber AAA, IP pool allocation, MAC binding,
// expired-user isolation, Hotspot vouchers, accounting, and live CoA updates.
type SessionManager struct {
	mu           sync.Mutex
	profiles     map[string]ispplan.ISPProfile
	pools        map[string][]netip.Prefix
	poolCursors  map[string]int
	secrets      map[string]ispplan.PPPoESecret
	vouchers     map[string]ispplan.HotspotVoucher
	voucherUsage map[string]int
	sessions     map[string]*SubscriberSession
	seq          uint64
}

func NewSessionManager(cfg *ispplan.ISPBlock) *SessionManager {
	m := &SessionManager{
		profiles:     make(map[string]ispplan.ISPProfile),
		pools:        make(map[string][]netip.Prefix),
		poolCursors:  make(map[string]int),
		secrets:      make(map[string]ispplan.PPPoESecret),
		vouchers:     make(map[string]ispplan.HotspotVoucher),
		voucherUsage: make(map[string]int),
		sessions:     make(map[string]*SubscriberSession),
	}
	if cfg == nil {
		return m
	}
	for _, pr := range cfg.Profiles {
		m.profiles[pr.Name] = pr
	}
	for _, pl := range cfg.IPPools {
		var pfxs []netip.Prefix
		for _, r := range pl.Ranges {
			if p, err := netip.ParsePrefix(r); err == nil {
				pfxs = append(pfxs, p)
			}
		}
		m.pools[pl.Name] = pfxs
	}
	for _, sec := range cfg.PPPoE.Secrets {
		m.secrets[sec.Username] = sec
	}
	for _, v := range cfg.Hotspot.Vouchers {
		m.vouchers[v.Code] = v
	}
	return m
}

// AuthenticatePPPoE validates local credentials, MAC binding, shared-users limit,
// and expiry status (isolating into expired_pool if expired_pool is defined).
func (m *SessionManager) AuthenticatePPPoE(username, password, callerMAC string, now time.Time) (*SubscriberSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sec, ok := m.secrets[username]
	if !ok {
		return nil, ErrAuthFailed
	}
	if sec.Disabled {
		return nil, ErrAccountDisabled
	}
	if subtle.ConstantTimeCompare([]byte(sec.Password), []byte(password)) != 1 {
		return nil, ErrAuthFailed
	}
	if sec.CallerMAC != "" && !strings.EqualFold(sec.CallerMAC, callerMAC) {
		return nil, fmt.Errorf("%w: expected %s got %s", ErrMACMismatch, sec.CallerMAC, callerMAC)
	}

	prof := m.profiles[sec.Profile]
	activeCount := 0
	for _, sess := range m.sessions {
		if sess.Username == username {
			activeCount++
		}
	}
	maxShared := prof.SharedUsers
	if maxShared <= 0 {
		maxShared = 1
	}
	if activeCount >= maxShared {
		return nil, fmt.Errorf("%w: user %s limit=%d", ErrSessionLimit, username, maxShared)
	}

	isolated := false
	targetPool := prof.AddressPool
	if sec.ExpiresAt != "" {
		if exp, err := time.Parse(time.RFC3339, sec.ExpiresAt); err == nil && !now.Before(exp) {
			if prof.ExpiredPool == "" {
				return nil, fmt.Errorf("%w: subscription expired at %s", ErrAuthFailed, sec.ExpiresAt)
			}
			isolated = true
			targetPool = prof.ExpiredPool
		}
	}

	assignedIP := sec.StaticIP
	if assignedIP == "" || isolated {
		ip, err := m.allocIP(targetPool)
		if err != nil {
			return nil, err
		}
		assignedIP = ip
	}

	m.seq++
	sess := &SubscriberSession{
		SessionID:         fmt.Sprintf("daiji-sess-%06d", m.seq),
		Username:          username,
		Service:           "pppoe",
		CallingMAC:        callerMAC,
		AssignedIP:        assignedIP,
		Profile:           prof.Name,
		DownloadKbps:      prof.DownloadKbps,
		UploadKbps:        prof.UploadKbps,
		Isolated:          isolated,
		SessionTimeoutSec: prof.SessionTimeoutSec,
		StartedAt:         now.UTC(),
		LastAccountingAt:  now.UTC(),
	}
	if isolated {
		sess.DownloadKbps = 128
		sess.UploadKbps = 128
	}
	m.sessions[sess.SessionID] = sess
	cp := *sess
	return &cp, nil
}

// RedeemHotspotVoucher authenticates a captive-portal user by voucher code.
func (m *SessionManager) RedeemHotspotVoucher(code, mac string, now time.Time) (*SubscriberSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	v, ok := m.vouchers[code]
	if !ok || v.Disabled {
		return nil, ErrVoucherInvalid
	}
	if v.ExpiresAt != "" {
		if exp, err := time.Parse(time.RFC3339, v.ExpiresAt); err == nil && !now.Before(exp) {
			return nil, fmt.Errorf("%w: voucher expired", ErrVoucherInvalid)
		}
	}
	maxDev := v.MaxDevices
	if maxDev <= 0 {
		maxDev = 1
	}
	if m.voucherUsage[code] >= maxDev {
		return nil, fmt.Errorf("%w: max_devices=%d reached", ErrVoucherInvalid, maxDev)
	}
	prof := m.profiles[v.Profile]
	ip, err := m.allocIP(prof.AddressPool)
	if err != nil {
		return nil, err
	}

	m.voucherUsage[code]++
	m.seq++
	sess := &SubscriberSession{
		SessionID:         fmt.Sprintf("daiji-hs-%06d", m.seq),
		Username:          "voucher:" + code,
		Service:           "hotspot",
		CallingMAC:        mac,
		AssignedIP:        ip,
		Profile:           prof.Name,
		DownloadKbps:      prof.DownloadKbps,
		UploadKbps:        prof.UploadKbps,
		DataLimitMB:       v.DataLimitMB,
		SessionTimeoutSec: v.ValiditySec,
		StartedAt:         now.UTC(),
		LastAccountingAt:  now.UTC(),
	}
	m.sessions[sess.SessionID] = sess
	cp := *sess
	return &cp, nil
}

// InterimAccounting updates octet counters and returns whether session exceeded quota or timeout.
func (m *SessionManager) InterimAccounting(sessionID string, inBytes, outBytes uint64, now time.Time) (exceeded bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sessionID]
	if !ok {
		return false, fmt.Errorf("session %q not found", sessionID)
	}
	sess.InputBytes = inBytes
	sess.OutputBytes = outBytes
	sess.LastAccountingAt = now.UTC()

	if sess.DataLimitMB > 0 {
		totalMB := (inBytes + outBytes) / (1024 * 1024)
		if totalMB >= uint64(sess.DataLimitMB) {
			delete(m.sessions, sessionID)
			return true, nil
		}
	}
	if sess.SessionTimeoutSec > 0 && now.Sub(sess.StartedAt) >= time.Duration(sess.SessionTimeoutSec)*time.Second {
		delete(m.sessions, sessionID)
		return true, nil
	}
	return false, nil
}

// HandleCoAPacket processes an RFC 5176 CoA-Request or Disconnect-Request against live sessions.
func (m *SessionManager) HandleCoAPacket(req *RADIUSPacket) (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sessID := req.GetString(AttrAcctSessionID)
	user := req.GetString(AttrUserName)
	var target *SubscriberSession
	if sessID != "" {
		target = m.sessions[sessID]
	} else if user != "" {
		for _, s := range m.sessions {
			if s.Username == user {
				target = s
				break
			}
		}
	}
	if target == nil {
		return false, "session not found"
	}

	if req.Code == CodeDisconnectRequest {
		delete(m.sessions, target.SessionID)
		return true, "disconnected"
	}

	if filter := req.GetString(AttrFilterID); strings.EqualFold(filter, "ISOLIR") {
		target.Isolated = true
		target.DownloadKbps = 64
		target.UploadKbps = 64
	} else if strings.EqualFold(filter, "ACTIVE") || strings.EqualFold(filter, "NORMAL") {
		target.Isolated = false
	}
	if rateExpr := req.GetDaijiRateLimit(); rateExpr != "" {
		var up, down int
		if _, err := fmt.Sscanf(rateExpr, "%d/%d", &up, &down); err == nil && up > 0 && down > 0 {
			target.UploadKbps = up
			target.DownloadKbps = down
			if !strings.EqualFold(req.GetString(AttrFilterID), "ISOLIR") {
				target.Isolated = false
			}
		}
	}
	return true, "coa applied"
}

// ListSessions returns active sessions sorted by SessionID.
func (m *SessionManager) ListSessions() []SubscriberSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SubscriberSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SessionID < out[j].SessionID })
	return out
}

func (m *SessionManager) allocIP(poolName string) (string, error) {
	pfxs := m.pools[poolName]
	if len(pfxs) == 0 {
		return "", fmt.Errorf("ip pool %q has no prefixes", poolName)
	}
	p := pfxs[0]
	if !p.Addr().Is4() {
		return p.Addr().Next().String(), nil
	}
	cursor := m.poolCursors[poolName] + 10
	m.poolCursors[poolName]++
	a4 := p.Addr().As4()
	base := binary.BigEndian.Uint32(a4[:])
	ipNum := base + uint32(cursor)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ipNum)
	addr := netip.AddrFrom4(b)
	if !p.Contains(addr) {
		return "", fmt.Errorf("ip pool %q exhausted", poolName)
	}
	return addr.String(), nil
}
