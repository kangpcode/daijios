// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package daijicloud implements DaijiCloud: the multi-tenant Fleet Control Plane
// (Org -> Site -> Device), tenant-isolated RBAC, Zero-Touch Provisioning (ZTP),
// telemetry monitoring & alert rules, config backup/versioning, Disaster Recovery
// snapshots, secure NAT-traversal tunnels, staged Canary firmware rollouts,
// Public API + Go SDK, and built-in metrics/logs/tracing observability.
package daijicloud

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kangpcode/daijios/pkg/secauth"
	"github.com/kangpcode/daijios/pkg/sysinfo"
)

var (
	ErrTenantForbidden = errors.New("cross-tenant or site access denied by DaijiCloud RBAC")
	ErrNotFound        = errors.New("cloud resource not found")
	ErrDuplicate       = errors.New("duplicate cloud resource")
	ErrInvalidZTP      = errors.New("invalid, expired, or already-claimed ZTP token")
	ErrDRTampered      = errors.New("disaster recovery snapshot HMAC verification failed")
)

// Organization represents a top-level customer/ISP tenant in DaijiCloud.
type Organization struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PlanTier  string `json:"plan_tier"` // free | pro | enterprise
	CreatedAt string `json:"created_at"`
}

// Site represents a physical POP, branch, or campus belonging to an Organization.
type Site struct {
	ID       string `json:"id"`
	OrgID    string `json:"org_id"`
	Name     string `json:"name"`
	Region   string `json:"region"`
	Timezone string `json:"timezone"`
}

// TenantBinding maps an operator identity to an Org (and optional specific Site) + RBAC role.
type TenantBinding struct {
	Actor  string `json:"actor"`
	OrgID  string `json:"org_id"`
	SiteID string `json:"site_id,omitempty"` // empty = org-wide
	Role   string `json:"role"`              // superadmin | netadmin | operator | readonly
}

// DeviceTelemetry holds live health & traffic stats reported by a managed device.
type DeviceTelemetry struct {
	CPUPercent     float64 `json:"cpu_percent"`
	MemPercent     float64 `json:"mem_percent"`
	TemperatureC   float64 `json:"temperature_c"`
	RxMbps         float64 `json:"rx_mbps"`
	TxMbps         float64 `json:"tx_mbps"`
	ActiveSessions int     `json:"active_sessions"`
	UptimeSec      int64   `json:"uptime_sec"`
}

// ConfigBackupVersion stores one immutable versioned cloud config snapshot for a device.
type ConfigBackupVersion struct {
	Version   int            `json:"version"`
	SHA256    string         `json:"sha256"`
	CreatedBy string         `json:"created_by"`
	CreatedAt string         `json:"created_at"`
	Note      string         `json:"note,omitempty"`
	Config    map[string]any `json:"config"`
}

// CloudDevice models an adopted DaijiOS router/switch/AC managed inside a Site.
type CloudDevice struct {
	ID            string                `json:"id"`
	OrgID         string                `json:"org_id"`
	SiteID        string                `json:"site_id"`
	Serial        string                `json:"serial"`
	MAC           string                `json:"mac"`
	Hostname      string                `json:"hostname"`
	Platform      string                `json:"platform"`
	FirmwareVer   string                `json:"firmware_ver"`
	Online        bool                  `json:"online"`
	AdoptedAt     string                `json:"adopted_at"`
	LastSeenAt    time.Time             `json:"last_seen_at"`
	Telemetry     DeviceTelemetry       `json:"telemetry"`
	Backups       []ConfigBackupVersion `json:"backups,omitempty"`
	Labels        map[string]string     `json:"labels,omitempty"`
}

// ZTPClaim stores a one-time Zero-Touch Provisioning enrollment token.
type ZTPClaim struct {
	Token     string `json:"token"`
	OrgID     string `json:"org_id"`
	SiteID    string `json:"site_id"`
	Serial    string `json:"serial"`
	Profile   string `json:"profile"`
	ExpiresAt int64  `json:"expires_at"`
	Claimed   bool   `json:"claimed"`
}

// AlertRule defines a threshold condition evaluated against incoming fleet telemetry.
type AlertRule struct {
	ID        string  `json:"id"`
	OrgID     string  `json:"org_id"`
	Name      string  `json:"name"`
	Metric    string  `json:"metric"` // cpu_percent | mem_percent | temperature_c
	Threshold float64 `json:"threshold"`
	Severity  string  `json:"severity"` // critical | warning
}

// CloudAlert represents a triggered or resolved alert for a device.
type CloudAlert struct {
	ID          string  `json:"id"`
	OrgID       string  `json:"org_id"`
	SiteID      string  `json:"site_id"`
	DeviceID    string  `json:"device_id"`
	RuleID      string  `json:"rule_id"`
	Severity    string  `json:"severity"`
	Message     string  `json:"message"`
	Value       float64 `json:"value"`
	Status      string  `json:"status"` // open | resolved
	TriggeredAt string  `json:"triggered_at"`
	ResolvedAt  string  `json:"resolved_at,omitempty"`
}

// RemoteTunnel represents a secure Cloud-relayed management tunnel to a NAT-behind device.
type RemoteTunnel struct {
	TunnelID   string   `json:"tunnel_id"`
	OrgID      string   `json:"org_id"`
	DeviceID   string   `json:"device_id"`
	Operator   string   `json:"operator"`
	Token      string   `json:"token"`
	Commands   []string `json:"commands,omitempty"`
	CreatedAt  string   `json:"created_at"`
	Active     bool     `json:"active"`
}

// RolloutJob orchestrates staged Canary fleet firmware upgrades with automatic halt-on-failure.
type RolloutJob struct {
	ID            string            `json:"id"`
	OrgID         string            `json:"org_id"`
	SiteID        string            `json:"site_id,omitempty"`
	TargetVersion string            `json:"target_version"`
	ImageSHA256   string            `json:"image_sha256"`
	CanaryPercent int               `json:"canary_percent"`
	MaxFailurePct int               `json:"max_failure_pct"`
	Stage         string            `json:"stage"` // canary | fleet | completed | halted_rollback
	CanaryIDs     []string          `json:"canary_device_ids"`
	RestIDs       []string          `json:"rest_device_ids"`
	Results       map[string]string `json:"results"` // deviceID -> pending | upgrading | ok | failed
	CreatedAt     string            `json:"created_at"`
}

// DisasterRecoverySnapshot captures the full signed ControlPlane state for DR backup/restore.
type DisasterRecoverySnapshot struct {
	Brand       string                  `json:"brand"`
	CreatedAt   string                  `json:"created_at"`
	HMAC        string                  `json:"hmac"`
	Orgs        map[string]*Organization `json:"orgs"`
	Sites       map[string]*Site        `json:"sites"`
	Bindings    []TenantBinding         `json:"bindings"`
	Devices     map[string]*CloudDevice `json:"devices"`
	AlertRules  map[string]*AlertRule   `json:"alert_rules"`
	Alerts      map[string]*CloudAlert  `json:"alerts"`
	Rollouts    map[string]*RolloutJob  `json:"rollouts"`
}

// ControlPlane manages multi-tenant fleets, ZTP, alerts, backups, tunnels, canary rollouts, & DR.
type ControlPlane struct {
	mu           sync.RWMutex
	orgs         map[string]*Organization
	sites        map[string]*Site
	bindings     map[string][]TenantBinding // actor -> bindings
	devices      map[string]*CloudDevice
	ztpClaims    map[string]*ZTPClaim
	alertRules   map[string]*AlertRule
	alerts       map[string]*CloudAlert
	tunnels      map[string]*RemoteTunnel
	rollouts     map[string]*RolloutJob
	rbac         *secauth.RBACPolicy
	ztpSecret    []byte
	drSecret     []byte
	obs          *Observability
	nowFn        func() time.Time
}

// NewControlPlane constructs a DaijiCloud multi-tenant fleet orchestrator.
func NewControlPlane(ztpSecret, drSecret []byte, nowFn func() time.Time) *ControlPlane {
	if len(ztpSecret) < 16 {
		ztpSecret = []byte("daijicloud-ztp-hmac-key-phase10")
	}
	if len(drSecret) < 16 {
		drSecret = []byte("daijicloud-dr-snapshot-key-p10")
	}
	if nowFn == nil {
		nowFn = time.Now
	}
	return &ControlPlane{
		orgs:       make(map[string]*Organization),
		sites:      make(map[string]*Site),
		bindings:   make(map[string][]TenantBinding),
		devices:    make(map[string]*CloudDevice),
		ztpClaims:  make(map[string]*ZTPClaim),
		alertRules: make(map[string]*AlertRule),
		alerts:     make(map[string]*CloudAlert),
		tunnels:    make(map[string]*RemoteTunnel),
		rollouts:   make(map[string]*RolloutJob),
		rbac:       secauth.NewDefaultRBACPolicy(true),
		ztpSecret:  append([]byte(nil), ztpSecret...),
		drSecret:   append([]byte(nil), drSecret...),
		obs:        NewObservability(),
		nowFn:      nowFn,
	}
}

func (cp *ControlPlane) CreateOrganization(o Organization) error {
	if o.ID == "" || o.Name == "" {
		return errors.New("org id and name required")
	}
	if o.PlanTier == "" {
		o.PlanTier = "pro"
	}
	o.CreatedAt = cp.nowFn().UTC().Format(time.RFC3339)

	cp.mu.Lock()
	defer cp.mu.Unlock()
	if _, exists := cp.orgs[o.ID]; exists {
		return ErrDuplicate
	}
	cpCopy := o
	cp.orgs[o.ID] = &cpCopy
	return nil
}

func (cp *ControlPlane) CreateSite(s Site) error {
	if s.ID == "" || s.OrgID == "" || s.Name == "" {
		return errors.New("site id, org_id, and name required")
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if _, ok := cp.orgs[s.OrgID]; !ok {
		return fmt.Errorf("%w: org %q", ErrNotFound, s.OrgID)
	}
	if _, exists := cp.sites[s.ID]; exists {
		return ErrDuplicate
	}
	cpCopy := s
	cp.sites[s.ID] = &cpCopy
	return nil
}

func (cp *ControlPlane) BindOperator(b TenantBinding) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.bindings[b.Actor] = append(cp.bindings[b.Actor], b)
}

// AuthorizeTenant enforces Org/Site scoping + RBAC role permission.
func (cp *ControlPlane) AuthorizeTenant(actor, orgID, siteID string, perm secauth.Permission) error {
	cp.mu.RLock()
	list := cp.bindings[actor]
	cp.mu.RUnlock()
	for _, b := range list {
		if b.OrgID == "*" || b.OrgID == orgID {
			if b.SiteID == "" || siteID == "" || b.SiteID == siteID {
				if err := cp.rbac.Authorize(b.Role, perm); err == nil {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("%w: actor=%q org=%q site=%q perm=%s", ErrTenantForbidden, actor, orgID, siteID, perm)
}

// CreateZTPClaimToken mints a time-limited, HMAC-signed Zero-Touch Provisioning enrollment token.
func (cp *ControlPlane) CreateZTPClaimToken(orgID, siteID, serial, profile string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	site, ok := cp.sites[siteID]
	if !ok || site.OrgID != orgID {
		return "", fmt.Errorf("%w: site %q in org %q", ErrNotFound, siteID, orgID)
	}
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	nonce := hex.EncodeToString(rnd[:])
	exp := cp.nowFn().UTC().Add(ttl).Unix()
	payload := fmt.Sprintf("ztp1.%s.%s.%s.%s.%d", orgID, siteID, serial, nonce, exp)
	sig := hmacHex(cp.ztpSecret, payload)
	tok := payload + "." + sig

	cp.ztpClaims[tok] = &ZTPClaim{
		Token:     tok,
		OrgID:     orgID,
		SiteID:    siteID,
		Serial:    serial,
		Profile:   profile,
		ExpiresAt: exp,
	}
	return tok, nil
}

// AdoptViaZTP validates a ZTP token once and enrolls the device under Org -> Site.
func (cp *ControlPlane) AdoptViaZTP(token, serial, mac, hostname, platform, fwVer string) (CloudDevice, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 7 || parts[0] != "ztp1" {
		return CloudDevice{}, ErrInvalidZTP
	}
	payload := strings.Join(parts[:6], ".")
	expSig, _ := hex.DecodeString(hmacHex(cp.ztpSecret, payload))
	gotSig, err := hex.DecodeString(parts[6])
	if err != nil || !hmac.Equal(gotSig, expSig) {
		return CloudDevice{}, ErrInvalidZTP
	}

	now := cp.nowFn().UTC()
	cp.mu.Lock()
	defer cp.mu.Unlock()
	claim, ok := cp.ztpClaims[token]
	if !ok || claim.Claimed || now.Unix() > claim.ExpiresAt {
		return CloudDevice{}, ErrInvalidZTP
	}
	if claim.Serial != "" && claim.Serial != serial {
		return CloudDevice{}, ErrInvalidZTP
	}
	claim.Claimed = true

	devID := "dev-" + serial
	dev := &CloudDevice{
		ID:          devID,
		OrgID:       claim.OrgID,
		SiteID:      claim.SiteID,
		Serial:      serial,
		MAC:         mac,
		Hostname:    hostname,
		Platform:    platform,
		FirmwareVer: fwVer,
		Online:      true,
		AdoptedAt:   now.Format(time.RFC3339),
		LastSeenAt:  now,
		Labels:      map[string]string{"profile": claim.Profile},
	}
	cp.devices[devID] = dev
	cp.obs.IncZTP()
	cp.obs.AddLog("INFO", claim.OrgID, "ztp", fmt.Sprintf("Adopted device %s into site %s", devID, claim.SiteID), "")
	return *dev, nil
}

// AddAlertRule registers an automated threshold rule for an organization.
func (cp *ControlPlane) AddAlertRule(r AlertRule) error {
	if r.ID == "" || r.OrgID == "" || r.Metric == "" {
		return errors.New("rule id, org_id, and metric required")
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cpCopy := r
	cp.alertRules[r.ID] = &cpCopy
	return nil
}

// IngestTelemetry records device metrics and evaluates matching Org alert rules.
func (cp *ControlPlane) IngestTelemetry(deviceID string, tel DeviceTelemetry) ([]CloudAlert, error) {
	now := cp.nowFn().UTC()
	cp.mu.Lock()
	defer cp.mu.Unlock()
	dev, ok := cp.devices[deviceID]
	if !ok {
		return nil, fmt.Errorf("%w: device %q", ErrNotFound, deviceID)
	}
	dev.Online = true
	dev.LastSeenAt = now
	dev.Telemetry = tel

	var fired []CloudAlert
	for _, rule := range cp.alertRules {
		if rule.OrgID != dev.OrgID {
			continue
		}
		var val float64
		switch rule.Metric {
		case "cpu_percent":
			val = tel.CPUPercent
		case "mem_percent":
			val = tel.MemPercent
		case "temperature_c":
			val = tel.TemperatureC
		default:
			continue
		}
		alKey := rule.ID + "|" + dev.ID
		if val > rule.Threshold {
			al := &CloudAlert{
				ID:          alKey,
				OrgID:       dev.OrgID,
				SiteID:      dev.SiteID,
				DeviceID:    dev.ID,
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				Message:     fmt.Sprintf("%s=%.1f > %.1f on %s", rule.Metric, val, rule.Threshold, dev.Hostname),
				Value:       val,
				Status:      "open",
				TriggeredAt: now.Format(time.RFC3339),
			}
			cp.alerts[alKey] = al
			fired = append(fired, *al)
		} else if prev, exists := cp.alerts[alKey]; exists && prev.Status == "open" {
			prev.Status = "resolved"
			prev.ResolvedAt = now.Format(time.RFC3339)
		}
	}
	return fired, nil
}

// UploadConfigBackup appends a SHA-256 verified config version to a device's cloud backup history.
func (cp *ControlPlane) UploadConfigBackup(deviceID, actor, note string, cfg map[string]any) (ConfigBackupVersion, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return ConfigBackupVersion{}, err
	}
	sum := sha256.Sum256(raw)

	cp.mu.Lock()
	defer cp.mu.Unlock()
	dev, ok := cp.devices[deviceID]
	if !ok {
		return ConfigBackupVersion{}, fmt.Errorf("%w: device %q", ErrNotFound, deviceID)
	}
	ver := ConfigBackupVersion{
		Version:   len(dev.Backups) + 1,
		SHA256:    hex.EncodeToString(sum[:]),
		CreatedBy: actor,
		CreatedAt: cp.nowFn().UTC().Format(time.RFC3339),
		Note:      note,
		Config:    deepCopyAnyMap(cfg),
	}
	dev.Backups = append(dev.Backups, ver)
	return ver, nil
}

// RestoreConfigVersion retrieves and verifies integrity of a specific device config backup version.
func (cp *ControlPlane) RestoreConfigVersion(deviceID string, version int) (ConfigBackupVersion, error) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	dev, ok := cp.devices[deviceID]
	if !ok {
		return ConfigBackupVersion{}, fmt.Errorf("%w: device %q", ErrNotFound, deviceID)
	}
	for _, b := range dev.Backups {
		if b.Version == version {
			raw, _ := json.Marshal(b.Config)
			sum := sha256.Sum256(raw)
			if hex.EncodeToString(sum[:]) != b.SHA256 {
				return ConfigBackupVersion{}, ErrDRTampered
			}
			return b, nil
		}
	}
	return ConfigBackupVersion{}, fmt.Errorf("%w: backup v%d for %s", ErrNotFound, version, deviceID)
}

// OpenRemoteTunnel creates an audited secure remote tunnel session for a NAT-behind device.
func (cp *ControlPlane) OpenRemoteTunnel(deviceID, operator string) (RemoteTunnel, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	dev, ok := cp.devices[deviceID]
	if !ok {
		return RemoteTunnel{}, fmt.Errorf("%w: device %q", ErrNotFound, deviceID)
	}
	var rnd [12]byte
	_, _ = rand.Read(rnd[:])
	tid := "tun-" + hex.EncodeToString(rnd[:4])
	tok := hmacHex(cp.ztpSecret, tid+"|"+dev.ID+"|"+operator)
	tun := &RemoteTunnel{
		TunnelID:  tid,
		OrgID:     dev.OrgID,
		DeviceID:  dev.ID,
		Operator:  operator,
		Token:     tok,
		CreatedAt: cp.nowFn().UTC().Format(time.RFC3339),
		Active:    true,
	}
	cp.tunnels[tid] = tun
	return *tun, nil
}

// StartCanaryRollout initiates Stage 1 Canary firmware upgrade across a scoped org/site cohort.
func (cp *ControlPlane) StartCanaryRollout(orgID, siteID, targetVer, imgSHA256 string, canaryPct, maxFailPct int) (*RolloutJob, error) {
	if canaryPct <= 0 || canaryPct > 100 {
		canaryPct = 20
	}
	if maxFailPct <= 0 {
		maxFailPct = 10
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()
	var targets []string
	for _, d := range cp.devices {
		if d.OrgID == orgID && (siteID == "" || d.SiteID == siteID) {
			targets = append(targets, d.ID)
		}
	}
	sort.Strings(targets)
	if len(targets) == 0 {
		return nil, fmt.Errorf("%w: no target devices for rollout", ErrNotFound)
	}

	canaryCount := (len(targets) * canaryPct) / 100
	if canaryCount < 1 {
		canaryCount = 1
	}
	if canaryCount > len(targets) {
		canaryCount = len(targets)
	}
	canaries := targets[:canaryCount]
	rest := targets[canaryCount:]

	results := make(map[string]string, len(targets))
	for _, id := range canaries {
		results[id] = "upgrading"
	}
	for _, id := range rest {
		results[id] = "pending"
	}

	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	job := &RolloutJob{
		ID:            "rol-" + hex.EncodeToString(rnd[:]),
		OrgID:         orgID,
		SiteID:        siteID,
		TargetVersion: targetVer,
		ImageSHA256:   imgSHA256,
		CanaryPercent: canaryPct,
		MaxFailurePct: maxFailPct,
		Stage:         "canary",
		CanaryIDs:     canaries,
		RestIDs:       rest,
		Results:       results,
		CreatedAt:     cp.nowFn().UTC().Format(time.RFC3339),
	}
	cp.rollouts[job.ID] = job
	cp.obs.IncRollout()
	cpCopy := *job
	return &cpCopy, nil
}

// ReportRolloutResult records device upgrade success/failure and auto-halts+rolls back if failure threshold breached.
func (cp *ControlPlane) ReportRolloutResult(rolloutID, deviceID string, success bool) (*RolloutJob, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	job, ok := cp.rollouts[rolloutID]
	if !ok {
		return nil, fmt.Errorf("%w: rollout %q", ErrNotFound, rolloutID)
	}
	if success {
		job.Results[deviceID] = "ok"
		if dev, exists := cp.devices[deviceID]; exists {
			dev.FirmwareVer = job.TargetVersion
		}
	} else {
		job.Results[deviceID] = "failed"
	}

	// Evaluate Canary failure rate.
	if job.Stage == "canary" && len(job.CanaryIDs) > 0 {
		fails := 0
		done := 0
		for _, id := range job.CanaryIDs {
			st := job.Results[id]
			if st == "failed" {
				fails++
				done++
			} else if st == "ok" {
				done++
			}
		}
		failPct := (fails * 100) / len(job.CanaryIDs)
		if failPct > job.MaxFailurePct {
			job.Stage = "halted_rollback"
			for _, id := range job.RestIDs {
				job.Results[id] = "skipped_rollback"
			}
			cpCopy := *job
			return &cpCopy, nil
		}
		if done == len(job.CanaryIDs) {
			if len(job.RestIDs) == 0 {
				job.Stage = "completed"
			} else {
				job.Stage = "fleet"
				for _, id := range job.RestIDs {
					job.Results[id] = "upgrading"
				}
			}
		}
	} else if job.Stage == "fleet" {
		allDone := true
		for _, st := range job.Results {
			if st == "pending" || st == "upgrading" {
				allDone = false
				break
			}
		}
		if allDone {
			job.Stage = "completed"
		}
	}

	cpCopy := *job
	return &cpCopy, nil
}

// ExportDisasterRecoverySnapshot exports an HMAC-signed full-cluster DR backup.
func (cp *ControlPlane) ExportDisasterRecoverySnapshot() (*DisasterRecoverySnapshot, error) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	var flatBindings []TenantBinding
	for _, list := range cp.bindings {
		flatBindings = append(flatBindings, list...)
	}
	sort.Slice(flatBindings, func(i, j int) bool {
		return flatBindings[i].Actor+flatBindings[i].OrgID < flatBindings[j].Actor+flatBindings[j].OrgID
	})

	snap := &DisasterRecoverySnapshot{
		Brand:      sysinfo.BrandBanner,
		CreatedAt:  cp.nowFn().UTC().Format(time.RFC3339),
		Orgs:       cp.orgs,
		Sites:      cp.sites,
		Bindings:   flatBindings,
		Devices:    cp.devices,
		AlertRules: cp.alertRules,
		Alerts:     cp.alerts,
		Rollouts:   cp.rollouts,
	}
	// Round-trip through JSON to detach internal pointers completely.
	raw, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	var detached DisasterRecoverySnapshot
	if err := json.Unmarshal(raw, &detached); err != nil {
		return nil, err
	}
	detached.HMAC = cp.signDRSnapshot(&detached)
	return &detached, nil
}

// RestoreDisasterRecoverySnapshot validates HMAC integrity and restores full multi-tenant cluster state.
func (cp *ControlPlane) RestoreDisasterRecoverySnapshot(snap *DisasterRecoverySnapshot) error {
	if snap == nil {
		return ErrDRTampered
	}
	expected := cp.signDRSnapshot(snap)
	gotB, err := hex.DecodeString(snap.HMAC)
	expB, _ := hex.DecodeString(expected)
	if err != nil || !hmac.Equal(gotB, expB) {
		return ErrDRTampered
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.orgs = make(map[string]*Organization, len(snap.Orgs))
	for k, v := range snap.Orgs {
		vCopy := *v
		cp.orgs[k] = &vCopy
	}
	cp.sites = make(map[string]*Site, len(snap.Sites))
	for k, v := range snap.Sites {
		vCopy := *v
		cp.sites[k] = &vCopy
	}
	cp.bindings = make(map[string][]TenantBinding)
	for _, b := range snap.Bindings {
		cp.bindings[b.Actor] = append(cp.bindings[b.Actor], b)
	}
	cp.devices = make(map[string]*CloudDevice, len(snap.Devices))
	for k, v := range snap.Devices {
		vCopy := *v
		cp.devices[k] = &vCopy
	}
	cp.alertRules = make(map[string]*AlertRule, len(snap.AlertRules))
	for k, v := range snap.AlertRules {
		vCopy := *v
		cp.alertRules[k] = &vCopy
	}
	cp.alerts = make(map[string]*CloudAlert, len(snap.Alerts))
	for k, v := range snap.Alerts {
		vCopy := *v
		cp.alerts[k] = &vCopy
	}
	cp.rollouts = make(map[string]*RolloutJob, len(snap.Rollouts))
	for k, v := range snap.Rollouts {
		vCopy := *v
		cp.rollouts[k] = &vCopy
	}
	return nil
}

func (cp *ControlPlane) signDRSnapshot(s *DisasterRecoverySnapshot) string {
	cpNoSig := *s
	cpNoSig.HMAC = ""
	raw, _ := json.Marshal(cpNoSig)
	h := hmac.New(sha256.New, cp.drSecret)
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

func hmacHex(secret []byte, msg string) string {
	h := hmac.New(sha256.New, secret)
	_, _ = h.Write([]byte(msg))
	return hex.EncodeToString(h.Sum(nil))
}

func deepCopyAnyMap(m map[string]any) map[string]any {
	raw, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}
