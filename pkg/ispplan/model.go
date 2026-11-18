// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package ispplan defines the typed Phase 3 ISP Features model (PPPoE, IPoE,
// Hotspot, RADIUS, Multi-WAN, Telemetry, DaijiScript/Automation) and semantic checks.
package ispplan

import (
	"encoding/json"

	"github.com/kangpcode/daijios/pkg/netplan"
)

type FullISPConfig struct {
	SchemaVersion string                  `json:"schema_version"`
	System        netplan.SystemTimeRef   `json:"system"`
	Interfaces    netplan.InterfacesBlock `json:"interfaces"`
	ISP           ISPBlock                `json:"isp"`
	Telemetry     TelemetryBlock          `json:"telemetry"`
	Automation    AutomationBlock         `json:"automation"`
}

type ISPBlock struct {
	Profiles []ISPProfile  `json:"profiles"`
	IPPools  []ISPIPPool   `json:"ip_pools"`
	RADIUS   RADIUSBlock   `json:"radius"`
	PPPoE    PPPoEBlock    `json:"pppoe"`
	IPoE     IPoEBlock     `json:"ipoe"`
	Hotspot  HotspotBlock  `json:"hotspot"`
	MultiWAN MultiWANBlock `json:"multi_wan"`
}

type ISPProfile struct {
	Name               string   `json:"name"`
	DownloadKbps       int      `json:"download_kbps"`
	UploadKbps         int      `json:"upload_kbps"`
	BurstDownloadKbps  int      `json:"burst_download_kbps"`
	BurstUploadKbps    int      `json:"burst_upload_kbps"`
	BurstTimeSec       int      `json:"burst_time_sec"`
	AddressPool        string   `json:"address_pool"`
	IPv6Pool           string   `json:"ipv6_pool"`
	DNSServers         []string `json:"dns_servers"`
	SessionTimeoutSec  int      `json:"session_timeout_sec"`
	IdleTimeoutSec     int      `json:"idle_timeout_sec"`
	SharedUsers        int      `json:"shared_users"`
	ExpiredPool        string   `json:"expired_pool"`
	ExpiredRedirectURL string   `json:"expired_redirect_url"`
}

type ISPIPPool struct {
	Name     string   `json:"name"`
	Ranges   []string `json:"ranges"`
	NextPool string   `json:"next_pool"`
}

type RADIUSServerTarget struct {
	Name       string `json:"name"`
	Host       string `json:"host"`
	AuthPort   int    `json:"auth_port"`
	AcctPort   int    `json:"acct_port"`
	Secret     string `json:"secret"`
	Priority   int    `json:"priority"`
	TimeoutSec int    `json:"timeout_sec"`
}

type RADIUSClientACL struct {
	Name   string `json:"name"`
	CIDR   string `json:"cidr"`
	Secret string `json:"secret"`
}

type RADIUSClientConfig struct {
	Enabled       bool                 `json:"enabled"`
	NASIdentifier string               `json:"nas_identifier"`
	NASIP         string               `json:"nas_ip"`
	CoAEnabled    bool                 `json:"coa_enabled"`
	CoAPort       int                  `json:"coa_port"`
	CoASecret     string               `json:"coa_secret"`
	Servers       []RADIUSServerTarget `json:"servers"`
}

type RADIUSServerConfig struct {
	Enabled  bool              `json:"enabled"`
	AuthPort int               `json:"auth_port"`
	AcctPort int               `json:"acct_port"`
	Clients  []RADIUSClientACL `json:"clients"`
}

type RADIUSBlock struct {
	Client RADIUSClientConfig `json:"client"`
	Server RADIUSServerConfig `json:"server"`
}

type PPPoEServer struct {
	Name             string   `json:"name"`
	ServiceName      string   `json:"service_name"`
	ACName           string   `json:"ac_name"`
	Interface        string   `json:"interface"`
	VLANID           int      `json:"vlan_id"`
	LocalIP          string   `json:"local_ip"`
	IPPool           string   `json:"ip_pool"`
	MTU              int      `json:"mtu"`
	MRU              int      `json:"mru"`
	AuthMethods      []string `json:"auth_methods"`
	UseRADIUS        bool     `json:"use_radius"`
	DefaultProfile   string   `json:"default_profile"`
	SessionLimit     int      `json:"session_limit"`
	OneSessionPerMAC bool     `json:"one_session_per_mac"`
	Enabled          bool     `json:"enabled"`
}

type PPPoEClient struct {
	Name         string `json:"name"`
	Interface    string `json:"interface"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	ServiceName  string `json:"service_name"`
	MTU          int    `json:"mtu"`
	DefaultRoute bool   `json:"default_route"`
	Distance     int    `json:"distance"`
	UsePeerDNS   bool   `json:"use_peer_dns"`
	Enabled      bool   `json:"enabled"`
}

type PPPoESecret struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Service   string `json:"service"`
	Profile   string `json:"profile"`
	StaticIP  string `json:"static_ip"`
	CallerMAC string `json:"caller_mac"`
	ExpiresAt string `json:"expires_at"`
	Disabled  bool   `json:"disabled"`
	Comment   string `json:"comment"`
}

type PPPoEBlock struct {
	Servers []PPPoEServer `json:"servers"`
	Clients []PPPoEClient `json:"clients"`
	Secrets []PPPoESecret `json:"secrets"`
}

type IPoEServer struct {
	Name           string `json:"name"`
	Interface      string `json:"interface"`
	AuthMode       string `json:"auth_mode"`
	IPPool         string `json:"ip_pool"`
	DefaultProfile string `json:"default_profile"`
	UseRADIUS      bool   `json:"use_radius"`
	Enabled        bool   `json:"enabled"`
}

type IPoEBlock struct {
	Servers []IPoEServer `json:"servers"`
}

type HotspotServer struct {
	Name               string   `json:"name"`
	Interface          string   `json:"interface"`
	AddressPool        string   `json:"address_pool"`
	DNSName            string   `json:"dns_name"`
	LoginPageURL       string   `json:"login_page_url"`
	TrialEnabled       bool     `json:"trial_enabled"`
	TrialUptimeSec     int      `json:"trial_uptime_sec"`
	WalledGardenHosts  []string `json:"walled_garden_hosts"`
	WalledGardenCIDRs  []string `json:"walled_garden_cidrs"`
	UseRADIUS          bool     `json:"use_radius"`
	MACCookie          bool     `json:"mac_cookie"`
	DefaultProfile     string   `json:"default_profile"`
	Enabled            bool     `json:"enabled"`
}

type HotspotVoucher struct {
	Code        string `json:"code"`
	Profile     string `json:"profile"`
	ValiditySec int    `json:"validity_sec"`
	DataLimitMB int    `json:"data_limit_mb"`
	MaxDevices  int    `json:"max_devices"`
	ExpiresAt   string `json:"expires_at"`
	Disabled    bool   `json:"disabled"`
}

type HotspotBlock struct {
	Servers  []HotspotServer  `json:"servers"`
	Vouchers []HotspotVoucher `json:"vouchers"`
}

type MultiWANLink struct {
	Name              string   `json:"name"`
	Interface         string   `json:"interface"`
	Gateway           string   `json:"gateway"`
	Weight            int      `json:"weight"`
	Distance          int      `json:"distance"`
	CheckMethod       string   `json:"check_method"`
	CheckTargets      []string `json:"check_targets"`
	CheckIntervalSec  int      `json:"check_interval_sec"`
	CheckTimeoutMS    int      `json:"check_timeout_ms"`
	FailThreshold     int      `json:"fail_threshold"`
	RecoverThreshold  int      `json:"recover_threshold"`
	RoutingTable      uint32   `json:"routing_table"`
	Enabled           bool     `json:"enabled"`
}

type MultiWANBlock struct {
	Enabled        bool           `json:"enabled"`
	Mode           string         `json:"mode"`
	StickySessions bool           `json:"sticky_sessions"`
	WANs           []MultiWANLink `json:"wans"`
}

type NetFlowCollector struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type NetFlowConfig struct {
	Enabled          bool               `json:"enabled"`
	Version          string             `json:"version"`
	ActiveTimeoutSec int                `json:"active_timeout_sec"`
	SamplingRate     int                `json:"sampling_rate"`
	Collectors       []NetFlowCollector `json:"collectors"`
}

type SNMPv3User struct {
	Username  string `json:"username"`
	AuthProto string `json:"auth_proto"`
	AuthPass  string `json:"auth_pass"`
	PrivProto string `json:"priv_proto"`
	PrivPass  string `json:"priv_pass"`
}

type SNMPConfig struct {
	Enabled       bool         `json:"enabled"`
	Version       string       `json:"version"`
	ListenAddress string       `json:"listen_address"`
	Port          int          `json:"port"`
	SysLocation   string       `json:"sys_location"`
	SysContact    string       `json:"sys_contact"`
	CommunityRO   string       `json:"community_ro"`
	CommunityRW   string       `json:"community_rw"`
	V3Users       []SNMPv3User `json:"v3_users"`
}

type SyslogTarget struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Proto       string `json:"proto"`
	MinSeverity string `json:"min_severity"`
}

type SyslogConfig struct {
	Enabled          bool           `json:"enabled"`
	LocalBufferLines int            `json:"local_buffer_lines"`
	RemoteTargets    []SyslogTarget `json:"remote_targets"`
}

type BandwidthTestConfig struct {
	ServerEnabled bool `json:"server_enabled"`
	Port          int  `json:"port"`
	MaxConcurrent int  `json:"max_concurrent"`
	RequireAuth   bool `json:"require_auth"`
}

type TelemetryBlock struct {
	NetFlow       NetFlowConfig       `json:"netflow"`
	SNMP          SNMPConfig          `json:"snmp"`
	Syslog        SyslogConfig        `json:"syslog"`
	BandwidthTest BandwidthTestConfig `json:"bandwidth_test"`
}

type DaijiScriptDef struct {
	Name        string   `json:"name"`
	Source      string   `json:"source"`
	Permissions []string `json:"permissions"`
	TimeoutMS   int      `json:"timeout_ms"`
	Enabled     bool     `json:"enabled"`
}

type ScriptSchedule struct {
	Name        string `json:"name"`
	ScriptName  string `json:"script_name"`
	IntervalSec int    `json:"interval_sec"`
	StartOnBoot bool   `json:"start_on_boot"`
	Enabled     bool   `json:"enabled"`
}

type EventHook struct {
	Name        string `json:"name"`
	Event       string `json:"event"`
	ScriptName  string `json:"script_name"`
	WebhookName string `json:"webhook_name"`
	Enabled     bool   `json:"enabled"`
}

type WebhookTarget struct {
	Name       string   `json:"name"`
	URL        string   `json:"url"`
	Secret     string   `json:"secret"`
	Events     []string `json:"events"`
	TimeoutMS  int      `json:"timeout_ms"`
	RetryCount int      `json:"retry_count"`
	Enabled    bool     `json:"enabled"`
}

type AutomationBlock struct {
	Scripts    []DaijiScriptDef `json:"scripts"`
	Schedules  []ScriptSchedule `json:"schedules"`
	EventHooks []EventHook      `json:"event_hooks"`
	Webhooks   []WebhookTarget  `json:"webhooks"`
}

// ParseConfig decodes a raw configuration map into FullISPConfig.
func ParseConfig(cfg map[string]any) (*FullISPConfig, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var out FullISPConfig
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
