// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package secplan defines the typed Phase 2 data model (Firewall, QoS, VPN, Hardening)
// and cross-field security/policy semantic validators.
package secplan

import (
	"encoding/json"

	"github.com/kangpcode/daijios/pkg/netplan"
)

// SecurityConfig encompasses Phase 2 configuration alongside Phase 1 interface references.
type SecurityConfig struct {
	SchemaVersion string                  `json:"schema_version"`
	System        netplan.SystemTimeRef   `json:"system"`
	Management    ManagementRef           `json:"management"`
	Interfaces    netplan.InterfacesBlock `json:"interfaces"`
	Firewall      FirewallBlock           `json:"firewall"`
	QoS           QoSBlock                `json:"qos"`
	VPN           VPNBlock                `json:"vpn"`
	Security      HardeningBlock          `json:"security"`
	Updates       UpdatesRef              `json:"updates"`
}

type ManagementRef struct {
	SSH struct {
		Enabled         bool     `json:"enabled"`
		Port            int      `json:"port"`
		PasswordAuth    bool     `json:"password_auth"`
		ListenAddresses []string `json:"listen_addresses"`
	} `json:"ssh"`
	API struct {
		Enabled       bool   `json:"enabled"`
		Port          int    `json:"port"`
		TLSEnabled    bool   `json:"tls_enabled"`
		SigningSecret string `json:"signing_secret"`
	} `json:"api"`
}

type UpdatesRef struct {
	RequireSignature bool `json:"require_signature"`
}

type FirewallBlock struct {
	DefaultPolicy DefaultPolicy        `json:"default_policy"`
	Conntrack     ConntrackConfig      `json:"conntrack"`
	AddressLists  []AddressList        `json:"address_lists"`
	L7DPI         L7DPIConfig          `json:"l7_dpi"`
	FilterRules   []FirewallFilterRule `json:"filter_rules"`
	NATRules      []FirewallNATRule    `json:"nat_rules"`
	MangleRules   []FirewallMangleRule `json:"mangle_rules"`
}

type DefaultPolicy struct {
	Input   string `json:"input"`
	Forward string `json:"forward"`
	Output  string `json:"output"`
}

type ConntrackConfig struct {
	MaxEntries               int  `json:"max_entries"`
	TCPEstablishedTimeoutSec int  `json:"tcp_established_timeout_sec"`
	UDPTimeoutSec            int  `json:"udp_timeout_sec"`
	SYNFloodProtect          bool `json:"syn_flood_protect"`
	SYNRatePerSec            int  `json:"syn_rate_per_sec"`
	LogInvalid               bool `json:"log_invalid"`
}

type AddressListEntry struct {
	CIDR       string `json:"cidr"`
	Comment    string `json:"comment"`
	TimeoutSec int    `json:"timeout_sec"`
}

type AddressList struct {
	Name    string             `json:"name"`
	Family  string             `json:"family"`
	Entries []AddressListEntry `json:"entries"`
}

type DPISignature struct {
	Name         string `json:"name"`
	Protocol     string `json:"protocol"`
	PortHints    []int  `json:"port_hints"`
	PayloadRegex string `json:"payload_regex"`
	Mark         uint32 `json:"mark"`
	Action       string `json:"action"`
}

type L7DPIConfig struct {
	Enabled           bool           `json:"enabled"`
	Engine            string         `json:"engine"`
	BlockedCategories []string       `json:"blocked_categories"`
	CustomSignatures  []DPISignature `json:"custom_signatures"`
}

type FirewallFilterRule struct {
	ID           string   `json:"id"`
	Chain        string   `json:"chain"`
	Order        int      `json:"order"`
	Protocol     string   `json:"protocol"`
	SrcIP        string   `json:"src_ip"`
	SrcList      string   `json:"src_list"`
	DstIP        string   `json:"dst_ip"`
	DstList      string   `json:"dst_list"`
	SrcPort      string   `json:"src_port"`
	DstPort      string   `json:"dst_port"`
	InInterface  string   `json:"in_interface"`
	OutInterface string   `json:"out_interface"`
	ConnState    []string `json:"conn_state"`
	L7App        string   `json:"l7_app"`
	MarkMatch    uint32   `json:"mark_match"`
	Action       string   `json:"action"`
	Log          bool     `json:"log"`
	LogPrefix    string   `json:"log_prefix"`
	Comment      string   `json:"comment"`
	Enabled      bool     `json:"enabled"`
}

type FirewallNATRule struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Order        int    `json:"order"`
	InInterface  string `json:"in_interface"`
	OutInterface string `json:"out_interface"`
	Protocol     string `json:"protocol"`
	SrcIP        string `json:"src_ip"`
	DstIP        string `json:"dst_ip"`
	DstPort      int    `json:"dst_port"`
	ToAddresses  string `json:"to_addresses"`
	ToPort       int    `json:"to_port"`
	Comment      string `json:"comment"`
	Enabled      bool   `json:"enabled"`
}

type FirewallMangleRule struct {
	ID           string `json:"id"`
	Chain        string `json:"chain"`
	Order        int    `json:"order"`
	Protocol     string `json:"protocol"`
	SrcIP        string `json:"src_ip"`
	DstIP        string `json:"dst_ip"`
	DstPort      string `json:"dst_port"`
	L7App        string `json:"l7_app"`
	SetMark      uint32 `json:"set_mark"`
	SetDSCP      *int   `json:"set_dscp"`
	MSSClampPMTU bool   `json:"mss_clamp_pmtu"`
	Enabled      bool   `json:"enabled"`
}

type QoSBlock struct {
	Interfaces   []QoSInterface   `json:"interfaces"`
	QueueTrees   []QoSQueueTree   `json:"queue_trees"`
	SimpleQueues []QoSSimpleQueue `json:"simple_queues"`
}

type QoSInterface struct {
	Interface     string `json:"interface"`
	Scheduler     string `json:"scheduler"`
	DownloadKbps  int    `json:"download_kbps"`
	UploadKbps    int    `json:"upload_kbps"`
	OverheadBytes int    `json:"overhead_bytes"`
	RTTMS         int    `json:"rtt_ms"`
	NATMode       bool   `json:"nat_mode"`
	Diffserv      string `json:"diffserv"`
}

type QoSQueueTree struct {
	Name            string `json:"name"`
	ParentInterface string `json:"parent_interface"`
	ClassID         int    `json:"class_id"`
	MarkMatch       uint32 `json:"mark_match"`
	RateKbps        int    `json:"rate_kbps"`
	CeilKbps        int    `json:"ceil_kbps"`
	BurstBytes      int    `json:"burst_bytes"`
	Priority        int    `json:"priority"`
	Qdisc           string `json:"qdisc"`
}

type QoSSimpleQueue struct {
	Name              string `json:"name"`
	TargetCIDR        string `json:"target_cidr"`
	Interface         string `json:"interface"`
	MaxUploadKbps     int    `json:"max_upload_kbps"`
	MaxDownloadKbps   int    `json:"max_download_kbps"`
	BurstUploadKbps   int    `json:"burst_upload_kbps"`
	BurstDownloadKbps int    `json:"burst_download_kbps"`
	BurstTimeSec      int    `json:"burst_time_sec"`
	PCQMode           bool   `json:"pcq_mode"`
	PCQRateKbps       int    `json:"pcq_rate_kbps"`
	Enabled           bool   `json:"enabled"`
}

type VPNBlock struct {
	WireGuard []WireGuardInterface `json:"wireguard"`
	IPsec     IPsecConfig          `json:"ipsec"`
	OpenVPN   []OpenVPNInstance    `json:"openvpn"`
	L2TP      L2TPConfig           `json:"l2tp"`
	PPTP      PPTPConfig           `json:"pptp"`
	SSTP      SSTPConfig           `json:"sstp"`
	EoIP      []EoIPTunnel         `json:"eoip"`
}

type WireGuardPeer struct {
	Name                string   `json:"name"`
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key"`
	AllowedIPs          []string `json:"allowed_ips"`
	Endpoint            string   `json:"endpoint"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
}

type WireGuardInterface struct {
	Interface  string          `json:"interface"`
	ListenPort int             `json:"listen_port"`
	PrivateKey string          `json:"private_key"`
	Addresses  []string        `json:"addresses"`
	MTU        int             `json:"mtu"`
	Peers      []WireGuardPeer `json:"peers"`
	Enabled    bool            `json:"enabled"`
}

type IPsecTunnel struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	LocalIP      string   `json:"local_ip"`
	RemoteIP     string   `json:"remote_ip"`
	LocalID      string   `json:"local_id"`
	RemoteID     string   `json:"remote_id"`
	AuthMethod   string   `json:"auth_method"`
	PSK          string   `json:"psk"`
	IKEProposals string   `json:"ike_proposals"`
	ESPProposals string   `json:"esp_proposals"`
	LocalTS      []string `json:"local_ts"`
	RemoteTS     []string `json:"remote_ts"`
	DPDDelaySec  int      `json:"dpd_delay_sec"`
	VTIInterface string   `json:"vti_interface"`
	VTIKey       uint32   `json:"vti_key"`
	Enabled      bool     `json:"enabled"`
}

type IPsecConfig struct {
	Enabled       bool          `json:"enabled"`
	CharonThreads int           `json:"charon_threads"`
	Tunnels       []IPsecTunnel `json:"tunnels"`
}

type OpenVPNInstance struct {
	Name           string `json:"name"`
	Role           string `json:"role"`
	Proto          string `json:"proto"`
	Port           int    `json:"port"`
	DevType        string `json:"dev_type"`
	Cipher         string `json:"cipher"`
	Subnet         string `json:"subnet"`
	RemoteHost     string `json:"remote_host"`
	TLSCryptKey    string `json:"tls_crypt_key"`
	CACert         string `json:"ca_cert"`
	Cert           string `json:"cert"`
	PrivateKeyPath string `json:"private_key_path"`
	Enabled        bool   `json:"enabled"`
}

type L2TPConfig struct {
	Enabled    bool   `json:"enabled"`
	ListenIP   string `json:"listen_ip"`
	IPsecPSK   string `json:"ipsec_psk"`
	LocalIP    string `json:"local_ip"`
	ClientPool string `json:"client_pool"`
}

type PPTPConfig struct {
	Enabled            bool   `json:"enabled"`
	LegacyAcknowledged bool   `json:"legacy_acknowledged"`
	LocalIP            string `json:"local_ip"`
	ClientPool         string `json:"client_pool"`
	RequireMPPE128     bool   `json:"require_mppe128"`
}

type SSTPConfig struct {
	Enabled        bool   `json:"enabled"`
	ListenPort     int    `json:"listen_port"`
	CertPath       string `json:"cert_path"`
	PrivateKeyPath string `json:"private_key_path"`
	ClientPool     string `json:"client_pool"`
}

type EoIPTunnel struct {
	Name     string `json:"name"`
	LocalIP  string `json:"local_ip"`
	RemoteIP string `json:"remote_ip"`
	TunnelID int    `json:"tunnel_id"`
	MTU      int    `json:"mtu"`
	Bridge   string `json:"bridge"`
	Enabled  bool   `json:"enabled"`
}

type HardeningBlock struct {
	RBAC struct {
		Enforce     bool   `json:"enforce"`
		DefaultRole string `json:"default_role"`
	} `json:"rbac"`
	TwoFactor struct {
		EnforceForAdmins bool   `json:"enforce_for_admins"`
		Issuer           string `json:"issuer"`
		WindowSkew       int    `json:"window_skew"`
	} `json:"two_factor"`
	SSHHardening struct {
		PermitRootLogin bool     `json:"permit_root_login"`
		MaxAuthTries    int      `json:"max_auth_tries"`
		IdleTimeoutSec  int      `json:"idle_timeout_sec"`
		AllowCiphers    []string `json:"allow_ciphers"`
		AllowKex        []string `json:"allow_kex"`
	} `json:"ssh_hardening"`
	APITokens struct {
		MaxTTLHours              int  `json:"max_ttl_hours"`
		RequireScopedPermissions bool `json:"require_scoped_permissions"`
	} `json:"api_tokens"`
	BruteForce struct {
		Enabled        bool     `json:"enabled"`
		SSHMaxAttempts int      `json:"ssh_max_attempts"`
		SSHWindowSec   int      `json:"ssh_window_sec"`
		APIMaxAttempts int      `json:"api_max_attempts"`
		APIWindowSec   int      `json:"api_window_sec"`
		BanDurationSec int      `json:"ban_duration_sec"`
		WhitelistCIDRs []string `json:"whitelist_cidrs"`
	} `json:"bruteforce"`
	FirmwareSecurity struct {
		SecureBootRequired bool `json:"secure_boot_required"`
		RequireSignedDPK   bool `json:"require_signed_dpk"`
		RequireSignedAB    bool `json:"require_signed_ab"`
		AuditLogImmutable  bool `json:"audit_log_immutable"`
	} `json:"firmware_security"`
}

// ParseConfig decodes a raw configuration map into SecurityConfig.
func ParseConfig(cfg map[string]any) (*SecurityConfig, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var out SecurityConfig
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
