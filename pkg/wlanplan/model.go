// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package wlanplan defines the typed Phase 4 Wireless & Campus AC model and
// cross-field semantic invariants (SSID security, 802.11r/k/v, RF profiles, AP groups, Mesh).
package wlanplan

import "encoding/json"

type FullWirelessConfig struct {
	SchemaVersion string        `json:"schema_version"`
	Wireless      WirelessBlock `json:"wireless"`
}

type WirelessBlock struct {
	Controller ACControllerConfig `json:"controller"`
	SSIDs      []WLANSSID         `json:"ssids"`
	RFProfiles []WLANRFProfile    `json:"rf_profiles"`
	APGroups   []WLANAPGroup      `json:"ap_groups"`
	APs        []ManagedAP        `json:"aps"`
	Mesh       MeshConfig         `json:"mesh"`
}

type ACControllerConfig struct {
	Enabled         bool   `json:"enabled"`
	ACName          string `json:"ac_name"`
	Mode            string `json:"mode"`
	CountryCode     string `json:"country_code"`
	ListenIP        string `json:"listen_ip"`
	ControlPort     int    `json:"control_port"`
	DTLSEnabled     bool   `json:"dtls_enabled"`
	AutoAdoptPolicy string `json:"auto_adopt_policy"`
	OnboardingToken string `json:"onboarding_token"`
	DefaultAPGroup  string `json:"default_ap_group"`
}

type RoamingConfig struct {
	Dot11k         bool   `json:"dot11k"`
	Dot11v         bool   `json:"dot11v"`
	Dot11r         bool   `json:"dot11r"`
	MobilityDomain string `json:"mobility_domain"`
	R0KHKey        string `json:"r0kh_key"`
}

type BandSteeringConfig struct {
	Enabled          bool `json:"enabled"`
	Prefer5GHzRSSI   int  `json:"prefer_5ghz_rssi_dbm"`
	Max2GRejects     int  `json:"max_2g_rejects"`
}

type GuestIsolationConfig struct {
	ClientIsolation   bool     `json:"client_isolation"`
	L2Isolate         bool     `json:"l2_isolate"`
	BlockLANCIDRs     []string `json:"block_lan_cidrs"`
	CaptivePortalRef  string   `json:"captive_portal_ref"`
}

type WLANSSID struct {
	Name               string               `json:"name"`
	SSID               string               `json:"ssid"`
	Hidden             bool                 `json:"hidden"`
	VLANID             int                  `json:"vlan_id"`
	Bridge             string               `json:"bridge"`
	Band               string               `json:"band"`
	SecurityMode       string               `json:"security_mode"`
	Passphrase         string               `json:"passphrase"`
	RadiusServer       string               `json:"radius_server"`
	RadiusPort         int                  `json:"radius_port"`
	RadiusSecret       string               `json:"radius_secret"`
	Roaming            RoamingConfig        `json:"roaming"`
	BandSteering       BandSteeringConfig   `json:"band_steering"`
	GuestIsolation     GuestIsolationConfig `json:"guest_isolation"`
	PerClientDownKbps  int                  `json:"per_client_down_kbps"`
	PerClientUpKbps    int                  `json:"per_client_up_kbps"`
	MaxClients         int                  `json:"max_clients"`
	Enabled            bool                 `json:"enabled"`
}

type AutoChannelConfig struct {
	Enabled           bool  `json:"enabled"`
	IntervalMin       int   `json:"interval_min"`
	Allowed2GChannels []int `json:"allowed_2g_channels"`
	Allowed5GChannels []int `json:"allowed_5g_channels"`
	AvoidDFS          bool  `json:"avoid_dfs"`
}

type AutoPowerConfig struct {
	Enabled                bool `json:"enabled"`
	MinTxDBm               int  `json:"min_tx_dbm"`
	MaxTxDBm               int  `json:"max_tx_dbm"`
	TargetCoverageRSSIDBm  int  `json:"target_coverage_rssi_dbm"`
}

type WLANRFProfile struct {
	Name           string            `json:"name"`
	AutoChannel    AutoChannelConfig `json:"auto_channel"`
	AutoPower      AutoPowerConfig   `json:"auto_power"`
	ChannelWidth2G int               `json:"channel_width_2g"`
	ChannelWidth5G int               `json:"channel_width_5g"`
}

type WLANAPGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	SSIDs       []string `json:"ssids"`
	RFProfile   string   `json:"rf_profile"`
	VLANNative  int      `json:"vlan_native"`
	LEDEnabled  bool     `json:"led_enabled"`
}

type ManagedAP struct {
	MAC             string `json:"mac"`
	Name            string `json:"name"`
	Serial          string `json:"serial"`
	Model           string `json:"model"`
	APGroup         string `json:"ap_group"`
	ManagementVLAN  int    `json:"management_vlan"`
	StaticIP        string `json:"static_ip"`
	Radio2GChannel  int    `json:"radio_2g_channel"`
	Radio5GChannel  int    `json:"radio_5g_channel"`
	TxPower2GDBm    int    `json:"tx_power_2g_dbm"`
	TxPower5GDBm    int    `json:"tx_power_5g_dbm"`
	MeshRole        string `json:"mesh_role"`
	Enabled         bool   `json:"enabled"`
}

type MeshConfig struct {
	Enabled      bool   `json:"enabled"`
	MeshID       string `json:"mesh_id"`
	Protocol     string `json:"protocol"`
	BackhaulBand string `json:"backhaul_band"`
	SAEPassword  string `json:"sae_password"`
	AutoHeal     bool   `json:"auto_heal"`
	MaxHops      int    `json:"max_hops"`
}

// ParseConfig decodes a raw config map into FullWirelessConfig.
func ParseConfig(cfg map[string]any) (*FullWirelessConfig, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var out FullWirelessConfig
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
