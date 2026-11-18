// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package netplan defines the typed Phase 1 networking data model, cross-field
// semantic invariants, and backward-compatible configuration migrations.
package netplan

import "encoding/json"

// NetworkConfig represents the networking sections of schema/daijios.schema.json (v1.1.0+).
type NetworkConfig struct {
	SchemaVersion string          `json:"schema_version"`
	System        SystemTimeRef   `json:"system"`
	Interfaces    InterfacesBlock `json:"interfaces"`
	IP            IPBlock         `json:"ip"`
	Routing       RoutingBlock    `json:"routing"`
	Switching     SwitchingBlock  `json:"switching"`
}

type SystemTimeRef struct {
	Hostname   string   `json:"hostname"`
	NTPServers []string `json:"ntp_servers"`
}

type InterfacesBlock struct {
	Physical []PhysicalIface `json:"physical"`
	VLANs    []VLANIface     `json:"vlans"`
	Bridges  []BridgeIface   `json:"bridges"`
	Bondings []BondingIface  `json:"bondings"`
	VRRP     []VRRPInstance  `json:"vrrp"`
	Veth     []VethIface     `json:"veth"`
	Tunnels  []TunnelIface   `json:"tunnels"`
}

type PhysicalIface struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Role        string   `json:"role"`
	MTU         int      `json:"mtu"`
	SpeedMbps   int      `json:"speed_mbps"`
	Duplex      string   `json:"duplex"`
	MACOverride string   `json:"mac_override"`
	VRF         string   `json:"vrf"`
	Addresses   []string `json:"addresses"`
	Enabled     bool     `json:"enabled"`
}

type VLANIface struct {
	Name         string   `json:"name"`
	Parent       string   `json:"parent"`
	VID          int      `json:"vid"`
	Protocol     string   `json:"protocol"`
	QinQInnerVID int      `json:"qinq_inner_vid"`
	MTU          int      `json:"mtu"`
	VRF          string   `json:"vrf"`
	Addresses    []string `json:"addresses"`
	Enabled      bool     `json:"enabled"`
}

type StormControl struct {
	BroadcastPPS      int `json:"broadcast_pps"`
	MulticastPPS      int `json:"multicast_pps"`
	UnknownUnicastPPS int `json:"unknown_unicast_pps"`
}

type PortSecurity struct {
	Enabled         bool     `json:"enabled"`
	MaxMACs         int      `json:"max_macs"`
	ViolationAction string   `json:"violation_action"`
	StaticMACs      []string `json:"static_macs"`
}

type BridgePort struct {
	Interface    string        `json:"interface"`
	PVID         int           `json:"pvid"`
	TaggedVIDs   []int         `json:"tagged_vids"`
	UntaggedVIDs []int         `json:"untagged_vids"`
	EdgePort     bool          `json:"edge_port"`
	BPDUGuard    bool          `json:"bpdu_guard"`
	StormControl *StormControl `json:"storm_control"`
	PortSecurity *PortSecurity `json:"port_security"`
}

type PortMirror struct {
	Enabled     bool     `json:"enabled"`
	SourcePorts []string `json:"source_ports"`
	DestPort    string   `json:"dest_port"`
	Direction   string   `json:"direction"`
}

type BridgeIface struct {
	Name          string       `json:"name"`
	VLANFiltering bool         `json:"vlan_filtering"`
	STPMode       string       `json:"stp_mode"`
	STPPriority   int          `json:"stp_priority"`
	IGMPSnooping  bool         `json:"igmp_snooping"`
	MLDSnooping   bool         `json:"mld_snooping"`
	Ports         []BridgePort `json:"ports"`
	Mirror        *PortMirror  `json:"mirror"`
	MTU           int          `json:"mtu"`
	VRF           string       `json:"vrf"`
	Addresses     []string     `json:"addresses"`
	Enabled       bool         `json:"enabled"`
}

type BondingIface struct {
	Name           string   `json:"name"`
	Mode           string   `json:"mode"`
	LACPRate       string   `json:"lacp_rate"`
	XmitHashPolicy string   `json:"xmit_hash_policy"`
	Members        []string `json:"members"`
	MTU            int      `json:"mtu"`
	VRF            string   `json:"vrf"`
	Addresses      []string `json:"addresses"`
	Enabled        bool     `json:"enabled"`
}

type VRRPInstance struct {
	Name            string   `json:"name"`
	Interface       string   `json:"interface"`
	VRID            int      `json:"vrid"`
	Priority        int      `json:"priority"`
	VirtualIPs      []string `json:"virtual_ips"`
	Preempt         bool     `json:"preempt"`
	AdvertIntMS     int      `json:"advert_int_ms"`
	AuthType        string   `json:"auth_type"`
	AuthSecret      string   `json:"auth_secret"`
	TrackInterfaces []string `json:"track_interfaces"`
	Enabled         bool     `json:"enabled"`
}

type VethIface struct {
	Name      string   `json:"name"`
	Peer      string   `json:"peer"`
	NetNS     string   `json:"netns"`
	MTU       int      `json:"mtu"`
	VRF       string   `json:"vrf"`
	Addresses []string `json:"addresses"`
	Enabled   bool     `json:"enabled"`
}

type TunnelIface struct {
	Name      string   `json:"name"`
	Mode      string   `json:"mode"`
	LocalIP   string   `json:"local_ip"`
	RemoteIP  string   `json:"remote_ip"`
	Dev       string   `json:"dev"`
	TTL       int      `json:"ttl"`
	Key       uint32   `json:"key"`
	VNI       uint32   `json:"vni"`
	DstPort   int      `json:"dst_port"`
	MTU       int      `json:"mtu"`
	VRF       string   `json:"vrf"`
	Addresses []string `json:"addresses"`
	Enabled   bool     `json:"enabled"`
}

type IPBlock struct {
	IPv4Forward *bool            `json:"ipv4_forward"`
	IPv6Forward *bool            `json:"ipv6_forward"`
	RPFilter    *int             `json:"rp_filter"`
	ARPProxy    bool             `json:"arp_proxy"`
	NDProxy     bool             `json:"nd_proxy"`
	ARPStatic   []StaticARPEntry `json:"arp_static"`
	DHCP        DHCPBlock        `json:"dhcp"`
	DNS         DNSBlock         `json:"dns"`
	NTP         NTPBlock         `json:"ntp"`
}

type StaticARPEntry struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Interface string `json:"interface"`
}

type DHCPBlock struct {
	Servers []DHCPServerPool `json:"servers"`
	Clients []DHCPClient     `json:"clients"`
	Relays  []DHCPRelay      `json:"relays"`
}

type DHCPStaticLease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

type DHCPServerPool struct {
	Name         string            `json:"name"`
	Interface    string            `json:"interface"`
	Subnet       string            `json:"subnet"`
	RangeStart   string            `json:"range_start"`
	RangeEnd     string            `json:"range_end"`
	Gateway      string            `json:"gateway"`
	DNSServers   []string          `json:"dns_servers"`
	DomainName   string            `json:"domain_name"`
	LeaseTimeSec int               `json:"lease_time_sec"`
	StaticLeases []DHCPStaticLease `json:"static_leases"`
	Enabled      bool              `json:"enabled"`
}

type DHCPClient struct {
	Interface          string `json:"interface"`
	DHCPv4             bool   `json:"dhcpv4"`
	DHCPv6PD           bool   `json:"dhcpv6_pd"`
	DefaultRouteMetric int    `json:"default_route_metric"`
	UsePeerDNS         bool   `json:"use_peer_dns"`
}

type DHCPRelay struct {
	Name             string   `json:"name"`
	ListenInterfaces []string `json:"listen_interfaces"`
	UpstreamServers  []string `json:"upstream_servers"`
	CircuitID        bool     `json:"circuit_id"`
	Enabled          bool     `json:"enabled"`
}

type DNSStaticHost struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

type DNSBlock struct {
	Enabled         bool            `json:"enabled"`
	ListenAddresses []string        `json:"listen_addresses"`
	Port            int             `json:"port"`
	Upstreams       []string        `json:"upstreams"`
	CacheSize       int             `json:"cache_size"`
	DNSSEC          bool            `json:"dnssec"`
	LocalDomain     string          `json:"local_domain"`
	StaticHosts     []DNSStaticHost `json:"static_hosts"`
}

type NTPBlock struct {
	Enabled      bool     `json:"enabled"`
	Servers      []string `json:"servers"`
	ServerMode   bool     `json:"server_mode"`
	AllowSubnets []string `json:"allow_subnets"`
}

type RoutingBlock struct {
	VRFs         []VRFDef      `json:"vrfs"`
	StaticRoutes []StaticRoute `json:"static_routes"`
	PolicyRoutes []PolicyRoute `json:"policy_routes"`
	BFD          []BFDProfile  `json:"bfd"`
	OSPF         OSPFBlock     `json:"ospf"`
	OSPFv3       OSPFv3Block   `json:"ospfv3"`
	BGP          BGPBlock      `json:"bgp"`
	RIP          RIPBlock      `json:"rip"`
	ISIS         ISISBlock     `json:"isis"`
	MPLS         MPLSBlock     `json:"mpls"`
}

type VRFDef struct {
	Name        string   `json:"name"`
	TableID     uint32   `json:"table_id"`
	RD          string   `json:"rd"`
	Interfaces  []string `json:"interfaces"`
	Description string   `json:"description"`
}

type ECMPHop struct {
	NextHop   string `json:"next_hop"`
	Interface string `json:"interface"`
	Weight    int    `json:"weight"`
}

type StaticRoute struct {
	Prefix    string    `json:"prefix"`
	NextHop   string    `json:"next_hop"`
	Interface string    `json:"interface"`
	Distance  int       `json:"distance"`
	VRF       string    `json:"vrf"`
	ECMPHops  []ECMPHop `json:"ecmp_hops"`
	Tag       uint32    `json:"tag"`
	Enabled   bool      `json:"enabled"`
}

type PolicyRoute struct {
	Priority    int    `json:"priority"`
	SrcPrefix   string `json:"src_prefix"`
	DstPrefix   string `json:"dst_prefix"`
	InInterface string `json:"in_interface"`
	FWMark      uint32 `json:"fwmark"`
	TableID     uint32 `json:"table_id"`
	Action      string `json:"action"`
}

type BFDProfile struct {
	Name             string `json:"name"`
	PeerIP           string `json:"peer_ip"`
	VRF              string `json:"vrf"`
	Interface        string `json:"interface"`
	MinTxMS          int    `json:"min_tx_ms"`
	MinRxMS          int    `json:"min_rx_ms"`
	DetectMultiplier int    `json:"detect_multiplier"`
	EchoMode         bool   `json:"echo_mode"`
}

type OSPFArea struct {
	AreaID   string   `json:"area_id"`
	AreaType string   `json:"area_type"`
	Networks []string `json:"networks"`
	AuthType string   `json:"auth_type"`
	AuthKey  string   `json:"auth_key"`
}

type OSPFBlock struct {
	Enabled           bool       `json:"enabled"`
	RouterID          string     `json:"router_id"`
	VRF               string     `json:"vrf"`
	BFD               bool       `json:"bfd"`
	DefaultOriginate  bool       `json:"default_originate"`
	PassiveInterfaces []string   `json:"passive_interfaces"`
	Redistribute      []string   `json:"redistribute"`
	Areas             []OSPFArea `json:"areas"`
}

type OSPFv3Area struct {
	AreaID     string   `json:"area_id"`
	Interfaces []string `json:"interfaces"`
}

type OSPFv3Block struct {
	Enabled  bool         `json:"enabled"`
	RouterID string       `json:"router_id"`
	VRF      string       `json:"vrf"`
	Areas    []OSPFv3Area `json:"areas"`
}

type PrefixListRule struct {
	Seq    int    `json:"seq"`
	Action string `json:"action"`
	Prefix string `json:"prefix"`
	GE     int    `json:"ge"`
	LE     int    `json:"le"`
}

type PrefixList struct {
	Name  string           `json:"name"`
	Rules []PrefixListRule `json:"rules"`
}

type RouteMapEntry struct {
	Seq             int    `json:"seq"`
	Action          string `json:"action"`
	MatchPrefixList string `json:"match_prefix_list"`
	MatchCommunity  string `json:"match_community"`
	SetLocalPref    *int   `json:"set_local_pref"`
	SetMED          *int   `json:"set_med"`
	SetASPrepend    string `json:"set_as_path_prepend"`
	SetCommunity    string `json:"set_community"`
}

type RouteMap struct {
	Name    string          `json:"name"`
	Entries []RouteMapEntry `json:"entries"`
}

type BGPNeighbor struct {
	PeerIP        string `json:"peer_ip"`
	RemoteASN     uint32 `json:"remote_asn"`
	Description   string `json:"description"`
	UpdateSource  string `json:"update_source"`
	EBGPMultihop  int    `json:"ebgp_multihop"`
	BFD           bool   `json:"bfd"`
	SendCommunity bool   `json:"send_community"`
	SoftReconfig  bool   `json:"soft_reconfig"`
	RouteMapIn    string `json:"route_map_in"`
	RouteMapOut   string `json:"route_map_out"`
	Password      string `json:"password"`
}

type BGPBlock struct {
	Enabled         bool          `json:"enabled"`
	ASN             uint32        `json:"asn"`
	RouterID        string        `json:"router_id"`
	VRF             string        `json:"vrf"`
	ECMPMaxPaths    int           `json:"ecmp_max_paths"`
	GracefulRestart bool          `json:"graceful_restart"`
	Networks        []string      `json:"networks"`
	PrefixLists     []PrefixList  `json:"prefix_lists"`
	RouteMaps       []RouteMap    `json:"route_maps"`
	Neighbors       []BGPNeighbor `json:"neighbors"`
}

type RIPBlock struct {
	Enabled           bool     `json:"enabled"`
	Version           int      `json:"version"`
	VRF               string   `json:"vrf"`
	Networks          []string `json:"networks"`
	PassiveInterfaces []string `json:"passive_interfaces"`
	Redistribute      []string `json:"redistribute"`
}

type ISISInterface struct {
	Name    string `json:"name"`
	Metric  int    `json:"metric"`
	BFD     bool   `json:"bfd"`
	Passive bool   `json:"passive"`
}

type ISISBlock struct {
	Enabled    bool            `json:"enabled"`
	NetID      string          `json:"net_id"`
	Level      string          `json:"level"`
	VRF        string          `json:"vrf"`
	Interfaces []ISISInterface `json:"interfaces"`
}

type LDPBlock struct {
	Enabled     bool     `json:"enabled"`
	RouterID    string   `json:"router_id"`
	TransportIP string   `json:"transport_ip"`
	Interfaces  []string `json:"interfaces"`
}

type MPLSBlock struct {
	Enabled       bool     `json:"enabled"`
	LabelRangeMin int      `json:"label_range_min"`
	LabelRangeMax int      `json:"label_range_max"`
	LDP           LDPBlock `json:"ldp"`
}

type SwitchingBlock struct {
	LLDP LLDPBlock `json:"lldp"`
}

type LLDPBlock struct {
	Enabled       bool     `json:"enabled"`
	TxIntervalSec int      `json:"tx_interval_sec"`
	TxHold        int      `json:"tx_hold"`
	CDPCompat     bool     `json:"cdp_compat"`
	MEDEnabled    bool     `json:"med_enabled"`
	Interfaces    []string `json:"interfaces"`
}

// ParseConfig decodes an untyped config map into strongly-typed NetworkConfig.
func ParseConfig(cfg map[string]any) (*NetworkConfig, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var out NetworkConfig
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
