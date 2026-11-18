// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package daijiacs implements DaijiACS: an embedded TR-069 (CWMP) & TR-369 (USP)
// Auto-Configuration Server for ONT/CPE provisioning, multi-vendor device
// templates (ZTE, Huawei, FiberHome, TR-181), virtual parameters, preset policies,
// customer WiFi control (Daimo/DaiWeb), and billing/optical monitoring integration.
package daijiacs

import (
	"fmt"
	"strconv"
	"strings"
)

// VendorTemplate maps canonical DaijiOS virtual attributes onto vendor-specific TR-098 / TR-181 paths.
type VendorTemplate struct {
	ID              string `json:"id"`
	VendorMatch     string `json:"vendor_match"`
	ModelPattern    string `json:"model_pattern,omitempty"`
	RootModel       string `json:"root_model"` // TR-098 | TR-181
	WiFiSSIDPath    string `json:"wifi_ssid_path"`
	WiFiPassPath    string `json:"wifi_pass_path"`
	WiFiEnablePath  string `json:"wifi_enable_path"`
	WANIPPath       string `json:"wan_ip_path"`
	WANPPPoEUser    string `json:"wan_pppoe_user_path"`
	WANEnablePath   string `json:"wan_enable_path"`
	OpticalRxPath   string `json:"optical_rx_path"`
	OpticalDivisor  float64 `json:"optical_divisor"` // e.g. 1.0 or 100.0 if vendor reports 0.01 dBm units
	FirmwareVerPath string `json:"firmware_ver_path"`
	InformIntPath   string `json:"inform_interval_path"`
}

// DefaultVendorTemplates returns built-in production templates for common FTTH ONT/CPE vendors.
func DefaultVendorTemplates() []VendorTemplate {
	return []VendorTemplate{
		{
			ID:              "zte-igd-v1",
			VendorMatch:     "zte",
			RootModel:       "TR-098",
			WiFiSSIDPath:    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
			WiFiPassPath:    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.KeyPassphrase",
			WiFiEnablePath:  "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Enable",
			WANIPPath:       "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress",
			WANPPPoEUser:    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username",
			WANEnablePath:   "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Enable",
			OpticalRxPath:   "InternetGatewayDevice.WANDevice.1.X_ZTE-COM_WANPONInterfaceConfig.RXPower",
			OpticalDivisor:  1.0,
			FirmwareVerPath: "InternetGatewayDevice.DeviceInfo.SoftwareVersion",
			InformIntPath:   "InternetGatewayDevice.ManagementServer.PeriodicInformInterval",
		},
		{
			ID:              "huawei-ont-v1",
			VendorMatch:     "huawei",
			RootModel:       "TR-098",
			WiFiSSIDPath:    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
			WiFiPassPath:    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.PreSharedKey",
			WiFiEnablePath:  "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Enable",
			WANIPPath:       "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress",
			WANPPPoEUser:    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username",
			WANEnablePath:   "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Enable",
			OpticalRxPath:   "InternetGatewayDevice.WANDevice.1.X_HW_DEBUG.AMP.Optic.RxPower",
			OpticalDivisor:  100.0, // Huawei often reports -2150 meaning -21.50 dBm
			FirmwareVerPath: "InternetGatewayDevice.DeviceInfo.SoftwareVersion",
			InformIntPath:   "InternetGatewayDevice.ManagementServer.PeriodicInformInterval",
		},
		{
			ID:              "fiberhome-ont-v1",
			VendorMatch:     "fiberhome",
			RootModel:       "TR-098",
			WiFiSSIDPath:    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
			WiFiPassPath:    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.KeyPassphrase",
			WiFiEnablePath:  "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Enable",
			WANIPPath:       "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress",
			WANPPPoEUser:    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username",
			WANEnablePath:   "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Enable",
			OpticalRxPath:   "InternetGatewayDevice.WANDevice.1.X_FH_OpticalInterface.RxPower",
			OpticalDivisor:  1.0,
			FirmwareVerPath: "InternetGatewayDevice.DeviceInfo.SoftwareVersion",
			InformIntPath:   "InternetGatewayDevice.ManagementServer.PeriodicInformInterval",
		},
		{
			ID:              "generic-tr181",
			VendorMatch:     "generic-tr181",
			RootModel:       "TR-181",
			WiFiSSIDPath:    "Device.WiFi.SSID.1.SSID",
			WiFiPassPath:    "Device.WiFi.AccessPoint.1.Security.KeyPassphrase",
			WiFiEnablePath:  "Device.WiFi.SSID.1.Enable",
			WANIPPath:       "Device.IP.Interface.1.IPv4Address.1.IPAddress",
			WANPPPoEUser:    "Device.PPP.Interface.1.Username",
			WANEnablePath:   "Device.PPP.Interface.1.Enable",
			OpticalRxPath:   "Device.Optical.Interface.1.RxPower",
			OpticalDivisor:  1.0,
			FirmwareVerPath: "Device.DeviceInfo.SoftwareVersion",
			InformIntPath:   "Device.ManagementServer.PeriodicInformInterval",
		},
	}
}

// MatchTemplate selects the best-fitting VendorTemplate for a CPE's Manufacturer/ProductClass/params.
func MatchTemplate(templates []VendorTemplate, manufacturer, productClass string, params map[string]string) VendorTemplate {
	mLow := strings.ToLower(manufacturer)
	pLow := strings.ToLower(productClass)
	for _, tpl := range templates {
		if tpl.VendorMatch != "generic-tr181" && (strings.Contains(mLow, tpl.VendorMatch) || strings.Contains(pLow, tpl.VendorMatch)) {
			return tpl
		}
	}
	for k := range params {
		if strings.HasPrefix(k, "Device.") {
			for _, tpl := range templates {
				if tpl.RootModel == "TR-181" {
					return tpl
				}
			}
		}
	}
	// Fallback to standard TR-098 layout.
	if len(templates) > 0 {
		return templates[0]
	}
	return DefaultVendorTemplates()[0]
}

// VirtualParams captures normalized cross-vendor CPE runtime/operational values.
type VirtualParams struct {
	TemplateID      string   `json:"template_id"`
	WiFiSSID        string   `json:"wifi_ssid,omitempty"`
	WiFiPassphrase  string   `json:"wifi_passphrase,omitempty"` // redacted on non-superadmin responses
	WiFiEnabled     *bool    `json:"wifi_enabled,omitempty"`
	WANIP           string   `json:"wan_ip,omitempty"`
	WANPPPoEUser    string   `json:"wan_pppoe_user,omitempty"`
	OpticalRxDBm    *float64 `json:"optical_rx_dbm,omitempty"`
	FirmwareVersion string   `json:"firmware_version,omitempty"`
}

// ExtractVirtualParams maps raw vendor TR-069/TR-369 parameter values into VirtualParams.
func ExtractVirtualParams(tpl VendorTemplate, params map[string]string, redactSecrets bool) VirtualParams {
	vp := VirtualParams{
		TemplateID:      tpl.ID,
		WiFiSSID:        params[tpl.WiFiSSIDPath],
		WANIP:           params[tpl.WANIPPath],
		WANPPPoEUser:    params[tpl.WANPPPoEUser],
		FirmwareVersion: params[tpl.FirmwareVerPath],
	}
	if pass := params[tpl.WiFiPassPath]; pass != "" {
		if redactSecrets {
			vp.WiFiPassphrase = "***REDACTED***"
		} else {
			vp.WiFiPassphrase = pass
		}
	}
	if enRaw, ok := params[tpl.WiFiEnablePath]; ok && enRaw != "" {
		b := enRaw == "1" || strings.EqualFold(enRaw, "true")
		vp.WiFiEnabled = &b
	}
	if rxRaw, ok := params[tpl.OpticalRxPath]; ok && rxRaw != "" {
		clean := strings.TrimSpace(strings.TrimSuffix(strings.ToLower(rxRaw), "dbm"))
		if v, err := strconv.ParseFloat(strings.TrimSpace(clean), 64); err == nil {
			div := tpl.OpticalDivisor
			if div <= 0 {
				div = 1.0
			}
			// If vendor stores integer hundredths (e.g. -2150), scale; if already in dBm range [-50, 10], keep directly.
			if div > 1.0 && (v < -50.0 || v > 10.0) {
				v = v / div
			}
			vp.OpticalRxDBm = &v
		}
	}
	return vp
}

// PresetRule defines an automated provisioning policy applied to matching CPE devices.
type PresetRule struct {
	ID            string            `json:"id"`
	PolicyVersion int               `json:"policy_version"`
	VendorFilter  string            `json:"vendor_filter,omitempty"` // case-insensitive substring
	EventFilter   string            `json:"event_filter,omitempty"`  // e.g. "0 BOOTSTRAP" or "1 BOOT"
	TagFilter     string            `json:"tag_filter,omitempty"`
	VirtualSets   map[string]string `json:"virtual_sets,omitempty"` // virtual key -> value
	RawSets       map[string]string `json:"raw_sets,omitempty"`     // direct TR path -> value
}

// ResolveVirtualSet translates one virtual parameter key into its concrete vendor path and XSD type.
func ResolveVirtualSet(tpl VendorTemplate, vKey, vVal string) (path string, xsdType string, value string, ok bool) {
	switch vKey {
	case "virtual.wifi.ssid":
		return tpl.WiFiSSIDPath, "xsd:string", vVal, true
	case "virtual.wifi.passphrase":
		return tpl.WiFiPassPath, "xsd:string", vVal, true
	case "virtual.wifi.enabled":
		return tpl.WiFiEnablePath, "xsd:boolean", boolStr(vVal), true
	case "virtual.wan.pppoe_user":
		return tpl.WANPPPoEUser, "xsd:string", vVal, true
	case "virtual.wan.enabled":
		return tpl.WANEnablePath, "xsd:boolean", boolStr(vVal), true
	case "virtual.inform.interval":
		return tpl.InformIntPath, "xsd:unsignedInt", vVal, true
	default:
		return "", "", "", false
	}
}

func boolStr(s string) string {
	if s == "1" || strings.EqualFold(s, "true") {
		return "true"
	}
	return "false"
}

// FormatParamPreview protects secret virtual/vendor parameter keys in audit logs.
func FormatParamPreview(path, val string) string {
	low := strings.ToLower(path)
	if strings.Contains(low, "pass") || strings.Contains(low, "secret") || strings.Contains(low, "key") {
		return fmt.Sprintf("%s=***REDACTED***", path)
	}
	return fmt.Sprintf("%s=%s", path, val)
}
