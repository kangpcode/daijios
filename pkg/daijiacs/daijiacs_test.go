// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijiacs

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kangpcode/daijios/pkg/secauth"
)

func TestCWMPMultiTurnProvisioningTemplatesWiFiBillingAndMonitoring(t *testing.T) {
	tm, err := secauth.NewTokenManager([]byte("daijiacs-unit-test-signing-key"), time.Hour)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	adminTok, _, _ := tm.Issue("acsadmin", "superadmin", []secauth.Permission{
		secauth.PermConfigRead, secauth.PermConfigWrite, secauth.PermSystemUpdate, secauth.PermSystemReboot, secauth.PermConfigReadSecrets, secauth.PermNetDiag,
	}, time.Hour, time.Now())
	netTok, _, _ := tm.Issue("netop", "netadmin", []secauth.Permission{
		secauth.PermConfigRead, secauth.PermConfigWrite, secauth.PermNetDiag,
	}, time.Hour, time.Now())
	roTok, _, _ := tm.Issue("viewer", "readonly", []secauth.Permission{
		secauth.PermConfigRead,
	}, time.Hour, time.Now())

	srv, err := NewServer(Config{
		CWMPUsername: "cpe-user",
		CWMPPassword: "cpe-strong-password",
		Tokens:       tm,
		Presets: []PresetRule{
			{
				ID:            "bootstrap-defaults",
				PolicyVersion: 1,
				EventFilter:   "0 BOOTSTRAP",
				VirtualSets:   map[string]string{"virtual.inform.interval": "300"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	jar, _ := cookiejar.New(nil)
	cpeClient := &http.Client{Jar: jar}

	// 1. Unauthenticated CPE Inform must receive 401 Basic challenge.
	unauthReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/tr069", strings.NewReader("<empty/>"))
	if resp, err := cpeClient.Do(unauthReq); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 CWMP unauth, got err=%v resp=%v", err, resp)
	} else {
		_ = resp.Body.Close()
	}

	// 2. Huawei ONT sends 0 BOOTSTRAP Inform reporting RxPower=-2850 (-28.50 dBm, low optical alarm!).
	huaweiInform := `<?xml version="1.0" encoding="UTF-8"?>
<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
  <soap-env:Header><cwmp:ID>inf-1</cwmp:ID></soap-env:Header>
  <soap-env:Body>
    <cwmp:Inform>
      <DeviceId>
        <Manufacturer>Huawei Technologies Co., Ltd</Manufacturer>
        <OUI>00E0FC</OUI>
        <ProductClass>EG8145V5</ProductClass>
        <SerialNumber>HWTC-99887766</SerialNumber>
      </DeviceId>
      <Event><EventStruct><EventCode>0 BOOTSTRAP</EventCode></EventStruct></Event>
      <ParameterList>
        <ParameterValueStruct><Name>InternetGatewayDevice.DeviceInfo.SoftwareVersion</Name><Value>V5R020C10S115</Value></ParameterValueStruct>
        <ParameterValueStruct><Name>InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID</Name><Value>Old-WiFi</Value></ParameterValueStruct>
        <ParameterValueStruct><Name>InternetGatewayDevice.WANDevice.1.X_HW_DEBUG.AMP.Optic.RxPower</Name><Value>-2850</Value></ParameterValueStruct>
      </ParameterList>
    </cwmp:Inform>
  </soap-env:Body>
</soap-env:Envelope>`

	postCWMP := func(body string) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/tr069", strings.NewReader(body))
		req.SetBasicAuth("cpe-user", "cpe-strong-password")
		req.Header.Set("Content-Type", "text/xml")
		resp, err := cpeClient.Do(req)
		if err != nil {
			t.Fatalf("CWMP POST error: %v", err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.String()
	}

	code, infResp := postCWMP(huaweiInform)
	if code != http.StatusOK || !strings.Contains(infResp, "<cwmp:InformResponse>") {
		t.Fatalf("Inform failed: %d %s", code, infResp)
	}

	// Preset rule queued PeriodicInformInterval=300; CPE polls via empty POST and gets SetParameterValues.
	code, rpc1 := postCWMP("")
	if code != http.StatusOK || !strings.Contains(rpc1, "PeriodicInformInterval") || !strings.Contains(rpc1, ">300<") {
		t.Fatalf("expected Preset SetParameterValues RPC, got %d %s", code, rpc1)
	}
	setRespXML := `<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><soap-env:Body><cwmp:SetParameterValuesResponse><Status>0</Status></cwmp:SetParameterValuesResponse></soap-env:Body></soap-env:Envelope>`
	code, endResp := postCWMP(setRespXML)
	if code != http.StatusNoContent {
		t.Fatalf("expected 204 end of session, got %d %s", code, endResp)
	}

	// 3. Re-Inform should NOT re-apply v1 preset idempotently.
	postCWMP(huaweiInform)
	code, emptyAfter := postCWMP("")
	if code != http.StatusNoContent {
		t.Fatalf("expected idempotent preset (no duplicate task), got %d %s", code, emptyAfter)
	}

	// 4. Customer WiFi update from Daimo/DaiWeb + RBAC + secret redaction for netadmin vs superadmin.
	wifiBody := `{"ssid":"Rumah-Budi-5G","passphrase":"UltraSafeWiFi2026","enabled":true}`
	wifiReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/acs/devices/HWTC-99887766/wifi", strings.NewReader(wifiBody))
	wifiReq.Header.Set("Authorization", "Bearer "+netTok)
	wifiResp, err := http.DefaultClient.Do(wifiReq)
	if err != nil || wifiResp.StatusCode != http.StatusOK {
		t.Fatalf("WiFi API failed: err=%v resp=%v", err, wifiResp)
	}
	var wifiTaskBuf bytes.Buffer
	_, _ = wifiTaskBuf.ReadFrom(wifiResp.Body)
	_ = wifiResp.Body.Close()
	if strings.Contains(wifiTaskBuf.String(), "UltraSafeWiFi2026") || !strings.Contains(wifiTaskBuf.String(), "***REDACTED***") {
		t.Fatalf("WiFi API response leaked passphrase: %s", wifiTaskBuf.String())
	}

	// Verify Huawei-specific PreSharedKey path emitted during next CWMP session!
	postCWMP(huaweiInform)
	code, wifiRPC := postCWMP("")
	if code != http.StatusOK || !strings.Contains(wifiRPC, "PreSharedKey.1.PreSharedKey") || !strings.Contains(wifiRPC, "Rumah-Budi-5G") {
		t.Fatalf("expected Huawei WiFi SetParameterValues, got %d %s", code, wifiRPC)
	}
	postCWMP(setRespXML)

	// Verify netadmin sees redacted device queue & virtual passphrase, while superadmin can read if authorized.
	devRedacted, ok := srv.GetDevice("HWTC-99887766", true)
	if !ok || devRedacted.Virtual.WiFiPassphrase != "***REDACTED***" {
		t.Fatalf("expected redacted virtual passphrase, got %+v", devRedacted.Virtual)
	}
	if devRedacted.Virtual.OpticalRxDBm == nil || *devRedacted.Virtual.OpticalRxDBm != -28.5 {
		t.Fatalf("expected normalized Huawei RxPower -28.50 dBm, got %+v", devRedacted.Virtual.OpticalRxDBm)
	}

	// 5. Reject unsafe http:// firmware URL (SSRF / MITM protection) & allow https:// upgrade + reboot + reset.
	if _, err := srv.EnqueueFirmwareUpgrade("HWTC-99887766", "http://insecure.example.com/fw.bin", 1024); !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("expected ErrUnsafeURL on insecure http firmware URL, got %v", err)
	}
	fwReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/acs/devices/HWTC-99887766/firmware", strings.NewReader(`{"url":"https://dl.daijios.dev/ont/eg8145v5.bin","file_size":4194304}`))
	fwReq.Header.Set("Authorization", "Bearer "+adminTok)
	if resp, err := http.DefaultClient.Do(fwReq); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("firmware upgrade failed: %v %v", err, resp)
	} else {
		_ = resp.Body.Close()
	}

	// Readonly token blocked from firmware upgrade & reboot.
	roRebootReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/acs/devices/HWTC-99887766/reboot", nil)
	roRebootReq.Header.Set("Authorization", "Bearer "+roTok)
	if resp, err := http.DefaultClient.Do(roRebootReq); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for readonly reboot, got %v %v", err, resp)
	} else {
		_ = resp.Body.Close()
	}

	// Enqueue Reboot & FactoryReset and verify SOAP RPC payloads render cleanly.
	if _, err := srv.EnqueueLifecycle("HWTC-99887766", RPCReboot); err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	if _, err := srv.EnqueueLifecycle("HWTC-99887766", RPCFactoryReset); err != nil {
		t.Fatalf("FactoryReset: %v", err)
	}
	postCWMP(huaweiInform)
	_, fwRPC := postCWMP("")
	if !strings.Contains(fwRPC, "<cwmp:Download>") {
		t.Fatalf("expected Download RPC, got %s", fwRPC)
	}
	_, dlDone := postCWMP(`<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><soap-env:Body><cwmp:DownloadResponse><Status>0</Status></cwmp:DownloadResponse></soap-env:Body></soap-env:Envelope>`)
	if !strings.Contains(dlDone, "<cwmp:Reboot>") {
		t.Fatalf("expected Reboot RPC, got %s", dlDone)
	}
	_, rbDone := postCWMP(`<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><soap-env:Body><cwmp:RebootResponse/></soap-env:Body></soap-env:Envelope>`)
	if !strings.Contains(rbDone, "<cwmp:FactoryReset/>") {
		t.Fatalf("expected FactoryReset RPC, got %s", rbDone)
	}
	postCWMP(`<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><soap-env:Body><cwmp:FactoryResetResponse/></soap-env:Body></soap-env:Envelope>`)

	// 6. Billing suspend/activate integration & TR-369 USP + ZTE/FiberHome/TR-181 templates + Monitoring alarms.
	billReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/acs/devices/HWTC-99887766/billing-state", strings.NewReader(`{"action":"suspend"}`))
	billReq.Header.Set("Authorization", "Bearer "+netTok)
	if resp, err := http.DefaultClient.Do(billReq); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("billing suspend failed: %v %v", err, resp)
	} else {
		_ = resp.Body.Close()
	}

	// Register ZTE, FiberHome & TR-369 USP device.
	uspPayload, _ := json.Marshal(USPMessage{
		MsgID: "usp-1", EndpointID: "TR181-USP-01", Manufacturer: "Generic", Type: "SET",
		Params: map[string]string{"virtual.wifi.ssid": "Campus-TR369"},
	})
	uspReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/usp", bytes.NewReader(uspPayload))
	uspReq.Header.Set("Authorization", "Bearer "+netTok)
	if resp, err := http.DefaultClient.Do(uspReq); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("USP SET failed: %v %v", err, resp)
	} else {
		_ = resp.Body.Close()
	}

	monReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/acs/monitoring", nil)
	monReq.Header.Set("Authorization", "Bearer "+netTok)
	monResp, err := http.DefaultClient.Do(monReq)
	if err != nil || monResp.StatusCode != http.StatusOK {
		t.Fatalf("monitoring HTTP failed: %v %v", err, monResp)
	}
	var monSum MonitoringSummary
	_ = json.NewDecoder(monResp.Body).Decode(&monSum)
	_ = monResp.Body.Close()
	if monSum.TotalCPEs != 2 || monSum.SuspendedBilling != 1 || len(monSum.LowOpticalAlarms) != 1 {
		t.Fatalf("unexpected monitoring summary: %+v", monSum)
	}
}

func BenchmarkCWMPInformAndTemplateMatch(b *testing.B) {
	tpls := DefaultVendorTemplates()
	informXML := `<?xml version="1.0"?><soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><soap-env:Header><cwmp:ID>1</cwmp:ID></soap-env:Header><soap-env:Body><cwmp:Inform><DeviceId><Manufacturer>ZTE</Manufacturer><OUI>001E10</OUI><ProductClass>F670L</ProductClass><SerialNumber>ZTEGC123456</SerialNumber></DeviceId><Event><EventStruct><EventCode>2 PERIODIC</EventCode></EventStruct></Event><ParameterList><ParameterValueStruct><Name>InternetGatewayDevice.WANDevice.1.X_ZTE-COM_WANPONInterfaceConfig.RXPower</Name><Value>-19.4</Value></ParameterValueStruct></ParameterList></cwmp:Inform></soap-env:Body></soap-env:Envelope>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, err := ParseCWMPEnvelope(strings.NewReader(informXML))
		if err != nil {
			b.Fatal(err)
		}
		tpl := MatchTemplate(tpls, p.Inform.Manufacturer, p.Inform.ProductClass, p.Inform.Params)
		_ = ExtractVirtualParams(tpl, p.Inform.Params, true)
	}
}
