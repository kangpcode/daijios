// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIEndToEndPhase0(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "schema", "daijios.schema.json")
	cfgPath := filepath.Join("..", "..", "schema", "examples", "default-config.json")
	storeDir := t.TempDir()

	runCmd := func(wantCode int, args ...string) string {
		t.Helper()
		var out, errBuf bytes.Buffer
		code := run(args, &out, &errBuf)
		if code != wantCode {
			t.Fatalf("cmd %v exited %d (want %d)\nstdout: %s\nstderr: %s",
				args, code, wantCode, out.String(), errBuf.String())
		}
		return out.String()
	}

	bannerOut := runCmd(0, "banner")
	if !strings.Contains(bannerOut, "DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)") {
		t.Fatalf("unexpected banner output: %s", bannerOut)
	}

	valOut := runCmd(0, "schema", "validate", "--schema", schemaPath, "--config", cfgPath)
	if !strings.Contains(valOut, "VALID:") {
		t.Fatalf("expected VALID output, got: %s", valOut)
	}

	cliSpec := runCmd(0, "schema", "export-cli", "--schema", schemaPath)
	if !strings.Contains(cliSpec, "system hostname") {
		t.Fatalf("exported CLI spec missing 'system hostname'")
	}

	runCmd(0, "config", "init", "--store", storeDir, "--schema", schemaPath, "--bootstrap", cfgPath)
	runCmd(0, "config", "set", "--store", storeDir, "--schema", schemaPath, "--path", "system.hostname", "--value", "daiji-cli-test")
	diffOut := runCmd(0, "config", "diff", "--store", storeDir, "--schema", schemaPath)
	if !strings.Contains(diffOut, "daiji-cli-test") {
		t.Fatalf("diff output missing staged value: %s", diffOut)
	}
	runCmd(0, "config", "commit", "--store", storeDir, "--schema", schemaPath, "--actor", "cli-admin", "--msg", "rename via cli")
	auditOut := runCmd(0, "config", "verify-audit", "--store", storeDir, "--schema", schemaPath)
	if !strings.Contains(auditOut, "OK: verified") {
		t.Fatalf("unexpected audit output: %s", auditOut)
	}

	abOut := runCmd(0, "ab", "status", "--state-dir", t.TempDir())
	if !strings.Contains(abOut, `"active_slot": "A"`) {
		t.Fatalf("unexpected ab status: %s", abOut)
	}

	ispCfg := filepath.Join("..", "..", "schema", "examples", "isp-core-config.json")
	planOut := runCmd(0, "net", "plan", "--schema", schemaPath, "--config", ispCfg)
	if !strings.Contains(planOut, "ip link add vrf-cust type vrf table 100") ||
		!strings.Contains(planOut, "ip route replace 0.0.0.0/0") {
		t.Fatalf("net plan output missing expected commands:\n%s", planOut)
	}
	frrOut := runCmd(0, "net", "render-frr", "--schema", schemaPath, "--config", ispCfg)
	if !strings.Contains(frrOut, "router bgp 65100") || strings.Contains(frrOut, "bgpPeerSecret2026") {
		t.Fatalf("net render-frr unexpected or leaked secret:\n%s", frrOut)
	}
	keaOut := runCmd(0, "net", "render-kea", "--schema", schemaPath, "--config", ispCfg)
	if !strings.Contains(keaOut, `"Dhcp4"`) {
		t.Fatalf("net render-kea missing Dhcp4:\n%s", keaOut)
	}
	vrrpOut := runCmd(0, "net", "render-keepalived", "--schema", schemaPath, "--config", ispCfg)
	if !strings.Contains(vrrpOut, "vrrp_instance vrrp-lan") || strings.Contains(vrrpOut, "daijiVrrpKey2026") {
		t.Fatalf("net render-keepalived unexpected or leaked secret:\n%s", vrrpOut)
	}

	secCfg := filepath.Join("..", "..", "schema", "examples", "isp-edge-sec-config.json")
	nftOut := runCmd(0, "sec", "render-nft", "--schema", schemaPath, "--config", secCfg)
	if !strings.Contains(nftOut, "table inet daiji_filter") {
		t.Fatalf("sec render-nft missing table:\n%s", nftOut)
	}
	qosOut := runCmd(0, "sec", "render-qos", "--schema", schemaPath, "--config", secCfg)
	if !strings.Contains(qosOut, "tc qdisc replace") {
		t.Fatalf("sec render-qos missing tc commands:\n%s", qosOut)
	}
	vpnOut := runCmd(0, "sec", "render-vpn", "--schema", schemaPath, "--config", secCfg)
	if !strings.Contains(vpnOut, "[Interface]") || strings.Contains(vpnOut, "AAAAAAAAAAA") {
		t.Fatalf("sec render-vpn unexpected or leaked secret:\n%s", vpnOut)
	}
	auditSecOut := runCmd(0, "sec", "audit-check", "--schema", schemaPath, "--config", secCfg)
	if !strings.Contains(auditSecOut, "AUDIT PASS") {
		t.Fatalf("unexpected audit-check output: %s", auditSecOut)
	}

	bngCfg := filepath.Join("..", "..", "schema", "examples", "isp-bng-config.json")
	accelOut := runCmd(0, "isp", "render-accel", "--schema", schemaPath, "--config", bngCfg)
	if !strings.Contains(accelOut, "[pppoe]") || strings.Contains(accelOut, "DaijiCoASecret2026!") {
		t.Fatalf("isp render-accel unexpected or leaked secret:\n%s", accelOut)
	}
	mwanOut := runCmd(0, "isp", "render-mwan", "--schema", schemaPath, "--config", bngCfg)
	if !strings.Contains(mwanOut, "table inet daiji_isp") {
		t.Fatalf("isp render-mwan missing table:\n%s", mwanOut)
	}
	snmpOut := runCmd(0, "isp", "render-snmp", "--schema", schemaPath, "--config", bngCfg)
	if !strings.Contains(snmpOut, "SHA256") || strings.Contains(snmpOut, "DaijiSNMPAuth2026!") {
		t.Fatalf("isp render-snmp unexpected or leaked secret:\n%s", snmpOut)
	}
	scriptOut := runCmd(0, "isp", "run-script", "--schema", schemaPath, "--config", bngCfg, "--script", "on-wan-failover")
	if !strings.Contains(scriptOut, "Multi-WAN failover event detected") {
		t.Fatalf("isp run-script unexpected output: %s", scriptOut)
	}
	bwOut := runCmd(0, "isp", "bw-test")
	if !strings.Contains(bwOut, "throughput_mbps") {
		t.Fatalf("isp bw-test unexpected output: %s", bwOut)
	}

	acCfg := filepath.Join("..", "..", "schema", "examples", "campus-ac-config.json")
	hapdOut := runCmd(0, "wlan", "render-hostapd", "--schema", schemaPath, "--config", acCfg)
	if !strings.Contains(hapdOut, "ssid=DaijiCorp-Secure") || strings.Contains(hapdOut, "Daiji8021xRad2026!") {
		t.Fatalf("wlan render-hostapd unexpected or leaked secret:\n%s", hapdOut)
	}
	rrmOut := runCmd(0, "wlan", "rrm-solve", "--schema", schemaPath, "--config", acCfg)
	if !strings.Contains(rrmOut, "ap-lobby-root") {
		t.Fatalf("wlan rrm-solve unexpected output:\n%s", rrmOut)
	}

	cmdSchemaOut := runCmd(0, "cli", "export-command-schema", "--schema", schemaPath)
	if !strings.Contains(cmdSchemaOut, `"schema_version": "1.4.0"`) || !strings.Contains(cmdSchemaOut, `"commit-confirm"`) {
		t.Fatalf("cli export-command-schema unexpected output:\n%s", cmdSchemaOut)
	}
	searchOut := runCmd(0, "cli", "search", "--schema", schemaPath, "--q", "hostname", "--json")
	if !strings.Contains(searchOut, "system.hostname") {
		t.Fatalf("cli search unexpected output:\n%s", searchOut)
	}
	cliExecOut := runCmd(0, "cli", "exec", "--store", storeDir, "--schema", schemaPath, "--cmd", "enable; show revisions")
	if !strings.Contains(cliExecOut, "rename via cli") {
		t.Fatalf("cli exec unexpected output:\n%s", cliExecOut)
	}
	webCheckOut := runCmd(0, "web", "check", "--schema", schemaPath, "--json")
	if !strings.Contains(webCheckOut, `"daiji-dark"`) || !strings.Contains(webCheckOut, `"gzip_bytes"`) {
		t.Fatalf("web check unexpected output:\n%s", webCheckOut)
	}
	qrOut := runCmd(0, "mobile", "qr-onboard", "--mode", "local", "--endpoint", "http://192.168.88.1:8443")
	if !strings.HasPrefix(qrOut, "daijios://onboard?") {
		t.Fatalf("mobile qr-onboard unexpected output:\n%s", qrOut)
	}
	acsOut := runCmd(0, "acs", "templates", "--json")
	if !strings.Contains(acsOut, "huawei-ont-v1") || !strings.Contains(acsOut, "zte-igd-v1") {
		t.Fatalf("acs templates unexpected output:\n%s", acsOut)
	}
	billOut := runCmd(0, "billing", "simulate-cycle", "--json")
	if !strings.Contains(billOut, `"collected_cents": 222000`) {
		t.Fatalf("billing simulate-cycle unexpected output:\n%s", billOut)
	}
	cloudOut := runCmd(0, "cloud", "dr-check", "--json")
	if !strings.Contains(cloudOut, `"dr_verified": true`) {
		t.Fatalf("cloud dr-check unexpected output:\n%s", cloudOut)
	}
	portalOut := runCmd(0, "portal", "license-demo", "--json")
	if !strings.Contains(portalOut, `"DJLIC1.`) || !strings.Contains(portalOut, `"enterprise"`) {
		t.Fatalf("portal license-demo unexpected output:\n%s", portalOut)
	}
	soakOut := runCmd(0, "release", "soak", "--hours", "72", "--json")
	if !strings.Contains(soakOut, `"simulated_hours": 72`) || !strings.Contains(soakOut, `"failed_ops": 0`) {
		t.Fatalf("release soak unexpected output:\n%s", soakOut)
	}
}
