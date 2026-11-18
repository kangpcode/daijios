// SPDX-License-Identifier: Apache-2.0
package ispengine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kangpcode/daijios/pkg/ispplan"
)

func TestRADIUSWireAndUDPCoALiveSessionControl(t *testing.T) {
	secret := []byte("DaijiCoASecret2026!")

	// 1. Test RFC 2865 PAP encode/decode round-trip.
	auth := NewRandomAuth()
	encPW := EncodePasswordPAP("BudiPass2026!", auth, secret)
	if dec := DecodePasswordPAP(encPW, auth, secret); dec != "BudiPass2026!" {
		t.Fatalf("PAP decode mismatch: got %q", dec)
	}

	// 2. Test PPPoE auth, MAC binding, expired-user isolation, and voucher limits.
	ispCfg := &ispplan.ISPBlock{
		IPPools: []ispplan.ISPIPPool{
			{Name: "pool-res", Ranges: []string{"100.64.0.0/20"}},
			{Name: "pool-isolir", Ranges: []string{"100.64.250.0/24"}},
		},
		Profiles: []ispplan.ISPProfile{
			{Name: "home-50m", DownloadKbps: 50000, UploadKbps: 25000, AddressPool: "pool-res", ExpiredPool: "pool-isolir", SharedUsers: 1},
		},
		PPPoE: ispplan.PPPoEBlock{
			Secrets: []ispplan.PPPoESecret{
				{Username: "budi", Password: "pw1", Profile: "home-50m", CallerMAC: "aa:bb:cc:11:22:33", ExpiresAt: "2027-01-01T00:00:00Z"},
				{Username: "telat", Password: "pw2", Profile: "home-50m", ExpiresAt: "2026-01-01T00:00:00Z"},
			},
		},
		Hotspot: ispplan.HotspotBlock{
			Vouchers: []ispplan.HotspotVoucher{
				{Code: "VOUCH1", Profile: "home-50m", ValiditySec: 3600, DataLimitMB: 100, MaxDevices: 1},
			},
		},
	}

	mgr := NewSessionManager(ispCfg)
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	// Wrong MAC must be rejected.
	if _, err := mgr.AuthenticatePPPoE("budi", "pw1", "00:00:00:00:00:99", now); !errors.Is(err, ErrMACMismatch) {
		t.Fatalf("expected ErrMACMismatch, got %v", err)
	}
	sess, err := mgr.AuthenticatePPPoE("budi", "pw1", "aa:bb:cc:11:22:33", now)
	if err != nil {
		t.Fatalf("valid PPPoE auth failed: %v", err)
	}
	// Expired user gets placed into pool-isolir.
	expSess, err := mgr.AuthenticatePPPoE("telat", "pw2", "aa:bb:cc:11:22:44", now)
	if err != nil || !expSess.Isolated || !strings.HasPrefix(expSess.AssignedIP, "100.64.250.") {
		t.Fatalf("expected isolated expired session in 100.64.250.x, got %+v err=%v", expSess, err)
	}

	// Hotspot voucher single-device & quota check.
	hsSess, err := mgr.RedeemHotspotVoucher("VOUCH1", "11:22:33:44:55:66", now)
	if err != nil {
		t.Fatalf("RedeemHotspotVoucher failed: %v", err)
	}
	if _, err := mgr.RedeemHotspotVoucher("VOUCH1", "11:22:33:44:55:77", now); !errors.Is(err, ErrVoucherInvalid) {
		t.Fatalf("expected second device voucher rejection, got %v", err)
	}
	exceeded, err := mgr.InterimAccounting(hsSess.SessionID, 60*1024*1024, 50*1024*1024, now.Add(time.Minute))
	if err != nil || !exceeded {
		t.Fatalf("expected quota exceeded disconnect, got exceeded=%v err=%v", exceeded, err)
	}

	// 3. Real UDP RFC 5176 CoA-Request & Disconnect-Request test over loopback!
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srvAddr, err := StartCoAServer(ctx, "127.0.0.1:0", secret, mgr.HandleCoAPacket)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("udp", srvAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	coaReq := &RADIUSPacket{Code: CodeCoARequest, Identifier: 7}
	coaReq.AddString(AttrAcctSessionID, sess.SessionID)
	coaReq.AddString(AttrFilterID, "ISOLIR")
	coaReq.AddDaijiRateLimit("512/512")
	coaReq.AddIPv4(AttrNASIPAddress, netip.MustParseAddr("10.255.0.1"))
	wire, err := SignCoARequest(coaReq, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	respBuf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(respBuf)
	if err != nil {
		t.Fatal(err)
	}
	respPkt, err := ParseRADIUSWire(respBuf[:n])
	if err != nil || respPkt.Code != CodeCoAACK {
		t.Fatalf("expected CodeCoAACK (44), got %+v err=%v", respPkt, err)
	}

	// Verify live session speed & isolation updated by CoA!
	sessions := mgr.ListSessions()
	var updated *SubscriberSession
	for i := range sessions {
		if sessions[i].SessionID == sess.SessionID {
			updated = &sessions[i]
		}
	}
	if updated == nil || !updated.Isolated || updated.DownloadKbps != 512 {
		t.Fatalf("CoA did not update live session: %+v", updated)
	}
}

func TestMultiWANFailoverAndAntiFlapRecovery(t *testing.T) {
	mon := NewMultiWANMonitor(ispplan.MultiWANBlock{
		Enabled: true,
		Mode:    "load-balance-ecmp",
		WANs: []ispplan.MultiWANLink{
			{Name: "wan-a", Interface: "eth0", Gateway: "203.0.113.1", Weight: 2, Distance: 1, CheckTargets: []string{"1.1.1.1", "8.8.8.8"}, FailThreshold: 3, RecoverThreshold: 2, Enabled: true},
			{Name: "wan-b", Interface: "eth1", Gateway: "198.51.100.1", Weight: 1, Distance: 2, CheckTargets: []string{"9.9.9.9"}, FailThreshold: 3, RecoverThreshold: 2, Enabled: true},
		},
	})

	// Initially both WANs are UP -> ECMP nexthops present.
	routeCmd := strings.Join(mon.ActiveDefaultRouteArgs(), " ")
	if !strings.Contains(routeCmd, "203.0.113.1") || !strings.Contains(routeCmd, "198.51.100.1") {
		t.Fatalf("expected ECMP both gateways, got: %s", routeCmd)
	}

	// If only 1 of 2 recursive targets fails on wan-a, wan-a must stay UP.
	for i := 0; i < 4; i++ {
		if tr := mon.RecordProbe("wan-a", "1.1.1.1", 0, false); tr != nil {
			t.Fatalf("wan-a flapped down despite 8.8.8.8 still reachable: %+v", tr)
		}
	}

	// Once 8.8.8.8 also fails 3 times, wan-a transitions DOWN -> wan-down event + route switches to wan-b only!
	var ev *WANTransition
	for i := 0; i < 3; i++ {
		ev = mon.RecordProbe("wan-a", "8.8.8.8", 0, false)
	}
	if ev == nil || ev.Event != "wan-down" {
		t.Fatalf("expected wan-down transition, got %+v", ev)
	}
	routeDown := strings.Join(mon.ActiveDefaultRouteArgs(), " ")
	if strings.Contains(routeDown, "203.0.113.1") || !strings.Contains(routeDown, "198.51.100.1") {
		t.Fatalf("failover route did not exclude down wan-a: %s", routeDown)
	}

	// Recover requires RecoverThreshold=2 consecutive OKs.
	if tr := mon.RecordProbe("wan-a", "1.1.1.1", 12.5, true); tr != nil {
		t.Fatalf("recovered too early on 1 probe: %+v", tr)
	}
	if tr := mon.RecordProbe("wan-a", "1.1.1.1", 11.2, true); tr == nil || tr.Event != "wan-up" {
		t.Fatalf("expected wan-up on 2nd consecutive pass, got %+v", tr)
	}
}
