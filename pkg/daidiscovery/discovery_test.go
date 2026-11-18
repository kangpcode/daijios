// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daidiscovery

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDJDP1WireEncodingAndHMACAuth(t *testing.T) {
	secret := []byte("daijios-l2-cluster-key-phase7")
	b := DeviceBeacon{
		Type:        TypeBeacon,
		Protocol:    "DJDP1",
		DeviceID:    "dj-gw-01",
		MAC:         "02:64:6a:aa:bb:cc",
		Hostname:    "daiji-core-jkt",
		IPv4:        "192.168.88.1",
		WebPort:     8443,
		OfflineOnly: true,
		Timestamp:   1700000000,
	}
	b.HMAC = ComputeBeaconHMAC(secret, b)

	wire, err := EncodeWire(b)
	if err != nil {
		t.Fatalf("EncodeWire: %v", err)
	}
	decoded, err := DecodeWire(wire)
	if err != nil {
		t.Fatalf("DecodeWire: %v", err)
	}
	if err := VerifyBeaconHMAC(secret, decoded); err != nil {
		t.Fatalf("VerifyBeaconHMAC valid failed: %v", err)
	}

	// Spoofed/tampered IP must fail HMAC verification.
	decoded.IPv4 = "10.0.0.99"
	if err := VerifyBeaconHMAC(secret, decoded); !errors.Is(err, ErrBadBeaconHMAC) {
		t.Fatalf("expected ErrBadBeaconHMAC on tampered beacon, got %v", err)
	}
}

func TestLiveUDPResponderAndScanner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	secret := []byte("lan-discovery-shared-secret")
	resp, err := StartResponder(ctx, "127.0.0.1:0", DeviceBeacon{
		DeviceID: "router-bng-01",
		MAC:      "02:64:6a:11:22:33",
		Hostname: "daiji-bng-01",
		IPv4:     "192.168.88.1",
		WebPort:  8443,
	}, secret)
	if err != nil {
		t.Fatalf("StartResponder: %v", err)
	}
	defer resp.Stop()

	// Valid secret discovers the node.
	beacons, err := ProbeTargets([]string{resp.AddrStr}, secret, 120*time.Millisecond)
	if err != nil {
		t.Fatalf("ProbeTargets: %v", err)
	}
	if len(beacons) != 1 || beacons[0].Hostname != "daiji-bng-01" || !beacons[0].OfflineOnly {
		t.Fatalf("unexpected discovered beacons: %+v", beacons)
	}

	// Wrong secret rejects untrusted/spoofed LAN announcements.
	untrusted, err := ProbeTargets([]string{resp.AddrStr}, []byte("wrong-secret"), 80*time.Millisecond)
	if err != nil {
		t.Fatalf("ProbeTargets untrusted: %v", err)
	}
	if len(untrusted) != 0 {
		t.Fatalf("expected untrusted beacon to be filtered out, got %+v", untrusted)
	}
}

func BenchmarkDJDP1EncodeDecodeVerify(b *testing.B) {
	secret := []byte("bench-discovery-key")
	beacon := DeviceBeacon{
		Type:      TypeBeacon,
		Protocol:  "DJDP1",
		DeviceID:  "dj-01",
		MAC:       "02:64:6a:11:22:33",
		Hostname:  "daiji-bench",
		IPv4:      "192.168.88.1",
		WebPort:   8443,
		Timestamp: 1700000000,
	}
	beacon.HMAC = ComputeBeaconHMAC(secret, beacon)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wire, err := EncodeWire(beacon)
		if err != nil {
			b.Fatal(err)
		}
		dec, err := DecodeWire(wire)
		if err != nil {
			b.Fatal(err)
		}
		if err := VerifyBeaconHMAC(secret, dec); err != nil {
			b.Fatal(err)
		}
	}
}
