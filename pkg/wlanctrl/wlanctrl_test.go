// SPDX-License-Identifier: Apache-2.0
package wlanctrl

import (
	"errors"
	"testing"
	"time"

	"github.com/kangpcode/daijios/pkg/wlanplan"
)

func TestZeroTouchAPOnboardingAndHeartbeat(t *testing.T) {
	secret := "DaijiZTPCampusSecret2026!"
	ac := NewACController(wlanplan.WirelessBlock{
		Controller: wlanplan.ACControllerConfig{
			Enabled:         true,
			ACName:          "DaijiOS-AC",
			AutoAdoptPolicy: "zero-touch-token",
			OnboardingToken: secret,
			DefaultAPGroup:  "campus-main",
		},
		APGroups: []wlanplan.WLANAPGroup{{Name: "campus-main", RFProfile: "hd"}},
	}, func() time.Time { return time.Unix(1700000000, 0) })

	// Bad ZTP token must be rejected.
	if _, err := ac.DiscoverAndAdopt(AdoptRequest{
		MAC: "aa:bb:cc:01:02:03", Serial: "DJAP-99", Model: "AX3000", IP: "10.50.0.55", Token: "bad-token",
	}); !errors.Is(err, ErrAdoptRejected) {
		t.Fatalf("expected ErrAdoptRejected, got %v", err)
	}

	// Valid HMAC-SHA256 onboarding token succeeds and assigns default AP group.
	tok := ComputeOnboardingToken(secret, "aa:bb:cc:01:02:03", "DJAP-99")
	ap, err := ac.DiscoverAndAdopt(AdoptRequest{
		MAC: "aa:bb:cc:01:02:03", Serial: "DJAP-99", Model: "AX3000", IP: "10.50.0.55", Token: tok,
	})
	if err != nil || !ap.Adopted || ap.APGroup != "campus-main" {
		t.Fatalf("unexpected adopted AP: %+v err=%v", ap, err)
	}
	if err := ac.RecordHeartbeat("aa:bb:cc:01:02:03", 42); err != nil {
		t.Fatal(err)
	}
	if inv := ac.Inventory(); len(inv) != 1 || inv[0].ClientCount != 42 {
		t.Fatalf("unexpected inventory: %+v", inv)
	}
}

func TestRRMAutoChannelPowerAndBandSteeringAndBTMAndMeshSelfHeal(t *testing.T) {
	aps := []wlanplan.ManagedAP{
		{MAC: "aa:bb:cc:01:01:01", Name: "ap-root", MeshRole: "root", Enabled: true},
		{MAC: "aa:bb:cc:01:01:02", Name: "ap-east", MeshRole: "node", Enabled: true},
		{MAC: "aa:bb:cc:01:01:03", Name: "ap-west", MeshRole: "node", Enabled: true},
	}
	rf := wlanplan.WLANRFProfile{
		Name: "hd",
		AutoChannel: wlanplan.AutoChannelConfig{
			Enabled:           true,
			Allowed2GChannels: []int{1, 6, 11},
			Allowed5GChannels: []int{36, 44, 149},
		},
		AutoPower: wlanplan.AutoPowerConfig{
			Enabled:               true,
			MinTxDBm:              10,
			MaxTxDBm:              22,
			TargetCoverageRSSIDBm: -68,
		},
	}
	scans := []NeighborScan{
		{ReporterMAC: "aa:bb:cc:01:01:01", NeighborMAC: "aa:bb:cc:01:01:02", Band: "2.4ghz", RSSIDBm: -52},
		{ReporterMAC: "aa:bb:cc:01:01:02", NeighborMAC: "aa:bb:cc:01:01:03", Band: "2.4ghz", RSSIDBm: -55},
		{ReporterMAC: "aa:bb:cc:01:01:01", NeighborMAC: "aa:bb:cc:01:01:03", Band: "2.4ghz", RSSIDBm: -58},
	}
	plans := OptimizeRF(aps, rf, scans)
	if len(plans) != 3 {
		t.Fatalf("expected 3 RF plans, got %d", len(plans))
	}
	// All 3 mutually interfering APs must receive distinct orthogonal 2.4GHz channels (1, 6, 11) and reduced power (10 dBm).
	chSet := map[int]bool{}
	for _, p := range plans {
		chSet[p.Channel2G] = true
		if p.Power2G != 10 {
			t.Errorf("expected TPC reduced power 10 dBm under strong neighbor overlap (-52 dBm), got %d", p.Power2G)
		}
	}
	if len(chSet) != 3 {
		t.Fatalf("RRM failed orthogonal channel assignment across neighbors: %+v", plans)
	}

	// Band steering steers capable 5GHz client up to Max2GRejects=2, then permits 2.4GHz fallback.
	bs := NewBandSteerAdvisor(wlanplan.BandSteeringConfig{Enabled: true, Prefer5GHzRSSI: -70, Max2GRejects: 2})
	bs.Record5GHzProbe("de:ad:be:ef:00:01")
	if dec := bs.Evaluate2GHzAssoc("de:ad:be:ef:00:01", -60); dec.AllowAssoc {
		t.Fatal("expected 1st 2.4GHz assoc steered to 5GHz")
	}
	if dec := bs.Evaluate2GHzAssoc("de:ad:be:ef:00:01", -60); dec.AllowAssoc {
		t.Fatal("expected 2nd 2.4GHz assoc steered to 5GHz")
	}
	if dec := bs.Evaluate2GHzAssoc("de:ad:be:ef:00:01", -60); !dec.AllowAssoc {
		t.Fatal("expected 3rd attempt to fall back gracefully to 2.4GHz")
	}

	// 802.11v BTM recommends stronger neighbor when RSSI drops to -78 dBm.
	btm := RecommendBTM("aa:bb:cc:01:01:01", -78, []NeighborCandidate{
		{APMAC: "aa:bb:cc:01:01:02", Channel: 44, RSSIDBm: -62},
	})
	if !btm.ShouldRoam || btm.TargetAP != "aa:bb:cc:01:01:02" {
		t.Fatalf("expected 802.11v BTM roam recommendation, got %+v", btm)
	}

	// Mesh self-heal test: direct link root<->west dies -> west automatically routes 2-hop via east!
	meshTree := SolveMeshTopology(aps, []MeshBackhaulLink{
		{FromMAC: "aa:bb:cc:01:01:01", ToMAC: "aa:bb:cc:01:01:02", RSSIDBm: -58, Alive: true},
		{FromMAC: "aa:bb:cc:01:01:01", ToMAC: "aa:bb:cc:01:01:03", RSSIDBm: -50, Alive: false}, // Dead direct link
		{FromMAC: "aa:bb:cc:01:01:02", ToMAC: "aa:bb:cc:01:01:03", RSSIDBm: -64, Alive: true},
	}, 4)
	for _, node := range meshTree {
		if node.APName == "ap-west" {
			if node.ParentMAC != "aa:bb:cc:01:01:02" || node.HopCount != 2 {
				t.Fatalf("expected ap-west to self-heal via ap-east (2 hops), got %+v", node)
			}
		}
	}
}
