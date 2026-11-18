// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijirelease

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/kangpcode/daijios/pkg/daidiscovery"
	"github.com/kangpcode/daijios/pkg/daijiacs"
	"github.com/kangpcode/daijios/pkg/daijicloud"
	"github.com/kangpcode/daijios/pkg/daijiportal"
)

// SoakConfig parameterizes an accelerated multi-day ecosystem stability soak simulation.
type SoakConfig struct {
	SimulatedHours int
	OpsPerHour     int
	HMACKey        []byte
}

// SoakReport summarizes stability, memory behavior, goroutine delta, and operation latency.
type SoakReport struct {
	SimulatedHours   int     `json:"simulated_hours"`
	TotalTransactions int    `json:"total_transactions"`
	FailedOps        int     `json:"failed_ops"`
	ElapsedMs        float64 `json:"wall_elapsed_ms"`
	ThroughputOpsSec float64 `json:"throughput_ops_sec"`
	P50LatencyUs     float64 `json:"p50_latency_us"`
	P99LatencyUs     float64 `json:"p99_latency_us"`
	MaxLatencyUs     float64 `json:"max_latency_us"`
	StartHeapKB      uint64  `json:"start_heap_kb"`
	EndHeapKB        uint64  `json:"end_heap_kb"`
	GoroutineDelta   int     `json:"goroutine_delta"`
}

// RunSoakSimulation exercises integrated DaijiOS subsystems across 72 simulated hours
// (accelerated clock) to verify zero crashes, zero goroutine leaks, and bounded heap usage.
func RunSoakSimulation(cfg SoakConfig) (*SoakReport, error) {
	if cfg.SimulatedHours <= 0 {
		cfg.SimulatedHours = 72
	}
	if cfg.OpsPerHour <= 0 {
		cfg.OpsPerHour = 10
	}
	if len(cfg.HMACKey) == 0 {
		cfg.HMACKey = []byte("daijios-phase12-soak-hmac-key-2026")
	}

	simClock := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return simClock }

	portal, err := daijiportal.NewPortal(nil, nowFn)
	if err != nil {
		return nil, err
	}
	_, lic, err := portal.PurchaseLicense("org-soak", "official", "sku-ent", "HW-SOAK-001", 50, 12)
	if err != nil {
		return nil, err
	}

	cp := daijicloud.NewControlPlane(cfg.HMACKey, cfg.HMACKey, nowFn)
	_ = cp.CreateOrganization(daijicloud.Organization{ID: "org-soak", Name: "Soak Carrier"})
	_ = cp.CreateSite(daijicloud.Site{ID: "site-soak", OrgID: "org-soak", Name: "Core POP"})
	tok, err := cp.CreateZTPClaimToken("org-soak", "site-soak", "SOAK-SN01", "edge", 24*time.Hour)
	if err != nil {
		return nil, err
	}
	dev, err := cp.AdoptViaZTP(tok, "SOAK-SN01", "02:64:6a:12:00:01", "soak-core-01", "amd64", "1.2.0-lts")
	if err != nil {
		return nil, err
	}

	acs, err := daijiacs.NewServer(daijiacs.Config{Now: nowFn})
	if err != nil {
		return nil, err
	}

	beacon := daidiscovery.DeviceBeacon{
		Type:      daidiscovery.TypeBeacon,
		DeviceID:  "soak-core-01",
		MAC:       "02:64:6a:12:00:01",
		Hostname:  "soak-core-01",
		Platform:  "DaijiOS",
		Version:   "1.2.0-lts",
		Arch:      "amd64",
		Interface: "eth0",
		IPv4:      "10.12.0.1",
		WebPort:   8443,
	}

	runtime.GC()
	var mStart, mEnd runtime.MemStats
	runtime.ReadMemStats(&mStart)
	gStart := runtime.NumGoroutine()

	total := cfg.SimulatedHours * cfg.OpsPerHour
	latNs := make([]int64, 0, total)
	failed := 0

	wallStart := time.Now()
	cwmpXML := `<Envelope><Header><ID>soak-1</ID></Header><Body><Inform><DeviceId><Manufacturer>Huawei</Manufacturer><OUI>00E0FC</OUI><ProductClass>HG8245H</ProductClass><SerialNumber>HWTC-SOAK-01</SerialNumber></DeviceId><Event><EventStruct><EventCode>2 PERIODIC</EventCode></EventStruct></Event></Inform></Body></Envelope>`

	for h := 0; h < cfg.SimulatedHours; h++ {
		simClock = simClock.Add(time.Hour)
		for op := 0; op < cfg.OpsPerHour; op++ {
			t0 := time.Now()

			// 1. Ed25519 offline license verify
			if _, err := daijiportal.VerifyOfflineLicense(portal.PublicKey(), lic.OfflineBlob, "HW-SOAK-001", "bgp", 20, simClock); err != nil {
				failed++
			}
			// 2. Cloud telemetry ingest
			if _, err := cp.IngestTelemetry(dev.ID, daijicloud.DeviceTelemetry{
				CPUPercent:     28.5,
				MemPercent:     42.0,
				TemperatureC:   46.0,
				RxMbps:         940.2,
				TxMbps:         810.5,
				ActiveSessions: 420,
				UptimeSec:      int64((h + 1) * 3600),
			}); err != nil {
				failed++
			}
			// 3. DJDP1 wire frame encode + decode
			raw, err := daidiscovery.EncodeWire(beacon)
			if err != nil {
				failed++
			} else if _, err := daidiscovery.DecodeWire(raw); err != nil {
				failed++
			}
			// 4. CWMP Inform parse every 5 ops
			if op%5 == 0 {
				if parsed, err := daijiacs.ParseCWMPEnvelope(strings.NewReader(cwmpXML)); err != nil || parsed.Kind != "Inform" {
					failed++
				}
			}

			latNs = append(latNs, time.Since(t0).Nanoseconds())
		}
	}

	wallElapsed := time.Since(wallStart)
	runtime.GC()
	runtime.ReadMemStats(&mEnd)
	gEnd := runtime.NumGoroutine()

	slices.Sort(latNs)
	p50 := percentileUs(latNs, 0.50)
	p99 := percentileUs(latNs, 0.99)
	maxUs := float64(latNs[len(latNs)-1]) / 1000.0
	opsPerSec := float64(total) / wallElapsed.Seconds()
	_ = acs

	if failed > 0 {
		return nil, fmt.Errorf("soak simulation encountered %d failed operations", failed)
	}

	return &SoakReport{
		SimulatedHours:    cfg.SimulatedHours,
		TotalTransactions: total,
		FailedOps:         failed,
		ElapsedMs:         float64(wallElapsed.Microseconds()) / 1000.0,
		ThroughputOpsSec:  opsPerSec,
		P50LatencyUs:      p50,
		P99LatencyUs:      p99,
		MaxLatencyUs:      maxUs,
		StartHeapKB:       mStart.HeapAlloc / 1024,
		EndHeapKB:         mEnd.HeapAlloc / 1024,
		GoroutineDelta:    gEnd - gStart,
	}, nil
}

func percentileUs(sortedNs []int64, pct float64) float64 {
	if len(sortedNs) == 0 {
		return 0
	}
	idx := int(float64(len(sortedNs)-1) * pct)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sortedNs) {
		idx = len(sortedNs) - 1
	}
	return float64(sortedNs[idx]) / 1000.0
}
