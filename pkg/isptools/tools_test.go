// SPDX-License-Identifier: Apache-2.0
package isptools

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"
)

func TestPingInjectionGuardTorchAndPCAPAndBandwidthTest(t *testing.T) {
	// 1. Injection guard blocks shell tricks and flag injection.
	for _, bad := range []string{"8.8.8.8; rm -rf /", "-c 1 127.0.0.1", "host$(id)", ""} {
		if _, err := PingArgs(bad, "", 4, 2); err == nil {
			t.Errorf("PingArgs allowed unsafe target %q", bad)
		}
	}
	args, err := PingArgs("1.1.1.1", "eth0", 3, 2)
	if err != nil || len(args) != 7 || args[6] != "1.1.1.1" {
		t.Fatalf("unexpected PingArgs: %v err=%v", args, err)
	}

	// 2. Torch flow aggregation & sorting.
	torch := NewTorchAggregator()
	torch.Ingest(FlowSample{SrcIP: "100.64.0.10", DstIP: "1.1.1.1", Protocol: "udp", SrcPort: 50000, DstPort: 53, Bytes: 1200, Tx: true})
	torch.Ingest(FlowSample{SrcIP: "100.64.0.11", DstIP: "142.250.1.1", Protocol: "tcp", SrcPort: 44322, DstPort: 443, Bytes: 150000, Tx: false})
	snap := torch.Snapshot(1.0, 5)
	if len(snap) != 2 || snap[0].SrcIP != "100.64.0.11" {
		t.Fatalf("expected highest throughput flow first, got %+v", snap)
	}

	// 3. Valid PCAP binary header & filtering.
	var pcapBuf bytes.Buffer
	samples := []FlowSample{
		{Timestamp: time.Now(), Protocol: "tcp", DstPort: 443, RawFrame: make([]byte, 64)},
		{Timestamp: time.Now(), Protocol: "udp", DstPort: 53, RawFrame: make([]byte, 48)},
	}
	n, err := WritePCAP(&pcapBuf, samples, PacketFilter{Protocol: "tcp", Port: 443})
	if err != nil || n != 1 {
		t.Fatalf("WritePCAP unexpected count=%d err=%v", n, err)
	}
	if magic := binary.LittleEndian.Uint32(pcapBuf.Bytes()[:4]); magic != 0xa1b2c3d4 {
		t.Fatalf("invalid pcap magic %x", magic)
	}
	if gotLen := pcapBuf.Len(); gotLen != 24+16+64 {
		t.Fatalf("expected 104 pcap bytes, got %d", gotLen)
	}

	// 4. Real TCP socket bandwidth test over loopback.
	res, err := RunLoopbackBandwidthTest(context.Background(), 2*1024*1024)
	if err != nil {
		t.Fatalf("RunLoopbackBandwidthTest failed: %v", err)
	}
	if res.BytesTransferred != 2*1024*1024 || res.ThroughputMbps <= 0 {
		t.Fatalf("unexpected bandwidth result: %+v", res)
	}
}
