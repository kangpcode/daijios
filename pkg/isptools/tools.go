// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package isptools implements Phase 3 diagnostics & telemetry utilities:
// injection-safe ping/traceroute argument builders, Torch-like live flow
// aggregator, libpcap binary packet sniffer writer, and TCP bandwidth test.
package isptools

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"
)

var validHostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

// ValidateProbeTarget rejects shell metacharacters, flags starting with '-', and invalid targets.
func ValidateProbeTarget(target string) error {
	if target == "" || target[0] == '-' {
		return fmt.Errorf("invalid probe target %q", target)
	}
	if _, err := netip.ParseAddr(target); err == nil {
		return nil
	}
	if !validHostRe.MatchString(target) {
		return fmt.Errorf("invalid IP or RFC 1123 hostname %q", target)
	}
	return nil
}

// PingArgs builds strict argv-only arguments for system ping (never via shell).
func PingArgs(target, srcIface string, count int, timeoutSec int) ([]string, error) {
	if err := ValidateProbeTarget(target); err != nil {
		return nil, err
	}
	if count <= 0 || count > 100 {
		count = 4
	}
	if timeoutSec <= 0 || timeoutSec > 30 {
		timeoutSec = 2
	}
	args := []string{"-c", strconv.Itoa(count), "-W", strconv.Itoa(timeoutSec)}
	if srcIface != "" {
		args = append(args, "-I", srcIface)
	}
	args = append(args, target)
	return args, nil
}

// TracerouteArgs builds strict argv-only arguments for traceroute.
func TracerouteArgs(target string, maxHops int) ([]string, error) {
	if err := ValidateProbeTarget(target); err != nil {
		return nil, err
	}
	if maxHops <= 0 || maxHops > 64 {
		maxHops = 30
	}
	return []string{"-n", "-m", strconv.Itoa(maxHops), target}, nil
}

// FlowSample captures one observed packet metadata record for Torch & PCAP sniffer.
type FlowSample struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	Protocol  string
	SrcPort   uint16
	DstPort   uint16
	Bytes     uint64
	Tx        bool
	RawFrame  []byte
}

// TorchRow summarizes aggregated real-time flow rates per tuple.
type TorchRow struct {
	SrcIP    string  `json:"src_ip"`
	DstIP    string  `json:"dst_ip"`
	Protocol string  `json:"protocol"`
	SrcPort  uint16  `json:"src_port"`
	DstPort  uint16  `json:"dst_port"`
	TxBytes  uint64  `json:"tx_bytes"`
	RxBytes  uint64  `json:"rx_bytes"`
	TxPkts   uint64  `json:"tx_pkts"`
	RxPkts   uint64  `json:"rx_pkts"`
	TotalBps float64 `json:"total_bps"`
}

// TorchAggregator provides MikroTik Torch-like live traffic breakdown sorted by throughput.
type TorchAggregator struct {
	mu   sync.Mutex
	rows map[string]*TorchRow
}

func NewTorchAggregator() *TorchAggregator {
	return &TorchAggregator{rows: make(map[string]*TorchRow)}
}

func (t *TorchAggregator) Ingest(s FlowSample) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := fmt.Sprintf("%s:%d->%s:%d/%s", s.SrcIP, s.SrcPort, s.DstIP, s.DstPort, s.Protocol)
	row, ok := t.rows[key]
	if !ok {
		row = &TorchRow{
			SrcIP:    s.SrcIP,
			DstIP:    s.DstIP,
			Protocol: s.Protocol,
			SrcPort:  s.SrcPort,
			DstPort:  s.DstPort,
		}
		t.rows[key] = row
	}
	if s.Tx {
		row.TxBytes += s.Bytes
		row.TxPkts++
	} else {
		row.RxBytes += s.Bytes
		row.RxPkts++
	}
}

// Snapshot returns top flows ranked by total bandwidth (bps) over windowSec.
func (t *TorchAggregator) Snapshot(windowSec float64, limit int) []TorchRow {
	if windowSec <= 0 {
		windowSec = 1.0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]TorchRow, 0, len(t.rows))
	for _, r := range t.rows {
		cp := *r
		cp.TotalBps = float64((cp.TxBytes+cp.RxBytes)*8) / windowSec
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TotalBps != out[j].TotalBps {
			return out[i].TotalBps > out[j].TotalBps
		}
		return out[i].SrcIP < out[j].SrcIP
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// PacketFilter filters captured frames for PCAP export.
type PacketFilter struct {
	Protocol string
	Port     uint16
	MaxPkts  int
}

// WritePCAP writes filtered packets in standard little-endian libpcap format (magic 0xa1b2c3d4).
func WritePCAP(w io.Writer, samples []FlowSample, filter PacketFilter) (int, error) {
	// 24-byte libpcap global header (LINKTYPE_ETHERNET = 1, snaplen = 65535).
	var gh [24]byte
	binary.LittleEndian.PutUint32(gh[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(gh[4:6], 2)
	binary.LittleEndian.PutUint16(gh[6:8], 4)
	binary.LittleEndian.PutUint32(gh[16:20], 65535)
	binary.LittleEndian.PutUint32(gh[20:24], 1)
	if _, err := w.Write(gh[:]); err != nil {
		return 0, err
	}

	written := 0
	for _, s := range samples {
		if filter.Protocol != "" && s.Protocol != filter.Protocol {
			continue
		}
		if filter.Port > 0 && s.SrcPort != filter.Port && s.DstPort != filter.Port {
			continue
		}
		if filter.MaxPkts > 0 && written >= filter.MaxPkts {
			break
		}
		frame := s.RawFrame
		if len(frame) == 0 {
			continue
		}
		if len(frame) > 65535 {
			frame = frame[:65535]
		}
		var ph [16]byte
		ts := s.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		binary.LittleEndian.PutUint32(ph[0:4], uint32(ts.Unix()))
		binary.LittleEndian.PutUint32(ph[4:8], uint32(ts.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(ph[8:12], uint32(len(frame)))
		binary.LittleEndian.PutUint32(ph[12:16], uint32(len(frame)))
		if _, err := w.Write(ph[:]); err != nil {
			return written, err
		}
		if _, err := w.Write(frame); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// BandwidthResult summarizes measured throughput from a DaijiOS TCP bandwidth/speed test.
type BandwidthResult struct {
	BytesTransferred int64   `json:"bytes_transferred"`
	DurationMS       float64 `json:"duration_ms"`
	ThroughputMbps   float64 `json:"throughput_mbps"`
}

// RunLoopbackBandwidthTest runs an active TCP throughput server & client test of targetBytes.
func RunLoopbackBandwidthTest(ctx context.Context, targetBytes int64) (*BandwidthResult, error) {
	if targetBytes <= 0 {
		return nil, errors.New("targetBytes must be > 0")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()

	srvDone := make(chan int64, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvDone <- 0
			return
		}
		defer conn.Close()
		n, _ := io.Copy(io.Discard, conn)
		srvDone <- n
	}()

	var dialer net.Dialer
	c, err := dialer.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		return nil, err
	}

	chunk := make([]byte, 32*1024)
	start := time.Now()
	var sent int64
	for sent < targetBytes {
		rem := targetBytes - sent
		toWrite := int64(len(chunk))
		if rem < toWrite {
			toWrite = rem
		}
		n, err := c.Write(chunk[:toWrite])
		sent += int64(n)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	_ = c.Close()
	recvd := <-srvDone
	elapsed := time.Since(start)
	if elapsed <= 0 {
		elapsed = time.Nanosecond
	}
	mbps := (float64(recvd) * 8.0) / elapsed.Seconds() / 1_000_000.0
	return &BandwidthResult{
		BytesTransferred: recvd,
		DurationMS:       float64(elapsed.Microseconds()) / 1000.0,
		ThroughputMbps:   mbps,
	}, nil
}
