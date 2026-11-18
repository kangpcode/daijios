// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package daidiscovery implements the original DaijiOS L2/LAN Discovery Protocol (DJDP1)
// for MAC-address neighbor discovery by DaiDesk in offline/LAN-only mode, with
// HMAC-SHA256 beacon authentication to prevent spoofed device announcements.
package daidiscovery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kangpcode/daijios/pkg/sysinfo"
)

const (
	DefaultUDPPort   = 56780
	WireMagic        = "DJDP1\x00"
	MaxWireFrameSize = 2048
)

var (
	ErrInvalidFrame  = errors.New("invalid DJDP1 discovery frame")
	ErrBadBeaconHMAC = errors.New("discovery beacon HMAC verification failed")
)

// PacketType identifies discovery probes vs responses.
type PacketType string

const (
	TypeProbe  PacketType = "probe"
	TypeBeacon PacketType = "beacon"
)

// DeviceBeacon carries L2/LAN identity published by a DaijiOS node.
type DeviceBeacon struct {
	Type        PacketType `json:"type"`
	Protocol    string     `json:"protocol"`
	DeviceID    string     `json:"device_id"`
	MAC         string     `json:"mac"`
	Hostname    string     `json:"hostname"`
	Platform    string     `json:"platform"`
	Version     string     `json:"version"`
	Arch        string     `json:"arch"`
	Interface   string     `json:"interface"`
	IPv4        string     `json:"ipv4"`
	WebPort     int        `json:"web_port"`
	UptimeSec   int64      `json:"uptime_sec"`
	OfflineOnly bool       `json:"offline_lan_ready"`
	Timestamp   int64      `json:"ts"`
	HMAC        string     `json:"hmac,omitempty"`
}

// ComputeBeaconHMAC computes an authenticated HMAC-SHA256 tag over canonical device fields.
func ComputeBeaconHMAC(secret []byte, b DeviceBeacon) string {
	h := hmac.New(sha256.New, secret)
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%d|%d",
		b.Protocol, strings.ToLower(b.MAC), b.DeviceID, b.Hostname, b.IPv4, b.WebPort, b.Timestamp)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyBeaconHMAC checks beacon integrity when a shared cluster/discovery key is configured.
func VerifyBeaconHMAC(secret []byte, b DeviceBeacon) error {
	if len(secret) == 0 {
		return nil
	}
	if b.HMAC == "" {
		return ErrBadBeaconHMAC
	}
	expected := ComputeBeaconHMAC(secret, b)
	gotBytes, err := hex.DecodeString(b.HMAC)
	expBytes, _ := hex.DecodeString(expected)
	if err != nil || !hmac.Equal(gotBytes, expBytes) {
		return ErrBadBeaconHMAC
	}
	return nil
}

// EncodeWire serializes a DJDP1 discovery packet into a bounded binary envelope.
func EncodeWire(b DeviceBeacon) ([]byte, error) {
	if b.Protocol == "" {
		b.Protocol = "DJDP1"
	}
	payload, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	total := len(WireMagic) + 2 + len(payload)
	if total > MaxWireFrameSize {
		return nil, fmt.Errorf("%w: frame size %d exceeds %d", ErrInvalidFrame, total, MaxWireFrameSize)
	}
	buf := make([]byte, total)
	copy(buf, WireMagic)
	binary.BigEndian.PutUint16(buf[len(WireMagic):len(WireMagic)+2], uint16(len(payload)))
	copy(buf[len(WireMagic)+2:], payload)
	return buf, nil
}

// DecodeWire validates the DJDP1 header and decodes a DeviceBeacon.
func DecodeWire(raw []byte) (DeviceBeacon, error) {
	if len(raw) < len(WireMagic)+2 || len(raw) > MaxWireFrameSize {
		return DeviceBeacon{}, ErrInvalidFrame
	}
	if !bytes.Equal(raw[:len(WireMagic)], []byte(WireMagic)) {
		return DeviceBeacon{}, ErrInvalidFrame
	}
	n := int(binary.BigEndian.Uint16(raw[len(WireMagic) : len(WireMagic)+2]))
	if n <= 0 || len(WireMagic)+2+n > len(raw) {
		return DeviceBeacon{}, ErrInvalidFrame
	}
	var b DeviceBeacon
	if err := json.Unmarshal(raw[len(WireMagic)+2:len(WireMagic)+2+n], &b); err != nil {
		return DeviceBeacon{}, fmt.Errorf("%w: %v", ErrInvalidFrame, err)
	}
	if b.Protocol != "DJDP1" {
		return DeviceBeacon{}, ErrInvalidFrame
	}
	return b, nil
}

// CollectLocalMACs enumerates non-loopback interface MAC addresses and primary IPv4s.
func CollectLocalMACs() []DeviceBeacon {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []DeviceBeacon
	for _, ifc := range ifaces {
		if (ifc.Flags&net.FlagLoopback) != 0 || len(ifc.HardwareAddr) == 0 {
			continue
		}
		var ipStr string
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					ipStr = ipn.IP.To4().String()
					break
				}
			}
		}
		out = append(out, DeviceBeacon{
			Type:        TypeBeacon,
			Protocol:    "DJDP1",
			MAC:         ifc.HardwareAddr.String(),
			Interface:   ifc.Name,
			IPv4:        ipStr,
			Platform:    sysinfo.ProductName,
			Version:     sysinfo.Version,
			Arch:        sysinfo.NormalizeArch(runtime.GOARCH),
			OfflineOnly: true,
		})
	}
	return out
}

// Responder answers DJDP1 L2/LAN discovery probes over UDP.
type Responder struct {
	mu      sync.RWMutex
	Beacon  DeviceBeacon
	Secret  []byte
	BootAt  time.Time
	conn    net.PacketConn
	AddrStr string
}

// StartResponder binds a UDP listener (use ":0" in tests) and responds to DJDP1 probes until ctx cancels.
func StartResponder(ctx context.Context, listenAddr string, base DeviceBeacon, authSecret []byte) (*Responder, error) {
	if listenAddr == "" {
		listenAddr = fmt.Sprintf(":%d", DefaultUDPPort)
	}
	pc, err := net.ListenPacket("udp4", listenAddr)
	if err != nil {
		return nil, err
	}
	if base.Protocol == "" {
		base.Protocol = "DJDP1"
	}
	if base.Type == "" {
		base.Type = TypeBeacon
	}
	if base.Platform == "" {
		base.Platform = sysinfo.ProductName
	}
	if base.Version == "" {
		base.Version = sysinfo.Version
	}
	if base.Arch == "" {
		base.Arch = sysinfo.NormalizeArch(runtime.GOARCH)
	}
	if base.MAC == "" {
		if locals := CollectLocalMACs(); len(locals) > 0 {
			base.MAC = locals[0].MAC
			if base.Interface == "" {
				base.Interface = locals[0].Interface
			}
			if base.IPv4 == "" {
				base.IPv4 = locals[0].IPv4
			}
		} else {
			base.MAC = "02:64:6a:00:00:01"
		}
	}

	r := &Responder{
		Beacon:  base,
		Secret:  append([]byte(nil), authSecret...),
		BootAt:  time.Now(),
		conn:    pc,
		AddrStr: pc.LocalAddr().String(),
	}

	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	go r.serveLoop()
	return r, nil
}

func (r *Responder) serveLoop() {
	buf := make([]byte, MaxWireFrameSize)
	for {
		n, peer, err := r.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt, err := DecodeWire(buf[:n])
		if err != nil || pkt.Type != TypeProbe {
			continue
		}
		r.mu.RLock()
		b := r.Beacon
		b.Type = TypeBeacon
		b.OfflineOnly = true
		b.Timestamp = time.Now().UTC().Unix()
		b.UptimeSec = int64(time.Since(r.BootAt).Seconds())
		if len(r.Secret) > 0 {
			b.HMAC = ComputeBeaconHMAC(r.Secret, b)
		}
		r.mu.RUnlock()

		wire, err := EncodeWire(b)
		if err != nil {
			continue
		}
		_, _ = r.conn.WriteTo(wire, peer)
	}
}

// Stop closes the UDP responder socket.
func (r *Responder) Stop() error {
	if r.conn != nil {
		return r.conn.Close()
	}
	return nil
}

// ProbeTargets sends DJDP1 probes to target UDP addresses (e.g. "255.255.255.255:56780" or "127.0.0.1:<port>")
// and collects deduplicated beacons keyed by lowercase MAC address within timeout.
func ProbeTargets(targets []string, verifySecret []byte, timeout time.Duration) ([]DeviceBeacon, error) {
	if len(targets) == 0 {
		targets = []string{fmt.Sprintf("255.255.255.255:%d", DefaultUDPPort)}
	}
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, err
	}
	defer pc.Close()

	probeWire, err := EncodeWire(DeviceBeacon{
		Type:     TypeProbe,
		Protocol: "DJDP1",
	})
	if err != nil {
		return nil, err
	}

	for _, t := range targets {
		addr, err := net.ResolveUDPAddr("udp4", t)
		if err != nil {
			continue
		}
		_, _ = pc.WriteTo(probeWire, addr)
	}

	_ = pc.SetReadDeadline(time.Now().Add(timeout))
	found := make(map[string]DeviceBeacon)
	buf := make([]byte, MaxWireFrameSize)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		b, err := DecodeWire(buf[:n])
		if err != nil || b.Type != TypeBeacon {
			continue
		}
		if err := VerifyBeaconHMAC(verifySecret, b); err != nil {
			continue
		}
		key := strings.ToLower(b.MAC)
		if key == "" {
			key = b.DeviceID
		}
		found[key] = b
	}

	out := make([]DeviceBeacon, 0, len(found))
	for _, b := range found {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out, nil
}
