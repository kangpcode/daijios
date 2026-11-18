// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package ispengine implements runtime ISP core services: RFC 2865/2866/5176
// RADIUS/CoA wire packets, PPPoE/IPoE/Hotspot subscriber & voucher session management
// (with MAC binding, expired-user isolation, accounting), and Multi-WAN recursive/netwatch failover.
package ispengine

import (
	"bytes"
	"context"
	"crypto/md5" // Required solely by IETF RFC 2865/5176 wire protocol compatibility
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

const (
	CodeAccessRequest      uint8 = 1
	CodeAccessAccept       uint8 = 2
	CodeAccessReject       uint8 = 3
	CodeAccountingRequest  uint8 = 4
	CodeAccountingResponse uint8 = 5
	CodeDisconnectRequest  uint8 = 40
	CodeDisconnectACK      uint8 = 41
	CodeDisconnectNAK      uint8 = 42
	CodeCoARequest         uint8 = 43
	CodeCoAACK             uint8 = 44
	CodeCoANAK             uint8 = 45
)

const (
	AttrUserName         uint8 = 1
	AttrUserPassword     uint8 = 2
	AttrNASIPAddress     uint8 = 4
	AttrFilterID         uint8 = 11
	AttrVendorSpecific   uint8 = 26
	AttrSessionTimeout   uint8 = 27
	AttrIdleTimeout      uint8 = 28
	AttrCallingStationID uint8 = 31
	AttrNASIdentifier    uint8 = 32
	AttrAcctStatusType   uint8 = 40
	AttrAcctInputOctets  uint8 = 42
	AttrAcctOutputOctets uint8 = 43
	AttrAcctSessionID    uint8 = 44
	AttrAcctSessionTime  uint8 = 46

	DaijiVendorID      uint32 = 65100
	DaijiAttrRateLimit uint8  = 1
)

type RADIUSAttr struct {
	Type  uint8
	Value []byte
}

// RADIUSPacket models an RFC 2865 / RFC 5176 binary RADIUS datagram.
type RADIUSPacket struct {
	Code          uint8
	Identifier    uint8
	Authenticator [16]byte
	Attrs         []RADIUSAttr
}

func (p *RADIUSPacket) AddString(t uint8, s string) {
	p.Attrs = append(p.Attrs, RADIUSAttr{Type: t, Value: []byte(s)})
}

func (p *RADIUSPacket) AddUint32(t uint8, v uint32) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	p.Attrs = append(p.Attrs, RADIUSAttr{Type: t, Value: buf[:]})
}

func (p *RADIUSPacket) AddIPv4(t uint8, ip netip.Addr) {
	if ip.Is4() {
		a4 := ip.As4()
		p.Attrs = append(p.Attrs, RADIUSAttr{Type: t, Value: a4[:]})
	}
}

func (p *RADIUSPacket) AddDaijiRateLimit(expr string) {
	// RFC 2865 VSA: 4-byte VendorID + 1-byte VendorType + 1-byte VendorLength + Value.
	val := []byte(expr)
	buf := make([]byte, 6+len(val))
	binary.BigEndian.PutUint32(buf[:4], DaijiVendorID)
	buf[4] = DaijiAttrRateLimit
	buf[5] = uint8(2 + len(val))
	copy(buf[6:], val)
	p.Attrs = append(p.Attrs, RADIUSAttr{Type: AttrVendorSpecific, Value: buf})
}

func (p *RADIUSPacket) GetString(t uint8) string {
	for _, a := range p.Attrs {
		if a.Type == t {
			return string(a.Value)
		}
	}
	return ""
}

func (p *RADIUSPacket) GetDaijiRateLimit() string {
	for _, a := range p.Attrs {
		if a.Type == AttrVendorSpecific && len(a.Value) >= 6 {
			vid := binary.BigEndian.Uint32(a.Value[:4])
			if vid == DaijiVendorID && a.Value[4] == DaijiAttrRateLimit {
				return string(a.Value[6:])
			}
		}
	}
	return ""
}

// EncodePasswordPAP obscures password per RFC 2865 section 5.2.
func EncodePasswordPAP(password string, reqAuth [16]byte, secret []byte) []byte {
	pw := []byte(password)
	paddedLen := ((len(pw) + 15) / 16) * 16
	if paddedLen == 0 {
		paddedLen = 16
	}
	out := make([]byte, paddedLen)
	copy(out, pw)

	prev := reqAuth[:]
	for i := 0; i < paddedLen; i += 16 {
		h := md5.New()
		_, _ = h.Write(secret)
		_, _ = h.Write(prev)
		pad := h.Sum(nil)
		for j := 0; j < 16; j++ {
			out[i+j] ^= pad[j]
		}
		prev = out[i : i+16]
	}
	return out
}

// DecodePasswordPAP recovers a PAP password obfuscated per RFC 2865 section 5.2.
func DecodePasswordPAP(enc []byte, reqAuth [16]byte, secret []byte) string {
	if len(enc) == 0 || len(enc)%16 != 0 {
		return ""
	}
	out := make([]byte, len(enc))
	prev := reqAuth[:]
	for i := 0; i < len(enc); i += 16 {
		h := md5.New()
		_, _ = h.Write(secret)
		_, _ = h.Write(prev)
		pad := h.Sum(nil)
		for j := 0; j < 16; j++ {
			out[i+j] = enc[i+j] ^ pad[j]
		}
		prev = enc[i : i+16]
	}
	return strings.TrimRight(string(out), "\x00")
}

// MarshalWire serializes a RADIUS packet into wire bytes.
func (p *RADIUSPacket) MarshalWire() ([]byte, error) {
	var attrBuf bytes.Buffer
	for _, a := range p.Attrs {
		if len(a.Value) > 253 {
			return nil, fmt.Errorf("attribute %d exceeds 253 bytes", a.Type)
		}
		attrBuf.WriteByte(a.Type)
		attrBuf.WriteByte(uint8(len(a.Value) + 2))
		attrBuf.Write(a.Value)
	}
	totalLen := 20 + attrBuf.Len()
	if totalLen > 4096 {
		return nil, errors.New("radius packet exceeds 4096 bytes")
	}
	raw := make([]byte, totalLen)
	raw[0] = p.Code
	raw[1] = p.Identifier
	binary.BigEndian.PutUint16(raw[2:4], uint16(totalLen))
	copy(raw[4:20], p.Authenticator[:])
	copy(raw[20:], attrBuf.Bytes())
	return raw, nil
}

// ParseRADIUSWire decodes wire bytes into a RADIUSPacket.
func ParseRADIUSWire(raw []byte) (*RADIUSPacket, error) {
	if len(raw) < 20 {
		return nil, errors.New("radius packet shorter than 20 bytes")
	}
	pktLen := int(binary.BigEndian.Uint16(raw[2:4]))
	if pktLen < 20 || pktLen > len(raw) {
		return nil, fmt.Errorf("invalid radius packet length %d (buf %d)", pktLen, len(raw))
	}
	pkt := &RADIUSPacket{
		Code:       raw[0],
		Identifier: raw[1],
	}
	copy(pkt.Authenticator[:], raw[4:20])
	pos := 20
	for pos < pktLen {
		if pos+2 > pktLen {
			return nil, errors.New("truncated radius attribute header")
		}
		aType := raw[pos]
		aLen := int(raw[pos+1])
		if aLen < 2 || pos+aLen > pktLen {
			return nil, fmt.Errorf("invalid radius attribute length %d", aLen)
		}
		val := make([]byte, aLen-2)
		copy(val, raw[pos+2:pos+aLen])
		pkt.Attrs = append(pkt.Attrs, RADIUSAttr{Type: aType, Value: val})
		pos += aLen
	}
	return pkt, nil
}

// SignCoARequest signs an RFC 5176 CoA-Request / Disconnect-Request / Accounting-Request.
func SignCoARequest(p *RADIUSPacket, secret []byte) ([]byte, error) {
	p.Authenticator = [16]byte{}
	raw, err := p.MarshalWire()
	if err != nil {
		return nil, err
	}
	h := md5.New()
	_, _ = h.Write(raw)
	_, _ = h.Write(secret)
	sum := h.Sum(nil)
	copy(p.Authenticator[:], sum)
	copy(raw[4:20], sum)
	return raw, nil
}

// VerifyCoARequest verifies RFC 5176 request authenticator in constant time.
func VerifyCoARequest(raw []byte, secret []byte) (*RADIUSPacket, error) {
	pkt, err := ParseRADIUSWire(raw)
	if err != nil {
		return nil, err
	}
	pktLen := int(binary.BigEndian.Uint16(raw[2:4]))
	tmp := make([]byte, pktLen)
	copy(tmp, raw[:pktLen])
	var zeros [16]byte
	copy(tmp[4:20], zeros[:])
	h := md5.New()
	_, _ = h.Write(tmp)
	_, _ = h.Write(secret)
	expected := h.Sum(nil)
	if subtle.ConstantTimeCompare(raw[4:20], expected) != 1 {
		return nil, errors.New("radius request authenticator mismatch")
	}
	return pkt, nil
}

// SignResponse signs a RADIUS reply (Access-Accept / CoA-ACK / Disconnect-ACK) against reqAuth.
func SignResponse(resp *RADIUSPacket, reqAuth [16]byte, secret []byte) ([]byte, error) {
	resp.Authenticator = reqAuth
	raw, err := resp.MarshalWire()
	if err != nil {
		return nil, err
	}
	h := md5.New()
	_, _ = h.Write(raw)
	_, _ = h.Write(secret)
	sum := h.Sum(nil)
	copy(resp.Authenticator[:], sum)
	copy(raw[4:20], sum)
	return raw, nil
}

// NewRandomAuth generates a 16-byte random RADIUS Access-Request authenticator.
func NewRandomAuth() [16]byte {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return b
}

// CoAHandler handles validated incoming RFC 5176 CoA / Disconnect packets.
type CoAHandler func(req *RADIUSPacket) (ack bool, errMsg string)

// StartCoAServer starts a UDP RFC 5176 CoA/Disconnect listener until ctx is canceled.
func StartCoAServer(ctx context.Context, listenAddr string, secret []byte, handler CoAHandler) (net.Addr, error) {
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req, err := VerifyCoARequest(buf[:n], secret)
			if err != nil {
				continue
			}
			ack, _ := handler(req)
			resp := &RADIUSPacket{Identifier: req.Identifier}
			switch req.Code {
			case CodeDisconnectRequest:
				if ack {
					resp.Code = CodeDisconnectACK
				} else {
					resp.Code = CodeDisconnectNAK
				}
			default:
				if ack {
					resp.Code = CodeCoAACK
				} else {
					resp.Code = CodeCoANAK
				}
			}
			if wire, err := SignResponse(resp, req.Authenticator, secret); err == nil {
				_, _ = pc.WriteTo(wire, peer)
			}
		}
	}()
	return pc.LocalAddr(), nil
}
