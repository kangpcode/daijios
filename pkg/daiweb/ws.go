// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package daiweb implements DaiWeb, the embedded zero-dependency Web UI,
// RFC 6455 WebSocket telemetry & browser CLI terminal, interactive topology,
// and schema-validated setup wizards for DaijiOS.
package daiweb

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0C85B11E"

const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

const maxWSFrameBytes = 64 * 1024

// WSConn represents one upgraded RFC 6455 server-side WebSocket connection.
type WSConn struct {
	conn net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex
}

// UpgradeWebSocket performs an RFC 6455 HTTP/1.1 Upgrade handshake cleanly.
func UpgradeWebSocket(w http.ResponseWriter, r *http.Request) (*WSConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("missing Upgrade: websocket header")
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return nil, errors.New("missing Connection: Upgrade header")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key header")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("http.Hijacker unsupported")
	}

	h := sha1.Sum([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(h[:])

	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijack failed: %w", err)
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := brw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &WSConn{conn: conn, br: brw.Reader}, nil
}

// ReadText reads the next client text message, handling Ping/Pong and Close frames.
func (ws *WSConn) ReadText() (string, error) {
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(ws.br, hdr[:]); err != nil {
			return "", err
		}
		opcode := hdr[0] & 0x0F
		masked := (hdr[1] & 0x80) != 0
		if !masked {
			_ = ws.WriteClose(1002, "client frames must be masked")
			return "", errors.New("unmasked client websocket frame")
		}
		plen := uint64(hdr[1] & 0x7F)
		switch plen {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(ws.br, ext[:]); err != nil {
				return "", err
			}
			plen = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(ws.br, ext[:]); err != nil {
				return "", err
			}
			plen = binary.BigEndian.Uint64(ext[:])
		}
		if plen > maxWSFrameBytes {
			_ = ws.WriteClose(1009, "frame too large")
			return "", fmt.Errorf("websocket frame %d exceeds limit %d", plen, maxWSFrameBytes)
		}

		var maskKey [4]byte
		if _, err := io.ReadFull(ws.br, maskKey[:]); err != nil {
			return "", err
		}
		payload := make([]byte, plen)
		if plen > 0 {
			if _, err := io.ReadFull(ws.br, payload); err != nil {
				return "", err
			}
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}

		switch opcode {
		case wsOpText, wsOpContinuation, wsOpBinary:
			return string(payload), nil
		case wsOpPing:
			_ = ws.writeFrame(wsOpPong, payload)
		case wsOpPong:
			continue
		case wsOpClose:
			_ = ws.writeFrame(wsOpClose, nil)
			return "", io.EOF
		default:
			_ = ws.WriteClose(1003, "unsupported opcode")
			return "", fmt.Errorf("unsupported websocket opcode %d", opcode)
		}
	}
}

// WriteText sends one unmasked server text frame.
func (ws *WSConn) WriteText(msg string) error {
	return ws.writeFrame(wsOpText, []byte(msg))
}

// WriteJSON marshals v and sends it as a text frame.
func (ws *WSConn) WriteJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return ws.writeFrame(wsOpText, b)
}

// WriteClose sends an RFC 6455 Close control frame.
func (ws *WSConn) WriteClose(code uint16, reason string) error {
	buf := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(buf[:2], code)
	copy(buf[2:], reason)
	return ws.writeFrame(wsOpClose, buf)
}

func (ws *WSConn) writeFrame(opcode byte, payload []byte) error {
	ws.wmu.Lock()
	defer ws.wmu.Unlock()

	var hdr [10]byte
	hdr[0] = 0x80 | opcode
	n := len(payload)
	hdrLen := 2
	switch {
	case n < 126:
		hdr[1] = byte(n)
	case n <= 65535:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		hdrLen = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		hdrLen = 10
	}
	if _, err := ws.conn.Write(hdr[:hdrLen]); err != nil {
		return err
	}
	if n > 0 {
		if _, err := ws.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the underlying socket.
func (ws *WSConn) Close() error {
	return ws.conn.Close()
}
