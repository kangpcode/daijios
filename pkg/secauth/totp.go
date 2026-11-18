// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package secauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"
)

// TOTPVerifier verifies RFC 6238 6-digit TOTP codes with constant-time comparison
// and per-user anti-replay protection.
type TOTPVerifier struct {
	mu           sync.Mutex
	PeriodSec    int64
	WindowSkew   int
	lastUsedStep map[string]int64
}

func NewTOTPVerifier(windowSkew int) *TOTPVerifier {
	if windowSkew < 0 {
		windowSkew = 0
	}
	if windowSkew > 2 {
		windowSkew = 2
	}
	return &TOTPVerifier{
		PeriodSec:    30,
		WindowSkew:   windowSkew,
		lastUsedStep: make(map[string]int64),
	}
}

// GenerateSecret generates a random 160-bit Base32 TOTP shared secret.
func GenerateSecret() (string, error) {
	var raw [20]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]), nil
}

// GenerateCode computes the 6-digit RFC 6238 TOTP code for secretB32 at timestamp t.
func (v *TOTPVerifier) GenerateCode(secretB32 string, t time.Time) (string, error) {
	step := t.Unix() / v.PeriodSec
	return computeTOTP(secretB32, step)
}

// Verify checks code against secretB32 within +-WindowSkew steps and prevents code replay.
func (v *TOTPVerifier) Verify(username, secretB32, code string, now time.Time) error {
	if len(code) != 6 {
		return ErrInvalidTOTP
	}
	curStep := now.Unix() / v.PeriodSec

	v.mu.Lock()
	defer v.mu.Unlock()
	lastStep, seen := v.lastUsedStep[username]

	for delta := -int64(v.WindowSkew); delta <= int64(v.WindowSkew); delta++ {
		step := curStep + delta
		if seen && step <= lastStep {
			continue
		}
		expected, err := computeTOTP(secretB32, step)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			v.lastUsedStep[username] = step
			return nil
		}
	}
	return ErrInvalidTOTP
}

func computeTOTP(secretB32 string, step int64) (string, error) {
	clean := strings.ToUpper(strings.TrimSpace(strings.TrimRight(secretB32, "=")))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("invalid base32 secret: %w", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", binCode%1000000), nil
}
