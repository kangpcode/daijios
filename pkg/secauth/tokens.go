// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package secauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// TokenClaims describes a DaijiOS scoped API token payload.
type TokenClaims struct {
	TokenID   string       `json:"jti"`
	Subject   string       `json:"sub"`
	Role      string       `json:"role"`
	Scopes    []Permission `json:"scopes"`
	IssuedAt  int64        `json:"iat"`
	ExpiresAt int64        `json:"exp"`
}

// TokenManager issues, verifies, and revokes HMAC-SHA256 signed scoped API tokens.
type TokenManager struct {
	mu      sync.RWMutex
	secret  []byte
	maxTTL  time.Duration
	revoked map[string]int64
}

func NewTokenManager(signingSecret []byte, maxTTL time.Duration) (*TokenManager, error) {
	if len(signingSecret) < 16 {
		return nil, errors.New("token signing secret must be at least 16 bytes")
	}
	if maxTTL <= 0 {
		maxTTL = 24 * time.Hour
	}
	secCopy := make([]byte, len(signingSecret))
	copy(secCopy, signingSecret)
	return &TokenManager{
		secret:  secCopy,
		maxTTL:  maxTTL,
		revoked: make(map[string]int64),
	}, nil
}

// Issue creates a signed scoped bearer token bounded by maxTTL.
func (tm *TokenManager) Issue(sub, role string, scopes []Permission, ttl time.Duration, now time.Time) (string, TokenClaims, error) {
	if sub == "" || role == "" || len(scopes) == 0 {
		return "", TokenClaims{}, errors.New("subject, role, and non-empty scopes are required")
	}
	if ttl <= 0 || ttl > tm.maxTTL {
		ttl = tm.maxTTL
	}
	var jtiBuf [12]byte
	_, _ = rand.Read(jtiBuf[:])
	claims := TokenClaims{
		TokenID:   hex.EncodeToString(jtiBuf[:]),
		Subject:   sub,
		Role:      role,
		Scopes:    append([]Permission(nil), scopes...),
		IssuedAt:  now.UTC().Unix(),
		ExpiresAt: now.UTC().Add(ttl).Unix(),
	}
	payloadRaw, err := json.Marshal(claims)
	if err != nil {
		return "", TokenClaims{}, err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadRaw)
	sig := tm.sign(payloadB64)
	return "djt1." + payloadB64 + "." + base64.RawURLEncoding.EncodeToString(sig), claims, nil
}

// Revoke blacklists a TokenID until its natural expiration.
func (tm *TokenManager) Revoke(jti string, expUnix int64) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.revoked[jti] = expUnix
}

// Verify validates signature, expiration, revocation, and required permission scope.
func (tm *TokenManager) Verify(token string, requiredScope Permission, now time.Time) (*TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "djt1" {
		return nil, ErrInvalidToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}
	expectedSig := tm.sign(parts[1])
	if !hmac.Equal(sig, expectedSig) {
		return nil, ErrInvalidToken
	}
	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims TokenClaims
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	if now.UTC().Unix() >= claims.ExpiresAt {
		return nil, fmt.Errorf("%w: token expired", ErrInvalidToken)
	}

	tm.mu.RLock()
	_, isRevoked := tm.revoked[claims.TokenID]
	tm.mu.RUnlock()
	if isRevoked {
		return nil, ErrTokenRevoked
	}

	if requiredScope != "" {
		hasScope := false
		for _, sc := range claims.Scopes {
			if sc == requiredScope {
				hasScope = true
				break
			}
		}
		if !hasScope {
			return nil, fmt.Errorf("%w: missing %q", ErrInsufficientScope, requiredScope)
		}
	}
	return &claims, nil
}

func (tm *TokenManager) sign(payload string) []byte {
	mac := hmac.New(sha256.New, tm.secret)
	_, _ = mac.Write([]byte("djt1." + payload))
	return mac.Sum(nil)
}
