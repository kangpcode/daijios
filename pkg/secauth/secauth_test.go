// SPDX-License-Identifier: Apache-2.0
package secauth

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestRBACLeastPrivilege(t *testing.T) {
	rbac := NewDefaultRBACPolicy(true)

	if err := rbac.Authorize("superadmin", PermSecurityKeys); err != nil {
		t.Fatalf("superadmin denied security:keys: %v", err)
	}
	if err := rbac.Authorize("netadmin", PermConfigCommit); err != nil {
		t.Fatalf("netadmin denied config:commit: %v", err)
	}
	// Privilege escalation checks:
	if err := rbac.Authorize("netadmin", PermConfigReadSecrets); !errors.Is(err, ErrForbidden) {
		t.Fatalf("netadmin should not read secrets, got %v", err)
	}
	if err := rbac.Authorize("operator", PermConfigWrite); !errors.Is(err, ErrForbidden) {
		t.Fatalf("operator should not write config, got %v", err)
	}
	if err := rbac.Authorize("readonly", PermAuditRead); !errors.Is(err, ErrForbidden) {
		t.Fatalf("readonly should not read audit, got %v", err)
	}
	if err := rbac.Authorize("guest", PermConfigRead); !errors.Is(err, ErrUnknownRole, ) {
		t.Fatalf("unknown role should fail, got %v", err)
	}
}

func TestTOTPVerifyAndAntiReplay(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewTOTPVerifier(1)
	now := time.Unix(1700000010, 0).UTC()

	code, err := verifier.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify("secadmin", secret, code, now); err != nil {
		t.Fatalf("valid TOTP failed: %v", err)
	}
	// Replay of the exact same OTP within the same 30s window must fail!
	if err := verifier.Verify("secadmin", secret, code, now.Add(5*time.Second)); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("expected anti-replay ErrInvalidTOTP, got %v", err)
	}
	// Next 30s window works cleanly.
	nextTime := now.Add(30 * time.Second)
	nextCode, _ := verifier.GenerateCode(secret, nextTime)
	if err := verifier.Verify("secadmin", secret, nextCode, nextTime); err != nil {
		t.Fatalf("next window TOTP failed: %v", err)
	}
}

func TestScopedTokenIssueVerifyAndRevoke(t *testing.T) {
	tm, err := NewTokenManager([]byte("DaijiOS-Test-HMAC-Key-2026"), 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0).UTC()
	tok, claims, err := tm.Issue("automation", "netadmin", []Permission{PermConfigRead, PermNetDiag}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tm.Verify(tok, PermConfigRead, now.Add(10*time.Minute)); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if _, err := tm.Verify(tok, PermConfigCommit, now.Add(10*time.Minute)); !errors.Is(err, ErrInsufficientScope) {
		t.Fatalf("expected ErrInsufficientScope, got %v", err)
	}
	// Tampered token rejected.
	if _, err := tm.Verify(tok+"X", PermConfigRead, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for tampered token, got %v", err)
	}
	// Expired token rejected.
	if _, err := tm.Verify(tok, PermConfigRead, now.Add(2*time.Hour)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for expired token, got %v", err)
	}
	// Revoked token rejected.
	tm.Revoke(claims.TokenID, claims.ExpiresAt)
	if _, err := tm.Verify(tok, PermConfigRead, now.Add(5*time.Minute)); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestBruteForceGuardAndWhitelist(t *testing.T) {
	guard := NewBruteForceGuard(BruteForcePolicy{
		Enabled:     true,
		MaxAttempts: 3,
		Window:      time.Minute,
		BanDuration: 10 * time.Minute,
		Whitelist:   []netip.Prefix{netip.MustParsePrefix("10.255.0.0/24")},
	})

	now := time.Unix(1700000000, 0)
	attacker := netip.MustParseAddr("198.51.100.99")
	adminIP := netip.MustParseAddr("10.255.0.5")

	// Whitelisted admin IP must never be banned even after repeated failures.
	for i := 0; i < 5; i++ {
		dec := guard.RecordFailure(adminIP, now)
		if dec.Banned {
			t.Fatal("whitelisted IP must never be banned")
		}
	}

	// Attacker gets banned on 3rd failure.
	for i := 0; i < 2; i++ {
		if dec := guard.RecordFailure(attacker, now.Add(time.Duration(i)*time.Second)); dec.Banned {
			t.Fatalf("banned prematurely on attempt %d", i+1)
		}
	}
	ban := guard.RecordFailure(attacker, now.Add(3*time.Second))
	if !ban.Banned || !ban.NewlyBanned || len(ban.NFTCmdArgs) == 0 {
		t.Fatalf("expected NewlyBanned decision on 3rd failure, got %+v", ban)
	}
	if !guard.IsBanned(attacker, now.Add(5*time.Minute)) {
		t.Fatal("attacker should remain banned at +5m")
	}
	if guard.IsBanned(attacker, now.Add(11*time.Minute)) {
		t.Fatal("attacker ban should expire after 10m")
	}
}
