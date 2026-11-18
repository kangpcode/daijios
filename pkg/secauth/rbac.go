// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package secauth implements runtime security enforcement primitives for DaijiOS:
// least-privilege RBAC, RFC 6238 TOTP 2FA with replay protection, HMAC-SHA256
// scoped API bearer tokens with revocation, and sliding-window brute-force defense.
package secauth

import (
	"errors"
	"fmt"
)

var (
	ErrForbidden      = errors.New("permission denied by RBAC policy")
	ErrUnknownRole    = errors.New("unknown RBAC role")
	ErrInvalidTOTP    = errors.New("invalid or replayed TOTP verification code")
	ErrInvalidToken   = errors.New("invalid or expired API bearer token")
	ErrTokenRevoked   = errors.New("API token has been revoked")
	ErrInsufficientScope = errors.New("API token lacks required scope")
)

type Permission string

const (
	PermConfigRead        Permission = "config:read"
	PermConfigWrite       Permission = "config:write"
	PermConfigCommit      Permission = "config:commit"
	PermConfigReadSecrets Permission = "config:read-secrets"
	PermSystemUpdate      Permission = "system:update"
	PermSystemReboot      Permission = "system:reboot"
	PermSecurityKeys      Permission = "security:keys"
	PermAuditRead         Permission = "audit:read"
	PermNetDiag           Permission = "net:diag"
)

var defaultRoleMatrix = map[string]map[Permission]bool{
	"superadmin": {
		PermConfigRead: true, PermConfigWrite: true, PermConfigCommit: true,
		PermConfigReadSecrets: true, PermSystemUpdate: true, PermSystemReboot: true,
		PermSecurityKeys: true, PermAuditRead: true, PermNetDiag: true,
	},
	"netadmin": {
		PermConfigRead: true, PermConfigWrite: true, PermConfigCommit: true,
		PermNetDiag: true, PermAuditRead: true,
	},
	"operator": {
		PermConfigRead: true, PermNetDiag: true,
	},
	"auditor": {
		PermConfigRead: true, PermAuditRead: true, PermNetDiag: true,
	},
	"readonly": {
		PermConfigRead: true,
	},
}

// RBACPolicy enforces least-privilege role authorization.
type RBACPolicy struct {
	Enforce bool
	Matrix  map[string]map[Permission]bool
}

// NewDefaultRBACPolicy creates the canonical DaijiOS least-privilege RBAC matrix.
func NewDefaultRBACPolicy(enforce bool) *RBACPolicy {
	return &RBACPolicy{
		Enforce: enforce,
		Matrix:  defaultRoleMatrix,
	}
}

// Authorize checks if role holds perm; returns ErrForbidden if denied.
func (p *RBACPolicy) Authorize(role string, perm Permission) error {
	if p != nil && !p.Enforce {
		return nil
	}
	matrix := defaultRoleMatrix
	if p != nil && p.Matrix != nil {
		matrix = p.Matrix
	}
	perms, ok := matrix[role]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownRole, role)
	}
	if !perms[perm] {
		return fmt.Errorf("%w: role %q cannot perform %q", ErrForbidden, role, perm)
	}
	return nil
}
