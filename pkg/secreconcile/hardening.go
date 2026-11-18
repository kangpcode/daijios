// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package secreconcile

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kangpcode/daijios/pkg/secplan"
)

// RenderSSHDHardening produces /etc/ssh/sshd_config.d/99-daiji.conf enforcing SSH hardening.
func RenderSSHDHardening(cfg *secplan.SecurityConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)\n")
	permitRoot := "no"
	if cfg.Security.SSHHardening.PermitRootLogin {
		permitRoot = "yes"
	}
	pwAuth := "no"
	if cfg.Management.SSH.PasswordAuth {
		pwAuth = "yes"
	}
	maxTries := cfg.Security.SSHHardening.MaxAuthTries
	if maxTries <= 0 {
		maxTries = 3
	}
	idle := cfg.Security.SSHHardening.IdleTimeoutSec
	if idle <= 0 {
		idle = 600
	}
	fmt.Fprintf(&b, "PermitRootLogin %s\n", permitRoot)
	fmt.Fprintf(&b, "PasswordAuthentication %s\n", pwAuth)
	fmt.Fprintf(&b, "PubkeyAuthentication yes\n")
	fmt.Fprintf(&b, "MaxAuthTries %d\n", maxTries)
	fmt.Fprintf(&b, "ClientAliveInterval %d\n", idle)
	fmt.Fprintf(&b, "ClientAliveCountMax 2\n")
	fmt.Fprintf(&b, "X11Forwarding no\nAllowTcpForwarding local\n")
	if len(cfg.Security.SSHHardening.AllowCiphers) > 0 {
		fmt.Fprintf(&b, "Ciphers %s\n", strings.Join(cfg.Security.SSHHardening.AllowCiphers, ","))
	}
	if len(cfg.Security.SSHHardening.AllowKex) > 0 {
		fmt.Fprintf(&b, "KexAlgorithms %s\n", strings.Join(cfg.Security.SSHHardening.AllowKex, ","))
	}
	return b.String()
}

// RenderDPIRulesJSON exports L7/DPI classification rules consumed by the DPI classifier hook.
func RenderDPIRulesJSON(cfg *secplan.SecurityConfig) ([]byte, error) {
	b, err := json.MarshalIndent(cfg.Firewall.L7DPI, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// HardeningSysctls returns kernel security sysctl knobs applied alongside firewall rules.
func HardeningSysctls(cfg *secplan.SecurityConfig) []string {
	synCookies := "1"
	if !cfg.Firewall.Conntrack.SYNFloodProtect {
		synCookies = "0"
	}
	knobs := []string{
		"net.ipv4.tcp_syncookies=" + synCookies,
		"net.ipv4.conf.all.accept_redirects=0",
		"net.ipv4.conf.all.send_redirects=0",
		"net.ipv4.conf.all.log_martians=1",
		"net.ipv6.conf.all.accept_redirects=0",
		"kernel.kptr_restrict=2",
		"kernel.dmesg_restrict=1",
	}
	if cfg.Firewall.Conntrack.MaxEntries > 0 {
		knobs = append(knobs, fmt.Sprintf("net.netfilter.nf_conntrack_max=%d", cfg.Firewall.Conntrack.MaxEntries))
	}
	if cfg.Firewall.Conntrack.TCPEstablishedTimeoutSec > 0 {
		knobs = append(knobs, fmt.Sprintf("net.netfilter.nf_conntrack_tcp_timeout_established=%d",
			cfg.Firewall.Conntrack.TCPEstablishedTimeoutSec))
	}
	return knobs
}
