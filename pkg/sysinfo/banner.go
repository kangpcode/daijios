// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

// Package sysinfo provides canonical DaijiOS identity, branding, boot banner,
// and hardware/build profile metadata.
package sysinfo

import (
	"fmt"
	"runtime"
	"strings"
)

const (
	// BrandBanner is the mandatory official branding string for DaijiOS.
	BrandBanner = "DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)"
	ProductName = "DaijiOS"
	Author      = "kangpcode (Dhafa Nazula Permadi)"
)

// Version is overridden at build time via -ldflags.
var Version = "0.1.0-phase0"

// BuildProfile identifies the target image variant.
type BuildProfile string

const (
	ProfileAppliance BuildProfile = "appliance"
	ProfileCHRVM     BuildProfile = "chr-vm"
	ProfileEmbedded  BuildProfile = "embedded"
)

// AboutInfo summarizes OS metadata for CLI `show version`, Web UI, and API `/system/about`.
type AboutInfo struct {
	Product      string       `json:"product"`
	BrandBanner  string       `json:"brand_banner"`
	Author       string       `json:"author"`
	Version      string       `json:"version"`
	Architecture string       `json:"architecture"`
	OS           string       `json:"os"`
	Profile      BuildProfile `json:"profile"`
	ActiveSlot   string       `json:"active_slot"`
	SafeMode     bool         `json:"safe_mode"`
}

// About returns structured DaijiOS build and runtime metadata.
func About(profile BuildProfile, activeSlot string, safeMode bool) AboutInfo {
	if profile == "" {
		profile = ProfileAppliance
	}
	if activeSlot == "" {
		activeSlot = "A"
	}
	return AboutInfo{
		Product:      ProductName,
		BrandBanner:  BrandBanner,
		Author:       Author,
		Version:      Version,
		Architecture: NormalizeArch(runtime.GOARCH),
		OS:           runtime.GOOS,
		Profile:      profile,
		ActiveSlot:   activeSlot,
		SafeMode:     safeMode,
	}
}

// NormalizeArch maps Go architectures to DaijiOS target hardware identifiers.
func NormalizeArch(goarch string) string {
	switch strings.ToLower(strings.TrimSpace(goarch)) {
	case "amd64", "x86_64":
		return "x86_64"
	case "arm64", "aarch64":
		return "arm64"
	case "arm", "armv7", "armv7l":
		return "armv7"
	case "mipsle":
		return "mipsel"
	case "mips":
		return "mips"
	case "mips64le":
		return "mips64el"
	default:
		return goarch
	}
}

// RenderBootBanner builds the console/SSH/serial boot banner containing the official branding.
func RenderBootBanner(hostname, arch, slot, version string, safeMode bool) string {
	if hostname == "" {
		hostname = "daiji-router"
	}
	if arch == "" {
		arch = NormalizeArch(runtime.GOARCH)
	}
	if slot == "" {
		slot = "A"
	}
	if version == "" {
		version = Version
	}
	modeTag := "NORMAL"
	if safeMode {
		modeTag = "SAFE-MODE (AUTO-RECOVERY ACTIVE)"
	}
	return fmt.Sprintf(
		"========================================================================\n"+
			"  %s\n"+
			"  Host: %-20s | Version: %-16s | Arch: %s\n"+
			"  Boot Slot: %-15s | Mode: %s\n"+
			"========================================================================\n",
		BrandBanner, hostname, version, arch, slot, modeTag,
	)
}
