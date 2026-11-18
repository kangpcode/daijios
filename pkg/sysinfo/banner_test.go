// SPDX-License-Identifier: Apache-2.0
package sysinfo

import (
	"strings"
	"testing"
)

func TestBrandBannerAndRender(t *testing.T) {
	const expected = "DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)"
	if BrandBanner != expected {
		t.Fatalf("unexpected BrandBanner: got %q, want %q", BrandBanner, expected)
	}

	banner := RenderBootBanner("edge-jkt-01", "x86_64", "B", "0.1.0", false)
	if !strings.Contains(banner, expected) {
		t.Fatalf("rendered banner missing official brand string:\n%s", banner)
	}
	if !strings.Contains(banner, "edge-jkt-01") || !strings.Contains(banner, "NORMAL") {
		t.Fatalf("rendered banner missing host or mode:\n%s", banner)
	}

	safeBanner := RenderBootBanner("", "", "", "", true)
	if !strings.Contains(safeBanner, "SAFE-MODE") {
		t.Fatalf("safe-mode banner missing SAFE-MODE warning:\n%s", safeBanner)
	}
}

func TestNormalizeArchAndAbout(t *testing.T) {
	cases := map[string]string{
		"amd64":  "x86_64",
		"arm64":  "arm64",
		"arm":    "armv7",
		"mipsle": "mipsel",
	}
	for in, want := range cases {
		if got := NormalizeArch(in); got != want {
			t.Errorf("NormalizeArch(%q) = %q, want %q", in, got, want)
		}
	}

	about := About(ProfileCHRVM, "A", false)
	if about.BrandBanner != BrandBanner || about.Profile != ProfileCHRVM {
		t.Fatalf("unexpected AboutInfo: %+v", about)
	}
}
