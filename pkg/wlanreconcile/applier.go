// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package wlanreconcile

import (
	"context"
	"fmt"

	"github.com/kangpcode/daijios/pkg/configengine"
	"github.com/kangpcode/daijios/pkg/netreconcile"
	"github.com/kangpcode/daijios/pkg/wlanplan"
)

// WLANApplier implements configengine.Applier for Phase 4 Wireless Controller & Mesh.
type WLANApplier struct {
	Driver netreconcile.SystemDriver
}

func (a *WLANApplier) Plan(_ context.Context, _, target map[string]any, _ []configengine.DiffEntry) error {
	return wlanplan.ValidateAllSemantic(target)
}

func (a *WLANApplier) Apply(ctx context.Context, target map[string]any, _ []configengine.DiffEntry) error {
	cfg, err := wlanplan.ParseConfig(target)
	if err != nil {
		return err
	}
	w := &cfg.Wireless

	if w.Controller.CountryCode != "" {
		_ = a.Driver.Exec(ctx, "iw", "reg", "set", w.Controller.CountryCode)
	}

	hostapdBytes := []byte(RenderHostapdConfig(w, false))
	if changed, err := a.Driver.WriteFile("/etc/hostapd/daiji.conf", hostapdBytes, 0o600); err != nil {
		return err
	} else if changed && w.Controller.Enabled {
		if err := a.Driver.ReloadService(ctx, "hostapd"); err != nil {
			return err
		}
	}

	meshBytes := []byte(RenderMeshConfig(w, false))
	if changed, err := a.Driver.WriteFile("/etc/wpa_supplicant/daiji-mesh.conf", meshBytes, 0o600); err != nil {
		return err
	} else if changed && w.Mesh.Enabled {
		if err := a.Driver.ReloadService(ctx, "wpa_supplicant-mesh"); err != nil {
			return err
		}
	}

	nftBytes := []byte(RenderWLANGuestNFT(w))
	if changed, err := a.Driver.WriteFile("/etc/nftables.d/daiji-wlan.nft", nftBytes, 0o600); err != nil {
		return err
	} else if changed {
		if err := a.Driver.Exec(ctx, "nft", "-f", "/etc/nftables.d/daiji-wlan.nft"); err != nil {
			return fmt.Errorf("apply wlan guest nftables: %w", err)
		}
	}

	return nil
}
