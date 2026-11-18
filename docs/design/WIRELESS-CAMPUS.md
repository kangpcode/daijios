# Desain Wireless & Campus Controller (FASE 4 — Gaya Operasional Reyee/Huawei AC)

## 1. Wireless Controller (`daiji-ac`) & Zero-Touch AP Onboarding
- **Manajemen Terpusat (`pkg/wlanctrl/ac.go`):** Mendukung kebijakan adopsi `manual`, `whitelist` (berbasis MAC terdaftar), maupun **`zero-touch-token`** berbasis verifikasi HMAC-SHA256 `(master_secret, mac|serial)` sehingga AP baru langsung masuk ke `default_ap_group` tanpa konfigurasi manual satu per satu.
- **Profil Terstruktur:** Memisahkan template `ssids`, `rf_profiles`, `ap_groups`, dan `aps` agar perubahan satu profil langsung terdistribusi ke seluruh AP dalam grupnya.

## 2. RRM Auto-Channel, Auto-Power (TPC), Band Steering, & 802.11k/v/r
- **RRM Optimizer (`pkg/wlanctrl/rrm.go`):**
  - **Auto-Channel:** *Graph coloring* berbobot RSSI tetangga yang memilih kanal ortogonal terbaik (2.4 GHz `1/6/11`, 5 GHz non-DFS/DFS sesuai kebijakan `avoid_dfs`).
  - **Auto-Power (TPC):** Menurunkan daya pancar AP ketika interferensi tetangga melampaui ambang overlap (`target_coverage_rssi + 8 dB`) dan menaikkan daya di area *sparse coverage*, sembari menghormati pin manual bila disetel.
- **Band Steering (`pkg/wlanctrl/roaming.go`):** Mengarahkan klien *dual-band* ber-RSSI kuat ke 5 GHz, namun membatasi penolakan 2.4 GHz (`max_2g_rejects`) agar klien lemah/legacy tidak pernah terkunci.
- **Fast Roaming 802.11k/v/r:** Mengaktifkan `rrm_neighbor_report`, `bss_transition` (rekomendasi BTM bila neighbor unggul >= +8 dB), dan `ft_over_ds` (`mobility_domain` + `r0kh`/`r1kh`) pada `hostapd`.

## 3. Keamanan WLAN, Guest Isolation, & Self-Healing Mesh
- **WPA2/WPA3/Enterprise & Captive Portal (`pkg/wlanreconcile/renderers.go`):** Mengonfigurasi PMF wajib (`ieee80211w=2`) pada WPA3-SAE & WPA3-Enterprise (`WPA-EAP-SHA256`), `ap_isolate=1` untuk isolasi klien nirkabel, serta `nftables` `table inet daiji_wlan` untuk memblokir akses guest ke subnet RFC1918 LAN sambil meloloskan DNS/DHCP/Captive Portal.
- **Mesh Self-Healing (`pkg/wlanctrl/mesh.go` & `wpa_supplicant-mesh`):** Backhaul 802.11s terenkripsi SAE (`ieee80211w=2`); solver Bellman-Ford berbobot SNR otomatis memindahkan jalur hop apabila link antar-AP terputus (`auto_heal`, dibatasi `max_hops`).
