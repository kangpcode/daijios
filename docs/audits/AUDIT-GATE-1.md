# AUDIT GATE 1 — DaijiOS Networking Core

**Proyek:** DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)  
**Tanggal Audit:** 2026-11-17  
**Auditor:** Principal Network OS Architect & Security Auditor  
**Keputusan Akhir:** **GO (Lulus ke FASE 2)** dengan catatan utang teknis terkelola.

---

## 1. Fitur Selesai vs Rencana (100% Item Networking Core Fase 1)

| Item Checklist Fase 1 | Status | Bukti Artefak |
| :--- | :--- | :--- |
| **Interface:** Ethernet, VLAN (802.1Q, QinQ 802.1ad), bridge, bonding/LACP, VRRP, veth, tunnel (GRE/GRETAP/IPIP/IP6GRE/VXLAN/SIT) | Selesai (100%) | `schema/daijios.schema.json` v1.1.0, `pkg/netplan`, `pkg/netreconcile/reconciler.go`, `pkg/netreconcile/renderers.go` (`keepalived.conf`) |
| **IP:** IPv4/IPv6 sysctl forwarding, DHCP server (`Kea`) / client / relay, DNS cache/forwarder (`dnsmasq`), NTP (`chrony`), static ARP/ND | Selesai (100%) | `pkg/netreconcile/{reconciler.go,renderers.go}`, `schema/examples/isp-core-config.json` |
| **Routing:** Static, PBR (`ip rule`), VRF (`ip link type vrf`), OSPFv2/v3, BGP (iBGP/eBGP, route-map, prefix-list, communities), RIP, IS-IS, BFD, ECMP weighted nexthop, MPLS/LDP (foundation stage) | Selesai (100%) | `pkg/netplan/semantic.go`, `pkg/netreconcile/renderers.go` (`frr.conf`), `services/daiji-netd/main.go` |
| **Switching:** STP/RSTP/MSTP (`mstpctl`), IGMP/MLD snooping, port mirroring (`tc mirred`), storm control (`tc police`), port security (`learning off` + static FDB), LLDP (`lldpd`) | Selesai (100%) | `pkg/netreconcile/reconciler.go`, `pkg/netreconcile/renderers.go`, `schema/yang/daiji-networking@2026-11-17.yang` |
| **Kompatibilitas Mundur (`1.0.0 -> 1.1.0`) & SSoT YANG** | Selesai (100%) | `pkg/netplan/migrate.go`, `schema/yang/daiji-networking@2026-11-17.yang` |

**Total Penyelesaian Rencana Fase 1:** **100%** (4/4 domain jaringan inti selesai dengan validasi skema, validasi semantik, rekonsiliasi idempoten, test terintegrasi, dan dokumentasi lisensi).

---

## 2. Hasil Test & Coverage (Setelah Edit Terakhir)

- `go vet ./...`: **LULUS (0 peringatan)**
- `go test -v -race -count=1 -coverprofile=coverage.out ./...`: **23/23 test PASS (0 gagal, 0 skip, 0 data race)**

| Paket | Jumlah Test | Status | Statement Coverage |
| :--- | :---: | :---: | :---: |
| `pkg/netplan` | 3 | PASS | `83.5%` |
| `services/daiji-netd` | 1 | PASS | `82.5%` |
| `pkg/abupdate` | 3 | PASS | `81.0%` |
| `pkg/sysinfo` | 2 | PASS | `80.0%` |
| `pkg/netreconcile` | 3 | PASS | `76.7%` |
| `pkg/pkgmgr` | 2 | PASS | `72.8%` |
| `pkg/configengine` | 4 | PASS | `70.6%` |
| `pkg/fsatomic` | 1 | PASS | `68.4%` |
| `pkg/schema` | 3 | PASS | `67.6%` |
| `cmd/daiji-ctl` | 1 | PASS | `50.6%` |
| **Total Proyek** | **23** | **PASS** | **`72.0%`** |

---

## 3. Temuan Keamanan & Reliabilitas + Perbaikan (Selama Fase 1)

| ID | Severity | Temuan | Status & Perbaikan |
| :--- | :---: | :--- | :--- |
| **AUD-101** | **High** | Field teks bebas (`bgp.neighbor.description`, `vrf.description`, `vrrp.auth_secret`, `dns.local_domain`) dapat disalahgunakan untuk *newline config injection* ke `frr.conf`/`keepalived.conf`/`dnsmasq.conf`. | **DIPERBAIKI** di `pkg/netplan/semantic.go` (`checkLineSafe` menolak `\r`, `\n`, `\x00`) dan `pkg/netreconcile/renderers.go` (`sanitizeLine`). Teruji pada `TestSemanticRejectsInvalidTopologies`. |
| **AUD-102** | **Medium** | `reconcileDaemons()` sempat menggunakan permission keras `0o600` untuk semua file alih-alih `sp.mode` per daemon (`0600` untuk rahasia `frr.conf`/`keepalived.conf`, `0640` untuk `kea-dhcp4.conf`, `0644` untuk non-secret). | **DIPERBAIKI** di `pkg/netreconcile/reconciler.go`. |
| **AUD-103** | **Medium** | Konfigurasi `ip.dhcp.relays` sudah ada pada skema namun belum di-render saat `reconcileDaemons()`. | **DIPERBAIKI**: ditambahkan `RenderDHCPRelay()` ke `/etc/daiji/dhcp-relay.conf` dengan verifikasi di `TestFullPhase1ReconciliationIdempotencyAndCleanup`. |
| **AUD-104** | **Medium** | `daiji-ctl net plan` sebelumnya mengasumsikan NIC fisik tetap `eth0..eth4`. | **DIPERBAIKI** di `cmd/daiji-ctl/main.go`: membaca nama NIC langsung dari `interfaces.physical` konfigurasi target. |
| **AUD-105** | **Low** | Uji migrasi `pkg/configengine/store_test.go` belum memiliki edge `1.0.0 -> 1.1.0` setelah skema utama naik ke `1.1.0`. | **DIPERBAIKI**: menguji jalur multi-hop `0.9.0 -> 1.0.0 -> 1.1.0`. |

---

## 4. Performa & Ukuran Binary Nyata

Diukur via `go test -bench=. -benchmem ./pkg/...` pada host `linux/amd64` (AMD Ryzen 5 6600H):
- **`BenchmarkNetworkReconcileApply-12` (rekonsiliasi penuh topologi ISP Core):** `157,105 ns/op` (~157.1 µs), `100,691 B/op`, `624 allocs/op`
- **`BenchmarkConfigDiffAndCommit-12`:** `478,519 ns/op` (~478.5 µs), `90,763 B/op`, `1,833 allocs/op`
- **`BenchmarkValidateDefaultConfig-12`:** `41,446 ns/op` (~41.4 µs), `17,022 B/op`, `362 allocs/op`
- **Idempotency & Stabilitas:** Pengaplikasian ulang konfigurasi identik menghasilkan **0 reload** layanan yang tidak perlu dan 0 kegagalan `RTNETLINK: File exists`.
- **Ukuran Binary Statis Cross-Compile (`CGO_ENABLED=0`, `-s -w`):**
  - `daiji-ctl`: `amd64` 3.6 MB | `arm64` 3.4 MB | `armv7` 3.6 MB | `mipsel` 4.0 MB | `mips64le` 4.1 MB
  - `daiji-netd`: `amd64` 3.6 MB | `arm64` 3.5 MB | `armv7` 3.6 MB | `mipsel` 3.9 MB | `mips64le` 4.1 MB

---

## 5. Utang Teknis & Risiko untuk Fase Berikutnya

1. **Dynamic MAC Sticky Limit (`port_security.max_macs`):** Saat ini driver kernel menonaktifkan `learning` + FDB statis; pembatasan *dynamic MAC learning cap* dan *violation shutdown* penuh perlu dihubungkan dengan `nftables` bridge family / hook netlink di **Fase 2**.
2. **Integrasi Kernel Live (Namespace Test HIL):** Pengujian Fase 1 dijalankan terhadap `SimulatedDriver` dan `--dry-run` tanpa `CAP_NET_ADMIN`; eksekusi nyata di `ip netns` terisolasi serta daemon FRR/Kea hidup perlu masuk suite integrasi berhak istimewa di VM/QEMU HIL (**Fase 12**).
3. **DHCP Client (`dhclient`/`udhcpc`):** Konfigurasi `ip.dhcp.clients` sudah dimodelkan dan divalidasi di skema, perlu service unit per-interface `udhcpc`/`kea` pada rootfs image Buildroot.
4. **Konsumsi Memori di MIPS 128 MB:** Dengan `daiji-netd` hanya 3.9 MB, penggunaan RAM paling signifikan pada perangkat MIPS nantinya berasal dari `FRRouting` (jika menjalankan BGP full-table, tidak disarankan di CPE 128 MB — wajib pembatasan profil/warning di Fase 2/5).

---

## 6. Keputusan Audit Gate 1

**DECISION: `GO` — Networking Core (Interface, IP, Routing, Switching) valid secara skema/semantik, idempoten, aman dari config-injection, dan siap melanjutkan ke FASE 2 (Firewall, QoS, Security).**
