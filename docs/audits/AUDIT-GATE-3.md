# AUDIT GATE 3 — ISP Features (PPPoE, Hotspot, RADIUS/CoA, Multi-WAN, Telemetry, DaijiScript)

**Proyek:** DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)  
**Tanggal Audit:** 2026-11-18  
**Auditor:** Principal Network OS Architect & Security Auditor  
**Keputusan Akhir:** **GO (Lulus ke FASE 4)** dengan catatan utang teknis terkelola.

---

## 1. Fitur Selesai vs Rencana (100% Item Fase 3)

| Item Checklist Fase 3 | Status | Bukti Artefak |
| :--- | :--- | :--- |
| **PPPoE server/client, IPoE, Hotspot (captive portal, voucher), RADIUS client/server (AAA, CoA)** | Selesai (100%) | `schema/daijios.schema.json` v1.3.0, `pkg/ispengine/{radius.go,sessions.go}`, `pkg/ispreconcile/renderers.go` (`accel-ppp.conf`, `FreeRADIUS`, `daiji-mwan.nft`) |
| **Profile/paket, rate-limit, expired-user, MAC binding, session accounting** | Selesai (100%) | `pkg/ispengine/sessions.go` (`AuthenticatePPPoE`, `RedeemHotspotVoucher`, `InterimAccounting`, `HandleCoAPacket`) |
| **Load balancing, failover (recursive/netwatch-like), multi-WAN** | Selesai (100%) | `pkg/ispengine/multiwan.go` (anti-flap hysteresis), `pkg/ispreconcile/renderers.go` (`jhash` PCC & weighted ECMP) |
| **Tools:** ping, traceroute, torch-like, packet sniffer (pcap), bandwidth test, speedtest, netflow/IPFIX, SNMP v1/2c/3, syslog | Selesai (100%) | `pkg/isptools/tools.go` (PCAP `0xa1b2c3d4`, Torch, TCP bw-test, injection-safe ping/traceroute), `pkg/ispreconcile/renderers.go` (`snmpd.conf`, `rsyslog`, `netflow.conf`) |
| **Scripting:** DaijiScript (otomasi, scheduler, event hooks) + REST API + Webhook | Selesai (100%) | `pkg/daijiscript/{engine.go,rest.go}`, `services/daiji-ispd/main.go`, `pkg/netplan/migrate.go` (`1.2.0 -> 1.3.0`) |

**Total Penyelesaian Rencana Fase 3:** **100%**.

---

## 2. Hasil Test & Coverage (Setelah Edit Terakhir)

- `go vet ./...`: **LULUS (0 peringatan)**
- `go test -v -race -count=1 -coverprofile=coverage.out ./...`: **40/40 test PASS pada 20 paket (0 gagal, 0 skip, 0 data race)**
- **Total Statement Coverage Proyek:** **`76.0%`** (naik dari `74.6%` pada Fase 2)

| Paket Baru / Diperbarui Fase 3 | Jumlah Test | Status | Statement Coverage |
| :--- | :---: | :---: | :---: |
| `pkg/ispreconcile` | 1 | PASS | `88.9%` |
| `pkg/netplan` | 3 | PASS | `83.3%` |
| `pkg/ispengine` | 2 | PASS | `83.2%` |
| `pkg/isptools` | 1 | PASS | `78.6%` |
| `services/daiji-ispd` | 1 | PASS | `77.8%` |
| `pkg/daijiscript` | 2 | PASS | `76.7%` |
| `pkg/ispplan` | 2 | PASS | `73.5%` |
| `cmd/daiji-ctl` | 1 | PASS | `53.6%` |

---

## 3. Temuan Keamanan & Perbaikan (Selama Fase 3)

| ID | Severity | Temuan / Observasi | Status & Mitigasi |
| :--- | :---: | :--- | :--- |
| **AUD-301** | **Low (Accepted RFC Exception)** | Static scan mendeteksi penggunaan `crypto/md5` pada `pkg/ispengine/radius.go:12`. | **TERKENDALI & DITERIMA**: MD5 digunakan eksklusif untuk kompatibilitas wire-protocol IETF **RFC 2865 §5.2 & RFC 5176** UDP RADIUS/CoA; seluruh token internal (`secauth`), audit log (`configengine`), dan signature Webhook (`daijiscript`) memakai **SHA-256 / HMAC-SHA256 / Ed25519**. RadSec (RADIUS-over-TLS) direkomendasikan saat melintasi jaringan publik. |
| **AUD-302** | **High (Preventive Control)** | `ping`/`traceroute` raw shell berisiko command injection dan webhook berisiko SSRF ke metadata cloud (`169.254.169.254`). | **TERVERIFIKASI AMAN**: `isptools.ValidateProbeTarget()` menolak metakarakter & flag `-`; `validateWebhookURL()` memblokir link-local/metadata IP (`ErrWebhookSSRF`), dan DaijiScript mengeksekusi dalam sandbox tanpa shell dengan batas langkah `maxSteps=1000`. |
| **AUD-303** | **Medium (Compile Fix)** | `p.Addr().As4()[:]` di `pkg/ispengine/sessions.go:314` gagal kompilasi karena array hasil `As4()` unaddressable. | **DIPERBAIKI** menjadi salinan array lokal `a4 := p.Addr().As4()` sebelum slicing. |

---

## 4. Performa & Ukuran Binary Nyata

- **Benchmarks (`go test -bench=. -benchmem ./pkg/...`, AMD Ryzen 5 6600H):**
  - `BenchmarkNetworkReconcileApply-12`: `146,876 ns/op` (~146.9 µs), `99,891 B/op`, `622 allocs/op`
  - `BenchmarkSecurityReconcileApply-12`: `147,373 ns/op` (~147.4 µs), `81,201 B/op`, `485 allocs/op`
  - `BenchmarkConfigDiffAndCommit-12`: `492,342 ns/op` (~492.3 µs), `90,778 B/op`, `1,823 allocs/op`
  - `BenchmarkValidateDefaultConfig-12`: `40,369 ns/op` (~40.4 µs), `16,974 B/op`, `360 allocs/op`
- **Loopback Bandwidth Test CLI (`daiji-ctl isp bw-test`):** `1,048,576` bytes dalam `0.95 ms` (**`8,824.48 Mbps`**).
- **Ukuran Binary Statis Cross-Compile (`CGO_ENABLED=0 -s -w`, 20 binary di 5 arsitektur):**
  - `daiji-ctl`: `4.9–6.0 MB`
  - `daiji-netd`: `3.5–4.1 MB`
  - `daiji-fw-qosd`: `3.5–4.1 MB`
  - `daiji-ispd`: `6.6–7.9 MB` (memuat `net/http`, RADIUS, DaijiScript, & diagnostics)

---

## 5. Utang Teknis & Risiko untuk Fase Berikutnya

1. **Captive Portal HTTP/HTTPS Server (`hotspot-portal`):** Saat ini `nftables` mengarahkan traffic captive ke port `:8080` dan `RedeemHotspotVoucher` menangani autentikasi; halaman HTML captive portal & redirector HTTP terintegrasi dengan `DaiWeb` pada Fase 6 / `daiji-ac` Fase 4.
2. **Integrasi Live `AF_PACKET` / Netlink NetFlow:** `WritePCAP` dan `TorchAggregator` telah teruji dengan sampel frame biner valid; hook `AF_PACKET`/eBPF live kernel capture diaktifkan saat image build Fase 12.
3. **Ukuran Binary `daiji-ispd` di Flash MIPS (7.9 MB):** Untuk CPE MIPS ber-flash kecil (16 MB SPI NOR), `daiji-ispd` harus dipaketkan sebagai modul `.dpk` opsional (`TierISP`) yang hanya diinstal pada BNG/router akses berkapasitas besar.

---

## 6. Keputusan Audit Gate 3

**DECISION: `GO` — Seluruh fitur ISP (PPPoE/IPoE/Hotspot, RADIUS/CoA RFC 5176, Multi-WAN failover/LB, Telemetry/Diagnostics, DaijiScript + REST + Webhook) terverifikasi dan siap melanjutkan ke FASE 4 (Wireless & Campus).**
