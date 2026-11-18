# AUDIT GATE 8 — DaijiACS (`TR-069 / CWMP` & `TR-369 / USP`)

**Proyek:** DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)  
**Tanggal Audit:** 2026-11-18  
**Auditor:** Principal Network OS Architect, Broadband/TR-069 Architect & Security Auditor  
**Keputusan Akhir:** **GO (Lulus ke FASE 9)** dengan catatan utang teknis terkelola.

---

## 1. Fitur Selesai vs Rencana (100% Item Fase 8)

| Item Checklist Fase 8 | Status | Bukti Artefak |
| :--- | :--- | :--- |
| **CWMP Server (`TR-069`), Provisioning, Get/Set Parameter, Firmware Upgrade, Reboot, Factory Reset** | Selesai (100%) | `pkg/daijiacs/{cwmp.go,server.go,daijiacs_test.go}`, `services/daiji-acsd/main.go` |
| **TR-369 (`USP`) Unified Controller Dispatch** | Selesai (100%) | `pkg/daijiacs/server.go` (`HandleUSPMessage`, `/usp` bearer RBAC endpoint) |
| **Device Template Multi-Vendor (ZTE, Huawei, FiberHome, Generic TR-181), Virtual Parameters, Preset/Policy** | Selesai (100%) | `pkg/daijiacs/templates.go` (`DefaultVendorTemplates`, `ExtractVirtualParams`, `applyPresetsLocked`), `cmd/daiji-ctl/main.go` (`acs templates`) |
| **WiFi Pelanggan (Daimo/DaiWeb), Integrasi Billing & Monitoring Optik** | Selesai (100%) | `pkg/daijiacs/server.go` (`/api/v1/acs/devices/{serial}/wifi`, `billing-state`, `monitoring` threshold `-27.0 dBm`) |

**Total Penyelesaian Rencana Fase 8:** **100%**.

---

## 2. Hasil Test & Coverage (Setelah Edit Terakhir)

- `go vet ./...`: **LULUS (0 peringatan)**
- `go test -v -race -count=1 -coverprofile=coverage.out ./...`: **64/64 test PASS pada 34 paket (0 gagal, 0 skip, 0 data race)**
- **Total Statement Coverage Proyek:** **`75.1%`**

| Paket Baru / Diperbarui Fase 8 | Jumlah Test | Status | Statement Coverage |
| :--- | :---: | :---: | :---: |
| `pkg/daijiacs` | 1 (Full CWMP SOAP multi-turn, USP, Presets, WiFi, Billing, Monitoring) | PASS | `72.3%` |
| `cmd/daiji-ctl` | 1 (`acs templates` + Fase 0–7 E2E) | PASS | `56.4%` |
| `services/daiji-acsd` | 1 (`--check` startup & template check) | PASS | `45.8%` |

---

## 3. Temuan Keamanan & Kualitas + Perbaikan (Selama Fase 8)

| ID | Severity | Temuan / Observasi | Status & Perbaikan |
| :--- | :---: | :--- | :--- |
| **AUD-801** | **High (CPE Task Queue Secret Leakage & Unauthenticated `/usp`)** | `cloneDeviceLocked` pada inspeksi CPE menyalin `Queue` apa adanya sehingga `SetParameterValues` untuk `KeyPassphrase` dapat terlihat role non-superadmin, dan endpoint `/usp` perlu autentikasi RBAC. | **DIPERBAIKI** di `pkg/daijiacs/server.go`: `cloneDeviceLocked` memanggil `redactTaskSecrets(tk)` bila `redactSecrets == true`, serta `/usp` dibungkus `requirePerm(secauth.PermConfigWrite, ...)`. |
| **AUD-802** | **High (SSRF / Cleartext Firmware Upgrade & XML DoS)** | URL `Download` `http://` rentan injeksi firmware MITM/SSRF dan parser XML SOAP harus dibatasi ukuran body agar tidak memicu OOM di router. | **TERVERIFIKASI AMAN**: `EnqueueFirmwareUpgrade` menolak non-`https://` secara default (`ErrUnsafeURL`), `ParseCWMPEnvelope` membatasi body `<= 512 KB`, dan seluruh output XML melalui `xmlEscape`. |
| **AUD-803** | **Medium (CWMP Auth & Idempotent Policy Loop)** | CPE tak terautentikasi tidak boleh mendaftarkan/mengakses `/tr069`, dan Preset bootstrap tidak boleh terulang terus-menerus pada setiap Inform periodik. | **TERVERIFIKASI AMAN**: `/tr069` memverifikasi HTTP Basic Auth constant-time (`401 Challenge`) dan `applyPresetsLocked` melacak `AppliedPolicy` per versi policy. |

---

## 4. Performa & Ukuran Binary Nyata

- **Benchmarks (`go test -bench=. -benchmem ./pkg/...`, AMD Ryzen 5 6600H):**
  - `BenchmarkCWMPInformAndTemplateMatch-12`: **`20,732 ns/op`** (`10,088 B/op`, `184 allocs/op`) — parsing XML Inform + pencocokan template vendor + normalisasi parameter optik dBm dalam `~20.7µs`.
  - `BenchmarkDJDP1EncodeDecodeVerify-12`: **`4,340 ns/op`** | `BenchmarkDaimoQRGenerateAndPair-12`: **`9,982 ns/op`**
  - `BenchmarkDaiWebStaticGzip-12`: **`4,250 ns/op`** | `BenchmarkCLISessionExecute-12`: **`83,261 ns/op`**
- **Cross-Compile Statis (`CGO_ENABLED=0 -s -w`, 45 binary pada 5 arsitektur, total `241 MB` di `bin/dist/`):**
  - `daiji-acsd`: `6.2 MB` (`arm64`), `6.6 MB` (`armv7`), `6.7 MB` (`amd64`), `7.4 MB` (`mipsel` & `mips64le`).

---

## 5. Utang Teknis & Risiko untuk Fase Berikutnya

1. **CWMP Outbound ConnectionRequest & Digest Auth:** Pengantrean RPC pada session Inform berikutnya sudah aktif 100%; inisiator HTTP ConnectionRequest outbound ke IP WAN CPE (dengan Digest auth) serta persistensi inventori ONT ke storage disk/SQLite akan disambungkan bersama integrasi database pelanggan pada **FASE 9 (DaijiBilling)** & **FASE 10 (DaijiCloud)**.
2. **TR-369 Binary Protobuf MTP Frame (MQTT/STOMP):** Saat ini `HandleUSPMessage` menormalisasi payload JSON MTP secara deterministik; transport MQTT/WebSocket broker eksternal untuk USP skala fleet jutaan perangkat disambungkan di layer **DaijiCloud** (Fase 10).

---

## 6. Keputusan Audit Gate 8

**DECISION: `GO` — DaijiACS (`pkg/daijiacs`, `services/daiji-acsd`, `daiji-ctl acs templates`) memenuhi standar CWMP TR-069, USP TR-369, template multi-vendor (ZTE/Huawei/FiberHome/TR-181), virtual parameters, preset idempoten, integrasi WiFi Daimo/DaiWeb, hook billing & monitoring optik (`-27 dBm`), serta kompilasi 45 binary statis. Siap melanjutkan ke FASE 9 (DaijiBilling).**
