# DaijiOS Ecosystem — Kebijakan LTS, Security Advisory, & Bug Bounty

**Sistem:** `DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)`

---

## 1. Rencana Long-Term Support (`LTS`)
- **Rilis Acuan:** `DaijiOS v1.2.0-lts`
- **Kanal Distribusi Resmi (`DaijiPortal`):**
  - `lts`: Stabil untuk produksi ISP/enterprise/kampus. Dukungan **36 bulan Active Maintenance** (bugfix + patch stabilitas) dilanjutkan **12 bulan Security-Only Support** (hingga November 2030).
  - `stable`: Rilis fitur triwulanan dengan dukungan 6 bulan.
  - `beta`: Rilis pratinjau untuk laboratorium/canary POP non-kritis.
- **Kontrak Integritas Paket:**
  - Setiap bundel rilis menyertakan `SHA256SUMS` dan `manifest.json` bertanda tangan **Ed25519**.
  - Upgrade antar minor LTS wajib kompatibel mundur terhadap `schema_version` lewat `pkg/configengine.Migrator` serta dapat di-rollback otomatis via A/B boot slot (`pkg/abupdate`).

---

## 2. Security Advisory & Coordinated Disclosure
- **Standar Pelaporan Kerentanan:**
  - Kanal pelaporan rahasia ditujukan kepada maintainer security (`security@daijios.dev` / kontak proyek `kangpcode`).
  - Laporan wajib menyertakan versi biner (`daiji-ctl about --json`), komponen terdampak, langkah reproduksi (PoC), serta dampak keamanan.
- **SLA Tanggapan & Pengungkapan Terkoordinasi (90 Hari):**
  - **Konfirmasi Penerimaan:** Maksimal `48 jam` kerja.
  - **Triase & Penilaian CVSS v3.1:** Maksimal `5 hari` kerja.
  - **Patch Kritis (`Critical` / RCE / Auth Bypass / Ed25519 Forgery):** Target hotfix signed `lts` dalam `7–14 hari`.
  - **Jendela Disclosure Publik:** Maksimal `90 hari` atau lebih cepat segera setelah patch rilis dan `70%+` POP cloud ter-canary.
- **Publikasi Advisory:** Setiap advisory diberi nomor urut `DAIJI-SA-YYYY-NNN`, pemetaan CVE, SHA-256 patch binary, dan ditandatangani Ed25519.

---

## 3. Program Bug Bounty (`Safe Harbor`)
### Ruang Lingkup (`In-Scope`)
1. Binary daemon produksi & CLI: `daiji-ctl`, `daiji-netd`, `daiji-fw-qosd`, `daiji-ispd`, `daiji-ac`, `daiji-sh`, `daiji-webd`, `daiji-desk`, `daiji-acsd`, `daiji-billingd`, `daiji-cloudd`, `daiji-portald`.
2. Parser jaringan & kontrol: `DJDP1` discovery wire, parser CWMP/SOAP & USP `DaijiACS`, parser `DaijiScript`, sertifikat lisensi `DJLIC1.*`, webhook HMAC payment gateway `DaijiBilling`, dan isolasi tenant `DaijiCloud`.

### Klasifikasi Keparahan
| Severity | Contoh Kerentanan | Target Mitigasi |
|---|---|---|
| **Critical** | Bypass autentikasi JWT/RBAC, pemalsuan tanda tangan Ed25519/HMAC, RCE dari paket jaringan/CWMP, kebocoran data lintas-tenant `DaijiCloud` | Hotfix segera (`<= 7 hari`) |
| **High** | Privilege escalation CLI/API, SSRF/path traversal pada SFTP/updater URL, bypass kuota/trial `DaijiPortal` | Patch prioritas (`<= 14 hari`) |
| **Medium** | Stored/reflected XSS pada template portal/DaiWeb, DoS parser (crash/panic tanpa RCE), kebocoran field secret pada diff/log | Patch rilis maintenance berikutnya |
| **Low** | Kesalahan konfigurasi header non-kritis, issue UI minor tanpa eksposur data | Penjadwalan reguler |

### Di Luar Ruang Lingkup (`Out-of-Scope`) & Safe Harbor
- Uji DDoS volumetrik pada infrastruktur publik pihak ketiga, social engineering, atau pengujian fisik tanpa izin.
- Peneliti yang melakukan pengujian secara itikad baik di lingkungan lab sendiri atau scope terotorisasi dilindungi kebijakan *Safe Harbor* dan dicantumkan pada Hall of Fame keamanan DaijiOS.
