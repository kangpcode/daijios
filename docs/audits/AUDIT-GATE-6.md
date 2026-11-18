# AUDIT GATE 6 — DaiWeb (Web UI Bawaan, WebSocket, Aksesibilitas & Performa Low-End)

**Proyek:** DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)  
**Tanggal Audit:** 2026-11-18  
**Auditor:** Principal Network OS Architect, Product Designer & Security Auditor  
**Keputusan Akhir:** **GO (Lulus ke FASE 7)** dengan catatan utang teknis terkelola.

---

## 1. Fitur Selesai vs Rencana (100% Item Fase 6)

| Item Checklist Fase 6 | Status | Bukti Artefak |
| :--- | :--- | :--- |
| **Dashboard Real-Time (CPU, RAM, Traffic, Sesi, Log, Alarm) via WebSocket** | Selesai (100%) | `pkg/daiweb/{ws.go,telemetry.go,server.go}` (`/ws/telemetry` RFC 6455 stdlib + fallback `/api/v1/telemetry/snapshot`), `pkg/daiweb/assets/app.js` |
| **Topologi Interaktif, Wizard (WAN, LAN, PPPoE, VPN, Firewall), Terminal CLI di Browser** | Selesai (100%) | `pkg/daiweb/{telemetry.go,wizards.go,server.go}` (`BuildTopologyGraph`, `ApplyWizard` dry-run & commit, `/ws/cli` terikat ke `daijicli.Session`) |
| **Dark/Light (`daiji-dark` / `daiji-light` / `system`), Responsif, i18n (`ID`/`EN`), Aksesibilitas** | Selesai (100%) | `pkg/daiweb/assets/{tokens.css,app.css,index.html,app.js}`, `TestDaiWebAccessibilityAndDesignSystem` |
| **Desain Unik DaijiOS (*Obsidian Circuit & Jade Impulse*, zero vendor cloning)** | Selesai (100%) | `pkg/daiweb/assets/tokens.css` (`--daiji-*` custom token system), `docs/design/DAIWEB-UI.md` |
| **Daemon & Integrasi CLI + Cross-Build 5 Arsitektur** | Selesai (100%) | `services/daiji-webd/{main.go,main_test.go}`, `cmd/daiji-ctl/main.go` (`web check`), `Makefile` (`VERSION=0.7.0-phase6`) |

**Total Penyelesaian Rencana Fase 6:** **100%**.

---

## 2. Hasil Test & Coverage (Setelah Edit Terakhir)

- `go vet ./...`: **LULUS (0 peringatan)**
- `go test -v -race -count=1 -coverprofile=coverage.out ./...`: **57/57 test PASS pada 28 paket (0 gagal, 0 skip, 0 data race)**
- **Total Statement Coverage Proyek:** **`76.0%`**

| Paket Baru / Diperbarui Fase 6 | Jumlah Test | Status | Statement Coverage |
| :--- | :---: | :---: | :---: |
| `pkg/daiweb` | 4 (Auth/Wizards/WS + A11y + Low-End Budget) | PASS | `77.0%` |
| `pkg/configengine` | 4 (termasuk recursive `RedactDiff`) | PASS | `70.1%` |
| `services/daiji-webd` | 1 (`--check` startup & bundle audit) | PASS | `56.2%` |
| `cmd/daiji-ctl` | 1 (`web check` + Fase 0–5 E2E) | PASS | `55.5%` |

---

## 3. Audit Gate 6: Aksesibilitas (WCAG 2.1 AA), i18n, & Performa Low-End

> **Ruang Lingkup Pengujian:** Verifikasi otomatis berjalan pada engine Go/DOM/matematika warna di `pkg/daiweb/audit_gate6_test.go` (tanpa eksekusi Chrome Lighthouse CLI headless eksternal, yang dijadwalkan pada pipeline CI browser E2E di Fase 12).

### 3.1 Kontras WCAG 2.1 AA (`>= 4.5:1`), Struktur Semantik & i18n
- **HTML5 Landmarks & Keyboard Navigation:** Lolos (`lang="id"`, skip-link `#main-content`, `<header>`, `<nav>`, `<main>`, `<aside>`, `<footer>`, `role="tablist"`/`role="tabpanel"`, `aria-live="polite"`, seluruh input berpasangan `<label for="...">`, 0 `<script>` inline).
- **Paritas i18n (`id` & `en`):** Seluruh label UI memiliki kunci terjemahan setara untuk Bahasa Indonesia dan English.
- **Rasio Kontras Matematis (`tokens.css`):**

| Pasangan Token Warna | Tema | Rasio Terukur | Target WCAG AA |
| :--- | :---: | :---: | :---: |
| Teks Utama (`#edf2f7`) vs Surface (`#111821`) | Dark | **`15.85 : 1`** | `>= 4.5:1` (PASS) |
| Teks Muted (`#98a8bc`) vs Surface (`#111821`) | Dark | **`7.36 : 1`** | `>= 4.5:1` (PASS) |
| Ink Tombol Aksen (`#071a14`) vs Jade (`#18c996`) | Dark | **`8.43 : 1`** | `>= 4.5:1` (PASS) |
| Teks Bahaya (`#ff6b78`) vs Surface (`#111821`) | Dark | **`6.48 : 1`** | `>= 4.5:1` (PASS) |
| Teks Utama (`#111922`) vs Surface (`#ffffff`) | Light | **`17.71 : 1`** | `>= 4.5:1` (PASS) |
| Teks Muted (`#4a5a6d`) vs Surface (`#ffffff`) | Light | **`7.06 : 1`** | `>= 4.5:1` (PASS) |
| Ink Tombol Aksen (`#ffffff`) vs Jade (`#097a5b`) | Light | **`5.32 : 1`** | `>= 4.5:1` (PASS) |
| Teks Bahaya (`#b4232c`) vs Surface (`#ffffff`) | Light | **`6.53 : 1`** | `>= 4.5:1` (PASS) |

### 3.2 Performa Perangkat Low-End & Payload Transfer
- **Ukuran Payload Embedded DaiWeb (`//go:embed assets/*`):**
  - Total Mentah (`index.html` + `tokens.css` + `app.css` + `app.js`): **`40,143 bytes` (`39.2 KB`)**
  - Total Terkompresi Gzip (`gzip -9` di RAM): **`11,561 bytes` (`11.3 KB`)** — melampaui anggaran `< 20 KB` untuk router MIPS/ARM RAM kecil, ditambah dukungan `ETag` `304 Not Modified`.
- **Simulasi Konkurensi (`64` request SPA gzip serentak):** Selesai dalam **`1.591ms`** (rata-rata **`25µs / request`**).
- **Benchmarks (`go test -bench=. -benchmem ./pkg/...`, AMD Ryzen 5 6600H):**
  - `BenchmarkDaiWebStaticGzip-12`: **`4,101 ns/op`** (`8,528 B/op`, `25 allocs/op`)
  - `BenchmarkDaiWebTelemetrySnapshot-12`: **`182,536 ns/op`** (`47,198 B/op`, `924 allocs/op`)
  - `BenchmarkDaiWebWizardDryRun-12`: **`458,467 ns/op`** (`81,850 B/op`, `1,463 allocs/op`)

---

## 4. Temuan Keamanan & Desain + Perbaikan (Selama Fase 6)

| ID | Severity | Temuan / Observasi | Status & Perbaikan |
| :--- | :---: | :--- | :--- |
| **AUD-601** | **Critical (Nested Secret Leakage in Add-Block Diffs)** | Ketika Wizard VPN menambahkan blok `vpn` untuk pertama kali (`op: "add"`), `configengine.RedactDiff` awalnya hanya memeriksa `secretCheck(d.Path)` pada `"vpn"` dan belum masuk ke child nested (`vpn.wireguard[0].private_key`), sehingga key privat mentah sempat muncul di JSON diff preview! | **DIPERBAIKI** di `pkg/configengine/applier.go`: ditambahkan penelusuran rekursif `redactValueAt(path, val, secretCheck)` pada map & array. Terverifikasi langsung oleh `TestDaiWebAssetsAuthSecurityAndWizards` (`vpn` dry-run mengembalikan `"***REDACTED***"`). |
| **AUD-602** | **High (CSWSH, Frame DoS, & Hijacked Context Cancel)** | Endpoint WebSocket rentan terhadap Cross-Site WebSocket Hijacking (CSWSH), frame oversized tanpa batas, serta pembatalan `r.Context()` pasca `http.Hijack()`. | **DIPERBAIKI & TERVERIFIKASI** di `pkg/daiweb/{server.go,ws.go}`: validasi `Origin == Host` (mengembalikan `403 Forbidden`), batas ukuran frame `64 KB`, kewajiban masking RFC 6455 dari klien, serta konteks lokal terkontrol `context.WithCancel(context.Background())`. |
| **AUD-603** | **High (Auth Brute Force, Token Revocation & RBAC)** | Perlu pembatasan tebakan sandi UI, pembatalan token saat logout, serta isolasi hak `readonly` terhadap Wizard mutasi dan pembacaan rahasia config. | **TERVERIFIKASI AMAN**: `BruteForceGuard` mengembalikan `429` pada percobaan gagal ke-6, `POST /api/v1/auth/logout` mencabut JTI via `TokenManager.Revoke`, `viewer` menerima config ter-redaksi serta mendapat `403 Forbidden` pada `/api/v1/wizards/apply`. |

---

## 5. Cross-Compile Statis (35 Binary, 5 Arsitektur)

Kompilasi statis `CGO_ENABLED=0 -s -w` versi `0.7.0-phase6` pada `bin/dist/` (**`179 MB`** total across 35 binary):
- `daiji-webd`: `6.9 MB` (`arm64`), `7.3 MB` (`armv7`), `7.4 MB` (`amd64`), `8.2 MB` (`mipsel` & `mips64le`).
- `daiji-ctl`: `5.5–6.6 MB` | `daiji-sh`: `3.5–4.2 MB` | `daiji-ac`: `3.5–4.2 MB` | `daiji-netd`: `3.5–4.1 MB` | `daiji-fw-qosd`: `3.5–4.1 MB` | `daiji-ispd`: `6.6–7.9 MB`.

---

## 6. Utang Teknis & Risiko untuk Fase Berikutnya

1. **TLS/HTTPS Certificate Automation (ACME/Self-Signed Boot):** `daiji-webd` menyediakan handler HTTP/WebSocket siap-TLS; terminasi TLS dengan rotasi sertifikat ECDSA otomatis di appliance akan diikat dengan subsystem manajemen sertifikat pada konfigurasi produksi (`management.daiweb.port=443`).
2. **Audit Browser Headless Real (Lighthouse CLI / Playwright):** Pemeriksaan Lighthouse Chromium penuh di berbagai viewport & metrik INP/CLS di browser nyata dijadwalkan bersama suite integrasi CI/E2E pada Fase 12.

---

## 7. Keputusan Audit Gate 6

**DECISION: `GO` — DaiWeb (`pkg/daiweb`, `services/daiji-webd`, `daiji-ctl web check`, dan perbaikan `AUD-601` pada `configengine.RedactDiff`) memenuhi target WebSocket real-time, topologi interaktif, 5 wizard tervalidasi SSoT, terminal CLI browser, Dark/Light/i18n/WCAG AA, serta payload low-end `11.3 KB` gzip. Siap melanjutkan ke FASE 7 (Daimo Mobile & DaiDesk Desktop).**
