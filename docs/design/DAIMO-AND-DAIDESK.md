# Daimo (Mobile) & DaiDesk (Desktop) Companion Architecture

**Brand:** DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)  
**Phase:** FASE 7 (Daimo Mobile & DaiDesk Desktop)  
**Packages:** `pkg/daidiscovery`, `pkg/daimo`, `pkg/daidesk` | **Binary:** `daiji-desk` (`services/daiji-desk`)

---

## 1. Protokol Penemuan L2 Orisinal (`DJDP1` — `pkg/daidiscovery`)

Untuk menggantikan kebutuhan discovery proprietary secara orisinal tanpa klon byte/protokol vendor lain, DaijiOS mendefinisikan **Daiji Discovery Protocol v1 (`DJDP1`)** pada UDP port default `56780`:

- **Format Frame Biner Ringkas:** Header magic `6 byte` (`"DJDP1\x00"`) + panjang uint16 big-endian + payload JSON terikat maks `2048 byte` (`DeviceBeacon`: `mac`, `device_id`, `hostname`, `platform`, `version`, `arch`, `interface`, `ipv4`, `web_port`, `offline_lan_ready`, `ts`).
- **Autentikasi Opsional Kluster (`HMAC-SHA256`):** Setiap beacon dapat membawa tanda tangan HMAC atas field identitas guna menangkis *beacon spoofing* dari node tak terpercaya di segmen L2.

---

## 2. Daimo Mobile (`pkg/daimo`)

- **Dual Mode Login (`local` & `cloud`):** Mendukung autentikasi lokal maupun cloud relay melalui `secauth.TokenManager` + `BruteForceGuard` + RFC 6238 `TOTPVerifier`.
- **QR Code Onboarding Tanpa Password:** URI `daijios://onboard?v=1&dev=...&mac=...&mode=...&ep=...&role=...&actor=...&nonce=...&exp=...&sig=...` bertanda tangan HMAC-SHA256 berbatas waktu (*TTL*) dengan `nonce` sekali pakai (*anti-replay*) yang ditukar menjadi bearer token terlingkup RBAC.
- **Push Alarm Feed (`/ws/daimo/alarms` & `/api/v1/daimo/push/register`):** Distribusi real-time alarm kritis/peringatan serta registrasi token OS push (Android/iOS/UnifiedPush).
- **Quick Actions (`/api/v1/daimo/quick-action`):**
  - `reboot` (khusus `superadmin` via `PermSystemReboot`)
  - `disable-user` (mengirim `CodeDisconnectRequest` CoA langsung ke `ispengine.SessionManager`)
  - `set-bandwidth` (mengirim `CodeCoARequest` batas `upload/download` kbps dinamis ke sesi PPPoE/Hotspot aktif)
- **Monitoring Grafik (`/api/v1/daimo/metrics`):** Ring buffer 120 titik waktu untuk CPU, RAM, Rx/Tx Mbps, dan sesi aktif.

---

## 3. DaiDesk Desktop & Dual Mode (`pkg/daidesk`)

- **Multi-Device Tabs (`Workspace`):** Membuka beberapa perangkat sekaligus dalam tab independen, baik lewat hasil scan MAC L2 (`ModeOfflineLAN` langsung tanpa internet) maupun `ModeCloud` via relay endpoint.
- **Terminal Terisolasi per Tab (`/api/v1/daidesk/cli`):** Menjaga state prompt dan log masing-masing tab via `daijicli.Session`.
- **File Manager Berpenjara (*Jailed Atomic FS*, `/api/v1/daidesk/files`):** Memastikan penulisan atomik (`0600`, `fsync`, `rename`) dengan validasi traversal `..`, null byte, dan penelusuran ancestor `EvalSymlinks` agar symlink pun tak pernah menembus keluar root jail.
- **Bulk Config & Backup-Diff:** `ApplyBulkConfig` mendorong patch konfigurasi secara paralel ke beberapa tab perangkat (mendukung `dry_run` preview sebelum `commit`), sedangkan `ExportBackup` & `DiffBackupVsRunning` menghasilkan backup bertanda tangan HMAC-SHA256 dengan penyamaran rahasia.
