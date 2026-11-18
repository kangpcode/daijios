# AUDIT GATE 0 — DaijiOS Arsitektur & Fondasi

**Proyek:** DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)  
**Tanggal Audit:** 2026-11-17  
**Auditor:** Principal Network OS Architect & Security Auditor  
**Keputusan Akhir:** **GO (Lulus ke FASE 1)** dengan catatan utang teknis terkelola.

---

## 1. Fitur Selesai vs Rencana (100% Item Fondasi Fase 0)

| Item Checklist Fase 0 | Status | Bukti Artefak |
| :--- | :--- | :--- |
| Diagram arsitektur (control, data, mgmt, cloud plane) | Selesai (100%) | `docs/architecture/FASE-0-ARCHITECTURE.md` |
| Pemilihan basis Linux kernel + userspace, target x86/ARM/MIPS, CHR | Selesai (100%) | `docs/architecture/FASE-0-ARCHITECTURE.md`, `os/buildroot/TARGETS.md`, `os/init/s6-boot-sequence.md` |
| Config engine (candidate/running/startup, commit, commit-confirm, rollback, diff, migration, safe-mode) | Selesai (100%) | `pkg/configengine/{store.go,applier.go,migrator.go}`, `docs/design/CONFIG-ENGINE.md` |
| Skema data konfigurasi (JSON Schema 2020-12 + YANG) sebagai Single Source of Truth | Selesai (100%) | `schema/daijios.schema.json`, `schema/yang/daiji-system@2026-11-17.yang`, `pkg/schema/validator.go` |
| Sistem paket modular (`.dpk`) + update A/B (rollback aman) | Selesai (100%) | `pkg/pkgmgr/dpk.go`, `pkg/abupdate/updater.go`, `docs/design/AB-UPDATE-AND-DPK.md` |
| Kepatuhan lisensi OSS & branding resmi | Selesai (100%) | `docs/compliance/THIRD-PARTY-LICENSES.md`, `pkg/sysinfo/banner.go`, `os/buildroot/overlay/etc/issue` |

**Total Penyelesaian Rencana Fase 0:** **100%** (6/6 workstream fondasi selesai dengan kode, unit/integration test, dokumentasi, dan cross-build statis).

---

## 2. Hasil Test & Coverage (Setelah Edit Terakhir)

- `go vet ./...`: **LULUS (0 peringatan)**
- `go test -v -race -count=1 -coverprofile=coverage.out ./...`: **16/16 test LULUS (0 gagal, 0 skip), 0 data race**

| Paket | Jumlah Test | Status | Statement Coverage |
| :--- | :---: | :---: | :---: |
| `pkg/abupdate` | 3 | PASS | `81.0%` |
| `pkg/sysinfo` | 2 | PASS | `80.0%` |
| `pkg/pkgmgr` | 2 | PASS | `72.8%` |
| `pkg/configengine` | 4 | PASS | `70.4%` |
| `pkg/schema` | 3 | PASS | `70.1%` |
| `pkg/fsatomic` | 1 | PASS | `68.4%` |
| `cmd/daiji-ctl` | 1 | PASS | `46.6%` |
| **Total Proyek** | **16** | **PASS** | **`69.1%`** |

---

## 3. Temuan Keamanan & Reliabilitas + Perbaikan (Selama Fase 0)

| ID | Severity | Temuan | Status & Perbaikan |
| :--- | :---: | :--- | :--- |
| **AUD-001** | **High** | `configengine.Open()` menimpa `candidate` dengan `running` saat `ColdBoot=false`, menyebabkan perubahan ter-stage antar pemanggilan CLI hilang. | **DIPERBAIKI** di `pkg/configengine/store.go`: `Open()` kini memuat `candidate.json` pada warm reopen dan hanya meresetnya dari `startup`/`SafeMode` saat `ColdBoot=true`. Terverifikasi oleh `TestCLIEndToEndPhase0`. |
| **AUD-002** | **Medium** | `CommitConfirm` dapat meninggalkan konfigurasi baru tanpa pengaman jika penulisan `confirm_pending.json` gagal setelah `Applier.Apply()`. | **DIPERBAIKI** di `pkg/configengine/store.go`: kegagalan persist `confirm_pending.json` langsung memicu rollback otomatis ke `rollbackRevID`. |
| **AUD-003** | **Medium** | `pkgmgr.Store.persist()` dan `abupdate.FileEnvBackend.Save()` belum melakukan `fsync` pada direktori induk pasca-`rename`, berisiko kehilangan update metadata saat mati listrik. | **DIPERBAIKI**: diekstrak ke helper terpusat `pkg/fsatomic.WriteJSONAtomic()` dengan permission `0600`, `file.Sync()`, `os.Rename`, dan `dir.Sync()`. |
| **AUD-004** | **Medium** | `abupdate.StageUpdate()` sebelumnya mengizinkan `ImageSize <= 0` melewati pemeriksaan ukuran eksplisit. | **DIPERBAIKI** di `pkg/abupdate/updater.go`: menolak `ImageSize <= 0` dengan `ErrImageCorrupted`. |
| **AUD-005** | **Low** | `cmdAB` di `cmd/daiji-ctl/main.go` fallback ke string `"x86_64"` keras jika `DAIJI_ARCH` kosong. | **DIPERBAIKI**: fallback dinamis ke `sysinfo.NormalizeArch(runtime.GOARCH)`. |

### Kontrol Keamanan Aktif Fase 0
- Verifikasi tanda tangan **Ed25519** + **SHA-256** pada `.dpk` maupun image firmware A/B, serta **anti path-traversal** dan **anti-downgrade `security_epoch`**.
- Redaksi otomatis field sensitif (`x-daiji-secret: true`) pada `diff`, `GetRunning(true)`, dan `audit.jsonl`.
- Audit log **hash-chained SHA-256** dengan verifikasi integritas (`VerifyAuditLog()`).

---

## 4. Performa & Ukuran Binary Nyata

Diukur via `go test -bench=. -benchmem ./pkg/...` pada host `linux/amd64` (AMD Ryzen 5 6600H):
- **Validasi Skema Konfigurasi (`BenchmarkValidateDefaultConfig-12`):** `27.3 µs/op` (`27314 ns/op`), `10,780 B/op`, `240 allocs/op`
- **Structural Diff + Transactional Commit (`BenchmarkConfigDiffAndCommit-12`):** `371.3 µs/op` (`371313 ns/op`), `65,897 B/op`, `1,300 allocs/op`
- **Stabilitas Memori / Concurrency:** 0 crash, 0 goroutine leak atau data race pada eksekusi `-race`.
- **Ukuran Binary Statis Cross-Compile (`CGO_ENABLED=0`, `-s -w`):**
  - `linux/amd64`: `3.4 MB`
  - `linux/arm64`: `3.3 MB`
  - `linux/armv7`: `3.4 MB`
  - `linux/mipsel`: `3.8 MB`
  - `linux/mips64le`: `3.9 MB`

---

## 5. Utang Teknis & Risiko untuk Fase Berikutnya

1. **Integrasi Bootloader & Flash Nyata (Fase 1 / Fase 12):** Saat ini `abupdate.EnvBackend` teruji dengan `FileEnvBackend`; implementasi `GRUBEnvBackend` (`grub-editenv`) dan `UBootEnvBackend` (`fw_setenv`) serta pipeline Buildroot/QEMU HIL akan dibangun bertahap mulai Fase 1 & diuji penuh pada Fase 12.
2. **Coverage `cmd/daiji-ctl` (`46.6%`):** Subperintah interaktif (`commit-confirm`, `confirm`, `rollback`, `export-ui`, `export-openapi`) pada harness CLI masih dapat ditambah pengujian negatifnya; target Fase 1 menjaga coverage paket inti `>= 75%`.
3. **Sertifikat & Key Rotation Store:** Trusted Ed25519 key saat ini disuntikkan via konfigurasi in-memory `Options.TrustedKeys`; pada Fase 2/11 perlu keystore terenkripsi di `/etc/daiji/keys/` dengan rotasi kunci dan CRL/revocation list.
4. **Target RAM MIPS 128 MB:** Ukuran binary 3.8 MB dan footprint validasi sangat ringan, namun pada Fase 1 saat menambah `FRRouting` + `accel-ppp` perlu profiling RSS di perangkat MIPS nyata / QEMU `malta`.

---

## 6. Keputusan Audit Gate 0

**DECISION: `GO` — Fondasi arsitektur, skema SSoT, config engine transaksional, modul `.dpk`, dan mekanisme update A/B siap menjadi basis FASE 1 (Networking Core).**
