# Desain Config Engine DaijiOS (`pkg/configengine`)

## 1. Tiga Datastore & Siklus Hidup Konfigurasi

| Datastore | File Penyimpanan | Sifat | Fungsi |
| :--- | :--- | :--- | :--- |
| **`candidate`** | `candidate.json` | Persisten antar sesi CLI/API (direset saat cold boot) | Ruang staging untuk `set`, `unset`, `validate`, `diff`, `discard` sebelum `commit`. |
| **`running`** | `running.json` | Aktif di kernel & control-plane | Sumber kebenaran operasional saat perangkat menyala. |
| **`startup`** | `startup.json` | Non-volatile (boot persistence) | Dimuat otomatis saat cold boot (`save` menyalin `running -> startup`). |
| **`revisions/`** | `rev-000001.json` ... | Immutable + SHA-256 digest | Riwayat lengkap setiap commit untuk `rollback` instan. |

## 2. Jaminan Transaksi, Compensating Rollback, & Crash Recovery

1. **Edit Lock Eksklusif (`lock.json`)**: Mencegah dua operator menimpa perubahan candidate satu sama lain secara diam-diam.
2. **Validasi 2-Tahap**: Validasi tipe/format/constraint via `schema.CompiledSchema`, diikuti `SemanticValidator` lintas-field.
3. **Pre-flight Plan & Compensating Rollback**:
   - `Applier.Plan()` memverifikasi kesiapan subsistem sebelum mutasi.
   - Jika `Applier.Apply()` gagal di tengah jalan, engine otomatis memanggil `Applier.Apply(prevRunning, InvertDiff(diffs))` sehingga kernel/daemon tidak pernah berada dalam kondisi setengah berubah.
4. **Deadman `CommitConfirm` Tahan Crash/Reboot**:
   - Ketika operator menjalankan `commit-confirm <timeout>`, state `confirm_pending.json` (berisi `token`, `rollback_revision_id`, `deadline_unix_nano`) ditulis secara atomic (`fsync`) **sebelum** timer in-memory berjalan.
   - Jika koneksi terputus karena konfigurasi jaringan/firewall salah, timer otomatis mengembalikan `running` ke `rollback_revision_id`.
   - Jika router mengalami crash/reboot di tengah jendela waktu tersebut, `Open()` memanggil `recoverPendingConfirmLocked()` yang segera mengembalikan konfigurasi aman begitu deadline terlewati.
5. **Safe-Mode Auto-Recovery (`boot_state.json`)**:
   - Setiap cold boot menaikkan `failed_boots` hingga daemon sehat memanggil `MarkBootHealthy()`.
   - Jika kegagalan boot mencapai `max_failed_boots` (default: `3`), engine masuk ke **Safe-Mode** dengan konfigurasi manajemen minimal (SSH/API/DaiWeb tetap dapat diakses tanpa aturan firewall/routing berisiko).
6. **Hash-Chained Immutable Audit Log (`audit.jsonl`)**:
   - Setiap entri `AuditEntry` memuat `prev_hash` dan `entry_hash` (SHA-256). Pemalsuan atau penghapusan baris di masa lalu terdeteksi langsung oleh `VerifyAuditLog()`.
7. **Backward-Compatible Migration (`Migrator`)**:
   - Saat memuat `startup.json` dengan `schema_version` lama, engine membuat cadangan `startup.pre-migration.<ver>.bak.json`, menjalankan migrasi berantai ke versi target, lalu memvalidasi ulang terhadap skema terbaru.
