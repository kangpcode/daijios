# Urutan Boot, Watchdog, & Safe-Mode (`s6-rc`)

1. **Stage 1 — Early Boot & Bootloader Slot Selection (`GRUB2` / `U-Boot`)**
   - Membaca `BootEnv` (`active_slot`, `pending_slot`, `boot_attempts`, `max_attempts`).
   - Jika `pending_slot` aktif dan `boot_attempts >= max_attempts` (default 3): bootloader otomatis fallback ke `last_good_slot`.
   - Jika tidak: increment `boot_attempts` lalu mount `ROOTFS-<slot>` (SquashFS read-only).

2. **Stage 2 — Hardware Watchdog & `/data` Mount (`s6-linux-init`)**
   - Membuka `/dev/watchdog` lebih awal (timeout default 30 detik) dan menjalankan `daiji-watchdogd`.
   - Memverifikasi integritas partisi `/data` (`fsck` bila kotor) dan mount read-write.

3. **Stage 3 — `daiji-configd` Startup, Crash Recovery, & Safe-Mode**
   - Menjalankan `configengine.Open(..., ColdBoot: true)`:
     - Menjalankan `Migrator` otomatis bila `schema_version` pada `startup.json` lebih lama dari image baru (dengan backup `.bak.json`).
     - Mengecek `boot_state.json`: bila `failed_boots >= max_failed_boots`, masuk ke **Safe-Mode** (hanya membuka interface manajemen dan SSH/API/DaiWeb dasar).
     - Mengecek `confirm_pending.json`: bila crash/reboot terjadi saat `commit-confirm` belum dikonfirmasi dan deadline sudah lewat, rollback otomatis ke revisi aman sebelumnya.

4. **Stage 4 — Control & Management Plane Bring-up**
   - Menyalakan `daiji-reconcilerd` (Fase 1+), `daiji-apid`, `daiji-clid`, dan `DaiWeb`.
   - Setelah seluruh service critical lolos probe kesehatan:
     - `abupdate.ConfirmBootHealth()` menandai slot aktif sebagai `good` dan memperbarui `security_epoch`.
     - `configengine.MarkBootHealthy()` mereset `failed_boots = 0`.
