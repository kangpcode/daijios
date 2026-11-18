# DaijiOS Ecosystem — Panduan Pengguna & Administrator (`v1.2.0-lts`)

**Sistem:** `DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)`

---

## 1. Instalasi & Target Perangkat Keras
DaijiOS dikompilasi statis (`CGO_ENABLED=0`) tanpa dependensi runtime eksternal dan mendukung 5 target arsitektur produksi:
- `amd64` — Router x86_64 rackmount, server bare-metal, dan Cloud Hosted Router (CHR/VM KVM/Proxmox/VMware).
- `arm64` — Gateway edge/ARM64 board.
- `armv7` — Router/AP SOHO dan CPE ARMv7.
- `mipsel` & `mips64le` — Perangkat router/ONT MIPS klasik (`GOMIPS=softfloat`).

### Profil Operasi (`--profile`)
- `appliance`: Full routing/firewall/ISP/AC profile pada hardware khusus.
- `chr-vm`: Virtual appliance untuk hypervisor KVM/ESXi/Cloud POP.
- `embedded`: Profil hemat memori untuk perangkat Flash/RAM terbatas.

---

## 2. Siklus Konfigurasi Aman & Update A/B
1. **Candidate → Commit-Confirm → Save:**
   - Gunakan `daiji-ctl config set` atau shell interaktif `daiji-sh` (`configure` -> `set ...` -> `commit-confirm 5`).
   - Jika operator kehilangan konektivitas sebelum `confirm`, rollback otomatis mengembalikan running config ke revisi stabil terakhir.
2. **A/B Boot Slot & Safe Mode:**
   - Pembaruan firmware (`signed .dpk` / channel `lts`/`stable`/`beta`) ditulis ke partisi pasif (`Slot B` saat `Slot A` aktif).
   - Kegagalan boot berulang otomatis kembali ke slot sebelumnya (`daiji-ctl ab status`).
   - Safe Mode menjaga konfigurasi minimal aman agar akses SSH/`DaiWeb` tetap pulih.

---

## 3. Operasional Layanan Ekosistem
- **Networking, Firewall, QoS & VPN:** `daiji-netd` & `daiji-fw-qosd` menghasilkan konfigurasi terverifikasi untuk kernel/FRR/Kea/Keepalived, nftables, HTB/CAKE QoS, serta WireGuard/IPsec/VXLAN.
- **ISP Core (`daiji-ispd`):** PPPoE BNG, IPoE, Hotspot voucher/captive portal, RADIUS AAA/CoA, Multi-WAN failover, SNMP v1/2c/3, IPFIX, dan otomasi `DaijiScript`.
- **Wireless Controller (`daiji-ac`):** Manajemen AP, roaming `802.11k/v/r`, auto-RF channel/power, WPA2/WPA3 Enterprise, serta mesh ZTP onboarding.
- **DaiWeb (`daiji-webd` `:8443`):** Dashboard real-time via WebSocket, topologi, wizard konfigurasi, dan browser CLI.
- **Daimo & DaiDesk (`daiji-desk`):** Onboarding QR (`local`/`cloud`), penemuan tetangga L2 `DJDP1` (MAC discovery port UDP `56780`), manajemen multi-tab, SFTP jailed file manager, dan bulk config.
- **DaijiACS (`daiji-acsd` `:7547`):** Manajemen TR-069 (CWMP SOAP) & TR-369 (USP) untuk ZTE, Huawei, FiberHome, dan TR-181 standar.
- **DaijiBilling (`daiji-billingd` `:8090`):** Siklus tagihan tetap/anniversary + prorata, auto-isolir CoA `ISOLIR`/`ACTIVE`, rekonsiliasi webhook Midtrans/Xendit/QRIS, dan ledger SHA-256 immutable.
- **DaijiCloud (`daiji-cloudd` `:8080`):** Kontrol multi-tenant `Org → Site → Device`, ZTP token adoption, canary rollout, alert telemetry, dan DR snapshot restore.
- **DaijiPortal (`daiji-portald` `:8070`):** White-label branding reseller, marketplace SKU/invoice, aktivasi online & offline Ed25519 (`DJLIC1.*`), distribusi update signed, tiket, dan KB dwibahasa.

---

## 4. Checklist Pemulihan Gangguan Cepat
1. **Verifikasi kesehatan seluruh daemon:** Jalankan `bash ./scripts/hil-smoke.sh` atau `<daemon> --check`.
2. **Validasi konfigurasi terhadap SSoT:** `daiji-ctl schema validate --schema schema/daijios.schema.json --config <file>`.
3. **Verifikasi rantai audit & billing:** `daiji-ctl config verify-audit` dan endpoint `/api/v1/billing/reconcile`.
4. **Verifikasi lisensi offline di POP terisolasi:** `daiji-ctl portal license-demo --hw <HW_ID> --json`.
