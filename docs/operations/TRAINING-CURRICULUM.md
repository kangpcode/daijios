# DaijiOS Ecosystem — Kurikulum Pelatihan & Sertifikasi Resmi

**Sistem:** `DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)`

---

## Jalur Sertifikasi Resmi

### Level 1 — DCNA (`DaijiOS Certified Network Associate`) | Durasi: 2 Hari
- **Target:** Operator NOC L1, Teknisi Lapangan ISP, Sysadmin pemula.
- **Materi & Lab:**
  1. Arsitektur DaijiOS (Control/Data/Mgmt/Cloud Plane) & target hardware (`amd64`/`arm64`/`mips`).
  2. Navigasi `daiji-sh` (`user`/`privileged`/`config`), tab-completion, `?`, serta pipa `| include` / `| json`.
  3. Siklus konfigurasi aman: `commit-confirm`, `diff`, `rollback`, dan recovery A/B boot slot.
  4. Konfigurasi dasar interface, VLAN 802.1Q, DHCP, NAT masquerade, dan penggunaan `DaiWeb` + `Daimo` QR onboarding.
- **Evaluasi Lab:** 20 skenario tugas CLI dasar + deployment topologi 1 WAN / 2 LAN bebas error.

### Level 2 — DCNP (`DaijiOS Certified ISP & Campus Professional`) | Durasi: 3 Hari
- **Target:** Network Engineer ISP, Pengelola WISP/Kampus, NOC L2.
- **Materi & Lab:**
  1. Routing dinamis OSPFv2/v3, BGP eBGP/iBGP, VRF, dan ECMP failover (`Multi-WAN`).
  2. PPPoE BNG & Hotspot Captive Portal (`daiji-ispd`), integrasi FreeRADIUS AAA + CoA.
  3. Wireless Controller (`daiji-ac`): RRM auto-channel/power, roaming `802.11k/v/r`, mesh AP ZTP.
  4. Otomasi harian dengan `DaijiScript`, manajemen CPE via `DaijiACS` (CWMP SOAP + TR-369 USP), dan tagihan otomatis `DaijiBilling` (prorata, auto-isolir, rekonsiliasi webhook).

### Level 3 — DCNE (`DaijiOS Certified Carrier & Cloud Architect`) | Durasi: 2 Hari
- **Target:** Principal Architect, Security Auditor, Operator Multi-POP SaaS.
- **Materi & Lab:**
  1. Arsitektur multi-tenant `DaijiCloud` (`Org → Site → Device`), ZTP mass adoption, canary rollout bertahap.
  2. Pengelolaan reseller white-label `DaijiPortal`, penerbitan & verifikasi offline lisensi `Ed25519` (`DJLIC1.*`).
  3. Disaster Recovery (DR snapshot verification), observability Prometheus `/metrics`, serta simulasi respon insiden CVE dan pembaruan signed `LTS`.
