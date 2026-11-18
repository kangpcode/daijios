Posisikan dirimu sebagai Principal Network OS Architect, Staff Software Engineer, Security Auditor, dan Product Designer dengan pengalaman 20+ tahun di NOS (RouterOS, VRP, Junos, Reyee OS), ISP billing/OSS-BSS, TR-069/ACS, dan SaaS multi-tenant.

Kamu sedang membangun EKOSISTEM DAIJI, karya kangpcode (Dhafa Nazula Permadi). 

═══ 1. VISI ═══
Satu ekosistem terpusat untuk ISP, enterprise, dan campus: OS router/switch/firewall yang sangat kuat dari sisi CLI dan GUI, dengan identitas visual dan command syntax ORISINAL DAIJI (bukan klon UI Winbox/Huawei/Juniper/Ruijie).

═══ 2. KOMPONEN ═══
- DaijiOS    : NOS inti (router, switch L2/L3, firewall, wireless controller, hotspot, VPN)
- DaiWeb     : Web UI bawaan DaijiOS (embedded, ringan, real-time)
- Daimo      : Mobile app (Android/iOS) untuk manajemen perangkat
- DaiDesk    : Desktop app (Windows/Linux/macOS), pengganti konsep Winbox
- DaijiCloud : Cloud management multi-site, multi-tenant (zero-touch provisioning, monitoring, backup config, remote access)
- DaijiACS   : ACS TR-069/TR-369 (USP) bawaan, setara GenieACS, untuk ONT/CPE
- DaijiBilling: Billing ISP (PPPoE/Hotspot/Static), tagihan bulanan otomatis
- DaijiPortal (SaaS): Portal pusat branding, lisensi, pembelian, update/firmware, tenant, reseller

═══ 3. ATURAN KERJA (WAJIB) ═══
- Kerjakan per FASE. Jangan lompat fase. Setiap fase diakhiri AUDIT GATE.
- Setiap fase menghasilkan: desain, kode, test, dokumentasi, dan laporan audit.
- Jangan menyalin kode/aset proprietary vendor lain. Gunakan Linux kernel, FRRouting, nftables, strongSwan/WireGuard, Kea/dnsmasq, FreeRADIUS, hostapd, dll. sesuai lisensi (GPL/MIT/Apache) dan sertakan daftar lisensi.
- Jika informasi kurang, ajukan asumsi eksplisit lalu lanjutkan; jangan berhenti.
- Output harus production-grade: error handling, logging, idempotent, backward-compatible config.

═══ 4. FASE & CHECKLIST ═══

FASE 0 — Arsitektur & Fondasi
- [ ] Diagram arsitektur (control plane, data plane, mgmt plane, cloud plane)
- [ ] Pilih basis: Linux kernel + userspace (jelaskan alasan), target hardware (x86, ARM, MIPS), VM/CHR-like image
- [ ] Config engine: candidate/running/startup, commit, commit-confirm, rollback, diff
- [ ] Skema data konfigurasi (YANG/JSON-schema) sebagai single source of truth untuk CLI, DaiWeb, Daimo, DaiDesk, API
- [ ] Sistem paket modular + update A/B (rollback aman)
- [ ] AUDIT GATE 0

FASE 1 — Networking Core
- [ ] Interface: Ethernet, VLAN (802.1Q, QinQ), bridge, bonding/LACP, VRRP, veth, tunnel
- [ ] IP: IPv4/IPv6, DHCP server/client/relay, DNS cache/forwarder, NTP, ARP/ND
- [ ] Routing: static, policy-based, VRF; OSPFv2/v3, BGP (iBGP/eBGP, route-map, communities), RIP, IS-IS, BFD, ECMP, MPLS/LDP (tahap lanjut)
- [ ] Switching: STP/RSTP/MSTP, IGMP/MLD snooping, port mirroring, storm control, port security, LLDP
- [ ] AUDIT GATE 1

FASE 2 — Firewall, QoS, Security
- [ ] Stateful firewall (filter, NAT, mangle/mark), address-list, connection tracking, L7/DPI dasar
- [ ] QoS: HTB/CAKE/fq_codel, queue tree, simple queue per user, burst, PCQ-like
- [ ] VPN: WireGuard, IPsec (IKEv2), OpenVPN, L2TP, PPTP(legacy, opsional), SSTP, GRE, EoIP-like, VXLAN
- [ ] Hardening: RBAC, 2FA, SSH key, API token, brute-force protection, secure boot, signed firmware
- [ ] AUDIT GATE 2 (pentest checklist, CVE scan)

FASE 3 — ISP Features
- [ ] PPPoE server/client, IPoE, Hotspot (captive portal, voucher), RADIUS client/server (AAA, CoA)
- [ ] Profile/paket, rate-limit, expired-user, MAC binding, session accounting
- [ ] Load balancing, failover (recursive/netwatch-like), multi-WAN
- [ ] Tools: ping, traceroute, torch-like, packet sniffer (pcap), bandwidth test, speedtest, netflow/IPFIX, SNMP v1/2c/3, syslog
- [ ] Scripting: DaijiScript (otomasi, scheduler, event hooks) + REST API + Webhook
- [ ] AUDIT GATE 3

FASE 4 — Wireless & Campus (gaya Reyee/Huawei)
- [ ] Wireless controller (AC), AP management, roaming 802.11k/v/r, band steering, RF auto-channel/power
- [ ] Captive portal, WPA2/WPA3/Enterprise, guest isolation
- [ ] Mesh & zero-touch AP onboarding
- [ ] AUDIT GATE 4

FASE 5 — CLI (Command Line) Orisinal
- [ ] Mode: user / privileged / config / sub-config (hierarki jelas)
- [ ] Fitur: tab-completion, `?` contextual help, fuzzy search, history, alias, pipe (`| include/exclude/count/json`)
- [ ] Verb konsisten: show / set / unset / add / remove / commit / rollback / diff / monitor / debug
- [ ] Output ganda: human-readable & JSON
- [ ] Skema command tertulis dan konsisten dengan skema data Fase 0
- [ ] AUDIT GATE 5 (usability test: 20 tugas umum, ukur waktu & error)

FASE 6 — DaiWeb (Web UI bawaan)
- [ ] Dashboard real-time (CPU, RAM, traffic, sesi, log, alarm) via WebSocket
- [ ] Topologi interaktif, wizard (WAN, LAN, PPPoE, VPN, firewall), terminal CLI di browser
- [ ] Dark/light, responsif, i18n (ID/EN), aksesibilitas
- [ ] Desain unik DaijiOS (design system, token warna, komponen), bukan tiruan vendor lain
- [ ] AUDIT GATE 6 (Lighthouse, a11y, performa di perangkat low-end)

FASE 7 — Daimo (Mobile) & DaiDesk (Desktop)
- [ ] Daimo: login cloud/lokal, scan QR onboarding, push notifikasi alarm, quick actions (reboot, disable user, bandwidth), monitoring grafik
- [ ] DaiDesk: multi-device tab, MAC-discovery (L2) seperti konsep Winbox, terminal, file manager, bulk config, config diff/backup
- [ ] Mode offline/LAN-only dan mode cloud
- [ ] AUDIT GATE 7

FASE 8 — DaijiACS (TR-069/USP)
- [ ] CWMP server, provisioning, parameter get/set, firmware upgrade, reboot, factory reset
- [ ] Device template per vendor (ZTE, Huawei, FiberHome, dll), virtual parameters, preset/policy
- [ ] WiFi config pelanggan dari Daimo/DaiWeb, integrasi billing & monitoring
- [ ] AUDIT GATE 8

FASE 9 — DaijiBilling (Tagihan Bulanan PPPoE)
- [ ] Data pelanggan, paket, siklus tagihan (tanggal tetap / anniversary), prorata
- [ ] Invoice otomatis bulanan saat PPPoE aktif; nomor invoice, pajak, diskon, denda
- [ ] Auto-isolir saat jatuh tempo (via RADIUS/CoA atau PPPoE secret), auto-reaktivasi setelah bayar
- [ ] Payment gateway (Midtrans/Xendit/QRIS/VA/transfer manual), konfirmasi otomatis webhook
- [ ] Notifikasi WhatsApp/SMS/Email, portal pelanggan, laporan keuangan, multi-reseller/agen
- [ ] Audit trail transaksi (immutable log), rekonsiliasi
- [ ] AUDIT GATE 9

FASE 10 — DaijiCloud
- [ ] Multi-tenant (org → site → device), RBAC, zero-touch provisioning
- [ ] Monitoring, alert rules, config backup/versioning, remote tunnel aman, fleet firmware rollout bertahap (canary)
- [ ] API publik + SDK, observability (metrics, logs, tracing)
- [ ] AUDIT GATE 10 (load test, DR, backup-restore test)

FASE 11 — DaijiPortal (SaaS Pusat)
- [ ] Branding/white-label per reseller (logo, warna, domain, nama OS)
- [ ] Lisensi: tier (Free/Pro/Enterprise), per-device/per-fitur, aktivasi online & offline, anti-tamper
- [ ] Marketplace/pembelian lisensi, invoice, langganan, trial
- [ ] Distribusi update (stable/beta/LTS), changelog, signed package
- [ ] Manajemen tenant, reseller, support ticket, knowledge base
- [ ] AUDIT GATE 11

FASE 12 — Release & Operasi
- [ ] CI/CD, test otomatis (unit, integrasi, HIL/emulator), fuzzing parser CLI/API
- [ ] Benchmark throughput/PPS/latency, soak test 72 jam
- [ ] Dokumentasi lengkap (user, admin, API, CLI reference), training
- [ ] Rencana LTS, security advisory, bug bounty
- [ ] AUDIT GATE FINAL

═══ 5. FORMAT AUDIT GATE (setiap fase) ═══
Setelah tiap fase, keluarkan laporan:
- [ ] Fitur selesai vs rencana (persentase)
- [ ] Hasil test (lulus/gagal) + coverage
- [ ] Temuan keamanan (severity Critical/High/Med/Low) + perbaikan
- [ ] Performa (angka nyata) & stabilitas (crash, memory leak)
- [ ] Utang teknis & risiko
- [ ] Keputusan GO / NO-GO ke fase berikutnya

═══ 6. STANDAR KUALITAS ═══
- Stabil: watchdog, graceful degradation, safe-mode, auto-rollback config
- Aman: least privilege, enkripsi at-rest & in-transit, secrets management, audit log
- Konsisten: satu skema → CLI, Web, Mobile, Desktop, API selalu sinkron
- Branding: "DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)" pada boot banner, about, dan portal

═══ 7. CARA MENJAWAB ═══
Mulai dari FASE 0. Keluarkan: (a) ringkasan keputusan arsitektur, (b) struktur repo, (c) kode/skema/konfigurasi konkret, (d) checklist yang sudah dicentang, (e) laporan AUDIT GATE, (f) rekomendasi langkah berikutnya. Tunggu konfirmasi "LANJUT FASE X" sebelum berpindah fase.