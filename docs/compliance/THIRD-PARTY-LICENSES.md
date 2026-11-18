# Kepatuhan Lisensi Open-Source & Batas Properti Intelektual — Ekosistem Daiji

> **Prinsip Wajib (CLAUDE.md Aturan #3):** Tidak ada penyalinan kode atau aset proprietary vendor lain (MikroTik/RouterOS, Huawei/VRP, Juniper/Junos, Ruijie/Reyee OS). Seluruh fondasi sistem dibangun di atas Linux upstream dan proyek open-source dengan kepatuhan lisensi penuh serta batas IPC/process isolation yang bersih.

## 1. Inventaris Komponen Pihak Ketiga & Lisensi

| Komponen | Peran dalam DaijiOS | Lisensi Upstream | Fase Integrasi | Mekanisme Isolasi / Kepatuhan |
| :--- | :--- | :--- | :--- | :--- |
| **Linux Kernel (6.12 LTS)** | Data plane, routing FIB, VRF, bridge/VLAN, Netfilter, tc, WireGuard, XDP | `GPL-2.0-only` | Fase 0–1 | Komunikasi via syscall / Netlink standar; kode kernel kustom (jika ada) terpisah sebagai GPL-2.0. |
| **musl libc** | Standard C library untuk rootfs ringan (x86/ARM/MIPS) | `MIT` | Fase 0 | Permissive; atribusi dicantumkan di `/usr/share/licenses/`. |
| **s6 & skalibs** | Process supervision & boot tree cepat | `ISC` | Fase 0 | Permissive; skrip service unit terpisah. |
| **BusyBox** | Utilitas shell/POSIX dasar rescue/init | `GPL-2.0-only` | Fase 0 | Binary userspace terpisah; source mirror tersedia sesuai kewajiban GPLv2. |
| **Go Standard Library / Runtime** | Bahasa inti daemon control/mgmt (`daiji-configd`, `daiji-apid`, `daiji-ctl`) | `BSD-3-Clause` | Fase 0+ | Permissive; menyertakan file NOTICE/LICENSE Go. |
| **FRRouting (FRR)** | BGP, OSPFv2/v3, RIP, IS-IS, BFD, LDP | `GPL-2.0-or-later` & `LGPL-2.1-or-later` | Fase 1 | Berjalan sebagai daemon terpisah; `daiji-netd` berkomunikasi melalui `frr.conf` / `vtysh` / Unix socket (bukan static-linking). |
| **iproute2 (`ip`, `bridge`, `tc`)** | Interface, VLAN/QinQ, bridge, bonding, VRF, PBR, ECMP, storm-control/mirroring | `GPL-2.0-only` | Fase 1 | Eksekusi proses userspace terpisah via `netreconcile.LinuxDriver`. |
| **keepalived** | VRRP high-availability gateway | `GPL-2.0-or-later` | Fase 1 | Daemon terpisah dikontrol via `/etc/keepalived/keepalived.conf` (`0600`) dan reload `s6-svc`. |
| **mstpd** | RSTP & MSTP user-space daemon untuk Linux bridge | `GPL-2.0-or-later` | Fase 1 | Daemon terpisah dikontrol via `mstpctl`. |
| **lldpd** | LLDP / CDP / LLDP-MED discovery daemon | `ISC` | Fase 1 | Permissive; konfigurasi melalui `/etc/lldpd.d/daiji.conf`. |
| **chrony** | NTP client & server | `GPL-2.0-only` | Fase 1 | Daemon terpisah dikontrol via `/etc/chrony/chrony.conf`. |
| **nftables (`nft` / `libnftables`)** | Stateful firewall, NAT, mangle, connection tracking, dynamic sets | `GPL-2.0-only` | Fase 2 | Eksekusi atomik via `nft -f /etc/nftables.d/daiji.nft` (`daiji-fw-qosd`). |
| **WireGuard (`wireguard-tools`)** | VPN modern kernel-space | `GPL-2.0-only` | Fase 2 | Modul kernel GPLv2 + CLI/Netlink boundary (`wg setconf`). |
| **strongSwan** | IPsec IKEv2 VPN | `GPL-2.0-or-later` | Fase 2 | Daemon terpisah dikontrol via `/etc/swanctl/conf.d/daiji.conf` (`0600`) dan `vici`. |
| **OpenVPN** | SSL/TLS tunnel VPN (TUN/TAP) | `GPL-2.0-only` | Fase 2 | Daemon terpisah dikontrol via `/etc/openvpn/*` (`0600`). |
| **xl2tpd / sstpd** | L2TP/IPsec & SSTP VPN server | `GPL-2.0-only` | Fase 2 | Daemon terpisah dikontrol via file konfigurasi terisolasi. |
| **Kea DHCP / dnsmasq** | DHCP server/relay, DNS forwarder/cache | `MPL-2.0` (Kea) / `GPL-2.0` or `GPL-3.0` (dnsmasq) | Fase 1 | Daemon terpisah dengan konfigurasi JSON/conf yang dihasilkan oleh `daiji-reconcilerd`. |
| **accel-ppp / pppd** | PPPoE/IPoE/L2TP access concentrator ISP | `GPL-2.0-or-later` | Fase 3 | Daemon terpisah; kontrol sesi via CLI/CoA/RADIUS. |
| **FreeRADIUS** | AAA & CoA server/proxy | `GPL-2.0-only` | Fase 3 | Daemon terpisah; komunikasi melalui protokol standar RADIUS RFC 2865/2866/5176. |
| **hostapd / wpa_supplicant** | Wireless AP, WPA2/WPA3/Enterprise, Mesh, 802.11k/v/r | `BSD-3-Clause` | Fase 4 | Permissive; kontrol melalui `ctrl_iface` socket. |
| **OpenSSH** | Akses manajemen SSH & SFTP terenkripsi | `BSD` / `OpenSSH` | Fase 0–2 | Daemon sistem terpisah. |

## 2. Kebijakan Orisinalitas DaijiOS
1. Seluruh syntax CLI (`daiji-clid`), skema JSON/YANG (`schema/daijios.schema.json`), token desain `DaiWeb`/`Daimo`/`DaiDesk`, dan ikonografi adalah karya orisinal Ekosistem Daiji.
2. Kode sumber Fase 0 di bawah `pkg/` dan `cmd/` hanya menggunakan pustaka standar Go (`BSD-3-Clause`) tanpa dependensi eksternal yang belum diaudit.
3. Setiap rilis image (mulai Fase 1/12) wajib menyertakan arsip SBOM (Software Bill of Materials) dan source offer untuk komponen berlisensi GPLv2/LGPL/MPL.
