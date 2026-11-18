# Peta Layanan Ekosistem Daiji (`services/`)

Direktori `services/` akan menampung layanan runtime yang dibangun bertahap sesuai urutan fase pada `CLAUDE.md` (seluruhnya terikat pada skema SSoT `schema/daijios.schema.json`):

| Layanan | Fase | Deskripsi |
| :--- | :--- | :--- |
| `daiji-netd` / `daiji-reconcilerd` | Fase 1 | Adapter Netlink (Interface, VLAN, QinQ, Bridge, LACP, VRRP) & FRRouting (OSPF, BGP, VRF, BFD) |
| `daiji-fw-qosd` | Fase 2 | Reconciler `nftables` (Filter/NAT/Mangle/DPI), `tc` (HTB/CAKE/PCQ), VPN (WireGuard/IPsec/OpenVPN) |
| `daiji-ispd` & `daiji-scriptd` | Fase 3 | PPPoE/IPoE/Hotspot, FreeRADIUS CoA, Multi-WAN failover, NetFlow/SNMP, DaijiScript |
| `daiji-ac` | Fase 4 | Wireless Controller (`hostapd` 802.11k/v/r, Mesh, Zero-Touch AP) |
| `daiji-clid` | Fase 5 | CLI Orisinal DaijiOS (completion, `?`, pipe, output ganda human/JSON) |
| `daiweb/` | Fase 6 | Web UI bawaan DaijiOS (real-time WebSocket, topologi, terminal, i18n ID/EN) |
| `daimo/` & `daidesk/` | Fase 7 | Aplikasi Mobile (Android/iOS) & Desktop (Windows/Linux/macOS, L2 MAC-discovery) |
| `daiji-acs/` | Fase 8 | Server ACS TR-069 / TR-369 (USP) untuk ONT/CPE |
| `daiji-billing/` | Fase 9 | Billing ISP PPPoE otomatis, invoice, isolir RADIUS CoA, payment webhook |
| `daiji-cloud/` | Fase 10 | Cloud management multi-tenant, ZTP, canary OTA rollout |
| `daiji-portal/` | Fase 11 | SaaS Portal lisensi, white-label reseller, distribusi update |
