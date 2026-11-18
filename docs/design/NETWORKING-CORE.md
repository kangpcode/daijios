# Desain Networking Core (FASE 1) — `pkg/netplan`, `pkg/netreconcile`, & `daiji-netd`

## 1. Alur Rekonsiliasi Transaksional & Idempoten

```
[Schema SSoT v1.1.0 + SemanticValidator]
                  │
                  ▼
     [NetworkApplier.Plan()]  ──(gagal)──> Tolak sebelum menyentuh kernel
                  │ (valid)
                  ▼
     [NetworkApplier.Apply()]
       1. sysctl (ip_forward, ipv6.forwarding, rp_filter, proxy_arp, mpls)
       2. VRF (ip link add <vrf> type vrf table <id>)
       3. Physical NICs (MTU, MAC, VRF master, ip addr replace, up/down)
       4. Bonding / LACP 802.3ad (lacp_rate, xmit_hash_policy, slave attach)
       5. VLAN 802.1Q & QinQ 802.1ad (stacked outer/inner S-Tag + C-Tag)
       6. Veth & Tunnels (GRE, GRETAP, IPIP, IP6GRE, VXLAN, SIT)
       7. Bridge & Switching (vlan_filtering, STP/RSTP/mstpctl, IGMP/MLD snooping,
          BPDU Guard, Port Security static FDB, TC ingress storm control, TC mirred SPAN)
       8. Static ARP/ND, PBR (`ip rule`), Static & ECMP weighted routes (`ip route replace`)
       9. Daemon config atomic write + SHA-256 conditional reload:
          FRRouting (`frr.conf`), Kea (`kea-dhcp4.conf`), dnsmasq, keepalived, chrony, lldpd
      10. Orphan cleanup via `ManagedState` (`netd-state.json`)
```

## 2. Invarian Keamanan & Reliabilitas Fase 1
- **Tidak Ada Reload Berulang (Zero-Churn Idempotency):** `WriteFile()` membandingkan SHA-256 isi file konfigurasi baru vs file lama; layanan (`s6-svc -h`) hanya di-reload apabila konfigurasi benar-benar berubah.
- **Perlindungan Tabel Routing Kernel:** `netplan.ValidateSemantic()` menolak VRF yang menggunakan ID tabel cadangan Linux (`0`, `253`, `254`, `255`), tabrakan nama interface, port bridge ganda, rentang DHCP di luar subnet, maupun referensi `route-map`/`prefix-list` yang tidak terdefinisi.
- **Isolasi Secret & Masking Preview:** Secret routing (`routing.bgp.neighbors[].password`, `routing.ospf.areas[].auth_key`, `interfaces.vrrp[].auth_secret`) ditandai `x-daiji-secret: true` di skema, ditulis dengan permission `0600` pada file daemon nyata, serta otomatis dimask sebagai `***REDACTED***` pada output pratinjau CLI (`daiji-ctl net render-frr` / `render-keepalived`).
- **Kompatibilitas Mundur (`1.0.0 -> 1.1.0`):** `netplan.RegisterMigrations()` mengonversi konfigurasi Fase 0 (`1.0.0`) secara otomatis menjadi skema Fase 1 (`1.1.0`) sambil mempertahankan seluruh field lama.
