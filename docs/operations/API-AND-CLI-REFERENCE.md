# DaijiOS Ecosystem — Referensi CLI & API (`v1.2.0-lts`)

**Sistem:** `DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)`

---

## 1. CLI Interaktif (`daiji-sh`) — Tata Bahasa Orisinal DaijiOS
- **Hierarki Mode:**
  - `user` (`user@host> `) -> `enable` -> `privileged` (`user@host# `) -> `configure` -> `config` (`user@host(cfg)# `) -> `edit <path>` -> `sub-config` (`user@host(cfg:path)# `)
- **Verb Konsisten:**
  `show`, `set`, `unset`, `add`, `remove`, `commit`, `commit-confirm <menit>`, `confirm`, `rollback [rev]`, `diff`, `monitor`, `debug`
- **Bantuan Kontekstual & Pipa (`|`) :**
  - `?` untuk menampilkan sintaks, tipe data, `impact` perubahan, dan deskripsi langsung dari `schema/daijios.schema.json`.
  - Pipe filter: `| include <pola>`, `| exclude <pola>`, `| count`, `| json`.

---

## 2. Perintah Utilitas Sistem (`daiji-ctl`)
| Subperintah | Fungsi Utama |
|---|---|
| `daiji-ctl banner` / `about` | Cetak identitas resmi DaijiOS, versi, & profil target (`appliance`/`chr-vm`/`embedded`) |
| `daiji-ctl schema <validate\|export-cli\|export-ui\|export-openapi>` | Validasi SSoT JSON Schema & proyeksi otomatis CLI/UI/OpenAPI |
| `daiji-ctl config <init\|show\|set\|diff\|commit\|commit-confirm\|confirm\|rollback\|save\|revisions\|verify-audit>` | Siklus transactional config & verifikasi integritas audit hash-chain |
| `daiji-ctl net <plan\|render-frr\|render-kea\|render-keepalived>` | Generator konfigurasi L2/L3, OSPF/BGP, DHCP, dan VRRP |
| `daiji-ctl sec <render-nft\|render-qos\|render-vpn\|audit-check>` | Generator nftables stateful firewall, QoS CAKE/HTB, WireGuard/IPsec, & audit |
| `daiji-ctl isp <render-accel\|render-mwan\|render-snmp\|run-script\|bw-test>` | PPPoE/Hotspot BNG, Multi-WAN failover, SNMP, & interpreter `DaijiScript` |
| `daiji-ctl wlan <render-hostapd\|render-mesh\|render-nft\|rrm-solve>` | Controller WiFi hostapd, 802.11s mesh, & solver RRM auto-channel/power |
| `daiji-ctl cli <export-command-schema\|search\|exec>` | Skema CLI JSON, fuzzy search perintah, & eksekusi skrip headless |
| `daiji-ctl web check` | Validasi embedded SPA gzipped, kontras a11y, & binding WS |
| `daiji-ctl mobile qr-onboard` | Pembuat payload QR onboarding Daimo (`local`/`cloud`) |
| `daiji-ctl acs templates` | Daftar template vendor CPE (`ZTE`, `Huawei`, `FiberHome`, `TR-181`) |
| `daiji-ctl billing simulate-cycle` | Simulasi tagihan bulanan prorata, isolir CoA, & ledger SHA-256 |
| `daiji-ctl cloud dr-check` | Uji ekspor/impor snapshot Disaster Recovery DaijiCloud |
| `daiji-ctl portal license-demo` | Demo invoice SaaS & penandatanganan sertifikat offline `DJLIC1.*` Ed25519 |
| `daiji-ctl release <manifest\|verify\|soak>` | Generate/verifikasi `SHA256SUMS` + manifest Ed25519 & jalankan soak test 72 jam |
| `daiji-ctl ab status --state-dir <dir>` | Status boot slot A/B dan kesehatan pembaruan |

---

## 3. Direktori REST API Ekosistem
Seluruh endpoint mutasi wajib menyertakan `Authorization: Bearer <JWT>` (`pkg/secauth.TokenManager`) yang diperiksa oleh `RBACPolicy` (`superadmin`, `netadmin`, `operator`, `readonly`):

- **DaiWeb (`:8443`):** `/api/v1/health`, `/api/v1/telemetry`, `/api/v1/topology`, `/api/v1/wizard/apply`, `/api/v1/ws` (WebSocket telemetry/CLI).
- **DaiDesk (`:8080`):** `/api/v1/desk/sessions`, `/api/v1/desk/discover` (`DJDP1`), `/api/v1/desk/files`, `/api/v1/desk/bulk-apply`.
- **DaijiACS (`:7547`):** `/cwmp` (SOAP TR-069), `/usp` (JSON TR-369), `/api/v1/acs/devices`, `/api/v1/acs/tasks`, `/api/v1/acs/wifi`.
- **DaijiBilling (`:8060`):** `/api/v1/billing/{customers,plans,invoices,reconcile}`, `/api/v1/billing/webhooks/{midtrans,xendit,qris}`, `/api/v1/billing/portal/{id}`.
- **DaijiCloud (`:8050`):** `/api/v1/cloud/{orgs,sites,ztp/claim,ztp/adopt,devices,telemetry,rollouts,dr/snapshot}`, `/metrics`.
- **DaijiPortal (`:8070`):** `/api/v1/portal/{health,branding,marketplace,licenses/trial,licenses/purchase,licenses/activate-online,updates,tickets,kb}`.
