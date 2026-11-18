# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

**DaijiOS (`v1.2.0-lts`)** adalah platform Network Operating System (NOS) terintegrasi beserta ekosistem manajemen terpusat untuk ISP, enterprise, dan campus — dibangun dari Go murni (`CGO_ENABLED=0`, nol dependensi eksternal) di atas fondasi Linux networking & single-source-of-truth JSON Schema (`schema/daijios.schema.json`).

---

## Komponen Ekosistem

| Komponen | Binary / Paket | Peran Utama |
|---|---|---|
| **DaijiOS Core** | `daiji-netd`, `daiji-fw-qosd`, `daiji-ispd`, `daiji-ac`, `daiji-ctl` | L2/L3 routing (OSPF/BGP/VRF/VRRP), stateful firewall (`nftables`), QoS (`CAKE`/`HTB`), VPN (WireGuard/IPsec/VXLAN), PPPoE/Hotspot BNG, Wireless Controller (`802.11k/v/r` & mesh), A/B safe rollback |
| **DaijiSH** | `daiji-sh` | CLI orisinal DaijiOS (`user`/`privileged`/`config`/`sub-config`), `?` contextual help, tab-completion, `| include/exclude/count/json` |
| **DaiWeb** | `daiji-webd` | Embedded Web UI real-time via WebSocket (`:8443`), wizard WAN/LAN/PPPoE/Firewall, dark/light, i18n ID/EN |
| **Daimo & DaiDesk** | `daiji-desk`, `pkg/daimo`, `pkg/daidiscovery` | Onboarding QR mobile, penemuan L2 `DJDP1` (UDP `:56780`), workspace multi-tab, SFTP jailed file manager, bulk config |
| **DaijiACS** | `daiji-acsd` | ACS TR-069 (CWMP SOAP `:7547`) & TR-369 (USP JSON) untuk ONT/CPE ZTE, Huawei, FiberHome, TR-181 |
| **DaijiBilling** | `daiji-billingd` | Tagihan ISP bulanan (`:8090`, siklus tetap/anniversary + prorata), auto-isolir RADIUS CoA, webhook Midtrans/Xendit/QRIS, ledger SHA-256 |
| **DaijiCloud** | `daiji-cloudd` | Kontrol multi-tenant `Org → Site → Device` (`:8080`), ZTP token adoption, alert telemetry, canary rollout, DR snapshot |
| **DaijiPortal** | `daiji-portald` | SaaS pusat (`:8070`): white-label reseller, lisensi online/offline **Ed25519 (`DJLIC1.*`)**, marketplace SKU, signed updates (`stable`/`beta`/`lts`), tiket & KB |

---

## Quick Start

### Persyaratan
- Go `1.27+` (linux host untuk build & verifikasi; target lintas arsitektur statis tersedia untuk `amd64`, `arm64`, `armv7`, `mipsel`, `mips64le`).

### Build & Verifikasi Lokal
```bash
# Static analysis, test suite (-race), coverage & 72h simulated soak
make vet
make test-race

# Parser fuzzing (CLI, DaijiPortal API/DJLIC1, CWMP SOAP, JSON Schema)
make fuzz

# Build seluruh 12 biner host
make build
./bin/daiji-ctl about --json
```

### Cross-Build Multi-Arsitektur & Bundel Rilis LTS (`v1.2.0-lts`)
```bash
# Opsional: generate kunci rilis Ed25519 persisten (PKCS#8 PEM)
./bin/daiji-ctl release keygen --out release.key.pem --pub-out release.pub.pem

# Build 60 biner statis (12 tools × 5 arsitektur), jalankan HIL smoke, tanda tangani manifest & SHA256SUMS
DAIJI_RELEASE_KEY_FILE=release.key.pem DAIJI_RELEASE_PUB_FILE=release.pub.pem \
  make release VERSION=1.2.0-lts
```

---

## Indeks Dokumentasi

- **Arsitektur & Desain:** [`docs/architecture/FASE-0-ARCHITECTURE.md`](docs/architecture/FASE-0-ARCHITECTURE.md) & [`docs/design/`](docs/design/)
- **Panduan User & Admin:** [`docs/operations/USER-AND-ADMIN-GUIDE.md`](docs/operations/USER-AND-ADMIN-GUIDE.md)
- **Referensi CLI & API:** [`docs/operations/API-AND-CLI-REFERENCE.md`](docs/operations/API-AND-CLI-REFERENCE.md)
- **Kurikulum Pelatihan (`DCNA` / `DCNP` / `DCNE`):** [`docs/operations/TRAINING-CURRICULUM.md`](docs/operations/TRAINING-CURRICULUM.md)
- **Rencana LTS, Security Advisory, & Bug Bounty:** [`docs/operations/LTS-AND-SECURITY-POLICY.md`](docs/operations/LTS-AND-SECURITY-POLICY.md)
- **Laporan Audit Gate (`0` s/d `FINAL`):** [`docs/audits/AUDIT-GATE-FINAL.md`](docs/audits/AUDIT-GATE-FINAL.md)
- **Lisensi Komponen Pihak Ketiga:** [`docs/compliance/THIRD-PARTY-LICENSES.md`](docs/compliance/THIRD-PARTY-LICENSES.md)

---

## Lisensi & Atribusi

Dilisensikan di bawah **Apache-2.0** ([LICENSE](LICENSE)).  
Seluruh komponen, antarmuka CLI/Web, dan dokumen rilis resmi membawa identitas proyek: **`DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)`**.
