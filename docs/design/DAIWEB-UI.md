# DaiWeb — Embedded Real-Time Web UI & Design System Architecture

**Brand:** DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)  
**Phase:** FASE 6 (DaiWeb Bawaan)  
**Server Binary:** `daiji-webd` (`services/daiji-webd`) & library `pkg/daiweb`  
**SSoT Binding:** `schema/daijios.schema.json` (`management.daiweb.*`, `x-daiji-ui`, `x-daiji-secret`)

---

## 1. Original Visual Design System (*Obsidian Circuit & Jade Impulse*)

DaiWeb dirancang 100% orisinal tanpa kerangka CSS/UI eksternal dan tanpa meniru tampilan vendor mana pun. Seluruh token visual dikontrol terpusat di [`assets/tokens.css`](../../pkg/daiweb/assets/tokens.css) dengan prefix namespace `--daiji-*`:

- **Tema `daiji-dark` (Default):** Kanvas obsidian slate (`#0b0f14`), permukaan berlapis (`#111821`, `#18222e`), aksen **Daiji Jade** (`#18c996`) bertulisan kontras `#071a14`, teks utama `#edf2f7` (`15.85:1`), muted `#98a8bc` (`7.36:1`).
- **Tema `daiji-light`:** Kertas alabaster (`#f5f7f9`), kartu putih (`#ffffff`), aksen Jade pekat (`#097a5b`) bertulisan `#ffffff` (`5.32:1`), teks utama `#111922` (`17.71:1`), muted `#4a5a6d` (`7.06:1`).
- **Mode `system`:** Mengikuti `prefers-color-scheme` browser serta mendukung `prefers-reduced-motion: reduce`.
- **I18n (ID / EN):** Penggantian bahasa *real-time* antara Bahasa Indonesia (`id`, default) dan English (`en`) dengan paritas kunci teruji otomatis.

---

## 2. Modul Fungsional & Protokol Real-Time

1. **Dashboard Real-Time (`/ws/telemetry`, RFC 6455):**
   - Server WebSocket stdlib murni di `pkg/daiweb/ws.go` mendorong snapshot berkala (`TelemetrySnapshot`: beban CPU `/proc/loadavg`, pemakaian RAM `/proc/meminfo`, throughput Rx/Tx dari `isptools.TorchAggregator`, jumlah sesi PPPoE/Hotspot dari `ispengine.SessionManager`, status Multi-WAN, alarm, dan entri revisi audit terbaru) dengan fallback otomatis ke REST polling `/api/v1/telemetry/snapshot`.
2. **Topologi Interaktif (`/api/v1/topology`):**
   - Graf SVG dinamis memvisualisasikan simpul inti, interface fisik, bridge L2, uplink Multi-WAN, peer VPN WireGuard, dan AP terkelola (`wlanctrl.ACController`) beserta inspektor detail berbasis keyboard (`Enter`/`Space`) maupun klik.
3. **5 Wizard Konfigurasi Transaksional (`/api/v1/wizards/apply`):**
   - Wizard terpandu untuk **WAN**, **LAN**, **PPPoE Server**, **VPN WireGuard**, dan **Firewall Filter** — semuanya memvalidasi kandidat terhadap SSoT JSON Schema + Validator Semantik (`wlanplan.ValidateAllSemantic`), mendukung **Dry-Run Preview Diff** (rahasia disamarkan rekursif via `configengine.RedactDiff`), sebelum `commit` atomik.
4. **Terminal CLI Orisinal di Browser (`/ws/cli`):**
   - Mengikat langsung ke [`daijicli.Session`](../../pkg/daijicli/session.go) dengan mempertahankan hak RBAC pengguna terautentikasi, mendukung tombol `Tab` (`complete`), `?` contextual help, riwayat perintah (`ArrowUp`), dan transisi mode `>` -> `#` -> `(cfg)#`.
5. **Penjelajah Skema SSoT (`/api/v1/ui-schema`):**
   - Menampilkan katalog field `ExtractUISchema()` (`group`, `widget`, `impact`, `rbac`) langsung dari Fase 0.

---

## 3. Keamanan & Performa pada Perangkat Low-End

- **Zero External Build / Zero CDN:** Seluruh SPA (HTML5 + CSS + Vanilla ES6 + SVG) tertanam via `//go:embed` ke binary Go statis, terkompresi `gzip -9` di RAM (`~11.3 KB` gzip total, `~39.2 KB` mentah), dan mendukung validasi `ETag` `304 Not Modified`.
- **Pertahanan HTTP & WebSocket:** Header ketat `Content-Security-Policy` (tanpa inline script), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, validasi `Origin` same-host (anti-CSWSH), cookie `HttpOnly; SameSite=Strict`, RFC 6238 TOTP opsional, dan `secauth.BruteForceGuard`.
