# DaijiACS — TR-069 (CWMP) & TR-369 (USP) Auto-Configuration Server

**Brand:** DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)  
**Phase:** FASE 8 (DaijiACS)  
**Package:** `pkg/daijiacs` | **Daemon:** `daiji-acsd` (`services/daiji-acsd`)

---

## 1. Protokol Ganda: CWMP (TR-069) & USP (TR-369)

- **CWMP SOAP Engine (`/tr069`, `pkg/daijiacs/cwmp.go`):**
  - Parser & generator SOAP 1.1 / CWMP 1.0 pure stdlib Go (`encoding/xml`) berbatas ukuran envelope `512 KB` per request guna menangkis payload DoS.
  - Siklus sesi lengkap: `Inform` (`0 BOOTSTRAP`, `1 BOOT`, `2 PERIODIC`, `4 VALUE CHANGE`) -> `InformResponse` + session cookie `daiji_cwmp_sid` -> dispatch antrean RPC (`GetParameterValues`, `SetParameterValues`, `Download`, `Reboot`, `FactoryReset`) -> penutupan `204 No Content`.
- **TR-369 USP Endpoint (`/usp`, terproteksi token RBAC):**
  - Menerima pesan JSON MTP (`GET`, `SET`, `OPERATE`: `Reboot`, `FactoryReset`, `FirmwareUpgrade`) yang dipetakan ke inventori CPE dan template vendor yang sama.

---

## 2. Device Templates, Virtual Parameters & Presets

- **Template Multi-Vendor (`DefaultVendorTemplates` di `pkg/daijiacs/templates.go`):**
  - `zte-igd-v1` (`ZTE` TR-098, `X_ZTE-COM_WANPONInterfaceConfig.RXPower`)
  - `huawei-ont-v1` (`Huawei` TR-098, `PreSharedKey.1.PreSharedKey`, `X_HW_DEBUG.AMP.Optic.RxPower` berskala `0.01 dBm`)
  - `fiberhome-ont-v1` (`FiberHome` TR-098, `X_FH_OpticalInterface.RxPower`)
  - `generic-tr181` (`Device:2` untuk CPE TR-181 / USP modern)
- **Virtual Parameters (`ExtractVirtualParams` & `ResolveVirtualSet`):**
  - Menormalkan field lintas-vendor ke kunci kanonik `virtual.wifi.ssid`, `virtual.wifi.passphrase` (disamarkan otomatis untuk role non-superadmin), `virtual.wifi.enabled`, `virtual.wan.ip`, `virtual.wan.pppoe_user`, dan `virtual.optical.rx_dbm`.
- **Idempotent Presets (`applyPresetsLocked`):**
  - Aturan policy berbasis `PolicyVersion`, `VendorFilter`, dan `EventFilter` mengeksekusi konfigurasi otomatis hanya satu kali per versi policy tanpa pengulangan pada setiap periodic inform.

---

## 3. Integrasi WiFi Pelanggan (Daimo/DaiWeb), Billing & Monitoring

- **WiFi API (`POST /api/v1/acs/devices/{serial}/wifi`):** Mengubah SSID & passphrase WPA pelanggan langsung dari Daimo Mobile atau DaiWeb sesuai template vendor CPE dan menyamarkan passphrase dari respons & audit.
- **Billing Hook (`POST /api/v1/acs/devices/{serial}/billing-state`):** Memicu `suspend` (`isolir` menonaktifkan WAN PPPoE CPE) atau `activate` secara otomatis — siap dihubungkan ke mesin **DaijiBilling** (Fase 9).
- **Monitoring Optik & Kesehatan (`GET /api/v1/acs/monitoring`):** Melacak status online/offline, distribusi vendor, dan memicu alarm sinyal optik lemah apabila `rx_dbm < -27.0 dBm`.
