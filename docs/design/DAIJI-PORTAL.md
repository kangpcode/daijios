# DaijiPortal — Central SaaS, White-Label Reseller, Ed25519 Licensing & Update Channels

**Brand:** DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)  
**Phase:** FASE 11 (DaijiPortal SaaS Pusat)  
**Package:** `pkg/daijiportal` | **Daemon:** `daiji-portald` (`services/daiji-portald`)

---

## 1. White-Label Reseller Branding

- `SetWhiteLabelBranding` & `ResolveBrandingByHost` menyesuaikan `OSName`, `PortalTitle`, `LogoURL`, `PrimaryColor`, `AccentColor` per domain reseller sambil menjaga footer merek ekosistem **`DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)`**.
- Seluruh field branding memfilter HTML tag `<>"` serta menolak skema URL berbahaya (`javascript:`).

---

## 2. Lisensi Asimetris Ed25519 (`Free` / `Pro` / `Enterprise`, Online & Offline Anti-Tamper)

- **Portable Offline Certificate (`DJLIC1.<payload>.<ed25519_sig>`):**
  - Perangkat *offline/air-gapped* hanya menyimpan **Ed25519 Public Key** sehingga tidak dapat memalsukan lisensi baru secara lokal.
  - `VerifyOfflineLicense` memvalidasi integritas tanda tangan kriptografis, tanggal kedaluwarsa (`ExpiresAt`), sidik jari perangkat keras (`HardwareID`, anti-klon), kuota perangkat (`MaxDevices`), dan daftar fitur per tier (`EnabledFeatures`).
- **Online Activation & Revocation (`ActivateOnline`, `RevokeLicense`):** Mengikat aktivasi online ke `HardwareID` serta memblokir sertifikat yang dicabut (`ErrLicenseRevoked`).

---

## 3. Marketplace, Update Channels (`stable`/`beta`/`lts`), Support & KB

- **Marketplace & Trial Anti-Farming:** SKU `sku-free`, `sku-pro`, dan `sku-ent` lengkap dengan perhitungan faktur otomatis, pembagian margin reseller 20%, serta pembatasan *single trial* per `(org_id | hardware_id)`.
- **Signed Update Channels (`PublishRelease`, `VerifyRelease`):** Distribusi release ke channel `stable`, `beta`, dan `lts` beserta changelog dan tanda tangan Ed25519 atas `(version | channel | https_url | sha256)`.
- **Support Tickets & Bilingual KB:** Manajemen tiket bantuan per tenant/reseller serta pencarian artikel Knowledge Base `id`/`en`.
