# DaijiBilling — Tagihan Bulanan PPPoE, Auto-Isolir, Payment Webhooks & Ledger Audit

**Brand:** DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)  
**Phase:** FASE 9 (DaijiBilling)  
**Package:** `pkg/daijibilling` | **Daemon:** `daiji-billingd` (`services/daiji-billingd`)

---

## 1. Siklus Tagihan, Prorata & Invoice Otomatis

- **Aritmetika Bilangan Bulat Deterministik:** Seluruh nominal tarif, prorata, diskon, denda keterlambatan, pajak (`TaxRatePct`), dan komisi reseller dihitung dalam integer (`*Cents` / Rupiah utuh) tanpa drift *floating-point*.
- **Dua Jenis Siklus (`CycleType`):**
  - `fixed-day`: jatuh tempo seragam (`FixedBillingDay + GraceDays`, otomatis memperpanjang masa tenggang bagi pelanggan baru yang aktif di tengah bulan agar terhindar dari isolir instan).
  - `anniversary`: berjangkar pada tanggal aktivasi pelanggan.
- **Prorata & Idempotensi:** Pelanggan yang aktif via PPPoE (`OnPPPoESessionActive`) menerima invoice proporsional `(prorataDays / cycleTotalDays)`, diindeks unik `(customer_id | YYYY-MM)` agar penagihan batch bulanan tak pernah menerbitkan faktur ganda.

---

## 2. Auto-Isolir & Auto-Reaktivasi Terpadu

1. **Auto-Isolir (`EnforceOverdueIsolation`):**
   - Menambahkan `LateFeeCents` sekali saja ketika invoice melewati `DueDate`, mengubah status menjadi `overdue` & `isolated`.
   - Mengirim **RADIUS `CoA-Request`** (`AttrFilterID = "ISOLIR"` -> throttle `64/64 kbps`) ke `ispengine.SessionManager`.
   - Memanggil `daijiacs.Server.ApplyBillingAction(cpe_serial, "suspend")` bila ONT TR-069 terikat.
2. **Auto-Reaktivasi (`MarkInvoicePaid`):**
   - Saat seluruh tagihan lewat batas lunas, mengembalikan status pelanggan ke `active`, mengirim `CoA-Request` (`AttrFilterID = "ACTIVE"` + `AddDaijiRateLimit` kecepatan profil penuh), mengaktifkan ONT TR-069, dan mengirim notifikasi konfirmasi.

---

## 3. Payment Gateway, Portal Pelanggan, Multi-Reseller & Audit Ledger

- **Gateway Terverifikasi:**
  - **Midtrans:** `SHA512(order_id + status_code + gross_amount + ServerKey)` constant-time (`VerifyMidtransSignature`).
  - **Xendit:** header `X-Callback-Token` constant-time.
  - **QRIS / VA:** HMAC-SHA256 atas raw payload + instruksi kode `BuildCheckout`.
  - **Transfer Manual:** konfirmasi admin via `POST /api/v1/billing/manual-confirm`, dengan proteksi anti-replay `PaymentRef` lintas invoice.
- **Notifikasi, Portal, Laporan & Rekonsiliasi:**
  - `notifyCustomer` menyalurkan peristiwa lewat `whatsapp`, `sms`, dan `email`.
  - **Portal Pelanggan (`/portal`, `/portal/invoices`, `/portal/checkout`):** token HMAC terikat ketat ke masing-masing `customer_id`.
  - **Laporan & Multi-Reseller (`GenerateFinancialReport` & `ReconcilePayments`):** merinci pemasukan bruto, pajak, denda, omzet/komisi tiap reseller, serta mencocokkan mutasi bank eksternal.
  - **Immutable Audit Ledger (`VerifyAuditChain`):** setiap mutasi transaksi membentuk rantai **SHA-256 hash chain** yang mendeteksi modifikasi retrospektif secara instan.
