# Desain Firewall, QoS, VPN & Security Hardening (FASE 2)

## 1. Stateful Firewall, L7/DPI, & Atomic `nftables`
- Seluruh aturan filter, NAT, mangle/mark, address-list (`set`), dynamic brute-force ban (`daiji_ban_v4`/`v6` dengan timeout otomatis), serta L2 bridge port-security di-render menjadi satu berkas transaksi atomik `/etc/nftables.d/daiji.nft` dan dimuat via `nft -f` agar tidak ada celah *drop-less/gap* selama pembaruan aturan.
- **Perlindungan Injeksi Template:** `secplan.ValidateSecuritySemantic` dan `sanitizeNFT` menolak karakter `\r`, `\n`, `\x00`, `;`, `{`, `}`, dan kutipan tidak aman pada komentar maupun log prefix.

## 2. QoS Shaping (`HTB`, `CAKE`, `fq_codel`, `Queue Tree`, `Simple Queue`, `PCQ`)
- Mendukung `cake` (diffserv4 + RTT + overhead + NAT mode), `fq_codel`, dan pohon kelas `HTB` bertingkat yang dikaitkan ke firewall `fwmark`.
- Pembatasan ingress (`download_kbps`) direkonsiliasi menggunakan antarmuka virtual `ifb-<iface>` + `tc mirred redirect`.
- `Simple Queue` mendukung burst (`burst_download_kbps`, `burst_time_sec`) dan mode keadilan per-pelanggan **PCQ-like** menggunakan isolasi host `cake dual-dsthost flows`.

## 3. Multi-Protocol VPN (`WireGuard`, `IPsec IKEv2`, `OpenVPN`, `L2TP`, `PPTP`, `SSTP`, `EoIP`)
- Seluruh rahasia (`private_key`, `preshared_key`, `psk`, `ipsec_psk`, `tls_crypt_key`) ditandai `x-daiji-secret: true` di skema SSoT, disimpan pada file `0600`, serta otomatis dimask sebagai `***REDACTED***` di CLI/audit.
- **PPTP Safety Gate:** Protokol legacy PPTP diblokir secara semantik kecuali operator secara eksplisit menyetujui risiko lewat `legacy_acknowledged: true`.
- **EoIP-like L2 Tunnel:** Diimplementasikan menggunakan standar Linux `gretap` berkunci 32-bit (`tunnel_id`) sehingga dapat di-bridge lintas-site tanpa kode proprietary.

## 4. OS Hardening & Kontrol Akses (`pkg/secauth`)
- **Least-Privilege RBAC (`rbac.go`):** Memisahkan hak `superadmin`, `netadmin`, `operator`, `auditor`, dan `readonly` (hanya `superadmin` yang dapat membaca secret atau mengelola kunci).
- **2FA TOTP RFC 6238 (`totp.go`):** Perbandingan *constant-time* + pelacakan `lastUsedStep` untuk menolak serangan *OTP replay*.
- **Scoped Bearer Tokens (`tokens.go`):** Token `djt1.*` bertanda tangan HMAC-SHA256 dengan batas TTL, pemeriksaan scope per-operasi, serta daftar revokasi (`jti`).
- **Brute-Force Guard (`bruteforce.go`):** Jendela geser per IP dengan pengecualian subnet tepercaya (`Whitelist`) agar admin NOC tidak pernah terkunci, sekaligus memicu `nft add element` ban sementara.
- **Secure Boot & Signed Firmware:** Terintegrasi dengan `pkg/abupdate` & `pkg/pkgmgr` (Ed25519 + SHA-256 + anti-downgrade `SecurityEpoch`).
