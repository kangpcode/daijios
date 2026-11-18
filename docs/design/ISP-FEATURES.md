# Desain Fitur ISP, Telemetry, & DaijiScript (FASE 3)

## 1. Subscriber Access (PPPoE, IPoE, Hotspot) & AAA/RADIUS CoA
- **Terminasi BNG (`accel-ppp` + `FreeRADIUS`):** Skema SSoT v1.3.0 menyatukan profil bandwidth/burst, `ip_pools`, PPPoE server/client/secrets, IPoE (MAC/Option-82), Hotspot captive portal + walled garden, serta voucher ke dalam `ispreconcile` (`/etc/accel-ppp.conf`, `/etc/freeradius/3.0/clients.conf`, `/etc/nftables.d/daiji-mwan.nft`).
- **Session Lifecycle (`pkg/ispengine/sessions.go`):**
  - Memvalidasi *MAC binding* (`caller_mac`), batas *shared users*, voucher multi-device + kuota data MB, serta penanganan **expired-user** otomatis ke `expired_pool` (isolir) atau penolakan login.
  - **RADIUS & CoA Wire Engine (`pkg/ispengine/radius.go`):** Implementasi biner RFC 2865/2866/5176 UDP listener (default port `3799`) untuk `CoA-Request` (`Filter-Id: ISOLIR`, `Daiji-Rate-Limit`) dan `Disconnect-Request` secara langsung tanpa restart sesi lain.

## 2. Multi-WAN Load Balancing & Recursive/Netwatch Failover
- **`pkg/ispengine/multiwan.go`:** Setiap link WAN memantau satu atau lebih `check_targets` (`recursive`, `netwatch-icmp`, atau `http`). Link hanya turun (`wan-down`) jika seluruh target gagal berturut-turut sejumlah `fail_threshold`, dan pulih (`wan-up`) setelah `recover_threshold` kali lolos (anti-flap).
- **Load Balancing:** Mendukung mode `failover`, `load-balance-ecmp` (kernel weighted multipath), dan `load-balance-pcc` (`nftables` `jhash` 5-tuple + `ct mark` sticky session).

## 3. Diagnostics & Telemetry (`pkg/isptools`)
- **Command-Injection Safe Probes:** `PingArgs()` dan `TracerouteArgs()` memvalidasi target via `netip.ParseAddr` / RFC 1123 hostname sebelum memanggil argumen biner langsung (tanpa shell).
- **Torch & PCAP:** `TorchAggregator` mengurutkan flow Tx/Rx per-tuple berdasarkan bps; `WritePCAP` mengekspor berkas `libpcap` standar (`0xa1b2c3d4`) dengan filter protokol/port.
- **Bandwidth Test, IPFIX, SNMPv3, Syslog:** TCP socket throughput test aktif, konfigurasi `NetFlow/IPFIX`, `SNMPv3` (`SHA256`/`AES128`), serta `rsyslog` TCP/TLS.

## 4. DaijiScript, Scheduler, Event Hooks, REST API, & Webhooks (`pkg/daijiscript`)
- **DaijiScript Sandbox:** DSL berizin eksplisit (`read`, `write`, `net`, `diag`) dengan batas langkah eksekusi (`maxSteps=1000`) dan tanpa eksekusi shell arbitrer.
- **REST API & Signed Webhooks:** Router `net/http` dilindungi `secauth.TokenManager` + `RBACPolicy`; Webhook ditandatangani dengan `X-Daiji-Signature: sha256=<HMAC-SHA256>` serta proteksi SSRF (`169.254.0.0/16` & `metadata.google.internal` diblokir).
