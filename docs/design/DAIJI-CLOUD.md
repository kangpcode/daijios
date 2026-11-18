# DaijiCloud — Multi-Tenant Fleet Control Plane, Canary Rollout & Observability

**Brand:** DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)  
**Phase:** FASE 10 (DaijiCloud)  
**Package:** `pkg/daijicloud` | **Daemon:** `daiji-cloudd` (`services/daiji-cloudd`)

---

## 1. Isolasi Multi-Tenant (`Org -> Site -> Device`) & ZTP

- **Tenant-Scoped RBAC (`AuthorizeTenant`):** Setiap operator terikat ke `OrgID`, opsional `SiteID`, dan peran RBAC (`secauth.RBACPolicy`). Permintaan lintas-organisasi atau lintas-site ditolak `403 Forbidden`.
- **Zero-Touch Provisioning (`CreateZTPClaimToken`, `AdoptViaZTP`):** Token ZTP berformat `ztp1.<org>.<site>.<serial>.<nonce>.<exp>.<hmac>` ditandatangani HMAC-SHA256, memiliki batas kedaluwarsa (`TTL`), dan hanya bisa diklaim satu kali (*anti-replay*).

---

## 2. Monitoring, Alert Rules, Config Versioning, Tunnels & Canary Firmware

- **Alert Engine (`AddAlertRule`, `IngestTelemetry`):** Mengevaluasi metrik CPU, RAM, suhu secara real-time per tenant; menembakkan `CloudAlert` (`open`) saat ambang batas terlampaui dan otomatis menutupnya (`resolved`) saat pulih.
- **Versioned Cloud Config Backup (`UploadConfigBackup`, `RestoreConfigVersion`) & Disaster Recovery (`ExportDisasterRecoverySnapshot`, `RestoreDisasterRecoverySnapshot`):** Setiap snapshot backup perangkat di-hash SHA-256, sedangkan DR snapshot seluruh kluster bertanda tangan HMAC-SHA256 untuk pemulihan penuh ke instance standby baru.
- **Remote Tunnel Aman (`OpenRemoteTunnel`):** Membuka sesi tunnel terautentikasi HMAC-SHA256 untuk manajemen perangkat di balik NAT/CGNAT.
- **Staged Canary Fleet Rollout (`StartCanaryRollout`, `ReportRolloutResult`):**
  1. Tahap 1 hanya memperbarui subset Canary (`canary_percent`, min 1 perangkat).
  2. Jika rasio kegagalan Canary melampaui `max_failure_pct`, rollout langsung beralih ke `halted_rollback` tanpa menyentuh sisa armada (`skipped_rollback`).
  3. Bila Canary lolos 100%, rollout promosi ke tahap `fleet` hingga `completed`.

---

## 3. Public API, Go SDK & Observability

- **Public REST API + `ClientSDK`:** Endpoint terversi `/api/v1/cloud/orgs/{orgID}/{devices|ztp-claims|alerts|rollouts}` bersama SDK client Go typed (`pkg/daijicloud/sdk_api.go`).
- **Tiga Pilar Observability (`pkg/daijicloud/observability.go`):**
  - **Metrics:** Eksposisi Prometheus `/metrics` (`daijicloud_devices_total`, `daijicloud_alerts_open`, `daijicloud_http_requests_total`, `daijicloud_rollouts_total`).
  - **Structured Logs & Distributed Tracing:** Ring buffer JSON logs & `TraceSpan` bertautan `X-Trace-ID` di `/api/v1/cloud/observability/traces`.
