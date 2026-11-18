# DaijiOS Original CLI Architecture & Command Schema

**Brand:** DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)  
**Phase:** FASE 5 (CLI Orisinal DaijiOS)  
**SSoT Schema Version:** `1.4.0` (`schema/daijios.schema.json`)  
**Generated Command Schema:** `schema/cli-commands.schema.json` (`daiji-ctl cli export-command-schema`)

---

## 1. Filosofi Desain Orisinal DaijiOS CLI

CLI DaijiOS (`daiji-sh` dan paket `pkg/daijicli`) dirancang orisinal sejak awal—tidak meniru sintaks CLI proprietary vendor mana pun—dan terikat langsung ke **Single Source of Truth (SSoT)** `schema/daijios.schema.json`. Setiap kali schema data berubah pada fase mendatang, pohon perintah, tab-completion, `?` contextual help, dan fuzzy search otomatis tersinkronisasi tanpa duplikasi parser manual.

Prinsip inti:
1. **Hierarki Mode Eksplisit & RBAC:** Operasi baca (*observability*), diagnostik istimewa (*privileged*), perubahan konfigurasi transaksional (*config*), dan navigasi kontainer bertingkat (*sub-config*) dipisahkan jelas beserta validasi `secauth.RBACPolicy`.
2. **Transaksional (`candidate` -> `diff` -> `validate` -> `commit` / `commit-confirm`):** Semua modifikasi `set`/`unset`/`add`/`remove` selalu masuk ke kandidat, tidak langsung menyentuh state aktif sebelum `commit`, dan rahasia (`password_hash`, `secret`, `private_key`, `token`) disamarkan otomatis pada `diff` maupun `history`.
3. **Output Ganda (Human & JSON) + Pipe Rantai (`|`):** Operator manusia melihat tabel/ringkasan ringkas, sementara skrip/otomasi dapat menyambungkan `| include`, `| exclude`, `| count`, dan `| json`.

---

## 2. Hierarki Mode & Prompt

| Mode | Prompt | Role Minimum | Deskripsi & Transisi |
| :--- | :--- | :--- | :--- |
| `user` | `<actor>@<host>> ` | `readonly` | Inspeksi dasar (`show version`, `show running`, `show interfaces`, `search`, `monitor`). Naik dengan `enable`. |
| `privileged` | `<actor>@<host># ` | `operator` | Inspeksi startup/revisi (`show startup`, `show revisions`, `show audit-verify`), `debug`, `save`, serta masuk konfigurasi via `config`. Turun dengan `disable` / `exit`. |
| `config` | `<actor>@<host>(cfg)# ` | `netadmin` | Root transaksi konfigurasi: `set`, `unset`, `add`, `remove`, `diff`, `validate`, `commit`, `commit-confirm`, `confirm`, `rollback`, `discard`, `enter`. Keluar ke `privileged` via `exit`. |
| `sub-config` | `<actor>@<host>(cfg:<ctx>)# ` | `netadmin` | Cakupan kontainer (`enter management`, `enter management.ssh`, `enter system`, dll.) dengan resolusi path relatif otomatis. Navigasi via `up`, `top`, atau `exit`. |

---

## 3. Kata Kerja Konsisten (*Canonical Verbs*) & Pipa (*Pipes*)

### 3.1 Verb Utama
- **Observasi & Diagnostik:** `show <target|dot.path>`, `monitor <traffic|torch|topic>`, `debug <config-tree|topic>`, `search <keyword>`
- **Mutasi Kandidat (Config/Sub-Config):** `set <path> <val>`, `unset <path>`, `add <array-path> <elem>`, `remove <array-path> <key|idx>`
- **Siklus Transaksi & Pemulihan:** `diff`, `validate`, `discard`, `commit [msg]`, `commit-confirm [sec]`, `confirm`, `rollback <rev|offset> [--commit]`, `save`
- **Produktivitas Shell:** `alias [name cmd...]`, `unalias <name>`, `history`, `!N` (recall), `<prefix>?` / `help`, `/tab <prefix>` / `<prefix>\t` (completion)

### 3.2 Operator Pipe (`|`)
Pipe menghormati tanda kutip (`"..."` / `'...'`) pada nilai argumen sebelum memecah tahap filter:
- `| include <substr>` — menyaring baris mengandung substring (case-insensitive)
- `| exclude <substr>` — membuang baris mengandung substring (case-insensitive)
- `| count` — menghitung jumlah baris non-kosong
- `| json` — merender objek terstruktur ke JSON terindentasi (`2 spaces`)

---

## 4. Mekanisme Interaktif & Portabilitas Multi-Arsitektur

- **`daijicli.BuildRegistry(cs)` & `BuildCommandSchema(cs)`:** Menelusuri seluruh `$defs`, properti objek, dan elemen array `[*]` dari `schema/daijios.schema.json` menjadi indeks path lengkap beserta metadata (`type`, `enum`, `secret`, `rbac`, `impact`, `description`, dan `x-daiji-cli` mapping).
- **`FuzzySearch(query, limit)`:** Peringkat kecocokan deterministik berbasis skor: exact path (`1000`), suffix/prefix (`700 - len`), substring (`500 - len`), subsequence terurut seperti `syshn -> system.hostname` (`250 - len`), dan deskripsi (`150`).
- **Portabilitas `services/daiji-sh`:** Tidak menggunakan struct `syscall.Termios` spesifik OS/arsitektur agar kompilasi statis `CGO_ENABLED=0` berjalan mulus dan seragam di `amd64`, `arm64`, `armv7`, `mipsel` (`softfloat`), maupun `mips64le`, mendukung baik mode REPL interaktif maupun batch (`--cmd "..."`).
