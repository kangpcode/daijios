# Target Hardware & Pipeline Buildroot / Image CHR (FASE 0)

Dokumen ini mendefinisikan profil target build untuk image DaijiOS agar satu codebase control/management plane dapat berjalan konsisten di perangkat keras bare-metal, embedded CPE, dan hypervisor cloud.

## 1. Profil Build Target

1. **`x86_64-appliance` (`GOARCH=amd64`)**
   - Bootloader: GRUB2 (Dual BIOS + UEFI Secure Boot ready)
   - Partisi: `ESP (256MB)` + `BOOTENV (16MB)` + `ROOTFS-A (1GB SquashFS)` + `ROOTFS-B (1GB SquashFS)` + `/data` (ext4/f2fs rw)
   - Driver Kernel Wajib: `igb`, `igc`, `ixgbe`, `i40e`, `ice`, `mlx5_core`, `r8169`, `bonding`, `8021q`, `vrf`, `nf_tables`, `sch_cake`, `wireguard`.

2. **`x86_64-chr` & `arm64-chr` (Cloud Hosted Router Image)**
   - Format Distribusi: `.qcow2`, `.vmdk`, `.vhdx`, `.raw`, `.iso`
   - Driver Virtualisasi Wajib: `virtio_net`, `virtio_blk`, `virtio_scsi`, `vmxnet3`, `hv_netvsc`, `ena`, `nvme`.
   - Zero-Touch Provisioning: Dukungan cloud-init / NoCloud seed untuk injeksi SSH key & enrollment token `DaijiCloud`.

3. **`arm64-embedded` (`GOARCH=arm64`)**
   - SoC Target: MediaTek Filogic 830/880, Rockchip RK3568/RK3588, NXP Layerscape, Raspberry Pi CM4/CM5.
   - Bootloader: U-Boot FIT uImage + `fw_setenv` A/B slot switching.

4. **`armv7-embedded` (`GOARCH=arm GOARM=7`)**
   - SoC Target: Qualcomm IPQ40xx/IPQ60xx, Marvell Armada 385.

5. **`mipsel-embedded` (`GOARCH=mipsle GOMIPS=softfloat`)**
   - SoC Target: MediaTek MT7621AT/DA (5-port DSA Gigabit switch + Dual-core MIPS 1004Kc).
   - Penyimpanan: SPI NOR/NAND Flash menggunakan UBI/UBIFS volume `rootfs_a`, `rootfs_b`, dan `data`.
   - Optimasi Memori: Binary Go di-strip (`-s -w -trimpath`), limit `GOMEMLIMIT=48MiB` untuk perangkat RAM 128 MB.
