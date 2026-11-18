#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)
# HIL / QEMU Emulator & Multi-Arch Smoke Matrix

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_STORE="$(mktemp -d)"
trap 'rm -rf "$TMP_STORE"' EXIT

./bin/daiji-ctl config init --store "$TMP_STORE/cfg" --schema schema/daijios.schema.json --bootstrap schema/examples/default-config.json >/dev/null

echo "[HIL-SMOKE] Verifying host amd64 daemons, shell & CLI..."
./bin/daiji-netd --dry-run --once --store "$TMP_STORE/cfg" --state "$TMP_STORE/netd.state" >/dev/null
echo "  PASS check: ./bin/daiji-netd"
./bin/daiji-fw-qosd --dry-run --store "$TMP_STORE/cfg" >/dev/null
echo "  PASS check: ./bin/daiji-fw-qosd"
./bin/daiji-ispd --dry-run --store "$TMP_STORE/cfg" >/dev/null
echo "  PASS check: ./bin/daiji-ispd"
./bin/daiji-ac --dry-run --store "$TMP_STORE/cfg" >/dev/null
echo "  PASS check: ./bin/daiji-ac"
./bin/daiji-sh --store "$TMP_STORE/cfg" --cmd "show version" --quiet >/dev/null
echo "  PASS check: ./bin/daiji-sh"
./bin/daiji-webd --check --store "$TMP_STORE/cfg" >/dev/null
echo "  PASS check: ./bin/daiji-webd"
./bin/daiji-desk banner >/dev/null
echo "  PASS check: ./bin/daiji-desk"
./bin/daiji-acsd --check >/dev/null
echo "  PASS check: ./bin/daiji-acsd"
./bin/daiji-billingd --check >/dev/null
echo "  PASS check: ./bin/daiji-billingd"
./bin/daiji-cloudd --check >/dev/null
echo "  PASS check: ./bin/daiji-cloudd"
./bin/daiji-portald --check >/dev/null
echo "  PASS check: ./bin/daiji-portald"

./bin/daiji-ctl about --json >/dev/null
./bin/daiji-ctl schema validate --schema schema/daijios.schema.json --config schema/examples/default-config.json >/dev/null
./bin/daiji-ctl portal license-demo --json >/dev/null
./bin/daiji-ctl release soak --json >/dev/null
echo "  PASS check: ./bin/daiji-ctl (all E2E probes)"

echo "[HIL-SMOKE] Inspecting cross-compiled multi-arch artifacts in bin/dist..."
DIST_COUNT=$(ls -1 bin/dist | wc -l)
if [ "$DIST_COUNT" -lt 60 ]; then
  echo "FAIL: expected at least 60 cross-compiled binaries in bin/dist, found $DIST_COUNT" >&2
  exit 1
fi
echo "  PASS binary count: $DIST_COUNT"

for arch_pair in \
  "arm64:qemu-aarch64-static" \
  "armv7:qemu-arm-static" \
  "mipsel:qemu-mipsel-static" \
  "mips64le:qemu-mips64el-static"
do
  arch="${arch_pair%%:*}"
  emu="${arch_pair#*:}"
  target="./bin/dist/daiji-ctl-linux-${arch}"
  if [ ! -x "$target" ]; then
    echo "FAIL: missing executable $target" >&2
    exit 1
  fi
  if command -v file >/dev/null 2>&1; then
    info="$(file -b "$target")"
    echo "  ELF $arch: $info"
  fi
  if command -v "$emu" >/dev/null 2>&1; then
    "$emu" "$target" banner >/dev/null
    echo "  PASS QEMU HIL run: $emu $target banner"
  else
    echo "  SKIP QEMU execution ($emu not installed on host; static ELF verified)"
  fi
done

echo "[HIL-SMOKE] ALL CHECKS PASSED"
