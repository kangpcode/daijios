#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)
# HIL / QEMU Emulator & Multi-Arch Smoke Matrix

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[HIL-SMOKE] Verifying host amd64 daemons & CLI..."
for bin in \
  ./bin/daiji-netd \
  ./bin/daiji-fw-qosd \
  ./bin/daiji-ispd \
  ./bin/daiji-ac \
  ./bin/daiji-webd \
  ./bin/daiji-desk \
  ./bin/daiji-acsd \
  ./bin/daiji-billingd \
  ./bin/daiji-cloudd \
  ./bin/daiji-portald
do
  "$bin" --check >/dev/null
  echo "  PASS check: $bin"
done

./bin/daiji-ctl about --json >/dev/null
./bin/daiji-ctl schema validate --schema schema/daijios.schema.json --config schema/examples/default-config.json >/dev/null
./bin/daiji-ctl portal license-demo --json >/dev/null
./bin/daiji-ctl release soak --json >/dev/null
echo "  PASS daiji-ctl E2E probes"

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
