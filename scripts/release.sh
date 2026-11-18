#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)
# Reproducible LTS Release Packager

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="${VERSION:-1.2.0-lts}"
REL_DIR="bin/release/daijios-v${VERSION}"

if [ ! -x ./bin/daiji-ctl ] || [ ! -d ./bin/dist ]; then
  make build VERSION="$VERSION"
  make cross-build VERSION="$VERSION"
fi

rm -rf "$REL_DIR"
mkdir -p "$REL_DIR"

./bin/daiji-ctl release manifest \
  --dir ./bin/dist \
  --out "$REL_DIR" \
  --version "$VERSION" \
  --json

./bin/daiji-ctl release verify \
  --dir ./bin/dist \
  --manifest "$REL_DIR/manifest.json" \
  --sums "$REL_DIR/SHA256SUMS"

echo "Release bundle ready in $REL_DIR"
