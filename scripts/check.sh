#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

./scripts/test-repository-metadata.sh
./scripts/check-repository-metadata.sh
./scripts/test-adr-index.sh
./scripts/check-adr-index.sh
./scripts/test-bootstrap-github.sh
./scripts/test-dco.sh

cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps

if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check
else
  echo "cargo-deny is not installed; dependency policy was not checked" >&2
fi
