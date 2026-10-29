#!/usr/bin/env bash
# Podman P0 black-box end-to-end gate (Rust + shell QA). Mirrors docs/PODMAN_PARITY_GOVERNANCE.md.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOXR_BIN="${1:-$REPO_ROOT/target/debug/boxr}"
if [[ ! -x "$BOXR_BIN" ]]; then
  BOXR_BIN="$REPO_ROOT/target/release/boxr"
fi
if [[ ! -x "$BOXR_BIN" ]]; then
  echo "boxr binary not found; run: cargo build" >&2
  exit 2
fi
BOXR_BIN="$(cd "$(dirname "$BOXR_BIN")" && pwd)/$(basename "$BOXR_BIN")"

export BOXR_TEST_EMBEDDED_USERNET="${BOXR_TEST_EMBEDDED_USERNET:-1}"
export CARGO_TERM_COLOR=always

cd "$REPO_ROOT"

echo "== Podman P0 CLI audit =="
python3 tools/podman_parity_audit.py --boxr "$BOXR_BIN"

echo "== Podman parity blackbox (Rust) =="
cargo test --test podman_parity_blackbox_test --test podman_upstream_parity_test -- --test-threads=1

echo "== Black-Box QA podman section (K1–K19 shell) =="
./scripts/run_blackbox_qa.sh -b "$BOXR_BIN" --no-rust -s podman

echo "Podman black-box E2E gate: OK"
