#!/usr/bin/env bash
# Fast local pre-push gate mirroring .github/workflows/ci.yml (Linux).
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TERM_COLOR=always

echo "== fmt =="
cargo fmt --all -- --check

echo "== clippy =="
cargo clippy --all-targets -- -A clippy::all

echo "== build =="
cargo build

echo "== podman BATS catalog + offline gate =="
cargo test --test podman_bats_manifest_test
./scripts/run_podman_bats_offline_gate.sh

echo "== podman black-box E2E =="
BOXR_TEST_EMBEDDED_USERNET=1 ./scripts/run_podman_blackbox_e2e.sh ./target/debug/boxr

echo "== full test suite (sequential) =="
BOXR_FORCE_EMBEDDED_USERNET=1 cargo test --all -- --test-threads=1

echo "Local CI gate: OK"
