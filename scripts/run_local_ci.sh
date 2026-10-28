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

echo "== podman P0 audit =="
python3 tools/podman_parity_audit.py --boxr ./target/debug/boxr

echo "== podman parity blackbox =="
cargo test --test podman_parity_blackbox_test -- --test-threads=1

echo "== full test suite (sequential) =="
cargo test --all -- --test-threads=1

echo "Local CI gate: OK"
