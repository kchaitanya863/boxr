#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOXR_BIN="${1:-$REPO_ROOT/target/debug/boxr}"
exec python3 "$REPO_ROOT/tools/podman_parity_audit.py" --boxr "$BOXR_BIN"
