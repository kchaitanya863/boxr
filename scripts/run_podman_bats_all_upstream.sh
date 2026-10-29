#!/usr/bin/env bash
# Run the full vendored upstream BATS catalog (77 files). Expect failures until parity is complete.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export MANIFEST="${MANIFEST:-$REPO_ROOT/tests/podman_bats/manifest-all.txt}"
exec "$REPO_ROOT/scripts/run_podman_bats_conformance.sh" "$@"
