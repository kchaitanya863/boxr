#!/usr/bin/env bash
# Strict BATS gate for patterns that pass without container runtime (help/tag/info CLI).
# Full curated + container suites: ubuntu-24.04 CI (see docs/PODMAN_BATS_CONFORMANCE.md).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
export PODMAN_BATS_STRICT=1
export BOXR_TEST_EMBEDDED_USERNET=1
chmod +x scripts/run_podman_bats_conformance.sh
for pat in 015-help 020-tag; do
  echo "== offline gate (strict): $pat =="
  PODMAN_BATS_PATTERN="$pat" ./scripts/run_podman_bats_conformance.sh
done
echo "Podman BATS offline gate: OK"
