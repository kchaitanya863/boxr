#!/usr/bin/env bash
# Run the full vendored upstream BATS catalog (77 files). Expect failures until parity is complete.
#
# Completion bar (capable Linux rootless VM, e.g. ubuntu-24.04 CI):
#   PODMAN_BATS_STRICT=1 PODMAN_BATS_OMIT_HOST_GATED=1 BOXR_TEST_EMBEDDED_USERNET=1 \
#     ./scripts/run_podman_bats_all_upstream.sh
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FULL_MANIFEST="${MANIFEST:-$REPO_ROOT/tests/podman_bats/manifest-all.txt}"
if [[ -n "${BATS_SHARD_INDEX:-}" && -n "${BATS_SHARD_TOTAL:-}" ]]; then
  SHARD_MANIFEST="$(mktemp "${TMPDIR:-/tmp}/boxr-bats-shard.XXXXXX")"
  trap 'rm -f "$SHARD_MANIFEST"' EXIT
  grep -vE '^\s*(#|$)' "$FULL_MANIFEST" | awk -v idx="$BATS_SHARD_INDEX" -v total="$BATS_SHARD_TOTAL" '(NR - 1) % total == (idx - 1)' > "$SHARD_MANIFEST"
  export MANIFEST="$SHARD_MANIFEST"
else
  export MANIFEST="$FULL_MANIFEST"
fi
exec "$REPO_ROOT/scripts/run_podman_bats_conformance.sh" "$@"
