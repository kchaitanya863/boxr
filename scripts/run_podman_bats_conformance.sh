#!/usr/bin/env bash
# Run a curated subset of Podman test/system BATS with PODMAN=boxr (Linux).
#
# This does NOT run the full upstream suite. Helpers are patched for boxr storage
# (BOXR_HOME) and OpenSSL 3.x. See docs/PODMAN_BATS_CONFORMANCE.md.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOXR_BIN="${BOXR_BIN:-$REPO_ROOT/target/debug/boxr}"
if [[ ! -x "$BOXR_BIN" ]]; then
  BOXR_BIN="$REPO_ROOT/target/release/boxr"
fi
if [[ ! -x "$BOXR_BIN" ]]; then
  echo "boxr binary not found; run: cargo build" >&2
  exit 2
fi

PODMAN_TESTS_REPO="${PODMAN_TESTS_REPO:-https://github.com/podman-container-tools/podman.git}"
PODMAN_TESTS_REF="${PODMAN_TESTS_REF:-main}"
CACHE_DIR="${PODMAN_BATS_CACHE:-$REPO_ROOT/.cache/podman-bats}"
SRC_DIR="$CACHE_DIR/podman"
MANIFEST="${MANIFEST:-$REPO_ROOT/tests/podman_bats/manifest.txt}"
OVERRIDES="$REPO_ROOT/tests/podman_bats/boxr-overrides.bash"
WRAPPER="$CACHE_DIR/boxr-podman-wrapper.sh"
RESULTS_DIR="${RESULTS_DIR:-$REPO_ROOT/.cache/podman-bats-results}"
mkdir -p "$CACHE_DIR" "$RESULTS_DIR"

if ! command -v bats >/dev/null; then
  echo "bats not installed (apt install bats)" >&2
  exit 2
fi

clone_or_update() {
  if [[ ! -d "$SRC_DIR/.git" ]]; then
    git clone --depth 1 --branch "$PODMAN_TESTS_REF" "$PODMAN_TESTS_REPO" "$SRC_DIR"
  else
    git -C "$SRC_DIR" fetch --depth 1 origin "$PODMAN_TESTS_REF" 2>/dev/null || true
    git -C "$SRC_DIR" checkout -q FETCH_HEAD 2>/dev/null || git -C "$SRC_DIR" pull -q --ff-only 2>/dev/null || true
  fi
}

apply_boxr_patches() {
  local stamp="$CACHE_DIR/.boxr-patches-applied"
  local helpers="$SRC_DIR/test/system/helpers.bash"
  local head
  head="$(git -C "$SRC_DIR" rev-parse HEAD 2>/dev/null || echo none)"
  if [[ -f "$stamp" ]] && [[ "$(cat "$stamp")" == "$head" ]]; then
    return 0
  fi
  # Re-apply overrides on each upstream bump (strip previous block first).
  if grep -q 'BOXR_BATS_OVERRIDES' "$helpers" 2>/dev/null; then
    sed -i '/^# BOXR_BATS_OVERRIDES$/,$d' "$helpers"
  fi
  {
    echo ''
    echo '# BOXR_BATS_OVERRIDES'
    cat "$OVERRIDES"
  } >>"$helpers"
  echo "$head" >"$stamp"
}

write_wrapper() {
  cat >"$WRAPPER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export BOXR_HOME="\${BOXR_HOME:-\${BOXR_BATS_HOME:-$HOME/.boxr-bats}}"
mkdir -p "\$BOXR_HOME"
exec "$BOXR_BIN" "\$@"
EOF
  chmod +x "$WRAPPER"
}

run_manifest() {
  local patterns=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(echo "$line" | xargs)"
    [[ -z "$line" ]] && continue
    patterns+=("$line")
  done <"$MANIFEST"

  if [[ ${#patterns[@]} -eq 0 ]]; then
    echo "Empty manifest: $MANIFEST" >&2
    exit 1
  fi

  export BOXR_HOME
  BOXR_HOME="$(mktemp -d "${TMPDIR:-/tmp}/boxr-bats.XXXXXX")"
  export BOXR_BATS_HOME="$BOXR_HOME"
  export PODMAN="$WRAPPER"
  export QUADLET="${QUADLET:-/bin/false}"

  echo "BOXR_HOME=$BOXR_HOME"
  echo "PODMAN=$PODMAN"
  echo "Podman tests: $SRC_DIR"

  cd "$SRC_DIR"
  local log="$RESULTS_DIR/run-$(date +%Y%m%d-%H%M%S).log"
  local failed=0
  for pat in "${patterns[@]}"; do
    echo "======== BATS pattern: $pat ========" | tee -a "$log"
    if ! hack/bats --rootless "$pat" 2>&1 | tee -a "$log"; then
      failed=1
    fi
  done

  echo "Log: $log"
  if [[ $failed -ne 0 ]]; then
    echo "BATS conformance: FAILED (see log; expected until parity improves)" >&2
    if [[ "${PODMAN_BATS_STRICT:-0}" == "1" ]]; then
      exit 1
    fi
    exit 0
  fi
  echo "BATS conformance: all curated patterns passed"
}

clone_or_update
apply_boxr_patches
write_wrapper
run_manifest
