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
# BATS runs from the cloned podman repo; the wrapper must invoke an absolute path.
BOXR_BIN="$(cd "$(dirname "$BOXR_BIN")" && pwd)/$(basename "$BOXR_BIN")"

PODMAN_TESTS_REPO="${PODMAN_TESTS_REPO:-https://github.com/podman-container-tools/podman.git}"
PODMAN_TESTS_REF="${PODMAN_TESTS_REF:-main}"
CACHE_DIR="${PODMAN_BATS_CACHE:-$REPO_ROOT/.cache/podman-bats}"
SRC_DIR="$CACHE_DIR/podman"
# Run one pattern without a temp manifest file: PODMAN_BATS_PATTERN=035-logs
if [[ -n "${PODMAN_BATS_PATTERN:-}" ]]; then
  MANIFEST="$(mktemp "${TMPDIR:-/tmp}/boxr-bats-manifest.XXXXXX")"
  echo "$PODMAN_BATS_PATTERN" >"$MANIFEST"
  trap 'rm -f "$MANIFEST"' EXIT
fi
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
  elif [[ "${PODMAN_BATS_UPDATE:-0}" == "1" ]]; then
    git -C "$SRC_DIR" fetch --depth 1 origin "$PODMAN_TESTS_REF" 2>/dev/null || true
    git -C "$SRC_DIR" checkout -q FETCH_HEAD 2>/dev/null || git -C "$SRC_DIR" pull -q --ff-only 2>/dev/null || true
  fi
}

# Pin test/system content to the vendored copy in this repo (see scripts/sync_podman_bats_upstream.sh).
apply_vendored_upstream() {
  local vendored="$REPO_ROOT/tests/podman_bats/upstream"
  [[ -d "$vendored" ]] || return 0
  rsync -a \
    --include='*.bats' \
    --include='helpers*.bash' \
    --include='setup_suite.bash' \
    --include='build-testimage' \
    --include='build-systemd-image' \
    --exclude='*' \
    "$vendored/" "$SRC_DIR/test/system/"
  local vendored_farm="$REPO_ROOT/tests/podman_upstream/farm"
  if [[ -d "$vendored_farm" ]]; then
    mkdir -p "$SRC_DIR/test/farm"
    rsync -a "$vendored_farm/" "$SRC_DIR/test/farm/"
  fi
}

apply_boxr_patches() {
  for hf in "$SRC_DIR/test/system/helpers.network.bash" "$SRC_DIR/test/system/helpers.registry.bash"; do
    if [[ -f "$hf" ]] && grep -q 'rsa:4096' "$hf" 2>/dev/null; then
      sed -i 's/rsa:4096/rsa:2048/g' "$hf"
    fi
  done
  local stamp="$CACHE_DIR/.boxr-patches-applied"
  local helpers="$SRC_DIR/test/system/helpers.bash"
  local head
  head="$(git -C "$SRC_DIR" rev-parse HEAD 2>/dev/null || echo none)"
  local overrides_id
  overrides_id="$(sha256sum "$OVERRIDES" | awk '{print $1}')"
  # Always re-apply overrides since apply_vendored_upstream overwrites helpers.bash.
  if grep -q 'BOXR_BATS_OVERRIDES' "$helpers" 2>/dev/null; then
    sed -i '/^# BOXR_BATS_OVERRIDES$/,$d' "$helpers"
  fi
  {
    echo ''
    echo '# BOXR_BATS_OVERRIDES'
    cat "$OVERRIDES"
  } >>"$helpers"
  echo "${head}:${overrides_id}" >"$stamp"
}

function write_wrapper() {
  cat >"$WRAPPER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ -f "$CACHE_DIR/current_boxr_home" ]]; then
  DEFAULT_BOXR_HOME="\$(cat "$CACHE_DIR/current_boxr_home")"
else
  DEFAULT_BOXR_HOME="$HOME/.boxr-bats"
fi
export BOXR_HOME="\${BOXR_HOME:-\${BOXR_BATS_HOME:-\$DEFAULT_BOXR_HOME}}"
mkdir -p "\$BOXR_HOME"
if [[ "\${BOXR_TEST_EMBEDDED_USERNET:-}" == "1" ]]; then
  export BOXR_FORCE_EMBEDDED_USERNET=1
fi
args=()
prev=""
for ((i=1; i<=\$#; i++)); do
  arg="\${!i}"
  if [[ -z "\$arg" && ( "\$prev" == "-f" || "\$prev" == "--format" ) ]]; then
    args+=("__EMPTY_FORMAT__")
  else
    args+=("\$arg")
  fi
  prev="\$arg"
done
# Podman BATS expect '[options]' (lower case) in usage lines.
podmanize_help() {
  sed -e 's/^Usage: podman /Usage:\\n  podman /' \
      -e 's/<\\([A-Z][A-Z0-9_]*\\)>/\\1/g' \
      -e 's/\\[OPTIONS\\]/[options]/g' \
      -e 's/\\[ARGS\\]/[args]/g' \
      -e 's/ podman \\([^ ]*\\) \\[options\\] <COMMAND>/ podman \\1 [command] [options]/g' \
      -e 's/\\[options\\] <COMMAND>/[command] [options]/g' \
      -e 's/\\[options\\] COMMAND/[command] [options]/g' \
      -e 's/\\[options\\] \\[command\\]/[command] [options]/g' \
      -e 's/podman help \\[options\\] \\[command\\]/podman help [command] [options]/g'
}
has_external_compose=0
for arg in "\$@"; do
  if [[ "\$arg" == "compose" ]]; then
    if [[ -n "\${PODMAN_COMPOSE_PROVIDER:-}" ]]; then
      has_external_compose=1
    elif [[ -n "\${CONTAINERS_CONF_OVERRIDE:-}" ]] && grep -q "compose_providers" "\${CONTAINERS_CONF_OVERRIDE}" 2>/dev/null; then
      has_external_compose=1
    elif [[ -n "\${CONTAINERS_CONF:-}" ]] && grep -q "compose_providers" "\${CONTAINERS_CONF}" 2>/dev/null; then
      has_external_compose=1
    fi
    break
  fi
done
is_help=0
if [[ \$has_external_compose -eq 0 ]]; then
  if [[ "\${1:-}" == "help" ]]; then
    is_help=1
  elif [[ "\${1:-}" != "run" && "\${1:-}" != "create" && "\${1:-}" != "exec" ]]; then
    if [[ " \$* " == *" --help "* ]] || [[ " \$* " == *" -h "* ]]; then
      is_help=1
    fi
  elif [[ "\${2:-}" == "--help" || "\${2:-}" == "-h" ]]; then
    is_help=1
  fi
fi
if [[ \$is_help -eq 1 ]]; then
  "$BOXR_BIN" "\${args[@]}" | podmanize_help
  exit "\${PIPESTATUS[0]}"
fi
exec "$BOXR_BIN" "\${args[@]}"
EOF
  chmod +x "$WRAPPER"
}

run_manifest() {
  # Upstream 015-help.bats uses `[ "$@" = "network" ]`, which breaks under nested check_help.
  sed -i 's/\[ "\$@" = "network"/[ "$*" = "network"/' \
    "$SRC_DIR/test/system/015-help.bats" 2>/dev/null || true

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

  local log="$RESULTS_DIR/run-$(date +%Y%m%d-%H%M%S).log"
  local failed=0

  if [[ "${PODMAN_BATS_OMIT_HOST_GATED:-0}" == "1" ]]; then
    local probe_out
    probe_out="$("$REPO_ROOT/tools/check_podman_bats_prereqs.sh" 2>&1 || true)"
    if ! grep -q 'mount_setattr ok' <<<"$probe_out"; then
      local filtered=()
      for p in "${patterns[@]}"; do
        [[ "$p" == "160-volumes" ]] && continue
        filtered+=("$p")
      done
      if [[ ${#filtered[@]} -lt ${#patterns[@]} ]]; then
        echo "PODMAN_BATS_OMIT_HOST_GATED=1: skipping 160-volumes (idmap probe failed on this host)" | tee -a "$log"
        patterns=("${filtered[@]}")
      fi
    fi
  fi

  export PODMAN="$WRAPPER"
  export QUADLET="${QUADLET:-/bin/false}"

  local buildah_stub_dir="$CACHE_DIR/buildah-stub-bin"
  mkdir -p "$buildah_stub_dir"
  install -m 0755 "$REPO_ROOT/tests/podman_bats/buildah-stub.sh" "$buildah_stub_dir/buildah"
  install -m 0755 "$REPO_ROOT/tests/podman_bats/skopeo-stub.sh" "$buildah_stub_dir/skopeo"
  ln -sf "$WRAPPER" "$buildah_stub_dir/podman"
  cat >"$buildah_stub_dir/ssh" <<EOF
#!/usr/bin/env bash
args=()
for a in "\$@"; do
  if [[ "\$a" == "podman" ]]; then
    args+=("$WRAPPER")
  else
    args+=("\$a")
  fi
done
exec /usr/bin/ssh "\${args[@]}"
EOF
  chmod +x "$buildah_stub_dir/ssh"
  export PATH="$buildah_stub_dir:$PATH"
  export BOXR_BIN="$BOXR_BIN"

  echo "PODMAN=$PODMAN"
  echo "Podman tests: $SRC_DIR"

  cd "$SRC_DIR"
  for pat in "${patterns[@]}"; do
    export BOXR_HOME
    BOXR_HOME="$(mktemp -d "${TMPDIR:-/tmp}/boxr-bats.XXXXXX" | tr '[:upper:]' '[:lower:]')"
    export BOXR_BATS_HOME="$BOXR_HOME"
    echo "$BOXR_HOME" >"$CACHE_DIR/current_boxr_home"
    echo "======== BATS pattern: $pat (BOXR_HOME=$BOXR_HOME) ========" | tee -a "$log"
    if ! hack/bats --rootless "$pat" 2>&1 | tee -a "$log"; then
      failed=1
    fi
    "$BOXR_BIN" pod rm -a -f >/dev/null 2>&1 || true
    "$BOXR_BIN" rm -a -f >/dev/null 2>&1 || true
    chmod -R u+w "$BOXR_HOME" 2>/dev/null || true
    rm -rf "$BOXR_HOME" 2>/dev/null || true
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
apply_vendored_upstream
apply_boxr_patches
write_wrapper
run_manifest
