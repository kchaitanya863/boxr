#!/usr/bin/env bash
# Run curated Podman test/e2e (Ginkgo) against boxr. Linux rootless.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOXR_BIN="${BOXR_BIN:-$REPO_ROOT/target/debug/boxr}"
[[ -x "$BOXR_BIN" ]] || BOXR_BIN="$REPO_ROOT/target/release/boxr"
BOXR_BIN="$(cd "$(dirname "$BOXR_BIN")" && pwd)/$(basename "$BOXR_BIN")"
PODMAN_TESTS_REPO="${PODMAN_TESTS_REPO:-https://github.com/podman-container-tools/podman.git}"
CACHE_DIR="${PODMAN_BATS_CACHE:-$REPO_ROOT/.cache/podman-bats}"
SRC_DIR="$CACHE_DIR/podman"
MANIFEST="${E2E_MANIFEST:-$REPO_ROOT/tests/podman_bats/e2e_manifest.txt}"
WRAPPER="$CACHE_DIR/boxr-podman-wrapper.sh"

if [[ ! -x "$BOXR_BIN" ]]; then
  echo "build boxr first: cargo build" >&2
  exit 2
fi

if [[ ! -d "$SRC_DIR/.git" ]]; then
  git clone --depth 1 "$PODMAN_TESTS_REPO" "$SRC_DIR"
fi

mkdir -p "$(dirname "$WRAPPER")"
cat >"$WRAPPER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export BOXR_HOME="\${BOXR_HOME:-\${BOXR_BATS_HOME:-$HOME/.boxr-e2e}}"
mkdir -p "\$BOXR_HOME"
podmanize_help() {
  sed -e 's/^Usage: podman /Usage:\\n  podman /' \\
      -e 's/<\\([A-Z][A-Z0-9_]*\\)>/\\1/g' \\
      -e 's/\\[OPTIONS\\]/[options]/g' \\
      -e 's/\\[ARGS\\]/[args]/g' \\
      -e 's/ podman \\([^ ]*\\) \\[options\\] <COMMAND>/ podman \\1 [command] [options]/g' \\
      -e 's/\\[options\\] <COMMAND>/[command] [options]/g' \\
      -e 's/\\[options\\] COMMAND/[command] [options]/g' \\
      -e 's/\\[options\\] \\[command\\]/[command] [options]/g' \\
      -e 's/podman help \\[options\\] \\[command\\]/podman help [command] [options]/g'
}
if [[ "\${1:-}" == "help" ]] || [[ " \$* " == *" --help "* ]] || [[ " \$* " == *" -h "* ]]; then
  "$BOXR_BIN" "\$@" | podmanize_help
  exit "\${PIPESTATUS[0]}"
fi
exec "$BOXR_BIN" "\$@"
EOF
chmod +x "$WRAPPER"

export PODMAN_BINARY="$WRAPPER"
export PODMAN="$WRAPPER"
if [[ -z "${CONMON_BINARY:-}" ]] && [[ ! -x /usr/bin/conmon ]] && [[ ! -x /usr/libexec/podman/conmon ]]; then
  ln -sf "$BOXR_BIN" "$CACHE_DIR/conmon"
  export CONMON_BINARY="$CACHE_DIR/conmon"
fi
export BOXR_HOME="${BOXR_HOME:-$(mktemp -d "${TMPDIR:-/tmp}/boxr-e2e.XXXXXX")}"
export BOXR_BATS_HOME="$BOXR_HOME"

cd "$SRC_DIR"
if [[ ! -f "$SRC_DIR/.install.ginkgo" ]] && [[ ! -x "$SRC_DIR/bin/ginkgo" ]]; then
  echo "Installing ginkgo (first run)..."
  make -C "$SRC_DIR" .install.ginkgo
fi

if [[ ! -x "$SRC_DIR/test/e2e/e2e.test" ]] || [[ ! -x "$SRC_DIR/test/checkseccomp/checkseccomp" ]]; then
  echo "Prebuilding test/e2e/e2e.test..."
  make -C "$SRC_DIR" test-binaries
  (cd "$SRC_DIR" && ./bin/ginkgo build --tags "grpcnotrace exclude_graphdriver_btrfs seccomp remote" test/e2e/.)
fi

export PATH="$PATH:$SRC_DIR/hack"

while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%%#*}"
  line="$(echo "$line" | xargs)"
  [[ -z "$line" ]] && continue
  if [[ -n "${PODMAN_E2E_PATTERN:-}" ]] && [[ "$line" != *"$PODMAN_E2E_PATTERN"* ]]; then
    continue
  fi
  echo "======== e2e FOCUS_FILE=$line ========"
  focus_pat="$line"
  if [[ "$focus_pat" != /* ]]; then
    focus_pat="/${focus_pat}$"
  fi
  if ! "$SRC_DIR/bin/ginkgo" -vv --tags "grpcnotrace exclude_graphdriver_btrfs seccomp remote" --timeout=90m --flake-attempts 0 --trace --no-color --focus-file "$focus_pat" --silence-skips "$SRC_DIR/test/e2e/e2e.test"; then
    if [[ "${PODMAN_E2E_STRICT:-0}" == "1" ]]; then
      exit 1
    fi
  fi
done <"$MANIFEST"

echo "e2e conformance run complete (see output; strict=${PODMAN_E2E_STRICT:-0})"
