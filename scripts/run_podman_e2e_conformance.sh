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
export BOXR_HOME="\${BOXR_HOME:-\${BOXR_BATS_HOME:-$HOME/.boxr-e2e}}"
mkdir -p "\$BOXR_HOME"
exec "$BOXR_BIN" "\$@"
EOF
chmod +x "$WRAPPER"

export PODMAN_BINARY="$WRAPPER"
export PODMAN="$WRAPPER"
export BOXR_HOME="${BOXR_HOME:-$(mktemp -d "${TMPDIR:-/tmp}/boxr-e2e.XXXXXX")}"
export BOXR_BATS_HOME="$BOXR_HOME"

cd "$SRC_DIR"
if [[ ! -f "$REPO_ROOT/.cache/podman-bats/.install.ginkgo" ]]; then
  echo "Installing ginkgo (first run)..."
  make -C "$SRC_DIR" .install.ginkgo
fi

while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%%#*}"
  line="$(echo "$line" | xargs)"
  [[ -z "$line" ]] && continue
  echo "======== e2e FOCUS_FILE=$line ========"
  if ! make localintegration FOCUS_FILE="$line" GINKGO_PARALLEL=n; then
    if [[ "${PODMAN_E2E_STRICT:-0}" == "1" ]]; then
      exit 1
    fi
  fi
done <"$MANIFEST"

echo "e2e conformance run complete (see output; strict=${PODMAN_E2E_STRICT:-0})"
