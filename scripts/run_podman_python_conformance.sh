#!/usr/bin/env bash
# Run Podman test/python/docker (docker-py compatibility suites) against boxr.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOXR_BIN="${BOXR_BIN:-$REPO_ROOT/target/debug/boxr}"
[[ -x "$BOXR_BIN" ]] || BOXR_BIN="$REPO_ROOT/target/release/boxr"
BOXR_BIN="$(cd "$(dirname "$BOXR_BIN")" && pwd)/$(basename "$BOXR_BIN")"
CACHE_DIR="${PODMAN_BATS_CACHE:-$REPO_ROOT/.cache/podman-bats}"
SRC_DIR="$CACHE_DIR/podman"
VENV_DIR="$CACHE_DIR/venv"
mkdir -p "$CACHE_DIR/bin"
WRAPPER="$CACHE_DIR/bin/podman"

if [[ ! -x "$BOXR_BIN" ]]; then
  echo "build boxr first: cargo build" >&2
  exit 2
fi

cat >"$WRAPPER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export BOXR_HOME="\${BOXR_HOME:-\${BOXR_BATS_HOME:-$HOME/.boxr-pydocker}}"
mkdir -p "\$BOXR_HOME"
exec "$BOXR_BIN" "\$@"
EOF
chmod +x "$WRAPPER"

export PODMAN="$WRAPPER"
export PODMAN_BINARY="$WRAPPER"
if [[ -d "$VENV_DIR/bin" ]]; then
  export PATH="$VENV_DIR/bin:$CACHE_DIR/bin:$PATH"
else
  export PATH="$CACHE_DIR/bin:$PATH"
fi

if [[ -d "$REPO_ROOT/tests/podman_upstream/python" ]]; then
  mkdir -p "$SRC_DIR/test/python"
  rsync -a "$REPO_ROOT/tests/podman_upstream/python/" "$SRC_DIR/test/python/"
fi

cd "$SRC_DIR"
touch test/__init__.py
trap 'rm -f "$SRC_DIR/test/__init__.py"' EXIT

echo "======== Running test/python/docker ========"
env CONTAINERS_CONF="$SRC_DIR/test/apiv2/containers.conf" \
    PODMAN="$WRAPPER" \
    PODMAN_BINARY="$WRAPPER" \
    pytest --verbose --disable-warnings test/python/docker/ "$@"

echo "python docker conformance run complete"
