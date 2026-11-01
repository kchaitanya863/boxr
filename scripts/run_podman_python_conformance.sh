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
if [[ -d "$REPO_ROOT/tests/podman_upstream/apiv2" ]]; then
  mkdir -p "$SRC_DIR/test/apiv2"
  rsync -a "$REPO_ROOT/tests/podman_upstream/apiv2/" "$SRC_DIR/test/apiv2/"
fi
if [[ ! -f "$SRC_DIR/test/registries.conf" && -f "$REPO_ROOT/tests/podman_upstream/e2e/testdata/registries.conf" ]]; then
  mkdir -p "$SRC_DIR/test"
  cp "$REPO_ROOT/tests/podman_upstream/e2e/testdata/registries.conf" "$SRC_DIR/test/registries.conf"
fi

cd "$SRC_DIR"
touch test/__init__.py
trap 'rm -f "$SRC_DIR/test/__init__.py"' EXIT

pytest_targets=("test/python/docker/")
if [[ $# -gt 0 ]]; then
  pytest_targets=()
  for arg in "$@"; do
    if [[ -f "test/python/docker/compat/$arg" ]]; then
      pytest_targets+=("test/python/docker/compat/$arg")
    elif [[ -f "test/python/docker/$arg" ]]; then
      pytest_targets+=("test/python/docker/$arg")
    else
      pytest_targets+=("$arg")
    fi
  done
fi

echo "======== Running test/python/docker ========"
env CONTAINERS_CONF="$SRC_DIR/test/apiv2/containers.conf" \
    PODMAN="$WRAPPER" \
    PODMAN_BINARY="$WRAPPER" \
    pytest --verbose --disable-warnings "${pytest_targets[@]}"

echo "python docker conformance run complete"
