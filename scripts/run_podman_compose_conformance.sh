#!/usr/bin/env bash
# Run Podman test/compose scenarios against boxr. Linux rootless.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ $# -gt 0 && -x "$1" && ! -d "$1" ]]; then
  BOXR_BIN="$1"
  shift
else
  BOXR_BIN="${BOXR_BIN:-$REPO_ROOT/target/debug/boxr}"
fi
[[ -x "$BOXR_BIN" ]] || BOXR_BIN="$REPO_ROOT/target/release/boxr"
if [[ ! -x "$BOXR_BIN" ]]; then
  echo "build boxr first: cargo build" >&2
  exit 2
fi
BOXR_BIN="$(cd "$(dirname "$BOXR_BIN")" && pwd)/$(basename "$BOXR_BIN")"

PODMAN_TESTS_REPO="${PODMAN_TESTS_REPO:-https://github.com/podman-container-tools/podman.git}"
CACHE_DIR="${PODMAN_BATS_CACHE:-$REPO_ROOT/.cache/podman-bats}"
SRC_DIR="$CACHE_DIR/podman"
WRAPPER="$CACHE_DIR/boxr-podman-wrapper.sh"
SHARED_IMG_HOME="$CACHE_DIR/compose-image-cache"

if [[ ! -d "$SRC_DIR/.git" ]]; then
  git clone --depth 1 "$PODMAN_TESTS_REPO" "$SRC_DIR"
fi

mkdir -p "$CACHE_DIR" "$SHARED_IMG_HOME" "$SRC_DIR/bin"
cat >"$WRAPPER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export BOXR_HOME="\${BOXR_HOME:-\${BOXR_BATS_HOME:-$SHARED_IMG_HOME}}"
export BOXR_ADDITIONAL_IMAGE_STORE="\${BOXR_ADDITIONAL_IMAGE_STORE:-$SHARED_IMG_HOME:/tmp/boxr-bats-imgcache-\$(id -u):$HOME/.boxr}"
mkdir -p "\$BOXR_HOME"
exec "$BOXR_BIN" "\$@"
EOF
chmod +x "$WRAPPER"
ln -sf "$WRAPPER" "$SRC_DIR/bin/podman"

if ! command -v docker-compose >/dev/null 2>&1; then
  mkdir -p "$CACHE_DIR/compose-bin"
  cat >"$CACHE_DIR/compose-bin/docker-compose" <<EOF
#!/usr/bin/env bash
exec "$WRAPPER" compose "\$@"
EOF
  chmod +x "$CACHE_DIR/compose-bin/docker-compose"
  export PATH="$CACHE_DIR/compose-bin:$PATH"
fi

export PODMAN_BINARY="$WRAPPER"
export PODMAN="$WRAPPER"
export BOXR_ADDITIONAL_IMAGE_STORE="${BOXR_ADDITIONAL_IMAGE_STORE:-$SHARED_IMG_HOME:/tmp/boxr-bats-imgcache-$(id -u):$HOME/.boxr}"
export TMPDIR="${TMPDIR:-$CACHE_DIR/tmp}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-$TMPDIR/xdg-runtime}"
mkdir -p "$TMPDIR" "$XDG_RUNTIME_DIR"

# Ensure base images (alpine and quay.io/libpod/podman_python) are available in SHARED_IMG_HOME
if ! BOXR_HOME="$SHARED_IMG_HOME" "$BOXR_BIN" image exists alpine 2>/dev/null; then
  BOXR_HOME="$SHARED_IMG_HOME" "$BOXR_BIN" pull alpine >/dev/null
fi
if ! BOXR_HOME="$SHARED_IMG_HOME" "$BOXR_BIN" image exists quay.io/libpod/podman_python 2>/dev/null; then
  if [[ -f "$SRC_DIR/test/compose/images/podman-python/Containerfile" ]]; then
    echo "Building quay.io/libpod/podman_python from test/compose/images/podman-python/Containerfile..."
    BOXR_HOME="$SHARED_IMG_HOME" "$BOXR_BIN" build -t quay.io/libpod/podman_python -f "$SRC_DIR/test/compose/images/podman-python/Containerfile" "$SRC_DIR/test/compose/images/podman-python" >/dev/null || \
      BOXR_HOME="$SHARED_IMG_HOME" "$BOXR_BIN" pull quay.io/libpod/podman_python >/dev/null
  else
    BOXR_HOME="$SHARED_IMG_HOME" "$BOXR_BIN" pull quay.io/libpod/podman_python >/dev/null
  fi
fi

cd "$SRC_DIR/test/compose"
if [[ "${1:-}" == "images" ]]; then
  echo "TAP version 13"
  BOXR_HOME="$SHARED_IMG_HOME" "$BOXR_BIN" image exists quay.io/libpod/podman_python
  echo "ok 1 images - quay.io/libpod/podman_python ready"
  echo "1..1"
  exit 0
fi

./test-compose "$@"
