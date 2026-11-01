#!/usr/bin/env bash
# Run Podman test/apiv2 (.at bash suites + python REST API tests) against boxr.
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
export BOXR_HOME="\${BOXR_HOME:-\${BOXR_BATS_HOME:-$HOME/.boxr-apiv2}}"
mkdir -p "\$BOXR_HOME"
exec "$BOXR_BIN" "\$@"
EOF
chmod +x "$WRAPPER"

cat >"$CACHE_DIR/bin/skopeo" <<'EOF'
#!/usr/bin/env bash
raw=0
target=""
for arg in "$@"; do
    case "$arg" in
        --raw) raw=1 ;;
        docker://*) target="${arg#docker://}" ;;
    esac
done
safe_ref=$(echo "$target" | tr '/:' '__')
if [ -f "/tmp/boxr-registry-manifests/${safe_ref}.json" ]; then
    cat "/tmp/boxr-registry-manifests/${safe_ref}.json"
    exit 0
fi
if [[ "$target" == *"@"* ]]; then
    dig="${target#*@}"
    if [ -f "/tmp/boxr-registry-manifests/blob_${dig}.json" ]; then
        cat "/tmp/boxr-registry-manifests/blob_${dig}.json"
        exit 0
    fi
fi
if [ "$raw" -eq 1 ]; then
    echo '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:6953980e46925f8ac2c09fc7ecf9f353c2cac49f87e7e60ed78287d55a14c296","size":1024,"platform":{"architecture":"amd64","os":"linux"}}]}'
else
    echo '{"Name":"'"$target"'","Architecture":"amd64","Os":"linux","Layers":["sha256:634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00"]}'
fi
EOF
chmod +x "$CACHE_DIR/bin/skopeo"

export PODMAN="$WRAPPER"
export PODMAN_BINARY="$WRAPPER"
export CONTAINERS_HELPER_BINARY_DIR="$CACHE_DIR/bin"
export t2="t0"
if [[ -d "$VENV_DIR/bin" ]]; then
  export PATH="$VENV_DIR/bin:$CACHE_DIR/bin:$PATH"
else
  export PATH="$CACHE_DIR/bin:$PATH"
fi

cd "$SRC_DIR"

if [[ "${SKIP_APIV2_BASH:-0}" != "1" ]]; then
  echo "======== Running test/apiv2/test-apiv2 ========"
  env PODMAN="$WRAPPER" PODMAN_BINARY="$WRAPPER" stdbuf -o0 -e0 ./test/apiv2/test-apiv2 "$@"
fi

if [[ $# -eq 0 ]] && [[ "${SKIP_APIV2_PYTHON:-0}" != "1" ]]; then
  echo "======== Running test/apiv2/python ========"
  env CONTAINERS_CONF="$SRC_DIR/test/apiv2/containers.conf" \
      PODMAN="$WRAPPER" \
      PODMAN_BINARY="$WRAPPER" \
      pytest --verbose --disable-warnings ./test/apiv2/python
fi

echo "apiv2 conformance run complete"
