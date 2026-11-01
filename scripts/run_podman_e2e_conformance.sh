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
mkdir -p "$CACHE_DIR/bin"
WRAPPER="$CACHE_DIR/bin/podman"

if [[ ! -x "$BOXR_BIN" ]]; then
  echo "build boxr first: cargo build" >&2
  exit 2
fi

if [[ ! -d "$SRC_DIR/.git" ]]; then
  git clone --depth 1 "$PODMAN_TESTS_REPO" "$SRC_DIR"
fi

if [[ -d "$REPO_ROOT/tests/podman_upstream/e2e" ]]; then
  rsync -a --exclude='e2e.test' --exclude='*.tmp' "$REPO_ROOT/tests/podman_upstream/e2e/" "$SRC_DIR/test/e2e/"
fi

mkdir -p "$(dirname "$WRAPPER")"
cat >"$WRAPPER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export BOXR_HOME="\${BOXR_HOME:-\${BOXR_BATS_HOME:-$HOME/.boxr-e2e}}"
export BOXR_ADDITIONAL_IMAGE_STORE="\${BOXR_ADDITIONAL_IMAGE_STORE:-$CACHE_DIR/compose-image-cache:/tmp/boxr-bats-imgcache-\$(id -u):$HOME/.boxr-e2e:$HOME/.boxr}"
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
ln -sf "$WRAPPER" "$CACHE_DIR/boxr-podman-wrapper.sh"

export PODMAN_BINARY="$WRAPPER"
export PODMAN="$WRAPPER"
export PODMAN_REMOTE_BINARY="$WRAPPER"
if [[ -z "${CONMON_BINARY:-}" ]] && [[ ! -x /usr/bin/conmon ]] && [[ ! -x /usr/libexec/podman/conmon ]]; then
  ln -sf "$BOXR_BIN" "$CACHE_DIR/conmon"
  export CONMON_BINARY="$CACHE_DIR/conmon"
fi
export TMPDIR="${TMPDIR:-$CACHE_DIR/tmp}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-$TMPDIR/xdg-runtime}"
mkdir -p "$TMPDIR" "$XDG_RUNTIME_DIR"
export BOXR_HOME="${BOXR_HOME:-$(mktemp -d "$TMPDIR/boxr-e2e.XXXXXX")}"
export BOXR_BATS_HOME="$BOXR_HOME"
export BOXR_ADDITIONAL_IMAGE_STORE="${BOXR_ADDITIONAL_IMAGE_STORE:-$CACHE_DIR/compose-image-cache:/tmp/boxr-bats-imgcache-$(id -u):$HOME/.boxr-e2e:$HOME/.boxr}"

mkdir -p "$CACHE_DIR/compose-image-cache"
for e2e_img in \
  "quay.io/libpod/testimage:20241011" \
  "quay.io/libpod/alpine:latest" \
  "quay.io/libpod/busybox:latest" \
  "quay.io/libpod/redis:alpine" \
  "quay.io/libpod/alpine_nginx:latest" \
  "quay.io/libpod/alpine_healthcheck:latest"; do
  if ! BOXR_HOME="$CACHE_DIR/compose-image-cache" "$BOXR_BIN" image exists "$e2e_img" 2>/dev/null; then
    BOXR_HOME="$CACHE_DIR/compose-image-cache" "$BOXR_BIN" pull "$e2e_img" >/dev/null 2>&1 || true
  fi
done

if ! command -v skopeo >/dev/null 2>&1; then
  mkdir -p "$CACHE_DIR/bin"
  cat >"$CACHE_DIR/bin/skopeo" <<'SKOPEO_EOF'
#!/usr/bin/env bash
set -euo pipefail
subcmd="${1:-}"
shift || true
if [[ "$subcmd" == "inspect" ]]; then
  raw=0
  ref=""
  for a in "$@"; do
    case "$a" in
      --raw) raw=1 ;;
      docker://*) ref="${a#docker://}" ;;
    esac
  done
  if [[ -n "$ref" ]]; then
    host="${ref%%/*}"
    rest="${ref#*/}"
    if [[ "$rest" == *:* ]]; then
      repo="${rest%:*}"
      tag="${rest##*:}"
    else
      repo="$rest"
      tag="latest"
    fi
    manifest="$(curl -fsSL -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json" "http://${host}/v2/${repo}/manifests/${tag}")"
    if [[ "$raw" == "1" ]]; then
      printf '%s\n' "$manifest"
      exit 0
    fi
    cfg_digest="$(printf '%s' "$manifest" | jq -r '.config.digest // empty')"
    if [[ -n "$cfg_digest" ]]; then
      cfg="$(curl -fsSL "http://${host}/v2/${repo}/blobs/${cfg_digest}")"
      arch="$(printf '%s' "$cfg" | jq -r '.architecture // .Architecture // "amd64"')"
      os_name="$(printf '%s' "$cfg" | jq -r '.os // .Os // "linux"')"
      jq -n --arg name "${host}/${repo}" --arg arch "$arch" --arg os "$os_name" '{Name: $name, Architecture: $arch, Os: $os}'
      exit 0
    fi
    printf '%s\n' "$manifest"
    exit 0
  fi
  exit 1
fi

if [[ "$subcmd" == "copy" ]]; then
  pos=()
  fmt=""
  for a in "$@"; do
    case "$a" in
      --format=*) fmt="${a#--format=}" ;;
      -*) ;;
      *) pos+=("$a") ;;
    esac
  done
  src="${pos[0]:-}"
  dst="${pos[1]:-}"
  if [[ "$src" == docker://* && "$dst" == dir:* ]]; then
    ref="${src#docker://}"
    dir="${dst#dir:}"
    mkdir -p "$dir"
    host="${ref%%/*}"
    rest="${ref#*/}"
    if [[ "$rest" == *:* ]]; then
      repo="${rest%:*}"
      tag="${rest##*:}"
    else
      repo="$rest"
      tag="latest"
    fi
    manifest="$(curl -fsSL -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" "http://${host}/v2/${repo}/manifests/${tag}")"
    printf '%s\n' "$manifest" >"$dir/manifest.json"
    cfg_digest="$(printf '%s' "$manifest" | jq -r '.config.digest')"
    cfg_hex="${cfg_digest#sha256:}"
    curl -fsSL "http://${host}/v2/${repo}/blobs/${cfg_digest}" -o "$dir/$cfg_hex"
    for ldig in $(printf '%s' "$manifest" | jq -r '.layers[].digest'); do
      lhex="${ldig#sha256:}"
      curl -fsSL "http://${host}/v2/${repo}/blobs/${ldig}" -o "$dir/$lhex"
    done
    exit 0
  fi
  if [[ "$src" == dir:* && "$dst" == dir:* ]]; then
    sdir="${src#dir:}"
    ddir="${dst#dir:}"
    mkdir -p "$ddir"
    cp -a "$sdir/." "$ddir/"
    if [[ "$fmt" == "v2s1" ]]; then
      jq 'del(.layers[].annotations)' "$ddir/manifest.json" >"$ddir/manifest.json.tmp" && mv "$ddir/manifest.json.tmp" "$ddir/manifest.json"
    fi
    exit 0
  fi
  if [[ "$src" == dir:* && "$dst" == docker://* ]]; then
    sdir="${src#dir:}"
    ref="${dst#docker://}"
    host="${ref%%/*}"
    rest="${ref#*/}"
    if [[ "$rest" == *:* ]]; then
      repo="${rest%:*}"
      tag="${rest##*:}"
    else
      repo="$rest"
      tag="latest"
    fi
    upload_blob() {
      local hex="$1"
      local file="$sdir/$hex"
      [[ -f "$file" ]] || return 0
      local loc
      loc="$(curl -fsSI -X POST "http://${host}/v2/${repo}/blobs/uploads/" | awk 'tolower($1)=="location:" {gsub(/\r/,"",$2); print $2}')"
      if [[ "$loc" != http* ]]; then
        loc="http://${host}${loc}"
      fi
      local sep="?"
      [[ "$loc" == *\?* ]] && sep="&"
      curl -fsSL -X PUT -H "Content-Type: application/octet-stream" --data-binary "@$file" "${loc}${sep}digest=sha256:${hex}" >/dev/null
    }
    cfg_digest="$(jq -r '.config.digest' "$sdir/manifest.json")"
    upload_blob "${cfg_digest#sha256:}"
    for ldig in $(jq -r '.layers[].digest' "$sdir/manifest.json"); do
      upload_blob "${ldig#sha256:}"
    done
    mt="$(jq -r '.mediaType // "application/vnd.oci.image.manifest.v1+json"' "$sdir/manifest.json")"
    curl -fsSL -X PUT -H "Content-Type: $mt" --data-binary "@$sdir/manifest.json" "http://${host}/v2/${repo}/manifests/${tag}" >/dev/null
    exit 0
  fi
fi
exit 1
SKOPEO_EOF
  chmod +x "$CACHE_DIR/bin/skopeo"
  export PATH="$CACHE_DIR/bin:$PATH"
fi

cd "$SRC_DIR"
if [[ ! -f "$SRC_DIR/.install.ginkgo" ]] && [[ ! -x "$SRC_DIR/bin/ginkgo" ]]; then
  echo "Installing ginkgo (first run)..."
  make -C "$SRC_DIR" .install.ginkgo
fi
[[ -x "$SRC_DIR/bin/ginkgo" ]] && touch "$SRC_DIR/.install.ginkgo"

if [[ ! -x "$SRC_DIR/bin/quadlet" ]]; then
  echo "Building bin/quadlet..."
  make -C "$SRC_DIR" bin/quadlet
fi
export QUADLET_BINARY="$SRC_DIR/bin/quadlet"

if [[ ! -x "$SRC_DIR/test/checkseccomp/checkseccomp" ]] || [[ ! -x "$SRC_DIR/test/goecho/goecho" ]] || [[ ! -x "$SRC_DIR/test/version/version" ]]; then
  make -C "$SRC_DIR" test-binaries
fi

if [[ ! -x "$SRC_DIR/test/e2e/e2e.test" ]] || [[ ! -x "$SRC_DIR/test/checkseccomp/checkseccomp" ]]; then
  echo "Prebuilding test/e2e/e2e.test..."
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
