#!/usr/bin/env bash
# Minimal skopeo stub for Podman BATS (030-run host env leak): dir <-> boxr image store.
set -euo pipefail

BOXR_BIN="${BOXR_BIN:-boxr}"
if ! command -v "$BOXR_BIN" >/dev/null 2>&1; then
  BOXR_BIN="${BOXR:-boxr}"
fi

if [[ "${1:-}" != "copy" ]] || [[ $# -lt 3 ]]; then
  echo "skopeo-stub: only 'skopeo copy <src> <dst>' is supported" >&2
  exit 1
fi

src=$2
dst=$3

docker_dir_to_save_tar() {
  local dir=$1
  local out=$2
  if jq -e 'type == "object" and .config.digest' "$dir/manifest.json" >/dev/null 2>&1; then
    local digest size cfghex
    digest=$(jq -r '.config.digest' "$dir/manifest.json")
    cfghex=${digest#sha256:}
    size=$(jq -r '.config.size // 0' "$dir/manifest.json")
    if [[ ! -f "$dir/$cfghex" ]]; then
      echo "skopeo-stub: missing config blob $dir/$cfghex" >&2
      exit 1
    fi
    local tmpd
    tmpd=$(mktemp -d)
    cp "$dir/$cfghex" "$tmpd/sha256_${cfghex}.json"
    if [[ -f "$dir/layer.tar" ]]; then
      cp "$dir/layer.tar" "$tmpd/layer.tar"
    fi
    printf '[{"Config":"sha256_%s.json","RepoTags":null,"Layers":["layer.tar"]}]\n' "$cfghex" >"$tmpd/manifest.json"
    tar -cf "$out" -C "$tmpd" .
    rm -rf "$tmpd"
    return 0
  fi
  tar -cf "$out" -C "$dir" .
}

copy_storage_to_dir() {
  local ref=${1#containers-storage:}
  local dir=$2
  local tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/boxr-skopeo.XXXXXX.tar")
  "$BOXR_BIN" save "$ref" -o "$tmp" >/dev/null 2>&1
  mkdir -p "$dir"
  tar -xf "$tmp" -C "$dir"
  rm -f "$tmp"
  if jq -e 'type == "array"' "$dir/manifest.json" >/dev/null 2>&1; then
    local cfg cfgpath digest size
    cfg=$(jq -r '.[0].Config' "$dir/manifest.json")
    cfgpath="$dir/$cfg"
    digest=$(sha256sum "$cfgpath" | awk '{print $1}')
    size=$(stat -c %s "$cfgpath")
    mv "$cfgpath" "$dir/$digest"
    jq -n --arg d "sha256:$digest" --argjson s "$size" \
      '{config: {digest: $d, size: $s}}' >"$dir/manifest.json.new"
    mv "$dir/manifest.json.new" "$dir/manifest.json"
  fi
}

copy_dir_to_storage() {
  local dir=${1#dir:}
  local ref=${2#containers-storage:}
  local digest cfghex cfgpath
  digest=$(jq -r '.config.digest' "$dir/manifest.json")
  cfghex=${digest#sha256:}
  cfgpath="$dir/$cfghex"
  if [[ ! -f "$cfgpath" ]]; then
    echo "skopeo-stub: missing config at $cfgpath" >&2
    exit 1
  fi
  python3 - "$cfgpath" "$ref" "${BOXR_HOME:?BOXR_HOME required}" <<'PY'
import hashlib, json, os, sys
from copy import deepcopy
from datetime import datetime, timezone

cfg_path, ref, home = sys.argv[1:4]
with open(cfg_path, "r", encoding="utf-8") as f:
    raw = json.load(f)
env = raw.get("Env") or raw.get("config", {}).get("Env") or []
if isinstance(env, dict):
    env = [f"{k}={v}" for k, v in env.items()]

index = os.path.join(home, "images.json")
with open(index, "r", encoding="utf-8") as f:
    data = json.load(f)
if not data.get("images"):
    raise SystemExit("skopeo-stub: no images in store")
base = data["images"][0]
rec = deepcopy(base)
cfg_digest = "sha256:" + hashlib.sha256(open(cfg_path, "rb").read()).hexdigest()
short = hashlib.sha256(open(cfg_path, "rb").read()).hexdigest()[:12]
rec["id"] = short
rec["manifest_digest"] = cfg_digest
rec["config_digest"] = cfg_digest
rec["created_at"] = datetime.now(timezone.utc).isoformat()
if "config" not in rec:
    rec["config"] = {}
if rec["config"].get("config") is None:
    rec["config"]["config"] = {}
rec["config"]["config"]["Env"] = env
if ":" in ref:
    repo, tag = ref.rsplit(":", 1)
else:
    repo, tag = ref, "latest"
if repo.startswith("localhost/"):
    rec["registry"] = "localhost"
    rec["reference"] = repo.split("/", 1)[1]
elif "/" in repo:
    reg, repo = repo.split("/", 1)
    rec["registry"] = reg
    rec["reference"] = repo
else:
    rec["registry"] = "localhost"
    rec["reference"] = repo
rec["tag"] = tag
data["images"].append(rec)
with open(index, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
PY
}

if [[ "$src" == containers-storage:* && "$dst" == dir:* ]]; then
  copy_storage_to_dir "$src" "${dst#dir:}"
  exit 0
fi

if [[ "$src" == dir:* && "$dst" == containers-storage:* ]]; then
  copy_dir_to_storage "$src" "$dst"
  exit 0
fi

echo "skopeo-stub: unsupported copy $src -> $dst" >&2
exit 1
