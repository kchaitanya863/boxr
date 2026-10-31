#!/usr/bin/env bash
# Minimal skopeo stub for Podman BATS (030-run host env leak): dir <-> boxr image store.
set -euo pipefail

BOXR_BIN="${BOXR_BIN:-boxr}"
if ! command -v "$BOXR_BIN" >/dev/null 2>&1; then
  BOXR_BIN="${BOXR:-boxr}"
fi

subcmd="${1:-}"
shift || true

authfile=""
raw_flag=0
pos_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --authfile=*)
      authfile="${1#--authfile=}"
      shift
      ;;
    --authfile)
      authfile="${2:-}"
      shift 2
      ;;
    --raw)
      raw_flag=1
      shift
      ;;
    --format=*|--dest-tls-verify=*|--src-tls-verify=*|--tls-verify=*)
      shift
      ;;
    --format|--dest-tls-verify|--src-tls-verify|--tls-verify)
      shift 2
      ;;
    -*)
      shift
      ;;
    *)
      pos_args+=("$1")
      shift
      ;;
  esac
done

resolve_authfile() {
  if [[ -n "$authfile" ]]; then
    echo "$authfile"
  elif [[ -n "${REGISTRY_AUTH_FILE:-}" ]]; then
    echo "$REGISTRY_AUTH_FILE"
  else
    echo "${BOXR_HOME:-$HOME/.boxr}/config.json"
  fi
}

check_registry_auth() {
  local reg="$1"
  local af
  af="$(resolve_authfile)"
  if [[ ! -f "$af" ]]; then
    return 1
  fi
  jq -e ".auths[\"$reg\"].auth != null and .auths[\"$reg\"].auth != \"\"" "$af" >/dev/null 2>&1
}

if [[ "$subcmd" == "inspect" ]]; then
  target="${pos_args[0]:-}"
  if [[ "$target" == containers-storage:* ]]; then
    ref="${target#containers-storage:}"
    cat <<EOF
{
  "Name": "${ref%:*}",
  "Digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "LayersData": [
    {
      "MIMEType": "application/vnd.oci.image.layer.v1.tar+zstd"
    }
  ]
}
EOF
    exit 0
  fi
  if [[ "$target" == docker://* ]]; then
    clean="${target#docker://}"
    reg="${clean%%/*}"
    if [[ "$clean" == localhost:* ]]; then
      if ! check_registry_auth "$reg"; then
        echo "time=\"2026-01-01T00:00:00Z\" level=fatal msg=\"reading manifest latest in $clean: authentication required\"" >&2
        exit 1
      fi
    fi
    if [[ $raw_flag -eq 1 ]]; then
      if [[ "$clean" == *@sha256:* ]]; then
        dig="${clean#*@}"
        by_dig="/tmp/boxr-registry-manifests/by-digest/${dig/:/_}.json"
        if [[ -f "$by_dig" ]]; then
          cat "$by_dig"
          exit 0
        fi
      fi
      safe_ref="${clean//[\/:]/_}"
      last_part="${clean##*/}"
      if [[ "$last_part" != *:* && "$last_part" != *@* ]]; then
        safe_ref="${safe_ref}_latest"
      fi
      if [[ -f "/tmp/boxr-registry-manifests/${safe_ref}.json" ]]; then
        cat "/tmp/boxr-registry-manifests/${safe_ref}.json"
        exit 0
      fi
    fi
    name_no_tag="$clean"
    last_part="${clean##*/}"
    if [[ "$last_part" == *:* ]]; then
      name_no_tag="${clean%:*}"
    fi
    cat <<EOF
{
  "Name": "$name_no_tag",
  "Digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "LayersData": [
    {
      "MIMEType": "application/vnd.oci.image.layer.v1.tar+zstd"
    }
  ]
}
EOF
    exit 0
  fi
  exit 1
fi

if [[ "$subcmd" != "copy" ]] || [[ ${#pos_args[@]} -lt 2 ]]; then
  echo "skopeo-stub: unsupported command $subcmd" >&2
  exit 1
fi

src="${pos_args[0]}"
dst="${pos_args[1]}"

if [[ "$src" == containers-storage:* && "$dst" == docker://* ]]; then
  clean_dst="${dst#docker://}"
  reg="${clean_dst%%/*}"
  if [[ "$clean_dst" == localhost:* ]]; then
    if ! check_registry_auth "$reg"; then
      echo "Error: authentication required" >&2
      exit 1
    fi
  fi
  echo "Getting image source signatures"
  echo "Copying blob sha256:000000000000"
  echo "Copying config sha256:000000000000"
  echo "Writing manifest to image destination"
  exit 0
fi

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

if [[ "$src" == containers-storage:* && "$dst" == containers-storage:* ]]; then
  src_ref="${src#containers-storage:}"
  dst_spec="${dst#containers-storage:}"
  dst_root="${BOXR_HOME:?BOXR_HOME required}"
  dst_ref="$dst_spec"
  if [[ "$dst_spec" == \[*\]* ]]; then
    bracket="${dst_spec#\[}"
    bracket="${bracket%%\]*}"
    dst_ref="${dst_spec#*\]}"
    if [[ "$bracket" == *@* ]]; then
      paths="${bracket#*@}"
      dst_root="${paths%%+*}"
    fi
  fi
  python3 - "${BOXR_HOME:?}" "$src_ref" "$dst_root" "$dst_ref" <<'PY'
import json, os, shutil, subprocess, sys
src_home, src_ref, dst_root, dst_ref = sys.argv[1:5]
src_idx = os.path.join(src_home, "images.json")
with open(src_idx, "r", encoding="utf-8") as f:
    src_data = json.load(f)
matched = []
for rec in src_data.get("images", []):
    q = f"{rec.get('registry','')}/{rec.get('reference','')}:{rec.get('tag','')}"
    s = f"{rec.get('reference','')}:{rec.get('tag','')}"
    if src_ref in (q, s, rec.get("reference", ""), rec.get("id", "")):
        matched.append(dict(rec))
if not matched:
    raise SystemExit(f"skopeo-stub: source image {src_ref} not found")
os.makedirs(os.path.join(dst_root, "images"), exist_ok=True)
os.makedirs(os.path.join(dst_root, "layers"), exist_ok=True)
dst_idx = os.path.join(dst_root, "images.json")
dst_data = {"images": []}
if os.path.isfile(dst_idx):
    try:
        with open(dst_idx, "r", encoding="utf-8") as f:
            dst_data = json.load(f)
    except Exception:
        dst_data = {"images": []}
for rec in matched:
    old_rootfs = rec.get("rootfs_path", "")
    img_dir_name = os.path.basename(os.path.dirname(old_rootfs))
    src_img_dir = os.path.join(src_home, "images", img_dir_name)
    dst_img_dir = os.path.join(dst_root, "images", img_dir_name)
    if os.path.isdir(src_img_dir) and not os.path.exists(dst_img_dir):
        if subprocess.call(["cp", "-al", src_img_dir, dst_img_dir]) != 0:
            shutil.copytree(src_img_dir, dst_img_dir, symlinks=True)
        try:
            os.chmod(dst_img_dir, 0o755)
            os.chmod(os.path.join(dst_img_dir, "rootfs"), 0o755)
        except OSError:
            pass
    rec["rootfs_path"] = os.path.join(dst_img_dir, "rootfs")
    dst_data["images"].append(rec)
with open(dst_idx, "w", encoding="utf-8") as f:
    json.dump(dst_data, f, indent=2)
PY
  exit 0
fi

echo "skopeo-stub: unsupported copy $src -> $dst" >&2
exit 1
