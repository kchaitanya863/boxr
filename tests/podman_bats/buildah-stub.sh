#!/usr/bin/env bash
# Minimal buildah stub for Podman BATS (external storage containers).
set -euo pipefail

home="${BOXR_HOME:-${BOXR_BATS_HOME:-$HOME/.boxr}}"
names_file="$home/external-container-names"
containers_file="$home/external-containers.json"
state_dir="$home/buildah-stub"

mkdir -p "$home" "$state_dir"

load_json() {
  if [[ -f "$containers_file" ]]; then
    cat "$containers_file"
  else
    echo "[]"
  fi
}

save_container() {
  local id="$1" image="$2" name="$3" rootfs="${4:-}"
  python3 - "$id" "$image" "$name" "$rootfs" "$containers_file" <<'PY'
import json, sys, time, os
cid, image, name, rootfs, path = sys.argv[1:6]
rows = []
if os.path.isfile(path):
    with open(path) as f:
        rows = json.load(f)
rows.append({
    "id": cid,
    "image": image,
    "name": name,
    "rootfs": rootfs if rootfs else None,
    "mounted": False,
    "created_unix": int(time.time()),
})
os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
with open(path, "w") as f:
    json.dump(rows, f, indent=2)
PY
  echo "$name" >>"$names_file"
}

new_id() {
  openssl rand -hex 32
}

image_name_from_ref() {
  local ref="$1"
  local base
  base="$(basename "$ref")"
  base="${base%%:*}"
  echo "${base}-working-container"
}

if [[ "${1:-}" == "unshare" ]]; then
  shift
  if [[ "${1:-}" == "buildah" ]]; then
    shift
  fi
fi

if [[ "${1:-}" == "from" && "${2:-}" == "--name" && -n "${3:-}" ]]; then
  name="${3}"
  img="${4:-scratch}"
  cid="$(new_id)"
  rootfs_dir="$state_dir/containers/$name/rootfs"
  mkdir -p "$rootfs_dir"

  img_rootfs="$(python3 - "$img" "$home" <<'PY'
import json, sys, os
img, home = sys.argv[1:3]
ipath = os.path.join(home, "images.json")
if os.path.isfile(ipath):
    with open(ipath) as f:
        data = json.load(f)
    for rec in data.get("images", []):
        ref = rec.get("reference", "")
        tag = rec.get("tag", "")
        reg = rec.get("registry", "")
        full = f"{ref}:{tag}" if tag else ref
        reg_full = f"{reg}/{full}" if reg else full
        candidates = {
            rec.get("id", ""),
            ref,
            full,
            reg_full,
            rec.get("manifest_digest", ""),
            rec.get("config_digest", ""),
        }
        if img in candidates or any(c.endswith(f"/{img}") or img.endswith(f"/{c}") for c in candidates if c):
            rpath = rec.get("rootfs_path", "")
            if os.path.isdir(rpath):
                print(rpath)
                break
PY
)"
  if [[ -z "$img_rootfs" && -n "${BOXR_BIN:-}" && -x "$BOXR_BIN" && "$img" != "scratch" ]]; then
    "$BOXR_BIN" pull "$img" >/dev/null 2>&1 || true
    img_rootfs="$(python3 - "$img" "$home" <<'PY'
import json, sys, os
img, home = sys.argv[1:3]
ipath = os.path.join(home, "images.json")
if os.path.isfile(ipath):
    with open(ipath) as f:
        data = json.load(f)
    for rec in data.get("images", []):
        ref = rec.get("reference", "")
        tag = rec.get("tag", "")
        reg = rec.get("registry", "")
        full = f"{ref}:{tag}" if tag else ref
        reg_full = f"{reg}/{full}" if reg else full
        candidates = {
            rec.get("id", ""),
            ref,
            full,
            reg_full,
            rec.get("manifest_digest", ""),
            rec.get("config_digest", ""),
        }
        if img in candidates or any(c.endswith(f"/{img}") or img.endswith(f"/{c}") for c in candidates if c):
            rpath = rec.get("rootfs_path", "")
            if os.path.isdir(rpath):
                print(rpath)
                break
PY
)"
  fi
  if [[ -n "$img_rootfs" && -d "$img_rootfs" ]]; then
    cp -a "$img_rootfs/." "$rootfs_dir/"
  fi

  save_container "$cid" "$img" "$name" "$rootfs_dir"
  echo "$name"
  exit 0
fi

if [[ "${1:-}" == "run" && -n "${2:-}" ]]; then
  cname="$2"
  shift 2
  rootfs="$(python3 - "$cname" "$containers_file" <<'PY'
import json, sys, os
name, path = sys.argv[1:3]
if os.path.isfile(path):
    with open(path) as f:
        rows = json.load(f)
    for c in rows:
        if c.get("name") == name or c.get("id") == name:
            r = c.get("rootfs")
            if r and os.path.isdir(r):
                print(r)
                break
PY
)"
  if [[ -n "$rootfs" && -d "$rootfs" ]]; then
    if [[ -n "${BOXR_BIN:-}" && -x "$BOXR_BIN" ]]; then
      "$BOXR_BIN" unshare chroot "$rootfs" "$@"
    else
      chroot "$rootfs" "$@"
    fi
    exit 0
  fi
  exit 0
fi

if [[ "${1:-}" == "rm" && -n "${2:-}" ]]; then
  target="$2"
  python3 - "$target" "$containers_file" "$names_file" <<'PY'
import json, sys, os, shutil
target, cpath, npath = sys.argv[1:4]
if os.path.isfile(cpath):
    with open(cpath) as f:
        rows = json.load(f)
    rem = [c for c in rows if c.get("name") == target or c.get("id") == target]
    rows = [c for c in rows if c.get("name") != target and c.get("id") != target]
    with open(cpath, "w") as f:
        json.dump(rows, f, indent=2)
    for c in rem:
        r = c.get("rootfs")
        if r:
            p = os.path.dirname(r)
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
if os.path.isfile(npath):
    with open(npath) as f:
        lines = f.read().splitlines()
    lines = [l for l in lines if l.strip() != target]
    with open(npath, "w") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
PY
  exit 0
fi

if [[ "${1:-}" == "from" && -n "${2:-}" ]]; then
  image_ref="$2"
  cid="$(new_id)"
  cname="$(image_name_from_ref "$image_ref")"
  save_container "$cid" "$image_ref" "$cname"
  echo "$cid"
  exit 0
fi

if [[ "${1:-}" == "commit" && -n "${2:-}" ]]; then
  cid_prefix="$2"
  img_id="$(new_id)"
  echo "$img_id" >"$state_dir/last-commit-image"
  echo "$img_id"
  exit 0
fi

if [[ "${1:-}" == "mount" && -n "${2:-}" ]]; then
  cid_prefix="$2"
  python3 - "$cid_prefix" "$containers_file" <<'PY'
import json, sys
prefix, path = sys.argv[1:3]
with open(path) as f:
    rows = json.load(f)
for row in rows:
    if row["id"].startswith(prefix) or prefix.startswith(row["id"][:12]):
        row["mounted"] = True
        break
with open(path, "w") as f:
    json.dump(rows, f, indent=2)
PY
  echo "/tmp/buildah-stub-mount-${cid_prefix:0:12}"
  exit 0
fi

echo "Error: buildah stub does not implement: $*" >&2
exit 127
