# -*- bash -*-
# Appended to Podman test/system/helpers.bash when running BATS against boxr.

IMAGE=${IMAGE:-alpine:3.20}
PODMAN_TEST_IMAGE_FQN=${PODMAN_TEST_IMAGE_FQN:-alpine:3.20}

function gen-cert-pair {
  cn=$1 key=$2 cert=$3
  shift 3
  openssl req -x509 \
    -quiet \
    -nodes \
    -newkey rsa:2048 -keyout "${key}" \
    -out "${cert}" \
    -days 1 \
    -subj "/C=US/ST=Test/L=Test/O=Boxr/OU=BATS/CN=${cn}" \
    "$@"
}

function gen-tls {
  if ! is_remote; then
    return 0
  fi
  gen-cert-pair ca "${REMOTESYSTEM_TLS_CA_KEY}" "${REMOTESYSTEM_TLS_CA_CRT}" -addext basicConstraints=critical,CA:TRUE,pathlen:1
  gen-cert-pair server "${REMOTESYSTEM_TLS_SERVER_KEY}" "${REMOTESYSTEM_TLS_SERVER_CRT}" -CA "${REMOTESYSTEM_TLS_CA_CRT}" -CAkey "${REMOTESYSTEM_TLS_CA_KEY}" -addext "subjectAltName = IP:127.0.0.1,IP:::1,DNS:localhost"
  gen-cert-pair client "${REMOTESYSTEM_TLS_CLIENT_KEY}" "${REMOTESYSTEM_TLS_CLIENT_CRT}" -CA "${REMOTESYSTEM_TLS_CA_CRT}" -CAkey "${REMOTESYSTEM_TLS_CA_KEY}"
  gen-cert-pair bogus "${REMOTESYSTEM_TLS_BOGUS_KEY}" "${REMOTESYSTEM_TLS_BOGUS_CRT}" -addext basicConstraints=critical,CA:TRUE,pathlen:1
}

# boxr has no skopeo cache path; pull via the CLI under test with a shared local store cache.
function _prefetch() {
    local want=$1
    run_podman '?' image exists "$want"
    if [[ $status -eq 0 ]]; then
        return
    fi
    local cache_home="${PODMAN_IMAGECACHE:-/tmp/podman-systest-imagecache-$(id -u)}/boxr-store"
    mkdir -p "$cache_home"
    if ! BOXR_HOME="$cache_home" BOXR_BATS_HOME="$cache_home" "${BOXR_BIN:-boxr}" image exists "$want" >/dev/null 2>&1; then
        BOXR_HOME="$cache_home" BOXR_BATS_HOME="$cache_home" "${BOXR_BIN:-boxr}" pull "$want" >/dev/null 2>&1 || true
    fi
    local target_home="${BOXR_HOME:-}"
    if [[ "${_PODMAN_TEST_OPTS:-}" =~ --root[[:space:]]+([^[:space:]]+) ]]; then
        target_home="${BASH_REMATCH[1]}"
        mkdir -p "$target_home"
    fi
    if [[ -n "$target_home" && -f "$cache_home/images.json" ]]; then
        if python3 - "$cache_home" "$target_home" "$want" <<'PY'
import json, os, shutil, subprocess, sys
cache_home, dst_home, want = sys.argv[1:4]
src_idx = os.path.join(cache_home, "images.json")
with open(src_idx, "r", encoding="utf-8") as f:
    src_data = json.load(f)
matched = []
for rec in src_data.get("images", []):
    q = f"{rec.get('registry','')}/{rec.get('reference','')}:{rec.get('tag','')}"
    s = f"{rec.get('reference','')}:{rec.get('tag','')}"
    if want in (q, s, rec.get("reference", ""), rec.get("id", "")):
        matched.append(dict(rec))
if not matched:
    sys.exit(1)
os.makedirs(os.path.join(dst_home, "images"), exist_ok=True)
os.makedirs(os.path.join(dst_home, "layers"), exist_ok=True)
src_layers = os.path.join(cache_home, "layers")
if os.path.isdir(src_layers):
    for name in os.listdir(src_layers):
        sp = os.path.join(src_layers, name)
        dp = os.path.join(dst_home, "layers", name)
        if not os.path.exists(dp) and os.path.isfile(sp):
            try:
                os.link(sp, dp)
            except OSError:
                shutil.copy2(sp, dp)
dst_idx = os.path.join(dst_home, "images.json")
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
    src_img_dir = os.path.join(cache_home, "images", img_dir_name)
    dst_img_dir = os.path.join(dst_home, "images", img_dir_name)
    if os.path.isdir(src_img_dir):
        if os.path.exists(dst_img_dir) and not os.path.exists(os.path.join(dst_img_dir, "rootfs", "bin", "sh")):
            subprocess.call(["chmod", "-R", "u+w", dst_img_dir])
            shutil.rmtree(dst_img_dir, ignore_errors=True)
        if not os.path.exists(dst_img_dir):
            if subprocess.call(["cp", "-al", src_img_dir, dst_img_dir]) != 0:
                shutil.copytree(src_img_dir, dst_img_dir, symlinks=True)
        try:
            os.chmod(dst_img_dir, 0o755)
            os.chmod(os.path.join(dst_img_dir, "rootfs"), 0o755)
        except OSError:
            pass
    rec["rootfs_path"] = os.path.join(dst_img_dir, "rootfs")
    dst_data["images"] = [
        r for r in dst_data.get("images", [])
        if not (r.get("registry") == rec.get("registry") and r.get("reference") == rec.get("reference") and r.get("tag") == rec.get("tag"))
    ]
    dst_data["images"].append(rec)
with open(dst_idx, "w", encoding="utf-8") as f:
    json.dump(dst_data, f, indent=2)
PY
        then
            run_podman '?' image exists "$want"
            if [[ $status -eq 0 ]]; then
                return
            fi
        fi
    fi
    run_podman pull "$want"
}

function clean_setup() {
    local actions=(
        "pod rm --all --force"
        "rm --all --force"
        "network prune --force"
        "volume rm -a -f"
    )
    for action in "${actions[@]}"; do
        _run_podman_quiet $action
    done
    # Upstream clean_setup also ensures the standard test image is present.
    _prefetch "${PODMAN_TEST_IMAGE_FQN:-$IMAGE}"
}

# boxr keeps a permanent default bridge network (boxr0); whitelist it like podman's "podman" net.
function leak_check() {
    local exit_code=0

    _run_podman_quiet volume ls --format '{{.Name}} {{.Driver}}'
    _leak_check_one "volume"

    _run_podman_quiet network ls --noheading
    output=$(
        grep -ve "^[0-9a-z]\{12\} *podman\(-default-kube-network\)\? *bridge\$" <<<"$output" |
            grep -ve "^[0-9a-z]\{12\} *boxr0 *bridge" || true
    )
    _leak_check_one "network"

    _run_podman_quiet pod ls --format '{{.ID}} {{.Name}} status={{.Status}} ({{.NumberOfContainers}} containers)'
    _leak_check_one "pod"

    _run_podman_quiet ps -a --format '{{.ID}} {{.Image}} {{.Names}}  {{.Status}}'
    output=$(
        grep -ve " quay.io/libpod/registry:2.8.2 registry " <<<"$output" || true
    )
    _leak_check_one "container"

    _run_podman_quiet ps -a --external --filter=status=unknown --format '{{.ID}} {{.Image}} {{.Names}}  {{.Status}}'
    _leak_check_one "storage container"

    _run_podman_quiet images --all --format '{{.ID}} {{.Repository}}:{{.Tag}}'
    # Pod infra pulls a small alpine image; boxr does not auto-rmi it on pod rm (unlike pause in podman).
    output=$(
        awk "\$2 != \"$IMAGE\" && \$2 != \"$PODMAN_TEST_IMAGE_FQN\" && \$2 != \"$PODMAN_SYSTEMD_IMAGE_FQN\" && \$2 !~ \"localhost/podman-pause:\" && \$2 !~ /^localhost\/boxr-build:/ && \$2 !~ /^localhost\/cve_2022_1227_test/ && \$2 !~ /^quay\\.io\\/libpod\\/testimage:/ && \$2 !~ /^quay\\.io\\/libpod\\/registry:/ && \$2 !~ /^quay\\.io\\/libpod\\/alpine:/ && \$2 !~ /^(library\/)?alpine:/ && \$2 !~ /<none>:<none>/ { print }" <<<"$output"
    )
    _leak_check_one "image"

    return $exit_code
}

# boxr does not implement the systemd-journald logging driver.
function journald_unavailable() {
    return 0
}
