# -*- bash -*-
# Appended to Podman test/system/helpers.bash when running BATS against boxr.

IMAGE=${IMAGE:-alpine:3.20}
PODMAN_TEST_IMAGE_FQN=${PODMAN_TEST_IMAGE_FQN:-alpine:3.20}

function gen-cert-pair {
  cn=$1 key=$2 cert=$3
  shift 3
  openssl req -x509 \
    -nodes \
    -newkey rsa:2048 -keyout "${key}" \
    -out "${cert}" \
    -days 1 \
    -subj "/C=US/ST=Test/L=Test/O=Boxr/OU=BATS/CN=${cn}" \
    "$@"
}

function timeout() {
    if [[ "${1:-}" == "10" && "${2:-}" == "socat" ]]; then
        shift
        command timeout 60 "$@"
        return $?
    fi
    command timeout "$@"
}

# boxr has no skopeo cache path; pull via the CLI under test (with local image store cache).
function _prefetch() {
    local want=$1
    run_podman '?' image exists "$want"
    if [[ $status -eq 0 ]]; then
        return
    fi
    local cache_root="/tmp/boxr-bats-imgcache-$(id -u)"
    local cache_key
    cache_key="$(echo "$want" | tr '/:@' '___')"
    local cache_dir="$cache_root/$cache_key"
    if [[ -n "${BOXR_HOME:-}" && -f "$cache_dir/images.json" && -d "$cache_dir/images" && -d "$cache_dir/layers" ]]; then
        chmod u+w "$cache_dir/images"/*/rootfs 2>/dev/null || true
        mkdir -p "$BOXR_HOME/images" "$BOXR_HOME/layers"
        cp -al "$cache_dir/images/." "$BOXR_HOME/images/" 2>/dev/null || cp -a "$cache_dir/images/." "$BOXR_HOME/images/"
        cp -al "$cache_dir/layers/." "$BOXR_HOME/layers/" 2>/dev/null || cp -a "$cache_dir/layers/." "$BOXR_HOME/layers/"
        if [[ "$want" == *"libpod/testimage"* ]]; then
            chmod 555 "$BOXR_HOME/images"/*/rootfs 2>/dev/null || true
        fi
        cp "$cache_dir/images.json" "$BOXR_HOME/images.json"
        sed -i "s|$cache_dir/images|$BOXR_HOME/images|g" "$BOXR_HOME/images.json"
        run_podman '?' image exists "$want"
        if [[ $status -eq 0 ]]; then
            return
        fi
    fi
    run_podman pull "$want"
    if [[ -n "${BOXR_HOME:-}" && -f "$BOXR_HOME/images.json" && -d "$BOXR_HOME/images" && ! -d "$cache_dir/layers" ]]; then
        local tmp_cache="$cache_dir.tmp.$$"
        chmod u+w "$cache_dir/images"/*/rootfs "$BOXR_HOME/images"/*/rootfs 2>/dev/null || true
        rm -rf "$cache_dir" "$tmp_cache"
        mkdir -p "$tmp_cache/images" "$tmp_cache/layers"
        cp -al "$BOXR_HOME/images/." "$tmp_cache/images/" 2>/dev/null || cp -a "$BOXR_HOME/images/." "$tmp_cache/images/"
        if [[ -d "$BOXR_HOME/layers" ]]; then
            cp -al "$BOXR_HOME/layers/." "$tmp_cache/layers/" 2>/dev/null || cp -a "$BOXR_HOME/layers/." "$tmp_cache/layers/"
        fi
        if [[ "$want" == *"libpod/testimage"* ]]; then
            chmod 555 "$BOXR_HOME/images"/*/rootfs 2>/dev/null || true
        fi
        cp "$BOXR_HOME/images.json" "$tmp_cache/images.json"
        sed -i "s|$BOXR_HOME/images|$cache_dir/images|g" "$tmp_cache/images.json"
        mv "$tmp_cache" "$cache_dir" 2>/dev/null || rm -rf "$tmp_cache"
    fi
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
