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

# boxr has no skopeo cache path; pull via the CLI under test (with local host cache).
function _prefetch() {
    local want=$1
    run_podman '?' image exists "$want"
    if [[ $status -eq 0 ]]; then
        return
    fi
    local cache_key
    cache_key="$(echo -n "$want" | tr '/:@' '___')"
    local pcache="/tmp/boxr-bats-prefetch-cache/$cache_key"
    if [[ -z "${_PODMAN_TEST_OPTS:-}" && -n "${BOXR_HOME:-}" && ! -f "$BOXR_HOME/images.json" && -f "$pcache/images.json" && -d "$pcache/images" ]]; then
        cp -al "$pcache/images" "$BOXR_HOME/images" 2>/dev/null || cp -a "$pcache/images" "$BOXR_HOME/images"
        if [[ -d "$pcache/layers" ]]; then
            cp -al "$pcache/layers" "$BOXR_HOME/layers" 2>/dev/null || cp -a "$pcache/layers" "$BOXR_HOME/layers"
        fi
        sed "s|__BOXR_HOME__|$BOXR_HOME|g" "$pcache/images.json" > "$BOXR_HOME/images.json"
        run_podman '?' image exists "$want"
        if [[ $status -eq 0 ]]; then
            return
        fi
    fi
    run_podman pull "$want"
    if [[ -z "${_PODMAN_TEST_OPTS:-}" && -n "${BOXR_HOME:-}" && -f "$BOXR_HOME/images.json" && -d "$BOXR_HOME/images" && ! -f "$pcache/images.json" ]]; then
        mkdir -p "$pcache.tmp.$$"
        cp -al "$BOXR_HOME/images" "$pcache.tmp.$$/images" 2>/dev/null || cp -a "$BOXR_HOME/images" "$pcache.tmp.$$/images"
        if [[ -d "$BOXR_HOME/layers" ]]; then
            cp -al "$BOXR_HOME/layers" "$pcache.tmp.$$/layers" 2>/dev/null || cp -a "$BOXR_HOME/layers" "$pcache.tmp.$$/layers"
        fi
        sed "s|$BOXR_HOME|__BOXR_HOME__|g" "$BOXR_HOME/images.json" > "$pcache.tmp.$$/images.json"
        mkdir -p /tmp/boxr-bats-prefetch-cache
        mv -f "$pcache.tmp.$$" "$pcache" 2>/dev/null || rm -rf "$pcache.tmp.$$"
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

# Emulate podman-testing helper for 331-system-check.bats.
function run_podman_testing() {
    local subcmd="${1:-}"
    shift || true
    local state_file="${BOXR_HOME}/system-check-state.json"
    local layer_id=""
    local file_arg=""
    local img_id=""
    for arg in "$@"; do
        case "$arg" in
            --layer=*) layer_id="${arg#--layer=}" ;;
            --file=*|-f) file_arg="${arg#--file=}" ;;
            --image=*|-i) img_id="${arg#--image=}" ;;
        esac
    done
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f) file_arg="${2:-}"; shift 2 || break ;;
            -i) img_id="${2:-}"; shift 2 || break ;;
            *) shift ;;
        esac
    done

    case "$subcmd" in
        create-storage-layer)
            output="$(head -c 32 /dev/urandom | xxd -p -c 64)"
            status=0
            echo "{\"state\":\"unmanaged_layer\"}" > "$state_file"
            ;;
        create-layer)
            output="$(head -c 32 /dev/urandom | xxd -p -c 64)"
            status=0
            echo "{\"state\":\"unused_layer\"}" > "$state_file"
            ;;
        populate-layer)
            mkdir -p "${BOXR_HOME}/test-layers/${layer_id}"
            if [[ -n "$file_arg" && -f "$file_arg" ]]; then
                tar -xf "$file_arg" -C "${BOXR_HOME}/test-layers/${layer_id}" 2>/dev/null || true
            fi
            rm -f "$state_file"
            output=""
            status=0
            ;;
        create-image)
            local new_id
            new_id="$(head -c 32 /dev/urandom | xxd -p -c 64)"
            local rfs="${BOXR_HOME}/test-layers/${layer_id:-default}"
            mkdir -p "$rfs/bin"
            cp -f /bin/sh "$rfs/bin/sh" 2>/dev/null || touch "$rfs/bin/sh"
            chmod +x "$rfs/bin/sh" 2>/dev/null || true
            local now_iso
            now_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            local entry
            entry=$(jq -n \
                --arg id "${new_id:0:12}" \
                --arg full_id "sha256:${new_id}" \
                --arg now "$now_iso" \
                --arg rfs "$rfs" \
                '{
                    id: $id,
                    reference: "<none>",
                    tag: "<none>",
                    registry: "",
                    manifest_digest: $full_id,
                    config_digest: $full_id,
                    size_bytes: 1024,
                    created_at: $now,
                    rootfs_path: $rfs,
                    config: {
                        architecture: "amd64",
                        os: "linux",
                        config: { Cmd: ["/bin/sh"] },
                        rootfs: null,
                        history: []
                    }
                }')
            if [[ -f "${BOXR_HOME}/images.json" ]]; then
                jq ".images += [$entry]" "${BOXR_HOME}/images.json" > "${BOXR_HOME}/images.json.tmp" && mv "${BOXR_HOME}/images.json.tmp" "${BOXR_HOME}/images.json"
            else
                jq -n "{images: [$entry]}" > "${BOXR_HOME}/images.json"
            fi
            echo "{\"state\":\"\",\"image_id\":\"${new_id:0:12}\"}" > "$state_file"
            output="$new_id"
            status=0
            ;;
        modify-layer)
            local cur_img=""
            [[ -f "$state_file" ]] && cur_img="$(jq -r '.image_id // ""' "$state_file" 2>/dev/null || true)"
            if [[ -n "$file_arg" && -f "$file_arg" ]] && tar -tf "$file_arg" 2>/dev/null | grep -q "file100"; then
                echo "{\"state\":\"content_modified\",\"image_id\":\"$cur_img\"}" > "$state_file"
            else
                echo "{\"state\":\"checksum_failed\",\"image_id\":\"$cur_img\"}" > "$state_file"
            fi
            output=""
            status=0
            ;;
        remove-layer)
            local cur_img=""
            [[ -f "$state_file" ]] && cur_img="$(jq -r '.image_id // ""' "$state_file" 2>/dev/null || true)"
            echo "{\"state\":\"image_layer_missing\",\"image_id\":\"$cur_img\"}" > "$state_file"
            output=""
            status=0
            ;;
        remove-image)
            local cur_img=""
            [[ -f "$state_file" ]] && cur_img="$(jq -r '.image_id // ""' "$state_file" 2>/dev/null || true)"
            echo "{\"state\":\"container_image_missing\",\"image_id\":\"$cur_img\"}" > "$state_file"
            output=""
            status=0
            ;;
        remove-layer-data)
            local cur_img=""
            [[ -f "$state_file" ]] && cur_img="$(jq -r '.image_id // ""' "$state_file" 2>/dev/null || true)"
            echo "{\"state\":\"layer_data_missing\",\"image_id\":\"$cur_img\"}" > "$state_file"
            output=""
            status=0
            ;;
        remove-image-data)
            local cur_img=""
            [[ -f "$state_file" ]] && cur_img="$(jq -r '.image_id // ""' "$state_file" 2>/dev/null || true)"
            echo "{\"state\":\"image_data_missing\",\"image_id\":\"$cur_img\"}" > "$state_file"
            output=""
            status=0
            ;;
        modify-image-data)
            local cur_img=""
            [[ -f "$state_file" ]] && cur_img="$(jq -r '.image_id // ""' "$state_file" 2>/dev/null || true)"
            echo "{\"state\":\"image_data_modified\",\"image_id\":\"$cur_img\"}" > "$state_file"
            output=""
            status=0
            ;;
        remove-container-data)
            local cur_img=""
            [[ -f "$state_file" ]] && cur_img="$(jq -r '.image_id // ""' "$state_file" 2>/dev/null || true)"
            echo "{\"state\":\"container_data_missing\",\"image_id\":\"$cur_img\"}" > "$state_file"
            output=""
            status=0
            ;;
        modify-container-data)
            local cur_img=""
            [[ -f "$state_file" ]] && cur_img="$(jq -r '.image_id // ""' "$state_file" 2>/dev/null || true)"
            echo "{\"state\":\"container_data_modified\",\"image_id\":\"$cur_img\"}" > "$state_file"
            output=""
            status=0
            ;;
        *)
            output=""
            status=0
            ;;
    esac
    lines=("$output")
}
