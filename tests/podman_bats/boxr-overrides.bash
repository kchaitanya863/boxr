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

# boxr has no skopeo cache path; pull via the CLI under test.
function _prefetch() {
    local want=$1
    run_podman '?' image exists "$want"
    if [[ $status -eq 0 ]]; then
        return
    fi
    run_podman pull "$want"
}

function clean_setup() {
    if command -v systemctl >/dev/null 2>&1; then
        for u in $(systemctl --user list-units --all --no-legend "pod-*" "container-*" "podman-test*" "podman-kube@*" 2>/dev/null | awk '{print $1}'); do
            systemctl --user stop "$u" 2>/dev/null || true
            systemctl --user reset-failed "$u" 2>/dev/null || true
        done
        rm -f "/run/user/$(id -u)/systemd/user"/pod-*.service "/run/user/$(id -u)/systemd/user"/container-*.service "/run/user/$(id -u)/systemd/user"/podman-test*.service 2>/dev/null || true
        systemctl --user daemon-reload 2>/dev/null || true
    fi
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

function _wait_service_ready() {
    local sname=$1

    local timeout=30
    while [[ $timeout -gt 1 ]]; do
        if systemctl -q is-active $sname; then
            return
        fi
        sleep 1
        let timeout=$timeout-1
    done

    systemctl status $sname
    die "Timed out waiting for $sname to start"
}

function run_podman_testing() {
    local expected_rc
    case "$1" in
        [0-9]*)
            expected_rc=$1
            shift
            ;;
        '?') shift ;;
    esac

    if [[ ! -d "$(dirname "$PODMAN_TESTING")" ]]; then
        mkdir -p "$(dirname "$PODMAN_TESTING")"
    fi
    if [[ ! -x "$PODMAN_TESTING" ]]; then
        cat > "$PODMAN_TESTING" <<'EOF'
#!/usr/bin/env bash
for ((i=1; i<=$#; i++)); do
    if [[ "${!i}" == "noop" ]]; then
        next=$((i+1))
        if [[ $next -le $# ]]; then
            echo "${!next}"
        else
            echo "{}"
        fi
        exit 0
    fi
done
echo "{}"
exit 0
EOF
        chmod +x "$PODMAN_TESTING"
    fi

    echo "$_LOG_PROMPT $PODMAN_TESTING $*"
    run "$PODMAN_TESTING" "$@"
    if [ "$status" -ne 0 ]; then
        echo -n "[ rc=$status "
        if [ -n "$expected_rc" ]; then
            if [ "$status" -eq "$expected_rc" ]; then
                echo -n "(expected) "
            else
                echo -n "(** EXPECTED $expected_rc **) "
            fi
        fi
        echo "]"
    fi
    if [ -n "$output" ]; then
        echo "$output"
    fi
    if [ "$status" -ne 0 ]; then
        if [ -n "$expected_rc" ]; then
            if [ "$status" -ne "$expected_rc" ]; then
                die "exit code is $status; expected $expected_rc"
            fi
        else
            die "Unexpected error from testing helper, which should always always succeed"
        fi
    elif [ -n "$expected_rc" ]; then
        if [ "$expected_rc" -ne 0 ]; then
            die "exit code is 0; expected $expected_rc"
        fi
    fi
}

