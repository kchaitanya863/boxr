# -*- bash -*-
# Appended to Podman test/system/helpers.bash when running BATS against boxr.
# Overrides teardown helpers and TLS generation for boxr + OpenSSL 3.x.

IMAGE=${IMAGE:-alpine:3.20}
PODMAN_TEST_IMAGE_FQN=${PODMAN_TEST_IMAGE_FQN:-alpine:3.20}

function gen-cert-pair {
  cn=$1 key=$2 cert=$3
  shift 3
  openssl req -x509 \
    -nodes \
    -newkey rsa:4096 -keyout "${key}" \
    -out "${cert}" \
    -days 1 \
    -subj "/C=US/ST=Test/L=Test/O=Boxr/OU=BATS/CN=${cn}" \
    "$@"
}

function clean_setup() {
    _run_podman_quiet ps -aq
    if [[ ${#lines[@]} -gt 0 && -n "${lines[0]}" ]]; then
        _run_podman_quiet rm -f "${lines[@]}"
    fi

    _run_podman_quiet pod ps -q
    if [[ ${#lines[@]} -gt 0 && -n "${lines[0]}" ]]; then
        _run_podman_quiet pod rm -f "${lines[@]}"
    fi

    _run_podman_quiet network ls -q
    if [[ ${#lines[@]} -gt 0 && -n "${lines[0]}" ]]; then
        for n in "${lines[@]}"; do
            [[ "$n" == "bridge" ]] && continue
            _run_podman_quiet network rm "$n"
        done
    fi

    _run_podman_quiet volume ls -q
    if [[ ${#lines[@]} -gt 0 && -n "${lines[0]}" ]]; then
        for v in "${lines[@]}"; do
            _run_podman_quiet volume rm "$v"
        done
    fi
}
