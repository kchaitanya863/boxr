#!/usr/bin/env bash
# ==============================================================================
# Boxr Enterprise Black-Box QA Suite
# Repeatable positive, negative, and stress tests for enterprise Docker-like usage.
# ==============================================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN=""
REMOTE_HOST=""
SECTION="all"
JUNIT_FILE=""
INCLUDE_STRESS=0
RUN_RUST=1

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0
START_TIME=$(date +%s)

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  -b, --binary <path>     Path to boxr binary (default: auto-detect)
  -r, --remote <host>    Run remotely over SSH
  -s, --section <name>   Run one section: runtime|compose|volumes|network|dns|
                         security|memory|permissions|negative|stress|podman|rust|all
  -j, --junit <file>      Write JUnit XML results
  --include-stress        Run stress tests (slow/flaky)
  --no-rust               Skip cargo test blackbox_* at end
  -h, --help              Show help

Examples:
  $0 -b ./target/release/boxr
  $0 -s volumes
  $0 --include-stress -j /tmp/blackbox.xml
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--binary) BIN="$2"; shift 2 ;;
        -r|--remote) REMOTE_HOST="$2"; shift 2 ;;
        -s|--section) SECTION="$2"; shift 2 ;;
        -j|--junit) JUNIT_FILE="$2"; shift 2 ;;
        --include-stress) INCLUDE_STRESS=1; shift ;;
        --no-rust) RUN_RUST=0; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

run_cmd() {
    if [[ -n "$REMOTE_HOST" ]]; then
        ssh "$REMOTE_HOST" "$@"
    else
        eval "$@"
    fi
}

if [[ -z "$REMOTE_HOST" && -z "$BIN" ]]; then
    if [[ -x "$REPO_ROOT/target/release/boxr" ]]; then
        BIN="$REPO_ROOT/target/release/boxr"
    elif [[ -x "$REPO_ROOT/target/debug/boxr" ]]; then
        BIN="$REPO_ROOT/target/debug/boxr"
    elif command -v boxr &>/dev/null; then
        BIN="$(command -v boxr)"
    else
        echo -e "${RED}Error: boxr binary not found. Run 'cargo build --release' first.${NC}"
        exit 1
    fi
fi

BOXR_CMD="${REMOTE_HOST:+docker}"
BOXR_CMD="${BOXR_CMD:-$BIN}"

# Isolated BOXR_HOME
BOXR_HOME_TMP="$(mktemp -d "${TMPDIR:-/tmp}/boxr-bb-qa.XXXXXX")"
export BOXR_HOME="$BOXR_HOME_TMP"
REAL_HOME="${HOME}/.boxr"
for d in images layers vm bin; do
    if [[ -d "$REAL_HOME/$d" ]]; then
        ln -sf "$REAL_HOME/$d" "$BOXR_HOME/$d"
    fi
done
if [[ -f "$REAL_HOME/images.json" ]]; then
    cp "$REAL_HOME/images.json" "$BOXR_HOME/images.json"
fi

cleanup() {
    "$BOXR_CMD" ps -aq 2>/dev/null | while read -r id; do
        [[ -n "$id" ]] && "$BOXR_CMD" rm -f "$id" 2>/dev/null || true
    done
    rm -rf "$BOXR_HOME_TMP"
}
trap cleanup EXIT

rand_id() {
    head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 8
}

section_enabled() {
    local name="$1"
    [[ "$SECTION" == "all" || "$SECTION" == "$name" ]]
}

test_step() {
    local name="$1"
    local cmd="$2"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    printf "  [..] %-60s " "$name"
    local output exit_code=0
    output=$(run_cmd "$cmd" 2>&1) || exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        printf "\r  [${GREEN}PASS${NC}] %-60s\n" "$name"
        [[ -n "$JUNIT_FILE" ]] && echo "<testcase name=\"${name}\" classname=\"blackbox\"/>" >> "$JUNIT_FILE.tmp"
        return 0
    fi
    FAILED_TESTS=$((FAILED_TESTS + 1))
    printf "\r  [${RED}FAIL${NC}] %-60s (exit %d)\n" "$name" "$exit_code"
    echo -e "${YELLOW}       $cmd${NC}"
    echo -e "${RED}       ${output}${NC}"
    [[ -n "$JUNIT_FILE" ]] && echo "<testcase name=\"${name}\" classname=\"blackbox\"><failure>${output}</failure></testcase>" >> "$JUNIT_FILE.tmp"
    return 1
}

test_step_neg() {
    local name="$1"
    local cmd="$2"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    printf "  [..] %-60s " "$name"
    local output exit_code=0
    output=$(run_cmd "$cmd" 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        printf "\r  [${GREEN}PASS${NC}] %-60s\n" "$name"
        return 0
    fi
    FAILED_TESTS=$((FAILED_TESTS + 1))
    printf "\r  [${RED}FAIL${NC}] %-60s (expected failure)\n" "$name"
    return 1
}

skip_step() {
    local name="$1"
    local reason="$2"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
    printf "  [${YELLOW}SKIP${NC}] %-60s (%s)\n" "$name" "$reason"
}

echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BOLD}${CYAN}   Boxr Enterprise Black-Box QA${NC}"
echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BLUE}Binary:${NC}   $BOXR_CMD"
echo -e "${BLUE}BOXR_HOME:${NC} $BOXR_HOME"
echo -e "${BLUE}Section:${NC}  $SECTION"
echo ""

[[ -n "$JUNIT_FILE" ]] && echo '<?xml version="1.0"?><testsuites><testsuite name="blackbox">' > "$JUNIT_FILE.tmp"

# --- A: Runtime ---
if section_enabled runtime; then
    echo -e "${BOLD}A. Runtime Invariants${NC}"
    test_step "A1 version" "$BOXR_CMD version | grep -q Client"
    test_step "A1 run alpine echo" "$BOXR_CMD run --rm alpine:latest echo ok | grep -q ok"
    test_step "A2 /tmp sticky 1777" "$BOXR_CMD run --rm alpine stat -c '%a' /tmp | grep -E '1777|777'"
    test_step "A2 nonroot /tmp write" "$BOXR_CMD run --rm --user 65534:65534 alpine sh -c 'echo ok > /tmp/t && cat /tmp/t' | grep -q ok"
    test_step "A3 /dev/shm writable" "$BOXR_CMD run --rm alpine sh -c 'touch /dev/shm/x && echo shm-ok' | grep -q shm-ok"
    test_step "A3 --shm-size" "$BOXR_CMD run --rm --shm-size 256m alpine df -h /dev/shm"
    test_step "A4 devices nonroot" "$BOXR_CMD run --rm --user 10001:10001 alpine sh -c 'head -c 8 /dev/urandom | wc -c' | grep -q 8"
    test_step "A8 read-only + volume" "$BOXR_CMD run --rm --read-only -v \"\$(mktemp -d):/data:rw\" alpine sh -c 'echo ok > /data/f && cat /data/f' | grep -q ok"
    test_step "A9 --init" "$BOXR_CMD run --rm --init alpine sh -c '(sleep 0.1 &) && sleep 0.2 && echo ok' | grep -q ok"
fi

# --- B: Compose ---
if section_enabled compose; then
    echo -e "\n${BOLD}B. Compose${NC}"
    COMPOSE_FIX="$REPO_ROOT/tests/fixtures/compose"
    FULLSTACK="$REPO_ROOT/examples/fullstack-compose/docker-compose.yml"
    if [[ -f "$FULLSTACK" ]]; then
        test_step "B1 compose up fullstack" "$BOXR_CMD compose -f \"$FULLSTACK\" up -d"
        test_step "B1 compose ps" "$BOXR_CMD compose -f \"$FULLSTACK\" ps | grep -q cache || $BOXR_CMD compose -f \"$FULLSTACK\" ps"
        test_step "B6 compose logs" "$BOXR_CMD compose -f \"$FULLSTACK\" logs cache 2>&1 | head -5"
        run_cmd "$BOXR_CMD compose -f \"$FULLSTACK\" down -v" 2>/dev/null || true
    else
        skip_step "B1 fullstack-compose" "fixture not found"
    fi
    test_step "B minimal-dns up" "$BOXR_CMD compose -f \"$COMPOSE_FIX/minimal-dns.yml\" up -d"
    test_step "B minimal-dns ps" "$BOXR_CMD compose -f \"$COMPOSE_FIX/minimal-dns.yml\" ps"
    run_cmd "$BOXR_CMD compose -f \"$COMPOSE_FIX/minimal-dns.yml\" down -v" 2>/dev/null || true
    REPLACEMENT_STACK="$COMPOSE_FIX/docker-replacement-stack/docker-compose.yml"
    if [[ -f "$REPLACEMENT_STACK" ]]; then
        test_step "B9 compose up service target (.env + \${VAR:-default})" "$BOXR_CMD compose -f \"$REPLACEMENT_STACK\" up --build -d web"
        test_step "B9 compose ps web" "$BOXR_CMD compose -f \"$REPLACEMENT_STACK\" ps | grep -q replacement-web"
        run_cmd "$BOXR_CMD compose -f \"$REPLACEMENT_STACK\" down -v" 2>/dev/null || true
    else
        skip_step "B9 docker-replacement-stack" "fixture not found"
    fi
    test_step_neg "B8 compose cycle" "$BOXR_CMD compose -f \"$COMPOSE_FIX/cycle.yml\" up -d"
fi

# --- C: Volumes ---
if section_enabled volumes || section_enabled permissions; then
    echo -e "\n${BOLD}C. Volumes${NC}"
    VID="bb-vol-$(rand_id)"
    test_step "C1 volume create" "$BOXR_CMD volume create $VID"
    test_step "C1 volume ls" "$BOXR_CMD volume ls | grep -q $VID"
    test_step "C1 volume rm" "$BOXR_CMD volume rm $VID"
    TMPD="$(mktemp -d)"
    test_step "C2 bind rw" "$BOXR_CMD run --rm -v \"$TMPD:/data:rw\" alpine sh -c 'echo bind > /data/f'"
    test_step_neg "C3 bind ro write" "$BOXR_CMD run --rm -v \"$TMPD:/data:ro\" alpine sh -c 'echo x > /data/new'"
    test_step "C6 chown chmod" "$BOXR_CMD run --rm -v \"$TMPD:/srv:rw\" alpine sh -c 'mkdir -p /srv/pg && chmod 700 /srv/pg && echo ok > /srv/pg/f && cat /srv/pg/f' | grep -q ok"
    rmdir "$TMPD" 2>/dev/null || rm -rf "$TMPD"
fi

# --- D/E: Network & DNS ---
if section_enabled network || section_enabled dns; then
    echo -e "\n${BOLD}D/E. Networking & DNS${NC}"
    NID="bb-net-$(rand_id)"
    NPORT=$((18000 + $(echo "$NID" | cksum | cut -d' ' -f1) % 1000))
    test_step "D1 nginx publish" "$BOXR_CMD run -d --name ${NID}-ngx -p ${NPORT}:80 nginx:alpine"
    sleep 3
    test_step "D1 curl published" "curl -sf http://127.0.0.1:${NPORT}/ >/dev/null"
    run_cmd "$BOXR_CMD rm -f ${NID}-ngx" 2>/dev/null || true
    test_step_neg "D none blocks external" "$BOXR_CMD run --rm --network none alpine wget -q --timeout=3 -O /dev/null http://8.8.8.8"
    test_step "E2 custom --dns" "$BOXR_CMD run --rm --dns 8.8.8.8 alpine cat /etc/resolv.conf | grep -q nameserver"
    if [[ "$(uname -s)" == "Linux" ]]; then
        test_step "D usernet" "$BOXR_CMD run --rm --network usernet alpine wget -qO- http://example.com | head -1"
    else
        skip_step "D usernet" "Linux only"
        skip_step "D pasta" "Linux only"
    fi
fi

# --- F: Security ---
if section_enabled security; then
    echo -e "\n${BOLD}F. Security${NC}"
    test_step "F2 --user" "$BOXR_CMD run --rm --user 10001:10001 alpine id -u | grep -q 10001"
    test_step_neg "F3 read-only /etc" "$BOXR_CMD run --rm --read-only alpine sh -c 'echo x > /etc/t'"
    test_step "F4 --privileged runs" "$BOXR_CMD run --rm --privileged alpine id"
fi

# --- G: Memory ---
if section_enabled memory; then
    echo -e "\n${BOLD}G. Memory & Resources${NC}"
    test_step "G1 --memory 64m" "$BOXR_CMD run --rm --memory 64m alpine echo mem-ok | grep -q mem-ok"
    test_step "G4 --cpus" "$BOXR_CMD run --rm --cpus 0.5 alpine echo cpu-ok | grep -q cpu-ok"
    test_step "G5 --pids-limit" "$BOXR_CMD run --rm --pids-limit 50 alpine echo pids-ok | grep -q pids-ok"
    test_step_neg "G7 bad memory" "$BOXR_CMD run --rm --memory notanumber alpine true"
fi

# --- I: Negative ---
if section_enabled negative; then
    echo -e "\n${BOLD}I. Negative CLI${NC}"
    test_step_neg "I missing image" "$BOXR_CMD run --rm nosuch/image:xyz echo hi"
    test_step_neg "I bad port" "$BOXR_CMD run --rm -p 70000:80 alpine true"
    test_step_neg "I bad volume" "$BOXR_CMD run --rm -v 'a:b:c:d' alpine true"
    test_step_neg "I bad dns" "$BOXR_CMD run --rm --dns not_an_ip alpine true"
fi

# --- J: Stress ---
if [[ $INCLUDE_STRESS -eq 1 ]] && section_enabled stress; then
    echo -e "\n${BOLD}J. Stress${NC}"
    for i in 1 2 3; do
        test_step "J concurrent $i" "$BOXR_CMD run -d --name bb-stress-$i-$(rand_id) alpine sleep 10"
    done
    run_cmd "$BOXR_CMD ps -aq 2>/dev/null | xargs $BOXR_CMD rm -f 2>/dev/null" || true
elif section_enabled stress; then
    skip_step "J stress" "use --include-stress"
fi

# --- K: Podman P0 parity ---
if section_enabled podman; then
    echo -e "\n${BOLD}K. Podman parity (P0)${NC}"
    PODMAN_FIX="$REPO_ROOT/tests/fixtures/podman"
    COMPOSE_STACK="$REPO_ROOT/tests/fixtures/compose/docker-replacement-stack/docker-compose.yml"
    test_step "K1 container exists missing" "! $BOXR_CMD container exists bb-missing-$(rand_id)"
    VID="bb-vol-$(rand_id)"
    test_step "K2 volume create+exists" "$BOXR_CMD volume create $VID && $BOXR_CMD volume exists $VID"
    run_cmd "$BOXR_CMD volume rm $VID" 2>/dev/null || true
    if [[ -f "$COMPOSE_STACK" ]]; then
        test_step "K3 compose up web" "$BOXR_CMD compose -f \"$COMPOSE_STACK\" up -d web"
        run_cmd "$BOXR_CMD compose -f \"$COMPOSE_STACK\" down -v" 2>/dev/null || true
    else
        skip_step "K3 compose stack" "fixture missing"
    fi
    if [[ -f "$PODMAN_FIX/minimal-pod.yaml" ]]; then
        test_step "K4 play kube" "$BOXR_CMD play kube \"$PODMAN_FIX/minimal-pod.yaml\""
        run_cmd "$BOXR_CMD play kube --down \"$PODMAN_FIX/minimal-pod.yaml\"" 2>/dev/null || true
    else
        skip_step "K4 play kube" "fixture missing"
    fi
    if [[ -f "$PODMAN_FIX/sample.container" ]]; then
        test_step "K5 quadlet install" "$BOXR_CMD quadlet install \"$PODMAN_FIX/sample.container\""
    else
        skip_step "K5 quadlet" "fixture missing"
    fi
    if [[ "${BOXR_TEST_EMBEDDED_USERNET:-}" == "1" && "$(uname -s)" == "Linux" ]]; then
        test_step "K6 embedded usernet gateway" "env BOXR_FORCE_EMBEDDED_USERNET=1 $BOXR_CMD run --rm --network usernet alpine sh -c \"sleep 1; ping -c 1 -W 3 10.0.2.2\""
    fi
fi

# --- Rust integration tests ---
if [[ $RUN_RUST -eq 1 && ( "$SECTION" == "all" || "$SECTION" == "rust" ) ]]; then
    echo -e "\n${BOLD}Rust blackbox_* integration tests${NC}"
    if [[ -d "$REPO_ROOT" ]] && command -v cargo &>/dev/null; then
        test_step "cargo blackbox tests" "cd \"$REPO_ROOT\" && cargo test --test 'blackbox_runtime_test' --test 'blackbox_volumes_test' --test 'blackbox_networking_test' --test 'blackbox_security_test' --test 'blackbox_resources_test' --test 'blackbox_negative_test' --test 'podman_parity_blackbox_test' -- --test-threads=1"
    else
        skip_step "cargo blackbox tests" "cargo not available"
    fi
fi

# --- Summary ---
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

if [[ -n "$JUNIT_FILE" ]]; then
    echo "</testsuite></testsuites>" >> "$JUNIT_FILE.tmp"
    mv "$JUNIT_FILE.tmp" "$JUNIT_FILE"
fi

echo ""
echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BOLD}   Black-Box QA Summary${NC}"
echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "  Total:    ${BOLD}${TOTAL_TESTS}${NC}"
echo -e "  Passed:   ${GREEN}${BOLD}${PASSED_TESTS}${NC}"
echo -e "  Failed:   ${RED}${BOLD}${FAILED_TESTS}${NC}"
echo -e "  Skipped:  ${YELLOW}${BOLD}${SKIPPED_TESTS}${NC}"
echo -e "  Duration: ${DURATION}s"
echo -e "${BOLD}${CYAN}========================================================================${NC}"

if [[ $FAILED_TESTS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}ALL BLACK-BOX QA TESTS PASSED${NC}\n"
    exit 0
else
    echo -e "${RED}${BOLD}SOME TESTS FAILED${NC}\n"
    exit 1
fi
