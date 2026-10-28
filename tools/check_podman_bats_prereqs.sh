#!/usr/bin/env bash
# Probe Linux host capabilities that gate Podman BATS 075-exec and 160-volumes on boxr.
# Exit 0 always; prints human-readable status (for docs/CI triage).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== Podman BATS environment probes (boxr rootless) ==="

echo -n "host setgroups([]): "
if python3 - <<'PY' 2>/dev/null
import ctypes
libc = ctypes.CDLL("libc.so.6", use_errno=True)
rc = libc.setgroups(0, None)
raise SystemExit(0 if rc == 0 else 1)
PY
then
  echo "ok (075-exec prerequisite met)"
else
  echo "FAILED (EPERM — 075-exec likely red; see docs/PODMAN_BATS_CONFORMANCE.md)"
fi

if [[ -x "$REPO_ROOT/target/debug/boxr" || -x "$REPO_ROOT/target/release/boxr" ]]; then
  BOXR="${BOXR:-$REPO_ROOT/target/debug/boxr}"
  [[ -x "$BOXR" ]] || BOXR="$REPO_ROOT/target/release/boxr"
  echo -n "boxr unshare id -G: "
  out="$("$BOXR" unshare id -G 2>/dev/null || true)"
  echo "${out:-failed}"
fi

echo -n "kernel: "
uname -r

if gcc -o /tmp/boxr-idmap-probe "$REPO_ROOT/tools/check_podman_bats_prereqs.sh.probe.c" 2>/dev/null; then
  /tmp/boxr-idmap-probe || true
else
  echo "idmap probe: skip (could not compile check_podman_bats_prereqs.sh.probe.c)"
fi
