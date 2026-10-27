#!/usr/bin/env python3
"""
Verify boxr exposes Podman P0 CLI surfaces (help succeeds for required command paths).
CI: exit 1 if any P0 command is missing from boxr --help tree.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

# Podman replacement P0 commands (argv after binary name).
P0_COMMANDS: list[list[str]] = [
    ["container", "exists", "--help"],
    ["image", "exists", "--help"],
    ["volume", "exists", "--help"],
    ["network", "exists", "--help"],
    ["pod", "exists", "--help"],
    ["secret", "exists", "--help"],
    ["compose", "up", "--help"],
    ["play", "kube", "--help"],
    ["generate", "spec", "--help"],
    ["network", "reload", "--help"],
    ["quadlet", "ls", "--help"],
    ["container", "checkpoint", "--help"],
    ["artifact", "ls", "--help"],
    ["auto-update", "--help"],
]


def run_help(boxr: Path, args: list[str]) -> tuple[bool, str]:
    cmd = [str(boxr)] + args
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "").strip()
    return True, ""


def audit(boxr: Path) -> dict:
    results: list[dict] = []
    failed = 0
    for parts in P0_COMMANDS:
        ok, err = run_help(boxr, parts)
        entry = {"command": parts, "ok": ok, "error": err}
        results.append(entry)
        if not ok:
            failed += 1
    return {
        "boxr": str(boxr),
        "p0_total": len(P0_COMMANDS),
        "p0_failed": failed,
        "commands": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Podman P0 CLI audit for boxr")
    parser.add_argument(
        "--boxr",
        type=Path,
        default=Path("target/debug/boxr"),
        help="Path to boxr binary",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON report")
    args = parser.parse_args()

    boxr = args.boxr.resolve()
    if not boxr.is_file():
        print(f"boxr binary not found: {boxr}", file=sys.stderr)
        return 2

    report = audit(boxr)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for row in report["commands"]:
            status = "OK" if row["ok"] else "FAIL"
            print(f"[{status}] boxr {' '.join(row['command'])}")
            if row["error"]:
                print(f"       {row['error']}")
        print(
            f"\nP0: {report['p0_total'] - report['p0_failed']}/{report['p0_total']} passed"
        )

    return 1 if report["p0_failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
