#!/usr/bin/env bash
# Minimal buildah stub for Podman BATS external-container name collision tests.
set -euo pipefail

home="${BOXR_HOME:-${BOXR_BATS_HOME:-$HOME/.boxr}}"
names_file="$home/external-container-names"

if [[ "${1:-}" == "from" && "${2:-}" == "--name" && -n "${3:-}" ]]; then
  mkdir -p "$home"
  name="${3}"
  if [[ ! -f "$names_file" ]] || ! grep -qxF "$name" "$names_file"; then
    echo "$name" >>"$names_file"
  fi
  echo "external-${name}"
  exit 0
fi

echo "Error: buildah stub does not implement: $*" >&2
exit 127
