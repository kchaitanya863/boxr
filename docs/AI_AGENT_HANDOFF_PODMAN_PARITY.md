# AI agent handoff: Podman parity (logging / BATS)

Living notes for cloud and local agents continuing **Podman-compatible** work on `boxr`. Authoritative matrix: [PODMAN_PARITY.md](PODMAN_PARITY.md). BATS harness: [PODMAN_BATS_CONFORMANCE.md](PODMAN_BATS_CONFORMANCE.md).

## Objective (this handoff slice)

Bring **`035-logs.bats`** (k8s-file / CRI logging) to green under `PODMAN=boxr`, and keep `boxr logs` behavior aligned with Podman for tail, since/until, follow, partial lines, and restart scenarios.

## Status: **Curated BATS manifest 100% green under STRICT=1** (Oct 30, 2026 PT)

| Check | Result |
|-------|--------|
| `001-basic.bats` | **15/15 ok** |
| `005-info.bats` | **17/17 ok** |
| `015-help.bats` | **1/1 ok** |
| `020-tag.bats` | **2/2 ok** |
| `030-run.bats` | **81/81 ok** |
| `035-logs.bats` | **19/19 ok** (journald cases skipped on rootless without journald) |
| `040-ps.bats` | **8/8 ok** |
| `045-start.bats` | **8/8 ok** |
| `050-stop.bats` | **9/9 ok** |
| `055-rm.bats` | **10/10 ok** |
| `075-exec.bats` | **10/10 ok** |
| `run_podman_bats_offline_gate.sh` | **OK** |
| Full curated suite (`STRICT=1`) | **180 ok, 0 failed** (exit code 0) |

Authoritative run log: `.cache/podman-bats-results/run-20261030-025555.log`.

### What was implemented (logging)

- **Multiline CRI records**: `stdout P` / `stdout F` partial-line merge (Podman k8s-file shape).
- **`--tail`**: applied after reconstruct (including partial merges).
- **`--since` / `--until`**: RFC3339, relative durations (`-1s`), unix timestamps; `until` duration strings used for **follow timeout**, not timestamp cutoff (Podman `PODMAN_TIMEOUT` / `--until 3s` follow).
- **`--follow`**: incremental read of `-ctr.log`; honors `PODMAN_TIMEOUT` (exit **124** + stderr message like Podman).
- **Timestamps**: `--timestamps` uses entry times from k8s records, not wall clock at print.
- **Noise**: drops synthetic `Terminated` payloads from displayed logs.

## Black-box E2E status: **green** (Oct 29, 2026 PT)

All Podman-oriented **boxr black-box** gates pass on Linux rootless CI/VM:

| Gate | Count |
|------|-------|
| `podman_parity_audit.py` P0 | 14/14 |
| `podman_parity_blackbox_test` | 16/16 |
| `podman_upstream_parity_test` | 18/18 |
| `run_blackbox_qa.sh -s podman` | 19/19 (K1–K19) |

One command:

```bash
cargo build
./scripts/run_podman_blackbox_e2e.sh ./target/debug/boxr
```

Artifacts from last agent run: `/opt/cursor/artifacts/podman-blackbox-cargo.log`, `blackbox-qa-podman.log`, `podman-parity-audit-run.log`.

Upstream Podman **BATS/Ginkgo** suites are conformance trackers, not this black-box gate (see below).

## How to verify (agents)

```bash
cargo build
cargo test --lib logging::tests
./scripts/run_podman_blackbox_e2e.sh ./target/debug/boxr

# Single BATS file (preferred):
PODMAN_BATS_PATTERN=035-logs ./scripts/run_podman_bats_conformance.sh

# Full curated manifest (long; see scorecard in PODMAN_BATS_CONFORMANCE.md):
./scripts/run_podman_bats_conformance.sh
```

Strict gate (fail CI-style on any curated red):

```bash
PODMAN_BATS_STRICT=1 ./scripts/run_podman_bats_conformance.sh
```

On hosts without idmapped bind mounts, omit host-gated volume case:

```bash
PODMAN_BATS_OMIT_HOST_GATED=1 PODMAN_BATS_STRICT=1 ./scripts/run_podman_bats_conformance.sh
```

Host probes before blaming boxr for **075-exec** / **160-volumes** reds:

```bash
./tools/check_podman_bats_prereqs.sh
```

## Curated manifest snapshot (same VM, Oct 28–29, 2026)

After logging work, full `tests/podman_bats/manifest.txt` run: **171 ok**, **3 not ok** (log: `run-20261029-045820.log`):

| Failure | Cause | Action |
|---------|--------|--------|
| `030` /etc/hosts + `--uidmap` | `newuidmap` / subuid mapping EPERM on VM | Host subuid/subgid + `newuidmap`; not a logs regression |
| `030` `--cert-dir` | BATS registry helper needs **`htpasswd`** (missing on minimal images) | `apt install apache2-utils` or skip in doc-only agents |
| `160` `--userns=keep-id` bind stat | **`mount_setattr(MOUNT_ATTR_IDMAP)`** EPERM on Cloud Agent | Documented gap; use `PODMAN_BATS_OMIT_HOST_GATED=1` for strict gates |

**035-logs** is not in the failure list.

## Next work (priority order)

1. **160-volumes keep-id** on hosts that support idmapped binds — kernel + policy, not logging (see PODMAN_BATS_CONFORMANCE § keep-id gap).
2. **030-run cert-dir** — ensure CI/dev images install `apache2-utils` (`htpasswd`) for registry BATS.
3. **Help / `podman info` JSON** — largest remaining BATS/e2e red surface (see PODMAN_BATS_CONFORMANCE “boxr fixes” table).
4. Expand `tests/podman_bats/manifest.txt` only with matching boxr fixes + doc row updates in [PODMAN_PARITY.md](PODMAN_PARITY.md).

## Invariants (do not break)

- Pre-Tokio trampoline for `unshare` ([AGENTS.md](../AGENTS.md)).
- Rootless-only; no sudo/setuid assumptions.
- Regression string contracts in `tests/issues_47_to_111_test.rs` when touching `src/lib.rs` / daemon exports.

## Related files

| Path | Role |
|------|------|
| `src/logging/mod.rs` | k8s-file decode, filters, follow |
| `src/lib.rs` | `logs` subcommand → `stream_k8s_container_logs` |
| `src/runtime/linux.rs` | log driver policy, conmon tee paths |
| `tests/podman_bats/manifest.txt` | Curated BATS patterns |
| `scripts/run_podman_bats_conformance.sh` | Wrapper + `PODMAN_BATS_PATTERN` |

When this handoff slice is done, update the **Status** section and link the latest `run-*.log` path under `.cache/podman-bats-results/`.
