# AI agent handoff: Podman parity (logging / BATS)

Living notes for cloud and local agents continuing **Podman-compatible** work on `boxr`. Authoritative matrix: [PODMAN_PARITY.md](PODMAN_PARITY.md). BATS harness: [PODMAN_BATS_CONFORMANCE.md](PODMAN_BATS_CONFORMANCE.md).

## Objective (this handoff slice)

Bring **`035-logs.bats`** (k8s-file / CRI logging) to green under `PODMAN=boxr`, and keep `boxr logs` behavior aligned with Podman for tail, since/until, follow, partial lines, and restart scenarios.

## Status: **035-logs complete** (Oct 28, 2026 PT)

| Check | Result |
|-------|--------|
| `035-logs.bats` (11 k8s-file cases + partial-line test) | **19/19 ok** (8 journald cases skipped on rootless without journald) |
| Implementation | `src/logging/mod.rs` — CRI k8s-file parse/reconstruct, filters, follow |
| CLI routing | `logging::stream_k8s_container_logs` from `src/lib.rs` |
| Detached runtime | conmon tees to `{bundle}-ctr.log` (see `src/runtime/linux.rs`) |

Log from verification run: `.cache/podman-bats-results/run-20261029-045731.log`.

### What was implemented (logging)

- **Multiline CRI records**: `stdout P` / `stdout F` partial-line merge (Podman k8s-file shape).
- **`--tail`**: applied after reconstruct (including partial merges).
- **`--since` / `--until`**: RFC3339, relative durations (`-1s`), unix timestamps; `until` duration strings used for **follow timeout**, not timestamp cutoff (Podman `PODMAN_TIMEOUT` / `--until 3s` follow).
- **`--follow`**: incremental read of `-ctr.log`; honors `PODMAN_TIMEOUT` (exit **124** + stderr message like Podman).
- **Timestamps**: `--timestamps` uses entry times from k8s records, not wall clock at print.
- **Noise**: drops synthetic `Terminated` payloads from displayed logs.

## How to verify (agents)

```bash
cargo build
cargo test --lib logging::tests
cargo test --test podman_upstream_parity_test --test podman_parity_blackbox_test -- --test-threads=1

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
