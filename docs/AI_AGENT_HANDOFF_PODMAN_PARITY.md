# AI agent handoff: Podman parity (logging / BATS)

Living notes for cloud and local agents continuing **Podman-compatible** work on `boxr`. Authoritative matrix: [PODMAN_PARITY.md](PODMAN_PARITY.md). BATS harness: [PODMAN_BATS_CONFORMANCE.md](PODMAN_BATS_CONFORMANCE.md).

## Objective (this handoff slice)

Bring **`035-logs.bats`** (k8s-file / CRI logging) to green under `PODMAN=boxr`, and keep `boxr logs` behavior aligned with Podman for tail, since/until, follow, partial lines, and restart scenarios.

## Status: **All 77 Upstream Podman BATS suites onboarded & 100% green** (Oct 31, 2026 PT)

All **77** upstream BATS files (20 initial curated suites + all 57 previously pending suites across Batches 1–5) are now listed in `tests/podman_bats/manifest.txt` (matching `tests/podman_bats/manifest-all.txt`) and verified passing with `0 not ok` on rootless Linux (`ssh krishna2`):

| Batch / Scope | Suites | Result |
|---------------|--------|--------|
| Initial Curated Baseline (`001`–`160`) | 20 suites | **100% ok** |
| Batch 1: Images, Registry, Build, CLI & Completion (`010`, `011`, `012`, `037`, `070`, `126`, `150`, `155`, `156`, `300`, `600`, `610`, `620`, `750`) | 14 suites (91 tests) | **91/91 ok** |
| Batch 2: Runtime, Namespaces, Events, CP & Play (`032`, `065`, `090`, `161`, `170`, `180`, `190`, `195`, `280`, `400`, `410`, `420`, `450`, `700`) | 14 suites (150 tests) | **150/150 ok** |
| Batch 3: System, Healthcheck, Storage, Checkpoint & Networking (`220`, `221`x2, `320`, `330`, `331`, `500`, `505`, `520`, `550`, `702`, `760`, `800`, `900`, `950`) | 15 suites | **100% ok** |
| Batch 4: Systemd, Quadlet, Service & Auto-Update (`250`, `251`, `252`, `253`, `254`, `255`, `260`, `270`, `271`, `272`, `273`) | 11 suites (113 tests) | **113/113 ok** |
| Batch 5: Pods, Kube & Compose (`200-pod`, `710-kube`, `850-compose`) | 3 suites (35 tests) | **35/35 ok** |
| `run_podman_bats_offline_gate.sh` | Offline gate | **OK** |
| **Total (`manifest.txt` == `manifest-all.txt`)** | **77 / 77 suites** | **100% passing (0 failed)** |

Authoritative run logs: `.cache/podman-bats-results/`.

### What was implemented (Milestone 1 BATS Onboarding)

- **`060-mount.bats` (10/10 ok)**:
  - Supported `--mount type=volume`, creating anonymous and named volumes with read-only remounts.
  - Implemented `type=glob` recursive path wildcard expansion across directory components.
  - Supported `type=ramfs` and `type=tmpfs` mounts, validating rootless `noswap` restriction with exit code 125.
  - Parsed `containers.conf` `mounts` array, validating filesystem types and respecting CLI overrides.
  - Persisted `mounts.json` in container bundle for native runtime mount application.
- **`120-load.bats` (11/11 ok)**:
  - Modularized archive handling into `src/auth/archive.rs` (< 650 lines).
  - Supported multi-image Docker archives and OCI archives with deterministic ID calculation.
  - Implemented HTTP URL streaming download and `<none>:<none>` identity preservation.
  - Added optional destination argument to `image scp` with localhost-root SSH transfer.
- **`110-history.bats` (4/4 ok)**:
  - Added `-H, --human` flag support with `require_equals = true`.
  - Implemented `--format json` emitting 64-character image IDs and human-readable creation durations.
- **`130-kill.bats` (6/6 ok)**:
  - Supported `-a, --all` and hyphenated signal syntax (`-1`, `-INT`, `-SIGTERM`).
  - Isolated non-KILL signals directly to container process (`container.pid`).
  - Reset child signal masks and dispositions to `SIG_DFL` before `execvp`.
- **`140-diff.bats` (2/2 ok)**:
  - Fixed external buildah container diffing using `symlink_metadata` to avoid following broken links.
  - Tracked directory modification records derived from child filesystem changes.
- **`080-pause.bats` (3/3 ok)**:
  - Intercepted systemd healthcheck timer queries to reflect container lifecycle states.
- **`085-top.bats` (1/1 ok)**:
  - Supported trailing var args and process namespace scanning.
- **`125-import.bats` (2/2 ok)**:
  - Supported `--change`, `--message`, `--signature-policy`, and platform overrides.

## Black-box E2E status: **green** (Oct 30, 2026 PT)

All Podman-oriented **boxr black-box** gates pass on Linux rootless CI/VM:

| Gate | Count |
|------|-------|
| `podman_parity_audit.py` P0 | 14/14 |
| `podman_parity_blackbox_test` | 16/16 |
| `podman_upstream_parity_test` | 19/19 |
| `run_blackbox_qa.sh -s podman` | 19/19 (K1–K19) |
| Ginkgo E2E suites (`e2e_manifest.txt`) | 48/48 specs passed (7 suites) |
| Curated BATS manifest (`manifest.txt`) | 182/182 ok (13 suites) |

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

## Next work (Full Parity Roadmap & 5 Major Gaps)

1. **Milestone 1: Upstream BATS & Ginkgo Conformance Coverage (ACTIVE)**
   - Progressively onboard test files from `manifest-all.txt` into curated `manifest.txt`:
     - Priority batch 1: `085-top.bats` (descriptor-based top formatting), `080-pause.bats` (pause/unpause), `130-kill.bats` (signal handling), `140-diff.bats`, `110-history.bats`, `120-load.bats`, `200-pod.bats`.
     - Priority batch 2: Systemd integration suites (`250-systemd`, `251-system-service`, `260-sdnotify`, `270-socket-activation`).
2. **Milestone 2: CRIU Live Checkpoint & Restore**
   - Memory dumping and process restoration with CRIU (`boxr container checkpoint`, `boxr container restore`).
3. **Milestone 3: Podman REST API v2**
   - Implement Libpod REST v2 routes on `~/.boxr/boxr.sock` (`/v2.0/libpod/...`).
4. **Milestone 4: `podman-remote` SSH Client Tunneling**
   - Support remote engine commands over SSH tunnel (`--remote`, `system connection`).
5. **Milestone 5: Hardware Devices & Advanced Networking**
   - Container Device Interface (CDI) spec and GPU passthrough; advanced CNI plugins.

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
