# Podman parity matrix

Track **Podman-compatible** CLI and behavior for `boxr`. Status meanings:

| Status | Meaning |
|--------|---------|
| **full** | CLI, behavior, tests, and platform notes align with Podman for this scope |
| **partial** | Usable replacement with documented gaps |
| **stub** | CLI routes; behavior incomplete or placeholder |
| **n/a** | Not applicable on this platform (see Notes) |

**P0** rows must stay at least **partial** on Linux and macOS (or **n/a** with explicit errors).

Automated checks (single gate):

```bash
./scripts/run_podman_blackbox_e2e.sh ./target/debug/boxr
```

Expands to: P0 CLI audit, `podman_parity_blackbox_test`, `podman_upstream_parity_test`, and black-box QA section `podman` (K1–K19). Upstream Podman BATS/Ginkgo conformance is separate: [PODMAN_BATS_CONFORMANCE.md](PODMAN_BATS_CONFORMANCE.md).

## Matrix

| Domain | CLI | Behavior | Linux | macOS | Tests | Notes |
|--------|-----|----------|-------|-------|-------|-------|
| **run / create / lifecycle** | partial | partial | partial | partial | `docker_parity_test`, blackbox runtime, `test_matrix_embedded_usernet_resolv` (K6) | Rootless default; `auto`/`usernet` use passt when installed, else embedded TAP (`BOXR_FORCE_EMBEDDED_USERNET`) |
| **compose** | partial | partial | partial | partial | `compose_docker_replacement_test`, B9 | `.env`, `${VAR:-default}`, `up SERVICE` |
| **container exists** | full | partial | partial | partial | `podman_parity_blackbox_test` | Exit 0/1 like Podman |
| **image exists** | full | partial | partial | partial | `podman_parity_blackbox_test` | |
| **volume exists** | full | partial | partial | partial | `podman_parity_blackbox_test` | |
| **network exists** | full | partial | partial | partial | `podman_parity_blackbox_test` | |
| **network reload** | full | partial | partial | partial | `podman_parity_blackbox_test`, blackbox K13, `network/mod` | Refreshes bridge `/etc/hosts` + port wait |
| **pod lifecycle** | partial | partial | partial | partial | `podman_upstream_parity_test`, `podman_parity_blackbox_test`, K12 | pause/unpause, stop/start/restart, stats, top, logs, prune, clone |
| **play kube** | partial | partial | partial | partial | `fixtures/podman/minimal-pod.yaml` | Pod + multi-doc YAML |
| **generate spec** | partial | partial | partial | partial | `podman_parity_blackbox_test` | SpecGenerator JSON subset |
| **quadlet** | partial | partial | partial | partial | `podman_parity_blackbox_test` | install + print round-trip |
| **checkpoint / restore** | partial | partial | partial | partial | `podman_parity_blackbox_test` | Metadata tarball subset (not CRIU) |
| **volume export/import** | partial | partial | partial | partial | `podman_parity_blackbox_test` | Tarball round-trip |
| **container export / import** | full | full | full | full | `podman_upstream_parity_test`, `import_test.go`, `125-import.bats` | Tarball export with symlinks, `--change`, `--message`, `--signature-policy`, platform overrides |
| **container diff** | full | full | full | full | `140-diff.bats`, `issues_47_to_111_test` | Diffing against base image and external buildah containers |
| **image history** | full | full | full | full | `110-history.bats`, `issues_47_to_111_test` | `--human`, `--format json`, relative/ISO creation timestamps |
| **image save / load / scp** | full | full | full | full | `120-load.bats`, `auth/archive.rs` | Multi-image Docker/OCI archives, HTTP download, scp transfer, identity preservation |
| **container kill / signals** | full | full | full | full | `130-kill.bats`, `issues_113_to_162_test` | Signal dispatch, `-a`/`--all`, hyphen flags, setsid isolation, process group handling |
| **container pause / unpause** | full | full | full | full | `080-pause.bats`, `issues_47_to_111_test` | Freeze/thaw cgroups, healthcheck timer integration |
| **container top** | full | full | full | full | `085-top.bats`, `issues_47_to_111_test` | Trailing var args, proc namespace scanning |
| **container mounts** | full | full | full | full | `060-mount.bats` | Volume/glob/ramfs/tmpfs mounts, containers.conf overrides, noswap check |
| **artifact** | partial | partial | partial | partial | `podman_parity_blackbox_test` | add / ls / rm |
| **machine** | partial | stub | **n/a** | partial | `podman_parity_blackbox_test` | Linux: clear error; macOS: VZ state |
| **farm** | partial | partial | partial | partial | `podman_parity_blackbox_test`, `podman_parity_test` | Local farm metadata create/ls/rm |
| **auto-update** | partial | partial | partial | partial | `podman_parity_blackbox_test`, `issues_343_to_391_test` | `--dry-run` smoke |
| **system connection** | partial | partial | partial | partial | `podman_parity_blackbox_test`, `issues_343_to_391_test` | `connection ls` subset |

## Out of scope (Docker-only)

Swarm, `plugin`, `config`, `node`, and top-level `trust` stubs are **Docker compatibility**, not Podman parity.

## Full Podman Parity Roadmap (5 Major Gaps)

To reach 100% full parity across all fronts as a complete Podman replacement, the remaining gaps are prioritized in 5 sequential milestones:

1. **Upstream BATS & Ginkgo Conformance Coverage (In Progress)**:
   - Expand curated `manifest.txt` from 13 suites towards the full 77-suite catalog in `manifest-all.txt`.
   - Onboarded & 100% green: `125-import.bats` (import/export), `085-top.bats` (top descriptors), `140-diff.bats` (diffing), `080-pause.bats` (pause/unpause), `130-kill.bats` (signal handling), `110-history.bats` (image history), `120-load.bats` (save/load/scp), `060-mount.bats` (volume/glob/ramfs/tmpfs mounts).
   - In progress: `200-pod.bats` (pod lifecycle), systemd integration suites (`250-systemd`, `251-system-service`, `260-sdnotify`, `270-socket-activation`).
2. **CRIU Live Checkpoint & Restore**:
   - Kernel process memory dumping and restoration with CRIU (`boxr container checkpoint`, `boxr container restore`, `--tcp-established`, `--leave-running`). Boxr currently provides metadata tarball checkpointing.
3. **Podman REST API v2 (`/v2.0/libpod/...`)**:
   - Native Libpod REST v2 endpoint compatibility on `~/.boxr/boxr.sock` alongside existing Docker Engine v1.45 REST socket.
4. **`podman-remote` Client SSH Tunneling**:
   - Tunneling CLI commands to remote engines over SSH (`--remote`, `system connection add/default/rm`, `system service`).
5. **Hardware Devices & Advanced Networking**:
   - Container Device Interface (CDI) specification and GPU passthrough (NVIDIA/AMD), alongside netavark/aardvark network plugins.

## Maintenance

1. Update this matrix when changing Podman-facing commands.
2. Add a black-box or contract test before marking a row **full**.
3. Release readiness: all **P0** rows ≥ **partial**; no **stub** without Notes.

See also [ARCHITECTURE.md](ARCHITECTURE.md) §5.4, [BLACKBOX_QA.md](BLACKBOX_QA.md), and [PODMAN_PARITY_GOVERNANCE.md](PODMAN_PARITY_GOVERNANCE.md).
