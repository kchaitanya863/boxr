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
| **pod lifecycle** | full | full | full | partial | `200-pod.bats`, `pod_create_test.go`, `pod_rm_test.go`, `pod_pause_test.go`, `pod_top_test.go` | pause/unpause, stop/start/restart, stats, top, logs, prune, clone |
| **play kube** | full | full | full | partial | `700-play.bats`, `710-kube.bats`, `generate_kube_test.go` | Pod + multi-doc YAML, kube generate/play/down/apply |
| **generate spec** | full | full | full | full | `generate_spec_test.go`, `podman_parity_blackbox_test` | SpecGenerator JSON for containers and pods (`--compact`, `--filename`, `--name`) |
| **quadlet** | full | full | full | partial | `252-quadlet.bats`, `253-podman-quadlet.bats`, `254-podman-quadlet-multi.bats` | install, ls, print, rm, multi-unit & systemd integration |
| **checkpoint / restore** | full | partial | full | partial | `520-checkpoint.bats`, `podman_parity_blackbox_test` | Checkpoint/restore archive & lifecycle parity |
| **volume export/import** | full | full | full | full | `160-volumes.bats`, `volume_create_test.go`, `volume_ls_test.go`, `volume_rm_test.go`, `volume_prune_test.go` | Tarball round-trip, create/ls/rm/prune filters |
| **container export / import** | full | full | full | full | `export_test.go`, `import_test.go`, `125-import.bats` | Tarball export with symlinks, `--change`, `--message`, `--signature-policy`, platform overrides |
| **container diff** | full | full | full | full | `140-diff.bats`, `diff_test.go` | Diffing against base image, parent layers, and external buildah containers |
| **image history** | full | full | full | full | `110-history.bats`, `history_test.go` | `--human`, `--format json`, relative/ISO creation timestamps |
| **image save / load / scp** | full | full | full | full | `120-load.bats`, `auth/archive.rs` | Multi-image Docker/OCI archives, HTTP download, scp transfer, identity preservation |
| **container kill / signals** | full | full | full | full | `130-kill.bats`, `032-sig-proxy.bats` | Signal dispatch, `-a`/`--all`, hyphen flags, setsid isolation, process group handling |
| **container pause / unpause** | full | full | full | full | `080-pause.bats`, `pause_test.go`, `pod_pause_test.go` | Freeze/thaw cgroups, `--all`/`--latest`/`--cidfile`/`--filter`, healthcheck timer integration |
| **container top** | full | full | full | full | `085-top.bats`, `top_test.go`, `pod_top_test.go` | Trailing var args, proc namespace scanning, `uid`/`huid`/`groups`/`capeff`/`aux`/`hn` |
| **container mounts** | full | full | full | full | `060-mount.bats` | Volume/glob/ramfs/tmpfs mounts, containers.conf overrides, noswap check |
| **artifact** | full | full | full | full | `702-artifact.bats`, `podman_parity_blackbox_test` | add / ls / inspect / extract / rm |
| **machine** | partial | stub | **n/a** | partial | `podman_parity_blackbox_test` | Linux: clear error; macOS: VZ state |
| **farm** | full | full | full | full | `farm_test.go`, `podman_parity_test` | Farm create/ls/update/rm with `PODMAN_CONNECTIONS_CONF` |
| **auto-update** | full | full | full | partial | `255-auto-update.bats` | Registry/image/local policies, rollback, `--dry-run`, `--format` |
| **system connection** | full | full | full | full | `272-system-connection.bats`, `system_connection_test.go` | `connection add/ls/rm/default/rename` with TLS/mTLS & farm integration |
| **image trust** | full | full | full | full | `750-trust.bats`, `trust_test.go` | `image trust show/set` with GPG UID extraction and `registries.d` sigstore lookup |
| **secrets** | full | full | full | full | `secret_test.go` | `secret create/inspect/ls/rm/exists` with env/file drivers and container mounts |

## Out of scope (Docker-only)

Swarm, `plugin`, `config`, `node`, and top-level `trust` stubs are **Docker compatibility**, not Podman parity.

## Full Podman Parity Roadmap (5 Major Gaps)

To reach 100% full parity across all fronts as a complete Podman replacement, the remaining gaps are prioritized in 5 sequential milestones:

1. **Upstream BATS & Ginkgo Conformance Coverage (Complete — 77/77 BATS & 31 Ginkgo E2E suites green)**:
   - Curated `manifest.txt` now contains all **77/77** upstream Podman BATS suites (`manifest-all.txt`) passing 100% (`0 not ok`).
   - Curated `e2e_manifest.txt` now contains **31** upstream Podman Ginkgo E2E suites (**401/401** specs passing under `PODMAN_E2E_STRICT=1`).
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
