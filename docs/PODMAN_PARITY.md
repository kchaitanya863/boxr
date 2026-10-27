# Podman parity matrix

Track **Podman-compatible** CLI and behavior for `boxr`. Status meanings:

| Status | Meaning |
|--------|---------|
| **full** | CLI, behavior, tests, and platform notes align with Podman for this scope |
| **partial** | Usable replacement with documented gaps |
| **stub** | CLI routes; behavior incomplete or placeholder |
| **n/a** | Not applicable on this platform (see Notes) |

**P0** rows must stay at least **partial** on Linux and macOS (or **n/a** with explicit errors).

Automated checks:

- `python3 tools/podman_parity_audit.py --boxr ./target/debug/boxr`
- `cargo test --test podman_parity_blackbox_test -- --test-threads=1`
- `./scripts/run_blackbox_qa.sh -s podman -b ./target/debug/boxr`

## Matrix

| Domain | CLI | Behavior | Linux | macOS | Tests | Notes |
|--------|-----|----------|-------|-------|-------|-------|
| **run / create / lifecycle** | partial | partial | partial | partial | `docker_parity_test`, blackbox runtime | Rootless default; pasta/usernet on Linux |
| **compose** | partial | partial | partial | partial | `compose_docker_replacement_test`, B9 | `.env`, `${VAR:-default}`, `up SERVICE` |
| **container exists** | full | partial | partial | partial | `podman_parity_blackbox_test` | Exit 0/1 like Podman |
| **image exists** | full | partial | partial | partial | `podman_parity_blackbox_test` | |
| **volume exists** | full | partial | partial | partial | `podman_parity_blackbox_test` | |
| **network exists** | full | partial | partial | partial | `podman_parity_blackbox_test` | |
| **network reload** | full | partial | partial | partial | `podman_parity_blackbox_test`, `network/mod` | Refreshes bridge `/etc/hosts` + port wait |
| **pod lifecycle** | partial | partial | partial | partial | `podman_parity_blackbox_test` | create → start → ps → rm |
| **play kube** | partial | partial | partial | partial | `fixtures/podman/minimal-pod.yaml` | Pod + multi-doc YAML |
| **generate spec** | partial | partial | partial | partial | `podman_parity_blackbox_test` | SpecGenerator JSON subset |
| **quadlet** | partial | partial | partial | partial | `podman_parity_blackbox_test` | install + print round-trip |
| **checkpoint / restore** | partial | partial | partial | partial | `podman_parity_blackbox_test` | Metadata tarball subset (not CRIU) |
| **volume export/import** | partial | partial | partial | partial | `podman_parity_blackbox_test` | Tarball round-trip |
| **artifact** | partial | partial | partial | partial | `podman_parity_blackbox_test` | add / ls / rm |
| **machine** | partial | stub | **n/a** | partial | `podman_parity_blackbox_test` | Linux: clear error; macOS: VZ state |
| **farm** | partial | stub | partial | partial | `podman_parity_test` | Local farm metadata only |
| **auto-update** | partial | stub | partial | partial | `issues_343_to_391_test` | Dry-run smoke |
| **system connection** | partial | stub | partial | partial | `issues_343_to_391_test` | Connection store subset |

## Out of scope (Docker-only)

Swarm, `plugin`, `config`, `node`, and top-level `trust` stubs are **Docker compatibility**, not Podman parity.

## Maintenance

1. Update this matrix when changing Podman-facing commands.
2. Add a black-box or contract test before marking a row **full**.
3. Release readiness: all **P0** rows ≥ **partial**; no **stub** without Notes.

See also [ARCHITECTURE.md](ARCHITECTURE.md) §5.4, [BLACKBOX_QA.md](BLACKBOX_QA.md), and [PODMAN_PARITY_GOVERNANCE.md](PODMAN_PARITY_GOVERNANCE.md).
