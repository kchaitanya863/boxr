# Podman upstream test mapping

This document maps [Podman](https://github.com/podman-container-tools/podman) test suites to **boxr** tests. We do not run Podman’s Go/BATS harness against `boxr`; we port **behavioral smokes** that fit rootless boxr scope.

## Upstream suites (reference)

| Podman path | Harness | Role |
|-------------|---------|------|
| `test/e2e/*_test.go` | Ginkgo (`make localintegration`) | CLI integration (~145 files) |
| `test/system/*.bats` | BATS (`make localsystem`) | Destructive host integration (~77 files) |
| `test/apiv2/*.at` | API acceptance | REST v2 |
| `pkg/machine/e2e/` | Ginkgo | `podman machine` |
| `test/compose/` | Shell fixtures | Compose edge cases |

## In scope for boxr

- Podman P0/P1 CLI parity in [PODMAN_PARITY.md](PODMAN_PARITY.md)
- **Linux-first** for runtime-heavy smokes (`unshare`, `container clone --run`, networking); macOS VZ follows once Linux gates are solid
- Rootless Linux + macOS VZ paths
- Subset checkpoint (metadata, not CRIU), quadlet, kube play/generate, farm, auto-update dry-run

## Explicit non-goals (no boxr port)

| Upstream theme | Why skipped |
|----------------|-------------|
| `libpod_suite_remote_test.go`, BATS `--remote` | No `podman-remote` client |
| `test/apiv2/` | No Podman-compatible REST API surface |
| `checkpoint_*` (CRIU), BATS `520-checkpoint` | Metadata-only checkpoint in boxr |
| `run_selinux`, `run_apparmor`, BATS `410-selinux` | Host LSM not modeled |
| `image_sign`, `trust`, BATS `750-trust` | Signing/trust out of matrix |
| `run_aardvark`, netavark-specific | pasta/usernet/embedded stack instead |
| `systemd_activate`, socket activation BATS | Host systemd integration |
| Full `pkg/machine/e2e` | macOS partial + Linux `n/a` only |
| `cdi/`, GPU device plugins | Not in parity matrix |

## File-level mapping (implemented)

| Podman e2e / system | boxr test |
|---------------------|-----------|
| `exists_test.go` | `podman_parity_blackbox_test` + `podman_upstream_parity_test` (`*_exists_*`) |
| `secret_test.go` | `podman_upstream_parity_test::test_secret_lifecycle` |
| `pod_pause_test.go`, `pause_test.go` | `test_pod_pause_unpause` |
| `pod_stop_test.go`, `pod_start_test.go`, `pod_restart_test.go` | `test_pod_stop_start_restart` |
| `pod_inspect_test.go` | `test_pod_inspect_json` |
| `pod_stats_test.go` | `test_pod_stats_no_stream` |
| `pod_prune_test.go` | `test_pod_prune_removes_stopped_pod` |
| `pod_clone_test.go` | `test_pod_clone_metadata` |
| `pod_top_test.go` | `test_pod_top_lists_processes` |
| `logs_test.go` (pod) | `test_pod_logs_smoke` |
| `generate_kube_test.go`, BATS `710-kube` | `test_generate_kube_from_running_pod` |
| `generate_systemd_test.go`, BATS `252-quadlet` | `test_generate_systemd_stdout` |
| `network_connect_disconnect_test.go` | `test_network_connect_disconnect` (+ reload in blackbox K13) |
| `play_kube_test.go` | `podman_parity_blackbox_test::test_play_kube_minimal_pod` |
| `farm_test.go` | `podman_parity_blackbox_test::test_farm_create_list_remove` |
| `quadlet_test.go` | `podman_parity_blackbox_test::test_quadlet_install_and_print` |
| `volume_*`, `artifact_*`, `checkpoint_test.go` | `podman_parity_blackbox_test` K9–K11 |
| `volume_rename_test.go`, BATS `160-volumes` | `test_volume_rename_updates_store` |
| `container_clone_test.go` | `test_container_clone_created_state`, `test_container_clone_run_starts_target` |
| `unshare_test.go`, BATS `170-run-userns` | `test_unshare_runs_command_in_user_namespace` |
| `run_test.go`, `create_test.go` | `docker_parity_test`, `blackbox_runtime_test` |
| `compose` (850) | `compose_docker_replacement_test`, blackbox K3 |

## Podman BATS conformance (upstream `test/system`)

```bash
./scripts/run_podman_bats_conformance.sh
```

See [PODMAN_BATS_CONFORMANCE.md](PODMAN_BATS_CONFORMANCE.md) and agent notes in [AI_AGENT_HANDOFF_PODMAN_PARITY.md](AI_AGENT_HANDOFF_PODMAN_PARITY.md). Uses `PODMAN=boxr` via a wrapper and `tests/podman_bats/manifest.txt`. Default exit code is **0** unless `PODMAN_BATS_STRICT=1` (failures are expected while parity is partial).

## Verification

```bash
cargo test --test podman_upstream_parity_test -- --test-threads=1
cargo test --test podman_parity_blackbox_test -- --test-threads=1
python3 tools/podman_parity_audit.py --boxr ./target/debug/boxr
./scripts/run_blackbox_qa.sh -b ./target/debug/boxr -s podman
```

## Adding coverage

1. Pick an upstream `test/e2e/<name>_test.go` or BATS file.
2. If the row in `PODMAN_PARITY.md` is in scope, add a **single focused** Rust test under `tests/podman_upstream_parity_test.rs` (or extend blackbox if release-gate K-step).
3. Record the mapping in the table above.
