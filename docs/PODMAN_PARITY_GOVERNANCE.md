# Podman parity governance

## GitHub tracking

- Label: `podman-parity`
- Epic title: **Full Podman parity program**
- Link matrix: [PODMAN_PARITY.md](PODMAN_PARITY.md)

Suggested child issues (one per matrix domain):

1. Core runtime + networking (`run`, pasta/usernet, `network reload`)
2. Compose replacement (`compose up SERVICE`, `.env`, interpolation)
3. Pods + kube + specgen + quadlet
4. Checkpoint (documented subset) + volume ops + artifacts
5. Machine (macOS) + Linux `n/a` errors
6. Farm / auto-update / system connection (stubs → partial)

Close a child issue when the matrix row reaches **partial** or **full** with tests listed in the Notes column.

## Release gate

Before tagging a release:

1. `./scripts/run_podman_blackbox_e2e.sh ./target/release/boxr` (Linux; sets `BOXR_TEST_EMBEDDED_USERNET=1` by default)
2. All P0 matrix rows ≥ **partial** (or **n/a** with documented errors)

The script runs: P0 CLI audit, `podman_parity_blackbox_test`, `podman_upstream_parity_test`, and `run_blackbox_qa.sh -s podman`.
