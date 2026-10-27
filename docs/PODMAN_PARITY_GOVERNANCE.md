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

1. `python3 tools/podman_parity_audit.py --boxr ./target/release/boxr`
2. `cargo test --test podman_parity_blackbox_test -- --test-threads=1`
3. All P0 matrix rows ≥ **partial** (or **n/a** with documented errors)
