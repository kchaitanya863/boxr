# Podman BATS conformance (boxr as `PODMAN`)

Runs a **curated** subset of upstream [Podman `test/system`](https://github.com/podman-container-tools/podman/tree/main/test/system) BATS files with `PODMAN` pointing at `boxr`. Linux rootless only for now.

## What this is / is not

| | |
|--|--|
| **Is** | A reproducible harness to track progress against Podman’s system tests |
| **Is not** | `make localsystem` with a 100% pass guarantee (Podman helpers assume `podman` CLI flags, storage, and `info` JSON) |

Upstream `clean_setup` uses flags like `rm -t 0 --ignore` and `ps --external`. The harness appends `tests/podman_bats/boxr-overrides.bash` to Podman’s `helpers.bash` to use boxr-compatible teardown and fixes OpenSSL `req -quiet` on OpenSSL 3.x.

## Prerequisites

- Linux, rootless-friendly (`newuidmap` / subuid for `boxr unshare` paths)
- `bats` (bats-core ≥ 1.8)
- `git`, `openssl`, network for image pulls
- Built `boxr`: `cargo build`

## Run

```bash
cargo build
./scripts/run_podman_bats_conformance.sh
```

Environment:

| Variable | Default | Purpose |
|----------|---------|---------|
| `BOXR_BIN` | `target/debug/boxr` | boxr binary |
| `PODMAN_BATS_CACHE` | `.cache/podman-bats` | Shallow podman git clone |
| `MANIFEST` | `tests/podman_bats/manifest.txt` | BATS filename patterns |
| `PODMAN_TESTS_REF` | `main` | Git ref for clone |

Each run uses a fresh `BOXR_HOME` under `/tmp` (via `boxr-podman-wrapper.sh`).

## Curated manifest

Edit `tests/podman_bats/manifest.txt` to add patterns (e.g. `160-volumes`). Match upstream names from `test/system/*.bats`.

## Results

Logs land in `.cache/podman-bats-results/run-*.log`. **Failures are expected** while matrix rows in [PODMAN_PARITY.md](PODMAN_PARITY.md) remain partial; the harness exists to measure improvement over time.

## Related

- Rust smokes: `tests/podman_upstream_parity_test.rs`
- Mapping: [PODMAN_TEST_MAPPING.md](PODMAN_TEST_MAPPING.md)
