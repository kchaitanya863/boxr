# Enterprise Black-Box QA

Repeatable black-box QA for `boxr` — enterprise runtime invariants, compose, volumes, networking, DNS, security, memory limits, and permissions.

## Prerequisites

- Built `boxr` binary: `cargo build --release`
- macOS: `boxr-vz` and VM kernel under `~/.boxr/vm/` (created on first container run)
- Network access for image pulls (`alpine`, `nginx`, `postgres`, etc.)
- `curl` on the host (daemon ping, published port checks)

## Quick start

```bash
cargo build --release
./scripts/run_blackbox_qa.sh -b ./target/release/boxr
```

Rust integration tests only:

```bash
cargo test --test blackbox_runtime_test \
           --test blackbox_volumes_test \
           --test blackbox_networking_test \
           --test blackbox_security_test \
           --test blackbox_resources_test \
           --test blackbox_negative_test \
           -- --test-threads=1 --nocapture
```

Stress tests (ignored by default):

```bash
cargo test --test blackbox_stress_test -- --ignored --test-threads=1
./scripts/run_blackbox_qa.sh -b ./target/release/boxr --include-stress -s stress
```

## Shell harness options

| Flag | Description |
|------|-------------|
| `-b <path>` | Path to `boxr` binary |
| `-s <section>` | One section: `runtime`, `compose`, `volumes`, `network`, `dns`, `security`, `memory`, `permissions`, `negative`, `stress`, `rust`, `all` |
| `-j <file>` | JUnit XML output |
| `--include-stress` | Run stress section |
| `--no-rust` | Skip `cargo test blackbox_*` at end |

Examples:

```bash
./scripts/run_blackbox_qa.sh -b ./target/release/boxr -s volumes
./scripts/run_blackbox_qa.sh -b ./target/release/boxr --no-rust -j /tmp/blackbox.xml
```

## Test layout

| Path | Purpose |
|------|---------|
| [scripts/run_blackbox_qa.sh](../scripts/run_blackbox_qa.sh) | Shell harness (sections A–J) |
| [tests/common/blackbox.rs](../tests/common/blackbox.rs) | Shared helpers (`isolated_home`, `run_boxr`, …) |
| [tests/blackbox_*_test.rs](../tests/) | Rust integration tests by domain |
| [tests/fixtures/compose/](../tests/fixtures/compose/) | Compose YAML fixtures |
| [tests/compose_docker_replacement_test.rs](../tests/compose_docker_replacement_test.rs) | Docker/Podman replacement compose (CLI service args, `.env`, `${VAR:-default}`) |

## Isolated state

Both the shell harness and Rust tests use a temporary `BOXR_HOME` per run. Heavy directories (`images/`, `layers/`, `vm/`, `bin/`) are symlinked from `~/.boxr` so cached images are reused without polluting the default store.

## Interpreting results

| Result | Meaning |
|--------|---------|
| **PASS** | Expected behavior confirmed |
| **FAIL** | Bug or regression — record repro command from output |
| **SKIP** | Platform N/A (e.g. `pasta`/`usernet` on macOS) |

## Adding a new case

1. Add a `test_step` or `test_step_neg` in `scripts/run_blackbox_qa.sh` under the right section.
2. Mirror with a `#[test]` in the matching `tests/blackbox_*_test.rs` using `isolated_home()` and `run_boxr_ok` / `run_boxr_fail`.
3. Use `bb-<suffix>` naming via `rand_id()` / `rand_suffix()` for containers, volumes, and networks.

## Matrix reference

| Section | IDs | Focus |
|---------|-----|-------|
| A | runtime | /tmp 1777, shm, devices, apt, postgres, nginx, read-only, init, daemon |
| B | compose | fullstack-compose, minimal-dns, docker-replacement-stack, cycles |
| C | volumes | CRUD, bind ro/rw, chown/chmod, cp |
| D/E | network, dns | publish, none, custom DNS, bridge names |
| F | security | user, read-only, privileged, env isolation |
| G | memory | limits, cpus, pids, parse errors |
| I | negative | bad image, port, volume, dns |
| J | stress | concurrent runs, rapid restart |

See also [ENTERPRISE_RUNTIMES.md](ENTERPRISE_RUNTIMES.md) and [NETWORKING.md](NETWORKING.md).
