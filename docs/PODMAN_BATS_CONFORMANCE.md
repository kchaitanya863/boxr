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

Summarize a log:

```bash
grep -E '^ok |^not ok ' .cache/podman-bats-results/run-*.log | tail -20
```

Set `PODMAN_BATS_STRICT=1` to make the script exit non-zero when any curated pattern fails (for future gating).

## E2E (Ginkgo)

```bash
chmod +x scripts/run_podman_e2e_conformance.sh
./scripts/run_podman_e2e_conformance.sh
```

Uses `tests/podman_bats/e2e_manifest.txt` and `make localintegration FOCUS_FILE=...` in a shallow Podman clone. First run installs ginkgo via upstream Makefile.

## boxr fixes for upstream tests (ongoing)

| Area | Status |
|------|--------|
| CLI usage exit **125** | Implemented (`try_parse`, `subcommand_required`) |
| `rm` / `pod rm` / `volume rm` bulk flags | `--all`, `-f`, `-a` (see `RmArgs`, `VolumeRmArgs`) |
| `--authfile` | Global + pull/run/build/login/… |
| BATS `skopeo` prefetch | Overridden to `boxr pull` in `boxr-overrides.bash` |
| Help text / `info` JSON / conmon fields | Still Podman-specific — most BATS/e2e cases remain red |
| `020-tag.bats` | **2/2** (tag/untag, untag all, `images --sort`, localhost short names) |
| `015-help.bats` | **1/1** (`inspect -l` + extra arg → exit **125**) |
| `030-run.bats` | **~48+/81**: **conmon-pidfile/cidfile** (shim `bundle/conmon` + `State.ConmonPid`), **keep-id `$HOME`** (incl. bad bind mounts), **`-t=false`**, invalid name **125**, **defaultenv**; still red: journald (needs host journal), preserve-fds, `--rootfs`, buildah/skopeo, … |
| `040-ps.bats` | **7/8** passing in isolation (`MANIFEST` one-liner `040-ps`); see gaps below |
| `045-start.bats` | **8/8** in isolation |
| `050-stop.bats` | **8–9/9** in isolation (`unlock while waiting` can be timing-sensitive) |
| `055-rm.bats` | **6/10** (`--depend` green); buildah external / conmon cases red |
| `075-exec.bats` | **9/10** in isolation (leak check, stdin, keep-id, umask, TTY, exec_pid/`GraphRoot`); red: **additional groups** `id -G` for `root:root` (rootless user-ns unmapped supplementary GIDs `65534`) |
| `160-volumes.bats` | **7/26** in isolation: basic binds (`:z,ro`), duplicate dest (**125** incl. `--tmpfs`), `volume ls --filter name=` regex, `ps --filter volume=`, `--ignore`, `ls --format` Labels; export/prune/mount/copyup still red |
| `ps --format` Labels / PodName | `{{.Labels}}`, `{{json .Labels}}`, `{{ .Label "k" }}`, `{{ .PodName }}` |
| Pod infra + BATS leak check | Infra uses `alpine:3.20`; `leak_check` whitelists `alpine:*` (not auto-rmi’d on `pod rm`) |

### Known gaps (`040-ps`)

- **`podman ps --external`**: Requires **buildah** and Podman storage “external” containers; not installed in typical CI/agent images. `ps --external` with no externals prints the table header only (Podman-shaped).
- Full **manifest.txt** run still has many reds (`030-run`, `020-tag`, volumes, etc.); use per-file manifests to track focused progress.

**100% pass** of upstream suites is not realistic until `info`, logging, networking, and storage output match Podman; the harness measures progress.

## Related

- Rust smokes: `tests/podman_upstream_parity_test.rs`
- Mapping: [PODMAN_TEST_MAPPING.md](PODMAN_TEST_MAPPING.md)
