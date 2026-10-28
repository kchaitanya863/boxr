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
| `BOXR_BIN` | `target/debug/boxr` | boxr binary (script resolves to an **absolute** path in the wrapper; relative paths break BATS because tests `cd` into the podman clone) |
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

**Agent/CI deps:** `libseccomp-dev`, `libgpgme-dev`, `pkg-config` (Go e2e compile). Global Podman storage flags (`--root`, `--runroot`, `--storage-driver`, …) are stripped in `preprocess_argv` so suite init can invoke the wrapper. **E2e still fails in `SynchronizedBeforeSuite` / `SynchronizedAfterSuite`** (Podman libpod storage, conmon, `/timings-*` artifacts)—**0 specs run** until boxr-specific e2e bootstrap exists; do not treat as boxr CLI regressions. Latest log: `e2e-run.log` in agent artifacts (`SynchronizedBeforeSuite` at `common_test.go:607`, AfterSuite `/timings-1` missing).

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
| `030-run.bats` | **75/75** ok (latest `bats-030-run-5.log`): cgroup sysfs order, **buildah** stub, systemd **`/run`**, **`--uidmap`** /etc/hosts (**46**, suppress `ip link` RTNETLINK noise on stdout); **journald** cases **skip** on VMs without persistent journal (`journald_unavailable` override in `boxr-overrides.bash`) |
| `040-ps.bats` | **8/8** in isolation (`ps --external` + buildah stub + `image prune --external`) |
| `045-start.bats` | **8/8** in isolation |
| `050-stop.bats` | **9/9** in isolation (SIGKILL warning before `--rm` teardown; stop/kill exit **137** race; trap exit **0** vs **143**) |
| `055-rm.bats` | **10/10** in isolation (`container exists --external`, `--health-on-failure=stop`, detached health supervisor subprocess) |
| `075-exec.bats` | **9/10** in isolation (`bats-075-exec-4.log`): combined `-td` flags, `exec --preserve-fd`, binary-safe exec stdout, credential resolution before mount setns; **red: additional groups** — `exec --user root:root` / `nobody:nobody` expect `id -G` to list only explicit primary/supplementary groups (see gap below) |
| `160-volumes.bats` | **24/26** + **2 skips** (`bats-160-volumes-6.log`, isolated `BOXR_HOME`); **red:** `--userns=keep-id` bind `stat` (`0:0:0` vs host `uid:gid`) — Podman keep-id UID maps use a `newuidmap` layout whose first segment maps container `[0,host_uid)` → host `[1,host_uid+1)`; **`newuidmap` rejects that on typical `/etc/subuid` entries starting at 100000** (`uid range [0-N) -> [1-N+1) not allowed`), so boxr falls back to default rootless maps; **idmapped bind mounts** (Podman’s other half of keep-id volumes) still fail here with `mount_setattr` **EPERM/EINVAL** until full keep-id maps exist |
| `030-run.bats` (spot) | **`--default-mounts-file`**, **`--rootfs`** (exit **127**), **`--pod new:`** rollback on duplicate name; many cases still red (journald, buildah, containers.conf); teardown may flag leaked `localhost/boxr-build:*` images from in-suite builds |
| Podman global flags (e2e init) | `preprocess_argv` strips `--root`, `--runroot`, `--storage-driver`, … before clap |
| `--runtime-flag` | Global flag; unknown values exit **126** (BATS `030-run` global runtime option) |
| `ps --format` Labels / PodName | `{{.Labels}}`, `{{json .Labels}}`, `{{ .Label "k" }}`, `{{ .PodName }}` |
| Pod infra + BATS leak check | Infra uses `alpine:3.20`; `leak_check` whitelists `alpine:*`, `localhost/cve_2022_1227_test*` (build test **49** image when `top` fails) |

### External storage (buildah stub)

- **`buildah` stub** (`tests/podman_bats/buildah-stub.sh` on `PATH`): `from`, `commit`, `mount`, `unshare` for BATS; persists `external-containers.json` under `BOXR_HOME`.
- **`podman ps --external`**, **`image prune -f --external`**, and **`rm`** on mounted externals use `src/storage/external.rs` (not full buildah/libpod storage).
- Full **manifest.txt** sequential run can OOM; use per-file BATS for focused progress.

**100% pass** of upstream suites is not realistic until `info`, logging, networking, and storage output match Podman; the harness measures progress.

### Known gap: `075-exec` additional groups (rootless)

Podman test **075-exec** (case 10) requires `podman exec --user root:root … id -G` to print **`0`** only (no inherited supplementary GIDs), and with `--group-add` to list **`0 1 2 … 10`** exactly. That needs `setgroups(2)` after entering the container user namespace.

On typical rootless boxr hosts (`newuidmap` / `newgidmap`, subuid/subgid):

1. The mapping child writes **`deny`** to `/proc/self/setgroups` before `gid_map` (required by the kernel).
2. The parent re-enables **`allow`** on the **mapping child PID** after `newuidmap`/`newgidmap` (`RootlessUserConfig::reenable_setgroups_for_pid`).
3. The PID-1 process that runs the container workload still observes **`/proc/self/setgroups` = `deny`** and **`write("allow")` returns `EPERM`**, so supplementary groups stay populated (often repeated **`65534`** / `nobody` in the user namespace).

Verified locally: `boxr run --rm … cat /proc/self/setgroups` → `deny`; explicit `allow` from the init process fails with **Operation not permitted**. Fixing this likely needs deeper alignment with Podman/runc’s user-namespace lifecycle (which process may call `setgroups`, and when), not a one-line CLI tweak. **9/10** on `075-exec.bats` is the current ceiling until that is resolved.

### Known gap: `160-volumes` keep-id bind `stat` (rootless)

Podman test **160-volumes** (case 12) expects `stat` on a host-owned bind-mount file under `--userns=keep-id` to print the **host** `uid:gid`. That requires both:

1. **Keep-id user namespace maps** (see `getRootlessKeepIDMapping` in upstream Podman), and/or  
2. **ID-mapped bind mounts** when maps alone are insufficient.

On this rootless host, `newuidmap` rejects Podman’s first keep-id segment because delegated `/etc/subuid` ranges do not cover host IDs `1..host_uid`. boxr then applies the usual `0 → host_uid` + subuid range maps, so `stat` shows `0:0:0` (same as without keep-id). boxr already attempts idmapped binds for `--userns=keep-id`; without working keep-id maps, `mount_setattr(2)` with `MOUNT_ATTR_IDMAP` returns **EPERM** or **EINVAL** and boxr falls back to a plain bind. Passing case 12 needs kernel/subuid layout parity with Podman CI or a deeper runtime mapping pipeline (OCI `linux.uidMappings` + crun-equivalent setup), not a CLI-only tweak.

## Related

- Rust smokes: `tests/podman_upstream_parity_test.rs`
- Mapping: [PODMAN_TEST_MAPPING.md](PODMAN_TEST_MAPPING.md)
