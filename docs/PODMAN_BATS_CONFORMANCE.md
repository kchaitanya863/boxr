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
- **`apache2-utils`** (`htpasswd`) for `030-run` **`--cert-dir`** / local registry BATS
- **`uidmap`** (`newuidmap` / subuid) for `030-run` **`--uidmap`** / `/etc/hosts` cases
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
| `MANIFEST` | `tests/podman_bats/manifest.txt` | BATS filename patterns (file path) |
| `PODMAN_BATS_PATTERN` | (unset) | Single pattern; writes a temp manifest (e.g. `035-logs`) |
| `PODMAN_TESTS_REF` | `main` | Git ref for clone |

Each pattern in `./scripts/run_podman_bats_conformance.sh` gets its own fresh `BOXR_HOME` (via `boxr-podman-wrapper.sh`).

## Curated manifest (isolated, Linux rootless VM)

Edit `tests/podman_bats/manifest.txt` to add patterns (e.g. `160-volumes`). Match upstream names from `test/system/*.bats`.

## Results

Logs land in `.cache/podman-bats-results/run-*.log`. **Failures are expected** while matrix rows in [PODMAN_PARITY.md](PODMAN_PARITY.md) remain partial; the harness exists to measure improvement over time.

Summarize a log:

```bash
grep -E '^ok |^not ok ' .cache/podman-bats-results/run-*.log | tail -20
```

**Curated manifest (Oct 2026, latest boxr on Linux rootless VM):**

| File | ok | not ok | notes |
|------|-----|--------|--------|
| 015-help | 1 | 0 | |
| 020-tag | 2 | 0 | |
| 030-run | 81 | 0 | **`--uidmap` /etc/hosts** — persist `boxr.uid_maps` / `boxr.rootfs_setup_uid` on `create` (annotations synced before `save_to_bundle`); init uses `assume_credentials_for_rootfs_setup` without an early `become_effective_container_root()` before `run_container_child`. MS propagation on `/` is best-effort when hardened hosts EPERM. |
| 040-ps | 8 | 0 | |
| 045-start | 8 | 0 | |
| 050-stop | 9 | 0 | |
| 055-rm | 10 | 0 | |
| 035-logs | 19 | 0 | **k8s-file** tail/since/until/follow/restart/partial lines via `src/logging/mod.rs`; journald cases skip without rootless journald |
| 075-exec | 10 | 0 | **`--group-add`** — setns exec joins mnt + proc remount, applies bundle supplementary GIDs (double-fork after remount for `/proc/self`); skips userns socket when group sync needed. |
| 160-volumes | 25 | 1 | **--userns=keep-id** — rootless `mount_setattr(MOUNT_ATTR_IDMAP)` returns EPERM (kernel requires idmapped binds; plain bind shows `0:0:0` not host uid). Host-side chown fallback is unsafe (subuid ownership breaks host teardown). |
| **Total** | **154** | **1** | plus skips (160-volumes keep-id on some hosts) |

Authoritative log: `.cache/podman-bats-results/run-20261028-130514.log` (153 ok / 2 not ok). Earlier scorecards predated `--uidmap` rootfs-setup identity; re-run `./scripts/run_podman_bats_conformance.sh` after pulling latest.

Set `PODMAN_BATS_STRICT=1` to make the script exit non-zero when any curated pattern fails (for future gating).

On hosts where **`mount_setattr` idmap** fails (Cloud Agent / hardened kernels), **`160-volumes` keep-id** stays red while everything else passes. For a strict gate that matches boxr capability (not host idmap policy), run:

```bash
PODMAN_BATS_OMIT_HOST_GATED=1 PODMAN_BATS_STRICT=1 ./scripts/run_podman_bats_conformance.sh
```

This skips **`160-volumes`** only when `tools/check_podman_bats_prereqs.sh` reports idmap failure.

### Host prerequisites (075 / 160)

Before treating **075-exec** or **160-volumes** keep-id failures as boxr regressions, run:

```bash
./tools/check_podman_bats_prereqs.sh
```

This checks whether the host allows **`setgroups(2)`** (075) and **`mount_setattr(MOUNT_ATTR_IDMAP)`** (160). Cloud Agent / hardened profiles often fail both with **EPERM** while the rest of the curated manifest passes.

## E2E (Ginkgo)

```bash
chmod +x scripts/run_podman_e2e_conformance.sh
./scripts/run_podman_e2e_conformance.sh
```

Uses `tests/podman_bats/e2e_manifest.txt` and `make localintegration FOCUS_FILE=...` in a shallow Podman clone. First run installs ginkgo via upstream Makefile.

**Agent/CI deps:** `libseccomp-dev`, `libgpgme-dev`, `pkg-config` (Go e2e compile). Global Podman storage flags (`--root`, `--runroot`, `--storage-driver`, `--runtime`, `--storage-opt`, `--log-level`, …) are stripped in `preprocess_argv` so suite init can invoke the wrapper. The shared **`boxr-podman-wrapper.sh`** (BATS + e2e) pipes **`--help`** output through **`podmanize_help`** so **`015-help`** sees lowercase **`[options]`** (do not overwrite the wrapper with a bare `exec boxr` shim).

| E2e file | Status |
|----------|--------|
| Full `e2e_manifest.txt` | **40/40** under `PODMAN_E2E_STRICT=1` (`e2e-strict-run4.log`, Oct 2026): exists, version, volume exists/rename, container clone, unshare |

## boxr fixes for upstream tests (ongoing)

| Area | Status |
|------|--------|
| CLI usage exit **125** | Implemented (`try_parse`, `subcommand_required`) |
| `rm` / `pod rm` / `volume rm` bulk flags | `--all`, `-f`, `-a`, combined `-fa` / `-fat` via `preprocess_argv`; `pod rm` accepts **`-a`** |
| `--authfile` | Global + pull/run/build/login/… |
| BATS `skopeo` prefetch | Overridden to `boxr pull` in `boxr-overrides.bash`; **`skopeo-stub.sh`** on `PATH` for `containers-storage:` ↔ dir (030 host env leak) |
| `--cert-dir` / `--creds` | Parsed on pull/run/create/push; BATS local registry TLS via skip built-in roots + `localhost`→127.0.0.1 resolve; **`030-run:cert-dir`** green |
| Registry **push** | Upload exact config/layer bytes from pull; manifest `Content-Type` from stored manifest (OCI vs Docker v2) |
| `image rm` / `rmi -a` | **`--all`** removes all local images (BATS registry teardown `rmi -a -f`) |
| Help text / `info` JSON / conmon fields | Still Podman-specific — most BATS/e2e cases remain red |
| `020-tag.bats` | **2/2** (tag/untag, untag all, `images --sort`, localhost short names) |
| `015-help.bats` | **1/1** (`inspect -l` + extra arg → exit **125**) |
| `030-run.bats` | **81/81** isolated (incl. **host env leak** via skopeo stub + kube play teardown); **8 skips** |
| `040-ps.bats` | **8/8** isolated |
| `045-start.bats` | **8/8** isolated (restart-policy filter accepts **`none`** alias for **`no`**) |
| `050-stop.bats` | **9/9** isolated: Podman **SIGKILL escalation** warnings on stderr when stop timeout **> 0**; **`stop -t 0`** stays silent on stderr (e2e cleanup) |
| `055-rm.bats` | **10/10** isolated (prior runs; re-verify if agent hangs on full file) |
| `075-exec.bats` | **10/10** isolated (`--group-add` exec matches init supplementary groups via setns + proc remount) |
| `160-volumes.bats` | **24/26** + **2 skips** isolated; **red:** `--userns=keep-id` (idmap; see gap below); **volume import** fixed (import into existing volume) |
| `030-run.bats` (spot) | **`--default-mounts-file`**, **`--rootfs`** (exit **127**), **`--pod new:`** rollback on duplicate name; many cases still red (journald, buildah); teardown may flag leaked `localhost/boxr-build:*` images from in-suite builds |
| Podman global flags (e2e init) | `preprocess_argv` strips `--root`, `--runroot`, `--storage-driver`, … before clap |
| Detached `-d` / restart | Short-lived commands (`true`/`false`) no longer fail start; conmon supervisor restart loop for `--restart=on-failure`; fast **`--rm`/`--rmi`** defers bundle rmdir from inside conmon so **`run -d`** does not race on **`conmon.pid`**; BATS restart+hooks green |
| `ps --format` Labels / PodName | `{{.Labels}}`, `{{json .Labels}}`, `{{ .Label "k" }}`, `{{ .PodName }}` |
| Pod infra + BATS leak check | Infra uses `alpine:3.20`; `leak_check` whitelists `alpine:*`, `quay.io/libpod/registry:*`, registry **container** named `registry`, `localhost/cve_2022_1227_test*` (build test **49** image when `top` fails) |

### External storage (buildah stub)

- **`buildah` stub** (`tests/podman_bats/buildah-stub.sh` on `PATH`): `from`, `commit`, `mount`, `unshare` for BATS; persists `external-containers.json` under `BOXR_HOME`.
- **`skopeo` stub** (`tests/podman_bats/skopeo-stub.sh`): `skopeo copy` between `dir:` and `containers-storage:` using boxr save/load and direct `images.json` updates for config env edits.
- **`podman ps --external`**, **`image prune -f --external`**, and **`rm`** on mounted externals use `src/storage/external.rs` (not full buildah/libpod storage).
- Full **manifest.txt** sequential run can OOM; use per-file BATS for focused progress.

**100% pass** of upstream suites is not realistic until `info`, logging, networking, and storage output match Podman; the harness measures progress.

### Known gap: `075-exec` additional groups (rootless)

### Known gap: `075-exec` supplementary groups (rootless)

Podman test **075-exec** requires `podman exec --user root:root … id -G` to print **`0`** only (no inherited supplementary GIDs), and with `--group-add` to list **`0 1 2 … 10`** exactly. That needs `setgroups(2)` after entering the container user namespace.

On typical rootless boxr hosts (`newuidmap` / `newgidmap`, subuid/subgid):

1. The mapping child writes **`deny`** to `/proc/self/setgroups` before `gid_map` (required by the kernel).
2. The parent re-enables **`allow`** on the **mapping child PID** after maps (`RootlessUserConfig::enable_setgroups_for_pid`: direct `/proc/<pid>/setgroups` write, then **`allow_setgroups_from_userns`** fallback).
3. boxr drops host supplementary groups before forking the mapping child, re-enables **`allow`** on **container init** after the PID-namespace fork, and uses a **setns user → setgroups sync → setns pid** exec path with **`allow_setgroups_from_userns`**.

**Environment blockers (Cloud Agent / hardened hosts):**

- Host **`setgroups(2)`** may return **`EPERM`** even when `/proc/self/setgroups` is `allow` (verify with `python3 -c "import ctypes; print(ctypes.CDLL(None).setgroups(0, None))"`). Then the mapping child inherits the host group list into the user namespace as repeated **`65534`** entries; **`id -G`** cannot be trimmed without a working post-map **`setgroups allow`**.
- Repro: `tools/userns_setgroups_repro.c` — after `gid_map`, writing **`allow`** to `/proc/<child>/setgroups` stays **`deny`** with **`errno=EPERM`** on affected kernels.

When **`setgroups allow`** works after maps (Podman CI-style hosts), boxr’s sync paths above are intended to match runc/conmon behavior; re-run **`075:podman exec - additional groups`** there before treating a failure as a boxr regression.

### Known gap: `160-volumes` keep-id bind `stat` (rootless)

Podman test **160-volumes** (case 12) expects `stat` on a host-owned bind-mount file under `--userns=keep-id` to print the **host** `uid:gid`. That requires both:

1. **Keep-id user namespace maps** (see `getRootlessKeepIDMapping` in upstream Podman), and/or  
2. **ID-mapped bind mounts** when maps alone are insufficient.

On this rootless host, boxr applies Podman-style keep-id maps (`getRootlessKeepIDMapping`: `0→1`, `host_uid→0`, remainder from subuid size sum), so **`id -u` / `--userns=keep-id`** match the host UID. Bind mounts still need **idmapped** binds (`mount_setattr(2)` + `MOUNT_ATTR_IDMAP`); on this Cloud Agent VM that step returns **`EPERM`** (plain bind leaves host-owned files visible as **`0:0`** in the container, while the test expects **`$(id -u):$(id -g):0`**). boxr falls back to a plain bind when idmap fails. Re-run case 12 on a host where **`mount_setattr`** idmap succeeds (Linux ≥ 6.3 with unprivileged idmapped mounts enabled) before treating a failure as a boxr regression.

## Related

- Rust smokes: `tests/podman_upstream_parity_test.rs`
- Mapping: [PODMAN_TEST_MAPPING.md](PODMAN_TEST_MAPPING.md)
