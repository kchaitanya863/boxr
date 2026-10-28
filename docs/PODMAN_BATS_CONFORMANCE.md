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

Each pattern in `./scripts/run_podman_bats_conformance.sh` gets its own fresh `BOXR_HOME` (via `boxr-podman-wrapper.sh`).

## Curated manifest (isolated, Linux rootless VM)

Edit `tests/podman_bats/manifest.txt` to add patterns (e.g. `160-volumes`). Match upstream names from `test/system/*.bats`.

## Results

Logs land in `.cache/podman-bats-results/run-*.log`. **Failures are expected** while matrix rows in [PODMAN_PARITY.md](PODMAN_PARITY.md) remain partial; the harness exists to measure improvement over time.

Summarize a log:

```bash
grep -E '^ok |^not ok ' .cache/podman-bats-results/run-*.log | tail -20
```

**Curated manifest (Oct 2026, `bats-manifest-v2.log`, pre–stopping-loop/volume-import commits on 030):**

| File | ok | not ok |
|------|-----|--------|
| 015-help | 1 | 0 |
| 020-tag | 2 | 0 |
| 030-run | 79 | 2 (stopping loop fixed in `547d118`; host env leak out of scope) |
| 040-ps | 8 | 0 |
| 045-start | 8 | 0 |
| 050-stop | 9 | 0 |
| 055-rm | 10 | 0 |
| 075-exec | 9 | 1 (additional groups) |
| 160-volumes | 24 | 2 (keep-id; import fixed in `fe93483`) |

Re-run `./scripts/run_podman_bats_conformance.sh` after pulling latest for authoritative counts (`bats-manifest-v3.log` in progress).

Set `PODMAN_BATS_STRICT=1` to make the script exit non-zero when any curated pattern fails (for future gating).

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
| BATS `skopeo` prefetch | Overridden to `boxr pull` in `boxr-overrides.bash` |
| `--cert-dir` / `--creds` | Parsed on pull/run/create/push; BATS local registry TLS via skip built-in roots + `localhost`→127.0.0.1 resolve; **`030-run:cert-dir`** green |
| Registry **push** | Upload exact config/layer bytes from pull; manifest `Content-Type` from stored manifest (OCI vs Docker v2) |
| `image rm` / `rmi -a` | **`--all`** removes all local images (BATS registry teardown `rmi -a -f`) |
| Help text / `info` JSON / conmon fields | Still Podman-specific — most BATS/e2e cases remain red |
| `020-tag.bats` | **2/2** (tag/untag, untag all, `images --sort`, localhost short names) |
| `015-help.bats` | **1/1** (`inspect -l` + extra arg → exit **125**) |
| `030-run.bats` | **~79/81** isolated: **cert-dir**, **`run --rmi`**, **stopping loop** green; **host env leak** (needs skopeo + Podman `containers-storage` transport) remains red; **8 skips** |
| `040-ps.bats` | **8/8** isolated |
| `045-start.bats` | **8/8** isolated (restart-policy filter accepts **`none`** alias for **`no`**) |
| `050-stop.bats` | **9/9** isolated: Podman **SIGKILL escalation** warnings on stderr when stop timeout **> 0**; **`stop -t 0`** stays silent on stderr (e2e cleanup) |
| `055-rm.bats` | **10/10** isolated (prior runs; re-verify if agent hangs on full file) |
| `075-exec.bats` | **9/10** isolated: **red: additional groups** — rootless `setgroups(2)` after `setns` into an existing user namespace returns EPERM in this environment (BATS expects explicit `user:group` to clear supplementary GIDs); comma-separated **`--group-add 1,2,3,...`** now lands in OCI `additional_gids` |
| `160-volumes.bats` | **24/26** + **2 skips** isolated; **red:** `--userns=keep-id` (idmap; see gap below); **volume import** fixed (import into existing volume) |
| `030-run.bats` (spot) | **`--default-mounts-file`**, **`--rootfs`** (exit **127**), **`--pod new:`** rollback on duplicate name; many cases still red (journald, buildah); teardown may flag leaked `localhost/boxr-build:*` images from in-suite builds |
| Podman global flags (e2e init) | `preprocess_argv` strips `--root`, `--runroot`, `--storage-driver`, … before clap |
| Detached `-d` / restart | Short-lived commands (`true`/`false`) no longer fail start; conmon supervisor restart loop for `--restart=on-failure`; fast **`--rm`/`--rmi`** defers bundle rmdir from inside conmon so **`run -d`** does not race on **`conmon.pid`**; BATS restart+hooks green |
| `ps --format` Labels / PodName | `{{.Labels}}`, `{{json .Labels}}`, `{{ .Label "k" }}`, `{{ .PodName }}` |
| Pod infra + BATS leak check | Infra uses `alpine:3.20`; `leak_check` whitelists `alpine:*`, `quay.io/libpod/registry:*`, registry **container** named `registry`, `localhost/cve_2022_1227_test*` (build test **49** image when `top` fails) |

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
3. boxr also re-enables **`allow`** on the **container init (PID 1) host PID** immediately after the PID-namespace fork.
4. The PID-1 process still may not shrink supplementary groups via `setgroups(2)` on some hosts ( **`id -G`** lists repeated **`65534`** ); **`exec --user root:root`** therefore stays red on **`075-exec`** case 10 until full runc/Podman-style credential application is ported.

Verified locally: `boxr run --rm … cat /proc/1/setgroups` → **`allow`** after the init fix; **`id -G`** after **`exec --user root:root`** may still include mapped **`65534`** entries on this VM. Fixing case 10 likely needs deeper alignment with Podman/runc’s user-namespace lifecycle, not a one-line CLI tweak. **9/10** on `075-exec.bats` is the current ceiling here.

### Known gap: `160-volumes` keep-id bind `stat` (rootless)

Podman test **160-volumes** (case 12) expects `stat` on a host-owned bind-mount file under `--userns=keep-id` to print the **host** `uid:gid`. That requires both:

1. **Keep-id user namespace maps** (see `getRootlessKeepIDMapping` in upstream Podman), and/or  
2. **ID-mapped bind mounts** when maps alone are insufficient.

On this rootless host, `newuidmap` rejects Podman’s first keep-id segment because delegated `/etc/subuid` ranges do not cover host IDs `1..host_uid`. boxr then applies the usual `0 → host_uid` + subuid range maps, so `stat` shows `0:0:0` (same as without keep-id). boxr already attempts idmapped binds for `--userns=keep-id`; without working keep-id maps, `mount_setattr(2)` with `MOUNT_ATTR_IDMAP` returns **EPERM** or **EINVAL** and boxr falls back to a plain bind. Passing case 12 needs kernel/subuid layout parity with Podman CI or a deeper runtime mapping pipeline (OCI `linux.uidMappings` + crun-equivalent setup), not a CLI-only tweak.

## Related

- Rust smokes: `tests/podman_upstream_parity_test.rs`
- Mapping: [PODMAN_TEST_MAPPING.md](PODMAN_TEST_MAPPING.md)
