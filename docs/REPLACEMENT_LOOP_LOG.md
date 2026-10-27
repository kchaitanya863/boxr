# Docker/Podman replacement loop test log

Hourly automated parity and real-world smoke tests. Each tick appends a section below.

## Tick metadata

| Field | Value |
|-------|-------|
| Started | 2026-10-27 (loop armed, 1h interval) |
| Binary | `./target/release/boxr` |
| Platform | Linux rootless |

## Issues (cumulative)

| ID | Severity | Area | Summary | Repro | First seen |
|----|----------|------|---------|-------|------------|
| L-001 | **fixed** | runtime / USER | Rootless child wrote `setgroups deny` before `newgidmap`, which **permanently** disables supplementary groups in the user namespace (kernel cannot revert to `allow`). Broke `gosu`/postgres entrypoints. **Fix:** stop denying from the child; let `newgidmap` + parent fallback set policy. | Same repro now passes `pg_isready` | Tick 1 → fixed tick 2 |
| L-002 | **low** | CLI UX | `boxr unshare --help` exits 1 with `ENOENT` (trampoline path); other top-level commands return 0 for `--help`. | `boxr unshare --help` | Tick 1 |
| L-003 | **test gap** | QA | Black-box B9 only asserts `replacement-web` is up; does not health-check `db` / postgres — L-001 not caught by `./scripts/run_blackbox_qa.sh`. | See `scripts/run_blackbox_qa.sh` B9 steps | Tick 1 |

## Tick history

### Tick 1 — 2026-10-27 ~11:58 AM PT

**Binary:** `boxr 0.1.54` (`./target/release/boxr`), Linux rootless (`passt`/`pasta` present, `subuid` OK).

**Automated**

| Suite | Result |
|-------|--------|
| `./scripts/run_blackbox_qa.sh -b ./target/release/boxr` | **PASS** — 54 passed, 0 failed, 1 skipped, ~115s |
| `python3 tools/podman_parity_audit.py` | **PASS** — P0 14/14 |
| `cargo test --test podman_parity_blackbox_test --test compose_docker_replacement_test` | **PASS** — 23 tests |

**Manual / real-world**

| Check | Result |
|-------|--------|
| `pull` + `run alpine` | OK |
| `nginx:alpine` publish `18080:80` | HTTP 200 |
| `postgres:16-alpine` | **FAIL** (L-001) |
| custom network + volume | OK |
| `build` simple Dockerfile | OK |
| `daemon` + API version via unix socket | OK |
| Top-level + nested `--help` sweep | Only `unshare` failed (L-002) |

**Artifacts:** `/opt/cursor/artifacts/blackbox-qa-run.log`, `blackbox-junit.xml`, `podman-parity-audit.log`, `podman-compose-tests.log`

### Tick 3 — 2026-10-27 ~1:00 PM PT

**Binary:** `boxr 0.1.54` with L-001 fix merged (`cursor/fix-l001-rootless-setgroups-17b5` → QA branch).

**Automated**

| Suite | Result |
|-------|--------|
| `./scripts/run_blackbox_qa.sh --include-stress` | **PASS** — 57 passed, 0 failed, 0 skipped, ~140s |
| `python3 tools/podman_parity_audit.py` | **PASS** — P0 14/14 |
| `cargo test --test podman_parity_blackbox_test --test compose_docker_replacement_test` | **PASS** — 23 tests |

**Manual / real-world (expanded)**

| Check | Result |
|-------|--------|
| `postgres:16-alpine` + `pg_isready` | **OK** (L-001 verified fixed) |
| `minimal-dns.yml` compose up/ps/down | OK |
| host bind mount `:ro` | OK |
| `play kube` minimal pod + down | OK |
| L-002 `unshare --help` | Still **FAIL** ENOENT |

**Notes:** Black-box harness teardown logged `rm: Permission denied` on postgres data dirs under temp `BOXR_HOME` (cosmetic cleanup; tests still passed).

**Artifacts:** `/opt/cursor/artifacts/blackbox-tick3.log`, `blackbox-tick3-junit.xml`, `podman-parity-tick3.log`, `integration-tick3.log`
