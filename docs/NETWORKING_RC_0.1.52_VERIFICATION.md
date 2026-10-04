# Networking RC Verification — v0.1.52

Verified on 2026-10-04 using release candidate **v0.1.52** (`boxr-linux-arm64.tar.gz`, `boxr-macos-arm64.tar.gz`).

## Closed Tickets (#413–#421) — Linux (root)

| Issue | Title | v0.1.52 Status |
|-------|-------|----------------|
| #413 | Default/bridge network namespace isolation | **PASS** |
| #414 | usernet TAP/eth0 interface | **PASS** |
| #415 | Detached port forwarding persists | **PASS** |
| #416 | Non-HTTP TCP readiness probe | **PASS** |
| #417 | stop/kill terminates process tree | **PASS** |
| #418 | compose ports forwarding | **PASS** |
| #419 | compose /etc/hosts service discovery | **PASS** |
| #420 | compose down removes project network | **PASS** |
| #421 | Detached port forward through container netns | **PASS** |

All nine closed networking tickets pass on **Linux aarch64 as root** with the v0.1.52 prebuilt binary.

Unit tests in `tests/issues_413_to_420_test.rs` also pass (8/8).

## New Bugs Found

### macOS (boxr-vz) — Critical

1. **Published ports hang** — `boxr-vz` binds the host port but dials unreachable `192.168.64.2:<port>`; curl connects then times out with 0 bytes.
2. **No container networking** — `eth0` is DOWN with no IP; DNS fails (`bad address`); outbound HTTP unreachable.
3. **Compose inter-service unreachable** — `/etc/hosts` entries are correct but `ping api` returns `Network unreachable`.

### Linux — Rootless

4. **EPERM on network unshare** — non-root users get `Failed to unshare network namespace: EPERM` despite subuid/subgid being configured.

### Compose Parity

5. **`compose exec -T` unsupported** — breaks scripts using `docker compose exec -T`.

## Test Environments

- **Linux**: Lima `ubuntu-runner` VM, aarch64, kernel with `unprivileged_userns_clone=1`
- **macOS**: Apple Silicon (aarch64), Darwin 27.0.0

## Reproduction

```bash
# Run issue regression tests
cargo test --test issues_413_to_420_test

# File new bug reports (requires gh auth)
./scripts/create_networking_bugs.sh
```
