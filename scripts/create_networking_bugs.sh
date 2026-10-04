#!/usr/bin/env bash
# Create GitHub issues for networking bugs found during v0.1.52 RC verification.
# Requires: gh auth login (or GH_TOKEN)
set -euo pipefail

REPO="${GITHUB_REPO:-kchaitanya863/boxr}"

create_issue() {
  local title="$1"
  local body="$2"
  gh issue create --repo "$REPO" --title "$title" --body "$body" --label bug
}

create_issue \
  "macOS (boxr-vz): published ports accept connections but hang with zero bytes (dials unreachable VM guest IP)" \
  "$(cat <<'EOF'
## Summary
On macOS with `boxr-vz` (v0.1.52), `boxr run -d -p <host>:<container-port>` starts the container and `boxr-vz` binds the published host port, but every HTTP/TCP connection hangs until timeout with 0 bytes received.

## Root cause
`src/runtime/boxr-vz.m` hardcodes `vm_ip` to `192.168.64.2` and the host-side forwarder dials that address from macOS. The container workload listens inside the micro-VM guest network namespace (e.g. nginx on `0.0.0.0:80`), but `192.168.64.2:80` is not reachable from the macOS host:

```
$ nc -zv 192.168.64.2 80
nc: connectx to 192.168.64.2 port 80 (tcp) failed: Operation timed out
```

Inside the container, `wget http://127.0.0.1:80/` works, but `wget http://192.168.64.2:80/` returns `Network unreachable`.

This is the macOS analogue of closed issue #421 (Linux forwarder dialing host localhost instead of container netns).

## Repro (v0.1.52 prebuilt `boxr-macos-arm64.tar.gz`, Apple Silicon)
```
$ boxr run -d --rm --name macnginx -p 127.0.0.1:19090:80 nginx:alpine
$ lsof -iTCP:19090 -sTCP:LISTEN   # boxr-vz is listening
$ curl -v --max-time 15 http://127.0.0.1:19090/
* Connected to 127.0.0.1 (127.0.0.1) port 19090
* Operation timed out after 15006 milliseconds with 0 bytes received
```

## Expected
Published ports should relay traffic to the container port for the lifetime of the container, same as the Linux Unix-socket bridge fix in #421.

## Environment
- boxr v0.1.52 (`boxr-macos-arm64.tar.gz`)
- macOS aarch64 (Apple Silicon)
- Verified 2026-10-04
EOF
)"

create_issue \
  "macOS (boxr-vz): containers have no working network — eth0 DOWN, DNS fails, outbound unreachable" \
  "$(cat <<'EOF'
## Summary
On macOS with `boxr-vz` (v0.1.52), containers boot with `eth0` in DOWN state with no IP address. DNS resolution and all outbound networking fail.

## Observed (v0.1.52 prebuilt `boxr-macos-arm64.tar.gz`, Apple Silicon)
```
$ boxr run --rm alpine:latest sh -c 'ip addr; wget -qO- http://example.com'
2: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether ... brd ff:ff:ff:ff:ff:ff
    (no inet address)
wget: bad address 'example.com'
```

Only `lo` is UP. The virtio network interface is never brought up or assigned the documented `192.168.64.x` guest address.

## Impact
- No outbound internet from containers on macOS
- DNS completely broken (`bad address` for all hostnames)
- Compose inter-service connectivity fails (`ping: sendto: Network unreachable`) even when `/etc/hosts` has correct IPAM entries
- Published port forwarding also broken (see related issue on boxr-vz dial target)

## Expected
Per `docs/NETWORKING.md`, containers on macOS should have a working virtio network interface with DNS and outbound connectivity through the micro-VM guest network.

## Environment
- boxr v0.1.52 (`boxr-macos-arm64.tar.gz`)
- macOS aarch64 (Apple Silicon)
- Verified 2026-10-04
EOF
)"

create_issue \
  "macOS: compose service discovery writes /etc/hosts entries but inter-service traffic is unreachable" \
  "$(cat <<'EOF'
## Summary
`boxr compose up` on macOS correctly synthesizes `/etc/hosts` entries mapping service names to IPAM addresses (fix for #419), but containers cannot reach each other because the bridge network has no working L2/L3 connectivity.

## Observed (v0.1.52, macOS aarch64)
```
$ cat ~/.boxr/containers/CONTAINER_ID/upper/etc/hosts
127.0.0.1 web
172.30.0.3 api
172.30.0.2 web
...

$ boxr compose exec web ping -c 1 api
PING api (172.30.0.3): 56 data bytes
ping: sendto: Network unreachable
```

`/etc/hosts` is correct but `eth0` is DOWN with no IP, so the synthetic bridge IPs are unreachable.

## Related
Likely blocked by the macOS virtio network interface not being configured (eth0 DOWN). Fixing guest networking should unblock compose service discovery end-to-end.

## Environment
- boxr v0.1.52
- macOS aarch64
- Verified 2026-10-04
EOF
)"

create_issue \
  "Linux rootless: `boxr run` fails with `Failed to unshare network namespace: EPERM` for non-root users" \
  "$(cat <<'EOF'
## Summary
On Linux, running `boxr` as a non-root user fails during container startup with `Failed to unshare network namespace: EPERM`, contradicting the rootless-first design in `docs/NETWORKING.md`.

## Observed (v0.1.52 prebuilt `boxr-linux-arm64.tar.gz`)
```
$ id
uid=502(knaragam) ...

$ boxr run --rm alpine:latest echo hello
Failed to unshare network namespace: EPERM
```

The same binary works correctly when run as root. Subuid/subgid mappings are present:
```
/etc/subuid:knaragam:524288:1073741824
/etc/subgid:knaragam:524288:1073741824
kernel.unprivileged_userns_clone = 1
user.max_user_namespaces = 13689
```

User namespace unshare appears to succeed (error is on `CLONE_NEWNET` in the trampoline child after UID mapping), suggesting the mapped root in the user namespace lacks `CAP_NET_ADMIN` for network namespace creation, or the trampoline mapping flow is incomplete for non-root invokers.

## Impact
Non-root users cannot run any container with default networking on Linux, despite documentation stating rootless operation.

## Expected
Rootless `boxr run` should work for unprivileged users with standard subuid/subgid configuration, using pasta or usernet fallback.

## Environment
- boxr v0.1.52 (`boxr-linux-arm64.tar.gz`)
- Linux aarch64 (Lima VM, Ubuntu)
- Verified 2026-10-04
EOF
)"

create_issue \
  "`boxr compose exec` missing Docker `-T` / `-d` flags (breaks `docker compose exec -T` scripts)" \
  "$(cat <<'EOF'
## Summary
`boxr compose exec` does not accept the `-T` (disable TTY) or `-d` (detach) flags that `docker compose exec` supports. Scripts using `docker compose exec -T service cmd` fail.

## Observed (v0.1.52)
```
$ boxr compose exec -T web ping -c 1 api
error: unexpected argument '-T' found
  tip: to pass '-T' as a value, use '-- -T'
Usage: boxr compose exec <SERVICE> [COMMAND]...
```

## Expected
`boxr compose exec` should accept `-T`, `-d`, `-e`, `--index`, and `--workdir` for Docker Compose parity (see `ComposeExecArgs` in `src/cli/image.rs`).

## Environment
- boxr v0.1.52
- Verified on Linux and macOS
EOF
)"

echo "All networking bug issues created."
