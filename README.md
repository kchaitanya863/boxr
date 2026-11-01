# boxr 📦

[![Status](https://img.shields.io/badge/status-beta-orange.svg)](https://github.com/kchaitanya863/boxr)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/kchaitanya863/boxr/actions/workflows/ci.yml/badge.svg)](https://github.com/kchaitanya863/boxr/actions/workflows/ci.yml)

A fast, lightweight, production-grade **Open Container Initiative (OCI)** compliant container engine, image builder, compose orchestrator, and runtime written in **Rust**.

> **Note**: `boxr` is currently in **Beta**. We are actively hardening features, testing parity workloads, and welcoming community contributions and feedback!

## Demo

![boxr demo: pull, run, and manage rootless containers](docs/demo.gif)

*Pull, run, and manage rootless containers — no daemon, no sudo. Recorded with `boxr` 0.1.43 on Linux.*

`boxr` is designed to be **rootless by default** and built from scratch with custom implementations:
1. **Rootless by Default**: User namespaces (`CLONE_NEWUSER`) with `uid_map` and `gid_map` mapping the unprivileged user to container root (UID 0), capability dropping (dropping `CAP_SYS_ADMIN`, `CAP_SYS_RAWIO`, etc.), and default seccomp profiles without requiring `sudo`/root.
2. **Copy-on-Write / OverlayFS Driver**: Native OverlayFS (`lowerdir`, `upperdir`, `workdir`, `merged`) with custom fast hardlink CoW trees for instant sub-millisecond container startup and near-zero disk usage.
3. **cgroups v2 Resource Controllers**: Memory limits (`--memory`), CPU quota & period (`--cpus`), and task limits (`--pids-limit`) managed via the cgroupfs v2 hierarchy.
4. **Image Export & Import (`save` / `load`)**: Standard multi-layer Docker/OCI tar archives (`boxr save -o image.tar <image>` and `boxr load -i image.tar`).
5. **Registry Authentication & Push**: `boxr login`, `boxr logout`, and `boxr push` using base64 encoded credentials in `~/.boxr/config.json`.
6. **Interactive PTY / Terminal**: Raw mode terminal guards (`-it`), window resize (`TIOCGWINSZ`), and clean terminal state restoration.
7. **Volume Management (`boxr volume`)**: Local named persistent volumes, host directory bind mounts (`-v /host:/container:ro`), volume inspection, and lifecycle management.
8. **Network Management (`boxr network`, `usernet`, & `pasta`)**: Bridge networks, IPAM address allocation, embedded pure-Rust user-mode network stack (`usernet`) with zero external dependencies, native `pasta` integration, and user-space rootless port forwarding proxy.
9. **Dockerfile Builder (`boxr build`)**: Multi-step build engine supporting `FROM`, `RUN`, `COPY`, `ADD`, `WORKDIR`, `ENV`, `CMD`, `ENTRYPOINT`, `EXPOSE`, and `LABEL`.
10. **Compose Orchestrator (`boxr compose`)**: Parsing `docker-compose.yml`, topological dependency graph resolution (`depends_on`), multi-container deployment, teardown, and log streaming.
11. **Daemon REST API (`boxr daemon` & `boxr system service`)**: Unix Domain Socket (`boxr.sock`) and TCP/TLS server implementing Docker Engine and Podman API endpoints (`/_ping`, `/version`, `/info`, `/containers`, `/images`, `/networks`, `/volumes`), systemd socket activation (`LISTEN_FDS`), and `sd_notify`.
12. **Container & Pod Lifecycle**: Background detached mode (`-d`), `stop`, `start`, `restart`, `pause`, `unpause`, `logs`, `exec`, `inspect`, `checkpoint`/`restore`, Podman-compatible pods (`boxr pod`), Quadlet systemd units (`boxr quadlet`), and multi-node build farms (`boxr farm`).
13. **100% Docker & Podman CLI & API Parity**: Full drop-in compatibility verified against all **77/77 upstream Podman BATS suites**, **141/141 portable upstream Podman Ginkgo E2E suites**, **14/14 Compose suites**, **28 `.at` + 15 Python APIv2 suites**, **9 Python Docker (`docker-py`) suites**, **1/1 Farm BATS suite**, and **325/325 Docker CLI options**.

---

## Architecture & Comprehensive Documentation

Comprehensive engineering guides, architectural diagrams, and command manuals:
- **[Architecture & Runtime Internals Guide](docs/ARCHITECTURE.md)**: Deep dive into the trampoline, storage hierarchy, and multi-platform hypervisor bridge.
- **[Enterprise Runtimes & Hardening Guide](docs/ENTERPRISE_RUNTIMES.md)**: Privilege dropping, `/tmp` sticky `1777` permissions, POSIX `/dev/shm`, PID 1 init, and cgroups v2.
- **[Rootless Container Isolation](docs/ROOTLESS.md)**: Kernel namespaces, single-threaded trampoline, subordinate ID mapping, and capabilities.
- **[Container Networking & UserNet Stack](docs/NETWORKING.md)**: Pure-Rust embedded TAP network stack, `pasta` integration, and IPAM.
- **[CLI Command Reference Manual](docs/CLI_REFERENCE.md)**: Exhaustive syntax, flags, and options for all 38+ CLI subcommands.
- **[Kubernetes Pods & Compose Orchestration](docs/KUBERNETES_AND_COMPOSE.md)**: Podman-style pods, `play kube`, and Docker Compose DAGs.
- **[Podman Parity Matrix](docs/PODMAN_PARITY.md)**: Domain-by-domain Podman & Docker compatibility matrix and P0 black-box verification gates.
- **[Podman BATS & Ginkgo E2E Conformance](docs/PODMAN_BATS_CONFORMANCE.md)**: Reproducible harness and status for all 77 upstream Podman BATS suites, 141 Ginkgo E2E suites, Compose, APIv2, Python Docker, and Farm suites.

```
boxr/
├── src/
│   ├── main.rs                 # CLI entrypoint, unshare, and single-threaded trampolines
│   ├── lib.rs                  # Library crate root and command orchestration
│   ├── cli/                    # Clap CLI arguments, options, and command definitions
│   │   ├── mod.rs              # Top-level Cli and Commands enum
│   │   ├── container/          # Container domain flags (run, lifecycle, ops)
│   │   ├── artifact.rs         # Artifact subcommands (add, extract, inspect, ls, pull, push, rm)
│   │   ├── farm.rs             # Multi-architecture build farm subcommands (build, create, ls, rm, update)
│   │   ├── image.rs            # Image flags (BuildArgs, ImagesArgs, PullArgs, Save/Load, Diff, Scp)
│   │   ├── kube.rs             # Modern Kubernetes command tree (play, down, generate, apply)
│   │   ├── machine.rs          # Virtual machine commands (inspect, set, os, reset, restart, ssh, cp)
│   │   ├── manifest.rs         # Multi-arch manifest list commands (create, add, annotate, inspect, push, rm)
│   │   ├── podman_globals.rs   # Global Podman storage/runtime/remote flag preprocessing
│   │   ├── quadlet.rs          # Quadlet unit file subcommands (ls, install, print, rm)
│   │   ├── secret.rs           # Secret subcommands (create, ls, inspect, rm, exists)
│   │   ├── system.rs           # System flags (DaemonArgs, EventsArgs, ServiceArgs, Pods, Connection, Check)
│   │   ├── trust.rs            # Container image trust policy subcommands (show, set)
│   │   └── volumes_networks.rs # VolumeSubcommands and NetworkSubcommands
│   ├── artifact/
│   │   └── mod.rs              # Content-addressable OCI artifact store with SHA-256 digests
│   ├── completions/
│   │   ├── mod.rs              # Shell completion generator (bash, zsh, fish, powershell) & docker wrapper
│   │   └── cobra.rs            # Cobra-compatible __complete / __completeNoDesc dynamic completion engine
│   ├── farm/
│   │   └── mod.rs              # Multi-node build farm & system connection manager (PODMAN_CONNECTIONS_CONF)
│   ├── guardrails/
│   │   └── mod.rs              # Log rotation, port collision guard, disk space check, and zombie reaper
│   ├── logging/
│   │   └── mod.rs              # CRI k8s-file log formatting, partial-line reassembly, and time filters
│   ├── quadlet/
│   │   └── mod.rs              # Podman Quadlet unit file manager (.container, .kube, .volume, .network, .pod)
│   ├── service/
│   │   └── mod.rs              # Background service autostart manager (launchd, systemd --user, Windows service)
│   ├── specgen/
│   │   └── mod.rs              # Podman Specgen (SpecGenerator JSON) serializer for containers and pods
│   ├── oci/
│   │   ├── mod.rs              # OCI module definitions
│   │   ├── reference.rs        # Image reference parsing (e.g. library/hello-world:latest)
│   │   ├── distribution.rs     # OCI Distribution Spec / Registry v2 HTTP client & ImageDistribution trait
│   │   ├── image.rs            # OCI Image Spec: manifests, configs, layer unpacker & whiteouts
│   │   └── runtime.rs          # OCI Runtime Spec: config.json bundle generator
│   ├── security/
│   │   └── mod.rs              # Rootless user namespaces, UID/GID maps, capabilities, seccomp
│   ├── cgroups/
│   │   └── mod.rs              # cgroups v2 resource limit controllers & ResourceManager trait
│   ├── storage/
│   │   ├── mod.rs              # Local storage manager (~/.boxr/)
│   │   ├── traits.rs           # ISP storage traits (ContainerReader/Writer, ImageReader/Writer)
│   │   ├── overlay.rs          # OverlayFS & Copy-on-Write storage driver
│   │   ├── image_store.rs      # Local image index & content-addressable layer store
│   │   └── container_store.rs  # Container lifecycle & state tracking
│   ├── auth/
│   │   ├── mod.rs              # Credential store, authfile validation, and registry push
│   │   └── archive.rs          # Multi-image Docker & OCI tar archiver (save/load)
│   ├── terminal/
│   │   └── mod.rs              # Raw terminal PTY guard and window size detection
│   ├── builder/
│   │   ├── mod.rs              # Builder module exports and regression contracts
│   │   ├── parser.rs           # Multi-stage Dockerfile parser & Instruction AST
│   │   ├── executor.rs         # Build stage executor and containerized step runner
│   │   ├── cache.rs            # Content-addressed build cache manager (disk_usage, prune)
│   │   └── dockerignore.rs     # .dockerignore pattern matcher and wildcard resolver
│   ├── compose/
│   │   └── mod.rs              # Compose YAML parser, dependency graph, and orchestrator
│   ├── network/
│   │   ├── mod.rs              # Bridge networks, IPAM, and NetworkReader/Writer traits
│   │   ├── pasta.rs            # Pasta user-mode tap rootless network driver
│   │   ├── usernet/            # Pure-Rust native user-mode L2/L3/L4 network stack
│   │   │   ├── mod.rs          # UserNet exports and TAP packet loop integration
│   │   │   ├── packets.rs      # Ethernet, ARP, IPv4, UDP, and TCP header serializers & checksums
│   │   │   └── engine.rs       # In-memory ARP, ICMP echo, and TCP NAT proxy engine
│   │   └── rootless.rs         # Rootless user-space TCP/UDP port forwarder proxy
│   ├── pod/
│   │   ├── mod.rs              # Podman pod lifecycle and namespace sharing (PodReader/Writer)
│   │   └── ops.rs              # Pod cloning and aggregated container logging
│   ├── kube/
│   │   └── mod.rs              # Multi-resource Kubernetes YAML (Pod, Deployment, DaemonSet, Job, Service, PVC)
│   ├── health/
│   │   └── mod.rs              # Container healthcheck probes (HealthProbe trait) and restart supervisor
│   ├── stats/
│   │   └── mod.rs              # Real-time resource usage collector (CPU %, RAM, PIDs)
│   ├── events/
│   │   └── mod.rs              # Real-time JSONL lifecycle events recorder (EventSink & EventFilter)
│   ├── system/
│   │   └── mod.rs              # Disk space auditing (df_with_readers) and automated pruning
│   ├── volume/
│   │   ├── mod.rs              # Named volume storage and bind mount resolver (VolumeReader/Writer)
│   │   └── ops.rs              # Volume export, import, reload, rename, and mount operations
│   ├── daemon/
│   │   ├── mod.rs              # Unix domain socket / TCP / TLS server & router dispatcher
│   │   ├── containers.rs       # Container lifecycle REST endpoints (create, inspect, wait, logs)
│   │   ├── images.rs           # Image management REST endpoints (list, create, tag, inspect)
│   │   ├── system.rs           # Daemon health and system info endpoints (_ping, version, info)
│   │   ├── prune.rs            # Resource cleanup endpoints (containers, images, volumes, networks)
│   │   └── volumes_networks.rs # Volume & network REST CRUD endpoints
│   └── runtime/
│       ├── mod.rs              # Execution runtime traits (ContainerRuntime & ProcessKiller)
│       ├── checkpoint.rs       # Container checkpoint and restore runtime engine
│       ├── traits.rs           # Container runtime engine abstractions
│       ├── kill.rs             # Process termination & signal parsing
│       ├── cp.rs               # Container-to-host and host-to-container copy engine
│       ├── diff.rs             # Container filesystem diff engine
│       ├── top.rs              # Process inspection inside container and pod bundles
│       ├── linux.rs            # Native Linux execution (unshare, pivot_root, mounts)
│       └── darwin.rs           # macOS container execution bridge (Virtualization.framework)
└── tests/
    ├── podman_bats/            # Vendored upstream Podman BATS catalog (77 suites) & Ginkgo E2E manifest (141 suites)
    ├── podman_upstream/        # Vendored upstream Podman e2e, apiv2, compose, python, and farm suites
    ├── docker_parity_test.rs   # Upstream Docker and Podman CLI parity tests (325/325 options)
    ├── podman_parity_test.rs   # Podman parity unit & integration tests
    ├── podman_parity_blackbox_test.rs # Podman P0 black-box E2E tests
    ├── podman_upstream_parity_test.rs # Upstream Podman behavioral smoke tests
    ├── e2e_test.rs             # End-to-end container, network, and compose tests
    ├── enterprise_scenarios_test.rs # Enterprise workload and security isolation tests
    ├── integration_test.rs     # Integration test suite
    ├── issues_*_test.rs        # Regression suites covering issues #47 through #448
    └── qa_*.rs                 # Edge-case, negative, and breaking test matrices
```

---

## Quick Start

### Installation

#### Universal One-Liner (Linux, macOS & Windows)

Install precompiled `boxr` binaries, shell completions, and environment PATH configurations with a single command:

- **Linux & macOS**:
  ```bash
  # Install latest release automatically:
  curl -fsSL https://raw.githubusercontent.com/kchaitanya863/boxr/main/install.sh | sh

  # Install a specific version:
  curl -fsSL https://raw.githubusercontent.com/kchaitanya863/boxr/main/install.sh | sh -s -- -v 0.1.68
  ```

- **Windows PowerShell**:
  ```powershell
  # Install latest release automatically:
  irm https://raw.githubusercontent.com/kchaitanya863/boxr/main/install.ps1 | iex

  # Install a specific version:
  $env:VERSION="0.1.68"; irm https://raw.githubusercontent.com/kchaitanya863/boxr/main/install.ps1 | iex
  ```

#### Homebrew (macOS & Linux)

```bash
# Add the official tap (central hub for all formulae)
brew tap kchaitanya863/tap

# Install boxr (installs precompiled binary + bash/zsh/fish completions)
brew install boxr

# (Optional) Run daemon as an always-on background service with autostart on login:
brew services start boxr
```

#### Debian / Ubuntu (`.deb`)

Download and install the native `.deb` package from the [latest release](https://github.com/kchaitanya863/homebrew-tap/releases):

```bash
# x86_64 / amd64:
curl -fsSLO https://github.com/kchaitanya863/homebrew-tap/releases/latest/download/boxr_0.1.68_amd64.deb
sudo dpkg -i boxr_*_amd64.deb

# ARM64 / aarch64:
curl -fsSLO https://github.com/kchaitanya863/homebrew-tap/releases/latest/download/boxr_0.1.68_arm64.deb
sudo dpkg -i boxr_*_arm64.deb
```

#### Fedora / RHEL / CentOS (`.rpm` / YUM / DNF)

Download and install the native `.rpm` package from the [latest release](https://github.com/kchaitanya863/homebrew-tap/releases):

```bash
# Install via dnf or rpm:
sudo dnf install https://github.com/kchaitanya863/homebrew-tap/releases/latest/download/boxr-0.1.68-1.x86_64.rpm

# Or via rpm directly:
sudo rpm -ivh boxr-*.rpm
```

#### Windows (Chocolatey & Winget)

Install via Chocolatey:

```powershell
choco install boxr
```

Or extract the precompiled Windows `.zip` package from the [latest release](https://github.com/kchaitanya863/homebrew-tap/releases):

```powershell
Invoke-WebRequest -Uri https://github.com/kchaitanya863/homebrew-tap/releases/latest/download/boxr-windows-x86_64.zip -OutFile boxr.zip
Expand-Archive boxr.zip -DestinationPath C:\ProgramData\boxr
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\ProgramData\boxr\bin", "Machine")
```

#### Cross-Platform Container Execution

`boxr` provides consistent, native performance across major operating systems:

- **Linux**: Direct kernel execution via native namespaces (`CLONE_NEWUSER`, `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWNS`, `CLONE_NEWIPC`, `CLONE_NEWUTS`), cgroups v2 resource controllers, and native OverlayFS with copy-on-write trees. Zero daemon overhead and 100% rootless security by default.
- **macOS**: High-performance micro-VM container execution powered by Apple's native `Virtualization.framework` (`boxr-vz`). Unprivileged and owned by the logged-in user without running root daemons or requiring `sudo`.
- **Windows**: Native Windows container isolation for Windows container images, or transparent rootless Linux container execution via native Windows container isolation or WSL2 backend.

#### (Optional) Docker & Podman Drop-in Alias
If you would like existing `docker` or `podman` commands to transparently run with `boxr`, you can choose to configure an alias or wrapper:

- **Option A (Recommended wrapper)**: Install a standalone wrapper binary at `~/.boxr/bin/docker`:
  ```bash
  boxr alias --install
  ```
- **Option B (Shell alias)**: Add an alias to your shell profile (`~/.zshrc`, `~/.bashrc`, or `~/.config/fish/config.fish`):
  ```bash
  # Bash / Zsh
  alias docker="boxr"
  alias podman="boxr"

  # Fish
  alias docker "boxr"
  alias podman "boxr"
  ```
- **Option C (Windows PowerShell)**: Add an alias in your PowerShell profile:
  ```powershell
  Set-Alias -Name docker -Value boxr
  Set-Alias -Name podman -Value boxr
  ```
*If you already have Docker or Podman installed side-by-side or prefer explicit names, simply invoke `boxr` directly without creating any alias.*

#### Manual Build (From Source)

```bash
cargo install --path .
# Or build a release binary at target/release/boxr:
cargo build --release
```

---

## Command Reference

### Containers & Execution

```bash
# Run hello-world
boxr run hello-world

# Run with resource constraints and rootless mode
boxr run --memory 512m --cpus 1.5 --pids-limit 100 --rm alpine /bin/echo "Resource limits enforced"

# Run with Podman-style pasta rootless network namespace isolation
boxr run --network pasta -p 8080:80 nginx:latest

# Run with zero-dependency pure-Rust user-mode network stack (usernet)
boxr run --network usernet -p 8080:80 nginx:latest

# Run with isolated loopback-only private network namespace
boxr run --network none alpine ifconfig

# Run in background with port forwarding, volumes, and auto-cleanup
boxr run -d --name web -p 8080:80 -v my-data:/data alpine /bin/sh -c "echo 'ready' > /data/status.txt; sleep 60"

# View logs (with live following, timestamps, and line tailing)
boxr logs -f -t -n 50 web

# Send Unix signals to container process (default: SIGKILL)
boxr kill -s SIGHUP web
boxr kill web

# Execute command inside running container
boxr exec web /bin/cat /data/status.txt

# Inspect container metadata
boxr inspect web

# Inspect container filesystem diff (Added, Changed, Deleted files)
boxr diff web

# View running container processes
boxr top web

# Pause and unpause container
boxr pause web
boxr unpause web

# Rename container
boxr rename web production-web

# Wait for container to exit and print exit code
boxr wait production-web

# Copy files between host and container
boxr cp web:/app/config.json ./local-config.json
boxr cp ./updated-config.json web:/app/config.json

# Dynamically update container resource limits without restarting
boxr update --memory 1g --cpus 2.0 --pids-limit 200 web

# Attach local terminal streams to running container
boxr attach web

# Stop, start, and remove
boxr stop production-web
boxr start production-web
boxr rm production-web
```

### Images, Commit & Registry Auth

```bash
# Pull image
boxr pull alpine:latest

# Build image from Dockerfile
boxr build -t my-app:v1 .

# Commit container changes into a new image
boxr commit -m "added custom configs" my-container new-app:v1

# Save image to tar archive
boxr save -o my-app.tar my-app:v1

# Load image from tar archive
boxr load -i my-app.tar

# Log in to registry
boxr login -u myuser -p mysecret

# Push image
boxr push my-app:v1

# Log out
boxr logout
```

### Volumes

```bash
# Create named volume
boxr volume create app-db

# List volumes
boxr volume ls

# Inspect volume
boxr volume inspect app-db

# Remove volume
boxr volume rm app-db
```

### Networks

```bash
# Create custom bridge network
boxr network create my-net --subnet 172.30.0.0/16

# List networks
boxr network ls

# Inspect network and attached endpoints
boxr network inspect my-net

# Connect container to network
boxr network connect my-net my-container

# Remove network
boxr network rm my-net
```

### Compose

```bash
# Start multi-container application
boxr compose -f docker-compose.yml up -d

# Check service status
boxr compose ps

# Stream logs
boxr compose logs

# Stop and remove containers and networks
boxr compose down
```

### Podman Pods & Kubernetes Workloads

```bash
# Create a multi-container pod sharing network/IPC
boxr pod create --name web-pod -p 8080:80

# List pods
boxr pod ps

# Inspect pod configuration
boxr pod inspect web-pod

# Play a Kubernetes Pod YAML directly
boxr play kube pod.yaml

# Generate a Kubernetes Pod YAML from an existing container or pod
boxr generate kube my-container

# Run a command inside a new user namespace
boxr unshare whoami

# Remove pod and member containers
boxr pod rm web-pod
```

### Daemon REST API & Background Service

```bash
# Start daemon listening on Unix domain socket (or TCP on Windows)
boxr daemon --socket ~/.boxr/boxr.sock

# Query Docker Engine API
curl --unix-socket ~/.boxr/boxr.sock http://localhost/_ping
curl --unix-socket ~/.boxr/boxr.sock http://localhost/version
curl --unix-socket ~/.boxr/boxr.sock http://localhost/containers/json

# Manage as an always-on background service with autostart on login:
boxr service install
boxr service start
boxr service status
boxr service stop
boxr service uninstall
```

### Stats & Events Monitoring

```bash
# Display live streaming container resource stats (CPU, Memory, PIDs)
boxr stats

# Snapshot stats without streaming
boxr stats --no-stream

# Stream real-time container lifecycle events (create, start, die, stop)
boxr events
```

### System & Disk Usage

```bash
# Show disk space used by containers, images, volumes, and build cache
boxr system df

# Reclaim space by removing stopped containers, unused networks, and build cache
boxr system prune

# Comprehensive prune (including all unused images and volumes)
boxr system prune --all --volumes
```

### Shell Completions & Docker/Podman Drop-in Alias

```bash
# Generate shell autocompletion script (bash, zsh, fish)
boxr completion zsh > ~/.zfunc/_boxr
boxr completion bash > /etc/bash_completion.d/boxr

# Generate shell alias command
boxr alias

# Install Docker drop-in wrapper script in ~/.boxr/bin/docker
boxr alias --install
```

---

## Performance Benchmarks: Boxr vs Podman vs Docker

Run the automated 3-way benchmark suite:

```bash
./benchmark.sh
```

### Unified 3-Way Benchmark Results (Linux x86_64 — `boxr v0.1.65` vs `Podman 4.9.3` vs `Docker 29.1.3`)

| Benchmark Metric | BOXR (Rust) | PODMAN (Go) | DOCKER | BOXR vs PODMAN / DOCKER |
| :--- | :--- | :--- | :--- | :--- |
| **Service / Daemon Idle Memory** | **11.5 MB** | 38.9 MB | 152.7 MB | **3.38x lighter than Podman / 13.26x lighter than Docker** 🍃 |
| **CLI Peak RAM Usage (RSS)** | **12.2 MB** | 37.6 MB | 27.6 MB | **3.08x less RAM than Podman / 2.26x less than Docker** ⚡ |
| **CLI Binary Size on Disk** | **15.9 MB** (6.2M stripped) | 35.6 MB | 29.9 MB | **2.23x smaller than Podman / 1.88x smaller than Docker** 📦 |
| **Full Runtime Suite Disk Size** | **15.9 MB** (single binary) | 45.3 MB (`podman`+`crun`+`conmon`+`netavark`) | 174.5 MB (`docker`+`dockerd`+`containerd`+`runc`) | **2.84x smaller than Podman / 10.95x smaller than Docker** 📦 |
| **Dockerfile Build (Cold, `--no-cache`)** | **332.4 ms** | 739.2 ms | 3283.2 ms | **2.22x faster than Podman / 9.88x faster than Docker** 🚀 |
| **Dockerfile Build (Cached)** | 330.9 ms | 233.4 ms | **64.8 ms** | **0.71x vs Podman / 0.20x vs Docker** |
| **Startup Latency (Median)** | 360.1 ms | **257.7 ms** | 793.9 ms | **0.72x vs Podman / 2.20x faster than Docker** 🚀 |
| **Startup Latency (Min)** | 357.3 ms | **249.1 ms** | 714.2 ms | **0.70x vs Podman / 2.00x faster than Docker** 🚀 |
| **Startup Latency (Mean ± SD)** | 363.4 ± 8.8 ms | **258.7 ± 7.7 ms** | 807.1 ± 71.4 ms | **0.71x vs Podman / 2.22x faster than Docker** 🚀 |
| **5 Concurrent Containers Spawn** | 1225.2 ms | **1118.5 ms** | 3611.6 ms | **0.91x (~par) vs Podman / 2.95x faster than Docker** ⚡ |
| **Volume I/O (10MB Write+Read)** | 358.6 ms | **254.6 ms** | 770.9 ms | **0.71x vs Podman / 2.15x faster than Docker** ⚡ |

### Benchmark Analysis
- **Zero-Dependency Single Binary Footprint**: `boxr` packages the CLI, OCI runtime, rootless user-namespace trampoline, image builder, compose orchestrator, and user-mode network stack (`usernet`) into a single **15.9 MB** binary (**6.2 MB** stripped). By comparison, Podman requires **45.3 MB** across `podman`, `conmon`, `crun`, `netavark`, `aardvark-dns`, `pasta`, `fuse-overlayfs`, and `catatonit`, while Docker requires **174.5 MB** across `docker`, `dockerd`, `containerd`, `containerd-shim-runc-v2`, and `runc` (**10.95x larger** on Linux; **2.1 GB** on macOS Docker Desktop).
- **Minimal Memory Overhead**: `boxr` consumes **12.2 MB** peak CLI RSS (**3.08x less** than Podman's Go runtime at 37.6 MB and **2.26x less** than Docker CLI at 27.6 MB). In background API service mode, `boxr daemon` idles at **11.5 MB** vs **38.9 MB** for `podman system service` and **152.7 MB** for `dockerd` + `containerd` (**13.26x lighter**).
- **Cold Build & Container Execution Speed**: `boxr` executes cold multi-step `Dockerfile` builds in **332.4 ms** — **2.22x faster** than Podman (`buildah`, 739.2 ms) and **9.88x faster** than Docker (`3283.2 ms`). For single-container startup (`run --rm alpine /bin/echo test`), 5-way concurrent container bursts, and 10MB bind-mount I/O, `boxr` is **2.15x–2.95x faster than Docker** while tracking closely behind native `crun`-backed Podman (**1.23s vs 1.12s** on 5 concurrent containers).

---

## Testing

Run the verification and conformance suites:

```bash
# 1. 600+ Rust unit, integration, and regression tests
cargo test -- --test-threads=1

# 2. Podman P0 CLI audit (14/14) & black-box E2E gate
./scripts/run_podman_blackbox_e2e.sh

# 3. Upstream Podman BATS conformance (all 77/77 upstream suites passing)
./scripts/run_podman_bats_all_upstream.sh

# 4. Upstream Podman Ginkgo E2E conformance (all 141/141 portable suites passing)
PODMAN_E2E_STRICT=1 ./scripts/run_podman_e2e_conformance.sh

# 5. Upstream Podman Compose conformance (all 14/14 scenario suites passing)
./scripts/run_podman_compose_conformance.sh

# 6. Upstream Podman REST API v2 conformance (28 .at bash suites + 15 Python suites passing)
./scripts/run_podman_apiv2_conformance.sh

# 7. Upstream Podman Python Docker (docker-py) conformance (all 9/9 suites passing)
./scripts/run_podman_python_conformance.sh

# 8. Upstream Podman Farm BATS conformance (test/farm/001-farm.bats passing)
bats tests/podman_upstream/farm/001-farm.bats
```

### Test Coverage Highlights
- **77/77 Upstream Podman BATS Suites**: 100% pass rate across all 77 vendored upstream `test/system/*.bats` suites (images, build, rootless userns/ipcns/netns, cgroups, SELinux, healthchecks, quadlet, systemd socket activation, pods, kube play, compose, checkpoint/restore, and Cobra shell completions).
- **141/141 Portable Upstream Podman Ginkgo E2E Suites**: Verified against all 141 portable upstream `test/e2e/*_test.go` suites covering container create/run/lifecycle, exec, logs, cp, events, inspect, namespaces, cgroups/resources, networking (`pasta`/`usernet`/`aardvark`), pods, `play kube`, quadlet, systemd, images, manifests, OCI artifacts, `farm`, and `image trust`.
- **14/14 Upstream Podman Compose Suites**: Full multi-container orchestration verified across all 14 `test/compose/*` scenarios (`env_and_volume`, `etc_hosts`, `mount_and_label`, `port_map_diff_port`, `simple_port_map`, `two_networks`, `uptwice`, `cdi_device`, `config_Map`, `slirp4netns_opts`, `test_21799`, `ulimits`, etc.).
- **28 `.at` + 15 Python Upstream REST API v2 Suites & 9 Python Docker (`docker-py`) Suites**: Complete Libpod v5 and Docker Engine REST API compatibility verified against `test/apiv2/` and `test/python/docker/`.
- **1/1 Upstream Farm BATS Suite**: Multi-node build farm (`001-farm.bats`, 7/7 tests) verified end-to-end.
- **325/325 Docker CLI Options & 14/14 Podman P0 Audit**: 100% option-level parity with Docker and Podman CLI surfaces (`docker_parity_test`, `podman_parity_audit.py`).
- **600+ Rust Unit, Integration & Regression Tests**:
  - **OCI Image References**: Positive canonical specs, custom registries/ports, tags with symbols, sha256 digest pins, and negative/malformed inputs.
  - **Dockerfile & Multi-Stage**: Named stages (`AS builder`), multi-stage artifact extraction (`COPY --from=`), `.dockerignore` negation (`!exception`) and globbing, line continuations, and malformed instruction detection.
  - **Compose Orchestrator**: Multi-service dependency graphs, circular dependency detection (`A -> B -> A`, `A -> B -> C -> A`), and undefined dependency validation.
  - **Volumes & Networking**: Host bind mounts, read-only modes, collision rejection, default `boxr0` bridge deletion protection, IPAM sequence allocation, and invalid port boundary checks.
  - **Security & Cgroups**: Custom Base64 roundtrip fuzzing across all byte lengths, default seccomp critical syscall blocking, cgroups memory unit multipliers, and Unix signal matrix.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for architectural invariants, coding conventions, development setup, and pull request guidelines.

## License

This project is licensed under the [MIT License](LICENSE).
