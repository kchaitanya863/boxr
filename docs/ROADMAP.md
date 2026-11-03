# Boxr Product Roadmap 🗺️

This document defines the strategic vision, architectural milestones, and delivery timeline for **`boxr`** as it evolves from high-conformance container runtime into the premier zero-dependency, rootless container platform in Rust.

---

## Strategic Vision

`boxr` is engineered to deliver:
1. **Zero External Dependencies**: Single static binary replacing multi-binary suites (`dockerd` + `containerd` + `runc` or `podman` + `conmon` + `crun` + `netavark`).
2. **Rootless Security by Default**: Unprivileged user namespaces, dropped capabilities, and strict seccomp profiles with zero daemon overhead.
3. **Unmatched Micro-Performance**: Sub-250ms cold container startup, sub-15ms cached Dockerfile builds, and under 15MB memory footprint.
4. **Universal Cross-Platform Ergonomics**: Native Linux kernel namespaces, macOS microVM hypervisor (`boxr-vz`), and Windows native / WSL2 execution.

---

## Roadmap Horizons

```
┌─────────────────────────────────┐   ┌─────────────────────────────────┐   ┌─────────────────────────────────┐
│           HORIZON 1             │   │           HORIZON 2             │   │           HORIZON 3             │
│   Hardening & Developer Speed   │──▶│    Cloud-Native & Edge Scale    │──▶│     Enterprise GA & Security    │
│         v0.2.0 – v0.4.0         │   │         v0.5.0 – v0.7.0         │   │         v0.8.0 – v1.0.0         │
└─────────────────────────────────┘   └─────────────────────────────────┘   └─────────────────────────────────┘
```

---

### Horizon 1: Engine Hardening & Developer Velocity (v0.2.0 – v0.4.0) — [CURRENT]

Focus: Maximize build & execution performance, automate multi-platform CI, and provide native Windows/macOS execution.

- [x] **v0.2.0: Performance & In-Memory Caching Engine**
  - In-memory layer cache registry and fast-path layer referencing (`src/builder/cache.rs`).
  - Sub-15ms cached Dockerfile builds (10.8ms achieved — 33x faster than Podman, 10x faster than Docker).
  - Parallelized rootless UID/GID mapping and pipe-signaled namespace synchronization (startup latency optimized to 187ms on Linux).
- [x] **v0.3.0: Multi-Platform Automated CI Matrix**
  - Continuous automated testing across GitHub-hosted `ubuntu-24.04`, `macos-15` (Apple Silicon), and `windows-latest`.
  - Windows stack size optimization (16MB PE linker & runtime stack) eliminating CLI stack overflow in debug builds.
  - Tracked pre-commit hook (`.githooks/pre-commit`) enforcing zero formatting regressions.
- [x] **v0.4.0: Windows Native WSL2 Machine Engine**
  - `boxr machine init`, `boxr machine start`, `boxr machine stop` lifecycle for Windows.
  - Transparent Linux OCI container routing through local WSL2 backend with path translation (`C:\...` to `/mnt/c/...`).
  - Validated live on real Windows hardware (`ssh legion`).

---

### Horizon 2: Cloud-Native & Edge Scale (v0.5.0 – v0.7.0)

Focus: Enable Kubernetes workloads, WebAssembly integration, and cryptographic supply chain security.

- [ ] **[v0.5.0: Kubernetes CRI (Container Runtime Interface) v1 Endpoint](https://github.com/kchaitanya863/boxr/milestone/4)** — Tracking Issue: **[#494](https://github.com/kchaitanya863/boxr/issues/494)**
  - Implement native gRPC CRI v1 server (`/run/boxr/cri.sock`) implementing `RuntimeService` and `ImageService`.
  - Direct integration with `k3s`, `k0s`, and `kubelet` without requiring `containerd` or `cri-o`.
  - Full compliance with Kubernetes CRI v1 specifications (`k8s.io/cri-api`) validated against `critest`.
  - Low-overhead rootless Kubernetes node execution for edge computing and single-board computers (Raspberry Pi, industrial IoT).
  - *Reference Specifications*: [Kubernetes CRI API Proto](https://github.com/kubernetes/cri-api/blob/master/pkg/apis/runtime/v1/api.proto), [cri-tools critest](https://github.com/kubernetes-sigs/cri-tools), [Tonic async gRPC](https://github.com/hyperium/tonic).

- [ ] **[v0.6.0: WebAssembly (WASI) Native Runtime Integration](https://github.com/kchaitanya863/boxr/milestone/5)** — Tracking Issue: **[#495](https://github.com/kchaitanya863/boxr/issues/495)**
  - Embedded `wasmtime` engine supporting direct invocation of OCI Wasm artifacts (`boxr run --runtime wasm <wasm-image>`).
  - Sub-millisecond cold start (<5ms) and ultra-lightweight memory footprint (<4MB RAM).
  - Hybrid container pods running mixed Linux ELF binaries and Wasm modules on the same shared virtual network.
  - *Reference Specifications*: [OCI Wasm Working Group](https://github.com/opencontainers/artifacts), [Bytecode Alliance Wasmtime](https://github.com/bytecodealliance/wasmtime), [WASI Standard](https://github.com/WebAssembly/WASI).

- [ ] **[v0.7.0: Cryptographic Supply Chain Security (Sigstore & Cosign)](https://github.com/kchaitanya863/boxr/milestone/6)** — Tracking Issue: **[#496](https://github.com/kchaitanya863/boxr/issues/496)**
  - Native verification of OCI signatures, attestations, and Software Bill of Materials (SBOM) using `sigstore-rs`.
  - Enforceable image trust policies (`boxr trust set --require-sigstore --key cosign.pub <repo>`).
  - In-toto provenance attestation and SLSA Level 2/3 provenance generation during `boxr build`.
  - *Reference Specifications*: [Sigstore Documentation](https://docs.sigstore.dev), [Cosign OCI Specification](https://github.com/sigstore/cosign/tree/main/specs), [SLSA Provenance v1.0](https://slsa.dev/spec/v1.0/provenance).

---

### Horizon 3: Enterprise GA & Compliance (v0.8.0 – v1.0.0)

Focus: Production GA release, regulatory cryptographic compliance, enterprise telemetry, and official OS distribution.

- [ ] **[v0.8.0: OpenTelemetry Distributed Tracing & Observability](https://github.com/kchaitanya863/boxr/milestone/7)**
  - Export OTLP metrics and traces for all container lifecycle operations, image pulls, and build steps.
  - Native integration with Prometheus (`/metrics` Prometheus exporter on daemon socket) and Grafana.
  - Real-time cgroups v2 kernel telemetry streaming.
  - *Reference Specifications*: [OpenTelemetry Rust](https://github.com/open-telemetry/opentelemetry-rust), [Prometheus Exporter Format](https://prometheus.io/docs/instrumenting/exposition_formats/).

- [ ] **[v0.9.0: FIPS 140-3 Cryptographic Validation & Enterprise Security Hardening](https://github.com/kchaitanya863/boxr/milestone/8)**
  - FIPS 140-3 compliant cryptographic mode using `aws-lc-rs` or OpenSSL FIPS provider.
  - Automated continuous fuzzing via `cargo-fuzz` and `libFuzzer` targeting OCI manifest parsers, tar layer extractors, and compose YAML engines.
  - Enforced zero-CVE SLA with automated weekly Dependabot and CodeQL scanning.
  - *Reference Specifications*: [NIST FIPS 140-3 Standards](https://csrc.nist.gov/publications/detail/fips/140/3/final), [Rust cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz).

- [ ] **[v1.0.0: General Availability (GA) & Universal Distribution](https://github.com/kchaitanya863/boxr/milestone/9)**
  - Upstream package repository distribution:
    - Debian / Ubuntu official PPA & Debian salsa packaging.
    - Fedora Copr & official RPM packaging.
    - Arch Linux AUR (`boxr-bin`, `boxr`).
    - Alpine Linux Community repository (`apk`).
    - Homebrew Core formula (`brew install boxr`).
    - Microsoft Winget (`winget install boxr`) and Chocolatey (`choco install boxr`).
  - Complete documentation portal with interactive CLI playground and architectural reference manual.
  - Formally declared backwards-compatibility guarantees for CLI surface, compose format, and REST API.

---

## Release Cadence & Governance

- **Patch Releases (`vX.Y.Z`)**: Bi-weekly or as needed for bug fixes, security patches, and minor performance enhancements.
- **Minor Releases (`vX.Y.0`)**: Monthly or milestone-driven feature deliverables according to roadmap horizons.
- **Major Release (`v1.0.0`)**: Milestone marking production enterprise readiness, stable API contracts, and official package availability.
