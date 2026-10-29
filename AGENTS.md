# AI Assistant & Contributor Guide for `boxr` 🤖

This guide provides context, architectural invariants, and verification workflows for AI agents (GitHub Copilot, Claude, etc.) and human contributors working on `boxr`.

---

## 1. Architectural Invariants

1. **Pre-Tokio Single-Threaded Trampoline**:
   - The Linux kernel rejects `unshare(CLONE_NEWUSER)` with `EINVAL` if executed from a multi-threaded process.
   - Any unshare operations (`boxr unshare`, `__internal-trampoline`, `__internal-trampoline-exec`) MUST be intercepted in `src/main.rs` before building the Tokio runtime.
2. **Rootless by Default**:
   - Never introduce code requiring `sudo`, setuid binaries, or host daemon permissions.
   - All network and filesystem operations must work within unprivileged user namespaces and rootless TAP virtualization (`usernet` or `pasta`).
3. **SOLID Subsystem Organization**:
   - Avoid monolithic files exceeding 700 lines. Place new domain models in submodules:
     - `src/cli/` (Domain-specific Clap argument structs)
     - `src/daemon/` (Domain-specific REST API route handlers)
     - `src/builder/` (Parser, executor, cache, and dockerignore)
     - `src/network/usernet/` (Packets vs Engine)
4. **Interface Segregation in Storage**:
   - Read-only operations (`ps`, `inspect`, `df`, `stats`) must accept `&impl ContainerReader` or `&impl ImageReader` rather than mutating handles.
5. **Regression Test String Contracts**:
   - `tests/issues_47_to_111_test.rs` performs static string checks (`include_str!`) on key source files (`src/builder/mod.rs`, `src/daemon/mod.rs`, `src/lib.rs`).
   - Retain necessary re-exports and signature strings when refactoring.

---

## 2. Skills & Knowledge Base

When working on this repository, reference:
- **`skill: "boxr"`**: Provides complete knowledge of runtime execution models, macOS `Virtualization.framework` (`boxr-vz`), Linux namespaces, guardrails, and packaging workflows.
- **`docs/ARCHITECTURE.md`**: In-depth architecture breakdown, diagrams, and trait definitions.
- **`docs/ENTERPRISE_RUNTIMES.md`**: Invariants for `/tmp` sticky bit (`1777`), POSIX `/dev/shm`, device node permissions, and zombie reaping.
- **`docs/NETWORKING.md`**: Embedded L2–L4 stack (`usernet`) and `pasta` rootless driver details.

---

## 3. Local Indexing & Fast Symbol Search

For fast symbol navigation across the codebase:
- `.vscode/tags` provides an indexed database of all 800+ struct, enum, trait, and function definitions.
- Search symbols with `grep -F '<SymbolName>' .vscode/tags`.

---

## 4. Verification Workflow

Before proposing or committing changes:
```bash
# 1. Check syntax and compilation
cargo check --all-targets

# 2. Run unit tests
cargo test --lib

# 3. Run full integration & parity suites sequentially
cargo test -- --test-threads=1

# 4. Enterprise black-box QA (compose, volumes, networking, security)
./scripts/run_blackbox_qa.sh -b ./target/release/boxr
# See docs/BLACKBOX_QA.md for section filters and Rust-only runs

# 5. Podman parity (P0 CLI audit + black-box E2E)
./scripts/run_podman_blackbox_e2e.sh ./target/debug/boxr
# Matrix: docs/PODMAN_PARITY.md
```
