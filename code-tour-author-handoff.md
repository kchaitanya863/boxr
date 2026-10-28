<decision>
Implemented Podman-aligned k8s-file logging in src/logging/mod.rs (CRI multiline records, partial-line tail, since/until/follow, timestamps from entry times) and routed container logs through stream_k8s_container_logs. Detached conmon tees k8s/json logs to ctr.log instead of plain logs.txt.
</decision>
<risk>
035 BATS still fails tests 6, 11, 15, 17 (restart follow, until filter, PODMAN_TIMEOUT follow). logs.txt fallback may still win in edge cases.
</risk>
<verified>
cargo fmt --all; cargo test --lib logging::tests; cargo build; MANIFEST=035-logs ./scripts/run_podman_bats_conformance.sh → 16/19 ok on k8s-relevant cases.
</verified>
