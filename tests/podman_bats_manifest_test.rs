//! Vendored Podman BATS catalog: manifest-all.txt must match tests/podman_bats/upstream/*.bats.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn vendored_upstream_manifest_all_matches_bats_files() {
    let upstream = repo_root().join("tests/podman_bats/upstream");
    assert!(
        upstream.join("UPSTREAM.json").is_file(),
        "run scripts/sync_podman_bats_upstream.sh to vendor Podman test/system"
    );

    let mut bats_stems: Vec<String> = fs::read_dir(&upstream)
        .expect("upstream dir")
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.strip_suffix(".bats")
                .filter(|s| *s != "000-TEMPLATE")
                .map(|s| s.to_string())
        })
        .collect();
    bats_stems.sort();

    let manifest = repo_root().join("tests/podman_bats/manifest-all.txt");
    let raw = fs::read_to_string(&manifest).expect("manifest-all.txt");
    let mut manifest_stems: Vec<String> = raw
        .lines()
        .map(|l| l.split('#').next().unwrap_or(l).trim())
        .filter(|l| !l.is_empty())
        .map(|s| s.to_string())
        .collect();
    manifest_stems.sort();

    assert_eq!(
        bats_stems, manifest_stems,
        "manifest-all.txt out of sync with tests/podman_bats/upstream; run scripts/sync_podman_bats_upstream.sh"
    );
    assert_eq!(bats_stems.len(), 77, "expected full upstream catalog size");
}

#[test]
fn curated_manifest_matches_all_upstream_bats_files() {
    let manifest_all = repo_root().join("tests/podman_bats/manifest-all.txt");
    let raw_all = fs::read_to_string(&manifest_all).expect("manifest-all.txt");
    let mut all_stems: Vec<String> = raw_all
        .lines()
        .map(|l| l.split('#').next().unwrap_or(l).trim())
        .filter(|l| !l.is_empty())
        .map(|s| s.to_string())
        .collect();
    all_stems.sort();

    let manifest = repo_root().join("tests/podman_bats/manifest.txt");
    let raw = fs::read_to_string(&manifest).expect("manifest.txt");
    let mut curated_stems: Vec<String> = raw
        .lines()
        .map(|l| l.split('#').next().unwrap_or(l).trim())
        .filter(|l| !l.is_empty())
        .map(|s| s.to_string())
        .collect();
    curated_stems.sort();

    assert_eq!(
        curated_stems, all_stems,
        "manifest.txt must include all 77 upstream BATS patterns"
    );
}

#[test]
fn vendored_upstream_includes_helpers_bash() {
    let helpers = repo_root().join("tests/podman_bats/upstream/helpers.bash");
    assert!(
        helpers.is_file(),
        "helpers.bash missing from vendored upstream"
    );
    let head = fs::read_to_string(&helpers).expect("read helpers");
    assert!(
        head.contains("run_podman"),
        "helpers.bash does not look like Podman test/system helpers"
    );
}
