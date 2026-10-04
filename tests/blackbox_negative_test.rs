#[path = "common/blackbox.rs"]
mod blackbox;

use blackbox::*;

#[test]
fn test_i_missing_image() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    run_boxr_fail(
        &home,
        &[
            "run",
            "--rm",
            "nosuch/image:definitely-missing-xyz",
            "echo",
            "hi",
        ],
    );
}

#[test]
fn test_i_malformed_port() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    run_boxr_fail(&home, &["run", "--rm", "-p", "70000:80", "alpine", "true"]);
}

#[test]
fn test_i_malformed_volume() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    run_boxr_fail(&home, &["run", "--rm", "-v", "a:b:c:d", "alpine", "true"]);
}

#[test]
fn test_i_nonexistent_container_exec() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    run_boxr_fail(&home, &["exec", "bb-nonexistent-container-xyz", "true"]);
}

#[test]
fn test_i_invalid_dns() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    run_boxr_fail(
        &home,
        &["run", "--rm", "--dns", "not_an_ip", "alpine", "true"],
    );
}

#[test]
fn test_i_duplicate_container_name() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let name = format!("bb-dup-name-{}", rand_suffix());
    run_boxr_ok(
        &home,
        &["run", "-d", "--name", &name, "alpine", "sleep", "60"],
    );
    run_boxr_fail(
        &home,
        &["run", "-d", "--name", &name, "alpine", "sleep", "60"],
    );
    cleanup_container(&home, &name);
}

#[test]
fn test_i_compose_cycle_fails() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    let fixture = fixture_path("tests/fixtures/compose/cycle.yml");
    let out = run_boxr(
        &home,
        &["compose", "-f", fixture.to_str().unwrap(), "up", "-d"],
    );
    let _ = run_boxr(
        &home,
        &["compose", "-f", fixture.to_str().unwrap(), "down", "-v"],
    );
    assert!(!out.status.success(), "circular depends_on should fail");
}
