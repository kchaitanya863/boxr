//! Compose coverage for Docker/Podman replacement workflows: CLI service args,
//! `.env` merging, and `${VAR:-default}` interpolation on real-world YAML shapes.

use boxr::cli::{Cli, Commands, ComposeArgs, ComposeSubcommand};
use boxr::compose::ComposeProject;
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

#[path = "common/blackbox.rs"]
mod blackbox;

fn fixture_stack_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compose/docker-replacement-stack")
}

fn compose_fixture_path() -> PathBuf {
    fixture_stack_dir().join("docker-compose.yml")
}

/// Regression: `compose up [SERVICE...]` must stay on the Clap surface (Docker CLI parity).
#[test]
fn test_compose_up_cli_accepts_service_names_after_flags() {
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--build", "-d", "web"]).unwrap();
    match cli.command {
        Commands::Compose(ComposeArgs {
            command: ComposeSubcommand::Up(up),
            ..
        }) => {
            assert!(up.build);
            assert!(up.detach);
            assert_eq!(up.services, vec!["web".to_string()]);
        }
        _ => panic!("expected compose up"),
    }
}

/// Static contracts so CLI/loader refactors do not drop replacement parity again.
#[test]
fn test_compose_replacement_regression_strings() {
    let cli_rs = include_str!("../src/cli/image.rs");
    assert!(
        cli_rs.contains("pub services: Vec<String>"),
        "ComposeUpArgs must accept trailing service names"
    );
    let compose_mod = include_str!("../src/compose/mod.rs");
    assert!(
        compose_mod.contains("interpolate::interpolate_yaml"),
        "ComposeProject::load must interpolate YAML string scalars"
    );
    let interpolate_rs = include_str!("../src/compose/interpolate.rs");
    assert!(
        interpolate_rs.contains("DefaultUnsetOrEmpty"),
        "compose interpolation must support VAR default modifier"
    );
}

#[test]
fn test_compose_fixture_loads_env_and_interpolates_ports() {
    let path = compose_fixture_path();
    let project = ComposeProject::load(&path).expect("fixture compose should load");

    let db_ports = project.compose.services["db"].ports.as_ref().unwrap();
    assert_eq!(db_ports[0], "15432:5432");

    let api_ports = project.compose.services["api"].ports.as_ref().unwrap();
    assert_eq!(api_ports[0], "18080:8080");

    let web_ports = project.compose.services["web"].ports.as_ref().unwrap();
    assert_eq!(web_ports[0], "13000:80");

    let api_env = project.compose.services["api"].environment.as_ref().unwrap();
    let env_list = api_env.to_vec();
    assert!(env_list.iter().any(|e| e.contains("fixture-api-key")));
}

#[test]
fn test_compose_services_for_up_includes_dependency_chain() {
    let path = compose_fixture_path();
    let project = ComposeProject::load(&path).unwrap();
    let order = project
        .services_for_up(&["web".to_string()], false)
        .unwrap();
    assert_eq!(order, vec!["db", "api", "web"]);
}

#[test]
fn test_compose_copy_fixture_without_dotenv_uses_defaults() {
    let src = fixture_stack_dir();
    let temp = tempdir().unwrap();
    let compose_path = temp.path().join("docker-compose.yml");
    fs::copy(src.join("docker-compose.yml"), &compose_path).unwrap();
    let project = ComposeProject::load(&compose_path).unwrap();
    let ports = project.compose.services["db"].ports.as_ref().unwrap();
    assert_eq!(ports[0], "5432:5432");
}

/// Black-box: `compose up -d web` must parse and run (not fail CLI parsing).
#[test]
fn test_compose_up_single_service_blackbox() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }

    let (_guard, home) = blackbox::isolated_home();
    blackbox::pull_if_needed(&home, "alpine:3.20");
    blackbox::pull_if_needed(&home, "nginx:alpine");
    blackbox::pull_if_needed(&home, "postgres:16-alpine");

    let compose = compose_fixture_path();
    let out = blackbox::run_boxr(
        &home,
        &[
            "compose",
            "-f",
            compose.to_str().unwrap(),
            "up",
            "-d",
            "web",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stderr.contains("unexpected argument"),
        "compose up must accept service name (stderr: {})",
        stderr
    );
    assert!(
        !stdout.contains("unexpected argument"),
        "compose up must accept service name (stdout: {})",
        stdout
    );
    assert!(
        out.status.success(),
        "compose up -d web failed: status={} stderr={} stdout={}",
        out.status,
        stderr,
        stdout
    );

    let ps = blackbox::run_boxr(
        &home,
        &["compose", "-f", compose.to_str().unwrap(), "ps"],
    );
    assert!(ps.status.success());
    let ps_out = String::from_utf8_lossy(&ps.stdout);
    assert!(ps_out.contains("replacement-web"));

    let _ = blackbox::run_boxr(
        &home,
        &["compose", "-f", compose.to_str().unwrap(), "down", "-v"],
    );
}

/// Ensure `boxr compose` subprocess matches what users run as `docker compose`.
#[test]
fn test_compose_fixture_matches_docker_compose_config_when_available() {
    let compose = compose_fixture_path();
    let docker = Command::new("docker")
        .args(["compose", "-f", compose.to_str().unwrap(), "config", "--format", "json"])
        .output();
    if docker.is_err() {
        eprintln!("SKIPPED: docker compose not available for cross-check");
        return;
    }
    let docker = docker.unwrap();
    if !docker.status.success() {
        eprintln!(
            "SKIPPED: docker compose config failed: {}",
            String::from_utf8_lossy(&docker.stderr)
        );
        return;
    }

    let project = ComposeProject::load(&compose).unwrap();
    let web = &project.compose.services["web"];
    let ports = web.ports.as_ref().unwrap();
    assert_eq!(ports[0], "13000:80");

    let docker_stdout = String::from_utf8_lossy(&docker.stdout);
    assert!(
        docker_stdout.contains("13000") && docker_stdout.contains("replacement-web"),
        "boxr and docker compose should agree on interpolated web port/name"
    );
}
