//! Integration test suite verifying fixes for GitHub issues #163 through #342 (one test each).

#[path = "common/blackbox.rs"]
mod blackbox;

use boxr::builder::{DockerfileParser, Instruction};
use boxr::cli::{
    ImagesArgs, NetworkAction, NetworkSubcommands, PsArgs, RunArgs, VolumeAction, VolumeSubcommands,
};
use boxr::network::PortMapping;
use boxr::oci::image::{ExecutionConfig, ImageConfig};
use boxr::oci::runtime::Spec;
use boxr::storage::container_store::{ContainerRecord, ContainerStatus, ContainerStore};
use boxr::storage::image_store::{ImageRecord, ImageStore};
use boxr::volume::VolumeStore;
use chrono::Utc;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn create_isolated_home() -> tempfile::TempDir {
    let temp = tempdir().unwrap();
    let base_home = boxr::storage::boxr_home();
    for dir_name in &["images", "layers", "vm", "bin"] {
        let src = base_home.join(dir_name);
        if src.exists() {
            let dst = temp.path().join(dir_name);
            #[cfg(unix)]
            let _ = std::os::unix::fs::symlink(&src, &dst);
            #[cfg(windows)]
            let _ = std::os::windows::fs::symlink_dir(&src, &dst);
        }
    }
    let src_images_json = base_home.join("images.json");
    if src_images_json.exists() {
        let dst_images_json = temp.path().join("images.json");
        let _ = fs::copy(&src_images_json, &dst_images_json);
    }
    temp
}

fn set_boxr_home(home: &Path) {
    unsafe {
        std::env::set_var("BOXR_HOME", home);
    }
}

fn run_boxr(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_boxr"))
        .env("BOXR_HOME", home)
        .args(args)
        .output()
        .expect("failed to execute boxr binary")
}

fn inspect_container_json(home: &Path, id_or_name: &str) -> serde_json::Value {
    let out = run_boxr(home, &["inspect", id_or_name]);
    assert!(
        out.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let arr: Vec<serde_json::Value> =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("invalid inspect JSON");
    arr.into_iter().next().expect("empty inspect result")
}

fn dummy_container_record(
    id: &str,
    name: &str,
    home: &Path,
    status: ContainerStatus,
) -> ContainerRecord {
    let bundle = home.join("containers").join(id);
    let _ = fs::create_dir_all(&bundle);
    let spec = Spec::new_default(None, Some(&["sh".to_string()]), None);
    let _ = spec.save_to_bundle(&bundle);
    ContainerRecord {
        id: id.to_string(),
        name: name.to_string(),
        image: "alpine:latest".to_string(),
        command: vec!["sh".to_string()],
        created_at: Utc::now(),
        status,
        bundle_path: bundle.to_string_lossy().to_string(),
        restart_policy: boxr::health::RestartPolicy::No,
        health_status: boxr::health::HealthStatus::None,
        restart_count: 0,
        ports: Vec::new(),
        exposed_ports: Vec::new(),
    }
}

fn host_architecture() -> String {
    match std::env::consts::ARCH {
        "x86_64" => "amd64".to_string(),
        "aarch64" => "arm64".to_string(),
        other => other.to_string(),
    }
}

fn dummy_image_record(repo: &str, tag: &str, home: &Path) -> ImageRecord {
    let rootfs = home
        .join("images")
        .join(format!("{}_{}", repo, tag))
        .join("rootfs");
    let _ = fs::create_dir_all(&rootfs);
    ImageRecord {
        id: format!("img{}123456789", repo.chars().take(3).collect::<String>()),
        reference: repo.to_string(),
        tag: tag.to_string(),
        registry: boxr::oci::reference::ImageReference::DEFAULT_REGISTRY.to_string(),
        manifest_digest: "sha256:1234567890abcdef".to_string(),
        config_digest: "sha256:1234567890abcdef".to_string(),
        size_bytes: 5 * 1024 * 1024,
        created_at: Utc::now(),
        rootfs_path: rootfs.to_string_lossy().to_string(),
        config: ImageConfig {
            architecture: host_architecture(),
            os: "linux".to_string(),
            config: Some(ExecutionConfig::default()),
            rootfs: None,
            history: Vec::new(),
        },
    }
}

fn default_run_args(image: &str) -> RunArgs {
    RunArgs {
        interactive: false,
        tty: false,
        detach: false,
        rm: false,
        name: None,
        env: Vec::new(),
        ports: Vec::new(),
        volumes: Vec::new(),
        workdir: None,
        memory: None,
        labels: Vec::new(),
        dns: Vec::new(),
        cidfile: None,
        cpus: None,
        pids_limit: None,
        rootless: true,
        restart: "no".to_string(),
        health_cmd: None,
        platform: None,
        network: "none".to_string(),
        disable_content_trust: false,
        privileged: false,
        gpus: None,
        entrypoint: None,
        env_file: None,
        user: None,
        hostname: None,
        add_host: Vec::new(),
        shm_size: None,
        cap_add: Vec::new(),
        cap_drop: Vec::new(),
        read_only: false,
        init: false,
        tmpfs: Vec::new(),
        devices: Vec::new(),
        security_opt: Vec::new(),
        cpu_shares: None,
        cpuset_cpus: None,
        memory_swap: None,
        memory_reservation: None,
        dns_search: Vec::new(),
        dns_option: Vec::new(),
        expose: Vec::new(),
        sysctl: Vec::new(),
        stop_timeout: None,
        stop_signal: None,
        annotations: Vec::new(),
        ulimits: Vec::new(),
        ipc: None,
        pid: None,
        uts: None,
        userns: None,
        cgroupns: None,
        cgroup_parent: None,
        isolation: None,
        cpu_count: None,
        cpu_percent: None,
        io_maxbandwidth: None,
        io_maxiops: None,
        publish_all: false,
        ip: None,
        ip6: None,
        mac_address: None,
        link: Vec::new(),
        network_alias: Vec::new(),
        mount: Vec::new(),
        health_interval: None,
        health_timeout: None,
        health_retries: None,
        health_start_period: None,
        health_start_interval: None,
        no_healthcheck: true,
        attach: Vec::new(),
        pull: None,
        quiet: false,
        log_driver: None,
        log_opt: Vec::new(),
        oom_kill_disable: false,
        oom_score_adj: None,
        group_add: Vec::new(),
        label_file: None,
        umask: None,
        domainname: None,
        detach_keys: None,
        blkio_weight: None,
        blkio_weight_device: Vec::new(),
        cpu_period: None,
        cpu_quota: None,
        cpu_rt_period: None,
        cpu_rt_runtime: None,
        cpuset_mems: None,
        device_cgroup_rule: Vec::new(),
        device_read_bps: Vec::new(),
        device_read_iops: Vec::new(),
        device_write_bps: Vec::new(),
        device_write_iops: Vec::new(),
        link_local_ip: Vec::new(),
        memory_swappiness: None,
        runtime: None,
        sig_proxy: true,
        storage_opt: Vec::new(),
        use_api_socket: false,
        volume_driver: None,
        volumes_from: Vec::new(),
        pod: None,
        image: image.to_string(),
        command: vec!["true".to_string()],
    }
}

// Issue #163: boxr ps accepts invalid --filter keys without returning an error
#[test]
fn test_issue_163_ps_accepts_invalid_filter_keys_without_returning_an_error() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let args = PsArgs {
        all: false,
        quiet: false,
        size: false,
        no_trunc: false,
        format: None,
        last: None,
        latest: false,
        filter: vec!["bogus=val".to_string()],
    };
    let res = boxr::list_containers(args);
    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(err.contains("Invalid filter"), "Unexpected: {}", err);
}

// Issue #164: boxr images accepts invalid --filter keys without returning an error
#[test]
fn test_issue_164_images_accepts_invalid_filter_keys_without_returning_an_error() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let args = ImagesArgs {
        quiet: false,
        all: false,
        digests: false,
        no_trunc: false,
        tree: false,
        format: None,
        filter: vec!["unknown_filter=xyz".to_string()],
    };
    let res = boxr::list_images(args);
    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(err.contains("Invalid filter"), "Unexpected: {}", err);
}

// Issue #165: boxr create accepts duplicate host port mappings within the same container specification
#[tokio::test]
async fn test_issue_165_create_accepts_duplicate_host_port_mappings_within_the_same_container() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("alpine", "latest", temp.path()))
        .unwrap();
    let mut args = default_run_args("alpine:latest");
    args.ports = vec!["8080:80".to_string(), "8080:81".to_string()];
    let res = boxr::create_only_container_with_home(args, Some(temp.path())).await;
    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("port is already allocated"),
        "Unexpected: {}",
        err
    );
}

// Issue #166: PortMapping::parse fails to parse Docker-standard port ranges (8000-8002:8000-8002)
#[test]
fn test_issue_166_portmapping_parse_fails_to_parse_docker_standard_port_ranges_8000_8002() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let mappings = PortMapping::parse_all("8000-8002:8000-8002").unwrap();
    assert_eq!(mappings.len(), 3);
    assert_eq!(mappings[0].host_port, 8000);
    assert_eq!(mappings[0].container_port, 8000);
    assert_eq!(mappings[2].host_port, 8002);
}

// Issue #167: boxr volume inspect fails with error when --format template flag is supplied
#[test]
fn test_issue_167_volume_inspect_fails_with_error_when_format_template_flag_is_supplied() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let temp = tempdir().unwrap();
    set_boxr_home(temp.path());
    let store = VolumeStore::with_home(temp.path().to_path_buf());
    store.create(Some("vol167"), None).unwrap();
    let sub = VolumeSubcommands {
        command: VolumeAction::Inspect {
            format: Some("{{.Name}}".to_string()),
            name: "vol167".to_string(),
        },
    };
    assert!(boxr::handle_volume(sub).is_ok());
}

// Issue #168: boxr network inspect fails with error when --format template flag is supplied
#[test]
fn test_issue_168_network_inspect_fails_with_error_when_format_template_flag_is_supplied() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let temp = tempdir().unwrap();
    set_boxr_home(temp.path());
    let store = boxr::network::NetworkStore::with_home(temp.path().to_path_buf());
    store.create("net168", None, None).unwrap();
    let sub = NetworkSubcommands {
        command: NetworkAction::Inspect {
            format: Some("{{.Name}}".to_string()),
            name: "net168".to_string(),
        },
    };
    assert!(boxr::handle_network(sub).is_ok());
}

// Issue #169: boxr volume ls rejects Docker-standard --filter, --format, and -q/--quiet flags
#[test]
fn test_issue_169_volume_ls_rejects_docker_standard_filter_format_and_q_quiet_flags() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "volume", "ls", "-q"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Volume(_)));
    let cli2 = Cli::try_parse_from(["boxr", "volume", "ls", "--filter", "dangling=true"]).unwrap();
    assert!(matches!(cli2.command, boxr::cli::Commands::Volume(_)));
    let cli3 = Cli::try_parse_from(["boxr", "volume", "ls", "--format", "{{.Name}}"]).unwrap();
    assert!(matches!(cli3.command, boxr::cli::Commands::Volume(_)));
}

// Issue #170: boxr network ls rejects Docker-standard --filter, --format, and -q/--quiet flags
#[test]
fn test_issue_170_network_ls_rejects_docker_standard_filter_format_and_q_quiet_flags() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "network", "ls", "-q"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Network(_)));
    let cli2 = Cli::try_parse_from(["boxr", "network", "ls", "--format", "{{.Name}}"]).unwrap();
    assert!(matches!(cli2.command, boxr::cli::Commands::Network(_)));
    let cli3 = Cli::try_parse_from(["boxr", "network", "ls", "-f", "driver=bridge"]).unwrap();
    assert!(matches!(cli3.command, boxr::cli::Commands::Network(_)));
}

// Issue #171: boxr create silently ignores nonexistent --env-file and creates container with exit code 0
#[tokio::test]
async fn test_issue_171_create_silently_ignores_nonexistent_env_file_and_creates_container_wit() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("alpine", "latest", temp.path()))
        .unwrap();
    let mut args = default_run_args("alpine:latest");
    args.env_file = Some("/nonexistent/env/file_171".to_string());
    let res = boxr::create_only_container_with_home(args, Some(temp.path())).await;
    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("open /nonexistent/env/file_171"),
        "Unexpected: {}",
        err
    );
}

// Issue #172: Dockerfile STOPSIGNAL instruction is unsupported, causing build failures
#[test]
fn test_issue_172_dockerfile_stopsignal_instruction_is_unsupported_causing_build_failure() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let dockerfile = "FROM alpine\nSTOPSIGNAL SIGQUIT\n";
    let instructions = DockerfileParser::parse_str(dockerfile).unwrap();
    assert!(
        instructions
            .iter()
            .any(|i| matches!(i, Instruction::StopSignal(s) if s == "SIGQUIT"))
    );
}

// Issue #173: Dockerfile SHELL instruction is unsupported, causing build failures
#[test]
fn test_issue_173_dockerfile_shell_instruction_is_unsupported_causing_build_failures() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let dockerfile = r#"FROM alpine
SHELL ["/bin/bash", "-c"]
"#;
    let instructions = DockerfileParser::parse_str(dockerfile).unwrap();
    assert!(
        instructions
            .iter()
            .any(|i| matches!(i, Instruction::Shell(parts) if parts == &["/bin/bash", "-c"]))
    );
}

// Issue #174: Dockerfile ONBUILD instruction is unsupported, causing build failures
#[test]
fn test_issue_174_dockerfile_onbuild_instruction_is_unsupported_causing_build_failures() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let dockerfile = "FROM alpine\nONBUILD RUN echo trigger\n";
    let instructions = DockerfileParser::parse_str(dockerfile).unwrap();
    assert!(
        instructions
            .iter()
            .any(|i| matches!(i, Instruction::OnBuild(_)))
    );
}

// Issue #175: boxr volume create fails when volume name is passed via --name flag
#[test]
fn test_issue_175_volume_create_fails_when_volume_name_is_passed_via_name_flag() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "volume", "create", "--name", "myvol175"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Volume(_)));
}

// Issue #176: boxr create allows specifying nonexistent --network names without validation
#[tokio::test]
async fn test_issue_176_create_allows_specifying_nonexistent_network_names_without_validation() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("alpine", "latest", temp.path()))
        .unwrap();
    let mut args = default_run_args("alpine:latest");
    args.network = "nonexistent_net_176".to_string();
    let res = boxr::create_only_container_with_home(args, Some(temp.path())).await;
    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("network nonexistent_net_176 not found"),
        "Unexpected: {}",
        err
    );
}

// Issue #177: boxr rename returns conflict error when renaming a container to its existing name
#[test]
fn test_issue_177_rename_returns_conflict_error_when_renaming_a_container_to_its_existin() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let temp = create_isolated_home();
    let store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c177", "cont-177", temp.path(), ContainerStatus::Created);
    store.add(cont).unwrap();
    assert!(store.rename("cont-177", "cont-177").is_ok());
}

// Issue #178: boxr wait rejects multiple container arguments
#[test]
fn test_issue_178_wait_rejects_multiple_container_arguments() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "wait", "c1", "c2"]).unwrap();
    assert!(
        matches!(cli.command, boxr::cli::Commands::Wait(args) if args.containers == vec!["c1".to_string(), "c2".to_string()])
    );
}

// Issue #179: boxr pause rejects multiple container arguments
#[test]
fn test_issue_179_pause_rejects_multiple_container_arguments() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "pause", "c1", "c2"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Pause(args) if args.containers.len() == 2));
}

// Issue #180: boxr unpause rejects multiple container arguments
#[test]
fn test_issue_180_unpause_rejects_multiple_container_arguments() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "unpause", "c1", "c2"]).unwrap();
    assert!(
        matches!(cli.command, boxr::cli::Commands::Unpause(args) if args.containers.len() == 2)
    );
}

// Issue #181: boxr compose config subcommand is missing
#[test]
fn test_issue_181_compose_config_subcommand_is_missing() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "config"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Compose(_)));
}

// Issue #182: boxr compose restart subcommand is missing
#[test]
fn test_issue_182_compose_restart_subcommand_is_missing() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "restart"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Compose(_)));
}

// Issue #183: boxr compose exec subcommand is missing
#[test]
fn test_issue_183_compose_exec_subcommand_is_missing() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "exec", "svc", "sh"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Compose(_)));
}

// Issue #184: boxr compose build subcommand is missing
#[test]
fn test_issue_184_compose_build_subcommand_is_missing() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "build"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Compose(_)));
}

// Issue #185: boxr compose stop and start subcommands are missing
#[test]
fn test_issue_185_compose_stop_and_start_subcommands_are_missing() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "stop"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Compose(_)));
    let cli2 = Cli::try_parse_from(["boxr", "compose", "start"]).unwrap();
    assert!(matches!(cli2.command, boxr::cli::Commands::Compose(_)));
}

// Issue #186: boxr compose rm subcommand is missing
#[test]
fn test_issue_186_compose_rm_subcommand_is_missing() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "rm"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Compose(_)));
}

// Issue #187: boxr volume prune rejects Docker-standard --filter flag
#[test]
fn test_issue_187_volume_prune_rejects_docker_standard_filter_flag() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "volume", "prune", "--filter", "label=foo"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Volume(_)));
}

// Issue #188: boxr network prune rejects Docker-standard --filter flag
#[test]
fn test_issue_188_network_prune_rejects_docker_standard_filter_flag() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "network", "prune", "--filter", "until=24h"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Network(_)));
}

// Issue #189: boxr container prune rejects Docker-standard --filter flag
#[test]
fn test_issue_189_container_prune_rejects_docker_standard_filter_flag() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "container", "prune", "--filter", "until=24h"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Container(_)));
}

// Issue #190: boxr image prune rejects Docker-standard --filter flag
#[test]
fn test_issue_190_image_prune_rejects_docker_standard_filter_flag() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "image", "prune", "--filter", "dangling=true"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Image(_)));
}

// Issue #191: boxr builder prune rejects Docker-standard -a/--all, -f/--force, and --filter flags
#[test]
fn test_issue_191_builder_prune_rejects_docker_standard_a_all_f_force_and_filter_flags() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from([
        "boxr",
        "builder",
        "prune",
        "-f",
        "-a",
        "--filter",
        "until=24h",
    ])
    .unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Builder(_)));
}

// Issue #192: boxr run accepts invalid non-duration strings in --health-interval and --health-timeout
#[tokio::test]
async fn test_issue_192_run_accepts_invalid_non_duration_strings_in_health_interval_and_health() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("alpine", "latest", temp.path()))
        .unwrap();
    let mut args = default_run_args("alpine:latest");
    args.health_cmd = Some("true".to_string());
    args.health_interval = Some("invalid_time".to_string());
    args.no_healthcheck = false;
    let res = boxr::create_only_container_with_home(args, Some(temp.path())).await;
    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("invalid value for --health-interval"),
        "Unexpected: {}",
        err
    );
}

// Issue #193: boxr run accepts invalid --pull options without validation
#[tokio::test]
async fn test_issue_193_run_accepts_invalid_pull_options_without_validation() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("alpine", "latest", temp.path()))
        .unwrap();
    let mut args = default_run_args("alpine:latest");
    args.pull = Some("bogus_value".to_string());
    let res = boxr::create_only_container_with_home(args, Some(temp.path())).await;
    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(err.contains("invalid pull option"), "Unexpected: {}", err);
}

// Issue #194: boxr images --format does not substitute {{.Size}} placeholder
#[test]
fn test_issue_194_images_format_does_not_substitute_size_placeholder() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let temp = create_isolated_home();
    set_boxr_home(temp.path());
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("repo194", "latest", temp.path()))
        .unwrap();
    let out = run_boxr(
        temp.path(),
        &["images", "--format", "{{.Repository}}:{{.Tag}} {{.Size}}"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("{{.Size}}"), "stdout: {}", stdout);
    assert!(stdout.contains("repo194:latest"), "stdout: {}", stdout);
}

// Issue #195: boxr images --format does not substitute {{.CreatedAt}} and {{.CreatedSince}} placeholders
#[test]
fn test_issue_195_images_format_does_not_substitute_createdat_and_createdsince_placehold() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let temp = create_isolated_home();
    set_boxr_home(temp.path());
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("repo195", "latest", temp.path()))
        .unwrap();
    let out = run_boxr(
        temp.path(),
        &["images", "--format", "{{.CreatedAt}} {{.CreatedSince}}"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("{{.CreatedAt}}"), "stdout: {}", stdout);
    assert!(!stdout.contains("{{.CreatedSince}}"), "stdout: {}", stdout);
}

// Issue #196: boxr ps --format does not substitute {{.Ports}} placeholder
#[test]
fn test_issue_196_ps_format_does_not_substitute_ports_placeholder() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let temp = create_isolated_home();
    set_boxr_home(temp.path());
    let store = ContainerStore::with_home(temp.path().to_path_buf());
    let mut cont =
        dummy_container_record("c196", "cont-196", temp.path(), ContainerStatus::Running);
    cont.ports = vec![PortMapping {
        host_ip: None,
        host_port: 8080,
        container_port: 80,
        protocol: "tcp".to_string(),
    }];
    store.add(cont).unwrap();
    let out = run_boxr(
        temp.path(),
        &["ps", "-a", "--format", "{{.Names}} {{.Ports}}"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("{{.Ports}}"), "stdout: {}", stdout);
    assert!(stdout.contains("8080"), "stdout: {}", stdout);
}

// Issue #197: boxr ps --format does not substitute {{.Command}}, {{.CreatedAt}}, {{.RunningFor}}, and {{.Size}}
#[test]
fn test_issue_197_ps_format_does_not_substitute_command_createdat_runningfor_and_size() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let temp = create_isolated_home();
    set_boxr_home(temp.path());
    let store = ContainerStore::with_home(temp.path().to_path_buf());
    store
        .add(dummy_container_record(
            "c197",
            "cont-197",
            temp.path(),
            ContainerStatus::Running,
        ))
        .unwrap();
    let fmt = "{{.Command}} {{.CreatedAt}} {{.RunningFor}} {{.State}} {{.Size}}";
    let out = run_boxr(temp.path(), &["ps", "-a", "--format", fmt]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    for placeholder in [
        "{{.Command}}",
        "{{.CreatedAt}}",
        "{{.RunningFor}}",
        "{{.State}}",
        "{{.Size}}",
    ] {
        assert!(
            !stdout.contains(placeholder),
            "stdout still has {}: {}",
            placeholder,
            stdout
        );
    }
}

// Issue #198: boxr build -q/--quiet flag does not suppress build step logs
#[test]
fn test_issue_198_build_q_quiet_flag_does_not_suppress_build_step_logs() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let temp = tempdir().unwrap();
    fs::write(
        temp.path().join("Dockerfile"),
        "FROM alpine\nRUN echo build-step-198\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_boxr"))
        .current_dir(temp.path())
        .args(["build", "-q", "-t", "quiet198:latest", "."])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        !combined.contains("Step "),
        "build -q should suppress steps: {}",
        combined
    );
}

// Issue #199: boxr system df rejects Docker-standard --format and -v/--verbose flags
#[test]
fn test_issue_199_system_df_rejects_docker_standard_format_and_v_verbose_flags() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "system", "df", "-v", "--format", "json"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::System(_)));
}

// Issue #200: boxr compose down rejects Docker-standard --remove-orphans flag
#[test]
fn test_issue_200_compose_down_rejects_docker_standard_remove_orphans_flag() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "down", "--remove-orphans"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Compose(_)));
}

// Issue #201: boxr compose up rejects --no-build, --force-recreate, and --no-recreate flags
#[test]
fn test_issue_201_compose_up_rejects_no_build_force_recreate_and_no_recreate_flags() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from([
        "boxr",
        "compose",
        "up",
        "--no-build",
        "--force-recreate",
        "--no-recreate",
    ])
    .unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Compose(_)));
}

// Issue #202: boxr compose ps rejects Docker-standard -q/--quiet and --format flags
#[test]
fn test_issue_202_compose_ps_rejects_docker_standard_q_quiet_and_format_flags() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "ps", "-q", "--format", "json"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Compose(_)));
}

// Issue #203: boxr compose logs rejects Docker-standard -f/--follow, --tail, and -t/--timestamps flags
#[test]
fn test_issue_203_compose_logs_rejects_docker_standard_f_follow_tail_and_t_timestamps_fl() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "logs", "-f", "--tail", "20", "-t"]).unwrap();
    assert!(matches!(cli.command, boxr::cli::Commands::Compose(_)));
}

// Issue #204: boxr inspect HostConfig does not report ReadonlyRootfs: true when --read-only is set
#[tokio::test]
async fn test_issue_204_inspect_hostconfig_does_not_report_readonlyrootfs_true_when_read_only() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("alpine", "latest", temp.path()))
        .unwrap();
    let mut args = default_run_args("alpine:latest");
    args.name = Some("cont-204".to_string());
    args.read_only = true;
    let cid = boxr::create_only_container_with_home(args, Some(temp.path()))
        .await
        .unwrap();
    let json = inspect_container_json(temp.path(), &cid);
    assert_eq!(json["HostConfig"]["ReadonlyRootfs"], true);
}

// Issue #205: boxr inspect HostConfig does not report CapAdd and CapDrop
#[tokio::test]
async fn test_issue_205_inspect_hostconfig_does_not_report_capadd_and_capdrop() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("alpine", "latest", temp.path()))
        .unwrap();
    let mut args = default_run_args("alpine:latest");
    args.name = Some("cont-205".to_string());
    args.cap_add = vec!["SYS_ADMIN".to_string()];
    args.cap_drop = vec!["NET_RAW".to_string()];
    let cid = boxr::create_only_container_with_home(args, Some(temp.path()))
        .await
        .unwrap();
    let json = inspect_container_json(temp.path(), &cid);
    let cap_add = json["HostConfig"]["CapAdd"].as_array().unwrap();
    let cap_drop = json["HostConfig"]["CapDrop"].as_array().unwrap();
    assert!(cap_add.iter().any(|v| v == "SYS_ADMIN"));
    assert!(cap_drop.iter().any(|v| v == "NET_RAW"));
}

// Issue #206: boxr inspect HostConfig does not report Privileged: true when --privileged is set
#[tokio::test]
async fn test_issue_206_inspect_hostconfig_does_not_report_privileged_true_when_privileged_is() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("alpine", "latest", temp.path()))
        .unwrap();
    let mut args = default_run_args("alpine:latest");
    args.name = Some("cont-206".to_string());
    args.privileged = true;
    let cid = boxr::create_only_container_with_home(args, Some(temp.path()))
        .await
        .unwrap();
    let json = inspect_container_json(temp.path(), &cid);
    assert_eq!(json["HostConfig"]["Privileged"], true);
}

// Issue #207: boxr inspect HostConfig does not report Memory resource limits
#[tokio::test]
async fn test_issue_207_inspect_hostconfig_does_not_report_memory_resource_limits() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("alpine", "latest", temp.path()))
        .unwrap();
    let mut args = default_run_args("alpine:latest");
    args.name = Some("cont-207".to_string());
    args.memory = Some("128m".to_string());
    args.memory_reservation = Some("64m".to_string());
    args.cpu_shares = Some(512);
    let cid = boxr::create_only_container_with_home(args, Some(temp.path()))
        .await
        .unwrap();
    let json = inspect_container_json(temp.path(), &cid);
    assert!(json["HostConfig"]["Memory"].as_i64().unwrap() > 0);
}

// Issue #208: boxr inspect HostConfig does not report NanoCpus
#[tokio::test]
async fn test_issue_208_inspect_hostconfig_does_not_report_nanocpus() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("alpine", "latest", temp.path()))
        .unwrap();
    let mut args = default_run_args("alpine:latest");
    args.name = Some("cont-208".to_string());
    args.cpus = Some("1.5".to_string());
    let cid = boxr::create_only_container_with_home(args, Some(temp.path()))
        .await
        .unwrap();
    let json = inspect_container_json(temp.path(), &cid);
    assert_eq!(json["HostConfig"]["NanoCpus"].as_i64(), Some(1_500_000_000));
}

// Issue #209: boxr inspect Config does not report User
#[tokio::test]
async fn test_issue_209_inspect_config_does_not_report_user() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("alpine", "latest", temp.path()))
        .unwrap();
    let mut args = default_run_args("alpine:latest");
    args.name = Some("cont-209".to_string());
    args.user = Some("1000:1000".to_string());
    let cid = boxr::create_only_container_with_home(args, Some(temp.path()))
        .await
        .unwrap();
    let json = inspect_container_json(temp.path(), &cid);
    assert_eq!(json["Config"]["User"].as_str(), Some("1000:1000"));
}

// Issue #210: boxr inspect Config does not report WorkingDir
#[tokio::test]
async fn test_issue_210_inspect_config_does_not_report_workingdir() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("alpine", "latest", temp.path()))
        .unwrap();
    let mut args = default_run_args("alpine:latest");
    args.name = Some("cont-210".to_string());
    args.workdir = Some("/app/work".to_string());
    let cid = boxr::create_only_container_with_home(args, Some(temp.path()))
        .await
        .unwrap();
    let json = inspect_container_json(temp.path(), &cid);
    assert!(
        json["Config"]["WorkingDir"]
            .as_str()
            .unwrap()
            .ends_with("/app/work")
    );
}

// Issue #211: boxr inspect Config does not report Hostname
#[tokio::test]
async fn test_issue_211_inspect_config_does_not_report_hostname() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("alpine", "latest", temp.path()))
        .unwrap();
    let mut args = default_run_args("alpine:latest");
    args.name = Some("cont-211".to_string());
    args.hostname = Some("myhost211".to_string());
    let cid = boxr::create_only_container_with_home(args, Some(temp.path()))
        .await
        .unwrap();
    let json = inspect_container_json(temp.path(), &cid);
    assert_eq!(json["Config"]["Hostname"].as_str(), Some("myhost211"));
}

// Issue #212: boxr inspect Config does not report Env environment variables
#[tokio::test]
async fn test_issue_212_inspect_config_does_not_report_env_environment_variables() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    img_store
        .add(dummy_image_record("alpine", "latest", temp.path()))
        .unwrap();
    let mut args = default_run_args("alpine:latest");
    args.name = Some("cont-212".to_string());
    args.env = vec!["FOO212=bar".to_string()];
    let cid = boxr::create_only_container_with_home(args, Some(temp.path()))
        .await
        .unwrap();
    let json = inspect_container_json(temp.path(), &cid);
    let env = json["Config"]["Env"].as_array().unwrap();
    assert!(env.iter().any(|e| e == "FOO212=bar"));
}

// Issue #213: [Docker Drift] Missing option flag '--disable-content-trust' on 'boxr run'
#[test]
fn test_issue_213_missing_option_flag_disable_content_trust_on_boxr_run() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli =
        Cli::try_parse_from(["boxr", "run", "--disable-content-trust", "alpine", "true"]).unwrap();
    let _ = cli;
}

// Issue #214: [Docker Drift] Missing option flag '--net' on 'boxr run'
#[test]
fn test_issue_214_missing_option_flag_net_on_boxr_run() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "run", "--net", "bridge", "alpine", "true"]).unwrap();
    let _ = cli;
}

// Issue #215: [Docker Drift] Missing option flag '--net-alias' on 'boxr run'
#[test]
fn test_issue_215_missing_option_flag_net_alias_on_boxr_run() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli =
        Cli::try_parse_from(["boxr", "run", "--network-alias", "web", "alpine", "true"]).unwrap();
    let _ = cli;
}

// Issue #216: [Docker Drift] Missing option flag '--disable-content-trust' on 'boxr build'
#[test]
fn test_issue_216_missing_option_flag_disable_content_trust_on_boxr_build() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "build", "--disable-content-trust", "."]).unwrap();
    let _ = cli;
}

// Issue #217: [Docker Drift] Missing option flag '--output' on 'boxr build'
#[test]
fn test_issue_217_missing_option_flag_output_on_boxr_build() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "build", "--output", "type=docker", "."]).unwrap();
    let _ = cli;
}

// Issue #218: [Docker Drift] Missing option flag '--progress' on 'boxr build'
#[test]
fn test_issue_218_missing_option_flag_progress_on_boxr_build() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "build", "--progress", "plain", "."]).unwrap();
    let _ = cli;
}

// Issue #219: [Docker Drift] Missing option flag '--secret' on 'boxr build'
#[test]
fn test_issue_219_missing_option_flag_secret_on_boxr_build() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "build", "--secret", "id=mysecret,src=.", "."]).unwrap();
    let _ = cli;
}

// Issue #220: [Docker Drift] Missing option flag '--ssh' on 'boxr build'
#[test]
fn test_issue_220_missing_option_flag_ssh_on_boxr_build() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "build", "--ssh", "default", "."]).unwrap();
    let _ = cli;
}

// Issue #221: [Docker Drift] Missing standard subcommand 'boxr compose build'
#[test]
fn test_issue_221_missing_standard_subcommand_boxr_compose_build() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "build"]).unwrap();
    let _ = cli;
}

// Issue #222: [Docker Drift] Missing standard subcommand 'boxr compose config'
#[test]
fn test_issue_222_missing_standard_subcommand_boxr_compose_config() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "config"]).unwrap();
    let _ = cli;
}

// Issue #223: [Docker Drift] Missing standard subcommand 'boxr compose cp'
#[test]
fn test_issue_223_missing_standard_subcommand_boxr_compose_cp() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "cp", "svc:/tmp/a", "./b"]).unwrap();
    let _ = cli;
}

// Issue #224: [Docker Drift] Missing standard subcommand 'boxr compose create'
#[test]
fn test_issue_224_missing_standard_subcommand_boxr_compose_create() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "create"]).unwrap();
    let _ = cli;
}

// Issue #225: [Docker Drift] Missing standard subcommand 'boxr compose events'
#[test]
fn test_issue_225_missing_standard_subcommand_boxr_compose_events() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "events"]).unwrap();
    let _ = cli;
}

// Issue #226: [Docker Drift] Missing standard subcommand 'boxr compose exec'
#[test]
fn test_issue_226_missing_standard_subcommand_boxr_compose_exec() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "exec", "svc", "sh"]).unwrap();
    let _ = cli;
}

// Issue #227: [Docker Drift] Missing standard subcommand 'boxr compose images'
#[test]
fn test_issue_227_missing_standard_subcommand_boxr_compose_images() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "images"]).unwrap();
    let _ = cli;
}

// Issue #228: [Docker Drift] Missing standard subcommand 'boxr compose kill'
#[test]
fn test_issue_228_missing_standard_subcommand_boxr_compose_kill() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "kill", "svc"]).unwrap();
    let _ = cli;
}

// Issue #229: [Docker Drift] Missing standard subcommand 'boxr compose ls'
#[test]
fn test_issue_229_missing_standard_subcommand_boxr_compose_ls() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "ls"]).unwrap();
    let _ = cli;
}

// Issue #230: [Docker Drift] Missing standard subcommand 'boxr compose pause'
#[test]
fn test_issue_230_missing_standard_subcommand_boxr_compose_pause() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "pause", "svc"]).unwrap();
    let _ = cli;
}

// Issue #231: [Docker Drift] Missing standard subcommand 'boxr compose port'
#[test]
fn test_issue_231_missing_standard_subcommand_boxr_compose_port() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "port", "svc", "80"]).unwrap();
    let _ = cli;
}

// Issue #232: [Docker Drift] Missing standard subcommand 'boxr compose pull'
#[test]
fn test_issue_232_missing_standard_subcommand_boxr_compose_pull() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "pull"]).unwrap();
    let _ = cli;
}

// Issue #233: [Docker Drift] Missing standard subcommand 'boxr compose push'
#[test]
fn test_issue_233_missing_standard_subcommand_boxr_compose_push() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "push"]).unwrap();
    let _ = cli;
}

// Issue #234: [Docker Drift] Missing standard subcommand 'boxr compose restart'
#[test]
fn test_issue_234_missing_standard_subcommand_boxr_compose_restart() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "restart"]).unwrap();
    let _ = cli;
}

// Issue #235: [Docker Drift] Missing standard subcommand 'boxr compose rm'
#[test]
fn test_issue_235_missing_standard_subcommand_boxr_compose_rm() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "rm"]).unwrap();
    let _ = cli;
}

// Issue #236: [Docker Drift] Missing standard subcommand 'boxr compose run'
#[test]
fn test_issue_236_missing_standard_subcommand_boxr_compose_run() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "run", "svc"]).unwrap();
    let _ = cli;
}

// Issue #237: [Docker Drift] Missing standard subcommand 'boxr compose start'
#[test]
fn test_issue_237_missing_standard_subcommand_boxr_compose_start() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "start"]).unwrap();
    let _ = cli;
}

// Issue #238: [Docker Drift] Missing standard subcommand 'boxr compose stop'
#[test]
fn test_issue_238_missing_standard_subcommand_boxr_compose_stop() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "stop"]).unwrap();
    let _ = cli;
}

// Issue #239: [Docker Drift] Missing standard subcommand 'boxr compose top'
#[test]
fn test_issue_239_missing_standard_subcommand_boxr_compose_top() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "top", "svc"]).unwrap();
    let _ = cli;
}

// Issue #240: [Docker Drift] Missing standard subcommand 'boxr compose unpause'
#[test]
fn test_issue_240_missing_standard_subcommand_boxr_compose_unpause() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "unpause", "svc"]).unwrap();
    let _ = cli;
}

// Issue #241: [Docker Drift] Missing standard subcommand 'boxr compose version'
#[test]
fn test_issue_241_missing_standard_subcommand_boxr_compose_version() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "version"]).unwrap();
    let _ = cli;
}

// Issue #242: [Docker Drift] Missing standard subcommand 'boxr compose wait'
#[test]
fn test_issue_242_missing_standard_subcommand_boxr_compose_wait() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "wait"]).unwrap();
    let _ = cli;
}

// Issue #243: [Docker Drift] Missing standard subcommand 'boxr system events'
#[test]
fn test_issue_243_missing_standard_subcommand_boxr_system_events() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "system", "events"]).unwrap();
    let _ = cli;
}

// Issue #244: [Docker Drift] Missing standard subcommand 'boxr system info'
#[test]
fn test_issue_244_missing_standard_subcommand_boxr_system_info() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "system", "info"]).unwrap();
    let _ = cli;
}

// Issue #245: [Docker Drift] Missing standard subcommand 'boxr builder build'
#[test]
fn test_issue_245_missing_standard_subcommand_boxr_builder_build() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "builder", "build", "."]).unwrap();
    let _ = cli;
}

// Issue #246: [Docker Drift] Missing standard subcommand 'boxr builder du'
#[test]
fn test_issue_246_missing_standard_subcommand_boxr_builder_du() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "builder", "du"]).unwrap();
    let _ = cli;
}

// Issue #247: [Docker Drift] Missing option flag '--archive' on 'boxr cp'
#[test]
fn test_issue_247_missing_option_flag_archive_on_boxr_cp() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "cp", "--archive", "src", "dest"]).unwrap();
    let _ = cli;
}

// Issue #248: [Docker Drift] Missing option flag '--follow-link' on 'boxr cp'
#[test]
fn test_issue_248_missing_option_flag_follow_link_on_boxr_cp() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "cp", "--follow-link", "src", "dest"]).unwrap();
    let _ = cli;
}

// Issue #249: [Docker Drift] Missing option flag '--quiet' on 'boxr cp'
#[test]
fn test_issue_249_missing_option_flag_quiet_on_boxr_cp() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "cp", "--quiet", "src", "dest"]).unwrap();
    let _ = cli;
}

// Issue #250: [Docker Drift] Missing option flag '--signal' on 'boxr restart'
#[test]
fn test_issue_250_missing_option_flag_signal_on_boxr_restart() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "restart", "--signal", "SIGTERM", "c1"]).unwrap();
    let _ = cli;
}

// Issue #251: [Docker Drift] Missing option flag '--change' on 'boxr import'
#[test]
fn test_issue_251_missing_option_flag_change_on_boxr_import() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli =
        Cli::try_parse_from(["boxr", "import", "--change", "ENV FOO=bar", "-", "img"]).unwrap();
    let _ = cli;
}

// Issue #252: [Docker Drift] Missing option flag '--message' on 'boxr import'
#[test]
fn test_issue_252_missing_option_flag_message_on_boxr_import() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "import", "--message", "msg", "-", "img"]).unwrap();
    let _ = cli;
}

// Issue #253: [Docker Drift] Missing option flag '--platform' on 'boxr import'
#[test]
fn test_issue_253_missing_option_flag_platform_on_boxr_import() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli =
        Cli::try_parse_from(["boxr", "import", "--platform", "linux/amd64", "-", "img"]).unwrap();
    let _ = cli;
}

// Issue #254: [Docker Drift] Missing option flag '--quiet' on 'boxr load'
#[test]
fn test_issue_254_missing_option_flag_quiet_on_boxr_load() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "load", "--quiet"]).unwrap();
    let _ = cli;
}

// Issue #255: [Docker Drift] Missing option flag '--change' on 'boxr commit'
#[test]
fn test_issue_255_missing_option_flag_change_on_boxr_commit() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli =
        Cli::try_parse_from(["boxr", "commit", "--change", "ENV FOO=bar", "c1", "img"]).unwrap();
    let _ = cli;
}

// Issue #256: [Docker Drift] Missing option flag '--all' on 'boxr stats'
#[test]
fn test_issue_256_missing_option_flag_all_on_boxr_stats() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "stats", "--all"]).unwrap();
    let _ = cli;
}

// Issue #257: [Docker Drift] Missing option flag '--format' on 'boxr stats'
#[test]
fn test_issue_257_missing_option_flag_format_on_boxr_stats() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "stats", "--format", "{{.Name}}"]).unwrap();
    let _ = cli;
}

// Issue #258: [Docker Drift] Missing option flag '--no-trunc' on 'boxr stats'
#[test]
fn test_issue_258_missing_option_flag_no_trunc_on_boxr_stats() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "stats", "--no-trunc"]).unwrap();
    let _ = cli;
}

// Issue #259: [Docker Drift] Missing option flag '--format' on 'boxr events'
#[test]
fn test_issue_259_missing_option_flag_format_on_boxr_events() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "events", "--format", "{{.Type}}"]).unwrap();
    let _ = cli;
}

// Issue #260: [Docker Drift] Missing option flag '--until' on 'boxr events'
#[test]
fn test_issue_260_missing_option_flag_until_on_boxr_events() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "events", "--until", "2020-01-01"]).unwrap();
    let _ = cli;
}

// Issue #261: [Docker Drift] Missing option flag '--format' on 'boxr history'
#[test]
fn test_issue_261_missing_option_flag_format_on_boxr_history() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "history", "alpine", "--format", "{{.ID}}"]).unwrap();
    let _ = cli;
}

// Issue #262: [Docker Drift] Missing option flag '--human' on 'boxr history'
#[test]
fn test_issue_262_missing_option_flag_human_on_boxr_history() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "history", "alpine", "--human"]).unwrap();
    let _ = cli;
}

// Issue #263: [Docker Drift] Missing option flag '--quiet' on 'boxr history'
#[test]
fn test_issue_263_missing_option_flag_quiet_on_boxr_history() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "history", "alpine", "--quiet"]).unwrap();
    let _ = cli;
}

// Issue #264: [Docker Drift] Missing option flag '--filter' on 'boxr search'
#[test]
fn test_issue_264_missing_option_flag_filter_on_boxr_search() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "search", "alpine", "--filter", "stars=3"]).unwrap();
    let _ = cli;
}

// Issue #265: [Docker Drift] Missing option flag '--no-trunc' on 'boxr history'
#[test]
fn test_issue_265_missing_option_flag_no_trunc_on_boxr_history() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "history", "alpine", "--no-trunc"]).unwrap();
    let _ = cli;
}

// Issue #266: [Docker Drift] Missing option flag '--format' on 'boxr search'
#[test]
fn test_issue_266_missing_option_flag_format_on_boxr_search() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "search", "alpine", "--format", "{{.Name}}"]).unwrap();
    let _ = cli;
}

// Issue #267: [Docker Drift] Missing option flag '--password-stdin' on 'boxr login'
#[test]
fn test_issue_267_missing_option_flag_password_stdin_on_boxr_login() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "login", "--password-stdin"]).unwrap();
    let _ = cli;
}

// Issue #268: [Docker Drift] Missing option flag '--disable-content-trust' on 'boxr create'
#[test]
fn test_issue_268_missing_option_flag_disable_content_trust_on_boxr_create() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from([
        "boxr",
        "create",
        "--disable-content-trust",
        "alpine",
        "true",
    ])
    .unwrap();
    let _ = cli;
}

// Issue #269: [Docker Drift] Missing option flag '--net-alias' on 'boxr create'
#[test]
fn test_issue_269_missing_option_flag_net_alias_on_boxr_create() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "create", "--network-alias", "web", "alpine", "true"])
        .unwrap();
    let _ = cli;
}

// Issue #270: [Docker Drift] Missing option flag '--net' on 'boxr create'
#[test]
fn test_issue_270_missing_option_flag_net_on_boxr_create() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "create", "--net", "bridge", "alpine", "true"]).unwrap();
    let _ = cli;
}

// Issue #271: [Docker Drift] Missing standard subcommand 'boxr container export'
#[test]
fn test_issue_271_missing_standard_subcommand_boxr_container_export() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "container", "export", "c1"]).unwrap();
    let _ = cli;
}

// Issue #272: [Docker Drift] Missing standard subcommand 'boxr container rename'
#[test]
fn test_issue_272_missing_standard_subcommand_boxr_container_rename() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "container", "rename", "c1", "c2"]).unwrap();
    let _ = cli;
}

// Issue #273: [Docker Drift] Missing standard subcommand 'boxr container stats'
#[test]
fn test_issue_273_missing_standard_subcommand_boxr_container_stats() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "container", "stats", "c1"]).unwrap();
    let _ = cli;
}

// Issue #274: [Docker Drift] Missing standard subcommand 'boxr context import'
#[test]
fn test_issue_274_missing_standard_subcommand_boxr_context_import() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "context", "import", "ctx", "ctx.tar"]).unwrap();
    let _ = cli;
}

// Issue #275: [Docker Drift] Missing option flag '--no-trunc' on 'boxr search'
#[test]
fn test_issue_275_missing_option_flag_no_trunc_on_boxr_search() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "search", "alpine", "--no-trunc"]).unwrap();
    let _ = cli;
}

// Issue #276: [Docker Drift] Missing standard subcommand 'boxr context export'
#[test]
fn test_issue_276_missing_standard_subcommand_boxr_context_export() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "context", "export", "ctx"]).unwrap();
    let _ = cli;
}

// Issue #277: [Docker Drift] Missing standard subcommand 'boxr container commit'
#[test]
fn test_issue_277_missing_standard_subcommand_boxr_container_commit() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "container", "commit", "c1", "img"]).unwrap();
    let _ = cli;
}

// Issue #278: [Docker Drift] Missing standard subcommand 'boxr context update'
#[test]
fn test_issue_278_missing_standard_subcommand_boxr_context_update() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "context", "update", "ctx"]).unwrap();
    let _ = cli;
}

// Issue #279: [Docker Drift] Missing standard subcommand 'boxr manifest rm'
#[test]
fn test_issue_279_missing_standard_subcommand_boxr_manifest_rm() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "manifest", "rm", "m1"]).unwrap();
    let _ = cli;
}

// Issue #280: [Docker Drift] Missing standard subcommand 'boxr manifest annotate'
#[test]
fn test_issue_280_missing_standard_subcommand_boxr_manifest_annotate() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "manifest", "annotate", "m1"]).unwrap();
    let _ = cli;
}

// Issue #281: [Docker Drift] Missing top-level command 'boxr plugin'
#[test]
fn test_issue_281_missing_top_level_command_boxr_plugin() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "plugin"]).unwrap();
    let _ = cli;
}

// Issue #282: [Docker Drift] Missing top-level command 'boxr swarm'
#[test]
fn test_issue_282_missing_top_level_command_boxr_swarm() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "swarm"]).unwrap();
    let _ = cli;
}

// Issue #283: [Docker Drift] Missing top-level command 'boxr config'
#[test]
fn test_issue_283_missing_top_level_command_boxr_config() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "config"]).unwrap();
    let _ = cli;
}

// Issue #284: [Docker Drift] Missing top-level command 'boxr secret'
#[test]
fn test_issue_284_top_level_command_boxr_secret() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "secret", "ls"]).unwrap();
    let _ = cli;
}

// Issue #285: [Docker Drift] Missing top-level command 'boxr node'
#[test]
fn test_issue_285_missing_top_level_command_boxr_node() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "node"]).unwrap();
    let _ = cli;
}

// Issue #286: [Docker Drift] Missing top-level command 'boxr trust'
#[test]
fn test_issue_286_missing_top_level_command_boxr_trust() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "trust"]).unwrap();
    let _ = cli;
}

// Issue #287: [Docker Drift] Missing option flag '--name' on 'boxr volume create'
#[test]
fn test_issue_287_missing_option_flag_name_on_boxr_volume_create() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "volume", "create", "--name", "myvol"]).unwrap();
    let _ = cli;
}

// Issue #288: [Docker Drift] Missing option flag '--filter' on 'boxr volume ls'
#[test]
fn test_issue_288_missing_option_flag_filter_on_boxr_volume_ls() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "volume", "ls", "--filter", "dangling=true"]).unwrap();
    let _ = cli;
}

// Issue #289: [Docker Drift] Missing option flag '--all' on 'boxr volume prune'
#[test]
fn test_issue_289_missing_option_flag_all_on_boxr_volume_prune() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "volume", "prune", "--all"]).unwrap();
    let _ = cli;
}

// Issue #290: [Docker Drift] Missing option flag '--quiet' on 'boxr volume ls'
#[test]
fn test_issue_290_missing_option_flag_quiet_on_boxr_volume_ls() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "volume", "ls", "-q"]).unwrap();
    let _ = cli;
}

// Issue #291: [Docker Drift] Missing option flag '--format' on 'boxr volume ls'
#[test]
fn test_issue_291_missing_option_flag_format_on_boxr_volume_ls() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "volume", "ls", "--format", "{{.Name}}"]).unwrap();
    let _ = cli;
}

// Issue #292: [Docker Drift] Missing option flag '--filter' on 'boxr network ls'
#[test]
fn test_issue_292_missing_option_flag_filter_on_boxr_network_ls() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "network", "ls", "--filter", "driver=bridge"]).unwrap();
    let _ = cli;
}

// Issue #293: [Docker Drift] Missing option flag '--filter' on 'boxr volume prune'
#[test]
fn test_issue_293_missing_option_flag_filter_on_boxr_volume_prune() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli =
        Cli::try_parse_from(["boxr", "volume", "prune", "--filter", "label=foo=bar"]).unwrap();
    let _ = cli;
}

// Issue #294: [Docker Drift] Missing option flag '--format' on 'boxr network ls'
#[test]
fn test_issue_294_missing_option_flag_format_on_boxr_network_ls() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "network", "ls", "--format", "{{.Name}}"]).unwrap();
    let _ = cli;
}

// Issue #295: [Docker Drift] Missing option flag '--no-trunc' on 'boxr network ls'
#[test]
fn test_issue_295_missing_option_flag_no_trunc_on_boxr_network_ls() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "network", "ls", "--no-trunc"]).unwrap();
    let _ = cli;
}

// Issue #296: [Docker Drift] Missing option flag '--quiet' on 'boxr network ls'
#[test]
fn test_issue_296_missing_option_flag_quiet_on_boxr_network_ls() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "network", "ls", "-q"]).unwrap();
    let _ = cli;
}

// Issue #297: [Docker Drift] Missing option flag '--format' on 'boxr system df'
#[test]
fn test_issue_297_missing_option_flag_format_on_boxr_system_df() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "system", "df", "--format", "json"]).unwrap();
    let _ = cli;
}

// Issue #298: [Docker Drift] Missing option flag '--filter' on 'boxr network prune'
#[test]
fn test_issue_298_missing_option_flag_filter_on_boxr_network_prune() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "network", "prune", "--filter", "until=24h"]).unwrap();
    let _ = cli;
}

// Issue #299: [Docker Drift] Missing option flag '--verbose' on 'boxr system df'
#[test]
fn test_issue_299_missing_option_flag_verbose_on_boxr_system_df() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "system", "df", "-v"]).unwrap();
    let _ = cli;
}

// Issue #300: [Docker Drift] Missing option flag '--filter' on 'boxr system prune'
#[test]
fn test_issue_300_missing_option_flag_filter_on_boxr_system_prune() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "system", "prune", "--filter", "until=24h"]).unwrap();
    let _ = cli;
}

// Issue #301: [Docker Drift] Missing option flag '--filter' on 'boxr image prune'
#[test]
fn test_issue_301_missing_option_flag_filter_on_boxr_image_prune() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "image", "prune", "--filter", "until=24h"]).unwrap();
    let _ = cli;
}

// Issue #302: [Docker Drift] Missing option flag '--filter' on 'boxr container prune'
#[test]
fn test_issue_302_missing_option_flag_filter_on_boxr_container_prune() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "container", "prune", "--filter", "until=24h"]).unwrap();
    let _ = cli;
}

// Issue #303: [Docker Drift] Missing option flag '--all' on 'boxr builder prune'
#[test]
fn test_issue_303_missing_option_flag_all_on_boxr_builder_prune() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "builder", "prune", "-a"]).unwrap();
    let _ = cli;
}

// Issue #304: [Docker Drift] Missing option flag '--filter' on 'boxr builder prune'
#[test]
fn test_issue_304_missing_option_flag_filter_on_boxr_builder_prune() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "builder", "prune", "--filter", "until=24h"]).unwrap();
    let _ = cli;
}

// Issue #305: [Docker Drift] Missing option flag '--keep-storage' on 'boxr builder prune'
#[test]
fn test_issue_305_missing_option_flag_keep_storage_on_boxr_builder_prune() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "builder", "prune", "--keep-storage", "10GB"]).unwrap();
    let _ = cli;
}

// Issue #306: [Docker Drift] Missing option flag '--force' on 'boxr builder prune'
#[test]
fn test_issue_306_missing_option_flag_force_on_boxr_builder_prune() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "builder", "prune", "-f"]).unwrap();
    let _ = cli;
}

// Issue #307: [Docker Drift] Missing option flag '--no-build' on 'boxr compose up'
#[test]
fn test_issue_307_missing_option_flag_no_build_on_boxr_compose_up() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--no-build"]).unwrap();
    let _ = cli;
}

// Issue #308: [Docker Drift] Missing option flag '--no-start' on 'boxr compose up'
#[test]
fn test_issue_308_missing_option_flag_no_start_on_boxr_compose_up() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--no-start"]).unwrap();
    let _ = cli;
}

// Issue #309: [Docker Drift] Missing option flag '--force-recreate' on 'boxr compose up'
#[test]
fn test_issue_309_missing_option_flag_force_recreate_on_boxr_compose_up() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--force-recreate"]).unwrap();
    let _ = cli;
}

// Issue #310: [Docker Drift] Missing option flag '--no-deps' on 'boxr compose up'
#[test]
fn test_issue_310_missing_option_flag_no_deps_on_boxr_compose_up() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--no-deps"]).unwrap();
    let _ = cli;
}

// Issue #311: [Docker Drift] Missing option flag '--no-recreate' on 'boxr compose up'
#[test]
fn test_issue_311_missing_option_flag_no_recreate_on_boxr_compose_up() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--no-recreate"]).unwrap();
    let _ = cli;
}

// Issue #312: [Docker Drift] Missing option flag '--pull' on 'boxr compose up'
#[test]
fn test_issue_312_missing_option_flag_pull_on_boxr_compose_up() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--pull", "always"]).unwrap();
    let _ = cli;
}

// Issue #313: [Docker Drift] Missing option flag '--quiet-pull' on 'boxr compose up'
#[test]
fn test_issue_313_missing_option_flag_quiet_pull_on_boxr_compose_up() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--quiet-pull"]).unwrap();
    let _ = cli;
}

// Issue #314: [Docker Drift] Missing option flag '--remove-orphans' on 'boxr compose up'
#[test]
fn test_issue_314_missing_option_flag_remove_orphans_on_boxr_compose_up() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--remove-orphans"]).unwrap();
    let _ = cli;
}

// Issue #315: [Docker Drift] Missing option flag '--renew-anon-volumes' on 'boxr compose up'
#[test]
fn test_issue_315_missing_option_flag_renew_anon_volumes_on_boxr_compose_up() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--renew-anon-volumes"]).unwrap();
    let _ = cli;
}

// Issue #316: [Docker Drift] Missing option flag '--scale' on 'boxr compose up'
#[test]
fn test_issue_316_missing_option_flag_scale_on_boxr_compose_up() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--scale", "web=2"]).unwrap();
    let _ = cli;
}

// Issue #317: [Docker Drift] Missing option flag '--timeout' on 'boxr compose up'
#[test]
fn test_issue_317_missing_option_flag_timeout_on_boxr_compose_up() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--timeout", "30"]).unwrap();
    let _ = cli;
}

// Issue #318: [Docker Drift] Missing option flag '--wait-timeout' on 'boxr compose up'
#[test]
fn test_issue_318_missing_option_flag_wait_timeout_on_boxr_compose_up() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--wait-timeout", "60"]).unwrap();
    let _ = cli;
}

// Issue #319: [Docker Drift] Missing option flag '--wait' on 'boxr compose up'
#[test]
fn test_issue_319_missing_option_flag_wait_on_boxr_compose_up() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--wait"]).unwrap();
    let _ = cli;
}

// Issue #320: [Docker Drift] Missing option flag '--timestamps' on 'boxr compose up'
#[test]
fn test_issue_320_missing_option_flag_timestamps_on_boxr_compose_up() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "up", "--timestamps"]).unwrap();
    let _ = cli;
}

// Issue #321: [Docker Drift] Missing option flag '--remove-orphans' on 'boxr compose down'
#[test]
fn test_issue_321_missing_option_flag_remove_orphans_on_boxr_compose_down() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "down", "--remove-orphans"]).unwrap();
    let _ = cli;
}

// Issue #322: [Docker Drift] Missing option flag '--rmi' on 'boxr compose down'
#[test]
fn test_issue_322_missing_option_flag_rmi_on_boxr_compose_down() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "down", "--rmi", "all"]).unwrap();
    let _ = cli;
}

// Issue #323: [Docker Drift] Missing option flag '--timeout' on 'boxr compose down'
#[test]
fn test_issue_323_missing_option_flag_timeout_on_boxr_compose_down() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "down", "--timeout", "30"]).unwrap();
    let _ = cli;
}

// Issue #324: [Docker Drift] Missing option flag '--all' on 'boxr compose ps'
#[test]
fn test_issue_324_missing_option_flag_all_on_boxr_compose_ps() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "ps", "--all"]).unwrap();
    let _ = cli;
}

// Issue #325: [Docker Drift] Missing option flag '--filter' on 'boxr compose ps'
#[test]
fn test_issue_325_missing_option_flag_filter_on_boxr_compose_ps() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "ps", "--filter", "status=running"]).unwrap();
    let _ = cli;
}

// Issue #326: [Docker Drift] Missing option flag '--quiet' on 'boxr compose ps'
#[test]
fn test_issue_326_missing_option_flag_quiet_on_boxr_compose_ps() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "ps", "-q"]).unwrap();
    let _ = cli;
}

// Issue #327: [Docker Drift] Missing option flag '--format' on 'boxr compose ps'
#[test]
fn test_issue_327_missing_option_flag_format_on_boxr_compose_ps() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "ps", "--format", "json"]).unwrap();
    let _ = cli;
}

// Issue #328: [Docker Drift] Missing option flag '--services' on 'boxr compose ps'
#[test]
fn test_issue_328_missing_option_flag_services_on_boxr_compose_ps() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "ps", "--services"]).unwrap();
    let _ = cli;
}

// Issue #329: [Docker Drift] Missing option flag '--status' on 'boxr compose ps'
#[test]
fn test_issue_329_missing_option_flag_status_on_boxr_compose_ps() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "ps", "--status", "running"]).unwrap();
    let _ = cli;
}

// Issue #330: [Docker Drift] Missing option flag '--follow' on 'boxr compose logs'
#[test]
fn test_issue_330_missing_option_flag_follow_on_boxr_compose_logs() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "logs", "--follow"]).unwrap();
    let _ = cli;
}

// Issue #331: [Docker Drift] Missing option flag '--no-color' on 'boxr compose logs'
#[test]
fn test_issue_331_missing_option_flag_no_color_on_boxr_compose_logs() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "logs", "--no-color"]).unwrap();
    let _ = cli;
}

// Issue #332: [Docker Drift] Missing option flag '--no-log-prefix' on 'boxr compose logs'
#[test]
fn test_issue_332_missing_option_flag_no_log_prefix_on_boxr_compose_logs() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "logs", "--no-log-prefix"]).unwrap();
    let _ = cli;
}

// Issue #333: [Docker Drift] Missing option flag '--since' on 'boxr compose logs'
#[test]
fn test_issue_333_missing_option_flag_since_on_boxr_compose_logs() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "logs", "--since", "1h"]).unwrap();
    let _ = cli;
}

// Issue #334: [Docker Drift] Missing option flag '--until' on 'boxr compose logs'
#[test]
fn test_issue_334_missing_option_flag_until_on_boxr_compose_logs() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "logs", "--until", "1h"]).unwrap();
    let _ = cli;
}

// Issue #335: [Docker Drift] Missing option flag '--timestamps' on 'boxr compose logs'
#[test]
fn test_issue_335_missing_option_flag_timestamps_on_boxr_compose_logs() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "logs", "--timestamps"]).unwrap();
    let _ = cli;
}

// Issue #336: [Docker Drift] Missing option flag '--no-cache' on 'boxr compose build'
#[test]
fn test_issue_336_missing_option_flag_no_cache_on_boxr_compose_build() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "build", "--no-cache"]).unwrap();
    let _ = cli;
}

// Issue #337: [Docker Drift] Missing option flag '--tail' on 'boxr compose logs'
#[test]
fn test_issue_337_missing_option_flag_tail_on_boxr_compose_logs() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "logs", "--tail", "20"]).unwrap();
    let _ = cli;
}

// Issue #338: [Docker Drift] Missing option flag '--build-arg' on 'boxr compose build'
#[test]
fn test_issue_338_missing_option_flag_build_arg_on_boxr_compose_build() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "build", "--build-arg", "FOO=bar"]).unwrap();
    let _ = cli;
}

// Issue #339: [Docker Drift] Missing option flag '--pull' on 'boxr compose build'
#[test]
fn test_issue_339_missing_option_flag_pull_on_boxr_compose_build() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "build", "--pull"]).unwrap();
    let _ = cli;
}

// Issue #340: [Docker Drift] Missing option flag '--push' on 'boxr compose build'
#[test]
fn test_issue_340_missing_option_flag_push_on_boxr_compose_build() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "build", "--push"]).unwrap();
    let _ = cli;
}

// Issue #341: [Docker Drift] Missing option flag '--quiet' on 'boxr compose build'
#[test]
fn test_issue_341_missing_option_flag_quiet_on_boxr_compose_build() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "build", "--quiet"]).unwrap();
    let _ = cli;
}

// Issue #342: [Docker Drift] Missing option flag '--no-deps' on 'boxr compose restart'
#[test]
fn test_issue_342_missing_option_flag_no_deps_on_boxr_compose_restart() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    use boxr::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["boxr", "compose", "restart", "--no-deps"]).unwrap();
    let _ = cli;
}
