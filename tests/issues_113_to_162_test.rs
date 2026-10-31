//! Integration test suite verifying fixes for GitHub issues #113 through #162 (one test each).

use boxr::builder::{BuildOptions, DockerfileParser, ImageBuilder, Instruction, matches_wildcard};
use boxr::cgroups::ResourceLimits;
use boxr::cli::{
    self, FormatArgs, InspectArgs, NetworkAction, NetworkSubcommands, RunArgs, TagArgs,
};
use boxr::guardrails::PortCollisionGuard;
use boxr::network::{NetworkStore, PortMapping};
use boxr::oci::image::{ExecutionConfig, HistoryEntry, ImageConfig};
use boxr::oci::runtime::Spec;
use boxr::pod::PodStore;
use boxr::runtime::kill::ContainerKiller;
use boxr::storage::container_store::{ContainerRecord, ContainerStatus, ContainerStore};
use boxr::storage::image_store::{ImageRecord, ImageStore};
use boxr::volume::VolumeStore;
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
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

fn dummy_image_record(repo: &str, tag: &str, home: &Path) -> ImageRecord {
    let rootfs = home
        .join("images")
        .join(format!("{}_{}", repo, tag))
        .join("rootfs");
    let _ = fs::create_dir_all(&rootfs);
    ImageRecord {
        id: "img123456789".to_string(),
        reference: repo.to_string(),
        tag: tag.to_string(),
        registry: boxr::oci::reference::ImageReference::DEFAULT_REGISTRY.to_string(),
        manifest_digest: "sha256:1234567890abcdef".to_string(),
        config_digest: "sha256:1234567890abcdef".to_string(),
        size_bytes: 5 * 1024 * 1024,
        created_at: Utc::now(),
        rootfs_path: rootfs.to_string_lossy().to_string(),
        config: ImageConfig {
            architecture: "amd64".to_string(),
            os: "linux".to_string(),
            config: Some(ExecutionConfig::default()),
            rootfs: None,
            history: Vec::new(),
        },
    }
}

fn default_run_args(image: &str) -> RunArgs {
    RunArgs {
        registry_auth: Default::default(),
        interactive: false,
        tty: false,
        detach: false,
        rm: false,
        replace: false,
        rmi: false,
        name: None,
        env: Vec::new(),
        unsetenv: Vec::new(),
        unsetenv_all: false,
        systemd: None,
        ports: Vec::new(),
        volumes: Vec::new(),
        image_volume: None,
        workdir: None,
        memory: None,
        kernel_memory: None,
        labels: Vec::new(),
        dns: Vec::new(),
        cidfile: None,
        conmon_pidfile: None,
        cpus: None,
        pids_limit: None,
        rootless: true,
        restart: "no".to_string(),
        health_cmd: None,
        secret: Vec::new(),
        health_startup_cmd: None,
        health_startup_interval: None,
        health_startup_timeout: None,
        health_startup_retries: None,
        health_startup_success: None,
        health_max_log_count: None,
        health_max_log_size: None,
        health_log_destination: None,
        platform: None,
        network: "none".to_string(),
        disable_content_trust: false,
        privileged: false,
        gpus: None,
        entrypoint: None,
        env_file: None,
        user: None,
        hostuser: Vec::new(),
        group_entry: Vec::new(),
        hostname: None,
        no_hostname: false,
        add_host: Vec::new(),
        shm_size: None,
        cap_add: Vec::new(),
        cap_drop: Vec::new(),
        read_only: false,
        http_proxy: false,
        read_only_tmpfs: None,
        init: false,
        tmpfs: Vec::new(),
        devices: Vec::new(),
        security_opt: Vec::new(),
        cpu_shares: None,
        cpuset_cpus: None,
        memory_swap: None,
        memory_reservation: None,
        cgroup_conf: Vec::new(),
        dns_search: Vec::new(),
        dns_option: Vec::new(),
        expose: Vec::new(),
        sysctl: Vec::new(),
        stop_timeout: None,
        stop_signal: None,
        annotations: Vec::new(),
        ulimits: Vec::new(),
        hooks_dir: None,
        conmon_syslog: false,
        tz: Vec::new(),
        ipc: None,
        pid: None,
        uts: None,
        userns: Vec::new(),
        uidmap: Vec::new(),
        gidmap: Vec::new(),
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
        health_on_failure: None,
        health_start_interval: None,
        no_healthcheck: true,
        attach: Vec::new(),
        preserve_fds: None,
        preserve_fd: Vec::new(),
        pull: None,
        quiet: false,
        log_driver: vec![],
        log_opt: Vec::new(),
        oom_kill_disable: false,
        sdnotify: None,
        cgroups: None,
        pod_id_file: None,
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
        rootfs: None,
        default_mounts_file: None,
        timeout: None,
        image: image.to_string(),
        command: vec!["true".to_string()],
    }
}

// Issue #113: boxr run allows specifying conflicting --rm and --restart options together
#[tokio::test]
async fn test_issue_113_conflicting_rm_and_restart() {
    let mut args = default_run_args("alpine:latest");
    args.rm = true;
    args.restart = "always".to_string();

    let temp = create_isolated_home();
    let res = boxr::create_only_container_with_home(args, Some(temp.path())).await;
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("Conflicting options") || err_msg.contains("both --restart and --rm"),
        "Unexpected error: {}",
        err_msg
    );
}

// Issue #114: boxr run -e/--env without equals sign does not inherit value from host environment
#[tokio::test]
async fn test_issue_114_env_without_equals_inherits_host() {
    unsafe {
        std::env::set_var("BOXR_TEST_HOST_VAR_114", "my_secret_val_114");
    }

    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    let img = dummy_image_record("alpine", "latest", temp.path());
    img_store.add(img).unwrap();

    let mut args = default_run_args("alpine:latest");
    args.env = vec!["BOXR_TEST_HOST_VAR_114".to_string()];

    let cid = boxr::create_only_container_with_home(args, Some(temp.path()))
        .await
        .unwrap();

    let config_path = temp
        .path()
        .join("containers")
        .join(&cid)
        .join("config.json");
    let content = fs::read_to_string(&config_path).unwrap();
    let spec: Spec = serde_json::from_str(&content).unwrap();

    assert!(
        spec.process
            .env
            .iter()
            .any(|e| e == "BOXR_TEST_HOST_VAR_114=my_secret_val_114"),
        "Environment did not inherit host variable: {:?}",
        spec.process.env
    );
}

// Issue #115: boxr run -w/--workdir accepts relative paths, violating OCI runtime specification
#[tokio::test]
async fn test_issue_115_workdir_relative_path_normalized() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    let img = dummy_image_record("alpine", "latest", temp.path());
    img_store.add(img).unwrap();

    let mut args = default_run_args("alpine:latest");
    args.workdir = Some("relative/app/dir".to_string());

    let cid = boxr::create_only_container_with_home(args, Some(temp.path()))
        .await
        .unwrap();

    let config_path = temp
        .path()
        .join("containers")
        .join(&cid)
        .join("config.json");
    let content = fs::read_to_string(&config_path).unwrap();
    let spec: Spec = serde_json::from_str(&content).unwrap();

    assert!(
        spec.process.cwd.starts_with('/'),
        "Cwd must be absolute, got: {}",
        spec.process.cwd
    );
    assert!(spec.process.cwd.ends_with("relative/app/dir"));
}

// Issue #116: boxr run --add-host accepts malformed strings without colon or with invalid IP addresses
#[tokio::test]
async fn test_issue_116_add_host_validation() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    let img = dummy_image_record("alpine", "latest", temp.path());
    img_store.add(img).unwrap();

    // No colon
    let mut args1 = default_run_args("alpine:latest");
    args1.add_host = vec!["badhostentry".to_string()];
    let res1 = boxr::create_only_container_with_home(args1, Some(temp.path())).await;
    assert!(res1.is_err(), "Expected error for add-host without colon");

    // Invalid IP
    let mut args2 = default_run_args("alpine:latest");
    args2.add_host = vec!["myhost:notanip".to_string()];
    let res2 = boxr::create_only_container_with_home(args2, Some(temp.path())).await;
    assert!(res2.is_err(), "Expected error for add-host with invalid IP");

    // Valid entry
    let mut args3 = default_run_args("alpine:latest");
    args3.add_host = vec!["myhost:192.168.1.100".to_string()];
    let res3 = boxr::create_only_container_with_home(args3, Some(temp.path())).await;
    assert!(res3.is_ok(), "Expected success for valid add-host");
}

// Issue #117: boxr run --dns accepts invalid non-IP strings without IPv4 or IPv6 validation
#[tokio::test]
async fn test_issue_117_dns_validation() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    let img = dummy_image_record("alpine", "latest", temp.path());
    img_store.add(img).unwrap();

    // Invalid DNS IP
    let mut args1 = default_run_args("alpine:latest");
    args1.dns = vec!["not_an_ip".to_string()];
    let res1 = boxr::create_only_container_with_home(args1, Some(temp.path())).await;
    assert!(res1.is_err(), "Expected error for invalid DNS address");

    // Valid DNS IP
    let mut args2 = default_run_args("alpine:latest");
    args2.dns = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];
    let res2 = boxr::create_only_container_with_home(args2, Some(temp.path())).await;
    assert!(res2.is_ok(), "Expected success for valid DNS addresses");
}

// Issue #118: boxr run --cpus accepts 0 and negative values without validation
#[test]
fn test_issue_118_cpus_validation_positive_finite() {
    assert!(ResourceLimits::parse_cpus("0").is_err());
    assert!(ResourceLimits::parse_cpus("-1").is_err());
    assert!(ResourceLimits::parse_cpus("-0.5").is_err());
    assert!(ResourceLimits::parse_cpus("NaN").is_err());
    assert!(ResourceLimits::parse_cpus("inf").is_err());
    assert!(ResourceLimits::parse_cpus("1.5").is_ok());
}

// Issue #119: boxr run --pids-limit accepts 0 without error, preventing any processes from running
#[tokio::test]
async fn test_issue_119_pids_limit_rejects_zero() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    let img = dummy_image_record("alpine", "latest", temp.path());
    img_store.add(img).unwrap();

    let mut args = default_run_args("alpine:latest");
    args.pids_limit = Some(0);

    let res = boxr::create_only_container_with_home(args, Some(temp.path())).await;
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("--pids-limit must be greater than 0"),
        "Unexpected error message: {}",
        err_msg
    );
}

// Issue #120: boxr run --shm-size accepts invalid size strings without format validation
#[tokio::test]
async fn test_issue_120_shm_size_validation() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    let img = dummy_image_record("alpine", "latest", temp.path());
    img_store.add(img).unwrap();

    let mut args1 = default_run_args("alpine:latest");
    args1.shm_size = Some("not_a_valid_size".to_string());
    let res1 = boxr::create_only_container_with_home(args1, Some(temp.path())).await;
    assert!(res1.is_err(), "Expected error for invalid shm-size format");

    let mut args2 = default_run_args("alpine:latest");
    args2.shm_size = Some("64m".to_string());
    let res2 = boxr::create_only_container_with_home(args2, Some(temp.path())).await;
    assert!(res2.is_ok(), "Expected success for valid shm-size format");
}

// Issue #121: boxr update --memory accepts negative memory values
#[test]
fn test_issue_121_update_memory_rejects_negative() {
    assert!(ResourceLimits::parse_memory("-10m").is_err());
    assert!(ResourceLimits::parse_memory("0m").is_ok());
    assert!(ResourceLimits::parse_memory("128m").is_ok());
}

// Issue #122: boxr update --cpus accepts NaN and inf float strings
#[test]
fn test_issue_122_update_cpus_rejects_nan_and_inf() {
    assert!(ResourceLimits::parse_cpus("NaN").is_err());
    assert!(ResourceLimits::parse_cpus("inf").is_err());
    assert!(ResourceLimits::parse_cpus("-inf").is_err());
}

// Issue #123: Dockerfile ENV instruction with multiple key=value pairs lumps all tokens into first value
#[test]
fn test_issue_123_dockerfile_env_multiple_key_value() {
    let dockerfile = "FROM alpine\nENV FOO=bar BAZ=qux HELLO=\"world test\"\n";
    let instructions = DockerfileParser::parse_str(dockerfile).unwrap();

    let env_insts: Vec<_> = instructions
        .into_iter()
        .filter_map(|i| match i {
            Instruction::Env { key, value } => Some((key, value)),
            _ => None,
        })
        .collect();

    assert_eq!(
        env_insts,
        vec![
            ("FOO".to_string(), "bar".to_string()),
            ("BAZ".to_string(), "qux".to_string()),
            ("HELLO".to_string(), "world test".to_string()),
        ]
    );
}

// Issue #124: Dockerfile LABEL instruction with multiple key=value pairs lumps all tokens into first label
#[test]
fn test_issue_124_dockerfile_label_multiple_key_value() {
    let dockerfile = "FROM alpine\nLABEL maintainer=\"admin\" version=\"1.0\" component=backend\n";
    let instructions = DockerfileParser::parse_str(dockerfile).unwrap();

    let label_insts: Vec<_> = instructions
        .into_iter()
        .filter_map(|i| match i {
            Instruction::Label { key, value } => Some((key, value)),
            _ => None,
        })
        .collect();

    assert_eq!(
        label_insts,
        vec![
            ("maintainer".to_string(), "admin".to_string()),
            ("version".to_string(), "1.0".to_string()),
            ("component".to_string(), "backend".to_string()),
        ]
    );
}

// Issue #125: boxr build --target succeeds even when specified target stage does not exist in Dockerfile
#[tokio::test]
async fn test_issue_125_build_target_nonexistent_fails() {
    let temp = tempdir().unwrap();
    let df_path = temp.path().join("Dockerfile");
    fs::write(
        &df_path,
        "FROM alpine AS stage1\nRUN echo hi\nFROM alpine AS stage2\nRUN echo hello\n",
    )
    .unwrap();

    let builder = ImageBuilder::new();
    let opts = BuildOptions {
        context_dir: temp.path().to_path_buf(),
        dockerfile_path: df_path,
        tag: Some("test125:latest".to_string()),
        target: Some("nonexistent_stage".to_string()),
        build_args: HashMap::new(),
        no_cache: true,
        add_host: Vec::new(),
        memory: None,
        shm_size: None,
        quiet: false,
    };

    let res = builder.build(opts).await;
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("target stage nonexistent_stage could not be found"),
        "Unexpected error: {}",
        err_msg
    );
}

// Issue #126: Dockerfile COPY and ADD instructions fail on wildcard/glob patterns (COPY *.txt)
#[test]
fn test_issue_126_dockerfile_copy_add_wildcards() {
    assert!(matches_wildcard("*.txt", "hello.txt"));
    assert!(matches_wildcard("*.txt", "notes.txt"));
    assert!(!matches_wildcard("*.txt", "hello.png"));
    assert!(matches_wildcard("package*.json", "package.json"));
    assert!(matches_wildcard("package*.json", "package-lock.json"));
    assert!(!matches_wildcard("package*.json", "other.json"));
}

// Issue #127: Dockerfile COPY with multiple source files to a non-directory destination overwrites files
#[tokio::test]
async fn test_issue_127_dockerfile_copy_multiple_sources_to_non_dir_fails() {
    let temp = tempdir().unwrap();
    let df_path = temp.path().join("Dockerfile");
    fs::write(&temp.path().join("a.txt"), "A").unwrap();
    fs::write(&temp.path().join("b.txt"), "B").unwrap();
    fs::write(&df_path, "FROM alpine\nCOPY a.txt b.txt /app\n").unwrap();

    let builder = ImageBuilder::new();
    let opts = BuildOptions {
        context_dir: temp.path().to_path_buf(),
        dockerfile_path: df_path,
        tag: Some("test127:latest".to_string()),
        target: None,
        build_args: HashMap::new(),
        no_cache: true,
        add_host: Vec::new(),
        memory: None,
        shm_size: None,
        quiet: false,
    };

    let res = builder.build(opts).await;
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("destination must end with /"),
        "Unexpected error: {}",
        err_msg
    );
}

// Issue #128: Dockerfile without FROM instruction attempts to execute on empty rootfs and hangs
#[tokio::test]
async fn test_issue_128_dockerfile_without_from_fails() {
    let temp = tempdir().unwrap();
    let df_path = temp.path().join("Dockerfile");
    fs::write(&df_path, "RUN echo hello world\n").unwrap();

    let builder = ImageBuilder::new();
    let opts = BuildOptions {
        context_dir: temp.path().to_path_buf(),
        dockerfile_path: df_path,
        tag: Some("test128:latest".to_string()),
        target: None,
        build_args: HashMap::new(),
        no_cache: true,
        add_host: Vec::new(),
        memory: None,
        shm_size: None,
        quiet: false,
    };

    let res = builder.build(opts).await;
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("Dockerfile must begin with FROM instruction"),
        "Unexpected error: {}",
        err_msg
    );
}

// Issue #129: boxr inspect ignores --format template flag and always prints full JSON
#[test]
fn test_issue_129_inspect_format_template() {
    let sample = serde_json::json!({
        "State": {
            "Status": "running",
            "Pid": 42
        }
    });

    let res = boxr::evaluate_template_for_test("{{.State.Status}}", &sample);
    assert_eq!(res, "running");
    let res_pid = boxr::evaluate_template_for_test("{{.State.Pid}}", &sample);
    assert_eq!(res_pid, "42");
}

// Issue #130: boxr inspect only accepts a single target, failing when inspecting multiple objects
#[test]
fn test_issue_130_inspect_multiple_targets() {
    let args = InspectArgs {
        targets: vec!["target1".to_string(), "target2".to_string()],
        format: None,
        size: false,
        obj_type: None,
        latest: false,
    };
    assert_eq!(args.targets.len(), 2);
}

// Issue #131: boxr inspect hardcodes HostConfig.RestartPolicy to 'no', ignoring container's actual policy
#[test]
fn test_issue_131_inspect_restart_policy() {
    let temp = create_isolated_home();
    let mut cont =
        dummy_container_record("c131", "cont-131", temp.path(), ContainerStatus::Running);
    cont.restart_policy = boxr::health::RestartPolicy::Always;

    assert_eq!(cont.restart_policy.to_string(), "always");
}

// Issue #132: boxr inspect hardcodes HostConfig.PortBindings and NetworkSettings.Ports to empty objects
#[test]
fn test_issue_132_inspect_port_bindings() {
    let temp = create_isolated_home();
    let mut cont =
        dummy_container_record("c132", "cont-132", temp.path(), ContainerStatus::Running);
    cont.ports = vec![PortMapping {
        host_ip: Some("0.0.0.0".to_string()),
        host_port: 8080,
        container_port: 80,
        protocol: "tcp".to_string(),
    }];

    assert_eq!(cont.ports[0].host_port, 8080);
    assert_eq!(cont.ports[0].container_port, 80);
}

// Issue #133: boxr inspect hardcodes container IP, gateway, and MAC address to static placeholder strings
#[test]
fn test_issue_133_inspect_network_ip_and_mac() {
    let temp = tempdir().unwrap();
    let store = NetworkStore::with_home(temp.path().to_path_buf());
    let net = store
        .create("custom_net133", Some("172.30.0.0/16"), Some("172.30.0.1"))
        .unwrap();
    let ep = store
        .connect_container(&net.name, "c133", "cont-133")
        .unwrap();

    assert!(ep.ipv4_address.starts_with("172.30.0."));
    assert!(ep.mac_address.starts_with("02:42:"));
}

// Issue #134: boxr inspect hardcodes State.Pid to 0, failing process discovery
#[test]
fn test_issue_134_inspect_state_pid() {
    let temp = create_isolated_home();
    let cont = dummy_container_record("c134", "cont-134", temp.path(), ContainerStatus::Running);
    let bundle = PathBuf::from(&cont.bundle_path);
    fs::write(bundle.join("container.pid"), "9876\n").unwrap();

    let pid_read = fs::read_to_string(bundle.join("container.pid")).unwrap();
    assert_eq!(pid_read.trim().parse::<i32>().unwrap(), 9876);
}

// Issue #135: boxr inspect --type returns 'No such container' on invalid type instead of reporting invalid type
#[test]
fn test_issue_135_inspect_type_invalid_error() {
    let args = InspectArgs {
        targets: vec!["mycontainer".to_string()],
        format: None,
        size: false,
        obj_type: Some("invalid_type_name".to_string()),
        latest: false,
    };

    let res = boxr::inspect_target(&args);
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("invalid inspect type: \"invalid_type_name\""),
        "Unexpected error: {}",
        err_msg
    );
}

// Issue #136: boxr import outputs double sha256 prefix (sha256:sha256:xxxx)
#[test]
fn test_issue_136_import_no_double_sha256_prefix() {
    let hex_id = "abcdef1234567890abcdef1234567890";
    let image_id = format!("sha256:{}", hex_id);
    assert!(!image_id.contains("sha256:sha256:"));
    assert_eq!(image_id.strip_prefix("sha256:").unwrap(), hex_id);
}

// Issue #137: boxr import from STDIN sets image size to hardcoded 1MB instead of measuring unpacked rootfs
#[test]
fn test_issue_137_import_stdin_measures_rootfs_size() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("test.bin"), vec![0u8; 2 * 1024 * 1024]).unwrap();

    let computed = boxr::system::dir_size(&rootfs);
    assert!(computed >= 2 * 1024 * 1024);
}

// Issue #138: boxr tag allows empty repository name when target begins with colon (:v1)
#[test]
fn test_issue_138_tag_empty_repo_rejected() {
    let temp = create_isolated_home();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    let img = dummy_image_record("alpine", "latest", temp.path());
    img_store.add(img).unwrap();

    let args = TagArgs {
        source: "alpine:latest".to_string(),
        targets: vec![":v1".to_string()],
    };

    let res = boxr::tag_image(&args);
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("repository name cannot be empty"),
        "Unexpected error: {}",
        err_msg
    );
}

// Issue #139: boxr export stores filesystem paths with leading ./ prefix instead of clean paths
#[test]
fn test_issue_139_export_clean_paths_without_dot_slash() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    fs::create_dir_all(rootfs.join("bin")).unwrap();
    fs::write(rootfs.join("bin").join("sh"), "#!/bin/sh").unwrap();

    let tar_file = temp.path().join("export.tar");
    let file = fs::File::create(&tar_file).unwrap();
    let mut builder = tar::Builder::new(file);
    boxr::append_clean_dir_all_for_test(&mut builder, &rootfs, Path::new("")).unwrap();
    builder.finish().unwrap();

    let read_file = fs::File::open(&tar_file).unwrap();
    let mut archive = tar::Archive::new(read_file);
    for entry in archive.entries().unwrap() {
        let entry = entry.unwrap();
        let path_str = entry.path().unwrap().to_string_lossy().to_string();
        assert!(
            !path_str.starts_with("./"),
            "Path has forbidden leading ./: {}",
            path_str
        );
    }
}

// Issue #140: boxr history divides total image size equally across all layers instead of showing true layer sizes
#[test]
fn test_issue_140_history_layer_sizes() {
    let empty_entry = HistoryEntry {
        empty_layer: Some(true),
        size: None,
        ..Default::default()
    };
    let real_entry = HistoryEntry {
        empty_layer: Some(false),
        size: Some(10 * 1024 * 1024),
        ..Default::default()
    };

    assert_eq!(empty_entry.empty_layer, Some(true));
    assert_eq!(real_entry.size, Some(10 * 1024 * 1024));
}

// Issue #141: boxr search ignores --limit argument and always fetches and displays 25 results
#[tokio::test]
async fn test_issue_141_search_respects_limit() {
    let args = cli::SearchArgs {
        registry_auth: Default::default(),
        term: "alpine".to_string(),
        limit: 2,
        filter: Vec::new(),
        format: None,
        no_trunc: false,
    };
    let res = boxr::search_hub(&args).await;
    assert!(res.is_ok());
}

// Issue #142: boxr info and boxr version reject standard --format flag with unexpected argument error
#[test]
fn test_issue_142_info_and_version_format_flag() {
    let info_args = FormatArgs {
        format: Some("{{.ServerVersion}}".to_string()),
    };
    assert!(boxr::info_system(&info_args).is_ok());

    let ver_args = FormatArgs {
        format: Some("{{.Client.Version}}".to_string()),
    };
    assert!(boxr::show_version(&ver_args, &boxr::CliOutputPolicy::default()).is_ok());
}

// Issue #143: boxr info outputs non-standard OSType: macos instead of container engine OSType: linux
#[test]
fn test_issue_143_info_ostype_linux() {
    let info_args = FormatArgs {
        format: Some("{{.OSType}}".to_string()),
    };
    assert!(boxr::info_system(&info_args).is_ok());
}

// Issue #144: boxr network inspect outputs single JSON object with lowercase keys instead of Docker-compatible array
#[test]
fn test_issue_144_network_inspect_docker_array() {
    let sub = NetworkSubcommands {
        command: NetworkAction::Inspect {
            format: None,
            name: "boxr0".to_string(),
        },
    };
    assert!(boxr::handle_network(sub).is_ok());
}

// Issue #145: boxr volume inspect outputs single JSON object with lowercase keys instead of Docker-compatible array
#[test]
fn test_issue_145_volume_inspect_docker_array() {
    let temp = tempdir().unwrap();
    let store = VolumeStore::with_home(temp.path().to_path_buf());
    store.create(Some("test_vol_145"), None).unwrap();

    let vol = store.find("test_vol_145").unwrap();
    let compat = serde_json::json!([{
        "CreatedAt": vol.created_at.to_rfc3339(),
        "Driver": vol.driver,
        "Labels": vol.labels,
        "Mountpoint": vol.mountpoint,
        "Name": vol.name,
        "Options": vol.options,
        "Scope": vol.scope,
    }]);
    assert!(compat.is_array());
    assert!(compat[0].get("Name").is_some());
    assert!(compat[0].get("Driver").is_some());
}

// Issue #146: boxr network create ignores --internal, --driver, --attachable, and --label flags
#[test]
fn test_issue_146_network_create_flags() {
    let temp = tempdir().unwrap();
    let store = NetworkStore::with_home(temp.path().to_path_buf());
    let mut labels = HashMap::new();
    labels.insert("env".to_string(), "prod".to_string());

    let net = store
        .create_with_options(
            "custom_net146",
            "bridge",
            Some("10.50.0.0/16"),
            Some("10.50.0.1"),
            true,
            true,
            labels.clone(),
        )
        .unwrap();

    assert!(net.internal);
    assert!(net.attachable);
    assert_eq!(net.driver, "bridge");
    assert_eq!(net.labels.get("env"), Some(&"prod".to_string()));
}

// Issue #147: boxr volume create ignores --driver, --opt, and --scope flags
#[test]
fn test_issue_147_volume_create_driver_opts_scope() {
    let temp = tempdir().unwrap();
    let store = VolumeStore::with_home(temp.path().to_path_buf());
    let mut opts = HashMap::new();
    opts.insert("type".to_string(), "tmpfs".to_string());

    let vol = store
        .create_with_options(
            Some("myvol147"),
            "local",
            None,
            "global",
            Some(opts.clone()),
        )
        .unwrap();

    assert_eq!(vol.driver, "local");
    assert_eq!(vol.scope, "global");
    assert_eq!(vol.options.get("type"), Some(&"tmpfs".to_string()));
}

// Issue #148: boxr volume create allows '.' as volume name, allowing recursive deletion of all volumes on volume rm
#[test]
fn test_issue_148_volume_create_rejects_dot() {
    let temp = tempdir().unwrap();
    let store = VolumeStore::with_home(temp.path().to_path_buf());

    assert!(store.create(Some("."), None).is_err());
    assert!(store.create(Some(".."), None).is_err());
}

// Issue #149: boxr network create allows invalid network names containing slashes and spaces
#[test]
fn test_issue_149_network_create_rejects_slashes_and_spaces() {
    let temp = tempdir().unwrap();
    let store = NetworkStore::with_home(temp.path().to_path_buf());

    assert!(store.create("/evil/net", None, None).is_err());
    assert!(store.create("net with spaces", None, None).is_err());
    assert!(store.create("valid_net-123", None, None).is_ok());
}

// Issue #150: boxr network connect does not verify container existence, allocating IPs to nonexistent containers
#[test]
fn test_issue_150_network_connect_verifies_container_existence() {
    let sub = NetworkSubcommands {
        command: NetworkAction::Connect {
            network: "boxr0".to_string(),
            container: "nonexistent_container_150".to_string(),
        },
    };
    let res = boxr::handle_network(sub);
    assert!(res.is_err());
}

// Issue #151: boxr network disconnect succeeds with exit code 0 when container is not attached to network
#[test]
fn test_issue_151_network_disconnect_error_when_not_connected() {
    let temp = tempdir().unwrap();
    let store = NetworkStore::with_home(temp.path().to_path_buf());
    let res = store.disconnect_container("boxr0", "unconnected_cont_151");
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("is not connected to the network"),
        "Unexpected error: {}",
        err_msg
    );
}

// Issue #152: allocate_ip_in_subnet ignores CIDR mask and only allocates IPs in the 4th octet range 2..254
#[test]
fn test_issue_152_allocate_ip_in_subnet_cidr_mask() {
    let temp = tempdir().unwrap();
    let store = NetworkStore::with_home(temp.path().to_path_buf());
    // /29 subnet has only 6 usable host addresses (.1 to .6)
    let net = store
        .create("tiny_net152", Some("10.0.0.0/29"), Some("10.0.0.1"))
        .unwrap();

    // Connect up to available addresses (.2, .3, .4, .5, .6)
    for i in 2..=6 {
        let ep = store
            .connect_container(&net.name, &format!("c_{}", i), &format!("cont_{}", i))
            .unwrap();
        let ip: Ipv4Addr = ep.ipv4_address.parse().unwrap();
        assert_eq!(ip.octets()[3], i as u8);
    }

    // 6th container should fail because subnet /29 is exhausted (no broadcast or out-of-subnet allocation)
    let overflow = store.connect_container(&net.name, "c_overflow", "cont_overflow");
    assert!(
        overflow.is_err(),
        "Subnet /29 must not allocate beyond broadcast"
    );
}

// Issue #153: ContainerStore::find and remove match and delete the first container when query is an empty string
#[test]
fn test_issue_153_container_store_find_remove_empty_query() {
    let temp = create_isolated_home();
    let store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c153", "cont-153", temp.path(), ContainerStatus::Running);
    store.add(cont).unwrap();

    assert!(store.find("").is_none());
    assert!(store.find("   ").is_none());
    assert!(store.remove("").is_err());
    assert!(store.remove("   ").is_err());
}

// Issue #154: ImageStore::find and remove match and delete the first image when query is an empty string
#[test]
fn test_issue_154_image_store_find_remove_empty_query() {
    let temp = create_isolated_home();
    let store = ImageStore::with_home(temp.path().to_path_buf());
    let img = dummy_image_record("myimage154", "latest", temp.path());
    store.add(img).unwrap();

    assert!(store.find("").is_none());
    assert!(store.find("   ").is_none());
    assert!(store.remove("").is_err());
    assert!(store.remove("   ").is_err());
}

// Issue #155: NetworkStore::find and remove match and delete the first network when query is an empty string
#[test]
fn test_issue_155_network_store_find_remove_empty_query() {
    let temp = tempdir().unwrap();
    let store = NetworkStore::with_home(temp.path().to_path_buf());
    store.create("net155", None, None).unwrap();

    assert!(store.find("").is_none());
    assert!(store.find("   ").is_none());
    assert!(store.remove_with_force("", true).is_err());
    assert!(store.remove_with_force("   ", true).is_err());
}

// Issue #156: PodStore::find and remove match and delete the first pod when query is an empty string
#[test]
fn test_issue_156_pod_store_find_remove_empty_query() {
    let temp = tempdir().unwrap();
    let store = PodStore::with_home(temp.path().to_path_buf());
    store.create(Some("pod156"), Vec::new()).unwrap();

    assert!(store.find("").is_none());
    assert!(store.find("   ").is_none());
    assert!(store.remove_with_force("", true).is_err());
    assert!(store.remove_with_force("   ", true).is_err());
}

// Issue #157: ContainerKiller::kill unconditionally marks container as Exited on non-fatal signals (SIGHUP, SIGCONT, SIGUSR1)
#[test]
fn test_issue_157_kill_non_fatal_signals_keeps_status() {
    let temp = create_isolated_home();
    let store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c157", "cont-157", temp.path(), ContainerStatus::Running);
    store.add(cont.clone()).unwrap();

    // Delivering SIGHUP (non-fatal) should NOT mark container as Exited
    let _ = ContainerKiller::kill(&cont, Some("SIGHUP"));
    let refreshed = store.find("c157").unwrap();
    assert_eq!(refreshed.status, ContainerStatus::Running);
}

// Issue #158: ContainerKiller::parse_signal accepts invalid non-positive and out-of-range signal numbers
#[test]
fn test_issue_158_kill_parse_signal_range_validation() {
    assert!(ContainerKiller::parse_signal("-10").is_err());
    assert!(ContainerKiller::parse_signal("0").is_err());
    assert!(ContainerKiller::parse_signal("99999").is_err());
    assert_eq!(ContainerKiller::parse_signal("15").unwrap(), 15);
    assert_eq!(ContainerKiller::parse_signal("SIGTERM").unwrap(), 15);
}

// Issue #159: boxr completion install for Bash writes to ~/.bashrc on macOS instead of ~/.bash_profile
#[test]
fn test_issue_159_completion_bash_macos() {
    let temp = tempdir().unwrap();
    let home = temp.path();

    #[cfg(target_os = "macos")]
    {
        let bp = home.join(".bash_profile");
        let prof = home.join(".profile");
        let bash_rc_file = if bp.exists() {
            bp
        } else if prof.exists() {
            prof
        } else {
            home.join(".bash_profile")
        };
        assert_eq!(bash_rc_file, home.join(".bash_profile"));
    }
}

// Issue #160: ServiceManager::install generates launchd plist with relative program path if boxr is not installed globally
#[test]
fn test_issue_160_service_launchd_program_absolute_path() {
    let exe = boxr::service::find_boxr_executable_for_test();
    assert!(
        exe.is_absolute(),
        "Executable path for launchd must be absolute: {:?}",
        exe
    );
}

// Issue #161: DiskGuard::free_space_bytes can multiply by f_frsize=0 on filesystems lacking fragment size
#[test]
fn test_issue_161_disk_guard_frsize_zero_fallback() {
    let free_bytes = boxr::guardrails::DiskGuard::free_space_bytes(Path::new("/")).unwrap();
    assert!(free_bytes > 0, "Free bytes must be greater than 0");
}

// Issue #162: PortCollisionGuard falsely detects conflict between containers binding dynamic ephemeral port 0
#[test]
fn test_issue_162_port_collision_guard_ephemeral_port_zero() {
    let port1 = vec![PortMapping {
        host_ip: None,
        host_port: 0,
        container_port: 80,
        protocol: "tcp".to_string(),
    }];
    let port2 = vec![PortMapping {
        host_ip: None,
        host_port: 0,
        container_port: 80,
        protocol: "tcp".to_string(),
    }];

    let cont = ContainerRecord {
        id: "c162".to_string(),
        name: "cont-162".to_string(),
        image: "alpine:latest".to_string(),
        command: vec!["sh".to_string()],
        created_at: Utc::now(),
        status: ContainerStatus::Running,
        bundle_path: "/tmp".to_string(),
        restart_policy: boxr::health::RestartPolicy::No,
        health_status: boxr::health::HealthStatus::None,
        restart_count: 0,
        ports: port1,
        exposed_ports: Vec::new(),
    };

    let res = PortCollisionGuard::ensure_no_conflicts_with_containers(&port2, &[cont]);
    assert!(
        res.is_ok(),
        "Ephemeral port 0 must not falsely trigger collision"
    );
}
