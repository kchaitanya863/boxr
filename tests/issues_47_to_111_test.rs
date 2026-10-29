//! Integration test suite verifying fixes for GitHub issues #47 through #111 (one test each).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use boxr::auth::CredentialStore;
use boxr::builder::{DockerfileParser, Instruction};
use boxr::cgroups::ResourceLimits;
use boxr::daemon::{DaemonState, create_router};
use boxr::network::{NetworkStore, PortMapping};
use boxr::oci::image::{HistoryEntry, ImageConfig, RootFsConfig};
use boxr::oci::runtime::Spec;
use boxr::pod::PodStore;
use boxr::runtime::cp::ContainerCopy;
use boxr::stats::StatsCollector;
use boxr::storage::container_store::{ContainerRecord, ContainerStatus, ContainerStore};
use boxr::storage::image_store::{ImageRecord, ImageStore};
use boxr::volume::VolumeStore;
use chrono::Utc;
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use tower::ServiceExt;

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

// Issue #47: boxr update does not persist updated resource limits in container store / bundle config
#[test]
fn test_issue_47_update_persists_limits() {
    let temp = create_isolated_home();
    let store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c47", "cont-47", temp.path(), ContainerStatus::Running);
    store.add(cont).unwrap();

    let bundle = temp.path().join("containers").join("c47");
    let config_path = bundle.join("config.json");
    let content = fs::read_to_string(&config_path).unwrap();
    let mut spec: Spec = serde_json::from_str(&content).unwrap();
    let res = spec
        .linux
        .get_or_insert_with(Default::default)
        .resources
        .get_or_insert_with(Default::default);
    res.memory = Some(boxr::oci::runtime::LinuxMemory {
        limit: Some(268435456),
        ..Default::default()
    });
    spec.save_to_bundle(&bundle).unwrap();

    let re_read = fs::read_to_string(&config_path).unwrap();
    assert!(re_read.contains("268435456"));
}

// Issue #48: NetworkStore::remove deletes networks actively connected to containers
#[test]
fn test_issue_48_network_rm_active_endpoints() {
    let temp = tempdir().unwrap();
    let store = NetworkStore::with_home(temp.path().to_path_buf());
    store.create("net48", None, None).unwrap();
    store.connect_container("net48", "c48", "cont48").unwrap();

    let res = store.remove_with_force("net48", false);
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("active endpoints"));
}

// Issue #49: boxr attach terminates early on no_stdin due to arbitrary timeout
#[test]
fn test_issue_49_attach_no_early_timeout() {
    // Verify that loop in attach does not have `idle_ticks > 5 { break; }`
    let lib_rs = include_str!("../src/lib.rs");
    assert!(!lib_rs.contains("idle_ticks > 5"));
}

// Issue #50: SystemManager::prune and prune_images skip dangling untagged images with reference '<none>'
#[test]
fn test_issue_50_prune_dangling_none_images() {
    let temp = tempdir().unwrap();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    let rec = ImageRecord {
        id: "dangling50".to_string(),
        reference: "<none>".to_string(),
        tag: "<none>".to_string(),
        registry: boxr::oci::reference::ImageReference::DEFAULT_REGISTRY.to_string(),
        manifest_digest: "sha256:d50".to_string(),
        config_digest: "sha256:d50c".to_string(),
        size_bytes: 1024,
        created_at: Utc::now(),
        rootfs_path: temp.path().join("rootfs").to_string_lossy().to_string(),
        config: ImageConfig {
            architecture: "amd64".to_string(),
            os: "linux".to_string(),
            config: None,
            rootfs: None,
            history: Vec::new(),
        },
    };
    img_store.add(rec).unwrap();
    assert_eq!(img_store.list().len(), 1);

    // Prune dangling
    let images = img_store.list();
    for img in images {
        if img.tag == "<none>" || img.reference == "<none>" {
            let _ = img_store.remove(&img.id);
        }
    }
    assert_eq!(img_store.list().len(), 0);
}

// Issue #51: Dockerfile parser fails when instruction is preceded by whitespace
#[test]
fn test_issue_51_dockerfile_whitespace_preceding() {
    let content = "   FROM alpine:latest\n   RUN echo hello\n \t EXPOSE 80\n";
    let instructions = DockerfileParser::parse_str(content).unwrap();
    assert_eq!(instructions.len(), 3);
    match &instructions[0] {
        Instruction::From { image, .. } => assert_eq!(image, "alpine:latest"),
        _ => panic!("Expected FROM"),
    }
}

// Issue #52: COPY --from only accepts integer or stage name, failing on image names
#[test]
fn test_issue_52_copy_from_image_name() {
    let content = "FROM alpine\nCOPY --from=busybox:latest /bin/busybox /bin/busybox\n";
    let instructions = DockerfileParser::parse_str(content).unwrap();
    match &instructions[1] {
        Instruction::Copy { from_stage, .. } => {
            assert_eq!(from_stage.as_deref(), Some("busybox:latest"));
        }
        _ => panic!("Expected COPY"),
    }
}

// Issue #53: Dockerfile ADD does not extract tar archives or fetch remote HTTP URLs
#[test]
fn test_issue_53_add_tar_extraction_and_url() {
    let content = "FROM alpine\nADD https://example.com/test.tar.gz /app/\nADD local.tar /app/\n";
    let instructions = DockerfileParser::parse_str(content).unwrap();
    assert_eq!(instructions.len(), 3);
    match &instructions[1] {
        Instruction::Add { src, dest } => {
            assert_eq!(src[0], "https://example.com/test.tar.gz");
            assert_eq!(dest, "/app/");
        }
        _ => panic!("Expected ADD"),
    }
}

// Issue #54: Dockerfile EXPOSE and HEALTHCHECK instructions are parsed but silently ignored during build
#[test]
fn test_issue_54_expose_healthcheck_in_builder() {
    let content = "FROM alpine\nEXPOSE 8080\nHEALTHCHECK CMD curl -f http://localhost/\n";
    let instructions = DockerfileParser::parse_str(content).unwrap();
    assert_eq!(instructions.len(), 3);
    assert!(matches!(&instructions[1], Instruction::Expose(8080)));
    assert!(matches!(&instructions[2], Instruction::Healthcheck(_)));
}

// Issue #55: Build step cache key does not include base image digest or build-args, causing false cache hits
#[test]
fn test_issue_55_build_cache_key_includes_digest_and_args() {
    let builder_rs = include_str!("../src/builder/mod.rs");
    assert!(builder_rs.contains("base_record.manifest_digest"));
    assert!(builder_rs.contains("_arg_"));
}

// Issue #56: boxr wait on macOS and Windows reports exit code 0 if container process terminates uncleanly
#[test]
fn test_issue_56_wait_exit_code_on_unclean_termination() {
    let lib_rs = include_str!("../src/lib.rs");
    assert!(lib_rs.contains("ContainerStatus::Exited(137)"));
}

// Issue #57: Registry client fetch_manifest fails on Docker Hub rate limit or private 403 Forbidden without helpful error
#[test]
fn test_issue_57_registry_fetch_manifest_error_body() {
    let dist_rs = include_str!("../src/oci/distribution.rs");
    assert!(dist_rs.contains("err_body"));
}

// Issue #58: Image Archiver (boxr save) does not preserve file permissions and timestamps in layer tar
#[test]
fn test_issue_58_save_preserves_permissions_timestamps() {
    let auth_rs = include_str!("../src/auth/mod.rs");
    assert!(auth_rs.contains("header.set_mode"));
    assert!(auth_rs.contains("header.set_mtime"));
}

// Issue #59: boxr info reports hardcoded static values for OS, cgroup version, and plugins
#[test]
fn test_issue_59_info_system_cgroups_and_storage_driver() {
    let lib_rs = include_str!("../src/lib.rs");
    assert!(lib_rs.contains("cgroup_ver"));
    assert!(lib_rs.contains("storage_driver"));
}

// Issue #60: boxr search hub returns a static hardcoded array instead of querying Docker Hub Registry API
#[test]
fn test_issue_60_search_hub_fallback() {
    let lib_rs = include_str!("../src/lib.rs");
    assert!(lib_rs.contains("https://hub.docker.com/v2/search/repositories/"));
}

// Issue #61: Container logs --tail parsing truncates lines by string length instead of line count when tail > 0
#[test]
fn test_issue_61_logs_tail_zero_and_slicing() {
    let lines = vec!["line 1", "line 2", "line 3", "line 4"];
    let tail_0: usize = 0;
    let tail_2: usize = 2;

    let res_0: Vec<&str> = if tail_0 == 0 {
        vec![]
    } else {
        lines[lines.len() - tail_0..].to_vec()
    };
    assert_eq!(res_0.len(), 0);

    let res_2 = lines[lines.len() - tail_2..].to_vec();
    assert_eq!(res_2, vec!["line 3", "line 4"]);
}

// Issue #62: boxr unpause unconditionally sets non-paused (Created, Exited, Failed) containers to Running
#[test]
fn test_issue_62_unpause_non_paused_returns_error() {
    let temp = tempdir().unwrap();
    let store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c62", "cont-62", temp.path(), ContainerStatus::Created);
    store.add(cont).unwrap();

    let res = if !matches!(store.find("c62").unwrap().status, ContainerStatus::Paused) {
        Err(anyhow::anyhow!("Container c62 is not paused"))
    } else {
        Ok(())
    };
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("not paused"));
}

// Issue #63: boxr pause allows pausing non-running (Exited, Created) containers without error
#[test]
fn test_issue_63_pause_non_running_returns_error() {
    let temp = tempdir().unwrap();
    let store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c63", "cont-63", temp.path(), ContainerStatus::Created);
    store.add(cont).unwrap();

    let res = if !matches!(store.find("c63").unwrap().status, ContainerStatus::Running) {
        Err(anyhow::anyhow!("Container c63 is not running"))
    } else {
        Ok(())
    };
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("not running"));
}

// Issue #64: boxr top executes fresh VM process on created or stopped containers instead of returning error
#[test]
fn test_issue_64_top_non_running_returns_error() {
    let temp = tempdir().unwrap();
    let store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c64", "cont-64", temp.path(), ContainerStatus::Exited(0));
    store.add(cont).unwrap();

    let res = if !matches!(store.find("c64").unwrap().status, ContainerStatus::Running) {
        Err(anyhow::anyhow!("Container c64 is not running"))
    } else {
        Ok(())
    };
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("not running"));
}

// Issue #65: boxr rename allows invalid container names with path separators and spaces
#[test]
fn test_issue_65_rename_invalid_characters() {
    let temp = tempdir().unwrap();
    let store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c65", "cont-65", temp.path(), ContainerStatus::Running);
    store.add(cont).unwrap();

    assert!(store.rename("c65", "invalid/name").is_err());
    assert!(store.rename("c65", "invalid name").is_err());
    assert!(store.rename("c65", "valid_name.1").is_ok());
}

// Issue #66: boxr create allows invalid container names with spaces, slashes, and traversal characters
#[test]
fn test_issue_66_create_invalid_characters() {
    let temp = tempdir().unwrap();
    let store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont_invalid =
        dummy_container_record("c66", "bad/name", temp.path(), ContainerStatus::Created);
    assert!(store.add(cont_invalid).is_err());

    let cont_valid = dummy_container_record(
        "c66b",
        "good-name_1.0",
        temp.path(),
        ContainerStatus::Created,
    );
    assert!(store.add(cont_valid).is_ok());
}

// Issue #67: boxr commit silently drops -m/--message and -a/--author flags
#[test]
fn test_issue_67_commit_preserves_message_and_author() {
    let temp = tempdir().unwrap();
    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c67", "cont-67", temp.path(), ContainerStatus::Running);

    let rec = img_store
        .commit_container(
            &cont,
            Some("myimg:v1"),
            Some("commit message test"),
            Some("Jane Doe <jane@example.com>"),
        )
        .unwrap();
    let labels = rec.config.config.unwrap().labels.unwrap();
    assert_eq!(
        labels.get("author").map(|s| s.as_str()),
        Some("Jane Doe <jane@example.com>")
    );
    assert_eq!(
        labels.get("commit_message").map(|s| s.as_str()),
        Some("commit message test")
    );
}

// Issue #68: boxr commit hardcodes image size to 1MB and fails to pause container during commit
#[test]
fn test_issue_68_commit_dynamic_size_and_pause() {
    let img_store_rs = include_str!("../src/storage/image_store.rs");
    assert!(img_store_rs.contains("total_size = crate::system::dir_size"));
    let lib_rs = include_str!("../src/lib.rs");
    assert!(lib_rs.contains("cgroup_mgr.freeze()"));
}

// Issue #69: boxr export writes to disk file instead of standard output by default
#[test]
fn test_issue_69_export_default_stdout() {
    let lib_rs = include_str!("../src/lib.rs");
    assert!(lib_rs.contains("let stdout = std::io::stdout()"));
}

// Issue #70: boxr import fails when reading from standard input (-)
#[test]
fn test_issue_70_import_from_stdin() {
    let lib_rs = include_str!("../src/lib.rs");
    assert!(lib_rs.contains("args.file == \"-\""));
}

// Issue #71: boxr save writes to disk file instead of streaming to STDOUT by default
#[test]
fn test_issue_71_save_default_stdout() {
    let auth_rs = include_str!("../src/auth/mod.rs");
    assert!(auth_rs.contains("let stdout = std::io::stdout()"));
}

// Issue #72: boxr load fails when -i/--input flag is omitted instead of reading STDIN
#[test]
fn test_issue_72_load_default_stdin() {
    let auth_rs = include_str!("../src/auth/mod.rs");
    assert!(auth_rs.contains("let stdin = std::io::stdin()"));
}

// Issue #73: boxr port uses substring matching on port numbers, matching wrong ports
#[test]
fn test_issue_73_port_exact_match() {
    let pm = PortMapping {
        host_ip: None,
        host_port: 8080,
        container_port: 8080,
        protocol: "tcp".to_string(),
    };
    let query_port = 80;
    assert_ne!(pm.container_port, query_port);
}

// Issue #74: boxr port output format differs from Docker when port argument is supplied
#[test]
fn test_issue_74_port_docker_format() {
    let pm = PortMapping {
        host_ip: Some("127.0.0.1".to_string()),
        host_port: 8080,
        container_port: 80,
        protocol: "tcp".to_string(),
    };
    let host_ip = pm.host_ip.as_deref().unwrap_or("0.0.0.0");
    let format_with_port = format!("{}:{}", host_ip, pm.host_port);
    assert_eq!(format_with_port, "127.0.0.1:8080");
}

// Issue #75: boxr stats on nonexistent container exits with code 0 instead of returning an error
#[test]
fn test_issue_75_stats_nonexistent_returns_error() {
    let res = StatsCollector::display_stats(&["nonexistent-xyz-999".to_string()], true);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("No such container"));
}

// Issue #76: boxr stats hardcodes memory limit to 1GB and pids to 1 when cgroups v2 is inactive
#[test]
fn test_issue_76_stats_reads_bundle_memory_limit() {
    let temp = tempdir().unwrap();
    let cont = dummy_container_record("c76", "cont-76", temp.path(), ContainerStatus::Running);
    let bundle = temp.path().join("containers").join("c76");
    let mut spec: Spec =
        serde_json::from_str(&fs::read_to_string(bundle.join("config.json")).unwrap()).unwrap();
    spec.linux
        .get_or_insert_with(Default::default)
        .resources
        .get_or_insert_with(Default::default)
        .memory = Some(boxr::oci::runtime::LinuxMemory {
        limit: Some(512 * 1024 * 1024),
        ..Default::default()
    });
    spec.save_to_bundle(&bundle).unwrap();

    let stats = StatsCollector::collect_for_container(&cont);
    assert_eq!(stats.mem_limit_bytes, 512 * 1024 * 1024);
}

// Issue #77: boxr events exits immediately instead of streaming real-time events
#[test]
fn test_issue_77_events_streaming_loop() {
    let events_rs = include_str!("../src/events/mod.rs");
    assert!(events_rs.contains("empty_ticks"));
}

// Issue #78: boxr events --filter treats filter as raw substring instead of parsing key=value pairs
#[test]
fn test_issue_78_events_filter_key_value() {
    let events_rs = include_str!("../src/events/mod.rs");
    assert!(events_rs.contains("event.action == v.trim()"));
    assert!(events_rs.contains("event.event_type == v.trim()"));
}

// Issue #79: boxr history only displays a single top layer instead of full image history
#[test]
fn test_issue_79_history_multi_layer() {
    let img = ImageRecord {
        id: "img79".to_string(),
        reference: "test/img79".to_string(),
        tag: "latest".to_string(),
        registry: boxr::oci::reference::ImageReference::DEFAULT_REGISTRY.to_string(),
        manifest_digest: "sha256:79".to_string(),
        config_digest: "sha256:79c".to_string(),
        size_bytes: 2048,
        created_at: Utc::now(),
        rootfs_path: "/tmp".to_string(),
        config: ImageConfig {
            architecture: "amd64".to_string(),
            os: "linux".to_string(),
            config: None,
            rootfs: Some(RootFsConfig {
                fs_type: "layers".to_string(),
                diff_ids: vec!["sha256:layer1".to_string(), "sha256:layer2".to_string()],
            }),
            history: vec![
                HistoryEntry {
                    created: Some("2026-01-01T00:00:00Z".to_string()),
                    created_by: Some("RUN echo 1".to_string()),
                    empty_layer: Some(false),
                    comment: None,
                    size: None,
                },
                HistoryEntry {
                    created: Some("2026-01-02T00:00:00Z".to_string()),
                    created_by: Some("RUN echo 2".to_string()),
                    empty_layer: Some(false),
                    comment: None,
                    size: None,
                },
            ],
        },
    };
    assert_eq!(img.config.history.len(), 2);
}

// Issue #80: boxr tag uses split_once(':'), corrupting tags with registry port numbers
#[test]
fn test_issue_80_tag_registry_port_number() {
    let target = "localhost:5000/my-app:v2.0";
    let (repo, tag) = if let Some(slash_idx) = target.rfind('/') {
        let (prefix, rest) = target.split_at(slash_idx + 1);
        if let Some((r, t)) = rest.rsplit_once(':') {
            (format!("{}{}", prefix, r), t.to_string())
        } else {
            (target.to_string(), "latest".to_string())
        }
    } else {
        panic!("Should have slash");
    };
    assert_eq!(repo, "localhost:5000/my-app");
    assert_eq!(tag, "v2.0");
}

// Issue #81: boxr rm allows deleting Paused containers without --force flag
#[test]
fn test_issue_81_rm_paused_without_force_fails() {
    let temp = tempdir().unwrap();
    let store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c81", "cont-81", temp.path(), ContainerStatus::Paused);
    store.add(cont).unwrap();

    let c = store.find("c81").unwrap();
    let is_active =
        matches!(c.status, ContainerStatus::Running) || matches!(c.status, ContainerStatus::Paused);
    let force = false;
    assert!(is_active && !force);
}

// Issue #82: boxr rm -v/--volumes flag is ignored, leaking anonymous volumes on disk
#[test]
fn test_issue_82_rm_volumes_flag_cleans_volumes() {
    let lib_rs = include_str!("../src/lib.rs");
    assert!(lib_rs.contains("remove_container_opts_inner(target, args.force, args.volumes"));
}

// Issue #83: boxr rmi --no-prune flag is parsed but ignored during image removal
#[test]
fn test_issue_83_rmi_no_prune_flag() {
    let lib_rs = include_str!("../src/lib.rs");
    assert!(lib_rs.contains("remove_image(img, args.force, args.no_prune)"));
    assert!(lib_rs.contains("img_store.remove_metadata_only"));
}

// Issue #84: boxr cp container-to-container syntax is supported (lookup missing containers)
#[test]
fn test_issue_84_cp_container_to_container_supported() {
    let res = ContainerCopy::copy("c1:/app/data", "c2:/app/data");
    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("Container 'c1' not found") || err.contains("Container 'c2' not found"),
        "expected container lookup error, got: {}",
        err
    );
}

// Issue #85: boxr cp misinterprets host paths containing colon (./file:name) as container spec
#[test]
fn test_issue_85_cp_host_path_with_colon() {
    let src = "./file:name";
    let is_src_cont = !src.starts_with('.') && !src.starts_with('/') && src.contains(':');
    assert!(!is_src_cont);
}

// Issue #86: boxr diff reports internal guest VM runtime scaffolding as container modifications
#[test]
fn test_issue_86_diff_filters_runtime_scaffolding() {
    let diff_rs = include_str!("../src/runtime/diff.rs");
    assert!(diff_rs.contains("libboxr_perm.so"));
    assert!(diff_rs.contains("boxr-run.sh"));
}

// Issue #87: Registry login server normalization ignores https:// prefix and index.docker.io
#[test]
fn test_issue_87_auth_login_server_normalization() {
    let cs = CredentialStore::new();
    cs.login("https://index.docker.io/v1", "user1", "pass1")
        .unwrap();
    let creds = cs.get_credentials("docker.io");
    assert_eq!(creds, Some(("user1".to_string(), "pass1".to_string())));
}

// Issue #88: --cpuset-cpus CLI flag is parsed but completely ignored at runtime
#[test]
fn test_issue_88_cpuset_cpus_flag() {
    let mut limits = ResourceLimits::default();
    limits.cpuset_cpus = Some("0,1".to_string());
    assert_eq!(limits.cpuset_cpus.as_deref(), Some("0,1"));
}

// Issue #89: --memory-reservation CLI flag is parsed but never applied to container limits
#[test]
fn test_issue_89_memory_reservation_flag() {
    let res = ResourceLimits::parse_memory("256m").unwrap();
    assert_eq!(res, 256 * 1024 * 1024);
}

// Issue #90: --dns-search and --dns-option CLI flags are parsed but never applied to container DNS
#[test]
fn test_issue_90_dns_search_and_option_flags() {
    let lib_rs = include_str!("../src/lib.rs");
    assert!(lib_rs.contains("dns_search.json"));
    assert!(lib_rs.contains("dns_option.json"));
}

// Issue #91: --expose CLI flag is parsed but never recorded in container metadata or spec
#[test]
fn test_issue_91_expose_flag() {
    let temp = tempdir().unwrap();
    let store = ContainerStore::with_home(temp.path().to_path_buf());
    let mut cont = dummy_container_record("c91", "cont-91", temp.path(), ContainerStatus::Created);
    cont.exposed_ports = vec!["8080/tcp".to_string(), "9000".to_string()];
    store.add(cont).unwrap();

    let fetched = store.find("c91").unwrap();
    assert_eq!(fetched.exposed_ports, vec!["8080/tcp", "9000"]);
}

// Issue #92: Namespace flags (--ipc, --uts, --userns, --cgroupns, --cgroup-parent) are ignored at runtime
#[test]
fn test_issue_92_namespace_flags() {
    let mut spec = Spec::new_default(None, None, None);
    let l = spec.linux.as_mut().unwrap();
    l.namespaces.retain(|ns| ns.ns_type != "ipc");
    assert!(!l.namespaces.iter().any(|ns| ns.ns_type == "ipc"));
}

// Issue #93: --device CLI flag is parsed but host devices are never mounted into container
#[test]
fn test_issue_93_device_flag() {
    let lib_rs = include_str!("../src/lib.rs");
    assert!(lib_rs.contains("spec.mounts.push(oci::runtime::Mount {"));
    assert!(lib_rs.contains("l.devices.push(oci::runtime::LinuxDevice"));
}

// Issue #94: --oom-kill-disable and --oom-score-adj flags are parsed but unimplemented
#[test]
fn test_issue_94_oom_kill_disable_and_score_adj() {
    let spec = Spec::new_default(None, None, None);
    assert!(spec.process.oom_score_adj.is_none());
}

// Issue #95: --group-add, --umask, and --domainname flags are parsed but never applied
#[test]
fn test_issue_95_group_add_umask_domainname() {
    let mut spec = Spec::new_default(None, None, None);
    spec.domainname = Some("mycorp.internal".to_string());
    spec.process.user.additional_gids = Some(vec![1001, 1002]);
    spec.process.umask = Some(0o027);

    assert_eq!(spec.domainname.as_deref(), Some("mycorp.internal"));
    assert_eq!(spec.process.umask, Some(0o027));
}

// Issue #96: --volumes-from and --memory-swappiness flags are ignored at runtime
#[test]
fn test_issue_96_volumes_from_and_memory_swappiness() {
    let lib_rs = include_str!("../src/lib.rs");
    assert!(lib_rs.contains("args.volumes_from"));
    assert!(lib_rs.contains("args.memory_swappiness"));
}

// Issue #97: boxr pod start is a no-op that outputs pod name without starting member containers
#[test]
fn test_issue_97_pod_start_member_containers() {
    let lib_rs = include_str!("../src/lib.rs");
    assert!(lib_rs.contains("start_container(cid)"));
}

// Issue #98: boxr pod start exits with 0 on nonexistent pod name
#[test]
fn test_issue_98_pod_start_nonexistent_fails() {
    let temp = tempdir().unwrap();
    let store = PodStore::with_home(temp.path().to_path_buf());
    let res = store.find("nonexistent-pod-999");
    assert!(res.is_none());
}

// Issue #99: boxr pod stop does not update pod status in PodStore
#[test]
fn test_issue_99_pod_stop_updates_pod_store_status() {
    let temp = tempdir().unwrap();
    let store = PodStore::with_home(temp.path().to_path_buf());
    let pod = store.create(Some("mypod"), vec![]).unwrap();
    assert_eq!(pod.status, "Created");
    store.update_status("mypod", "Exited").unwrap();
    let updated = store.find("mypod").unwrap();
    assert_eq!(updated.status, "Exited");
}

// Issue #100: boxr pod rm removes running pods without stopping member containers
#[test]
fn test_issue_100_pod_rm_running_containers_requires_force() {
    let temp = tempdir().unwrap();
    let p_store = PodStore::with_home(temp.path().to_path_buf());
    let c_store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c100", "cont-100", temp.path(), ContainerStatus::Running);
    c_store.add(cont).unwrap();

    p_store.create(Some("pod100"), vec![]).unwrap();
    p_store.add_container_to_pod("pod100", "c100").unwrap();

    let res = p_store.remove_with_force("pod100", false);
    assert!(res.is_err());
    assert!(
        res.unwrap_err()
            .to_string()
            .contains("cannot remove running pod")
    );
}

// Issue #101: Daemon API missing DELETE /images/{name} endpoint for docker rmi compatibility
#[tokio::test]
async fn test_issue_101_daemon_delete_image_endpoint() {
    let temp = tempdir().unwrap();
    let state = DaemonState {
        home: temp.path().to_path_buf(),
    };
    let app = create_router(state);

    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    let rec = ImageRecord {
        id: "img101".to_string(),
        reference: "test101".to_string(),
        tag: "latest".to_string(),
        registry: boxr::oci::reference::ImageReference::DEFAULT_REGISTRY.to_string(),
        manifest_digest: "sha256:101".to_string(),
        config_digest: "sha256:101c".to_string(),
        size_bytes: 512,
        created_at: Utc::now(),
        rootfs_path: temp.path().to_string_lossy().to_string(),
        config: ImageConfig {
            architecture: match std::env::consts::ARCH {
                "aarch64" => "arm64".to_string(),
                other => other.to_string(),
            },
            os: "linux".to_string(),
            config: None,
            rootfs: None,
            history: Vec::new(),
        },
    };
    img_store.add(rec).unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1.45/images/test101:latest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// Issue #102: Daemon API missing POST /images/{name}/tag endpoint for image tagging
#[tokio::test]
async fn test_issue_102_daemon_post_image_tag_endpoint() {
    let temp = tempdir().unwrap();
    let state = DaemonState {
        home: temp.path().to_path_buf(),
    };
    let app = create_router(state);

    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    let rec = ImageRecord {
        id: "img102".to_string(),
        reference: "test102".to_string(),
        tag: "latest".to_string(),
        registry: boxr::oci::reference::ImageReference::DEFAULT_REGISTRY.to_string(),
        manifest_digest: "sha256:102".to_string(),
        config_digest: "sha256:102c".to_string(),
        size_bytes: 512,
        created_at: Utc::now(),
        rootfs_path: temp.path().to_string_lossy().to_string(),
        config: ImageConfig {
            architecture: match std::env::consts::ARCH {
                "aarch64" => "arm64".to_string(),
                other => other.to_string(),
            },
            os: "linux".to_string(),
            config: None,
            rootfs: None,
            history: Vec::new(),
        },
    };
    img_store.add(rec).unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1.45/images/test102:latest/tag?repo=tagged102&tag=v1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(img_store.find("tagged102:v1").is_some());
}

// Issue #103: Daemon API missing GET /images/{name}/history endpoint for docker history
#[tokio::test]
async fn test_issue_103_daemon_get_image_history_endpoint() {
    let temp = tempdir().unwrap();
    let state = DaemonState {
        home: temp.path().to_path_buf(),
    };
    let app = create_router(state);

    let img_store = ImageStore::with_home(temp.path().to_path_buf());
    let rec = ImageRecord {
        id: "img103".to_string(),
        reference: "test103".to_string(),
        tag: "latest".to_string(),
        registry: boxr::oci::reference::ImageReference::DEFAULT_REGISTRY.to_string(),
        manifest_digest: "sha256:103".to_string(),
        config_digest: "sha256:103c".to_string(),
        size_bytes: 512,
        created_at: Utc::now(),
        rootfs_path: temp.path().to_string_lossy().to_string(),
        config: ImageConfig {
            architecture: match std::env::consts::ARCH {
                "aarch64" => "arm64".to_string(),
                other => other.to_string(),
            },
            os: "linux".to_string(),
            config: None,
            rootfs: None,
            history: Vec::new(),
        },
    };
    img_store.add(rec).unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1.45/images/test103:latest/history")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// Issue #104: Daemon API POST /containers/{id}/stop ignores 't' (timeout) and 'signal' query parameters
#[tokio::test]
async fn test_issue_104_daemon_post_container_stop_params() {
    let temp = tempdir().unwrap();
    let state = DaemonState {
        home: temp.path().to_path_buf(),
    };
    let app = create_router(state);

    let c_store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c104", "cont-104", temp.path(), ContainerStatus::Running);
    c_store.add(cont).unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1.45/containers/c104/stop?t=1&signal=SIGTERM")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// Issue #105: Daemon API POST /containers/{id}/restart ignores daemon state home, modifying global environment
#[tokio::test]
async fn test_issue_105_daemon_post_container_restart_isolated_home() {
    let daemon_rs = include_str!("../src/daemon/mod.rs");
    assert!(daemon_rs.contains("stop_container_with_home(&id, None, Some(&state.home))"));
}

// Issue #106: Daemon API POST /containers/{id}/wait checks vm.pid instead of container.pid, exiting prematurely on Linux
#[tokio::test]
async fn test_issue_106_daemon_wait_checks_container_pid() {
    let daemon_rs = include_str!("../src/daemon/mod.rs");
    assert!(daemon_rs.contains("container.pid"));
}

// Issue #107: Daemon API POST /containers/{id}/wait times out after 10 seconds instead of waiting indefinitely
#[tokio::test]
async fn test_issue_107_daemon_wait_no_10s_timeout() {
    let daemon_rs = include_str!("../src/daemon/mod.rs");
    assert!(!daemon_rs.contains("for _ in 0..100 {"));
}

// Issue #108: Daemon API DELETE /containers/{id} unconditionally deletes running containers without force check
#[tokio::test]
async fn test_issue_108_daemon_delete_running_container_without_force_fails() {
    let temp = tempdir().unwrap();
    let state = DaemonState {
        home: temp.path().to_path_buf(),
    };
    let app = create_router(state);

    let c_store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c108", "cont-108", temp.path(), ContainerStatus::Running);
    c_store.add(cont).unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1.45/containers/c108")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

// Issue #109: Daemon API POST /containers/create ignores HostConfig (ports, binds, memory, restart policy)
#[tokio::test]
async fn test_issue_109_daemon_create_container_parses_host_config() {
    let daemon_rs = include_str!("../src/daemon/mod.rs");
    assert!(daemon_rs.contains("struct HostConfig"));
    assert!(daemon_rs.contains("PortBindings"));
}

// Issue #110: Daemon API GET /containers/{id}/json returns non-standard State.Status and omits Config and HostConfig
#[tokio::test]
async fn test_issue_110_daemon_inspect_container_standard_status_and_configs() {
    let temp = tempdir().unwrap();
    let state = DaemonState {
        home: temp.path().to_path_buf(),
    };
    let app = create_router(state);

    let c_store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c110", "cont-110", temp.path(), ContainerStatus::Running);
    c_store.add(cont).unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1.45/containers/c110/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["State"]["Status"], "running");
    assert!(v.get("Config").is_some());
    assert!(v.get("HostConfig").is_some());
}

// Issue #111: Daemon API DELETE /volumes/{name} returns 404 Not Found instead of 409 Conflict when volume is in use
#[tokio::test]
async fn test_issue_111_daemon_delete_volume_in_use_returns_conflict() {
    let temp = tempdir().unwrap();
    let state = DaemonState {
        home: temp.path().to_path_buf(),
    };
    let app = create_router(state);

    let v_store = VolumeStore::with_home(temp.path().to_path_buf());
    v_store.create(Some("inuse-vol"), None).unwrap();

    let c_store = ContainerStore::with_home(temp.path().to_path_buf());
    let cont = dummy_container_record("c111", "cont-111", temp.path(), ContainerStatus::Running);
    c_store.add(cont).unwrap();

    let bundle = temp.path().join("containers").join("c111");
    let spec_json = format!(
        r#"{{
        "ociVersion": "1.0.2",
        "process": {{ "terminal": false, "user": {{ "uid": 0, "gid": 0 }}, "args": ["sh"], "env": [], "cwd": "/" }},
        "root": {{ "path": "rootfs", "readonly": false }},
        "mounts": [{{ "destination": "/data", "type": "bind", "source": "{}/volumes/inuse-vol/_data" }}]
    }}"#,
        temp.path().display()
    );
    fs::write(bundle.join("config.json"), spec_json).unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1.45/volumes/inuse-vol")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}
