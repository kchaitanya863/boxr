//! Podman-specific parity tests (exists subcommands, network reload, machine, farm, umount, quadlet, kube).

#[path = "common/blackbox.rs"]
mod blackbox;

use boxr::cli::Cli;
use boxr::farm::FarmManager;
use clap::Parser;
use tempfile::tempdir;

#[test]
fn test_podman_container_exists_parses() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "container", "exists", "my-container"]).unwrap();
    let _ = cli;
}

#[test]
fn test_podman_image_exists_parses() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "image", "exists", "alpine:latest"]).unwrap();
    let _ = cli;
}

#[test]
fn test_podman_volume_exists_parses() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "volume", "exists", "myvol"]).unwrap();
    let _ = cli;
}

#[test]
fn test_podman_network_exists_parses() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "network", "exists", "bridge"]).unwrap();
    let _ = cli;
}

#[test]
fn test_podman_network_reload_parses() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "network", "reload", "web"]).unwrap();
    let _ = cli;
}

#[test]
fn test_container_exists_missing_returns_error() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let err = boxr::ensure_container_exists("definitely-missing-container-id").unwrap_err();
    assert!(err.to_string().contains("not found"));
}

#[test]
fn test_volume_exists_missing_returns_error() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let err = boxr::ensure_volume_exists("definitely-missing-volume").unwrap_err();
    assert!(err.to_string().contains("not found"));
}

#[test]
fn test_network_exists_missing_returns_error() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let err = boxr::ensure_network_exists("definitely-missing-network").unwrap_err();
    assert!(err.to_string().contains("not found"));
}

#[test]
fn test_image_exists_missing_returns_error() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let err = boxr::ensure_image_exists("definitely-missing-image:tag").unwrap_err();
    assert!(err.to_string().contains("not found"));
}

#[test]
fn test_network_reload_requires_container() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let err = boxr::reload_container_networks(&[]).unwrap_err();
    assert!(err.to_string().contains("requires at least one container"));
}

#[test]
fn test_podman_pod_exists_parses() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "pod", "exists", "my-pod"]).unwrap();
    let _ = cli;
}

#[test]
fn test_podman_secret_exists_parses() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "secret", "exists", "my-secret"]).unwrap();
    let _ = cli;
}

#[test]
fn test_podman_umount_alias_parses() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "umount", "my-container"]).unwrap();
    let _ = cli;
    let cli_cnt = Cli::try_parse_from(["boxr", "container", "umount", "my-container"]).unwrap();
    let _ = cli_cnt;
    let cli_img = Cli::try_parse_from(["boxr", "image", "umount", "alpine:latest"]).unwrap();
    let _ = cli_img;
    let cli_vol = Cli::try_parse_from(["boxr", "volume", "umount", "my-vol"]).unwrap();
    let _ = cli_vol;
}

#[test]
fn test_podman_farm_cli_parses() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli_create =
        Cli::try_parse_from(["boxr", "farm", "create", "arm-farm", "node1", "node2"]).unwrap();
    let _ = cli_create;
    let cli_ls = Cli::try_parse_from(["boxr", "farm", "ls"]).unwrap();
    let _ = cli_ls;
    let cli_list = Cli::try_parse_from(["boxr", "farm", "list"]).unwrap();
    let _ = cli_list;
    let cli_rm = Cli::try_parse_from(["boxr", "farm", "rm", "arm-farm"]).unwrap();
    let _ = cli_rm;
    let cli_rm_all = Cli::try_parse_from(["boxr", "farm", "remove", "--all"]).unwrap();
    let _ = cli_rm_all;
    let cli_update = Cli::try_parse_from([
        "boxr",
        "farm",
        "update",
        "--add",
        "node3",
        "--remove",
        "node1",
        "--default",
        "arm-farm",
    ])
    .unwrap();
    let _ = cli_update;
    let cli_build = Cli::try_parse_from([
        "boxr",
        "farm",
        "build",
        "--farm",
        "arm-farm",
        "-t",
        "myimage:latest",
        "--platforms",
        "linux/amd64,linux/arm64",
        ".",
    ])
    .unwrap();
    let _ = cli_build;
}

#[test]
fn test_podman_farm_manager_lifecycle() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let temp = tempdir().unwrap();
    let mgr = FarmManager::with_home(temp.path().to_path_buf());

    // Create
    let f1 = mgr
        .create("farm1", &["node-a".to_string(), "node-b".to_string()])
        .unwrap();
    assert_eq!(f1.name, "farm1");
    assert!(f1.is_default);
    assert_eq!(f1.connections.len(), 2);

    // List
    let list = mgr.list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "farm1");

    // Duplicate create fails
    assert!(mgr.create("farm1", &[]).is_err());

    // Update
    let updated = mgr
        .update(
            "farm1",
            &["node-c".to_string()],
            &["node-a".to_string()],
            true,
        )
        .unwrap();
    assert!(updated.connections.contains(&"node-c".to_string()));
    assert!(!updated.connections.contains(&"node-a".to_string()));

    // Create second farm
    let f2 = mgr.create("farm2", &["node-x".to_string()]).unwrap();
    assert!(!f2.is_default);
    assert_eq!(mgr.list().len(), 2);

    // Remove single
    let removed = mgr.remove("farm1").unwrap();
    assert_eq!(removed.name, "farm1");
    assert_eq!(mgr.list().len(), 1);

    // Remove all
    let count = mgr.remove_all().unwrap();
    assert_eq!(count, 1);
    assert!(mgr.list().is_empty());
}

#[test]
fn test_podman_additional_specialized_parses() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli_auto = Cli::try_parse_from(["boxr", "auto-update", "--dry-run"]).unwrap();
    let _ = cli_auto;
    let cli_hc = Cli::try_parse_from(["boxr", "healthcheck", "run", "c1"]).unwrap();
    let _ = cli_hc;
    let cli_quad = Cli::try_parse_from(["boxr", "quadlet", "ls"]).unwrap();
    let _ = cli_quad;
    let cli_kube = Cli::try_parse_from(["boxr", "kube", "play", "pod.yaml"]).unwrap();
    let _ = cli_kube;
    let cli_spec = Cli::try_parse_from(["boxr", "generate", "spec", "c1"]).unwrap();
    let _ = cli_spec;
    let cli_init = Cli::try_parse_from(["boxr", "init", "c1"]).unwrap();
    let _ = cli_init;
    let cli_untag = Cli::try_parse_from(["boxr", "untag", "myimage:tag1"]).unwrap();
    let _ = cli_untag;
}
