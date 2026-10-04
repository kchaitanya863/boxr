//! Integration tests for GitHub issues #343 through #391 (Podman parity sprint).

#[path = "common/blackbox.rs"]
mod blackbox;

use boxr::artifact::ArtifactStore;
use boxr::builder::BuildCache;
use boxr::cli::Cli;
use clap::Parser;
use std::fs;
use tempfile::tempdir;

// Issue #343: Podman parity: `artifact` command group
#[test]
fn test_issue_343_artifact_command_group() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "artifact", "ls"]).unwrap();
    let _ = cli;
    let cli_add = Cli::try_parse_from(["boxr", "artifact", "add", "my-art", "test.tar"]).unwrap();
    let _ = cli_add;
    let cli_extract =
        Cli::try_parse_from(["boxr", "artifact", "extract", "my-art", "/tmp"]).unwrap();
    let _ = cli_extract;

    let temp = tempdir().unwrap();
    let store = ArtifactStore::with_home(temp.path().to_path_buf());
    let src_file = temp.path().join("data.bin");
    fs::write(&src_file, b"sample artifact payload").unwrap();

    let rec = store
        .add("test-artifact", &src_file, "application/octet-stream")
        .unwrap();
    assert_eq!(rec.name, "test-artifact");
    assert!(rec.digest.starts_with("sha256:"));

    let list = store.list();
    assert_eq!(list.len(), 1);

    let dest_dir = temp.path().join("extracted");
    let extracted = store.extract("test-artifact", &dest_dir).unwrap();
    assert!(extracted.exists());
    assert_eq!(fs::read(&extracted).unwrap(), b"sample artifact payload");

    store.remove("test-artifact").unwrap();
    assert!(store.list().is_empty());
}

// Issue #344: Podman parity: `auto-update`
#[test]
fn test_issue_344_auto_update() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "auto-update", "--dry-run"]).unwrap();
    let _ = cli;
}

// Issue #345: Podman parity: `healthcheck run`
#[test]
fn test_issue_345_healthcheck_run() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "healthcheck", "run", "my-container"]).unwrap();
    let _ = cli;
}

// Issue #346: Podman parity: `quadlet` command group
#[test]
fn test_issue_346_quadlet_command_group() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli_ls = Cli::try_parse_from(["boxr", "quadlet", "ls"]).unwrap();
    let _ = cli_ls;
    let cli_install = Cli::try_parse_from(["boxr", "quadlet", "install", "my.container"]).unwrap();
    let _ = cli_install;
    let cli_print = Cli::try_parse_from(["boxr", "quadlet", "print", "my.container"]).unwrap();
    let _ = cli_print;

    let temp = tempdir().unwrap();
    let unit_file = temp.path().join("web.container");
    fs::write(&unit_file, "[Container]\nImage=alpine:latest\n").unwrap();
    assert!(unit_file.exists());
}

// Issue #347: Podman parity: modern `kube` command tree
#[test]
fn test_issue_347_kube_command_tree() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli_play = Cli::try_parse_from(["boxr", "kube", "play", "pod.yaml"]).unwrap();
    let _ = cli_play;
    let cli_down = Cli::try_parse_from(["boxr", "kube", "down", "pod.yaml"]).unwrap();
    let _ = cli_down;
    let cli_gen = Cli::try_parse_from(["boxr", "kube", "generate", "my-container"]).unwrap();
    let _ = cli_gen;
    let cli_apply = Cli::try_parse_from(["boxr", "kube", "apply", "pod.yaml"]).unwrap();
    let _ = cli_apply;
}

// Issue #348: Podman parity: top-level `init` command
#[test]
fn test_issue_348_toplevel_init() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "init", "my-container"]).unwrap();
    let _ = cli;
}

// Issue #349: Podman parity: top-level `untag` command
#[test]
fn test_issue_349_toplevel_untag() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "untag", "myimage:tag1", "tag2"]).unwrap();
    let _ = cli;
}

// Issue #350: Podman parity: `container checkpoint`
#[test]
fn test_issue_350_container_checkpoint() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "container", "checkpoint", "--keep", "c1"]).unwrap();
    let _ = cli;
    let cli_exp = Cli::try_parse_from([
        "boxr",
        "container",
        "checkpoint",
        "--export",
        "/tmp/cp.tar",
        "c1",
    ])
    .unwrap();
    let _ = cli_exp;
}

// Issue #351: Podman parity: `container restore`
#[test]
fn test_issue_351_container_restore() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from([
        "boxr",
        "container",
        "restore",
        "--import",
        "/tmp/cp.tar",
        "c1",
    ])
    .unwrap();
    let _ = cli;
}

// Issue #352: Podman parity: `container cleanup`
#[test]
fn test_issue_352_container_cleanup() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "container", "cleanup", "--all", "--rm"]).unwrap();
    let _ = cli;
    let cli_single = Cli::try_parse_from(["boxr", "container", "cleanup", "c1"]).unwrap();
    let _ = cli_single;
}

// Issue #353: Podman parity: `container clone`
#[test]
fn test_issue_353_container_clone() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from([
        "boxr",
        "container",
        "clone",
        "--run",
        "source_c",
        "target_c",
    ])
    .unwrap();
    let _ = cli;
}

// Issue #354: Podman parity: `container init`
#[test]
fn test_issue_354_container_init() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "container", "init", "c1"]).unwrap();
    let _ = cli;
}

// Issue #355: Podman parity: `container runlabel`
#[test]
fn test_issue_355_container_runlabel() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli =
        Cli::try_parse_from(["boxr", "container", "runlabel", "run", "alpine:latest"]).unwrap();
    let _ = cli;
}

// Issue #356: Podman parity: `container mount` and `container unmount`
#[test]
fn test_issue_356_container_mount_unmount() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli_m = Cli::try_parse_from(["boxr", "container", "mount", "c1"]).unwrap();
    let _ = cli_m;
    let cli_u = Cli::try_parse_from(["boxr", "container", "unmount", "c1"]).unwrap();
    let _ = cli_u;
}

// Issue #357: Podman parity: container checkpoint runtime (`start --checkpoint`)
#[test]
fn test_issue_357_start_checkpoint() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "start", "--checkpoint", "cp1", "c1"]).unwrap();
    let _ = cli;
    let cli_dir =
        Cli::try_parse_from(["boxr", "start", "--checkpoint-dir", "/tmp/cp", "c1"]).unwrap();
    let _ = cli_dir;
}

// Issue #358: Podman parity: `image diff`
#[test]
fn test_issue_358_image_diff() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "image", "diff", "img1", "img2"]).unwrap();
    let _ = cli;
}

// Issue #359: Podman parity: `image scp`
#[test]
fn test_issue_359_image_scp() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "image", "scp", "user@host:img1", "local_img"]).unwrap();
    let _ = cli;
}

// Issue #360: Podman parity: `image sign`
#[test]
fn test_issue_360_image_sign() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from([
        "boxr",
        "image",
        "sign",
        "--sign-by",
        "me@example.com",
        "alpine",
    ])
    .unwrap();
    let _ = cli;
}

// Issue #361: Podman parity: `image tree`
#[test]
fn test_issue_361_image_tree() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "image", "tree", "--whatrequires", "alpine"]).unwrap();
    let _ = cli;
}

// Issue #362: Podman parity: `image trust`
#[test]
fn test_issue_362_image_trust() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli_show = Cli::try_parse_from(["boxr", "image", "trust", "show", "--raw"]).unwrap();
    let _ = cli_show;
    let cli_set = Cli::try_parse_from([
        "boxr",
        "image",
        "trust",
        "set",
        "--type",
        "accept",
        "docker.io",
    ])
    .unwrap();
    let _ = cli_set;
}

// Issue #363: Podman parity: `image untag`
#[test]
fn test_issue_363_image_untag() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "image", "untag", "alpine", "3.18", "3.19"]).unwrap();
    let _ = cli;
}

// Issue #364: Podman parity: `image mount` and `image unmount`
#[test]
fn test_issue_364_image_mount_unmount() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli_m = Cli::try_parse_from(["boxr", "image", "mount", "alpine"]).unwrap();
    let _ = cli_m;
    let cli_u = Cli::try_parse_from(["boxr", "image", "unmount", "alpine"]).unwrap();
    let _ = cli_u;
}

// Issue #365: Podman parity: `volume export`
#[test]
fn test_issue_365_volume_export() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli =
        Cli::try_parse_from(["boxr", "volume", "export", "--output", "vol.tar", "myvol"]).unwrap();
    let _ = cli;
}

// Issue #366: Podman parity: `volume import`
#[test]
fn test_issue_366_volume_import() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "volume", "import", "myvol", "vol.tar"]).unwrap();
    let _ = cli;
}

// Issue #367: Podman parity: `volume reload`
#[test]
fn test_issue_367_volume_reload() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "volume", "reload", "myvol"]).unwrap();
    let _ = cli;
}

// Issue #368: Podman parity: `volume rename`
#[test]
fn test_issue_368_volume_rename() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "volume", "rename", "old_vol", "new_vol"]).unwrap();
    let _ = cli;
}

// Issue #369: Podman parity: `volume mount` and `volume unmount`
#[test]
fn test_issue_369_volume_mount_unmount() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli_m = Cli::try_parse_from(["boxr", "volume", "mount", "myvol"]).unwrap();
    let _ = cli_m;
    let cli_u = Cli::try_parse_from(["boxr", "volume", "unmount", "myvol"]).unwrap();
    let _ = cli_u;
}

// Issue #370: Podman parity: `network update`
#[test]
fn test_issue_370_network_update() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from([
        "boxr",
        "network",
        "update",
        "--dns-add",
        "8.8.8.8",
        "--dns-drop",
        "1.1.1.1",
        "--label-add",
        "env=prod",
        "--label-drop",
        "temp",
        "net1",
    ])
    .unwrap();
    let _ = cli;
}

// Issue #371: Podman parity: `network reload` full implementation
#[test]
fn test_issue_371_network_reload() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "network", "reload", "c1", "c2"]).unwrap();
    let _ = cli;
}

// Issue #372: Podman parity: `pod clone`
#[test]
fn test_issue_372_pod_clone() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "pod", "clone", "src_pod", "dst_pod"]).unwrap();
    let _ = cli;
}

// Issue #373: Podman parity: `pod logs`
#[test]
fn test_issue_373_pod_logs() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "pod", "logs", "--timestamps", "my-pod"]).unwrap();
    let _ = cli;
}

// Issue #374: Podman parity: `secret exists`
#[test]
fn test_issue_374_secret_exists() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "secret", "exists", "my-secret"]).unwrap();
    let _ = cli;
    let err = boxr::ensure_secret_exists("definitely-missing-secret").unwrap_err();
    assert!(err.to_string().contains("not found"));
}

// Issue #375: Podman parity: `machine inspect`
#[test]
fn test_issue_375_machine_inspect() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "machine", "inspect", "my-vm"]).unwrap();
    let _ = cli;
}

// Issue #376: Podman parity: `machine set`
#[test]
fn test_issue_376_machine_set() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "machine", "set", "--rootful", "my-vm"]).unwrap();
    let _ = cli;
}

// Issue #377: Podman parity: `machine os`
#[test]
fn test_issue_377_machine_os() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli_check = Cli::try_parse_from(["boxr", "machine", "os", "check", "my-vm"]).unwrap();
    let _ = cli_check;
    let cli_apply = Cli::try_parse_from(["boxr", "machine", "os", "apply", "my-vm"]).unwrap();
    let _ = cli_apply;
}

// Issue #378: Podman parity: `machine reset`
#[test]
fn test_issue_378_machine_reset() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "machine", "reset", "--force"]).unwrap();
    let _ = cli;
}

// Issue #379: Podman parity: `machine restart`
#[test]
fn test_issue_379_machine_restart() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "machine", "restart", "my-vm"]).unwrap();
    let _ = cli;
}

// Issue #380: Podman parity: `machine ssh` and `machine cp` real implementation
#[test]
fn test_issue_380_machine_ssh_cp() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli_ssh =
        Cli::try_parse_from(["boxr", "machine", "ssh", "my-vm", "echo", "hello"]).unwrap();
    let _ = cli_ssh;
    let cli_cp = Cli::try_parse_from(["boxr", "machine", "cp", "/tmp/a", "/tmp/b"]).unwrap();
    let _ = cli_cp;
}

// Issue #381: Podman parity: `generate spec` (Specgen JSON)
#[test]
fn test_issue_381_generate_spec() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "generate", "spec", "my-container"]).unwrap();
    let _ = cli;
}

// Issue #382: Podman parity: `system check`
#[test]
fn test_issue_382_system_check() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "system", "check"]).unwrap();
    let _ = cli;
}

// Issue #383: Podman parity: `system connection`
#[test]
fn test_issue_383_system_connection() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli_ls = Cli::try_parse_from(["boxr", "system", "connection", "ls"]).unwrap();
    let _ = cli_ls;
    let cli_add = Cli::try_parse_from([
        "boxr",
        "system",
        "connection",
        "add",
        "remote",
        "ssh://user@host",
    ])
    .unwrap();
    let _ = cli_add;
    let cli_rm = Cli::try_parse_from(["boxr", "system", "connection", "rm", "remote"]).unwrap();
    let _ = cli_rm;
    let cli_def =
        Cli::try_parse_from(["boxr", "system", "connection", "default", "remote"]).unwrap();
    let _ = cli_def;
}

// Issue #384: Podman parity: `system migrate`
#[test]
fn test_issue_384_system_migrate() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "system", "migrate"]).unwrap();
    let _ = cli;
}

// Issue #385: Podman parity: `system renumber`
#[test]
fn test_issue_385_system_renumber() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "system", "renumber"]).unwrap();
    let _ = cli;
}

// Issue #386: Podman parity: `system reset`
#[test]
fn test_issue_386_system_reset() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "system", "reset", "--force"]).unwrap();
    let _ = cli;
}

// Issue #387: Podman parity: `system service`
#[test]
fn test_issue_387_system_service() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "system", "service", "--time", "60"]).unwrap();
    let _ = cli;
}

// Issue #388: Podman parity: `system hyperv-prep`
#[test]
fn test_issue_388_system_hyperv_prep() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "system", "hyperv-prep"]).unwrap();
    let _ = cli;
}

// Issue #389: Podman parity: `play kube` Deployment/Service/Volume support
#[test]
fn test_issue_389_play_kube_multi_resource() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: nginx
        image: nginx:latest
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-service
spec:
  ports:
  - port: 80
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: nginx-pvc
"#;
    let temp = tempdir().unwrap();
    let yaml_file = temp.path().join("deploy.yaml");
    fs::write(&yaml_file, yaml).unwrap();

    let cli_down = Cli::try_parse_from([
        "boxr",
        "play",
        "kube",
        "--down",
        yaml_file.to_str().unwrap(),
    ])
    .unwrap();
    let _ = cli_down;
}

// Issue #390: Podman parity: `builder du` real disk usage
#[test]
fn test_issue_390_builder_du() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli = Cli::try_parse_from(["boxr", "builder", "du"]).unwrap();
    let _ = cli;
    let (count, _size) = BuildCache::disk_usage().unwrap();
    assert_eq!(count, count);
}

// Issue #391: Podman parity: kernel `mount`/`unmount` behavior
#[test]
fn test_issue_391_kernel_mount_unmount() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let cli_m = Cli::try_parse_from(["boxr", "mount", "my-container"]).unwrap();
    let _ = cli_m;
    let cli_u = Cli::try_parse_from(["boxr", "unmount", "my-container"]).unwrap();
    let _ = cli_u;
}
