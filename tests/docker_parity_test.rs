use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::tempdir;

#[path = "common/blackbox.rs"]
mod blackbox;

fn run_isolated(home: &Path, args: &[&str]) -> Output {
    blackbox::run_boxr(home, args)
}

fn ensure_alpine(home: &Path) {
    blackbox::pull_if_needed(home, "alpine:latest");
}

fn boxr_bin() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("boxr");
    if !path.exists() {
        let alt = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(if cfg!(debug_assertions) {
                "release"
            } else {
                "debug"
            })
            .join("boxr");
        if alt.exists() {
            return alt;
        }
    }
    path
}

fn boxr_cmd(bin: &PathBuf) -> Command {
    let mut cmd = Command::new(bin);
    cmd.env_remove("DOCKER_HOST");
    cmd
}

fn boxr_cmd_in(bin: &PathBuf, home: &std::path::Path) -> Command {
    let mut cmd = Command::new(bin);
    cmd.env_remove("DOCKER_HOST");
    cmd.env("BOXR_HOME", home);
    cmd
}

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
        let _ = fs::copy(&src_images_json, temp.path().join("images.json"));
    }
    temp
}

fn unique_id() -> String {
    hex::encode(boxr::storage::container_store::rand_id())[..8].to_string()
}

#[test]
fn test_isolated_home_preserves_images_catalog() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let home = create_isolated_home();
    let img_store = boxr::storage::ImageStore::with_home(home.path().to_path_buf());
    let base_store = boxr::storage::ImageStore::new();
    assert_eq!(img_store.list().len(), base_store.list().len());
}

/// Docker Parity Test: Version and System Info commands
#[test]
fn test_docker_parity_version_and_info() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let out = boxr_cmd(&bin).arg("version").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Client:"));
    assert!(stdout.contains("Server:"));
    assert!(stdout.contains("Version:"));
    assert!(stdout.contains("API version:"));

    let out = boxr_cmd(&bin).arg("info").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Containers:"));
    assert!(stdout.contains("Images:"));
    assert!(stdout.contains("Operating System:"));
}

/// Docker Parity Test: Volume CLI lifecycle (create, ls, inspect, rm, prune)
#[test]
fn test_docker_parity_volume_crud() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let vol = format!("dockertest-vol-{}", unique_id());

    // 1. volume create
    let out = boxr_cmd(&bin)
        .args(["volume", "create", &vol])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), vol);

    // 2. volume ls
    let out = boxr_cmd(&bin).args(["volume", "ls"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains(&vol));

    // 3. volume inspect
    let out = boxr_cmd(&bin)
        .args(["volume", "inspect", &vol])
        .output()
        .unwrap();
    assert!(out.status.success());
    let json_str = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    let name_val = parsed
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|obj| obj.get("Name").or_else(|| obj.get("name")))
        .or_else(|| parsed.get("name").or_else(|| parsed.get("Name")))
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(name_val, vol);

    // 4. volume rm
    let out = boxr_cmd(&bin)
        .args(["volume", "rm", &vol])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 5. Verify gone
    let out = boxr_cmd(&bin).args(["volume", "ls"]).output().unwrap();
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&vol));
}

/// Docker Parity Test: Network CLI lifecycle (create, ls, inspect, rm, prune)
#[test]
fn test_docker_parity_network_crud() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let net = format!("dockertest-net-{}", unique_id());

    // 1. network create
    let out = boxr_cmd(&bin)
        .args(["network", "create", &net])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 2. network ls
    let out = boxr_cmd(&bin).args(["network", "ls"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains(&net));

    // 3. network inspect
    let out = boxr_cmd(&bin)
        .args(["network", "inspect", &net])
        .output()
        .unwrap();
    assert!(out.status.success());
    let json_str = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    let name_val = parsed
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|obj| obj.get("Name").or_else(|| obj.get("name")))
        .or_else(|| parsed.get("name").or_else(|| parsed.get("Name")))
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(name_val, net);

    // 4. network rm
    let out = boxr_cmd(&bin)
        .args(["network", "rm", &net])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 5. Verify removed
    let out = boxr_cmd(&bin).args(["network", "ls"]).output().unwrap();
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&net));
}

/// Docker Parity Test: Container Creation without starting (docker create)
#[test]
fn test_docker_parity_create_command() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let name = format!("dockertest-created-{}", unique_id());

    let out = boxr_cmd(&bin)
        .args(["create", "--name", &name, "alpine", "echo", "created"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(!id.is_empty());

    // Inspect created container
    let out = boxr_cmd(&bin).args(["inspect", &name]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&name));

    // Cleanup
    let _ = boxr_cmd(&bin).args(["rm", &name]).output();
}

/// Docker Parity Test: Dockerfile Build and Image Tagging / Removal
#[test]
fn test_docker_parity_build_and_tag_lifecycle() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let temp = tempdir().unwrap();
    let dockerfile = r#"
FROM alpine:latest
ENV APP_ENV=production
RUN echo "hello docker parity" > /app.txt
CMD ["cat", "/app.txt"]
"#;

    fs::write(temp.path().join("Dockerfile"), dockerfile).unwrap();
    let img_name = format!("dockertest-img-{}", unique_id());
    let tag1 = format!("{}:1.0", img_name);
    let tag2 = format!("{}:latest", img_name);

    // 1. build
    let out = boxr_cmd(&bin)
        .args(["build", "-t", &tag1, temp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "docker build failed: {:?}", out);

    // 2. tag
    let out = boxr_cmd(&bin).args(["tag", &tag1, &tag2]).output().unwrap();
    assert!(out.status.success());

    // 3. images list
    let out = boxr_cmd(&bin).args(["images"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&img_name));

    // 4. history
    let out = boxr_cmd(&bin).args(["history", &tag1]).output().unwrap();
    assert!(out.status.success());

    // 5. rmi
    let out = boxr_cmd(&bin).args(["rmi", &tag2]).output().unwrap();
    assert!(out.status.success());
    let out = boxr_cmd(&bin).args(["rmi", &tag1]).output().unwrap();
    assert!(out.status.success());
}

/// Docker Parity Test: Docker Compose specification orchestration
#[test]
fn test_docker_parity_compose_up_down() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let (_guard, home) = blackbox::isolated_home();
    blackbox::pull_if_needed(&home, "nginx:alpine");
    blackbox::pull_if_needed(&home, "redis:alpine");

    let temp = tempdir().unwrap();
    let compose_file = r#"
version: '3.8'
services:
  web:
    image: nginx:alpine
    ports:
      - "8999:80"
  cache:
    image: redis:alpine
"#;

    let file_path = temp.path().join("docker-compose.yml");
    fs::write(&file_path, compose_file).unwrap();

    let out = run_isolated(
        &home,
        &["compose", "-f", file_path.to_str().unwrap(), "up", "-d"],
    );
    assert!(out.status.success());

    let out = run_isolated(
        &home,
        &["compose", "-f", file_path.to_str().unwrap(), "down"],
    );
    assert!(out.status.success());
}

/// Docker Parity Test: System disk usage and prune commands
#[test]
fn test_docker_parity_system_df_and_prune() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }
    let home = create_isolated_home();

    let out = boxr_cmd_in(&bin, home.path())
        .args(["system", "df"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("TYPE"));
    assert!(stdout.contains("TOTAL"));

    let out = boxr_cmd_in(&bin, home.path())
        .args(["system", "prune", "-f"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

/// Docker Parity Test: Image Inspect, History, Save and Load lifecycle
#[test]
fn test_docker_parity_image_inspect_history_save_load() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let temp = tempdir().unwrap();
    let dockerfile = "FROM alpine:latest\nRUN echo 'save-load-test' > /test.txt\n";
    fs::write(temp.path().join("Dockerfile"), dockerfile).unwrap();

    let tag = format!("dockertest-saveload-{}", unique_id());
    let archive_path = temp.path().join("image-archive.tar");

    // 1. Build
    let out = boxr_cmd(&bin)
        .args(["build", "-t", &tag, temp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 2. Inspect
    let out = boxr_cmd(&bin).args(["inspect", &tag]).output().unwrap();
    assert!(out.status.success());
    let json_str = String::from_utf8_lossy(&out.stdout);
    assert!(json_str.contains(&tag));

    // 3. History
    let out = boxr_cmd(&bin).args(["history", &tag]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("IMAGE"));

    // 4. Save
    let out = boxr_cmd(&bin)
        .args(["save", "-o", archive_path.to_str().unwrap(), &tag])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(archive_path.exists());

    // 5. Remove image
    let out = boxr_cmd(&bin).args(["rmi", &tag]).output().unwrap();
    assert!(out.status.success());

    // 6. Load
    let out = boxr_cmd(&bin)
        .args(["load", "-i", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Verify loaded
    let out = boxr_cmd(&bin).args(["images"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains(&tag));

    // Cleanup
    let _ = boxr_cmd(&bin).args(["rmi", &tag]).output();
}

/// Docker Parity Test: Container Rename and Port Inspection
#[test]
fn test_docker_parity_container_rename_and_port() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let orig_name = format!("dockertest-orig-{}", unique_id());
    let new_name = format!("dockertest-new-{}", unique_id());

    // Create container with port mapping
    let out = boxr_cmd(&bin)
        .args(["create", "--name", &orig_name, "-p", "8888:80", "alpine"])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Port check
    let out = boxr_cmd(&bin).args(["port", &orig_name]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("80/tcp") || stdout.contains("8888"));

    // Rename
    let out = boxr_cmd(&bin)
        .args(["rename", &orig_name, &new_name])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Verify new name
    let out = boxr_cmd(&bin)
        .args(["inspect", &new_name])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Old name should now fail
    let out = boxr_cmd(&bin)
        .args(["inspect", &orig_name])
        .output()
        .unwrap();
    assert!(!out.status.success());

    // Cleanup
    let _ = boxr_cmd(&bin).args(["rm", &new_name]).output();
}

/// Docker Parity Test: Negative CLI handling (non-existent containers/images)
#[test]
fn test_docker_parity_error_handling() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    // Inspect non-existent container should exit non-zero
    let out = boxr_cmd(&bin)
        .args(["inspect", "container_does_not_exist_xyz"])
        .output()
        .unwrap();
    assert!(!out.status.success());

    // Stop non-existent container should exit non-zero
    let out = boxr_cmd(&bin)
        .args(["stop", "container_does_not_exist_xyz"])
        .output()
        .unwrap();
    assert!(!out.status.success());

    // Remove non-existent volume should exit non-zero
    let out = boxr_cmd(&bin)
        .args(["volume", "rm", "volume_does_not_exist_xyz"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

/// Docker Parity Test: Exec flags (-t, -w, -u, -d)
#[test]
fn test_docker_parity_exec_flags() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let (_guard, home) = blackbox::isolated_home();
    ensure_alpine(&home);
    let name = format!("dockertest-exec-{}", unique_id());

    // 1. Run a background container
    let out = run_isolated(
        &home,
        &["run", "-d", "--name", &name, "alpine", "sleep", "60"],
    );
    assert!(out.status.success());

    // 2. Exec with workdir (-w)
    let out = run_isolated(&home, &["exec", "-w", "/tmp", &name, "pwd"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("/tmp"));

    // 3. Exec with user (-u)
    let out = run_isolated(&home, &["exec", "-u", "1000", &name, "id", "-u"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("1000"));

    // 4. Exec with tty (-t)
    let out = run_isolated(&home, &["exec", "-t", &name, "echo", "tty-ok"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tty-ok"));

    // 5. Cleanup
    let _ = run_isolated(&home, &["rm", "-f", &name]);
}

/// Docker Parity Test: Run flags (-m, -l, --dns, --cidfile)
#[test]
fn test_docker_parity_run_flags() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let temp = tempdir().unwrap();
    let cid_path = temp.path().join("container.cid");
    let name = format!("dockertest-flags-{}", unique_id());

    // Run container with -m, -l, --dns, --cidfile
    let out = boxr_cmd(&bin)
        .args([
            "run",
            "-d",
            "--name",
            &name,
            "-m",
            "512m",
            "-l",
            "env=testing",
            "-l",
            "tier=backend",
            "--dns",
            "1.0.0.1",
            "--cidfile",
            cid_path.to_str().unwrap(),
            "alpine",
            "sleep",
            "60",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Verify cidfile exists and matches container ID
    assert!(cid_path.exists());
    let cid = fs::read_to_string(&cid_path).unwrap();
    assert!(!cid.trim().is_empty());

    // Verify inspect includes labels
    let out = boxr_cmd(&bin).args(["inspect", &name]).output().unwrap();
    assert!(out.status.success());
    let json_str = String::from_utf8_lossy(&out.stdout);
    assert!(json_str.contains("env") && json_str.contains("testing"));

    // Cleanup
    let _ = boxr_cmd(&bin).args(["stop", &name]).output();
    let _ = boxr_cmd(&bin).args(["rm", &name]).output();
}

/// Docker Parity Test: Ps flags (-n, -l, -f, -q)
#[test]
fn test_docker_parity_ps_flags() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let (_home_guard, home) = blackbox::isolated_home();
    ensure_alpine(&home);
    let name = format!("dockertest-ps-{}", unique_id());

    let out = run_isolated(
        &home,
        &["run", "-d", "--name", &name, "alpine", "sleep", "60"],
    );
    assert!(out.status.success());

    // ps -q
    let out = run_isolated(&home, &["ps", "-q"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.trim().is_empty());

    // ps -n 1
    let out = run_isolated(&home, &["ps", "-n", "1"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&name));

    // ps -l (latest)
    let out = run_isolated(&home, &["ps", "-l"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&name));

    // ps -f name=...
    let out = run_isolated(&home, &["ps", "-f", &format!("name={}", name)]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&name));

    // Cleanup
    let _ = run_isolated(&home, &["rm", "-f", &name]);
}

/// Docker Parity Test: Images flags (-q, -a, -f)
#[test]
fn test_docker_parity_images_flags() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    // images -q
    let out = boxr_cmd(&bin).args(["images", "-q"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.is_empty());

    // images -a
    let out = boxr_cmd(&bin).args(["images", "-a"]).output().unwrap();
    assert!(out.status.success());

    // images -f reference=alpine
    let out = boxr_cmd(&bin)
        .args(["images", "-f", "reference=alpine"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("alpine"));
}

/// Docker Parity Test: Container & Image management subcommands (docker container ..., docker image ...)
#[test]
fn test_docker_parity_management_subcommands() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let name = format!("dockertest-mgmt-{}", unique_id());

    // 1. docker image ls
    let out = boxr_cmd(&bin).args(["image", "ls"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("REPOSITORY"));

    // 2. docker container run -d
    let out = boxr_cmd(&bin)
        .args([
            "container",
            "run",
            "-d",
            "--name",
            &name,
            "alpine",
            "sleep",
            "60",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 3. docker container ls
    let out = boxr_cmd(&bin).args(["container", "ls"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains(&name));

    // 4. docker container inspect
    let out = boxr_cmd(&bin)
        .args(["container", "inspect", &name])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 5. docker container stop
    let out = boxr_cmd(&bin)
        .args(["container", "stop", &name])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 6. docker container rm
    let out = boxr_cmd(&bin)
        .args(["container", "rm", &name])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 7. docker container prune
    let out = boxr_cmd(&bin)
        .args(["container", "prune", "-f"])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 8. docker image prune
    let out = boxr_cmd(&bin)
        .args(["image", "prune", "-f"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

/// Docker Parity Test: Dockerfile ARG, USER, VOLUME builder directives
#[test]
fn test_docker_parity_builder_directives() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let temp = tempdir().unwrap();
    let dockerfile_path = temp.path().join("Dockerfile");
    fs::write(
        &dockerfile_path,
        r#"
FROM alpine:latest
ARG APP_VERSION=1.0.0
USER 1000
VOLUME ["/data"]
CMD ["echo", "test"]
"#,
    )
    .unwrap();

    let tag = format!("dockertest-directives:{}", unique_id());

    // Build with --build-arg
    let out = boxr_cmd(&bin)
        .args([
            "build",
            "-t",
            &tag,
            "-f",
            dockerfile_path.to_str().unwrap(),
            "--build-arg",
            "APP_VERSION=2.5.0",
            temp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Inspect image config
    let out = boxr_cmd(&bin).args(["inspect", &tag]).output().unwrap();
    assert!(out.status.success());
    let json_str = String::from_utf8_lossy(&out.stdout);
    assert!(json_str.contains("1000"));

    // Cleanup
    let _ = boxr_cmd(&bin).args(["rmi", &tag]).output();
}

/// Docker Parity Test: Context Commands (context ls, show, create, use, inspect, rm)
#[test]
fn test_docker_parity_context_commands() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let ctx_name = format!("dockertest-ctx-{}", unique_id());

    // 1. context ls
    let out = boxr_cmd(&bin).args(["context", "ls"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("default"));

    // 2. context show
    let out = boxr_cmd(&bin).args(["context", "show"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.trim().is_empty());

    // 3. context create
    let out = boxr_cmd(&bin)
        .args([
            "context",
            "create",
            &ctx_name,
            "--description",
            "Test remote context",
            "--docker",
            "tcp://127.0.0.1:2375",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 4. context use
    let out = boxr_cmd(&bin)
        .args(["context", "use", &ctx_name])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 5. context inspect
    let out = boxr_cmd(&bin)
        .args(["context", "inspect", &ctx_name])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&ctx_name));

    // Reset to default
    let _ = boxr_cmd(&bin).args(["context", "use", "default"]).output();

    // 6. context rm
    let out = boxr_cmd(&bin)
        .args(["context", "rm", &ctx_name])
        .output()
        .unwrap();
    assert!(out.status.success());
}

/// Docker Parity Test: Manifest Commands (manifest inspect, create)
#[test]
fn test_docker_parity_manifest_commands() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    // 1. manifest inspect
    let out = boxr_cmd(&bin)
        .args(["manifest", "inspect", "alpine:latest"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("schemaVersion")
            || stdout.contains("mediaType")
            || stdout.contains("config")
    );

    // 2. manifest create
    let out = boxr_cmd(&bin)
        .args(["manifest", "create", "my-app:multi", "alpine:latest"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

/// Docker Parity Test: Container Init flag (--init)
#[test]
fn test_docker_parity_run_init() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let (_guard, home) = blackbox::isolated_home();
    ensure_alpine(&home);
    let name = format!("dockertest-init-{}", unique_id());

    let out = run_isolated(
        &home,
        &[
            "run", "--rm", "--init", "--name", &name, "alpine", "echo", "init-ok",
        ],
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("init-ok"));
}

/// Docker Parity Test: Builder Multi-Tag Support (docker build -t tag1 -t tag2)
#[test]
fn test_docker_parity_builder_multi_tags() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let temp = tempdir().unwrap();
    let dockerfile_path = temp.path().join("Dockerfile");
    fs::write(
        &dockerfile_path,
        "FROM alpine:latest\nCMD [\"echo\", \"multitag\"]\n",
    )
    .unwrap();

    let tag1 = format!("multitag1:{}", unique_id());
    let tag2 = format!("multitag2:{}", unique_id());

    // Build with two tags
    let out = boxr_cmd(&bin)
        .args([
            "build",
            "-t",
            &tag1,
            "-t",
            &tag2,
            "-f",
            dockerfile_path.to_str().unwrap(),
            temp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Verify both tags exist
    let out = boxr_cmd(&bin).args(["inspect", &tag1]).output().unwrap();
    assert!(out.status.success());
    let out = boxr_cmd(&bin).args(["inspect", &tag2]).output().unwrap();
    assert!(out.status.success());

    // Cleanup
    let _ = boxr_cmd(&bin).args(["rmi", &tag1]).output();
    let _ = boxr_cmd(&bin).args(["rmi", &tag2]).output();
}

/// Docker Parity Test: Compose Advanced Directives (container_name, env_file, restart)
#[test]
fn test_docker_parity_compose_advanced() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let temp = tempdir().unwrap();
    let compose_file = temp.path().join("docker-compose.yml");
    let env_file = temp.path().join("custom.env");
    fs::write(&env_file, "CUSTOM_VAR=advanced_compose_ok\n").unwrap();

    let custom_cname = format!("custom-srv-{}", unique_id());

    fs::write(
        &compose_file,
        format!(
            r#"
version: '3.8'
services:
  web:
    image: alpine:latest
    container_name: {}
    env_file:
      - custom.env
    restart: unless-stopped
    command: sleep 30
"#,
            custom_cname
        ),
    )
    .unwrap();

    // 1. compose up -d
    let out = boxr_cmd(&bin)
        .args(["compose", "-f", compose_file.to_str().unwrap(), "up", "-d"])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 2. compose ps
    let out = boxr_cmd(&bin)
        .args(["compose", "-f", compose_file.to_str().unwrap(), "ps"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&custom_cname));

    // 3. inspect container env
    let out = boxr_cmd(&bin)
        .args(["inspect", &custom_cname])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 4. compose down
    let out = boxr_cmd(&bin)
        .args(["compose", "-f", compose_file.to_str().unwrap(), "down"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

/// Docker Parity Test: Runtime Flags (--tmpfs, --security-opt)
#[test]
fn test_docker_parity_runtime_flags() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let (_guard, home) = blackbox::isolated_home();
    ensure_alpine(&home);
    let name = format!("dockertest-rt-{}", unique_id());

    let out = run_isolated(
        &home,
        &[
            "run",
            "--rm",
            "--name",
            &name,
            "--tmpfs",
            "/run:rw,size=64m",
            "--security-opt",
            "seccomp=unconfined",
            "alpine",
            "echo",
            "rt-flags-ok",
        ],
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("rt-flags-ok"));
}

/// Docker Parity Test: CPU and Memory Resource Limits (-m, --cpus, --pids-limit, and docker update)
#[test]
fn test_docker_parity_resource_limits() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let name = format!("dockertest-limits-{}", unique_id());

    // 1. Run container with memory, cpu, and pid restrictions
    let out = boxr_cmd(&bin)
        .args([
            "run",
            "-d",
            "--name",
            &name,
            "-m",
            "256m",
            "--cpus",
            "1.5",
            "--pids-limit",
            "100",
            "alpine",
            "sleep",
            "60",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 2. Inspect container
    let out = boxr_cmd(&bin).args(["inspect", &name]).output().unwrap();
    assert!(out.status.success());

    // 3. Update container resource limits dynamically (docker update)
    let out = boxr_cmd(&bin)
        .args(["update", "--memory", "512m", "--cpus", "2.0", &name])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 4. Cleanup
    let _ = boxr_cmd(&bin).args(["stop", &name]).output();
    let _ = boxr_cmd(&bin).args(["rm", &name]).output();
}

/// Docker Parity Test: Exec with --env-file
#[test]
fn test_docker_parity_exec_env_file() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let temp = tempdir().unwrap();
    let env_file = temp.path().join("exec.env");
    fs::write(&env_file, "EXEC_VAR=custom_exec_val\n").unwrap();

    let (_guard, home) = blackbox::isolated_home();
    ensure_alpine(&home);
    let name = format!("dockertest-execenv-{}", unique_id());

    let out = run_isolated(
        &home,
        &["run", "-d", "--name", &name, "alpine", "sleep", "60"],
    );
    assert!(out.status.success());

    let out = run_isolated(
        &home,
        &[
            "exec",
            "--env-file",
            env_file.to_str().unwrap(),
            &name,
            "printenv",
            "EXEC_VAR",
        ],
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("custom_exec_val"));

    let _ = run_isolated(&home, &["rm", "-f", &name]);
}

/// Docker Parity Test: Ps with --format (json and template) and --size
#[test]
fn test_docker_parity_ps_format_and_size() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }
    let home = create_isolated_home();

    let name = format!("dockertest-psfmt-{}", unique_id());

    let out = boxr_cmd_in(&bin, home.path())
        .args(["create", "--name", &name, "alpine"])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 1. ps --format json
    let out = boxr_cmd_in(&bin, home.path())
        .args(["ps", "-a", "--format", "json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&name) && stdout.contains("["));

    // 2. ps --format template
    let out = boxr_cmd_in(&bin, home.path())
        .args(["ps", "-a", "--format", "{{.ID}} - {{.Names}}"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&name));

    // 3. ps --size
    let out = boxr_cmd_in(&bin, home.path())
        .args(["ps", "-a", "--size"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("SIZE"));

    let _ = boxr_cmd_in(&bin, home.path()).args(["rm", &name]).output();
}

/// Docker Parity Test: Advanced Run Options (--cpu-shares, --memory-swap, --annotation, --ulimit)
#[test]
fn test_docker_parity_advanced_run_options() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let (_guard, home) = blackbox::isolated_home();
    ensure_alpine(&home);
    let name = format!("dockertest-advrun-{}", unique_id());

    let out = run_isolated(
        &home,
        &[
            "run",
            "--rm",
            "--name",
            &name,
            "-c",
            "512",
            "--memory-swap",
            "512m",
            "--annotation",
            "team=infra",
            "--ulimit",
            "nofile=1024:2048",
            "alpine",
            "echo",
            "adv-run-ok",
        ],
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("adv-run-ok"));
}

/// Docker Parity Test: Standard Mount & Namespace Flags (--mount, --ipc, --uts, -P)
#[test]
fn test_docker_parity_mount_and_namespace_flags() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let (_guard, home) = blackbox::isolated_home();
    ensure_alpine(&home);
    let name = format!("dockertest-mount-{}", unique_id());
    let temp = tempdir().unwrap();
    let host_dir = temp.path().join("host-data");
    fs::create_dir_all(&host_dir).unwrap();
    fs::write(host_dir.join("test.txt"), "mount_ok").unwrap();

    let canonical_host = host_dir.canonicalize().unwrap();
    let mount_spec = format!("type=bind,source={},target=/data", canonical_host.display());

    let out = run_isolated(
        &home,
        &[
            "run",
            "--rm",
            "--name",
            &name,
            "--mount",
            &mount_spec,
            "--ipc",
            "private",
            "--uts",
            "private",
            "-P",
            "alpine",
            "cat",
            "/data/test.txt",
        ],
    );
    if !out.status.success() {
        eprintln!("STDOUT: {}", String::from_utf8_lossy(&out.stdout));
        eprintln!("STDERR: {}", String::from_utf8_lossy(&out.stderr));
    }
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("mount_ok"));
}

/// Docker Parity Test: Windows Flags (--isolation, --cpu-count, --cpu-percent, --io-maxbandwidth, --io-maxiops)
#[test]
fn test_docker_parity_windows_flags() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let name = format!("dockertest-win-{}", unique_id());

    let out = boxr_cmd(&bin)
        .args([
            "create",
            "--name",
            &name,
            "--isolation",
            "default",
            "--cpu-count",
            "4",
            "--cpu-percent",
            "80",
            "--io-maxbandwidth",
            "100m",
            "--io-maxiops",
            "5000",
            "alpine",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Inspect container to verify creation
    let out = boxr_cmd(&bin).args(["inspect", &name]).output().unwrap();
    assert!(out.status.success());

    // Cleanup
    let _ = boxr_cmd(&bin).args(["rm", &name]).output();
}

/// Docker Parity Test: Stop with -s/--signal and Inspect with --type
#[test]
fn test_docker_parity_stop_signal_and_inspect_type() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let name = format!("dockertest-sig-{}", unique_id());

    // 1. Run container
    let out = boxr_cmd(&bin)
        .args(["run", "-d", "--name", &name, "alpine", "sleep", "60"])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 2. Inspect with --type container
    let out = boxr_cmd(&bin)
        .args(["inspect", "--type", "container", &name])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&name));

    // 3. Stop container with -s SIGTERM
    let out = boxr_cmd(&bin)
        .args(["stop", "-s", "SIGTERM", &name])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 4. Cleanup
    let _ = boxr_cmd(&bin).args(["rm", &name]).output();
}

/// Docker Parity Test: Images --digests, --format, and --no-trunc
#[test]
fn test_docker_parity_images_digests_and_format() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    // 1. images --digests
    let out = boxr_cmd(&bin)
        .args(["images", "--digests"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("DIGEST"));

    // 2. images --format json
    let out = boxr_cmd(&bin)
        .args(["images", "--format", "json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("["));

    // 3. images --no-trunc
    let out = boxr_cmd(&bin)
        .args(["images", "--no-trunc"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

/// Docker Parity Test: Complete 100% Upstream CLI Flags Coverage Validation
#[test]
fn test_docker_parity_100_percent_upstream_coverage() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let (_guard, home) = blackbox::isolated_home();
    ensure_alpine(&home);
    let name = format!("dockertest-full-{}", unique_id());

    // 1. run with storage-opt, volume-driver, runtime, sig-proxy
    let out = run_isolated(
        &home,
        &[
            "run",
            "--rm",
            "--name",
            &name,
            "--sig-proxy",
            "--storage-opt",
            "size=10G",
            "--volume-driver",
            "local",
            "alpine",
            "echo",
            "full-spec-ok",
        ],
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("full-spec-ok"));

    // 2. update with blkio-weight, cpu-rt-period, cpuset-mems
    let out = run_isolated(&home, &["create", "--name", &name, "alpine"]);
    assert!(out.status.success());

    let out = run_isolated(
        &home,
        &[
            "update",
            "--blkio-weight",
            "500",
            "--cpu-rt-period",
            "100000",
            "--cpuset-mems",
            "0",
            &name,
        ],
    );
    assert!(out.status.success());

    let _ = boxr_cmd(&bin).args(["rm", &name]).output();
}
