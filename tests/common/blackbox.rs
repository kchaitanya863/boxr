//! Shared helpers for black-box integration tests (isolated BOXR_HOME, CLI runners).

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const BOXR_CMD_TIMEOUT: Duration = Duration::from_secs(90);
use tempfile::TempDir;

/// Cross-process lock so parallel integration tests don't contend on the shared macOS VM.
#[cfg(target_os = "macos")]
struct VmTestLock {
    file: std::fs::File,
}

#[cfg(target_os = "macos")]
impl VmTestLock {
    fn acquire() -> Self {
        use std::os::unix::io::AsRawFd;
        // Lock per BOXR_HOME (not under shared vm/ symlinks) so isolated homes run in parallel.
        let lock_path = boxr::storage::boxr_home().join(".test_lock");
        if let Some(parent) = lock_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)
            .expect("failed to open VM test lock");
        let fd = file.as_raw_fd();
        while unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
            std::thread::sleep(Duration::from_millis(50));
        }
        Self { file }
    }
}

#[cfg(target_os = "macos")]
impl Drop for VmTestLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        let fd = self.file.as_raw_fd();
        unsafe {
            libc::flock(fd, libc::LOCK_UN);
        }
    }
}

/// Serialize macOS micro-VM operations across parallel integration test processes.
pub fn with_vm_lock<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    #[cfg(target_os = "macos")]
    let _lock = VmTestLock::acquire();
    f()
}

/// Returns path to the boxr binary under `target/{debug|release}/`.
pub fn boxr_bin() -> PathBuf {
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

/// Create an isolated BOXR_HOME that symlinks heavy assets from the real home.
/// Each test gets a fresh images.json; layer blobs and image rootfs are shared.
pub fn isolated_home() -> (TempDir, PathBuf) {
    let temp = tempfile::tempdir().expect("failed to create temp BOXR_HOME");
    let home = temp.path().to_path_buf();
    let base_home = boxr::storage::boxr_home();
    for dir_name in &["images", "layers", "vm", "bin"] {
        let src = base_home.join(dir_name);
        if src.exists() {
            let dst = home.join(dir_name);
            #[cfg(unix)]
            let _ = std::os::unix::fs::symlink(&src, &dst);
            #[cfg(windows)]
            let _ = std::os::windows::fs::symlink_dir(&src, &dst);
        }
    }
    // Share image catalog so isolated tests resolve cached images without registry pulls.
    let src_images_json = base_home.join("images.json");
    if src_images_json.exists() {
        let _ = fs::copy(&src_images_json, home.join("images.json"));
    }
    (temp, home)
}

pub fn rand_suffix() -> String {
    hex::encode(boxr::storage::container_store::rand_id())[..8].to_string()
}

pub fn run_boxr(home: &Path, args: &[&str]) -> Output {
    #[cfg(target_os = "macos")]
    let _vm_lock = VmTestLock::acquire();

    let bin = boxr_bin();
    assert!(bin.exists(), "boxr binary not found at {}", bin.display());
    let mut cmd = Command::new(&bin);
    cmd.env_remove("DOCKER_HOST");
    cmd.env("BOXR_HOME", home);
    cmd.args(args);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("failed to execute boxr");
    let started = Instant::now();
    while started.elapsed() < BOXR_CMD_TIMEOUT {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .expect("failed to read boxr output");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(err) => panic!("failed waiting for boxr: {}", err),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let timeout_status = std::process::Command::new("false")
        .status()
        .expect("failed to obtain non-zero exit status for timeout");
    Output {
        status: timeout_status,
        stdout: Vec::new(),
        stderr: format!(
            "boxr {} timed out after {}s",
            args.join(" "),
            BOXR_CMD_TIMEOUT.as_secs()
        )
        .into_bytes(),
    }
}

pub fn run_boxr_ok(home: &Path, args: &[&str]) -> String {
    let attempts = if cfg!(target_os = "macos") { 3 } else { 1 };
    let mut last = None;
    for attempt in 0..attempts {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(2));
        }
        let out = run_boxr(home, args);
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).to_string();
        }
        last = Some(out);
    }
    let out = last.expect("run_boxr_ok called without attempts");
    assert!(
        out.status.success(),
        "boxr {} failed (exit {}): stderr={} stdout={}",
        args.join(" "),
        out.status,
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

pub fn run_boxr_fail(home: &Path, args: &[&str]) {
    let out = run_boxr(home, args);
    assert!(
        !out.status.success(),
        "expected boxr {} to fail, got success: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout)
    );
}

pub fn combined_output(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

pub fn skip_on_macos() -> bool {
    cfg!(target_os = "macos")
}

pub fn skip_on_linux() -> bool {
    cfg!(target_os = "linux")
}

pub fn fixture_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Run a detached container and wait until an HTTP URL responds (retries on macOS).
pub fn run_detached_until_http(
    home: &Path,
    run_args: &[&str],
    url: &str,
    timeout: Duration,
) -> bool {
    // Micro-VM boot and port-forward helper startup can be slow on CI; retry.
    let attempts = 3;
    for attempt in 0..attempts {
        if attempt > 0 {
            if let Some(name) = run_args
                .iter()
                .position(|a| *a == "--name")
                .and_then(|i| run_args.get(i + 1))
            {
                cleanup_container(home, name);
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        let out = run_boxr(home, run_args);
        if !out.status.success() {
            continue;
        }
        if wait_http_ok(url, timeout) {
            return true;
        }
    }
    false
}

pub fn wait_http_ok(url: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let ok = std::process::Command::new("curl")
            .args(["-sf", "--connect-timeout", "2", "--max-time", "5", url])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

pub fn wait_container_running(home: &Path, name: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let out = run_boxr(home, &["inspect", "-f", "{{.State.Running}}", name]);
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.trim() == "true" {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

pub fn wait_exec_success(home: &Path, container: &str, cmd: &[&str], timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let mut args = vec!["exec", container];
        args.extend_from_slice(cmd);
        let out = run_boxr(home, &args);
        if out.status.success() {
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

pub fn cleanup_container(home: &Path, name: &str) {
    let _ = run_boxr(home, &["rm", "-f", name]);
}

pub fn cleanup_volume(home: &Path, name: &str) {
    let _ = run_boxr(home, &["volume", "rm", "-f", name]);
}

pub fn cleanup_network(home: &Path, name: &str) {
    let _ = run_boxr(home, &["network", "rm", name]);
}

pub fn inspect_json(home: &Path, id_or_name: &str) -> serde_json::Value {
    let out = run_boxr_ok(home, &["inspect", id_or_name]);
    let arr: Vec<serde_json::Value> = serde_json::from_str(&out).expect("invalid inspect JSON");
    arr.into_iter().next().expect("empty inspect result")
}

pub fn pull_if_needed(home: &Path, image: &str) {
    let out = run_boxr(home, &["images"]);
    let listing = String::from_utf8_lossy(&out.stdout);
    let repo = image.split(':').next().unwrap_or(image);
    let tag = image.split(':').nth(1).unwrap_or("latest");
    let needle = format!("{}/{}", repo.replace('/', " "), tag);
    let alt_needle = format!("{} {}", repo, tag);
    let listed =
        listing.contains(&needle) || listing.contains(&alt_needle) || listing.contains(repo);
    if !listed || !image_rootfs_valid(home, image) {
        run_boxr_ok(home, &["pull", image]);
    }
}

/// Verify a cached image rootfs matches its config (catches attestation-manifest corruption).
fn image_rootfs_valid(home: &Path, image: &str) -> bool {
    let images_json = home.join("images.json");
    if !images_json.exists() {
        return false;
    }
    let content = match fs::read_to_string(&images_json) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let store: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let repo = image.split(':').next().unwrap_or(image);
    let tag = image.split(':').nth(1).unwrap_or("latest");
    let images = store
        .get("images")
        .and_then(|v| v.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[]);
    let record = images.iter().find(|img| {
        let reference = img.get("reference").and_then(|v| v.as_str()).unwrap_or("");
        let img_tag = img.get("tag").and_then(|v| v.as_str()).unwrap_or("latest");
        let short = reference.strip_prefix("library/").unwrap_or(reference);
        (reference == repo || short == repo || reference.ends_with(&format!("/{}", repo)))
            && img_tag == tag
    });
    let Some(record) = record else {
        return false;
    };
    let rootfs = record
        .get("rootfs_path")
        .and_then(|v| v.as_str())
        .map(PathBuf::from);
    let Some(rootfs) = rootfs else {
        return false;
    };
    if !rootfs.exists() {
        return false;
    }
    if let Some(ep) = record
        .pointer("/config/config/Entrypoint/0")
        .and_then(|v| v.as_str())
    {
        let ep_clean = ep.strip_prefix('/').unwrap_or(ep);
        let ep_exists = rootfs.join(ep_clean).exists()
            || (!ep_clean.contains('/')
                && ["usr/local/bin", "usr/bin", "bin", "sbin"]
                    .iter()
                    .any(|dir| rootfs.join(dir).join(ep_clean).exists()));
        if !ep_exists {
            return false;
        }
    }
    let diff_count = record
        .pointer("/config/rootfs/diff_ids")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    if diff_count > 0 {
        let manifest_path = rootfs
            .parent()
            .map(|p| p.join("manifest.json"))
            .filter(|p| p.exists());
        if let Some(manifest_path) = manifest_path {
            if let Ok(manifest_text) = fs::read_to_string(&manifest_path) {
                if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&manifest_text) {
                    let layer_count = manifest
                        .get("layers")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    if layer_count != diff_count {
                        return false;
                    }
                }
            }
        }
    }
    true
}

/// Returns true if the current environment can create network namespaces.
/// Forks a child to probe unshare(CLONE_NEWNET) so the test process's own
/// network namespace is unaffected. GitHub hosted runners block this with
/// EPERM, so netns-dependent tests skip gracefully there.
#[cfg(target_os = "linux")]
pub fn netns_available() -> bool {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            // Child: probe unshare, exit 0 on success, 1 on failure.
            let ret = libc::unshare(libc::CLONE_NEWNET);
            libc::_exit(if ret == 0 { 0 } else { 1 });
        } else if pid > 0 {
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
            return libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        }
    }
    false
}

/// macOS micro-VM networking does not use Linux network namespaces.
#[cfg(not(target_os = "linux"))]
pub fn netns_available() -> bool {
    true
}
