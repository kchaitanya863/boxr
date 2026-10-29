use super::*;
use crate::storage::{ImageRecord, ImageStore};
use std::path::{Path, PathBuf};
use tempfile::tempdir;

/// Points $HOME at a temp dir for the duration of a test, then restores it.
/// Needed because `get_credentials` falls back to ~/.docker/config.json for
/// Docker compatibility, which would otherwise leak whatever credentials
/// happen to exist on the machine running the tests.
struct HomeGuard {
    orig: Option<std::ffi::OsString>,
}

impl HomeGuard {
    fn isolate_to(path: &std::path::Path) -> Self {
        let orig = std::env::var_os("HOME");
        // SAFETY: the test suite runs single-threaded (--test-threads=1) and
        // no other test in this binary reads or writes HOME concurrently.
        unsafe { std::env::set_var("HOME", path) };
        Self { orig }
    }
}

impl Drop for HomeGuard {
    fn drop(&mut self) {
        // SAFETY: same as above; the guard restores the previous value.
        unsafe {
            match self.orig.take() {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
    }
}

#[test]
fn test_credential_store_login_logout() {
    let temp = tempdir().unwrap();
    let _home_guard = HomeGuard::isolate_to(temp.path());
    let store = CredentialStore {
        config_file: temp.path().join("config.json"),
    };

    store.login("docker.io", "testuser", "secret123").unwrap();
    let creds = store.get_credentials("docker.io").unwrap();
    assert_eq!(creds.0, "testuser");
    assert_eq!(creds.1, "secret123");

    store.logout("docker.io").unwrap();
    assert!(store.get_credentials("docker.io").is_none());

    // Test server normalization for https:// and index.docker.io
    store
        .login("https://index.docker.io/v1/", "hubuser", "token999")
        .unwrap();
    let creds2 = store.get_credentials("registry-1.docker.io").unwrap();
    assert_eq!(creds2.0, "hubuser");
    assert_eq!(creds2.1, "token999");
}

// Issue #407: save/load roundtrip must preserve the image identity and
// produce a runnable rootfs (symlinks intact). Previously load minted a
// random id, hardcoded size_bytes to 1MB, and save silently dropped
// symlinks, leaving an unrunnable image.
#[cfg(unix)]
#[test]
fn test_issue_407_save_load_roundtrip() {
    use crate::oci::image::ImageConfig;

    let home = tempdir().unwrap();

    // Build a fake image whose rootfs contains a file and a symlink,
    // mirroring the alpine layout that exposed this bug.
    let img_dir = home.path().join("images").join("sha256_aaa").join("rootfs");
    let bin_dir = img_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::write(bin_dir.join("busybox"), b"fake-busybox").unwrap();
    std::os::unix::fs::symlink("busybox", bin_dir.join("sh")).unwrap();

    let store = ImageStore::with_home(home.path().to_path_buf());
    // Use the host architecture so ImageStore::find (which filters by
    // platform) matches on any CI runner (amd64 or arm64).
    let host_arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    let record = ImageRecord {
        id: "aaa111bbb222".to_string(),
        reference: "library/testimg".to_string(),
        tag: "latest".to_string(),
        registry: "registry-1.docker.io".to_string(),
        manifest_digest: "sha256:aaa".to_string(),
        config_digest: "sha256:cfg".to_string(),
        size_bytes: 4242,
        created_at: chrono::Utc::now(),
        rootfs_path: img_dir.to_string_lossy().to_string(),
        config: ImageConfig {
            architecture: host_arch.to_string(),
            os: "linux".to_string(),
            config: None,
            rootfs: None,
            history: Vec::new(),
        },
    };
    store.add(record).unwrap();

    // Save, wipe the original, then load.
    let tar_path = home.path().join("testimg.tar");
    ImageArchiver::save_with_home("testimg:latest", Some(&tar_path), home.path(), false).unwrap();
    store.remove("testimg:latest").unwrap();
    assert!(store.find("testimg:latest").is_none());

    let loaded = ImageArchiver::load_from(Some(&tar_path), home.path()).unwrap();
    assert_eq!(loaded.len(), 1);
    let rec = &loaded[0];

    // Identity preserved.
    assert_eq!(rec.id, "aaa111bbb222");
    assert_eq!(rec.manifest_digest, "sha256:aaa");
    assert_eq!(rec.config_digest, "sha256:cfg");
    assert_eq!(rec.size_bytes, 4242);
    assert_eq!(rec.reference, "library/testimg");
    assert_eq!(rec.tag, "latest");

    // Rootfs restored with the symlink intact.
    let link_target =
        std::fs::read_link(Path::new(&rec.rootfs_path).join("bin").join("sh")).unwrap();
    assert_eq!(link_target, PathBuf::from("busybox"));
    assert!(
        Path::new(&rec.rootfs_path)
            .join("bin")
            .join("busybox")
            .exists()
    );
}
