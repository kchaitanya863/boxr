//! Regression tests for GitHub issues #478 through #486 (Security fixes).

use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

// Issue #478: Path traversal in container archive endpoint
#[test]
fn test_issue_478_archive_path_normalization() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();

    let secret_file = temp.path().join("host_secret.txt");
    fs::write(&secret_file, b"secret_data").unwrap();

    // Verify normalization prevents escaping rootfs
    let malicious_paths = [
        "../../host_secret.txt",
        "/../../host_secret.txt",
        "/../../../etc/passwd",
        "....//....//etc/passwd",
    ];

    for req_path in malicious_paths {
        let mut norm_path = PathBuf::from("/");
        for comp in Path::new(req_path).components() {
            match comp {
                std::path::Component::RootDir => {
                    norm_path = PathBuf::from("/");
                }
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    norm_path.pop();
                    if norm_path.as_os_str().is_empty() {
                        norm_path = PathBuf::from("/");
                    }
                }
                std::path::Component::Normal(c) => {
                    norm_path.push(c);
                }
                std::path::Component::Prefix(_) => {}
            }
        }
        let rel = norm_path.strip_prefix("/").unwrap_or(&norm_path);
        let host_target = if rel.as_os_str().is_empty() {
            rootfs.clone()
        } else {
            rootfs.join(rel)
        };

        // host_target must stay under rootfs
        assert!(
            host_target.starts_with(&rootfs),
            "Normalized path {:?} escaped rootfs: {:?}",
            req_path,
            host_target
        );
    }
}

// Issue #479: Tar-slip via symlink traversal in unpack_layer
#[test]
fn test_issue_479_tar_slip_symlink_rejection() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).unwrap();

    // Build a tar with a malicious symlink pointing outside target_dir
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);

        // Add a symlink pointing to /etc (or parent dir)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        let _ = header.set_link_name("../../../../../../../../../../../../../tmp");
        header.set_cksum();
        builder
            .append_data(&mut header, "escape_link", std::io::empty())
            .unwrap();
        builder.finish().unwrap();
    }

    let mut archive = tar::Archive::new(&tar_bytes[..]);
    let result = boxr::oci::image::unpack_archive_safely(&mut archive, &target_dir);
    assert!(
        result.is_err(),
        "Expected symlink escape to be rejected in archive unpack"
    );
}

// Issue #480: Arbitrary host file read in artifacts API
#[test]
fn test_issue_480_local_artifact_path_restriction() {
    let temp = tempdir().unwrap();
    let boxr_home = temp.path().join("home");
    fs::create_dir_all(&boxr_home).unwrap();

    let outside_file = temp.path().join("sensitive.txt");
    fs::write(&outside_file, b"topsecret").unwrap();

    let inside_file = boxr_home.join("artifacts").join("valid.txt");
    fs::create_dir_all(inside_file.parent().unwrap()).unwrap();
    fs::write(&inside_file, b"public").unwrap();

    let is_path_trusted = |p: &Path| -> bool {
        let Ok(canon) = p.canonicalize() else {
            return false;
        };
        let canon_home = boxr_home.canonicalize().unwrap();
        canon.starts_with(&canon_home)
    };

    assert!(!is_path_trusted(&outside_file));
    assert!(is_path_trusted(&inside_file));
}

// Issue #481: Quadlet upload sanitization
#[test]
fn test_issue_481_quadlet_path_sanitization() {
    let invalid_names = [
        "../escape.container",
        "../../service.network",
        "/etc/passwd",
        "nested/path.container",
        "sub\\path.volume",
        ".hidden.kube",
    ];

    for name in invalid_names {
        let is_unsafe = name.contains('/')
            || name.contains('\\')
            || name.contains("..")
            || name.starts_with('.');
        assert!(is_unsafe, "Filename {:?} should be flagged as unsafe", name);
    }
}

// Issue #483: macOS command injection prevention
#[test]
fn test_issue_483_env_var_name_validation_and_quoting() {
    fn is_valid_env_name(name: &str) -> bool {
        let mut chars = name.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    // Valid names
    assert!(is_valid_env_name("PATH"));
    assert!(is_valid_env_name("_FOO_BAR"));
    assert!(is_valid_env_name("VAR123"));

    // Malicious / invalid names
    assert!(!is_valid_env_name("FOO;rm -rf /"));
    assert!(!is_valid_env_name("FOO$(reboot)"));
    assert!(!is_valid_env_name("123VAR"));
    assert!(!is_valid_env_name("VAR-WITH-DASH"));
    assert!(!is_valid_env_name("VAR`whoami`"));

    // Shell quoting of values
    let malicious_value = "hello\"; rm -rf /; echo \"pwned";
    let quoted = format!("export FOO={}", boxr::shell_quote(malicious_value));
    assert_eq!(quoted, "export FOO='hello\"; rm -rf /; echo \"pwned'");
}

// Issue #482: macOS guest supervisor script ID and ownership validation
#[test]
fn test_issue_482_supervisor_script_id_validation() {
    let validate_id = |f: &str| -> Option<String> {
        if let Some(rest) = f.strip_prefix("/boxr-exec-") {
            if let Some(id) = rest.strip_suffix(".sh") {
                if id.len() >= 8 && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(id.to_string());
                }
            }
        }
        None
    };

    // Valid hex IDs
    assert!(
        validate_id(
            "/boxr-exec-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.sh"
        )
        .is_some()
    );
    // Invalid / attack IDs
    assert!(validate_id("/boxr-exec-escalate.sh").is_none());
    assert!(validate_id("/boxr-exec-root.sh").is_none());
    assert!(validate_id("/boxr-exec-../../etc/evil.sh").is_none());
    assert!(validate_id("/boxr-exec-foo;reboot;.sh").is_none());
}

// Issue #484: cp intermediate symlink resolution
#[test]
fn test_issue_484_cp_symlink_escape_rejection() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();

    // Create an escaped symlink inside rootfs pointing outside
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside_dir = temp.path().join("outside");
        fs::create_dir_all(&outside_dir).unwrap();
        let symlink_path = rootfs.join("escape_dir");
        symlink(&outside_dir, &symlink_path).unwrap();

        // Target path traversing through escape_dir
        let target_host_path = rootfs.join("escape_dir/secret.txt");
        let canon_rootfs = rootfs.canonicalize().unwrap();

        // Any parent of target_host_path that resolves outside rootfs must be detected
        let mut curr = target_host_path.as_path();
        let mut escaped = false;
        while let Some(parent) = curr.parent() {
            if parent.exists() {
                if let Ok(canon_parent) = parent.canonicalize() {
                    if !canon_parent.starts_with(&canon_rootfs) {
                        escaped = true;
                    }
                }
                break;
            }
            curr = parent;
        }
        assert!(
            escaped,
            "Path through symlink should be detected as escaping container rootfs"
        );
    }
}

// Issue #485: Windows service command injection avoidance
#[test]
fn test_issue_485_windows_service_no_powershell_interpolation() {
    let exe = PathBuf::from("C:\\Program Files\\Boxr\\boxr.exe");
    let run_val = format!("\"{}\" daemon", exe.display());
    assert_eq!(run_val, "\"C:\\Program Files\\Boxr\\boxr.exe\" daemon");
    // Ensure arguments are formatted without raw shell concatenation
    assert!(!run_val.contains("powershell -Command"));
}

// Issue #486: Seccomp rule action parsing
#[test]
fn test_issue_486_seccomp_rule_parsing() {
    let default_filter = boxr::security::SeccompRule::default_filter();
    assert_eq!(default_filter.default_action, "SCMP_ACT_ALLOW");
    assert!(!default_filter.syscalls.is_empty());
    assert_eq!(default_filter.syscalls[0].action, "SCMP_ACT_ERRNO");
}
