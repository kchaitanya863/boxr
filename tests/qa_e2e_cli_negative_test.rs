#[path = "common/blackbox.rs"]
mod blackbox;

use std::path::PathBuf;
use std::process::Command;

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

#[test]
fn test_qa_cli_negative_inspect_nonexistent() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let output = Command::new(&bin)
        .args(["inspect", "non_existent_target_123456789_xyz"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "inspecting nonexistent container must fail"
    );
}

#[test]
fn test_qa_cli_negative_rm_nonexistent() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let output = Command::new(&bin)
        .args(["rm", "non_existent_container_abc"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "removing nonexistent container must fail"
    );
}

#[test]
fn test_qa_cli_negative_stop_nonexistent() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let output = Command::new(&bin)
        .args(["stop", "non_existent_container_xyz"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "stopping nonexistent container must fail"
    );
}

#[test]
fn test_qa_cli_negative_rename_nonexistent() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let output = Command::new(&bin)
        .args(["rename", "non_existent_target", "new_name"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "renaming nonexistent container must fail"
    );
}

#[test]
fn test_qa_cli_negative_invalid_flag() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let output = Command::new(&bin)
        .args(["run", "--invalid-nonexistent-flag", "alpine"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "running with unknown flag must fail"
    );
}

#[test]
fn test_qa_cli_negative_copy_invalid_syntax() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    // Neither src nor dest specifies container
    let output = Command::new(&bin)
        .args(["cp", "/host/path/a", "/host/path/b"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "cp without container specifier must fail"
    );
}
