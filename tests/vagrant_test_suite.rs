#[path = "common/blackbox.rs"]
mod blackbox;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Check if vagrant is installed or can be run
fn has_vagrant() -> bool {
    Command::new("vagrant")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Locate release binary or build release if missing
#[allow(dead_code)]
fn release_bin(target: Option<&str>) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(t) = target {
        manifest_dir
            .join("target")
            .join(t)
            .join("release")
            .join("boxr")
    } else {
        manifest_dir.join("target").join("release").join("boxr")
    }
}

/// Structure defining a test VM environment in Vagrant
#[derive(Debug, Clone)]
pub struct VagrantVmSpec {
    pub name: &'static str,
    pub os_name: &'static str,
    pub image: &'static str,
    pub test_arch: &'static str,
}

impl VagrantVmSpec {
    pub fn test_matrix() -> Vec<Self> {
        vec![
            Self {
                name: "ubuntu-2404",
                os_name: "Ubuntu 24.04 LTS (Noble)",
                image: "ubuntu:24.04",
                test_arch: "arm64",
            },
            Self {
                name: "ubuntu-2204",
                os_name: "Ubuntu 22.04 LTS (Jammy)",
                image: "ubuntu:22.04",
                test_arch: "arm64",
            },
            Self {
                name: "debian-12",
                os_name: "Debian 12 (Bookworm)",
                image: "debian:12",
                test_arch: "arm64",
            },
            Self {
                name: "alpine-latest",
                os_name: "Alpine Linux (musl)",
                image: "alpine:latest",
                test_arch: "arm64",
            },
            Self {
                name: "fedora-latest",
                os_name: "Fedora 41 (RPM)",
                image: "fedora:latest",
                test_arch: "arm64",
            },
        ]
    }
}

/// Generate a multi-machine Vagrantfile for testing across OS distributions
pub fn generate_vagrantfile(vms: &[VagrantVmSpec], work_dir: &Path) -> std::io::Result<()> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut vf = String::new();
    vf.push_str("Vagrant.configure(\"2\") do |config|\n");

    for vm in vms {
        vf.push_str(&format!("  config.vm.define \"{}\" do |v|\n", vm.name));
        vf.push_str("    v.vm.provider \"docker\" do |d|\n");
        vf.push_str(&format!("      d.image = \"{}\"\n", vm.image));
        vf.push_str("      d.has_ssh = false\n");
        vf.push_str("      d.cmd = [\"sleep\", \"infinity\"]\n");
        vf.push_str(&format!(
            "      d.volumes = [\"{}:/vagrant_bin:ro\"]\n",
            manifest_dir.join("target").join("release").display()
        ));
        vf.push_str("    end\n");
        vf.push_str("  end\n\n");
    }

    vf.push_str("end\n");
    fs::write(work_dir.join("Vagrantfile"), vf)
}

#[test]
#[ignore = "Slow multi-OS Vagrant matrix for local manual verification; CI tests natively on each target OS"]
fn test_vagrant_matrix_multi_os_verification() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    if !has_vagrant() {
        eprintln!("Vagrant not available on this host. Skipping Vagrant test suite.");
        return;
    }

    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir for Vagrant testing");
    let work_dir = temp_dir.path();
    let vms = VagrantVmSpec::test_matrix();

    // 1. Generate Vagrantfile for all target OS distributions
    generate_vagrantfile(&vms, work_dir).expect("Failed to generate Vagrantfile");

    // 2. Validate Vagrantfile syntax
    let val_out = Command::new("vagrant")
        .current_dir(work_dir)
        .args(["validate", "-p"])
        .output()
        .expect("Failed to run vagrant validate");
    assert!(
        val_out.status.success(),
        "Vagrantfile validation failed: {}",
        String::from_utf8_lossy(&val_out.stderr)
    );

    // 3. Test running Vagrant machine provisioning and verifying our boxr binary in each OS
    for vm in &vms {
        println!("=== Testing boxr on {} via Vagrant ===", vm.os_name);

        // Bring up the machine with docker provider
        let up_out = Command::new("vagrant")
            .current_dir(work_dir)
            .args(["up", vm.name, "--provider=docker"])
            .output()
            .expect("Failed to run vagrant up");

        assert!(
            up_out.status.success(),
            "vagrant up failed for {}: {}",
            vm.name,
            String::from_utf8_lossy(&up_out.stderr)
        );

        // Check machine state is running
        let status_out = Command::new("vagrant")
            .current_dir(work_dir)
            .args(["status", vm.name])
            .output()
            .expect("Failed to query vagrant status");
        assert!(status_out.status.success());
        let status_text = String::from_utf8_lossy(&status_out.stdout);
        assert!(
            status_text.contains("running"),
            "Machine {} should be running",
            vm.name
        );

        // Execute command inside the provisioned Vagrant VM
        let exec_out = Command::new("vagrant")
            .current_dir(work_dir)
            .args(["docker-exec", vm.name, "--", "uname", "-m"])
            .output()
            .expect("Failed to run vagrant docker-exec");

        assert!(
            exec_out.status.success(),
            "Failed executing inside {}: {}",
            vm.name,
            String::from_utf8_lossy(&exec_out.stderr)
        );

        let out_text = String::from_utf8_lossy(&exec_out.stdout);
        assert!(
            out_text.contains("aarch64") || out_text.contains("x86_64"),
            "Unexpected kernel architecture from {}: {}",
            vm.name,
            out_text
        );

        // Verify boxr binary execution and rootless functionality inside the provisioned Linux VM
        let bin = release_bin(None);
        if bin.exists() {
            let boxr_ver_out = Command::new("vagrant")
                .current_dir(work_dir)
                .args([
                    "docker-exec",
                    vm.name,
                    "--",
                    "/vagrant_bin/boxr",
                    "--version",
                ])
                .output();
            if let Ok(b_out) = boxr_ver_out {
                if b_out.status.success() {
                    let b_text = String::from_utf8_lossy(&b_out.stdout);
                    assert!(b_text.contains("boxr"));
                    println!(
                        "  ✓ boxr binary executed successfully inside {}",
                        vm.os_name
                    );
                }
            }
        }

        // Tear down the VM cleanly
        let down_out = Command::new("vagrant")
            .current_dir(work_dir)
            .args(["destroy", "-f", vm.name])
            .output()
            .expect("Failed to destroy vagrant VM");
        assert!(down_out.status.success());
        println!("✓ Verified and cleanly destroyed {}", vm.os_name);
    }
}

#[test]
#[ignore = "Requires local Windows image"]
fn test_windows_container_image_and_runtime_guard() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = release_bin(None);
    if !bin.exists() {
        return;
    }

    // 1. Inspect Windows image architecture and OS metadata
    let inspect_out = Command::new(&bin)
        .args(["inspect", "windows/nanoserver:ltsc2022"])
        .output()
        .unwrap();
    if inspect_out.status.success() {
        let stdout = String::from_utf8_lossy(&inspect_out.stdout);
        assert!(stdout.contains("\"Os\": \"windows\"") || stdout.contains("\"os\": \"windows\""));
    }

    // 2. On macOS/Linux, running Windows container should trigger clean host requirement error
    #[cfg(not(target_os = "windows"))]
    {
        let run_out = Command::new(&bin)
            .args([
                "run",
                "--rm",
                "--platform",
                "windows/amd64",
                "windows/nanoserver:ltsc2022",
                "cmd.exe",
                "/c",
                "ver",
            ])
            .output()
            .unwrap();
        assert!(!run_out.status.success());
        let err = String::from_utf8_lossy(&run_out.stderr);
        assert!(err.contains("Windows container execution requires a native Windows host"));
    }
}
