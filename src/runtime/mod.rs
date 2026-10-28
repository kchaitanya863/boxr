use std::path::Path;

pub mod checkpoint;
pub mod cp;
pub mod diff;
pub mod kill;
pub mod oci_hooks;
pub mod top;
pub mod traits;

pub use checkpoint::CheckpointManager;
pub use kill::{ContainerKiller, ProcessKiller};
pub use traits::{ContainerRuntime, NativeContainerRuntime};

/// Stdin/TTY attachment for `exec_in_bundle` (Podman `exec -i` / `exec -t`).
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecAttach {
    pub interactive: bool,
    pub tty: bool,
}

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::{bundle_process_is_alive, exec_in_bundle, execute_bundle};

#[cfg(target_os = "macos")]
pub mod darwin;
#[cfg(target_os = "macos")]
pub use darwin::{exec_in_bundle, execute_bundle};

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::{exec_in_bundle, execute_bundle};

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn execute_bundle(
    _bundle_path: &Path,
    _spec: &Spec,
    _mounts: &[MountSpec],
    _ports: &[PortMapping],
    _detach: bool,
    _spawn_detached_watcher: bool,
) -> Result<i32> {
    anyhow::bail!("Container execution is only supported on Linux, macOS, and Windows");
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn exec_in_bundle(
    _bundle_path: &Path,
    _command: &[String],
    _env: &[String],
    _workdir: Option<&str>,
    _user: Option<&str>,
    _detach: bool,
    _attach: ExecAttach,
    _exec_pid_path: Option<&Path>,
) -> Result<i32> {
    anyhow::bail!("Container execution is only supported on Linux, macOS, and Windows");
}
