use crate::network::PortMapping;
use crate::oci::runtime::Spec;
use crate::volume::MountSpec;
use anyhow::Result;
use std::path::Path;

/// Open/Closed Principle: Container runtime execution engine abstraction.
/// Enables extending Boxr with additional backends (e.g. Wasm, gVisor, Firecracker, mock test runners)
/// without modifying core container execution orchestration.
pub trait ContainerRuntime: Send + Sync {
    fn execute_bundle(
        &self,
        bundle_path: &Path,
        spec: &Spec,
        mounts: &[MountSpec],
        ports: &[PortMapping],
        detach: bool,
    ) -> Result<i32>;

    fn exec_in_bundle(
        &self,
        bundle_path: &Path,
        command: &[String],
        env: &[String],
        workdir: Option<&str>,
        user: Option<&str>,
        detach: bool,
        attach: super::ExecAttach,
        exec_pid_path: Option<&Path>,
    ) -> Result<i32>;
}

/// Native OS platform container runtime
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeContainerRuntime;

impl ContainerRuntime for NativeContainerRuntime {
    fn execute_bundle(
        &self,
        bundle_path: &Path,
        spec: &Spec,
        mounts: &[MountSpec],
        ports: &[PortMapping],
        detach: bool,
    ) -> Result<i32> {
        super::execute_bundle(bundle_path, spec, mounts, ports, detach, detach)
    }

    fn exec_in_bundle(
        &self,
        bundle_path: &Path,
        command: &[String],
        env: &[String],
        workdir: Option<&str>,
        user: Option<&str>,
        detach: bool,
        attach: super::ExecAttach,
        exec_pid_path: Option<&Path>,
    ) -> Result<i32> {
        super::exec_in_bundle(
            bundle_path,
            command,
            env,
            workdir,
            user,
            detach,
            attach,
            exec_pid_path,
        )
    }
}
