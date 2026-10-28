use crate::runtime::exec_in_bundle;
use anyhow::Result;
use std::path::Path;

pub struct ContainerTop;

impl ContainerTop {
    pub fn list_processes(bundle_path: &Path, ps_args: &[String]) -> Result<String> {
        let mut cmd = vec!["/bin/ps".to_string()];
        if ps_args.is_empty() {
            cmd.push("-ef".to_string());
        } else {
            cmd.extend_from_slice(ps_args);
        }

        // Run ps in bundle
        let code = exec_in_bundle(
            bundle_path,
            &cmd,
            &[],
            None,
            None,
            false,
            crate::runtime::ExecAttach::default(),
            None,
            &[],
        )?;
        if code != 0 {
            // Fallback to simple ps without flags
            let fallback = vec!["ps".to_string()];
            let _ = exec_in_bundle(
                bundle_path,
                &fallback,
                &[],
                None,
                None,
                false,
                crate::runtime::ExecAttach::default(),
                None,
                &[],
            );
        }

        Ok("".to_string())
    }
}
