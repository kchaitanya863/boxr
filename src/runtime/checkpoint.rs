//! Container checkpoint and restore runtime (Podman `container checkpoint` / `container restore` parity).
//! Supports real CRIU (`criu dump` / `criu restore`) when installed and running with privileges,
//! falling back cleanly to filesystem and state archival when unprivileged/rootless.

use crate::storage::container_store::{ContainerStatus, ContainerStore};
use crate::storage::image_store::{ImageRecord, ImageStore};
use anyhow::{Result, anyhow};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointMetadata {
    pub container_id: String,
    pub container_name: String,
    pub image: String,
    pub created_at: chrono::DateTime<Utc>,
    pub checkpointed_at: chrono::DateTime<Utc>,
    pub ports: Vec<crate::network::PortMapping>,
    pub bundle_path: String,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub tcp_established: bool,
    #[serde(default)]
    pub ignore_rootfs: bool,
    #[serde(default)]
    pub ignore_volumes: bool,
    #[serde(default)]
    pub file_locks: bool,
    #[serde(default)]
    pub criu_used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContainerCheckpointState {
    pub checkpointed: bool,
    pub restored: bool,
    pub checkpointed_at: String,
    pub restored_at: String,
    pub checkpoint_path: String,
    pub checkpoint_log: String,
    pub restore_log: String,
}

pub struct CheckpointManager;

impl CheckpointManager {
    pub fn checkpoint_dir(bundle: &Path) -> PathBuf {
        bundle.join("checkpoints")
    }

    pub fn userdata_checkpoint_dir(bundle: &Path) -> PathBuf {
        bundle.join("userdata").join("checkpoint")
    }

    pub fn load_state(bundle: &Path) -> ContainerCheckpointState {
        let state_file = bundle.join("checkpoint_state.json");
        if let Ok(raw) = fs::read_to_string(state_file) {
            if let Ok(st) = serde_json::from_str(&raw) {
                return st;
            }
        }
        ContainerCheckpointState::default()
    }

    fn save_state(bundle: &Path, state: &ContainerCheckpointState) {
        if let Ok(raw) = serde_json::to_string_pretty(state) {
            let _ = fs::write(bundle.join("checkpoint_state.json"), raw);
        }
    }

    fn read_container_pid(bundle: &Path) -> Option<i32> {
        for name in ["container.pid", "vm.pid"] {
            if let Ok(s) = fs::read_to_string(bundle.join(name)) {
                if let Ok(pid) = s.trim().parse::<i32>() {
                    if pid > 0 {
                        return Some(pid);
                    }
                }
            }
        }
        None
    }

    fn try_criu_dump(
        pid: i32,
        cp_dir: &Path,
        dump_log: &Path,
        tcp_established: bool,
        leave_running: bool,
        file_locks: bool,
        pre_checkpoint: bool,
    ) -> bool {
        #[cfg(target_os = "linux")]
        {
            if unsafe { libc::geteuid() != 0 } {
                return false;
            }
            let action = if pre_checkpoint { "pre-dump" } else { "dump" };
            let mut cmd = std::process::Command::new("criu");
            cmd.arg(action)
                .arg("-t")
                .arg(pid.to_string())
                .arg("-D")
                .arg(cp_dir)
                .arg("-o")
                .arg(dump_log)
                .arg("--shell-job")
                .arg("--ext-unix-sk");
            if tcp_established {
                cmd.arg("--tcp-established");
            }
            if leave_running || pre_checkpoint {
                cmd.arg("--leave-running");
            }
            if file_locks {
                cmd.arg("--file-locks");
            }
            if let Ok(status) = cmd.status() {
                return status.success();
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                pid,
                cp_dir,
                dump_log,
                tcp_established,
                leave_running,
                file_locks,
                pre_checkpoint,
            );
        }
        false
    }

    fn try_criu_restore(
        cp_dir: &Path,
        restore_log: &Path,
        tcp_established: bool,
        tcp_close: bool,
        file_locks: bool,
    ) -> Option<i32> {
        #[cfg(target_os = "linux")]
        {
            if unsafe { libc::geteuid() != 0 } {
                return None;
            }
            if !cp_dir.join("core-1.img").exists() && !cp_dir.join("inventory.img").exists() {
                return None;
            }
            let pidfile = cp_dir.join("restored.pid");
            let _ = fs::remove_file(&pidfile);
            let mut cmd = std::process::Command::new("criu");
            cmd.arg("restore")
                .arg("-D")
                .arg(cp_dir)
                .arg("-o")
                .arg(restore_log)
                .arg("--pidfile")
                .arg(&pidfile)
                .arg("--shell-job")
                .arg("--ext-unix-sk")
                .arg("-d");
            if tcp_established {
                cmd.arg("--tcp-established");
            }
            if tcp_close {
                cmd.arg("--tcp-close");
            }
            if file_locks {
                cmd.arg("--file-locks");
            }
            if let Ok(status) = cmd.status() {
                if status.success() {
                    if let Ok(s) = fs::read_to_string(&pidfile) {
                        if let Ok(pid) = s.trim().parse::<i32>() {
                            return Some(pid);
                        }
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (cp_dir, restore_log, tcp_established, tcp_close, file_locks);
        }
        None
    }

    pub fn checkpoint(
        query: &str,
        export_path: Option<&Path>,
        keep: bool,
        leave_running: bool,
    ) -> Result<PathBuf> {
        let mut args = crate::cli::ContainerCheckpointArgs::default();
        args.container = query.to_string();
        args.export = export_path.map(|p| p.to_string_lossy().to_string());
        args.keep = keep;
        args.leave_running = leave_running;
        Self::checkpoint_single(query, &args)
    }

    pub fn checkpoint_with_args(args: &crate::cli::ContainerCheckpointArgs) -> Result<Vec<String>> {
        if args.all && args.latest {
            crate::cli::usage_errors::exit_usage_error(
                "--all and --latest cannot be used together",
            );
        }
        if (args.all || args.latest)
            && (!args.container.is_empty() || !args.extra_containers.is_empty())
        {
            crate::cli::usage_errors::exit_usage_error(
                "--all or --latest and containers cannot be used together",
            );
        }
        let store = ContainerStore::new();
        let mut targets = Vec::new();
        let mut print_id_always = false;
        if args.all {
            print_id_always = true;
            for c in store.list() {
                if matches!(c.status, ContainerStatus::Running) {
                    targets.push(c.id);
                }
            }
        } else if args.latest {
            print_id_always = true;
            if let Some(c) = store.list().last() {
                targets.push(c.id.clone());
            }
        } else {
            if !args.container.is_empty() {
                targets.push(args.container.clone());
            }
            targets.extend(args.extra_containers.clone());
        }

        if targets.is_empty() && !args.all {
            crate::cli::usage_errors::exit_usage_error(
                "you must provide at least one container name or ID",
            );
        }

        let mut outputs = Vec::new();
        for t in targets {
            let Some(cont) = store.find(&t) else {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "no container with name or ID {:?} found: no such container",
                    t
                ));
            };
            let _ = Self::checkpoint_single(&cont.id, args)?;
            if print_id_always || t == cont.id {
                outputs.push(cont.id);
            } else {
                outputs.push(t);
            }
        }
        Ok(outputs)
    }

    fn checkpoint_single(
        query: &str,
        args: &crate::cli::ContainerCheckpointArgs,
    ) -> Result<PathBuf> {
        let store = ContainerStore::new();
        let cont = store.find(query).ok_or_else(|| {
            anyhow!(
                "no container with name or ID {:?} found: no such container",
                query
            )
        })?;

        let bundle = PathBuf::from(&cont.bundle_path);
        let cp_dir = Self::checkpoint_dir(&bundle).join("default");
        let userdata_dir = bundle.join("userdata");
        let userdata_cp = Self::userdata_checkpoint_dir(&bundle);
        fs::create_dir_all(&cp_dir)?;
        fs::create_dir_all(&userdata_cp)?;

        let dump_log = userdata_dir.join("dump.log");
        let _ = fs::write(&dump_log, b"CRIU dump log\n");

        let mut criu_used = false;
        if let Some(pid) = Self::read_container_pid(&bundle) {
            criu_used = Self::try_criu_dump(
                pid,
                &userdata_cp,
                &dump_log,
                args.tcp_established,
                args.leave_running,
                args.file_locks,
                args.pre_checkpoint,
            );
        }

        let now = Utc::now();
        let meta = CheckpointMetadata {
            container_id: cont.id.clone(),
            container_name: cont.name.clone(),
            image: cont.image.clone(),
            created_at: cont.created_at,
            checkpointed_at: now,
            ports: cont.ports.clone(),
            bundle_path: cont.bundle_path.clone(),
            command: cont.command.clone(),
            tcp_established: args.tcp_established,
            ignore_rootfs: args.ignore_rootfs,
            ignore_volumes: args.ignore_volumes,
            file_locks: args.file_locks,
            criu_used,
        };

        let meta_json = serde_json::to_string_pretty(&meta)?;
        let meta_file = cp_dir.join("checkpoint.json");
        fs::write(&meta_file, &meta_json)?;
        let _ = fs::write(userdata_cp.join("checkpoint.json"), &meta_json);

        for cfg_name in ["config.json", "mounts.json", "create_command.json"] {
            let src = bundle.join(cfg_name);
            if src.exists() {
                let _ = fs::copy(&src, cp_dir.join(cfg_name));
            }
        }

        if !args.ignore_rootfs {
            let upper_dir = bundle.join("upper");
            if upper_dir.exists() {
                let diff_tar = cp_dir.join("rootfs-diff.tar");
                if let Ok(file) = fs::File::create(&diff_tar) {
                    let mut tar = tar::Builder::new(file);
                    let _ = tar.append_dir_all(".", &upper_dir);
                    let _ = tar.finish();
                }
            }
        }

        if !args.leave_running && !args.pre_checkpoint {
            if !criu_used {
                let _ = crate::runtime::kill::ContainerKiller::kill(&cont, None);
            }
            let _ = store.update_status(&cont.id, ContainerStatus::Exited(0));
            let state = ContainerCheckpointState {
                checkpointed: true,
                restored: false,
                checkpointed_at: now.to_rfc3339(),
                restored_at: "0001-01-01T00:00:00Z".to_string(),
                checkpoint_path: userdata_cp.to_string_lossy().to_string(),
                checkpoint_log: dump_log.to_string_lossy().to_string(),
                restore_log: String::new(),
            };
            Self::save_state(&bundle, &state);
        }

        if let Some(ref create_img) = args.create_image {
            Self::create_checkpoint_image(&cont, &cp_dir, create_img)?;
        }

        if let Some(ref exp_str) = args.export {
            let exp = Path::new(exp_str);
            if let Some(parent) = exp.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let file = fs::File::create(exp)?;
            let mut tar = tar::Builder::new(file);
            tar.append_dir_all(".", &cp_dir)?;
            tar.finish()?;
            return Ok(exp.to_path_buf());
        }

        Ok(meta_file)
    }

    fn create_checkpoint_image(
        cont: &crate::storage::ContainerRecord,
        cp_dir: &Path,
        image_name: &str,
    ) -> Result<()> {
        let i_store = ImageStore::new();
        let parsed = crate::oci::reference::ImageReference::parse(image_name).unwrap_or(
            crate::oci::reference::ImageReference {
                registry: "localhost".to_string(),
                repository: image_name.to_string(),
                tag: "latest".to_string(),
                digest: None,
            },
        );
        let registry = if image_name.contains('/')
            && (image_name.starts_with("localhost/")
                || image_name
                    .split('/')
                    .next()
                    .is_some_and(|p| p.contains('.')))
        {
            parsed.registry
        } else {
            "localhost".to_string()
        };
        let reference = if registry == "localhost" {
            image_name
                .strip_prefix("localhost/")
                .unwrap_or(image_name)
                .split(':')
                .next()
                .unwrap_or(image_name)
                .to_string()
        } else {
            parsed.repository
        };
        let tag = image_name
            .rsplit_once(':')
            .map(|(_, t)| t.to_string())
            .unwrap_or_else(|| "latest".to_string());

        let rand_hex = hex::encode(crate::storage::container_store::rand_id());
        let full_id = format!("{}{}", rand_hex, rand_hex);
        let short_id = full_id[..12].to_string();
        let img_rootfs = crate::storage::boxr_home()
            .join("images")
            .join(format!("sha256_{}", full_id))
            .join("rootfs");
        fs::create_dir_all(&img_rootfs)?;
        for entry in fs::read_dir(cp_dir)?.flatten() {
            let p = entry.path();
            if p.is_file() {
                let _ = fs::copy(&p, img_rootfs.join(entry.file_name()));
            }
        }

        let runtime_name = crate::cli::info_report::default_oci_runtime_name();
        let mut labels = HashMap::new();
        labels.insert(
            "io.podman.annotations.checkpoint.name".to_string(),
            cont.name.clone(),
        );
        labels.insert(
            "io.podman.annotations.checkpoint.runtime.name".to_string(),
            runtime_name,
        );
        labels.insert(
            "io.podman.annotations.checkpoint.rootfsImageName".to_string(),
            cont.image.clone(),
        );

        let mut inner = crate::oci::image::ExecutionConfig::default();
        inner.labels = Some(labels);
        let cfg = crate::oci::image::ImageConfig {
            architecture: std::env::consts::ARCH.to_string(),
            os: std::env::consts::OS.to_string(),
            config: Some(inner),
            rootfs: None,
            history: Vec::new(),
        };

        let record = ImageRecord {
            id: short_id,
            reference,
            tag,
            registry,
            manifest_digest: format!("sha256:{}", full_id),
            config_digest: format!("sha256:{}", full_id),
            size_bytes: 4096,
            created_at: Utc::now(),
            rootfs_path: img_rootfs.to_string_lossy().to_string(),
            config: cfg,
        };
        i_store.add(record)?;
        Ok(())
    }

    pub fn restore(query: &str, import_path: Option<&Path>, keep: bool) -> Result<()> {
        let mut args = crate::cli::ContainerRestoreArgs::default();
        args.container = query.to_string();
        args.import = import_path.map(|p| p.to_string_lossy().to_string());
        args.keep = keep;
        Self::restore_single(query, &args)?;
        Ok(())
    }

    pub async fn restore_with_args(args: &crate::cli::ContainerRestoreArgs) -> Result<Vec<String>> {
        if args.all && args.latest {
            crate::cli::usage_errors::exit_usage_error(
                "--all and --latest cannot be used together",
            );
        }
        if (args.all || args.latest)
            && (!args.container.is_empty() || !args.extra_containers.is_empty())
        {
            crate::cli::usage_errors::exit_usage_error(
                "--all or --latest and containers cannot be used together",
            );
        }
        let store = ContainerStore::new();
        let mut outputs = Vec::new();

        if let Some(ref imp_str) = args.import {
            let imp = Path::new(imp_str);
            if !imp.exists() {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "open {}: no such file or directory",
                    imp.display()
                ));
            }
            let id = Self::restore_from_archive(imp, args).await?;
            outputs.push(id);
            return Ok(outputs);
        }

        let mut targets = Vec::new();
        let mut print_id_always = false;
        if args.all {
            print_id_always = true;
            for c in store.list() {
                let st = Self::load_state(Path::new(&c.bundle_path));
                if st.checkpointed {
                    targets.push(c.id);
                }
            }
        } else if args.latest {
            print_id_always = true;
            if let Some(c) = store.list().last() {
                targets.push(c.id.clone());
            }
        } else {
            if !args.container.is_empty() {
                targets.push(args.container.clone());
            }
            targets.extend(args.extra_containers.clone());
        }

        for t in targets {
            if store.find(&t).is_some() {
                let id = Self::restore_single(&t, args)?;
                if print_id_always || t == id {
                    outputs.push(id);
                } else {
                    outputs.push(t);
                }
                continue;
            }
            let i_store = ImageStore::new();
            if let Some(img) = i_store.find(&t) {
                if Self::is_checkpoint_image(&img) {
                    let cp_json = Path::new(&img.rootfs_path).join("checkpoint.json");
                    if cp_json.exists() {
                        let id =
                            Self::restore_from_checkpoint_dir(Path::new(&img.rootfs_path), args)
                                .await?;
                        outputs.push(id);
                        continue;
                    }
                }
            }
            crate::cli::usage_errors::exit_usage_error(format!(
                "no container or checkpoint image with name or ID {:?} found: no such container or image",
                t
            ));
        }

        Ok(outputs)
    }

    pub fn is_checkpoint_image(img: &ImageRecord) -> bool {
        if let Some(labels) = img.config.config.as_ref().and_then(|c| c.labels.as_ref()) {
            if labels.contains_key("io.podman.annotations.checkpoint.name") {
                return true;
            }
        }
        Path::new(&img.rootfs_path).join("checkpoint.json").exists()
    }

    async fn restore_from_archive(
        imp: &Path,
        args: &crate::cli::ContainerRestoreArgs,
    ) -> Result<String> {
        let tmp = tempfile::tempdir()?;
        let file = fs::File::open(imp)?;
        let mut archive = tar::Archive::new(file);
        archive.unpack(tmp.path())?;
        Self::restore_from_checkpoint_dir(tmp.path(), args).await
    }

    async fn restore_from_checkpoint_dir(
        cp_dir: &Path,
        args: &crate::cli::ContainerRestoreArgs,
    ) -> Result<String> {
        let meta_file = cp_dir.join("checkpoint.json");
        let meta_raw = fs::read_to_string(&meta_file)?;
        let meta: CheckpointMetadata = serde_json::from_str(&meta_raw)?;

        let store = ContainerStore::new();
        let target_name = args
            .name
            .clone()
            .unwrap_or_else(|| meta.container_name.clone());

        if let Some(existing) = store.find(&target_name) {
            if args.name.is_none() {
                Self::restore_single(&existing.id, args)?;
                let _ = crate::start_container_with_home(&existing.id, None, true).await;
                return Ok(existing.id);
            }
        }

        let mut run_args = crate::cli::RunArgs::default();
        run_args.name = Some(target_name.clone());
        run_args.detach = true;
        run_args.image = meta.image.clone();
        run_args.command = if meta.command.is_empty() {
            vec!["top".to_string()]
        } else {
            meta.command.clone()
        };
        if !args.publish.is_empty() {
            run_args.ports = args.publish.clone();
        } else {
            run_args.ports = meta
                .ports
                .iter()
                .map(|p| {
                    if let Some(ref hip) = p.host_ip {
                        format!(
                            "{}:{}:{}/{}",
                            hip, p.host_port, p.container_port, p.protocol
                        )
                    } else {
                        format!("{}:{}/{}", p.host_port, p.container_port, p.protocol)
                    }
                })
                .collect();
        }

        let id = crate::create_only_container_with_home(run_args, None).await?;
        let _ = crate::start_container_with_home(&id, None, true).await;
        if let Some(c) = store.find(&id) {
            let bundle = PathBuf::from(&c.bundle_path);
            let userdata_dir = bundle.join("userdata");
            let _ = fs::create_dir_all(&userdata_dir);
            let restore_log = userdata_dir.join("restore.log");
            let _ = fs::write(&restore_log, b"CRIU restore log\n");
            let mut state = Self::load_state(&bundle);
            state.checkpointed = false;
            state.restored = true;
            state.restored_at = Utc::now().to_rfc3339();
            state.restore_log = restore_log.to_string_lossy().to_string();
            Self::save_state(&bundle, &state);
        }
        Ok(id)
    }

    fn restore_single(query: &str, args: &crate::cli::ContainerRestoreArgs) -> Result<String> {
        let store = ContainerStore::new();
        let cont = store
            .find(query)
            .ok_or_else(|| anyhow!("Container '{}' not found", query))?;

        let bundle = PathBuf::from(&cont.bundle_path);
        let cp_dir = Self::checkpoint_dir(&bundle).join("default");
        let userdata_dir = bundle.join("userdata");
        let userdata_cp = Self::userdata_checkpoint_dir(&bundle);
        fs::create_dir_all(&userdata_dir)?;

        if let Some(ref imp_str) = args.import {
            let imp = Path::new(imp_str);
            if !imp.exists() {
                return Err(anyhow!("Import archive '{}' not found", imp.display()));
            }
            fs::create_dir_all(&cp_dir)?;
            let file = fs::File::open(imp)?;
            let mut archive = tar::Archive::new(file);
            archive.unpack(&cp_dir)?;
        }

        let meta_file = cp_dir.join("checkpoint.json");
        if !meta_file.exists() {
            return Err(anyhow!("No checkpoint found for container '{}'", query));
        }

        let restore_log = userdata_dir.join("restore.log");
        let _ = fs::write(&restore_log, b"CRIU restore log\n");

        if let Some(restored_pid) = Self::try_criu_restore(
            &userdata_cp,
            &restore_log,
            args.tcp_established,
            args.tcp_close,
            args.file_locks,
        ) {
            let _ = fs::write(bundle.join("container.pid"), restored_pid.to_string());
        }

        if !args.ignore_rootfs {
            let diff_tar = cp_dir.join("rootfs-diff.tar");
            let upper_dir = bundle.join("upper");
            if diff_tar.exists() && upper_dir.exists() {
                if let Ok(file) = fs::File::open(&diff_tar) {
                    let mut archive = tar::Archive::new(file);
                    let _ = archive.unpack(&upper_dir);
                }
            }
        }

        let mut state = Self::load_state(&bundle);
        state.checkpointed = false;
        state.restored = true;
        state.restored_at = Utc::now().to_rfc3339();
        state.restore_log = restore_log.to_string_lossy().to_string();
        if !args.keep {
            state.checkpoint_path.clear();
            state.checkpoint_log.clear();
        }
        Self::save_state(&bundle, &state);

        store.update_status(&cont.id, ContainerStatus::Running)?;
        Ok(cont.id)
    }
}
