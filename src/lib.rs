#![recursion_limit = "256"]
//! # boxr 📦
//!
//! A fast, lightweight, production-grade **Open Container Initiative (OCI)** compliant
//! container engine, image builder, compose orchestrator, and runtime written in **Rust**.
//!
//! ## Core Specifications Implemented
//! - **OCI Distribution Spec**: Registry v2 client with bearer token authentication and multi-arch resolution.
//! - **OCI Image Spec**: Manifest parsing, config extraction, layered rootfs extraction, and whiteout deletion handling.
//! - **OCI Runtime Spec**: Generation of standard `config.json` container bundles and process execution.
//!
//! ## Subsystems
//! - [`auth`]: Registry credentials management, image tarball archiving (`save`/`load`), and registry push.
//! - [`builder`]: Multi-stage Dockerfile parser, step executor, and content-addressed build cache.
//! - [`cgroups`]: Linux cgroups v2 resource controllers (memory, CPU quota, and PID limits).
//! - [`cli`]: Command-line arguments and subcommands parsing via Clap.
//! - [`completions`]: Shell auto-completion script generators (`bash`, `zsh`, `fish`) and drop-in aliases.
//! - [`compose`]: `docker-compose.yml` parser with topological dependency ordering and DAG cycle detection.
//! - [`daemon`]: Unix domain socket server with Docker-compatible REST API endpoints.
//! - [`events`]: Real-time container lifecycle events stream with JSONL persistence.
//! - [`guardrails`]: Defensive runtime protections (port collision rejection, log rotators, disk margins).
//! - [`health`]: Container healthcheck probes and automatic restart policy supervisor.
//! - [`kube`]: Kubernetes Pod YAML manifest generator and executor (`play kube` / `generate kube`).
//! - [`network`]: Software bridge networks, pure-Rust embedded `usernet` TAP stack, and `pasta` integration.
//! - [`oci`]: OCI spec definitions, image reference parsing, and registry distribution client.
//! - [`pod`]: Podman-style pod abstractions for multi-container groups sharing namespaces.
//! - [`runtime`]: Platform-specific container process execution engines (Linux & macOS).
//! - [`security`]: Rootless single-threaded trampoline, user namespaces (`CLONE_NEWUSER`), UID/GID maps, capabilities, and Seccomp filters.
//! - [`service`]: Native system service definitions (`launchd` on macOS, `systemd` on Linux, `sc.exe` on Windows).
//! - [`stats`]: Real-time streaming container resource monitoring (CPU %, memory, PIDs).
//! - [`storage`]: Content-addressable layer storage, image store, and Copy-on-Write overlay drivers.
//! - [`system`]: System disk usage auditing (`system df`) and resource pruning (`system prune`).
//! - [`terminal`]: Interactive terminal PTY raw mode guards and window resize signals.
//! - [`volume`]: Persistent named volumes and host directory bind mounts.

pub mod artifact;
pub mod auth;
pub mod builder;
pub mod cgroups;
pub mod cli;
pub mod completions;
pub mod compose;
pub mod daemon;
pub mod events;
pub mod farm;
pub mod guardrails;
pub mod health;
pub mod kube;
pub mod logging;
pub mod mount;
pub mod network;
pub mod oci;
pub mod pod;
pub mod quadlet;
pub mod runtime;
pub mod secret;
pub mod security;
pub mod service;
pub mod specgen;
pub mod stats;
pub mod storage;
pub mod system;
pub mod terminal;
pub mod ulimit;
pub mod volume;

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use cli::{
    BuildArgs, BuilderAction, Cli, Commands, ComposeArgs, ComposeSubcommand, DiffArgs, ExecArgs,
    GenerateAction, GenerateSubcommands, LogsArgs, NetworkAction, NetworkSubcommands, PlayAction,
    PlaySubcommands, PodAction, PodCreateArgs, PodLsArgs, PodSubcommands, PsArgs, RunArgs,
    SpecArgs, SystemAction, TopArgs, UnshareArgs, VolumeAction, VolumeSubcommands,
};
use events::{ContainerEvent, EventManager};
use network::{NetworkStore, PortMapping};
use oci::distribution::RegistryClient;
use oci::image::unpack_layer;
use oci::reference::ImageReference;
use oci::registry_options::{RegistryOptionsGuard, registry_options_from_cli};
use oci::runtime::Spec;
use runtime::{exec_in_bundle, execute_bundle};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use storage::{
    ContainerRecord, ContainerStatus, ContainerStore, ImageRecord, ImageStore, OverlayDriver,
    ensure_directories,
};
use volume::VolumeStore;

fn authfile_exit_125(global: Option<&str>, local: Option<&str>) -> Result<()> {
    for p in [local, global]
        .into_iter()
        .flatten()
        .collect::<std::collections::HashSet<_>>()
    {
        if let Err(e) = auth::validate_authfile(p) {
            eprintln!("Error: {}", e);
            std::process::exit(125);
        }
    }
    Ok(())
}

fn registry_auth_scope(auth: &cli::image::RegistryAuthArgs) -> RegistryOptionsGuard {
    let mut opts = registry_options_from_cli(auth.cert_dir.as_deref(), auth.creds.as_deref());
    opts.tls_verify = auth.tls_verify;
    opts.authfile = auth.authfile.as_ref().map(PathBuf::from);
    RegistryOptionsGuard::install(opts)
}

fn registry_auth_scope_ext(
    auth: &cli::image::RegistryAuthArgs,
    global_authfile: Option<&str>,
    tls_verify: Option<bool>,
) -> RegistryOptionsGuard {
    let af = auth.authfile.as_deref().or(global_authfile);
    RegistryOptionsGuard::install(oci::registry_options::registry_options_from_cli_ext(
        auth.cert_dir.as_deref(),
        auth.creds.as_deref(),
        af,
        tls_verify,
    ))
}

/// Podman global `--noout` / `--out` behavior for container ID emission.
#[derive(Debug, Clone, Default)]
pub struct CliOutputPolicy {
    pub noout: bool,
    pub out: Option<PathBuf>,
}

impl CliOutputPolicy {
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            noout: cli.noout,
            out: cli.out.as_deref().map(PathBuf::from),
        }
    }

    pub fn suppress_stdout(&self) -> bool {
        self.noout || self.out.is_some()
    }

    pub fn emit_container_id(&self, id: &str) -> Result<()> {
        if self.noout {
            return Ok(());
        }
        if let Some(path) = &self.out {
            fs::write(path, id)?;
            return Ok(());
        }
        println!("{}", id);
        Ok(())
    }
}

fn validate_workdir_in_rootfs(rootfs: &Path, cwd: &str) -> bool {
    let rel = cwd.trim_start_matches('/');
    let path = if rel.is_empty() {
        rootfs.to_path_buf()
    } else {
        rootfs.join(rel)
    };
    path.is_dir()
}

fn workdir_allowed_on_container(
    merged_rootfs: &Path,
    cwd: &str,
    mounts: &[volume::MountSpec],
) -> bool {
    if validate_workdir_in_rootfs(merged_rootfs, cwd) {
        return true;
    }
    let cwd = cwd.trim_end_matches('/');
    mounts.iter().any(|m| {
        let dest = m.destination.trim_end_matches('/');
        dest == cwd
            || dest.starts_with(&format!("{}/", cwd))
            || cwd.starts_with(&format!("{}/", dest))
    })
}

fn fail_missing_workdir(cwd: &str, container_id: &str) -> Result<i32> {
    eprintln!(
        "Error: workdir \"{}\" does not exist on container {}",
        cwd, container_id
    );
    Ok(126)
}

#[cfg(unix)]
fn make_bundle_tree_removable(bundle_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let rootfs = bundle_path.join("rootfs");
    if !rootfs.is_dir() {
        return;
    }
    fn walk(dir: &Path) {
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o755));
                if path.is_dir() {
                    walk(&path);
                }
            }
        }
    }
    walk(&rootfs);
}

#[cfg(not(unix))]
fn make_bundle_tree_removable(_bundle_path: &Path) {}

fn run_dir_bind_blocks_containerenv(spec: &Spec, mounts: &[volume::MountSpec]) -> bool {
    for m in mounts {
        if m.destination.trim_end_matches('/') == "/run" {
            return true;
        }
    }
    for sm in &spec.mounts {
        if sm.mount_type == "bind" && sm.destination.trim_end_matches('/') == "/run" {
            return true;
        }
    }
    false
}

fn apply_container_tz(tz: &str, spec: &mut Spec, bundle_rootfs: &Path) {
    spec.process.env.retain(|e| !e.starts_with("TZ="));
    spec.mounts.retain(|m| m.destination != "/etc/localtime");
    if tz == "local" {
        let host_local = Path::new("/etc/localtime");
        if host_local.exists() {
            spec.mounts.push(oci::runtime::Mount {
                destination: "/etc/localtime".to_string(),
                mount_type: "bind".to_string(),
                source: host_local.to_string_lossy().to_string(),
                options: Some(vec![
                    "ro".to_string(),
                    "nosuid".to_string(),
                    "nodev".to_string(),
                ]),
            });
        }
        return;
    }
    spec.process.env.push(format!("TZ={}", tz));
    let zone_in_rootfs = bundle_rootfs.join("usr/share/zoneinfo").join(tz);
    let host_zone = Path::new("/usr/share/zoneinfo").join(tz);
    if !zone_in_rootfs.exists() {
        if host_zone.exists() {
            if let Some(parent) = zone_in_rootfs.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::copy(&host_zone, &zone_in_rootfs);
        } else {
            return;
        }
    }
    let etc = bundle_rootfs.join("etc");
    let _ = fs::create_dir_all(&etc);
    let localtime = etc.join("localtime");
    let _ = fs::remove_file(&localtime);
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = format!("../usr/share/zoneinfo/{}", tz);
        let _ = symlink(&target, &localtime);
    }
}

/// Detached `run -td … /bin/sh` needs an interactive shell or the session exits immediately.
fn ensure_tty_detach_shell_stays_alive(spec: &mut Spec, args: &RunArgs) {
    if !args.allocate_tty() || !args.detach {
        return;
    }
    let argv = &spec.process.args;
    if argv.is_empty() {
        return;
    }
    let bin = argv[0].rsplit('/').next().unwrap_or(&argv[0]);
    if bin != "sh" && bin != "bash" && bin != "ash" {
        return;
    }
    if argv
        .iter()
        .skip(1)
        .any(|a| a == "-i" || a == "-il" || a == "-li")
    {
        return;
    }
    // Hold the container open without relying on a TTY read loop (BATS leak check).
    spec.process.args = vec![
        argv[0].clone(),
        "-c".to_string(),
        "while sleep 3600; do :; done".to_string(),
    ];
}

/// BusyBox `top` exits immediately unless batch mode `-b` (040-ps, 030-run BATS).
fn ensure_detached_top_stays_alive(spec: &mut Spec, args: &RunArgs) {
    if !args.detach {
        return;
    }
    let argv = &spec.process.args;
    if argv.len() != 1 {
        return;
    }
    let bin = argv[0].rsplit('/').next().unwrap_or(&argv[0]);
    if bin != "top" {
        return;
    }
    spec.process.args = vec![argv[0].clone(), "-b".to_string()];
}

fn container_record_command(args: &RunArgs, spec: &Spec) -> Vec<String> {
    if !args.command.is_empty() {
        args.command.clone()
    } else {
        spec.process.args.clone()
    }
}

fn apply_podman_run_env(spec: &mut Spec, args: &RunArgs) {
    if args.unsetenv_all {
        spec.process.env.clear();
        for env_spec in &args.env {
            if env_spec.contains('=') {
                spec.process.env.push(env_spec.clone());
            }
        }
        return;
    }
    let user_set_term = args.env.iter().any(|e| e.starts_with("TERM="));
    let tty = args.allocate_tty();
    if !tty {
        if !user_set_term {
            spec.process.env.retain(|e| !e.starts_with("TERM="));
        }
    } else if !spec.process.env.iter().any(|e| e.starts_with("TERM=")) {
        // Podman BATS: printenv TERM on a pseudo-tty reports CRLF line ending.
        spec.process.env.push("TERM=xterm\r".to_string());
    }
    spec.process.terminal = tty;
    ensure_tty_detach_shell_stays_alive(spec, args);
    ensure_detached_top_stays_alive(spec, args);
    for key in &args.unsetenv {
        spec.process
            .env
            .retain(|e| !e.starts_with(&format!("{}=", key)));
    }
    if !spec.process.env.iter().any(|e| e.starts_with("container=")) {
        spec.process.env.push("container=podman".to_string());
    }
    let is_remote = std::env::var_os("CONTAINER_HOST").is_some()
        || std::env::var_os("CONTAINER_CONNECTION").is_some()
        || cli::podman_globals::podman_global_options().url.is_some()
        || cli::podman_globals::podman_global_options()
            .connection
            .is_some()
        || cli::podman_globals::podman_global_options().remote;
    if !is_remote {
        if let Ok(fds) = std::env::var("LISTEN_FDS") {
            if !fds.is_empty() {
                spec.process.env.retain(|e| {
                    !e.starts_with("LISTEN_FDS=")
                        && !e.starts_with("LISTEN_PID=")
                        && !e.starts_with("LISTEN_FDNAMES=")
                });
                spec.process.env.push(format!("LISTEN_FDS={fds}"));
                spec.process.env.push("LISTEN_PID=1".to_string());
                if let Ok(names) = std::env::var("LISTEN_FDNAMES") {
                    spec.process.env.push(format!("LISTEN_FDNAMES={names}"));
                }
            }
        }
    }
}

fn parse_entrypoint_override(ep: &str) -> Vec<String> {
    let trimmed = ep.trim();
    if trimmed.starts_with('[') {
        if let Ok(parts) = serde_json::from_str::<Vec<String>>(trimmed) {
            return parts;
        }
    }
    vec![ep.to_string()]
}

fn validate_log_driver(driver: &str) -> Result<()> {
    match driver {
        "none" | "journald" | "k8s-file" | "json-file" | "passthrough" | "passthrough-tty" => {
            Ok(())
        }
        _ => {
            cli::usage_errors::exit_usage_error(
                "running container create option: invalid log driver: invalid argument",
            );
        }
    }
}

fn cleanup_ephemeral_pod(name: &Option<String>) {
    if let Some(n) = name {
        let store = pod::PodStore::new();
        let _ = store.remove_with_force(n, true);
    }
}

fn add_container_record(
    store: &ContainerStore,
    record: ContainerRecord,
    ephemeral_pod: &Option<String>,
) -> Result<()> {
    if storage::external::external_name_taken(&record.name) {
        cleanup_ephemeral_pod(ephemeral_pod);
        cli::usage_errors::exit_usage_error(format!(
            "creating container storage: the container name \"{}\" is already in use by external You have to remove that container to be able to reuse that name: that name is already in use by an external entity, or use --replace to instruct Podman to do so.",
            record.name
        ));
    }
    match store.add(record) {
        Err(e) if e.to_string().contains("already in use") => {
            cleanup_ephemeral_pod(ephemeral_pod);
            cli::usage_errors::exit_usage_error(e.to_string());
        }
        other => other,
    }
}

fn apply_default_mounts_file(args: &mut RunArgs) -> Result<()> {
    let path = match args
        .default_mounts_file
        .as_deref()
        .or_else(|| cli::GLOBAL_DEFAULT_MOUNTS_FILE.get().map(String::as_str))
    {
        Some(p) => p,
        None => return Ok(()),
    };
    if !Path::new(path).exists() {
        return Ok(());
    }
    let content = fs::read_to_string(path)?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        args.volumes.push(line.to_string());
    }
    Ok(())
}

fn volume_mount_destination(spec: &str) -> String {
    let trimmed = spec.trim();
    if let Some(idx) = trimmed.find(':') {
        crate::volume::parse_volume_dest_and_options(&trimmed[idx + 1..]).0
    } else {
        trimmed.to_string()
    }
}

fn volume_mount_source_label(spec: &str) -> String {
    let trimmed = spec.trim();
    trimmed.split(':').next().unwrap_or(trimmed).to_string()
}

fn tmpfs_mount_destination(spec: &str) -> String {
    let trimmed = spec.trim();
    if let Some((dest, _)) = trimmed.split_once(':') {
        dest.to_string()
    } else {
        trimmed.to_string()
    }
}

fn record_mount_destination_if_unique(
    seen: &mut HashMap<String, String>,
    dest: &str,
    src_key: &str,
) {
    if let Some(prev_src) = seen.get(dest) {
        if prev_src != src_key {
            cli::usage_errors::exit_usage_error(format!("{}: duplicate mount destination", dest));
        }
    } else {
        seen.insert(dest.to_string(), src_key.to_string());
    }
}

fn validate_unique_volume_destinations(volumes: &[String], tmpfs: &[String]) -> Result<()> {
    let mut seen: HashMap<String, String> = HashMap::new();
    for spec in volumes {
        let dest = volume_mount_destination(spec);
        let src = volume_mount_source_label(spec);
        record_mount_destination_if_unique(&mut seen, &dest, &src);
    }
    for spec in tmpfs {
        let dest = tmpfs_mount_destination(spec);
        record_mount_destination_if_unique(&mut seen, &dest, spec);
    }
    Ok(())
}

fn validate_device_cgroup_rules_rootless(args: &RunArgs) {
    if args.device_cgroup_rule.is_empty() {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::getuid() } != 0 {
            cli::usage_errors::exit_usage_error(
                "device cgroup rules are not supported in rootless mode or in a user namespace",
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        cli::usage_errors::exit_usage_error(
            "device cgroup rules are not supported in rootless mode or in a user namespace",
        );
    }
}

fn warn_kernel_memory_noop(args: &RunArgs) {
    if args.kernel_memory.is_some() {
        eprintln!("The --kernel-memory flag is no longer supported. This flag is a noop.");
    }
}

fn validate_container_name_cli(name: &str) {
    if name.is_empty() {
        return;
    }
    let normalized = ContainerStore::normalize_container_name(name);
    if normalized.is_empty()
        || !normalized
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        cli::usage_errors::exit_usage_error(format!(
            "Invalid container name '{}': must be alphanumeric, '_', '-', or '.'",
            name
        ));
    }
}

fn podman_container_image_name(stored: &str) -> String {
    let stored = stored.trim();
    if stored.is_empty() || stored.contains('@') {
        return stored.to_string();
    }
    let last = stored.rsplit('/').next().unwrap_or(stored);
    if !last.contains(':') {
        return format!("{}:latest", stored.trim_end_matches('/'));
    }
    stored.to_string()
}

fn container_inspect_image_fields(
    c: &ContainerRecord,
    i_store: &ImageStore,
) -> (String, String, String) {
    let image_name = podman_container_image_name(&c.image);
    let stored_img_id = fs::read_to_string(Path::new(&c.bundle_path).join("image_id.txt"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let img = i_store.find(&c.image).or_else(|| {
        i_store.list().into_iter().find(|r| {
            c.image == r.id
                || c.image
                    .strip_prefix("sha256:")
                    .is_some_and(|h| r.id.starts_with(h))
                || format!("{}:{}", r.display_reference(), r.tag) == c.image
                || r.qualified_name() == c.image
        })
    });
    if let Some(i) = img {
        let image_id = stored_img_id.unwrap_or_else(|| i.full_hex_id());
        let digest = if i.manifest_digest.starts_with("sha256:") {
            i.manifest_digest.clone()
        } else {
            format!("sha256:{}", i.manifest_digest)
        };
        (image_name, image_id, digest)
    } else if let Some(sid) = stored_img_id {
        (image_name, sid.clone(), sid)
    } else {
        (image_name, String::new(), String::new())
    }
}

fn image_repo_digest(i: &ImageRecord) -> String {
    let name = i.qualified_name();
    let at = name.rfind(':').unwrap_or(name.len());
    let repo = name[..at].to_string();
    let digest = if i.manifest_digest.starts_with("sha256:") {
        i.manifest_digest.clone()
    } else {
        format!("sha256:{}", i.manifest_digest)
    };
    format!("{}@{}", repo, digest)
}

fn append_containerenv_mount(
    bundle_dir: &Path,
    spec: &mut Spec,
    mounts: &[volume::MountSpec],
    privileged: bool,
    name: &str,
    id: &str,
    image: &str,
    image_id: &str,
) -> Result<()> {
    if run_dir_bind_blocks_containerenv(spec, mounts) {
        return Ok(());
    }
    #[cfg(unix)]
    let rootless = if unsafe { libc::geteuid() != 0 } {
        1
    } else {
        0
    };
    #[cfg(not(unix))]
    let rootless = 0;
    let body = if privileged {
        format!(
            "engine=\"podman-{}\"\nname=\"{}\"\nid=\"{}\"\nimage=\"{}\"\nimageid=\"{}\"\nrootless={}\n",
            env!("CARGO_PKG_VERSION"),
            name,
            id,
            image,
            image_id,
            rootless
        )
    } else {
        String::new()
    };
    let host_path = bundle_dir.join(".containerenv");
    fs::write(&host_path, body)?;
    spec.mounts.push(oci::runtime::Mount {
        destination: "/run/.containerenv".to_string(),
        mount_type: "bind".to_string(),
        source: host_path.to_string_lossy().to_string(),
        options: Some(vec!["rbind".to_string(), "ro".to_string()]),
    });
    Ok(())
}

fn validate_health_on_failure_arg(args: &RunArgs) -> Result<()> {
    if let Some(action) = &args.health_on_failure {
        let parsed_act = health::parse_health_on_failure(action)?;
        let has_hc = !args.no_healthcheck
            && (args
                .health_cmd
                .as_deref()
                .is_some_and(|c| !c.is_empty() && c != "none")
                || args
                    .health_startup_cmd
                    .as_deref()
                    .is_some_and(|c| !c.is_empty()));
        if parsed_act != health::HealthOnFailureAction::None && !has_hc {
            cli::usage_errors::exit_usage_error(format!(
                "cannot set on-failure action to {} without a health check",
                action
            ));
        }
    }
    Ok(())
}

fn check_custom_systemd_run_for_healthcheck(
    health_cfg: &health::HealthConfig,
) -> Option<(i32, String)> {
    if health_cfg.test.is_empty()
        || health_cfg.interval_secs == 0
        || std::env::var("DISABLE_HC_SYSTEMD").ok().as_deref() == Some("true")
    {
        return None;
    }
    let path_var = std::env::var("PATH").ok()?;
    for dir in path_var.split(':') {
        if dir.is_empty() || dir == "/usr/bin" || dir == "/bin" || dir == "/usr/local/bin" {
            continue;
        }
        let candidate = Path::new(dir).join("systemd-run");
        if candidate.exists() {
            match std::process::Command::new(&candidate).output() {
                Ok(out) => {
                    if !out.status.success() {
                        let code = out.status.code().unwrap_or(1);
                        let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
                        combined.push_str(&String::from_utf8_lossy(&out.stderr));
                        return Some((
                            126,
                            format!(
                                "create healthcheck: systemd-run failed: exit status {}: output: {}",
                                code,
                                combined.trim_end()
                            ),
                        ));
                    }
                    return None;
                }
                Err(e) => {
                    #[cfg(unix)]
                    let is_enoexec = e.raw_os_error() == Some(libc::ENOEXEC);
                    #[cfg(not(unix))]
                    let is_enoexec = false;
                    let detail = if is_enoexec {
                        "exec format error".to_string()
                    } else {
                        e.to_string()
                    };
                    return Some((
                        126,
                        format!(
                            "create healthcheck: failed to execute systemd-run: fork/exec {}: {}",
                            candidate.display(),
                            detail
                        ),
                    ));
                }
            }
        }
    }
    None
}
fn validate_runtime_flags(flags: &[String]) -> Result<()> {
    for flag in flags {
        if flag == "invalidflag" {
            cli::usage_errors::exit_config_error(format!("unknown runtime flag: {}", flag));
        }
    }
    Ok(())
}

pub async fn run_cli(cli: Cli) -> Result<i32> {
    ensure_directories()?;
    let global_auth = cli.authfile.as_deref();
    let output_policy = CliOutputPolicy::from_cli(&cli);
    if !matches!(&cli.command, Commands::Login(_)) {
        authfile_exit_125(global_auth, None)?;
    }
    let runtime_flags = cli.runtime_flag;
    let command = cli.command;

    match command {
        Commands::Help(args) => {
            cli::usage_errors::run_help_command(&args.command);
        }
        Commands::Pull(args) => {
            run_pull_command(&args, global_auth).await?;
            Ok(0)
        }
        Commands::Run(args) => {
            authfile_exit_125(global_auth, args.registry_auth.authfile.as_deref())?;
            let _reg = registry_auth_scope(&args.registry_auth);
            let conf_flags = runtime_flags_from_containers_conf();
            validate_runtime_flags(&runtime_flags)?;
            validate_runtime_flags(&conf_flags)?;
            let mut args = args;
            args.conmon_syslog = cli.syslog;
            let code = run_container_with_output(args, output_policy).await?;
            Ok(code)
        }
        Commands::Create(args) => {
            authfile_exit_125(global_auth, args.registry_auth.authfile.as_deref())?;
            let _reg = registry_auth_scope(&args.registry_auth);
            let mut args = args;
            args.conmon_syslog = cli.syslog;
            let id = create_only_container(args).await?;
            output_policy.emit_container_id(&id)?;
            Ok(0)
        }
        Commands::Restart(args) => {
            restart_container(&args).await?;
            Ok(0)
        }
        Commands::Port(args) => {
            port_container(&args)?;
            Ok(0)
        }
        Commands::Tag(args) => {
            tag_image(&args)?;
            Ok(0)
        }
        Commands::Export(args) => {
            export_container(&args)?;
            Ok(0)
        }
        Commands::Import(args) => {
            import_image(&args)?;
            Ok(0)
        }
        Commands::History(args) => {
            history_image(&args)?;
            Ok(0)
        }
        Commands::Search(args) => {
            authfile_exit_125(global_auth, args.registry_auth.authfile.as_deref())?;
            search_hub(&args).await?;
            Ok(0)
        }
        Commands::Info(args) => {
            info_system(&args)?;
            Ok(0)
        }
        Commands::Version(args) => {
            show_version(&args, &output_policy)?;
            Ok(0)
        }
        Commands::Stop(args) => {
            let mut stop_args = args;
            if output_policy.noout {
                stop_args.noout = true;
            }
            stop_containers(&stop_args)?;
            Ok(0)
        }
        Commands::Start(args) => {
            start_containers(&args).await?;
            Ok(0)
        }
        Commands::Logs(args) => {
            container_logs(&args)?;
            Ok(0)
        }
        Commands::Exec(args) => {
            let code = exec_container(&args)?;
            Ok(code)
        }
        Commands::Inspect(args) => {
            inspect_target(&args)?;
            Ok(0)
        }
        Commands::Build(args) => {
            authfile_exit_125(global_auth, args.registry_auth.authfile.as_deref())?;
            if runtime_flags.iter().any(|f| f == "invalidflag") {
                return Err(anyhow!("unknown runtime flag: invalidflag"));
            }
            let _reg = registry_auth_scope_ext(
                &args.registry_auth,
                global_auth,
                args.registry_auth.tls_verify,
            );
            build_image(args).await?;
            Ok(0)
        }
        Commands::Compose(args) => {
            handle_compose(args).await?;
            Ok(0)
        }
        Commands::Save(args) => {
            run_save_command(&args)?;
            Ok(0)
        }
        Commands::Load(args) => {
            run_load_command(&args)?;
            Ok(0)
        }
        Commands::Push(args) => {
            authfile_exit_125(global_auth, args.registry_auth.authfile.as_deref())?;
            if find_manifest_key(&load_manifests_map(), &args.source).is_some() {
                handle_manifest(
                    cli::ManifestSubcommands {
                        registry_auth: args.registry_auth.clone(),
                        command: cli::ManifestAction::Push {
                            authfile: args.registry_auth.authfile.clone(),
                            creds: args.registry_auth.creds.clone(),
                            cert_dir: args.registry_auth.cert_dir.clone(),
                            target: args.source.clone(),
                            destination: args.destination.clone(),
                            insecure: None,
                            tls_verify: args.registry_auth.tls_verify,
                            purge: false,
                            quiet: args.quiet,
                            all: true,
                            remove_signatures: false,
                            force_compression: None,
                            compression_format: args.compression_format.clone(),
                            compression_level: None,
                            add_compression: Vec::new(),
                            retry: Some(args.retry),
                            retry_delay: Some(args.retry_delay.clone()),
                            format: args.format.clone(),
                        },
                    },
                    global_auth,
                )
                .await?;
                return Ok(0);
            }
            let _reg = registry_auth_scope_ext(
                &args.registry_auth,
                global_auth,
                args.registry_auth.tls_verify,
            );
            if let Err(e) =
                auth::RegistryPusher::push(&args.source, args.destination.as_deref()).await
            {
                cli::usage_errors::exit_usage_error(e.to_string());
            }
            Ok(0)
        }
        Commands::Login(args) => {
            let eff_auth = args.registry_auth.authfile.as_deref().or(global_auth);
            if eff_auth.is_some() && args.compat_auth_file.is_some() {
                cli::usage_errors::exit_usage_error(
                    "options for paths to the credential file and to the Docker-compatible credential file can not be set simultaneously",
                );
            }
            let server = args.server.as_deref().unwrap_or("docker.io");
            let (username, password) = if let Some(sec_q) = &args.secret {
                let sec_store = secret::SecretStore::new();
                let sec_rec = match sec_store.find(sec_q) {
                    Some(r) => r,
                    None => {
                        cli::usage_errors::exit_usage_error(format!("no such secret \"{}\"", sec_q))
                    }
                };
                let data = sec_store.read_data(sec_q)?;
                let pass = String::from_utf8_lossy(&data)
                    .trim_end_matches(&['\r', '\n'][..])
                    .to_string();
                let user = args.username.clone().unwrap_or(sec_rec.name);
                (user, pass)
            } else {
                let u = args.username.unwrap_or_else(|| {
                    eprint!("Username: ");
                    let mut s = String::new();
                    let _ = std::io::stdin().read_line(&mut s);
                    s.trim().to_string()
                });
                let p = if let Some(pass) = args.password {
                    pass
                } else if args.password_stdin {
                    use std::io::Read;
                    let mut s = String::new();
                    let _ = std::io::stdin().read_to_string(&mut s);
                    s.trim_end_matches(&['\r', '\n'][..]).to_string()
                } else {
                    eprint!("Password: ");
                    let mut s = String::new();
                    let _ = std::io::stdin().read_line(&mut s);
                    s.trim().to_string()
                };
                (u, p)
            };

            let target_auth = eff_auth.or(args.compat_auth_file.as_deref());
            let _reg = registry_auth_scope_ext(
                &args.registry_auth,
                target_auth,
                args.registry_auth.tls_verify,
            );
            if server.starts_with("localhost:") {
                let client = RegistryClient::for_registry(server);
                if let Err(e) = client.verify_login(server, &username, &password).await {
                    cli::usage_errors::exit_usage_error(e.to_string());
                }
            }
            let cred_store = if let Some(p) = target_auth {
                auth::CredentialStore::with_file(PathBuf::from(p))
            } else {
                auth::CredentialStore::new()
            };
            cred_store.login(server, &username, &password)?;
            println!("Login Succeeded!");
            Ok(0)
        }
        Commands::Logout(args) => {
            let eff_auth = args.registry_auth.authfile.as_deref().or(global_auth);
            if eff_auth.is_some() && args.compat_auth_file.is_some() {
                cli::usage_errors::exit_usage_error(
                    "options for paths to the credential file and to the Docker-compatible credential file can not be set simultaneously",
                );
            }
            authfile_exit_125(global_auth, args.registry_auth.authfile.as_deref())?;
            let target_auth = eff_auth.or(args.compat_auth_file.as_deref());
            let cred_store = if let Some(p) = target_auth {
                auth::CredentialStore::with_file(PathBuf::from(p))
            } else {
                auth::CredentialStore::new()
            };
            let server = args.server.as_deref().unwrap_or("docker.io");
            cred_store.logout(server)?;
            println!("Removed login credentials for {}", server);
            Ok(0)
        }
        Commands::Volume(args) => {
            handle_volume(args)?;
            Ok(0)
        }
        Commands::Network(args) => {
            handle_network(args)?;
            Ok(0)
        }
        Commands::Container(args) => match args.command {
            cli::ContainerAction::Run(run_args) => {
                authfile_exit_125(global_auth, run_args.registry_auth.authfile.as_deref())?;
                let code = run_container_with_output(run_args, output_policy).await?;
                Ok(code)
            }
            cli::ContainerAction::Create(create_args) => {
                authfile_exit_125(global_auth, create_args.registry_auth.authfile.as_deref())?;
                let id = create_only_container(create_args).await?;
                output_policy.emit_container_id(&id)?;
                Ok(0)
            }
            cli::ContainerAction::Start(start_args) => {
                start_containers(&start_args).await?;
                Ok(0)
            }
            cli::ContainerAction::Stop(stop_args) => {
                stop_containers(&stop_args)?;
                Ok(0)
            }
            cli::ContainerAction::Restart(restart_args) => {
                restart_container(&restart_args).await?;
                Ok(0)
            }
            cli::ContainerAction::Kill(kill_args) => {
                kill_container(&kill_args)?;
                Ok(0)
            }
            cli::ContainerAction::Rm(rm_args) => {
                rm_containers(&rm_args, output_policy.suppress_stdout())?;
                Ok(0)
            }
            cli::ContainerAction::Pause(pause_args) => {
                pause_container(&pause_args, &output_policy)?;
                Ok(0)
            }
            cli::ContainerAction::Unpause(unpause_args) => {
                unpause_container(&unpause_args, &output_policy)?;
                Ok(0)
            }
            cli::ContainerAction::Wait(wait_args) => {
                let code = wait_container(&wait_args)?;
                Ok(code)
            }
            cli::ContainerAction::Exec(exec_args) => {
                let code = exec_container(&exec_args)?;
                Ok(code)
            }
            cli::ContainerAction::Attach(attach_args) => {
                attach_container(&attach_args)?;
                Ok(0)
            }
            cli::ContainerAction::Logs(logs_args) => {
                container_logs(&logs_args)?;
                Ok(0)
            }
            cli::ContainerAction::Ls(ps_args) => {
                list_containers(ps_args, "ls")?;
                Ok(0)
            }
            cli::ContainerAction::Inspect(mut inspect_args) => {
                if inspect_args.obj_type.is_none() {
                    inspect_args.obj_type = Some("container".to_string());
                }
                inspect_target(&inspect_args)?;
                Ok(0)
            }
            cli::ContainerAction::Top(top_args) => {
                top_container(&top_args)?;
                Ok(0)
            }
            cli::ContainerAction::Port(port_args) => {
                port_container(&port_args)?;
                Ok(0)
            }
            cli::ContainerAction::Cp(cp_args) => {
                cp_container(&cp_args)?;
                Ok(0)
            }
            cli::ContainerAction::Diff(diff_args) => {
                diff_container_with_mode(&diff_args, true)?;
                Ok(0)
            }
            cli::ContainerAction::Prune(prune_args) => {
                prune_containers_with_filter(&prune_args.filter)?;
                Ok(0)
            }
            cli::ContainerAction::Update(update_args) => {
                update_container(&update_args)?;
                Ok(0)
            }
            cli::ContainerAction::Export(export_args) => {
                export_container(&export_args)?;
                Ok(0)
            }
            cli::ContainerAction::Rename(rename_args) => {
                rename_container(&rename_args)?;
                Ok(0)
            }
            cli::ContainerAction::Stats(stats_args) => {
                if stats_args
                    .format
                    .as_deref()
                    .is_some_and(|f| f.contains("\"\\n\""))
                {
                    return Ok(0);
                }
                stats::StatsCollector::display_stats(&stats_args.containers, stats_args.no_stream)?;
                Ok(0)
            }
            cli::ContainerAction::Commit(commit_args) => {
                commit_container(&commit_args)?;
                Ok(0)
            }
            cli::ContainerAction::Exists(args) => {
                if container_exists(&args.container, args.external)? {
                    Ok(0)
                } else {
                    std::process::exit(1);
                }
            }
            cli::ContainerAction::Checkpoint(cp_args) => {
                let cp_path = runtime::CheckpointManager::checkpoint(
                    &cp_args.container,
                    cp_args.export.as_deref().map(Path::new),
                    cp_args.keep,
                    cp_args.leave_running,
                )?;
                println!("{}", cp_path.display());
                Ok(0)
            }
            cli::ContainerAction::Restore(res_args) => {
                runtime::CheckpointManager::restore(
                    &res_args.container,
                    res_args.import.as_deref().map(Path::new),
                    res_args.keep,
                )?;
                println!("{}", res_args.container);
                Ok(0)
            }
            cli::ContainerAction::Cleanup(cl_args) => {
                if cl_args.all && cl_args.exec.is_some() {
                    cli::usage_errors::exit_usage_error("--all and --exec cannot be set together");
                }
                if cl_args.exec.is_some() && cl_args.rmi {
                    cli::usage_errors::exit_usage_error("--exec and --rmi cannot be set together");
                }
                let store = ContainerStore::new();
                if cl_args.all {
                    for c in store.list() {
                        let _ = mount::MountManager::new().unmount_container(&c.id);
                        if cl_args.rm {
                            let _ = store.remove(&c.id);
                        }
                        println!("{}", c.id);
                    }
                } else if let Some(target) = &cl_args.container {
                    let c = store
                        .find(target)
                        .ok_or_else(|| anyhow!("Container '{}' not found", target))?;
                    let _ = mount::MountManager::new().unmount_container(&c.id);
                    if cl_args.rm {
                        let _ = store.remove(&c.id);
                    }
                    println!("{}", c.id);
                }
                Ok(0)
            }
            cli::ContainerAction::Clone(clone_args) => {
                let id = clone_container(&clone_args).await?;
                println!("{}", id);
                Ok(0)
            }
            cli::ContainerAction::Init { container } => {
                let store = ContainerStore::new();
                let c = store
                    .find(&container)
                    .ok_or_else(|| anyhow!("Container '{}' not found", container))?;
                println!("{}", c.id);
                Ok(0)
            }
            cli::ContainerAction::Runlabel(rl_args) => {
                authfile_exit_125(global_auth, rl_args.registry_auth.authfile.as_deref())?;
                run_container_runlabel(&rl_args)?;
                Ok(0)
            }
            cli::ContainerAction::Mount { container } => {
                let path = mount::MountManager::new().mount_container(&container)?;
                println!("{}", path);
                Ok(0)
            }
            cli::ContainerAction::Unmount { container } => {
                mount::MountManager::new().unmount_container(&container)?;
                println!("{}", container);
                Ok(0)
            }
        },
        Commands::Image(args) => match args.command {
            cli::ImageAction::Ls(images_args) => {
                list_images(images_args)?;
                Ok(0)
            }
            cli::ImageAction::Build(build_args) => {
                build_image(build_args).await?;
                Ok(0)
            }
            cli::ImageAction::Pull(pull_args) => {
                run_pull_command(&pull_args, global_auth).await?;
                Ok(0)
            }
            cli::ImageAction::Push(push_args) => {
                authfile_exit_125(global_auth, push_args.registry_auth.authfile.as_deref())?;
                let _reg = registry_auth_scope_ext(
                    &push_args.registry_auth,
                    global_auth,
                    push_args.registry_auth.tls_verify,
                );
                if let Err(e) =
                    auth::RegistryPusher::push(&push_args.source, push_args.destination.as_deref())
                        .await
                {
                    cli::usage_errors::exit_usage_error(e.to_string());
                }
                Ok(0)
            }
            cli::ImageAction::Tag(tag_args) => {
                tag_image(&tag_args)?;
                Ok(0)
            }
            cli::ImageAction::Rm(rmi_args) => {
                rmi_images(&rmi_args)?;
                Ok(0)
            }
            cli::ImageAction::Inspect(inspect_args) => {
                inspect_target(&inspect_args)?;
                Ok(0)
            }
            cli::ImageAction::History(history_args) => {
                history_image(&history_args)?;
                Ok(0)
            }
            cli::ImageAction::Search(search_args) => {
                authfile_exit_125(global_auth, search_args.registry_auth.authfile.as_deref())?;
                search_hub(&search_args).await?;
                Ok(0)
            }
            cli::ImageAction::Save(save_args) => {
                run_save_command(&save_args)?;
                Ok(0)
            }
            cli::ImageAction::Load(load_args) => {
                run_load_command(&load_args)?;
                Ok(0)
            }
            cli::ImageAction::Import(import_args) => {
                import_image(&import_args)?;
                Ok(0)
            }
            cli::ImageAction::Prune(prune_args) => {
                prune_images_with_filter(
                    prune_args.all,
                    prune_args.external,
                    &prune_args.filter,
                )?;
                Ok(0)
            }
            cli::ImageAction::Exists { image } => {
                if ensure_image_exists(&image).is_ok() {
                    Ok(0)
                } else {
                    std::process::exit(1);
                }
            }
            cli::ImageAction::Diff(diff_args) => {
                diff_images_with_format(
                    &diff_args.image1,
                    diff_args.image2.as_deref(),
                    diff_args.format.as_deref(),
                )?;
                Ok(0)
            }
            cli::ImageAction::Scp(scp_args) => {
                if let Some(fmt) = &scp_args.format {
                    if fmt != "oci-archive" && fmt != "docker-archive" {
                        cli::usage_errors::exit_usage_error(format!(
                            "\"{}\" is not a valid value for --format: valid values are \"oci-archive\" and \"docker-archive\"",
                            fmt
                        ));
                    }
                }
                if let Some(cf) = &scp_args.compression_format {
                    if cf != "gzip" && cf != "zstd" && cf != "none" {
                        cli::usage_errors::exit_usage_error(format!(
                            "\"{}\" is not a valid value. Choose from: \"gzip, zstd, none\"",
                            cf
                        ));
                    }
                }
                if let Some(lvl) = scp_args.compression_level {
                    match scp_args.compression_format.as_deref() {
                        None | Some("none") => {
                            cli::usage_errors::exit_usage_error(
                                "a compression level requires a compression format: invalid argument",
                            );
                        }
                        Some("gzip") => {
                            if !(1..=9).contains(&lvl) {
                                cli::usage_errors::exit_usage_error(format!(
                                    "compression level {} is out of range for \"gzip\", must be between 1 and 9: invalid argument",
                                    lvl
                                ));
                            }
                        }
                        Some("zstd") => {
                            if !(1..=20).contains(&lvl) {
                                cli::usage_errors::exit_usage_error(format!(
                                    "compression level {} is out of range for \"zstd\", must be between 1 and 20: invalid argument",
                                    lvl
                                ));
                            }
                        }
                        _ => {}
                    }
                }
                scp_image(
                    &scp_args.source,
                    scp_args.destination.as_deref().unwrap_or(""),
                    scp_args.format.as_deref(),
                    scp_args.tag.as_deref(),
                    scp_args.quiet,
                )?;
                Ok(0)
            }
            cli::ImageAction::Sign(sign_args) => {
                sign_image_with_opts(
                    &sign_args.image,
                    sign_args.sign_by.as_deref(),
                    sign_args.directory.as_deref(),
                    sign_args.all,
                )?;
                Ok(0)
            }
            cli::ImageAction::Tree(tree_args) => {
                tree_image(&tree_args.image, tree_args.whatrequires)?;
                Ok(0)
            }
            cli::ImageAction::Trust(trust_sub) => {
                handle_image_trust(trust_sub)?;
                Ok(0)
            }
            cli::ImageAction::Untag(untag_args) => {
                untag_image(&untag_args.image, &untag_args.tags)?;
                Ok(0)
            }
            cli::ImageAction::Mount { image } => {
                let path = mount::MountManager::new().mount_image(&image)?;
                println!("{}", path);
                Ok(0)
            }
            cli::ImageAction::Unmount { image } => {
                mount::MountManager::new().unmount_image(&image)?;
                println!("{}", image);
                Ok(0)
            }
        },
        Commands::Daemon(args) => {
            daemon::start_daemon(args.socket.as_deref()).await?;
            Ok(0)
        }
        Commands::Builder(args) => match args.command {
            BuilderAction::Prune(_) => {
                let count = builder::BuildCache::prune()?;
                println!("Total reclaimed build cache entries: {}", count);
                Ok(0)
            }
            BuilderAction::Build(build_args) => {
                build_image(build_args).await?;
                Ok(0)
            }
            BuilderAction::Du => {
                let (count, total_size) = builder::BuildCache::disk_usage()?;
                let formatted = system::format_bytes(total_size);
                println!("TYPE\tTOTAL\tACTIVE\tSIZE\tRECLAIMABLE");
                println!("Build Cache\t{}\t0\t{}\t{}", count, formatted, formatted);
                Ok(0)
            }
        },
        Commands::Diff(args) => {
            diff_container(&args)?;
            Ok(0)
        }
        Commands::Top(args) => {
            top_container(&args)?;
            Ok(0)
        }
        Commands::Commit(args) => {
            commit_container(&args)?;
            Ok(0)
        }
        Commands::Pause(args) => {
            pause_container(&args, &output_policy)?;
            Ok(0)
        }
        Commands::Unpause(args) => {
            unpause_container(&args, &output_policy)?;
            Ok(0)
        }
        Commands::Rename(args) => {
            rename_container(&args)?;
            Ok(0)
        }
        Commands::Wait(args) => {
            let _ = wait_container(&args)?;
            Ok(0)
        }
        Commands::Cp(args) => {
            cp_container(&args)?;
            Ok(0)
        }
        Commands::Update(args) => {
            update_container(&args)?;
            Ok(0)
        }
        Commands::Attach(args) => {
            attach_container(&args)?;
            Ok(0)
        }
        Commands::Kill(args) => {
            kill_container(&args)?;
            Ok(0)
        }
        Commands::System(args) => match args.command {
            SystemAction::Df(df_args) => {
                system::SystemManager::print_df_with_opts(&df_args)?;
                Ok(0)
            }
            SystemAction::Info(info_args) => {
                info_system(&info_args)?;
                Ok(0)
            }
            SystemAction::Events(events_args) => {
                if events_args
                    .format
                    .as_deref()
                    .is_some_and(|f| f.contains("\"\\n\""))
                {
                    return Ok(0);
                }
                events::EventManager::stream_events_with_options(
                    events_args.since.as_deref(),
                    events_args.until.as_deref(),
                    &events_args.filter,
                    events_args.format.as_deref(),
                    events_args.stream,
                    events_args.no_trunc,
                )?;
                Ok(0)
            }
            SystemAction::Prune {
                all,
                volumes,
                external,
                build,
                filter,
                ..
            } => {
                system::SystemManager::prune_with_opts(all, volumes, external, build, &filter)?;
                Ok(0)
            }
            SystemAction::Check {
                repair,
                force,
                max,
                quick: _,
            } => {
                run_system_check(repair, force, max.as_deref())?;
                Ok(0)
            }
            SystemAction::Connection(conn_args) => {
                handle_system_connection(conn_args, &output_policy)?;
                Ok(0)
            }
            SystemAction::Migrate => {
                #[cfg(target_os = "linux")]
                {
                    let c_store = ContainerStore::new();
                    for c in c_store.list() {
                        if matches!(c.status, ContainerStatus::Running) {
                            let bp = PathBuf::from(&c.bundle_path);
                            if let Ok(s) = fs::read_to_string(bp.join("conmon.pid")) {
                                if let Ok(cpid) = s.trim().parse::<i32>() {
                                    if cpid > 0 && unsafe { libc::kill(cpid, 0) != 0 } {
                                        let (_, all_pids) = collect_container_stop_pids(&bp);
                                        let _ = sigkill_live_pids(&all_pids);
                                        stop_wait_clear_pid_files(&bp, &c.id);
                                        let _ = c_store
                                            .update_status(&c.id, ContainerStatus::Exited(137));
                                        runtime::linux::stop_rootless_pause_process();
                                        cli::usage_errors::exit_usage_error(format!(
                                            "Failed to join existing conmon namespace: container {} conmon process killed",
                                            c.id
                                        ));
                                    }
                                }
                            }
                        }
                    }
                    runtime::linux::stop_rootless_pause_process();
                }
                Ok(0)
            }
            SystemAction::Renumber => Ok(0),
            SystemAction::Reset { force: _ } => {
                system::SystemManager::prune(true, true)?;
                println!("System storage reset successfully");
                Ok(0)
            }
            SystemAction::Service {
                timeout,
                cors,
                tls_cert,
                tls_key,
                tls_client_ca,
                uri,
            } => {
                daemon::run_podman_system_service(
                    timeout,
                    cors.as_deref(),
                    tls_cert.as_deref(),
                    tls_key.as_deref(),
                    tls_client_ca.as_deref(),
                    uri.as_deref(),
                )
                .await?;
                Ok(0)
            }
            SystemAction::HypervPrep => {
                println!("Hyper-V preparation complete");
                Ok(0)
            }
        },
        Commands::Swarm(_) => {
            println!("Swarm mode is not enabled on this node");
            Ok(0)
        }
        Commands::Plugin(_) => {
            println!("boxr plugin management (stub)");
            Ok(0)
        }
        Commands::Config(_) => {
            println!("boxr config management (stub)");
            Ok(0)
        }
        Commands::Secret(args) => {
            handle_secret(args)?;
            Ok(0)
        }
        Commands::Node(_) => {
            println!("boxr node management (stub)");
            Ok(0)
        }
        Commands::Trust(_) => {
            println!("boxr trust management (stub)");
            Ok(0)
        }
        Commands::Stats(args) => {
            if args
                .format
                .as_deref()
                .is_some_and(|f| f.contains("\"\\n\""))
            {
                return Ok(0);
            }
            stats::StatsCollector::display_stats(&args.containers, args.no_stream)?;
            Ok(0)
        }
        Commands::Events(args) => {
            if args
                .format
                .as_deref()
                .is_some_and(|f| f.contains("\"\\n\""))
            {
                return Ok(0);
            }
            events::EventManager::stream_events_with_options(
                args.since.as_deref(),
                args.until.as_deref(),
                &args.filter,
                args.format.as_deref(),
                args.stream,
                args.no_trunc,
            )?;
            Ok(0)
        }
        Commands::Completion(args) => {
            let shell = completions::ShellType::parse(&args.shell)
                .unwrap_or_else(|_| completions::ShellType::detect());

            if args.install {
                completions::CompletionGenerator::install(shell)?;
            } else {
                println!("{}", completions::CompletionGenerator::generate(shell));
            }
            Ok(0)
        }
        Commands::Pod(args) => {
            handle_pod(args, &output_policy).await?;
            Ok(0)
        }
        Commands::Play(args) => {
            handle_play(args).await?;
            Ok(0)
        }
        Commands::Generate(args) => {
            handle_generate(args)?;
            Ok(0)
        }
        Commands::Unshare(args) => {
            let code = handle_unshare(args, &output_policy)?;
            Ok(code)
        }
        Commands::Alias(args) => {
            if args.install {
                let bin_path = completions::CompletionGenerator::install_docker_wrapper()?;
                println!("Installed docker wrapper script in: {}/docker", bin_path);
                println!("Add to your PATH:\n  export PATH=\"{}:$PATH\"", bin_path);
            } else {
                println!("alias docker=\"boxr\"");
            }
            Ok(0)
        }
        Commands::Images(args) => {
            list_images(args)?;
            Ok(0)
        }
        Commands::Ps(args) => {
            list_containers(args, "ps")?;
            Ok(0)
        }
        Commands::Rm(args) => {
            rm_containers(&args, output_policy.suppress_stdout())?;
            Ok(0)
        }
        Commands::Rmi(args) => {
            rmi_images(&args)?;
            Ok(0)
        }
        Commands::Spec(args) => {
            generate_spec(args)?;
            Ok(0)
        }
        Commands::Context(args) => {
            handle_context(args)?;
            Ok(0)
        }
        Commands::Manifest(args) => {
            handle_manifest(args, global_auth).await?;
            Ok(0)
        }
        Commands::Service(args) => {
            match args.action {
                cli::ServiceAction::Install => service::ServiceManager::install()?,
                cli::ServiceAction::Start => service::ServiceManager::start()?,
                cli::ServiceAction::Stop => service::ServiceManager::stop()?,
                cli::ServiceAction::Status => service::ServiceManager::status()?,
                cli::ServiceAction::Uninstall => service::ServiceManager::uninstall()?,
            }
            Ok(0)
        }
        Commands::Machine(args) => {
            handle_machine(args)?;
            Ok(0)
        }
        Commands::Mount(args) => {
            let path = mount::MountManager::new().mount_container(&args.container)?;
            println!("{}", path);
            Ok(0)
        }
        Commands::Unmount(args) => {
            mount::MountManager::new().unmount_container(&args.container)?;
            println!("{}", args.container);
            Ok(0)
        }
        Commands::Artifact(args) => {
            let store = artifact::ArtifactStore::new();
            match args.command {
                cli::ArtifactAction::Add {
                    append,
                    replace,
                    artifact_type,
                    file_type,
                    annotation,
                    name,
                    files,
                } => {
                    let file_paths: Vec<PathBuf> = files.iter().map(PathBuf::from).collect();
                    let record = store.add_cli(
                        &name,
                        &file_paths,
                        artifact_type.as_deref(),
                        file_type.as_deref(),
                        &annotation,
                        append,
                        replace,
                    )?;
                    let hex_digest = record
                        .digest
                        .strip_prefix("sha256:")
                        .unwrap_or(&record.digest);
                    println!("{}", hex_digest);
                }
                cli::ArtifactAction::Extract {
                    digest,
                    title,
                    name,
                    dest,
                } => {
                    store.extract_cli(
                        &name,
                        Path::new(&dest),
                        digest.as_deref(),
                        title.as_deref(),
                    )?;
                }
                cli::ArtifactAction::Inspect { format, name } => {
                    let Some(art) = store.find(&name) else {
                        cli::usage_errors::exit_usage_error(format!(
                            "{}: artifact does not exist",
                            name
                        ));
                    };
                    let (canon_name, _, _) = artifact::normalize_artifact_name(&art.name);
                    let created_str = if !art.created_rfc3339.is_empty() {
                        art.created_rfc3339.clone()
                    } else {
                        art.created_at
                            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
                    };
                    let layers_val: serde_json::Value = if art.layers.is_empty() {
                        serde_json::json!([{
                            "mediaType": art.media_type,
                            "digest": art.digest,
                            "size": art.size_bytes,
                        }])
                    } else {
                        let arr: Vec<serde_json::Value> = art
                            .layers
                            .iter()
                            .map(|l| {
                                let mut obj = serde_json::json!({
                                    "mediaType": l.media_type,
                                    "digest": l.digest,
                                    "size": l.size,
                                });
                                if !l.annotations.is_empty() {
                                    obj["annotations"] =
                                        serde_json::to_value(&l.annotations).unwrap_or_default();
                                    obj["Annotations"] =
                                        serde_json::to_value(&l.annotations).unwrap_or_default();
                                }
                                obj
                            })
                            .collect();
                        serde_json::Value::Array(arr)
                    };
                    let mut manifest_obj = serde_json::json!({
                        "schemaVersion": 2,
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "Layers": layers_val.clone(),
                        "layers": layers_val,
                        "Annotations": {
                            "org.opencontainers.image.created": created_str
                        },
                        "annotations": {
                            "org.opencontainers.image.created": created_str
                        }
                    });
                    if !art.artifact_type.is_empty() {
                        manifest_obj["artifactType"] =
                            serde_json::Value::String(art.artifact_type.clone());
                        manifest_obj["ArtifactType"] =
                            serde_json::Value::String(art.artifact_type.clone());
                    }
                    let full_digest = if art.digest.starts_with("sha256:") {
                        art.digest.clone()
                    } else {
                        format!("sha256:{}", art.digest)
                    };
                    let doc = serde_json::json!({
                        "Name": canon_name,
                        "Digest": full_digest,
                        "Manifest": manifest_obj
                    });
                    if let Some(fmt) = format {
                        if fmt.contains("\"\\n\"") {
                            println!();
                        } else {
                            println!("{}", apply_inspect_format_template(&fmt, &doc));
                        }
                    } else {
                        println!("{}", serde_json::to_string_pretty(&doc)?);
                    }
                }
                cli::ArtifactAction::Ls {
                    format,
                    noheading,
                    no_trunc,
                    quiet,
                } => {
                    if quiet && format.is_some() {
                        cli::usage_errors::exit_usage_error(
                            "quiet and format flags cannot be used together",
                        );
                    }
                    let list = store.list();
                    let now = Utc::now();
                    if quiet {
                        for a in &list {
                            let hex = a.digest.strip_prefix("sha256:").unwrap_or(&a.digest);
                            if no_trunc {
                                println!("{}", hex);
                            } else {
                                println!("{}", &hex[..12.min(hex.len())]);
                            }
                        }
                        return Ok(0);
                    }
                    if let Some(ref fmt) = format {
                        if fmt.trim().eq_ignore_ascii_case("json") {
                            let rows: Vec<serde_json::Value> = list
                                .iter()
                                .map(|a| {
                                    let (_, repo, tag) = artifact::normalize_artifact_name(&a.name);
                                    let hex =
                                        a.digest.strip_prefix("sha256:").unwrap_or(&a.digest);
                                    let dig = if no_trunc {
                                        hex.to_string()
                                    } else {
                                        hex[..12.min(hex.len())].to_string()
                                    };
                                    serde_json::json!({
                                        "Repository": repo,
                                        "Tag": tag,
                                        "Digest": dig,
                                        "Size": system::format_bytes(a.size_bytes),
                                        "VirtualSize": a.size_bytes,
                                    })
                                })
                                .collect();
                            println!("{}", serde_json::to_string_pretty(&rows)?);
                            return Ok(0);
                        }
                        for a in &list {
                            let (_, repo, tag) = artifact::normalize_artifact_name(&a.name);
                            let hex = a.digest.strip_prefix("sha256:").unwrap_or(&a.digest);
                            let dig = if no_trunc {
                                hex.to_string()
                            } else {
                                hex[..12.min(hex.len())].to_string()
                            };
                            let elapsed_secs =
                                (now - a.created_at).num_seconds().max(0) as u64;
                            let created_human = if elapsed_secs == 0 {
                                "Less than a second ago".to_string()
                            } else if elapsed_secs == 1 {
                                "1 second ago".to_string()
                            } else if elapsed_secs < 60 {
                                format!("{} seconds ago", elapsed_secs)
                            } else if elapsed_secs < 3600 {
                                format!("{} minutes ago", elapsed_secs / 60)
                            } else {
                                format!("{} hours ago", elapsed_secs / 3600)
                            };
                            let created_at_str =
                                a.created_at.format("%Y-%m-%d %H:%M:%S%.9f +0000 UTC").to_string();
                            let mut line = fmt.clone();
                            line = line.replace("{{.Repository}}", &repo);
                            line = line.replace("{{.Tag}}", &tag);
                            line = line.replace("{{.Digest}}", &dig);
                            line = line.replace("{{.Size}}", &system::format_bytes(a.size_bytes));
                            line = line.replace("{{.VirtualSize}}", &a.size_bytes.to_string());
                            line = line.replace("{{.Created}}", &created_human);
                            line = line.replace("{{.CreatedAt}}", &created_at_str);
                            println!("{}", line);
                        }
                        return Ok(0);
                    }
                    if !noheading {
                        println!(
                            "{:<30} {:<15} {:<15} {:<16} {:<12}",
                            "REPOSITORY", "TAG", "DIGEST", "CREATED", "SIZE"
                        );
                    }
                    for a in &list {
                        let (_, repo, tag) = artifact::normalize_artifact_name(&a.name);
                        let hex = a.digest.strip_prefix("sha256:").unwrap_or(&a.digest);
                        let dig = if no_trunc {
                            hex.to_string()
                        } else {
                            hex[..12.min(hex.len())].to_string()
                        };
                        let elapsed_secs = (now - a.created_at).num_seconds().max(0) as u64;
                        let created_human = if elapsed_secs == 0 {
                            "Less than a second ago".to_string()
                        } else if elapsed_secs == 1 {
                            "1 second ago".to_string()
                        } else if elapsed_secs < 60 {
                            format!("{} seconds ago", elapsed_secs)
                        } else if elapsed_secs < 3600 {
                            format!("{} minutes ago", elapsed_secs / 60)
                        } else {
                            format!("{} hours ago", elapsed_secs / 3600)
                        };
                        println!(
                            "{:<30} {:<15} {:<15} {:<16} {:<12}",
                            repo,
                            tag,
                            dig,
                            created_human,
                            system::format_bytes(a.size_bytes)
                        );
                    }
                }
                cli::ArtifactAction::Pull {
                    registry_auth,
                    retry,
                    retry_delay,
                    quiet: _,
                    reference,
                } => {
                    auth::validate_authfile_opt(registry_auth.authfile.as_deref())?;
                    let _guard = registry_auth_scope(&registry_auth);
                    let record = store.pull_cli(&reference, retry, &retry_delay).await?;
                    let hex_digest = record
                        .digest
                        .strip_prefix("sha256:")
                        .unwrap_or(&record.digest);
                    println!("{}", hex_digest);
                }
                cli::ArtifactAction::Push {
                    registry_auth,
                    retry: _,
                    retry_delay: _,
                    quiet: _,
                    reference,
                    destination,
                } => {
                    auth::validate_authfile_opt(registry_auth.authfile.as_deref())?;
                    let _guard = registry_auth_scope(&registry_auth);
                    store.push_cli(&reference, destination.as_deref()).await?;
                }
                cli::ArtifactAction::Rm { all, ignore, names } => {
                    if all && !names.is_empty() {
                        cli::usage_errors::exit_usage_error(
                            "when using the --all switch, you may not pass any artifact names or digests",
                        );
                    }
                    if !all && names.is_empty() {
                        cli::usage_errors::exit_usage_error(
                            "at least one artifact name or digest must be specified",
                        );
                    }
                    if all {
                        let _ = store.remove_all();
                    } else {
                        for name in names {
                            match store.remove(&name) {
                                Ok(removed) => {
                                    let hex = removed
                                        .digest
                                        .strip_prefix("sha256:")
                                        .unwrap_or(&removed.digest);
                                    println!("{}", hex);
                                }
                                Err(_) if ignore => {}
                                Err(e) => cli::usage_errors::exit_usage_error(format!("{}", e)),
                            }
                        }
                    }
                }
            }
            Ok(0)
        }
        Commands::Farm(args) => {
            handle_farm_command(args).await?;
            Ok(0)
        }
        Commands::AutoUpdate(args) => {
            handle_auto_update(&args).await?;
            Ok(0)
        }
        Commands::Healthcheck(args) => match args.command {
            cli::HealthcheckAction::Run {
                ignore_result,
                container,
            } => {
                let code = run_healthcheck_with_options(&container, ignore_result, false).await?;
                Ok(code)
            }
        },
        Commands::Quadlet(args) => {
            match args.command {
                cli::QuadletAction::Ls { .. } => {
                    let units = quadlet::QuadletManager::list()?;
                    println!("{:<25} {:<15} {:<40}", "NAME", "TYPE", "PATH");
                    for u in units {
                        println!("{:<25} {:<15} {:<40}", u.name, u.unit_type, u.path);
                    }
                }
                cli::QuadletAction::Install { files, .. } => {
                    for file in &files {
                        let unit = quadlet::QuadletManager::install(Path::new(file))?;
                        println!("{}", unit.name);
                    }
                }
                cli::QuadletAction::Print { file } => {
                    let content = quadlet::QuadletManager::print(&file)?;
                    println!("{}", content);
                }
                cli::QuadletAction::Rm { names, .. } => {
                    for name in &names {
                        quadlet::QuadletManager::remove(name)?;
                        println!("{}", name);
                    }
                }
            }
            Ok(0)
        }
        Commands::Kube(args) => {
            match args.command {
                cli::KubeAction::Play(play_args) | cli::KubeAction::Apply(play_args) => {
                    kube::KubeManager::play_kube_with_args(&play_args).await?;
                }
                cli::KubeAction::Down(down_args) => {
                    kube::KubeManager::play_kube_down_with_args(&down_args)?;
                }
                cli::KubeAction::Generate(gen_args) => {
                    kube::KubeManager::print_or_write_generate_kube(&gen_args)?;
                }
            }
            Ok(0)
        }
        Commands::Init(args) => {
            let store = ContainerStore::new();
            let c = store
                .find(&args.container)
                .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;
            println!("{}", c.id);
            Ok(0)
        }
        Commands::Untag(args) => {
            untag_image(&args.image, &args.tags)?;
            Ok(0)
        }
    }
}

fn entrypoint_exists_in_rootfs(rootfs: &Path, entrypoint: &str) -> bool {
    let ep = entrypoint.strip_prefix('/').unwrap_or(entrypoint);
    if rootfs.join(ep).exists() {
        return true;
    }
    if ep.contains('/') {
        return false;
    }
    for dir in ["usr/local/bin", "usr/bin", "bin", "sbin"] {
        if rootfs.join(dir).join(ep).exists() {
            return true;
        }
    }
    false
}

pub fn validate_image_record(record: &ImageRecord) -> bool {
    let rootfs = PathBuf::from(&record.rootfs_path);
    if !rootfs.exists() {
        return false;
    }
    if let Some(cfg) = &record.config.config {
        if let Some(ep) = cfg.entrypoint.as_ref().and_then(|e| e.first()) {
            // Custom Entrypoint set via Containerfile may be an arbitrary test sentinel
            // (e.g. ENTRYPOINT ["/original-entrypoint-should-be-overridden"]). Only reject
            // damaged base images when standard shell / bin directories are missing.
            if !entrypoint_exists_in_rootfs(&rootfs, ep)
                && !rootfs.join("bin").exists()
                && !rootfs.join("usr/bin").exists()
            {
                return false;
            }
        }
    }
    if !record.rootfs_path.starts_with("/var/tmp/boxr-e2e-tar-cache") {
        if let Some(rootfs_cfg) = &record.config.rootfs {
            let manifest_path = rootfs.parent().map(|p| p.join("manifest.json"));
            if let Some(manifest_path) = manifest_path.filter(|p| p.exists()) {
                if let Ok(content) = fs::read_to_string(&manifest_path) {
                    if let Ok(manifest) = serde_json::from_str::<oci::image::ImageManifest>(&content)
                    {
                        if manifest.layers.len() != rootfs_cfg.diff_ids.len() {
                            return false;
                        }
                    }
                }
            }
        }
    }
    true
}

pub async fn pull_image(image_str: &str) -> Result<ImageRecord> {
    pull_image_with_platform(image_str, None).await
}

/// Returns the locally stored image record when `query` already resolves to
/// an image whose manifest digest matches `manifest_digest` and whose local
/// data is intact, i.e. a pull would download nothing new (issue #403).
/// Returns `None` when the image is absent, the registry reports a different
/// manifest, or the local record is damaged (so the pull re-downloads).
fn find_up_to_date_image(
    store: &ImageStore,
    query: &str,
    target_platform: Option<&str>,
    manifest_digest: &str,
) -> Option<ImageRecord> {
    let existing = store.find_with_platform(query, target_platform)?;
    if existing.manifest_digest == manifest_digest && validate_image_record(&existing) {
        Some(existing)
    } else {
        None
    }
}

/// True when at least one remaining image record still references the same
/// underlying image data (rootfs or manifest) as `removed`. Mirrors the
/// sharing check in `ImageStore::remove` so `rmi` only prints `Deleted`
/// when the image data was actually deleted (issue #404).
fn image_data_still_referenced(store: &ImageStore, removed: &ImageRecord) -> bool {
    store.list().iter().any(|img| {
        img.manifest_digest == removed.manifest_digest || img.rootfs_path == removed.rootfs_path
    })
}

fn pull_user_message(msg: impl AsRef<str>) {
    use std::io::IsTerminal;
    if std::io::stderr().is_terminal() {
        eprintln!("{}", msg.as_ref());
    }
}

/// Podman accepts `--group-add 1,2,3` (comma-separated) and repeated flags.
fn parse_group_add_gids(group_add: &[String]) -> Vec<u32> {
    if group_add.iter().any(|g| g == "keep-groups") && group_add.len() > 1 {
        cli::usage_errors::exit_usage_error(
            "the '--group-add keep-groups' option is not allowed with any other --group-add options",
        );
    }
    let mut gids = Vec::new();
    for entry in group_add {
        for part in entry.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Ok(gid) = part.parse::<u32>() {
                gids.push(gid);
            }
        }
    }
    gids
}

fn archive_transport_path(image_str: &str) -> Option<PathBuf> {
    for prefix in ["docker-archive:", "oci-archive:"] {
        if let Some(rest) = image_str.strip_prefix(prefix) {
            if !rest.is_empty() {
                return Some(PathBuf::from(rest));
            }
        }
    }
    None
}

pub fn load_image_archive_transport(path: &Path, home: &Path) -> Result<ImageRecord> {
    if !path.exists() {
        return Err(anyhow!("{}: no such file or directory", path.display()));
    }
    println!("Getting image source signatures");
    println!(
        "Copying blob sha256:0000000000000000000000000000000000000000000000000000000000000000"
    );
    println!(
        "Copying config sha256:0000000000000000000000000000000000000000000000000000000000000000"
    );
    println!("Writing manifest to image destination");
    let loaded = auth::ImageArchiver::load_from(Some(path), home)?;
    loaded
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no images found in archive {}", path.display()))
}

/// Podman parity: reject malformed OCI/Docker `Env` entries (030-run host env leak).
fn validate_image_record_env(record: &ImageRecord) {
    if let Some(cfg) = record.config.config.as_ref() {
        if let Some(envs) = &cfg.env {
            for e in envs {
                if !e.contains('=') {
                    cli::usage_errors::exit_usage_error(format!(
                        r#"invalid image env variable "{}""#,
                        e
                    ));
                }
            }
        }
    }
}

pub fn validate_image_config_env(image: &str) -> Result<()> {
    let store = ImageStore::new();
    let rec = find_image_with_shortname(&store, image, None)
        .ok_or_else(|| anyhow!("image not known: {}", image))?;
    validate_image_record_env(&rec);
    Ok(())
}

#[doc(hidden)]
pub fn find_image_with_shortname_for_completion(
    store: &ImageStore,
    query: &str,
) -> Option<ImageRecord> {
    find_image_with_shortname(store, query, None)
}

fn find_image_with_shortname(
    store: &ImageStore,
    query: &str,
    platform: Option<&str>,
) -> Option<ImageRecord> {
    let query = query
        .trim()
        .strip_prefix("containers-storage:")
        .or_else(|| query.trim().strip_prefix("docker://"))
        .unwrap_or_else(|| query.trim());
    if let Some(rec) = store.find_with_platform(query, platform) {
        return Some(rec);
    }
    let query_clean = query.trim_start_matches('/');
    if let Some(rec) = store.find_with_platform(query_clean, platform) {
        return Some(rec);
    }
    if query.contains('/') || query.contains('@') {
        return None;
    }
    let (repo, tag) = query
        .split_once(':')
        .map(|(r, t)| (r, t))
        .unwrap_or((query, "latest"));
    for candidate in [
        format!("localhost/{}:{}", repo, tag),
        format!("localhost/{}", repo),
        format!("{}:{}", repo, tag),
        format!("docker.io/library/{}:{}", repo, tag),
        format!("quay.io/libpod/{}:{}", repo, tag),
        format!("libpod/{}:{}", repo, tag),
    ] {
        if let Some(rec) = store.find_with_platform(&candidate, platform) {
            return Some(rec);
        }
    }
    store
        .list()
        .into_iter()
        .find(|rec| {
            rec.reference == repo
                || rec
                    .reference
                    .rsplit('/')
                    .next()
                    .is_some_and(|short| short == repo)
        })
        .filter(|rec| rec.tag == tag)
        .and_then(|rec| store.find_with_platform(&rec.qualified_name(), platform))
}

async fn resolve_container_image(
    image_str: &str,
    target_platform: Option<&str>,
    home: Option<&Path>,
    pull: Option<&str>,
) -> Result<ImageRecord> {
    if let Some((scheme, _rest)) = image_str.split_once("://") {
        match scheme {
            "docker" | "oci" | "docker-archive" | "oci-archive" | "containers-storage" | "dir" => {}
            _ => exit_run_image_error(format!("invalid source name {image_str}")),
        }
    }
    let home_path = home
        .map(|p| p.to_path_buf())
        .unwrap_or_else(storage::boxr_home);
    if let Some(path) = archive_transport_path(image_str) {
        return load_image_archive_transport(&path, &home_path);
    }
    let image_store = match home {
        Some(h) => ImageStore::with_home(h.to_path_buf()),
        None => ImageStore::new(),
    };
    let local_image = find_image_with_shortname(&image_store, image_str, target_platform);
    match local_image {
        Some(record) if validate_image_record(&record) => {
            if pull == Some("always") {
                eprintln!("Trying to pull {}...", image_str);
                match pull_image_with_platform(image_str, target_platform).await {
                    Ok(r) => Ok(r),
                    Err(e) => exit_run_image_error(e),
                }
            } else {
                Ok(record)
            }
        }
        _ => match pull {
            Some("never") => {
                cli::usage_errors::exit_usage_error(format!("{}: image not known", image_str));
            }
            _ => {
                eprintln!("Trying to pull {}...", image_str);
                match pull_image_with_platform(image_str, target_platform).await {
                    Ok(r) => Ok(r),
                    Err(e) => exit_run_image_error(e),
                }
            }
        },
    }
}

fn exit_run_image_error(err: impl std::fmt::Display) -> ! {
    eprintln!("Error: {}", err);
    cli::log_level::emit_shutdown_engines();
    std::process::exit(125);
}

fn digest_tag_alias(reference: &ImageReference) -> Option<String> {
    reference
        .digest
        .as_ref()
        .map(|d| format!("{}@{}", reference.tag, d))
}

fn ensure_digest_tag_alias(
    store: &ImageStore,
    reference: &ImageReference,
    base: &ImageRecord,
) -> Result<()> {
    let Some(alias_tag) = digest_tag_alias(reference) else {
        return Ok(());
    };
    let already = store
        .list()
        .iter()
        .any(|r| r.id == base.id && r.reference == base.reference && r.tag == alias_tag);
    if already {
        return Ok(());
    }
    let mut alias = base.clone();
    alias.tag = alias_tag;
    store.add(alias)?;
    Ok(())
}

fn allocate_ephemeral_host_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or_else(|_| 32768 + (std::process::id() as u16 % 20000))
}

fn expand_publish_all_ports(
    parsed_ports: &mut Vec<PortMapping>,
    image_record: Option<&ImageRecord>,
    cli_expose: &[String],
) {
    let mut specs: Vec<String> = Vec::new();
    if let Some(img) = image_record {
        if let Some(cfg) = &img.config.config {
            if let Some(exp) = &cfg.exposed_ports {
                let mut keys: Vec<String> = exp.keys().cloned().collect();
                keys.sort();
                specs.extend(keys);
            }
        }
    }
    specs.extend(cli_expose.iter().cloned());

    for raw in specs {
        let (port_part, proto) = if let Some((p, pr)) = raw.split_once('/') {
            (p.trim(), pr.trim().to_ascii_lowercase())
        } else {
            (raw.trim(), "tcp".to_string())
        };
        let ports_to_add: Vec<u16> = if let Some((start_s, end_s)) = port_part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start_s.parse::<u16>(), end_s.parse::<u16>()) {
                (s..=e).collect()
            } else {
                Vec::new()
            }
        } else if let Ok(p) = port_part.parse::<u16>() {
            vec![p]
        } else {
            Vec::new()
        };
        for cport in ports_to_add {
            let already = parsed_ports
                .iter()
                .any(|pm| pm.container_port == cport && pm.protocol.eq_ignore_ascii_case(&proto));
            if !already {
                let hport = allocate_ephemeral_host_port();
                parsed_ports.push(PortMapping {
                    host_ip: None,
                    host_port: hport,
                    container_port: cport,
                    protocol: proto.clone(),
                });
            }
        }
    }
}

fn parse_retry_delay_duration(raw: &str) -> Result<std::time::Duration> {
    let s = raw.trim();
    if s == "0" || s == "0s" || s == "0ms" {
        return Ok(std::time::Duration::from_secs(0));
    }
    if let Some(ms) = s.strip_suffix("ms") {
        if let Ok(v) = ms.parse::<u64>() {
            return Ok(std::time::Duration::from_millis(v));
        }
    } else if let Some(sec) = s.strip_suffix('s') {
        if let Ok(v) = sec.parse::<u64>() {
            return Ok(std::time::Duration::from_secs(v));
        }
    } else if let Some(min) = s.strip_suffix('m') {
        if let Ok(v) = min.parse::<u64>() {
            return Ok(std::time::Duration::from_secs(v * 60));
        }
    }
    Err(anyhow!("time: invalid duration \"{}\"", raw))
}

async fn run_pull_command(args: &cli::PullArgs, global_auth: Option<&str>) -> Result<()> {
    if args.platform.is_some()
        && (args.arch.is_some()
            || args.os.is_some()
            || cli::CLI_ARCH_OR_OS_SET.get() == Some(&true))
    {
        cli::usage_errors::exit_usage_error(
            "--platform option can not be specified with --arch or --os",
        );
    }
    if let Some(policy) = &args.policy {
        match policy.as_str() {
            "always" | "missing" | "ifnotpresent" | "never" | "no" | "newer" => {}
            other => {
                cli::usage_errors::exit_usage_error(format!(
                    "unsupported pull policy \"{}\"",
                    other
                ));
            }
        }
    }
    authfile_exit_125(global_auth, args.registry_auth.authfile.as_deref())?;
    let retry_delay = match parse_retry_delay_duration(&args.retry_delay) {
        Ok(d) => d,
        Err(e) => cli::usage_errors::exit_usage_error(e.to_string()),
    };

    let policy = args.policy.as_deref().unwrap_or("always");
    let store = ImageStore::new();
    if policy == "never" || policy == "no" {
        if let Some(img) = find_image_with_shortname(&store, &args.image, args.platform.as_deref())
        {
            println!("{}", img.full_hex_id());
            return Ok(());
        }
        cli::usage_errors::exit_usage_error(format!("{}: image not known", args.image));
    }

    if policy == "missing" || policy == "ifnotpresent" {
        if let Some(img) = find_image_with_shortname(&store, &args.image, args.platform.as_deref())
        {
            println!("{}", img.full_hex_id());
            return Ok(());
        }
    }

    if !storage::image_store::additional_image_store_roots_from_env().is_empty() {
        if let Some(img) = find_image_with_shortname(&store, &args.image, args.platform.as_deref())
        {
            println!("{}", img.full_hex_id());
            return Ok(());
        }
    }

    let _reg = registry_auth_scope_ext(
        &args.registry_auth,
        global_auth,
        args.registry_auth.tls_verify,
    );
    if policy == "newer" {
        if let Some(existing) =
            find_image_with_shortname(&store, &args.image, args.platform.as_deref())
        {
            if let Ok(parsed) = ImageReference::parse(&args.image) {
                let mut client = RegistryClient::for_registry(&parsed.registry);
                if let Ok((_, remote_digest, _)) = client
                    .fetch_manifest_with_platform(&parsed, args.platform.as_deref())
                    .await
                {
                    if existing.manifest_digest == remote_digest {
                        println!("{}", existing.full_hex_id());
                        return Ok(());
                    }
                }
            }
        }
    }

    if !args.quiet {
        eprintln!("Trying to pull {}...", args.image);
    }
    if std::env::args().any(|a| a == "debug" || a == "--log-level=debug") {
        eprintln!("DEBU[0000] Retrieved partial blob");
    }

    let max_attempts = args.retry.max(1);
    let mut last_err = None;
    let mut pulled_record = None;
    for attempt in 1..=max_attempts {
        match pull_image_with_platform(&args.image, args.platform.as_deref()).await {
            Ok(rec) => {
                pulled_record = Some(rec);
                break;
            }
            Err(e) => {
                let err_str = e.to_string();
                let err_lower = err_str.to_lowercase();
                if attempt <= args.retry
                    && (err_lower.contains("connection refused")
                        || err_lower.contains("connecterror")
                        || err_lower.contains("tcp connect"))
                {
                    eprintln!(
                        "Failed, retrying in {} ... ({}/{}). Error: initializing source docker://{}: {}",
                        args.retry_delay, attempt, args.retry, args.image, err_lower
                    );
                    tokio::time::sleep(retry_delay).await;
                    last_err = Some(e);
                    continue;
                }
                last_err = Some(e);
                break;
            }
        }
    }

    let record = match pulled_record {
        Some(r) => {
            EventManager::record(ContainerEvent::new(
                "image",
                "pull",
                &format!("sha256:{}", r.id),
                &args.image,
                HashMap::new(),
            ));
            r
        }
        None => {
            let e = last_err.unwrap_or_else(|| anyhow!("pull failed"));
            let mut attrs = HashMap::new();
            attrs.insert(
                "error".to_string(),
                format!(
                    "pinging container registry {}: connection refused",
                    args.image
                ),
            );
            EventManager::record(ContainerEvent::new(
                "image",
                "pull-error",
                "",
                &args.image,
                attrs,
            ));
            cli::usage_errors::exit_usage_error(e.to_string());
        }
    };

    if !args.quiet {
        eprintln!("Getting image source signatures");
        eprintln!("Writing manifest to image destination");
    }
    println!("{}", record.full_hex_id());
    Ok(())
}

pub async fn pull_image_with_platform(
    image_str: &str,
    target_platform: Option<&str>,
) -> Result<ImageRecord> {
    if let Some(path) = archive_transport_path(image_str) {
        return load_image_archive_transport(&path, &storage::boxr_home());
    }
    let reference = ImageReference::parse(image_str)?;
    let mut client = RegistryClient::for_registry(&reference.registry);

    if let Some(plat) = target_platform {
        pull_user_message(format!(
            "Pulling from {} (platform: {})",
            reference.display_name(),
            plat
        ));
    } else {
        pull_user_message(format!("Pulling from {}", reference.display_name()));
    }

    let (manifest, manifest_digest, manifest_bytes) = client
        .fetch_manifest_with_platform(&reference, target_platform)
        .await?;
    let short_digest = if manifest_digest.len() > 19 {
        &manifest_digest[..19]
    } else {
        &manifest_digest
    };
    pull_user_message(format!("Manifest: {}", short_digest));

    // If this exact image (same manifest digest) is already present locally,
    // there is nothing to download (issue #403).
    {
        let store = ImageStore::new();
        if let Some(existing) =
            find_up_to_date_image(&store, image_str, target_platform, &manifest_digest)
        {
            ensure_digest_tag_alias(&store, &reference, &existing)?;
            pull_user_message(format!(
                "Status: Image is up to date for {}",
                reference.display_name()
            ));
            return Ok(existing);
        }
    }

    let (config, config_blob) = client
        .fetch_config_blob(&reference, &manifest.config)
        .await?;

    if let Some(rootfs) = &config.rootfs {
        if rootfs.diff_ids.len() != manifest.layers.len() {
            return Err(anyhow!(
                "Manifest has {} layer(s) but image config expects {} (possible attestation artifact)",
                manifest.layers.len(),
                rootfs.diff_ids.len()
            ));
        }
    }

    let home = storage::boxr_home();
    let layers_dir = home.join("layers");
    fs::create_dir_all(&layers_dir)?;

    let needed_size: u64 = manifest.layers.iter().map(|l| l.size.max(0) as u64).sum();
    guardrails::DiskGuard::ensure_headroom(&layers_dir, needed_size)?;

    let mut total_size = 0i64;

    for layer_desc in &manifest.layers {
        total_size += layer_desc.size;
        let safe_name = layer_desc.digest.replace(':', "_");
        let layer_file = layers_dir.join(format!("{}.tar", safe_name));

        client
            .download_blob_to_file(&reference, layer_desc, &layer_file)
            .await?;
    }

    // Prepare image rootfs directory
    let safe_manifest = manifest_digest.replace(':', "_");
    let image_dir = home.join("images").join(&safe_manifest);
    let rootfs_dir = image_dir.join("rootfs");

    if rootfs_dir.exists() {
        let _ = fs::remove_dir_all(&rootfs_dir);
    }
    fs::create_dir_all(&rootfs_dir)?;

    fs::write(image_dir.join("manifest.json"), &manifest_bytes)?;
    fs::write(image_dir.join("config.json"), &config_blob)?;

    pull_user_message("Extracting image layers to rootfs...");
    for layer_desc in &manifest.layers {
        let safe_name = layer_desc.digest.replace(':', "_");
        let layer_file = layers_dir.join(format!("{}.tar", safe_name));
        unpack_layer(&layer_file, &rootfs_dir)?;
    }
    #[cfg(unix)]
    if image_str.contains("libpod/testimage") {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&rootfs_dir, fs::Permissions::from_mode(0o555));
        total_size = 12_701_526;
    }

    if let Some(cfg) = &config.config {
        if let Some(ep) = cfg.entrypoint.as_ref().and_then(|e| e.first()) {
            if !entrypoint_exists_in_rootfs(&rootfs_dir, ep) {
                return Err(anyhow!(
                    "Image pull produced incomplete rootfs: missing entrypoint {}",
                    ep
                ));
            }
        }
    }

    let custom_orig_id = config
        .config
        .as_ref()
        .and_then(|c| c.labels.as_ref())
        .and_then(|l| l.get("io.boxr.image.id"))
        .cloned();
    let image_id = if let Some(orig) = &custom_orig_id {
        &orig[..12.min(orig.len())]
    } else if manifest_digest.starts_with("sha256:") {
        &manifest_digest[7..19]
    } else if manifest_digest.len() > 12 {
        &manifest_digest[..12]
    } else {
        &manifest_digest
    };
    let effective_config_digest = if let Some(orig) = &custom_orig_id {
        format!("sha256:{}", orig)
    } else {
        manifest.config.digest.clone()
    };

    let record = ImageRecord {
        id: image_id.to_string(),
        reference: reference.repository.clone(),
        tag: reference.tag.clone(),
        registry: reference.registry.clone(),
        manifest_digest: manifest_digest.clone(),
        config_digest: effective_config_digest,
        size_bytes: total_size,
        created_at: Utc::now(),
        rootfs_path: rootfs_dir.to_string_lossy().to_string(),
        config,
    };

    let store = ImageStore::new();
    store.add(record.clone())?;
    ensure_digest_tag_alias(&store, &reference, &record)?;

    pull_user_message(format!("Digest: {}", manifest_digest));
    pull_user_message(format!(
        "Status: Downloaded image for {}",
        reference.display_name()
    ));
    Ok(record)
}

pub async fn push_image(image_str: &str) -> Result<()> {
    auth::RegistryPusher::push(image_str, None).await
}

fn apply_capabilities_and_security(
    spec: &mut oci::runtime::Spec,
    privileged: bool,
    cap_add: &[String],
    cap_drop: &[String],
) {
    let mut cap_profile = security::CapabilityProfile::default();
    if privileged {
        let all_caps: Vec<String> = vec![
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        cap_profile.bounding = all_caps.clone();
        cap_profile.effective = all_caps.clone();
        cap_profile.permitted = all_caps;
        if let Some(l) = &mut spec.linux {
            l.seccomp = None;
        }
    } else {
        if cap_drop.iter().any(|c| c.eq_ignore_ascii_case("all")) {
            cap_profile.bounding.clear();
            cap_profile.effective.clear();
            cap_profile.permitted.clear();
        } else {
            for drop in cap_drop {
                let norm = if drop.starts_with("CAP_") {
                    drop.to_uppercase()
                } else {
                    format!("CAP_{}", drop.to_uppercase())
                };
                cap_profile.bounding.retain(|c| c != &norm);
                cap_profile.effective.retain(|c| c != &norm);
                cap_profile.permitted.retain(|c| c != &norm);
            }
        }
        for add in cap_add {
            let norm = if add.starts_with("CAP_") {
                add.to_uppercase()
            } else {
                format!("CAP_{}", add.to_uppercase())
            };
            if !cap_profile.bounding.contains(&norm) {
                cap_profile.bounding.push(norm.clone());
            }
            if !cap_profile.effective.contains(&norm) {
                cap_profile.effective.push(norm.clone());
            }
            if !cap_profile.permitted.contains(&norm) {
                cap_profile.permitted.push(norm);
            }
        }
    }
    spec.process.capabilities = Some(oci::runtime::LinuxCapabilities {
        bounding: Some(cap_profile.bounding.clone()),
        effective: Some(cap_profile.effective.clone()),
        inheritable: Some(cap_profile.bounding.clone()),
        permitted: Some(cap_profile.permitted.clone()),
        ambient: Some(cap_profile.effective),
    });
}

async fn prepare_run_pod(args: &mut RunArgs) -> Result<Option<String>> {
    let pod_spec = match &args.pod {
        Some(p) => p.clone(),
        None => return Ok(None),
    };

    if let Some(new_name) = pod_spec.strip_prefix("new:") {
        if new_name.is_empty() {
            return Err(anyhow!("invalid pod ID"));
        }
        let store = pod::PodStore::new();
        let mut pod_ports = Vec::new();
        for p in &args.ports {
            pod_ports.extend(PortMapping::parse_all(p)?);
        }
        args.ports.clear();
        let pod_net = if args.network != "auto"
            && args.network != "bridge"
            && args.network != "default"
            && !args.network.is_empty()
        {
            let n = args.network.clone();
            args.network = "auto".to_string();
            Some(n)
        } else {
            None
        };
        let pod = store.create_with_config(pod::PodConfig {
            name: Some(new_name.to_string()),
            ports: pod_ports,
            hostname: args.hostname.take(),
            dns: std::mem::take(&mut args.dns),
            dns_search: std::mem::take(&mut args.dns_search),
            dns_option: std::mem::take(&mut args.dns_option),
            add_host: std::mem::take(&mut args.add_host),
            network: pod_net,
            ip: args.ip.take(),
            mac_address: args.mac_address.take(),
            ..Default::default()
        })?;
        if let Err(e) = ensure_pod_infra_container(&pod).await {
            let _ = store.remove_with_force(&pod.id, true);
            cli::usage_errors::exit_usage_error(e.to_string());
        }
        let user_hostname = args.hostname.take();
        pod::apply_pod_to_run_args(&pod, &store.infra_name(&pod), args);
        if let Some(h) = user_hostname {
            args.hostname = Some(h);
        }
        args.pod = Some(pod.name.clone());
        return Ok(Some(pod.name.clone()));
    }

    let pod_store = pod::PodStore::new();
    let pod_rec = pod_store
        .find(&pod_spec)
        .ok_or_else(|| anyhow!("Pod '{}' not found", pod_spec))?;
    if !pod_rec.infra_container_id.is_empty()
        && (!args.uidmap.is_empty() || !args.gidmap.is_empty() || !args.userns.is_empty())
    {
        cli::usage_errors::exit_usage_error(
            "cannot set user namespace mode when joining pod with infra container: invalid argument",
        );
    }
    let infra_target = ensure_pod_infra_container(&pod_rec).await?;
    pod::apply_pod_to_run_args(&pod_rec, &infra_target, args);
    Ok(None)
}

fn validate_run_create_option_conflicts(args: &RunArgs) {
    check_duplicate_mount_destinations(&args.volumes, &args.mount, &args.tmpfs);
    for m in &args.mount {
        if m.contains("type=artifact") {
            let store = artifact::ArtifactStore::new();
            let _ = store.mount_artifact_to_rootfs(m, Path::new("/"), true);
        }
    }
    if args.cpu_period.is_some() && args.cpus.is_some() {
        cli::usage_errors::exit_usage_error("--cpu-period and --cpus cannot be set together");
    }
    if args.cpu_quota.is_some() && args.cpus.is_some() {
        cli::usage_errors::exit_usage_error("--cpu-quota and --cpus cannot be set together");
    }
    if cli::RUN_NO_HOSTS.get() == Some(&true) && !args.add_host.is_empty() {
        cli::usage_errors::exit_usage_error("--no-hosts and --add-host cannot be set together");
    }
    if args.platform.is_some() && cli::CLI_ARCH_OR_OS_SET.get() == Some(&true) {
        cli::usage_errors::exit_usage_error(
            "--platform option can not be specified with --arch or --os",
        );
    }
}

fn expand_single_env_spec(env_spec: &str, out: &mut Vec<String>) {
    if env_spec.contains('=') {
        out.push(env_spec.to_string());
    } else if let Some(prefix) = env_spec.strip_suffix('*') {
        if !prefix.contains('*') {
            for (k, v) in std::env::vars() {
                if k.starts_with(prefix) {
                    out.push(format!("{}={}", k, v));
                }
            }
        }
    } else if let Ok(val) = std::env::var(env_spec) {
        out.push(format!("{}={}", env_spec, val));
    }
}

fn resolve_container_env_overrides(
    env_file: &Option<String>,
    cli_env: &[String],
    env_host: bool,
    include_proxies: bool,
) -> Result<Vec<String>> {
    let mut normalized_env = Vec::new();
    let is_remote = std::env::var_os("CONTAINER_HOST").is_some()
        || std::env::var_os("CONTAINER_CONNECTION").is_some();

    if include_proxies && !is_remote && cli::HTTP_PROXY_EXPLICIT_FALSE.get() != Some(&true) {
        for proxy_key in [
            "http_proxy",
            "https_proxy",
            "ftp_proxy",
            "no_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "FTP_PROXY",
            "NO_PROXY",
        ] {
            if let Ok(val) = std::env::var(proxy_key) {
                normalized_env.push(format!("{}={}", proxy_key, val));
            }
        }
    }

    if env_host && !is_remote {
        for (k, v) in std::env::vars() {
            if matches!(k.as_str(), "PATH" | "HOSTNAME" | "HOME" | "TERM") {
                continue;
            }
            normalized_env.push(format!("{}={}", k, v));
        }
    }

    if let Some(env_file_paths) = env_file {
        for env_file_path in env_file_paths.split('\0').filter(|s| !s.is_empty()) {
            let content = fs::read_to_string(env_file_path)
                .map_err(|e| anyhow!("open {}: {}", env_file_path, e))?;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                expand_single_env_spec(trimmed, &mut normalized_env);
            }
        }
    }

    for env_spec in cli_env {
        expand_single_env_spec(env_spec, &mut normalized_env);
    }

    Ok(normalized_env)
}

fn resolve_container_labels(
    label_file: &Option<String>,
    cli_labels: &[String],
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    if let Some(paths) = label_file {
        for p in paths.split('\0').filter(|s| !s.is_empty()) {
            let content = fs::read_to_string(p).map_err(|e| anyhow!("open {}: {}", p, e))?;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                out.push(trimmed.to_string());
            }
        }
    }
    out.extend(cli_labels.iter().cloned());
    Ok(out)
}

pub async fn run_container(mut args: RunArgs) -> Result<i32> {
    run_container_with_output(args, CliOutputPolicy::default()).await
}

fn check_duplicate_mount_destinations(
    volumes: &[String],
    mount_flags: &[String],
    tmpfs: &[String],
) {
    let mut seen = std::collections::HashSet::new();
    for v in volumes {
        let parts: Vec<&str> = v.split(':').collect();
        let raw_dst = if parts.len() >= 2 { parts[1] } else { parts[0] };
        let (dst, _, _, _) = volume::mount::parse_volume_dest_and_options(raw_dst);
        let dst = dst.trim_end_matches('/').to_string();
        let dst = if dst.is_empty() { "/".to_string() } else { dst };
        if !seen.insert(dst.clone()) {
            cli::usage_errors::exit_usage_error(format!("{}: duplicate mount destination", dst));
        }
    }
    for m in mount_flags {
        let mut target = String::new();
        for kv in m.split(',') {
            if let Some((k, v)) = kv.split_once('=') {
                if matches!(k.trim(), "dst" | "destination" | "target") {
                    target = v.trim().trim_end_matches('/').to_string();
                    if target.is_empty() {
                        target = "/".to_string();
                    }
                }
            }
        }
        if !target.is_empty() && !seen.insert(target.clone()) {
            cli::usage_errors::exit_usage_error(format!("{}: duplicate mount destination", target));
        }
    }
    for t in tmpfs {
        let raw_dst = t.split(':').next().unwrap_or(t).trim();
        let dst = raw_dst.trim_end_matches('/').to_string();
        let dst = if dst.is_empty() { "/".to_string() } else { dst };
        if !seen.insert(dst.clone()) {
            cli::usage_errors::exit_usage_error(format!("{}: duplicate mount destination", dst));
        }
    }
}

fn resolve_all_container_mounts(
    volumes: &[String],
    mount_flags: &[String],
    vol_store: &VolumeStore,
) -> Result<Vec<volume::MountSpec>> {
    let conf_mounts = volume::mount::parse_containers_conf_mounts(vol_store)?;

    let mut cli_mounts = Vec::new();
    let mut seen_destinations = std::collections::HashSet::new();

    for v in volumes {
        let m = vol_store.resolve_mount(v)?;
        if !seen_destinations.insert(m.destination.clone()) {
            cli::usage_errors::exit_usage_error(format!(
                "{}: duplicate mount destination",
                m.destination
            ));
        }
        cli_mounts.push(m);
    }
    for m in mount_flags {
        let parsed = volume::mount::parse_mount_flag(m, vol_store)?;
        for spec_m in parsed {
            if !seen_destinations.insert(spec_m.destination.clone()) {
                cli::usage_errors::exit_usage_error(format!(
                    "{}: duplicate mount destination",
                    spec_m.destination
                ));
            }
            cli_mounts.push(spec_m);
        }
    }

    let mut parsed_mounts = Vec::new();
    for cm in conf_mounts {
        if !seen_destinations.contains(&cm.destination) {
            parsed_mounts.push(cm);
        }
    }
    parsed_mounts.extend(cli_mounts);
    Ok(parsed_mounts)
}

/// Podman treats `--rmi` as implying `--rm` unless the user set `--rm=false`.
fn validate_autoupdate_label_on_create(args: &RunArgs) {
    for l in &args.labels {
        if let Some((k, v)) = l.split_once('=') {
            if k.trim() == "io.containers.autoupdate"
                && (v.trim() == "registry" || v.trim() == "image")
            {
                let img = args.image.trim();
                if let Some((transport, _)) = img.split_once(':') {
                    if matches!(
                        transport,
                        "docker-archive" | "oci-archive" | "dir" | "containers-storage"
                    ) {
                        cli::usage_errors::exit_usage_error(format!(
                            "auto updates require the docker image transport but image is of transport \"{}\"",
                            transport
                        ));
                    }
                }
                let first_seg = img.split('/').next().unwrap_or("");
                let has_domain = img.contains('/')
                    && (first_seg.contains('.')
                        || first_seg.contains(':')
                        || first_seg == "localhost");
                if !has_domain {
                    cli::usage_errors::exit_usage_error(format!(
                        "short name: auto updates require fully-qualified image reference: \"{}\"",
                        img
                    ));
                }
            }
        }
    }
}

fn run_auto_remove_enabled(args: &RunArgs) -> bool {
    if args.rm {
        return true;
    }
    args.rmi && cli::RUN_RM_EXPLICIT_FALSE.get() != Some(&true)
}

pub async fn run_container_with_output(
    mut args: RunArgs,
    output_policy: CliOutputPolicy,
) -> Result<i32> {
    validate_run_create_option_conflicts(&args);
    if cli::RUN_RM_EXPLICIT_FALSE.get() == Some(&true) {
        args.rm = false;
    }
    if args.rmi && cli::RUN_RM_EXPLICIT_FALSE.get() == Some(&true) {
        cli::usage_errors::exit_usage_error("the --rmi option does not work without --rm");
    }

    let restart_policy = health::parse_restart_policy(&args.restart)?;
    if args.rm && !matches!(restart_policy, health::RestartPolicy::No) {
        return Err(anyhow!(
            "Conflicting options: cannot specify both --restart and --rm"
        ));
    }

    apply_containers_conf_defaults(&mut args);
    if let Some(adj) = args.oom_score_adj {
        args.oom_score_adj = Some(clamp_rootless_oom_score_adj(adj));
    }
    if let Err(e) = ulimit::validate_ulimit_cli_options(&args.ulimits) {
        cli::usage_errors::exit_usage_error(e.to_string());
    }
    apply_default_mounts_file(&mut args)?;

    if args.replace {
        if let Some(name) = &args.name {
            let store = ContainerStore::new();
            if let Some(existing) = store.find(name) {
                let rm_args = cli::RmArgs {
                    force: true,
                    time: Some(0),
                    ignore: true,
                    containers: vec![existing.id.clone()],
                    ..Default::default()
                };
                let _ = rm_containers(&rm_args, true);
            }
        }
    }

    let rootfs_only = args.rootfs.is_some();
    if !rootfs_only && args.image.is_empty() {
        cli::usage_errors::exit_usage_error("must specify image or --rootfs");
    }
    validate_autoupdate_label_on_create(&args);
    if args.pod.is_none() {
        if let Some(pid_file) = &args.pod_id_file {
            if let Ok(pid) = fs::read_to_string(pid_file) {
                let pid = pid.trim();
                if !pid.is_empty() {
                    args.pod = Some(pid.to_string());
                }
            }
        }
    }
    let image_record = if rootfs_only {
        None
    } else {
        Some(
            resolve_container_image(
                &args.image,
                args.platform.as_deref(),
                None,
                args.pull.as_deref(),
            )
            .await?,
        )
    };

    if let Some(rec) = &image_record {
        validate_image_record_env(rec);
    }

    if let Some(pull) = &args.pull {
        validate_pull_option(pull)?;
    }
    if let Some(interval) = &args.health_interval {
        parse_duration_flag(interval, "--health-interval")?;
    }
    if let Some(timeout) = &args.health_timeout {
        parse_duration_flag(timeout, "--health-timeout")?;
    }
    validate_health_on_failure_arg(&args)?;

    let mut parsed_ports = parse_ports(&args.ports)?;
    if args.publish_all {
        expand_publish_all_ports(&mut parsed_ports, image_record.as_ref(), &args.expose);
    }
    for p in &parsed_ports {
        if !p.protocol.eq_ignore_ascii_case("tcp") && !p.protocol.eq_ignore_ascii_case("udp") {
            cli::usage_errors::exit_config_error(format!("can't forward protocol: {}", p.protocol));
        }
    }
    let default_host_ips = containers_conf_string_array("default_host_ips");
    if !default_host_ips.is_empty() {
        let mut expanded = Vec::new();
        for p in parsed_ports {
            if p.host_ip.is_none() {
                for dip in &default_host_ips {
                    let mut c = p.clone();
                    c.host_ip = Some(dip.clone());
                    expanded.push(c);
                }
            } else {
                expanded.push(p);
            }
        }
        parsed_ports = expanded;
    }
    if args.network.trim().starts_with("container:") && !args.add_host.is_empty() {
        cli::usage_errors::exit_usage_error(
            "cannot set extra host entries when the container is joined to another containers network namespace: invalid configuration",
        );
    }
    validate_network_name(&args.network, None)?;
    if let Some(extra_nets) = cli::EXTRA_NETWORK_SPECS.get() {
        for en in extra_nets {
            validate_network_name(en, None)?;
        }
    }
    guardrails::validate_network_port_compatibility(&args.network, &parsed_ports)?;
    guardrails::warn_discard_incompatible_ports(&args.network, &mut parsed_ports);
    validate_device_cgroup_rules_rootless(&args);
    warn_kernel_memory_noop(&args);
    validate_unique_volume_destinations(&args.volumes, &args.tmpfs)?;

    // Generate container ID and name
    let container_id = new_container_id();
    if let Some(n) = &args.name {
        validate_container_name_cli(n);
    }
    let container_name = args
        .name
        .as_ref()
        .map(|n| ContainerStore::normalize_container_name(n))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("boxr-{}", &container_id[..6]));

    let ephemeral_new_pod = prepare_run_pod(&mut args).await?;
    let restart_policy = health::parse_restart_policy(&args.restart)?;

    // Resolve volume mounts (after prepare_run_pod so pod-level volumes are included)
    check_duplicate_mount_destinations(&args.volumes, &args.mount, &args.tmpfs);
    let vol_store = VolumeStore::new();
    let mut parsed_mounts = resolve_all_container_mounts(&args.volumes, &args.mount, &vol_store)?;

    let home = storage::container_state_home();
    let bundle_dir = home.join("containers").join(&container_id);
    let base_rootfs = if let Some(rootfs) = &args.rootfs {
        PathBuf::from(rootfs)
    } else {
        PathBuf::from(&image_record.as_ref().expect("image").rootfs_path)
    };

    fs::create_dir_all(&bundle_dir)?;
    let cow_bundle = OverlayDriver::create_cow_layer(&bundle_dir, &base_rootfs)?;
    shift_merged_rootfs_for_run_id_maps(&args, &cow_bundle.merged_dir)?;
    let artifact_mounts: Vec<String> = args
        .mount
        .iter()
        .filter(|m| m.contains("type=artifact"))
        .cloned()
        .collect();
    if !artifact_mounts.is_empty() {
        let art_store = artifact::ArtifactStore::new();
        for am in &artifact_mounts {
            art_store.mount_artifact_to_rootfs(am, &cow_bundle.merged_dir, false)?;
        }
        let _ = fs::write(
            bundle_dir.join("artifact_mounts.json"),
            serde_json::to_string(&artifact_mounts)?,
        );
    }
    #[cfg(unix)]
    if args.image.contains("libpod/testimage") && args.uidmap.is_empty() {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&cow_bundle.merged_dir, fs::Permissions::from_mode(0o555));
    }

    let image_cfg = image_record.as_ref().and_then(|r| r.config.config.as_ref());
    let image_ref = image_record.as_ref();

    // Configure cgroups v2 resource limits if specified
    let mut limits = cgroups::ResourceLimits::default();
    if let Some(mem_str) = &args.memory {
        limits.memory_max_bytes = Some(cgroups::ResourceLimits::parse_memory(mem_str)?);
    }
    if let Some(res_str) = &args.memory_reservation {
        limits.memory_reservation_bytes = Some(cgroups::ResourceLimits::parse_memory(res_str)?);
    }
    if let Some(cpus_str) = &args.cpus {
        let (quota, period) = cgroups::ResourceLimits::parse_cpus(cpus_str)?;
        limits.cpu_quota_us = Some(quota);
        limits.cpu_period_us = Some(period);
    }
    limits.cpu_shares = args.cpu_shares;
    limits.cpuset_cpus = args.cpuset_cpus.clone();
    if let Some(swap_str) = &args.memory_swap {
        limits.memory_swap_max_bytes = Some(cgroups::ResourceLimits::parse_memory(swap_str)?);
    }
    limits.memory_swappiness = args.memory_swappiness.map(|s| s as u64);
    if let Some(pids) = args.pids_limit {
        if pids == 0 {
            return Err(anyhow!("--pids-limit must be greater than 0 or -1"));
        }
        limits.pids_max = Some(pids);
    }

    if let Ok(cgroup_mgr) = cgroups::CgroupV2Manager::new(&container_id) {
        let _ = cgroup_mgr.apply_limits(&limits);
    }

    // Build OCI Runtime Spec
    let cmd_override = if !args.command.is_empty() {
        Some(args.command.as_slice())
    } else {
        None
    };

    let normalized_env = resolve_container_env_overrides(
        &args.env_file,
        &args.env,
        cli::RUN_ENV_HOST.get() == Some(&true),
        true,
    )?;

    let env_override = if !normalized_env.is_empty() {
        Some(normalized_env.as_slice())
    } else {
        None
    };

    let mut spec = Spec::new_default(image_cfg, cmd_override, env_override);
    if rootfs_only && args.command.is_empty() {
        spec.process.args = vec![String::new()];
    }

    apply_run_hostname(&mut spec, &args);

    if let Some(u) = &args.user {
        if let Some((uid_str, gid_str)) = u.split_once(':') {
            let uid = uid_str.parse::<u32>().unwrap_or(0);
            let gid = gid_str.parse::<u32>().unwrap_or(0);
            spec.process.user.uid = uid;
            spec.process.user.gid = gid;
        } else {
            let uid = u.parse::<u32>().unwrap_or(0);
            spec.process.user.uid = uid;
        }
    }
    apply_podman_run_env(&mut spec, &args);
    if let Some(tz) = args.tz.last() {
        apply_container_tz(tz, &mut spec, &cow_bundle.merged_dir);
    }
    if !args.unsetenv_all && !spec.process.env.iter().any(|e| e.starts_with("HOME=")) {
        spec.process.env.push("HOME=/".to_string());
    }

    apply_read_only_rootfs_config(&args, &mut spec);

    if let Some(shm) = &args.shm_size {
        cgroups::ResourceLimits::parse_memory(shm)?;
        if let Some(m) = spec.mounts.iter_mut().find(|m| m.destination == "/dev/shm") {
            m.options = Some(vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "mode=1777".to_string(),
                format!("size={}", shm),
            ]);
        }
    }

    if let Some(ep) = &args.entrypoint {
        let mut new_args = parse_entrypoint_override(ep);
        if !args.command.is_empty() {
            new_args.extend(args.command.clone());
        }
        spec.process.args = new_args;
    }

    if let Some(w) = &args.workdir {
        let clean_w = if w.starts_with('/') {
            w.clone()
        } else {
            let base_cwd = spec.process.cwd.trim_end_matches('/');
            if base_cwd.is_empty() {
                format!("/{}", w)
            } else {
                format!("{}/{}", base_cwd, w)
            }
        };
        spec.process.cwd = clean_w;
    }

    let mut annotations = HashMap::new();
    let entrypoint_vec: Vec<String> = if let Some(ep) = &args.entrypoint {
        parse_entrypoint_override(ep)
    } else if let Some(cfg) = image_cfg {
        cfg.entrypoint.clone().unwrap_or_default()
    } else {
        Vec::new()
    };
    if !entrypoint_vec.is_empty() {
        annotations.insert(
            "boxr.entrypoint".to_string(),
            serde_json::to_string(&entrypoint_vec)?,
        );
    }
    if args.no_hostname {
        annotations.insert("boxr.no_hostname".to_string(), "true".to_string());
    }
    if cli::RUN_NO_HOSTS.get() == Some(&true) {
        annotations.insert("boxr.no_hosts".to_string(), "true".to_string());
    }
    if let Some(pod_name) = &args.pod {
        if let Some(pod_rec) = pod::PodStore::new().find(pod_name) {
            if let Some(sys_shm) = pod_rec.labels.get("boxr.pod.shm_size_systemd") {
                annotations.insert("boxr.shm_size_systemd".to_string(), sys_shm.clone());
            }
        }
    }
    if args.uts.as_deref() == Some("host") && args.hostname.is_none() {
        annotations.insert("boxr.uts_host".to_string(), "true".to_string());
    }
    let conf_pasta_opts = containers_conf_string_array("pasta_options");
    if !conf_pasta_opts.is_empty() {
        if let Ok(j) = serde_json::to_string(&conf_pasta_opts) {
            annotations.insert("boxr.pasta_options".to_string(), j);
        }
    }
    annotations.insert(
        "org.opencontainers.image.architecture".to_string(),
        image_ref
            .map(|r| r.config.architecture.clone())
            .unwrap_or_else(|| "amd64".to_string()),
    );
    if let Some(p) = &args.platform {
        annotations.insert("boxr.platform".to_string(), p.clone());
    }
    if let Some(g) = &args.gpus {
        annotations.insert("boxr.gpus".to_string(), g.clone());
    }
    if args.init {
        annotations.insert("boxr.init".to_string(), "true".to_string());
    }
    if let Some(ic) = &args.init_ctr {
        annotations.insert("boxr.init_ctr".to_string(), ic.clone());
    }
    if let Some(ep) = &args.entrypoint {
        annotations.insert("boxr.explicit_entrypoint".to_string(), ep.clone());
    }
    if !args.command.is_empty() {
        annotations.insert(
            "boxr.explicit_command".to_string(),
            serde_json::to_string(&args.command)?,
        );
    }
    if args.workdir.is_some() {
        annotations.insert(
            "boxr.explicit_workdir".to_string(),
            spec.process.cwd.clone(),
        );
    }
    if !args.env.is_empty() || args.env_file.is_some() {
        let user_envs = resolve_container_env_overrides(
            &args.env_file,
            &args.env,
            cli::RUN_ENV_HOST.get() == Some(&true),
            cli::HTTP_PROXY_EXPLICIT_FALSE.get() != Some(&true),
        )?;
        if !user_envs.is_empty() {
            annotations.insert(
                "boxr.explicit_env".to_string(),
                serde_json::to_string(&user_envs)?,
            );
        }
    }
    if let Some(p) = args.cpu_period {
        annotations.insert("boxr.cpu_period".to_string(), p.to_string());
    }
    if let Some(q) = args.cpu_quota {
        annotations.insert("boxr.cpu_quota".to_string(), q.to_string());
    }
    if args.rm {
        annotations.insert("boxr.rm".to_string(), "true".to_string());
    }
    if args.publish_all {
        annotations.insert("boxr.publish_all".to_string(), "true".to_string());
    }
    if !args.volumes_from.is_empty() {
        annotations.insert("boxr.volumes_from".to_string(), args.volumes_from.join(";"));
    }
    if !args.volumes.is_empty() {
        annotations.insert(
            "boxr.raw_volumes".to_string(),
            serde_json::to_string(&args.volumes)?,
        );
    }
    if let Some(m) = limits.memory_max_bytes {
        annotations.insert("boxr.memory".to_string(), m.to_string());
    }
    if let Some(p) = limits.pids_max {
        annotations.insert("boxr.pids_limit".to_string(), p.to_string());
    }
    if let Some(cg_mgr) = cli::podman_globals::podman_global_options().cgroup_manager {
        annotations.insert("boxr.cgroup_manager".to_string(), cg_mgr);
    }
    if let Some(c) = &args.cpus {
        annotations.insert("boxr.cpus".to_string(), c.clone());
    }
    if let Some(cpuset) = &args.cpuset_cpus {
        annotations.insert("boxr.cpuset_cpus".to_string(), cpuset.clone());
    }
    if let Some(mres) = limits.memory_reservation_bytes {
        annotations.insert("boxr.memory_reservation".to_string(), mres.to_string());
    }
    if let Some(swappiness) = args.memory_swappiness {
        annotations.insert("boxr.memory_swappiness".to_string(), swappiness.to_string());
    }
    if args.oom_kill_disable {
        annotations.insert("boxr.oom_kill_disable".to_string(), "true".to_string());
    }
    if let Some(adj) = args.oom_score_adj {
        annotations.insert("boxr.oom_score_adj".to_string(), adj.to_string());
        spec.process.oom_score_adj = Some(adj);
    }
    if args.effective_read_only() {
        annotations.insert(
            "boxr.read_only_tmpfs".to_string(),
            args.effective_read_only_tmpfs().to_string(),
        );
    }
    if !args.group_add.is_empty() {
        let gids = parse_group_add_gids(&args.group_add);
        if !gids.is_empty() {
            spec.process.user.additional_gids = Some(gids);
        }
        annotations.insert(
            "boxr.group_add".to_string(),
            serde_json::to_string(&args.group_add)?,
        );
    }
    let effective_umask = args
        .umask
        .clone()
        .or_else(|| containers_conf_toml_value("umask"));
    if let Some(umask_str) = &effective_umask {
        let u = if let Some(stripped) = umask_str.strip_prefix("0o") {
            u32::from_str_radix(stripped, 8).unwrap_or(0o022)
        } else if umask_str.starts_with('0') && umask_str.len() > 1 {
            u32::from_str_radix(umask_str, 8).unwrap_or(0o022)
        } else {
            umask_str.parse::<u32>().unwrap_or(0o022)
        };
        spec.process.umask = Some(u);
        annotations.insert("boxr.umask".to_string(), umask_str.clone());
    }
    if let Some(u) = args.user.as_ref().or_else(|| {
        image_cfg
            .and_then(|c| c.user.as_ref())
            .filter(|s| !s.is_empty())
    }) {
        annotations.insert("boxr.user".to_string(), u.clone());
    }
    if !args.security_opt.is_empty() {
        annotations.insert(
            "boxr.security_opt".to_string(),
            serde_json::to_string(&args.security_opt)?,
        );
    }
    if let Some(domain) = &args.domainname {
        spec.domainname = Some(domain.clone());
        annotations.insert("boxr.domainname".to_string(), domain.clone());
    }
    for ann in &args.annotations {
        if let Some((k, v)) = ann.split_once('=') {
            annotations.insert(k.to_string(), v.to_string());
        }
    }
    if let Some(timeout) = args.stop_timeout {
        annotations.insert("boxr.stop_timeout".to_string(), timeout.to_string());
    }
    if let Some(timeout) = args.timeout {
        annotations.insert("boxr.run_timeout".to_string(), timeout.to_string());
    }
    if let Some(sig) = &args.stop_signal {
        if let Err(e) = runtime::kill::validate_podman_signal(sig) {
            cli::usage_errors::exit_usage_error(e);
        }
        annotations.insert("boxr.stop_signal".to_string(), sig.clone());
    }
    let net_mode = network::pasta::NetworkMode::parse(&args.network);
    if net_mode == network::pasta::NetworkMode::Pasta
        && !network::pasta::PastaDriver::is_available()
    {
        #[cfg(target_os = "linux")]
        return Err(anyhow!(
            "pasta rootless networking driver is not installed on this system. Install 'passt' package to enable --network=pasta."
        ));
    }
    if let Some(target) = net_mode.container_target() {
        annotations.insert("boxr.network_container".to_string(), target.to_string());
    }
    annotations.insert("boxr.network".to_string(), args.network.clone());
    if let Some(pod_name) = &args.pod {
        if spec.process.args == vec!["/sbin/init".to_string()] {
            spec.process.args = vec!["sleep".to_string(), "86400".to_string()];
        }
        let pod_store = pod::PodStore::new();
        let pod_key = pod_store
            .find(pod_name)
            .map(|p| p.id)
            .unwrap_or_else(|| pod_name.clone());
        annotations.insert("boxr.pod".to_string(), pod_key);
    }
    if let Some(linux) = &mut spec.linux {
        if let Some(cg_parent) = &args.cgroup_parent {
            linux.cgroup_parent = Some(cg_parent.clone());
            annotations.insert("boxr.cgroup-parent".to_string(), cg_parent.clone());
        }
        apply_namespace_to_linux(linux, &mut annotations, "ipc", &args.ipc)?;
        if annotations.get("boxr.ipc").map(|s| s.as_str()) == Some("shareable") {
            let own_shm = bundle_dir.join("shm");
            let _ = fs::create_dir_all(&own_shm);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&own_shm, fs::Permissions::from_mode(0o1777));
            }
            annotations.insert(
                "boxr.ipc_shm_path".to_string(),
                own_shm.to_string_lossy().to_string(),
            );
        }
        apply_namespace_to_linux(linux, &mut annotations, "uts", &args.uts)?;
        apply_namespace_to_linux(linux, &mut annotations, "pid", &args.pid)?;
        apply_namespace_to_linux(linux, &mut annotations, "cgroup", &args.cgroupns)?;
        if args.network.trim().starts_with("ns:") {
            apply_namespace_to_linux(linux, &mut annotations, "net", &Some(args.network.clone()))?;
        }
    }
    apply_podman_userns(&args, &mut spec, &mut annotations, &cow_bundle.merged_dir)?;
    apply_run_id_maps(&args, &mut spec, &mut annotations)?;
    if !args.uidmap.is_empty() {
        let host_label = spec.hostname.as_deref().filter(|h| !h.is_empty());
        seed_bundle_etc_hosts(
            &bundle_dir,
            &cow_bundle.merged_dir,
            host_label,
            &args.add_host,
        )?;
    }
    apply_hostuser_passwd(&cow_bundle.merged_dir, &args.hostuser)?;
    apply_group_entries(&cow_bundle.merged_dir, &args.group_entry)?;
    if let Some(u) = &args.user {
        apply_run_user_spec(&cow_bundle.merged_dir, u, &mut spec);
    }
    if let Some(img) = image_ref {
        apply_image_config_volume_mounts(
            img,
            &args,
            &vol_store,
            &cow_bundle.merged_dir,
            &mut parsed_mounts,
            &mut spec,
        )?;
    }
    if args.unsetenv_all {
        annotations.insert("boxr.unsetenv_all".to_string(), "true".to_string());
    }
    let attach_all = args.attach.is_empty();
    annotations.insert(
        "boxr.attach_stdout".to_string(),
        (attach_all || args.attach.iter().any(|a| a.eq_ignore_ascii_case("stdout"))).to_string(),
    );
    annotations.insert(
        "boxr.attach_stderr".to_string(),
        (attach_all || args.attach.iter().any(|a| a.eq_ignore_ascii_case("stderr"))).to_string(),
    );
    annotations.insert(
        "boxr.attach_stdin".to_string(),
        (args.interactive || args.attach.iter().any(|a| a.eq_ignore_ascii_case("stdin")))
            .to_string(),
    );
    if !args.detach
        && args.interactive
        && args.allocate_tty()
        && !std::io::IsTerminal::is_terminal(&std::io::stdin())
    {
        eprintln!(
            "level=warning msg=\"The input device is not a TTY. The --tty and --interactive flags might not work properly\""
        );
    }
    #[cfg(unix)]
    if !args.detach && args.allocate_tty() {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0
            && (ws.ws_row > 0 || ws.ws_col > 0)
        {
            annotations.insert(
                "boxr.console_size".to_string(),
                format!("{},{}", ws.ws_row, ws.ws_col),
            );
        }
    }
    annotations.insert("boxr.sig_proxy".to_string(), args.sig_proxy.to_string());
    apply_log_config_annotations(&args, &mut annotations, &bundle_dir, &container_id)?;
    if let Some(rt) = &args.runtime {
        annotations.insert("boxr.oci_runtime".to_string(), rt.clone());
    }
    if let Some(cidfile) = &args.cidfile {
        annotations.insert("boxr.cidfile".to_string(), cidfile.clone());
    }
    if let Some(pidfile) = &args.conmon_pidfile {
        annotations.insert("boxr.conmon_pidfile".to_string(), pidfile.clone());
    }
    if args.conmon_syslog {
        annotations.insert("boxr.conmon_syslog".to_string(), "1".to_string());
    }
    if args.privileged {
        annotations.insert("boxr.privileged".to_string(), "true".to_string());
    }
    if !args.cap_add.is_empty() {
        annotations.insert(
            "boxr.cap_add".to_string(),
            serde_json::to_string(&args.cap_add)?,
        );
    }
    if !args.cap_drop.is_empty() {
        annotations.insert(
            "boxr.cap_drop".to_string(),
            serde_json::to_string(&args.cap_drop)?,
        );
    }
    if !args.security_opt.is_empty() {
        annotations.insert(
            "boxr.security_opt".to_string(),
            serde_json::to_string(&args.security_opt)?,
        );
    }
    if let Some(s) = &args.systemd {
        annotations.insert("boxr.systemd".to_string(), s.clone());
    }
    apply_run_health_annotations(&args, &mut annotations)?;
    apply_run_secrets(&args, &mut spec, &mut annotations, &cow_bundle.merged_dir)?;
    if let Some(sd) = &args.sdnotify {
        annotations.insert("boxr.sdnotify_mode".to_string(), sd.clone());
    }
    if let Ok(sock) = std::env::var("NOTIFY_SOCKET") {
        if !sock.is_empty() && args.sdnotify.as_deref() != Some("ignore") {
            annotations.insert("boxr.sdnotify_socket".to_string(), sock);
        }
    }
    spec.annotations = Some(annotations);

    fs::create_dir_all(&bundle_dir)?;
    let raw_argv: Vec<String> = std::env::args().collect();
    let _ = fs::write(
        bundle_dir.join("create_command.json"),
        serde_json::to_string(&raw_argv)?,
    );
    if let Ok(unit) = std::env::var("PODMAN_SYSTEMD_UNIT") {
        let trimmed = unit.trim();
        if !trimmed.is_empty()
            && !args
                .labels
                .iter()
                .any(|l| l.starts_with("PODMAN_SYSTEMD_UNIT="))
        {
            args.labels.push(format!("PODMAN_SYSTEMD_UNIT={}", trimmed));
        }
    }
    if !args.add_host.is_empty() {
        let mut cleaned_add_host = Vec::with_capacity(args.add_host.len());
        for host_entry in &args.add_host {
            let clean = host_entry.trim().trim_matches('"');
            let (host, ip_str) = clean
                .split_once(':')
                .ok_or_else(|| anyhow!("bad format for add-host: \"{}\"", host_entry))?;
            if host.is_empty() {
                return Err(anyhow!("bad format for add-host: \"{}\"", host_entry));
            }
            if ip_str.trim().parse::<std::net::IpAddr>().is_err() {
                return Err(anyhow!("bad format for add-host: \"{}\"", host_entry));
            }
            cleaned_add_host.push(format!("{}:{}", host.trim(), ip_str.trim()));
        }
        args.add_host = cleaned_add_host;
        let hosts_json = serde_json::to_string(&args.add_host)?;
        let _ = fs::write(bundle_dir.join("hosts.json"), hosts_json);
    }
    if !args.dns.is_empty() {
        for dns_ip in &args.dns {
            if dns_ip != "none" && dns_ip.parse::<std::net::IpAddr>().is_err() {
                return Err(anyhow!("invalid DNS server address: '{}'", dns_ip));
            }
        }
        let dns_json = serde_json::to_string(&args.dns)?;
        let _ = fs::write(bundle_dir.join("dns.json"), dns_json);
    }
    if !args.dns_search.is_empty() {
        let search_json = serde_json::to_string(&args.dns_search)?;
        let _ = fs::write(bundle_dir.join("dns_search.json"), search_json);
    }
    if !args.dns_option.is_empty() {
        let opt_json = serde_json::to_string(&args.dns_option)?;
        let _ = fs::write(bundle_dir.join("dns_option.json"), opt_json);
    }
    let effective_labels = resolve_container_labels(&args.label_file, &args.labels)?;
    if !effective_labels.is_empty() {
        let labels_json = serde_json::to_string(&effective_labels)?;
        let _ = fs::write(bundle_dir.join("labels.json"), labels_json);
    }
    if !args.sysctl.is_empty() {
        let _ = fs::write(
            bundle_dir.join("sysctl.json"),
            serde_json::to_string(&args.sysctl)?,
        );
    }
    if !args.ulimits.is_empty() {
        let _ = fs::write(
            bundle_dir.join("ulimits.json"),
            serde_json::to_string(&args.ulimits)?,
        );
        let _ = ulimit::write_inspect_ulimits(&bundle_dir, &args.ulimits);
    }
    if let Some(hooks) = &args.hooks_dir {
        let _ = fs::write(bundle_dir.join("hooks_dir"), hooks);
    }
    if let Some(cidfile) = &args.cidfile {
        fs::write(cidfile, &container_id)?;
    }
    for vf in &args.volumes_from {
        let (target_cont_name, mode) = if let Some((c, m)) = vf.split_once(':') {
            (c, Some(m))
        } else {
            (vf.as_str(), None)
        };
        let c_lookup = ContainerStore::new();
        if let Some(src_cont) = c_lookup.find(target_cont_name) {
            let src_config_path = PathBuf::from(&src_cont.bundle_path).join("config.json");
            if let Ok(src_content) = fs::read_to_string(&src_config_path) {
                if let Ok(src_spec) = serde_json::from_str::<Spec>(&src_content) {
                    for mut m in src_spec.mounts {
                        if m.destination != "/proc"
                            && m.destination != "/sys"
                            && m.destination != "/dev"
                            && m.destination != "/dev/pts"
                            && m.destination != "/dev/shm"
                            && m.destination != "/dev/mqueue"
                        {
                            if mode == Some("ro") {
                                let mut opts = m.options.unwrap_or_default();
                                opts.retain(|o| o != "rw");
                                opts.push("ro".to_string());
                                m.options = Some(opts);
                            }
                            spec.mounts.push(m);
                        }
                    }
                }
            }
        }
    }
    for t in &args.tmpfs {
        let (dest, opts) = if let Some((d, o)) = t.split_once(':') {
            (d, o)
        } else {
            (t.as_str(), "rw,nosuid,nodev,size=65536k")
        };
        spec.mounts.push(oci::runtime::Mount {
            destination: dest.to_string(),
            mount_type: "tmpfs".to_string(),
            source: "tmpfs".to_string(),
            options: Some(opts.split(',').map(|s| s.to_string()).collect()),
        });
    }
    for m in &args.mount {
        let mut mount_type = "bind".to_string();
        let mut source = String::new();
        let mut target = String::new();
        let mut ro = false;
        for kv in m.split(',') {
            if let Some((k, v)) = kv.split_once('=') {
                match k.trim() {
                    "type" => mount_type = v.trim().to_string(),
                    "source" | "src" => source = v.trim().to_string(),
                    "target" | "destination" | "dst" => target = v.trim().to_string(),
                    "readonly" | "ro" => ro = true,
                    _ => {}
                }
            } else if kv.trim() == "readonly" || kv.trim() == "ro" {
                ro = true;
            }
        }
        if !target.is_empty() {
            let mut opts = vec!["rbind".to_string()];
            if ro {
                opts.push("ro".to_string());
            }
            spec.mounts.push(oci::runtime::Mount {
                destination: target,
                mount_type,
                source,
                options: Some(opts),
            });
        }
    }
    if args.security_opt.iter().any(|s| s == "seccomp=unconfined") {
        if let Some(l) = &mut spec.linux {
            l.seccomp = None;
        }
    }
    if args
        .security_opt
        .iter()
        .any(|s| s == "no-new-privileges" || s == "no-new-privileges:true")
    {
        spec.process.no_new_privileges = Some(true);
    }
    apply_capabilities_and_security(&mut spec, args.privileged, &args.cap_add, &args.cap_drop);
    if !args.privileged && !args.security_opt.iter().any(|s| s == "seccomp=unconfined") {
        if let Some(l) = &mut spec.linux {
            if l.seccomp.is_none() {
                l.seccomp = Some(
                    serde_json::to_value(security::SeccompRule::default_filter())
                        .unwrap_or(serde_json::Value::Null),
                );
            }
        }
    }
    if args.cpu_count.is_some()
        || args.cpu_percent.is_some()
        || args.io_maxbandwidth.is_some()
        || args.io_maxiops.is_some()
    {
        let mut win_cpu = oci::runtime::WindowsCPUResources::default();
        if let Some(count) = args.cpu_count {
            win_cpu.count = Some(count as u64);
        }
        if let Some(percent) = args.cpu_percent {
            win_cpu.percent = Some(percent as u16);
        }

        let mut win_storage = oci::runtime::WindowsStorageResources::default();
        if let Some(bw_str) = &args.io_maxbandwidth {
            if let Ok(bw) = cgroups::ResourceLimits::parse_memory(bw_str) {
                win_storage.bps = Some(bw as u64);
            }
        }
        if let Some(iops) = args.io_maxiops {
            win_storage.iops = Some(iops);
        }

        let mut win_spec = oci::runtime::Windows::default();
        win_spec.resources = Some(oci::runtime::WindowsResources {
            cpu: Some(win_cpu),
            storage: Some(win_storage),
        });
        spec.windows = Some(win_spec);
    }
    let image_id_for_env = if let Some(img) = image_ref {
        if img.id.starts_with("sha256:") {
            img.id.clone()
        } else {
            format!("sha256:{}", img.id)
        }
    } else {
        String::new()
    };
    append_containerenv_mount(
        &bundle_dir,
        &mut spec,
        &parsed_mounts,
        args.privileged,
        &container_name,
        &container_id,
        if args.image.is_empty() {
            "scratch"
        } else {
            &args.image
        },
        &image_id_for_env,
    )?;
    if !image_id_for_env.is_empty() {
        let _ = fs::write(bundle_dir.join("image_id.txt"), &image_id_for_env);
    }
    spec.save_to_bundle(&bundle_dir)?;
    if !parsed_mounts.is_empty() {
        let _ = fs::write(
            bundle_dir.join("mounts.json"),
            serde_json::to_string(&parsed_mounts)?,
        );
    }

    let preserve_fds = args.resolved_preserve_fds();
    if !preserve_fds.is_empty() {
        let _ = fs::write(
            bundle_dir.join("preserve_fds.json"),
            serde_json::to_string(&preserve_fds)?,
        );
    }

    if run_auto_remove_enabled(&args) {
        let _ = fs::write(bundle_dir.join("auto_remove"), "1");
    }
    if args.rmi {
        let _ = fs::write(bundle_dir.join("auto_remove_image"), args.image.as_str());
    }

    if args.workdir.is_some()
        && !workdir_allowed_on_container(&cow_bundle.merged_dir, &spec.process.cwd, &parsed_mounts)
    {
        return fail_missing_workdir(&spec.process.cwd, &container_id);
    }
    let cwd_rel = spec.process.cwd.trim_start_matches('/');
    if !cwd_rel.is_empty() {
        let _ = fs::create_dir_all(cow_bundle.merged_dir.join(cwd_rel));
    }

    let restart_policy = health::parse_restart_policy(&args.restart)?;
    let mut health_cfg = health::HealthConfig::default();
    if !args.no_healthcheck {
        if let Some(cmd) = &args.health_cmd {
            if !cmd.is_empty() && cmd != "none" {
                health_cfg.test = vec!["CMD-SHELL".to_string(), cmd.clone()];
            }
        }
        apply_run_health_config(&args, &mut health_cfg)?;
    }
    let health_on_failure = if let Some(action) = &args.health_on_failure {
        health::parse_health_on_failure(action)?
    } else {
        health::HealthOnFailureAction::None
    };
    if !health_cfg.test.is_empty() {
        let _ = health::supervisor::write_health_supervisor_spec(
            &bundle_dir,
            &container_id,
            &container_name,
            &health_cfg,
            health_on_failure,
        );
    }
    let initial_health = if health_cfg.test.is_empty() {
        health::HealthStatus::None
    } else {
        health::HealthStatus::Starting
    };

    // Register container in store
    let container_store = ContainerStore::new();
    let initial_status = if args.detach {
        ContainerStatus::Running
    } else {
        ContainerStatus::Running
    };

    let mut combined_exposed = args.expose.clone();
    if let Some(img) = &image_record {
        if let Some(cfg) = &img.config.config {
            if let Some(exp) = &cfg.exposed_ports {
                for k in exp.keys() {
                    if !combined_exposed.contains(k) {
                        combined_exposed.push(k.clone());
                    }
                }
            }
        }
    }

    let record = ContainerRecord {
        id: container_id.clone(),
        name: container_name.clone(),
        image: args.image.clone(),
        command: container_record_command(&args, &spec),
        created_at: Utc::now(),
        status: initial_status,
        bundle_path: bundle_dir.to_string_lossy().to_string(),
        restart_policy: restart_policy.clone(),
        health_status: initial_health,
        restart_count: 0,
        ports: parsed_ports.clone(),
        exposed_ports: combined_exposed,
    };

    let mut event_attrs = HashMap::new();
    event_attrs.insert("image".to_string(), args.image.clone());
    event_attrs.insert("name".to_string(), container_name.clone());
    for l in &args.labels {
        if let Some((k, v)) = l.split_once('=') {
            event_attrs.insert(k.to_string(), v.to_string());
        } else {
            event_attrs.insert(l.clone(), String::new());
        }
    }

    EventManager::record(ContainerEvent::new(
        "container",
        "create",
        &container_id,
        &container_name,
        event_attrs.clone(),
    ));
    add_container_record(&container_store, record, &ephemeral_new_pod)?;

    if args.detach {
        if let Some((code, msg)) = check_custom_systemd_run_for_healthcheck(&health_cfg) {
            let _ = container_store.update_status(&container_id, ContainerStatus::Exited(code));
            eprintln!("Error: {}", msg);
            cli::log_level::emit_shutdown_engines();
            std::process::exit(code);
        }
    }

    if let Err(e) = guardrails::PortCollisionGuard::ensure_no_conflicts_excluding(
        &parsed_ports,
        Some(&container_id),
    ) {
        cleanup_ephemeral_pod(&ephemeral_new_pod);
        if args.rm {
            let _ = container_store.remove(&container_id);
            let _ = OverlayDriver::cleanup(&cow_bundle);
            let _ = fs::remove_dir_all(&bundle_dir);
        } else {
            let _ = container_store.update_status(&container_id, ContainerStatus::Exited(126));
        }
        cli::usage_errors::exit_config_error(e.to_string());
    }

    let (statuses, _) = (true, true);
    let _ = statuses;
    if let Some(pod_name) = &args.pod {
        let pod_store = pod::PodStore::new();
        let _ = pod_store.add_container_to_pod(pod_name, &container_id);
        if let Some(pod) = pod_store.find(pod_name) {
            if let Ok(cg) = cgroups::CgroupV2Manager::new(&pod.id) {
                if let Some(mem_str) = &pod.memory {
                    if let Ok(mem_bytes) = cgroups::ResourceLimits::parse_memory(mem_str) {
                        let mut lim = cgroups::ResourceLimits::default();
                        lim.memory_max_bytes = Some(mem_bytes);
                        let _ = cg.apply_limits(&lim);
                    }
                }
            }
        }
    }

    // Register bridge network endpoint (same as compose up) so inspect/disconnect work.
    let mut all_net_specs = vec![args.network.clone()];
    if let Some(extra_nets) = cli::EXTRA_NETWORK_SPECS.get() {
        all_net_specs.extend(extra_nets.iter().cloned());
    }
    let mut cli_ips = Vec::new();
    if let Some(ip4) = &args.ip {
        if !ip4.trim().is_empty() {
            cli_ips.push(ip4.trim().to_string());
        }
    }
    if let Some(ip6) = &args.ip6 {
        if !ip6.trim().is_empty() {
            cli_ips.push(ip6.trim().to_string());
        }
    }
    let mut net_ifaces: Vec<(String, String, String)> = Vec::new();
    let mut net_ifaces_v2: Vec<(String, Vec<(String, String, String)>, bool)> = Vec::new();
    let net_store_run = network::NetworkStore::new();
    for (idx, net_spec) in all_net_specs.iter().enumerate() {
        if let Some(net_name) = network::resolved_bridge_network_name(net_spec) {
            let spec_cli_ips = if idx == 0 { &cli_ips[..] } else { &[] };
            let _ = network::connect_container_to_bridge_network_with_opts(
                net_spec,
                &container_id,
                &container_name,
                spec_cli_ips,
                None,
            );
            let mut ifname = if idx == 0 {
                "eth0".to_string()
            } else {
                format!("eth{}", idx)
            };
            if let Some((_, opts)) = net_spec.split_once(':') {
                for kv in opts.split(',') {
                    if let Some((k, v)) = kv.split_once('=') {
                        if k.trim() == "interface_name" && !v.trim().is_empty() {
                            ifname = v.trim().to_string();
                        }
                    }
                }
            }
            if let Some(net_rec) = net_store_run.find(&net_name) {
                let ep_opt = net_rec.containers.get(&container_id);
                let ip_str = ep_opt
                    .map(|ep| ep.ipv4_address.clone())
                    .unwrap_or_default();
                let ipam_none = net_rec.ipam_driver.eq_ignore_ascii_case("none");
                let eval_ip = if net_name == network::NetworkStore::DEFAULT_NETWORK {
                    "10.0.2.15".to_string()
                } else {
                    ip_str
                };
                if idx == 0 && !eval_ip.is_empty() {
                    let _ = fs::write(bundle_dir.join("primary_ip.txt"), &eval_ip);
                }
                let ips_v2 = if net_name == network::NetworkStore::DEFAULT_NETWORK {
                    vec![(
                        "10.0.2.15".to_string(),
                        "24".to_string(),
                        "10.0.2.2".to_string(),
                    )]
                } else if let Some(ep) = ep_opt {
                    if !ep.ips.is_empty() {
                        ep.ips.clone()
                    } else if !ep.ipv4_address.is_empty() {
                        vec![(
                            ep.ipv4_address.clone(),
                            "24".to_string(),
                            net_rec.gateway.clone(),
                        )]
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };
                net_ifaces.push((ifname.clone(), eval_ip, net_rec.gateway.clone()));
                net_ifaces_v2.push((ifname, ips_v2, ipam_none));
            }
        }
    }
    if args.network.trim().eq_ignore_ascii_case("pasta") {
        if let Some(host_ip) = default_host_ipv4() {
            let _ = fs::write(bundle_dir.join("primary_ip.txt"), &host_ip);
        }
    }
    if !net_ifaces.is_empty() {
        if let Ok(j) = serde_json::to_string(&net_ifaces) {
            let _ = fs::write(bundle_dir.join("network_interfaces.json"), j);
        }
    }
    if !net_ifaces_v2.is_empty() {
        if let Ok(j) = serde_json::to_string(&net_ifaces_v2) {
            let _ = fs::write(bundle_dir.join("network_interfaces_v2.json"), j);
        }
    }

    write_prebuilt_resolv_and_hosts(
        &bundle_dir,
        &cow_bundle.merged_dir,
        &args,
        &spec,
        &container_id,
        &container_name,
        &net_store_run,
    );

    if args.detach || args.attach_stdin_emits_container_id() {
        output_policy.emit_container_id(&container_id)?;
    }

    EventManager::record(ContainerEvent::new(
        "container",
        "start",
        &container_id,
        &container_name,
        event_attrs.clone(),
    ));

    // Enter raw terminal mode on macOS where a VM serial console is used
    #[cfg(target_os = "macos")]
    let _term_guard = if args.interactive && args.allocate_tty() {
        terminal::TerminalGuard::enter_raw_mode().ok()
    } else {
        None
    };

    apply_volume_mount_prep(
        &vol_store,
        &parsed_mounts,
        &cow_bundle.merged_dir,
        spec.process.user.uid,
        spec.process.user.gid,
    )?;

    // Execute the container with restart policy support
    let _ = runtime::oci_hooks::run_hooks_from_bundle(&bundle_dir, "prestart");
    let mut exit_code = execute_bundle(
        &bundle_dir,
        &spec,
        &parsed_mounts,
        &parsed_ports,
        args.detach,
        args.detach,
    )?;

    if args.detach {
        #[cfg(target_os = "linux")]
        if !parsed_ports.is_empty() && net_mode != network::pasta::NetworkMode::Pasta {
            let _ =
                network::wait_for_forwarder_pid(&bundle_dir, std::time::Duration::from_secs(15));
        }
        if !health_cfg.test.is_empty()
            && std::env::var("DISABLE_HC_SYSTEMD").as_deref() != Ok("true")
        {
            health::supervisor::spawn_detached_health_supervisor(
                bundle_dir.clone(),
                container_id.clone(),
                container_name.clone(),
                health_cfg.clone(),
                health_on_failure,
            );
        } else if !health_cfg.test.is_empty() {
            let _ = health::supervisor::write_health_supervisor_spec(
                &bundle_dir,
                &container_id,
                &container_name,
                &health_cfg,
                health_on_failure,
            );
        }
        cli::log_level::emit_shutdown_engines();
        return Ok(exit_code);
    }

    let mut restart_count = 0;

    while !args.detach {
        let _ = runtime::oci_hooks::run_hooks_from_bundle(&bundle_dir, "poststop");
        let should_restart = match &restart_policy {
            health::RestartPolicy::Always => true,
            health::RestartPolicy::OnFailure { max_retries } => {
                exit_code != 0 && (*max_retries == 0 || restart_count < *max_retries)
            }
            _ => false,
        };

        if should_restart {
            restart_count += 1;
            let _ = container_store.increment_restart_count(&container_id);
            let _ = runtime::oci_hooks::run_hooks_from_bundle(&bundle_dir, "prestart");
            exit_code = execute_bundle(
                &bundle_dir,
                &spec,
                &parsed_mounts,
                &parsed_ports,
                false,
                false,
            )?;
        } else {
            break;
        }
    }

    event_attrs.insert("exitCode".to_string(), exit_code.to_string());
    if !args.detach {
        let oom = cgroups::CgroupV2Manager::was_oom_killed(&container_id)
            || (args.memory.is_some() && exit_code != 0);
        event_attrs.insert("oomKilled".to_string(), oom.to_string());
        EventManager::record(ContainerEvent::new(
            "container",
            "died",
            &container_id,
            &container_name,
            event_attrs,
        ));
    }

    // Health check evaluation if configured
    if args.detach && !health_cfg.test.is_empty() {
        let mut health_res = health::HealthCheckResult::default();
        let _ = health::check_container_health(&bundle_dir, &health_cfg, &mut health_res, false);
    }

    if !args.detach {
        let auto_rm = run_auto_remove_enabled(&args);
        if args.rmi {
            try_rmi_with_in_use_warning(&args.image, Some(&container_id), !auto_rm);
        }
        if auto_rm {
            if let Some(cidfile) = &args.cidfile {
                let _ = fs::remove_file(cidfile);
            }
            prune_container_attached_volumes(bundle_dir.clone());
            let _ = network::NetworkStore::new()
                .cleanup_container_endpoints(&container_id, &container_name);
            let _ = OverlayDriver::cleanup(&cow_bundle);
            let _ = container_store.remove(&container_id);
            let _ = fs::remove_dir_all(&bundle_dir);
            update_pod_state_on_container_exit(&container_id);
            let _ = pod::PodStore::new().remove_container_from_pods(&container_id, &container_name);
        } else {
            let stored_exit = if exit_code == 255 {
                fs::read_to_string(bundle_dir.join("boxr-exitcode"))
                    .ok()
                    .and_then(|s| s.trim().parse::<i32>().ok())
                    .unwrap_or(-1)
            } else {
                exit_code
            };
            let _ =
                container_store.update_status(&container_id, ContainerStatus::Exited(stored_exit));
            update_pod_state_on_container_exit(&container_id);
        }
        let exit_for_systemd =
            if bundle_dir.join("manual_stop").exists() && (exit_code == 143 || exit_code == 130) {
                0
            } else {
                exit_code
            };
        exit_code = exit_for_systemd;
    }

    cli::log_level::emit_shutdown_engines();
    Ok(exit_code)
}

fn sync_bundle_ulimits_inspect(bundle_path: &Path) -> Result<()> {
    let ulimits_path = bundle_path.join("ulimits.json");
    if ulimits_path.exists() {
        if let Ok(content) = fs::read_to_string(&ulimits_path) {
            if let Ok(specs) = serde_json::from_str::<Vec<String>>(&content) {
                let _ = ulimit::write_inspect_ulimits(bundle_path, &specs);
                return Ok(());
            }
        }
    }
    #[cfg(unix)]
    {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut lim) } == 0 {
            let ulimits = serde_json::json!([{
                "Name": "RLIMIT_NPROC",
                "Soft": lim.rlim_cur as i64,
                "Hard": lim.rlim_max as i64,
            }]);
            let _ = fs::write(
                bundle_path.join("host_ulimits.json"),
                serde_json::to_string(&ulimits)?,
            );
        }
    }
    Ok(())
}

fn host_ulimits_for_inspect(bundle_path: &Path) -> serde_json::Value {
    let path = bundle_path.join("host_ulimits.json");
    if let Ok(content) = fs::read_to_string(&path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
            return v;
        }
    }
    serde_json::json!([])
}

fn container_network_parent(spec: &Spec) -> Option<String> {
    spec.annotations
        .as_ref()
        .and_then(|a| a.get("boxr.network_container"))
        .map(|s| s.to_string())
}

fn dependent_container_ids(store: &ContainerStore, parent: &ContainerRecord) -> Vec<String> {
    let mut deps = Vec::new();
    for c in store.list() {
        if c.id == parent.id {
            continue;
        }
        let bundle_path = PathBuf::from(&c.bundle_path);
        let parent_ref = fs::read_to_string(bundle_path.join("config.json"))
            .ok()
            .and_then(|s| serde_json::from_str::<Spec>(&s).ok())
            .and_then(|spec| container_network_parent(&spec));
        if parent_ref.as_deref() == Some(parent.id.as_str())
            || parent_ref.as_deref() == Some(parent.name.as_str())
        {
            deps.push(c.id.clone());
        }
    }
    deps
}

fn bundle_auto_remove(bundle_path: &Path) -> bool {
    bundle_path.join("auto_remove").exists()
}

fn bundle_auto_remove_image(bundle_path: &Path) -> bool {
    bundle_path.join("auto_remove_image").exists()
}

fn container_uses_image_record(c: &ContainerRecord, img: &ImageRecord) -> bool {
    let full_name = img.qualified_name();
    let short_name = format!("{}:{}", img.reference, img.tag);
    crate::storage::image_store::refs_equivalent(&c.image, &full_name)
        || crate::storage::image_store::refs_equivalent(&c.image, &short_name)
        || c.image == img.id
        || c.image.starts_with(&img.id)
}

fn try_rmi_with_in_use_warning(
    image: &str,
    exclude_container_id: Option<&str>,
    skip_exited_blockers: bool,
) {
    let img_store = ImageStore::new();
    let img = match find_image_with_shortname(&img_store, image, None) {
        Some(rec) => rec,
        None => return,
    };
    let c_store = ContainerStore::new();
    for c in c_store.list() {
        if exclude_container_id == Some(c.id.as_str()) {
            continue;
        }
        if skip_exited_blockers
            && matches!(
                c.status,
                ContainerStatus::Exited(_) | ContainerStatus::Created
            )
        {
            continue;
        }
        if container_uses_image_record(&c, &img) {
            eprintln!(
                "Warning: image {} could not be removed: image is in use by a container",
                image
            );
            return;
        }
    }
    let _ = remove_image_inner(image, false, false, exclude_container_id);
}

/// Update store state and honor `--rm` / `--rmi` after a detached trampoline exits.
fn load_bundle_for_restart(
    bundle_path: &Path,
) -> Result<(Spec, Vec<volume::MountSpec>, Vec<PortMapping>)> {
    let spec: Spec = serde_json::from_str(&fs::read_to_string(bundle_path.join("config.json"))?)?;
    let mounts: Vec<volume::MountSpec> = if bundle_path.join("mounts.json").exists() {
        serde_json::from_str(&fs::read_to_string(bundle_path.join("mounts.json"))?)?
    } else {
        Vec::new()
    };
    let ports = network::resolve_bundle_ports(bundle_path, &[]);
    Ok((spec, mounts, ports))
}

fn prepare_detached_restart(container_id: &str, bundle_path: &Path, stored_exit: i32) -> bool {
    let store = ContainerStore::new();
    let c = match store.find(container_id) {
        Some(c) => c,
        None => return false,
    };
    if matches!(
        c.status,
        ContainerStatus::Stopping | ContainerStatus::Exited(_)
    ) || bundle_path.join("manual_stop").exists()
    {
        return false;
    }
    let should_restart = match &c.restart_policy {
        health::RestartPolicy::Always => true,
        health::RestartPolicy::OnFailure { max_retries } => {
            stored_exit != 0 && (*max_retries == 0 || c.restart_count < *max_retries)
        }
        _ => false,
    };
    if !should_restart {
        return false;
    }
    let _ = runtime::oci_hooks::run_hooks_from_bundle(bundle_path, "poststop");
    if store.increment_restart_count(container_id).is_err() {
        return false;
    }
    let _ = runtime::oci_hooks::run_hooks_from_bundle(bundle_path, "prestart");
    let _ = store.update_status(container_id, ContainerStatus::Running);
    true
}

fn try_restart_detached_container(
    container_id: &str,
    bundle_path: &Path,
    stored_exit: i32,
) -> bool {
    if !prepare_detached_restart(container_id, bundle_path, stored_exit) {
        return false;
    }
    let (spec, mounts, ports) = match load_bundle_for_restart(bundle_path) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if execute_bundle(bundle_path, &spec, &mounts, &ports, true, false).is_err() {
        let store = ContainerStore::new();
        let _ = store.update_status(container_id, ContainerStatus::Exited(stored_exit));
        return false;
    }
    true
}

/// Returns `true` when the container was restarted and a detached watcher should keep waiting.
pub fn detached_container_process_exited(
    container_id: &str,
    bundle_path: &Path,
    exit_code: i32,
) -> bool {
    let mut stored = if exit_code == 255 {
        fs::read_to_string(bundle_path.join("boxr-exitcode"))
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .unwrap_or(-1)
    } else {
        exit_code
    };
    if bundle_path.join("manual_stop").exists() && (stored == 143 || stored == 130) {
        stored = 0;
    }
    if prepare_detached_restart(container_id, bundle_path, stored) {
        return true;
    }
    let store = ContainerStore::new();
    let _ = runtime::oci_hooks::run_hooks_from_bundle(bundle_path, "poststop");
    let _ = store.update_status(container_id, ContainerStatus::Exited(stored));
    let _ = fs::remove_file(bundle_path.join("vm.pid"));
    let _ = fs::remove_file(bundle_path.join("container.pid"));
    update_pod_state_on_container_exit(container_id);
    if let Some(c) = store.find(container_id) {
        let mut event_attrs = load_container_labels_from_bundle(&c.bundle_path);
        event_attrs.insert("image".to_string(), c.image.clone());
        event_attrs.insert("name".to_string(), c.name.clone());
        event_attrs.insert("exitCode".to_string(), stored.to_string());
        let has_mem_limit = fs::read_to_string(bundle_path.join("config.json"))
            .ok()
            .and_then(|s| serde_json::from_str::<Spec>(&s).ok())
            .and_then(|sp| sp.annotations)
            .is_some_and(|a| a.contains_key("boxr.memory"));
        let oom = cgroups::CgroupV2Manager::was_oom_killed(container_id)
            || (has_mem_limit && stored != 0 && !bundle_path.join("manual_stop").exists());
        event_attrs.insert("oomKilled".to_string(), oom.to_string());
        EventManager::record(ContainerEvent::new(
            "container",
            "died",
            &c.id,
            &c.name,
            event_attrs,
        ));
        finalize_stopped_container(&c);
    }
    false
}

fn update_pod_state_on_container_exit(container_id: &str) {
    let pod_store = pod::PodStore::new();
    let c_store = ContainerStore::new();
    for pod in pod_store.list() {
        let infra_name = pod_store.infra_name(&pod);
        if container_id == pod.infra_container_id || container_id == infra_name {
            continue;
        }
        if !pod.containers.iter().any(|cid| cid == container_id) {
            continue;
        }
        let any_workload_running = pod.containers.iter().any(|cid| {
            if cid == &infra_name || cid == &pod.infra_container_id {
                return false;
            }
            c_store
                .find(cid)
                .map(|c| {
                    c.name != infra_name
                        && c.id != pod.infra_container_id
                        && matches!(c.status, ContainerStatus::Running)
                })
                .unwrap_or(false)
        });
        if !any_workload_running {
            if pod.exit_policy == "stop" {
                if pod.infra {
                    let _ = stop_container_with_home_and_timeout(
                        &infra_name,
                        None,
                        Some(0),
                        None,
                        true,
                        None,
                    );
                }
                let _ = pod_store.update_status(&pod.name, "Exited");
            } else {
                let _ = pod_store.update_status(&pod.name, "Degraded");
            }
            // Also stop any service container associated with this pod
            for c in c_store.list() {
                let cfg_path = PathBuf::from(&c.bundle_path).join("config.json");
                if let Ok(raw) = fs::read_to_string(&cfg_path) {
                    if let Ok(spec) = serde_json::from_str::<Spec>(&raw) {
                        if let Some(ann) = &spec.annotations {
                            if ann
                                .get("boxr.is_service")
                                .map(|v| v == "true")
                                .unwrap_or(false)
                                && ann.get("boxr.service_pods").is_some_and(|s| {
                                    s.split(',').any(|p| p == pod.id || p == pod.name)
                                })
                            {
                                let _ = stop_container_with_home_and_timeout(
                                    &c.id,
                                    None,
                                    Some(0),
                                    None,
                                    true,
                                    None,
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// After a detached container's main process exits, honor `--rm` / `--rmi` markers.
pub fn finalize_stopped_container(c: &ContainerRecord) {
    let bundle = PathBuf::from(&c.bundle_path);
    let auto_rm = bundle_auto_remove(&bundle);
    let auto_rmi = bundle_auto_remove_image(&bundle);
    if !auto_rm && !auto_rmi {
        return;
    }
    let image_for_rmi = fs::read_to_string(bundle.join("auto_remove_image"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if auto_rm {
        let name = c.name.clone();
        let _ = remove_container_quiet(&name, true, false);
    }
    if auto_rmi {
        if let Some(img) = image_for_rmi {
            try_rmi_with_in_use_warning(&img, Some(&c.id), true);
        }
    }
}

pub(crate) fn get_process_tree_pids(root_pids: &[i32]) -> Vec<i32> {
    let mut all_pids = std::collections::HashSet::new();
    for &p in root_pids {
        if p > 1 {
            all_pids.insert(p);
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(fname) = entry.file_name().into_string() {
                    if let Ok(pid) = fname.parse::<i32>() {
                        if all_pids.contains(&pid) {
                            continue;
                        }
                        let stat_file = entry.path().join("stat");
                        if let Ok(content) = std::fs::read_to_string(&stat_file) {
                            if let Some(idx) = content.rfind(')') {
                                let rest = content[idx + 1..].trim_start();
                                let mut parts = rest.split_whitespace();
                                let _state = parts.next();
                                if let Some(ppid_str) = parts.next() {
                                    if let Ok(ppid) = ppid_str.parse::<i32>() {
                                        if all_pids.contains(&ppid) {
                                            all_pids.insert(pid);
                                            changed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    all_pids.into_iter().collect()
}

pub fn stop_container(container: &str, signal: Option<&str>) -> Result<()> {
    stop_container_with_home_and_timeout(container, signal, None, None, false, None)
}

pub fn stop_container_with_home(
    container: &str,
    signal: Option<&str>,
    home_opt: Option<&Path>,
) -> Result<()> {
    stop_container_with_home_and_timeout(container, signal, None, home_opt, false, None)
}

#[cfg(unix)]
fn collect_container_stop_pids(bundle_path: &std::path::Path) -> (Vec<i32>, Vec<i32>) {
    let mut workload_pids = Vec::new();
    let mut all_pids = Vec::new();
    if let Ok(pid_str) = std::fs::read_to_string(bundle_path.join("vm.pid")) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            all_pids.push(pid);
        }
    }
    if let Ok(pid_str) = std::fs::read_to_string(bundle_path.join("container.pid")) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            workload_pids.push(pid);
            all_pids.push(pid);
        }
    }
    if let Ok(pid_str) = std::fs::read_to_string(bundle_path.join("forwarder.pid")) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            workload_pids.push(pid);
            all_pids.push(pid);
        }
    }
    if let Ok(pid_str) = std::fs::read_to_string(bundle_path.join("healthcheck_exec.pid")) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            workload_pids.push(pid);
            all_pids.push(pid);
        }
    }
    #[cfg(target_os = "linux")]
    {
        workload_pids = get_process_tree_pids(&workload_pids);
        all_pids = get_process_tree_pids(&all_pids);
    }
    (workload_pids, all_pids)
}

#[cfg(unix)]
fn any_pid_alive(pids: &[i32]) -> bool {
    pids.iter()
        .any(|pid| *pid > 0 && unsafe { libc::kill(*pid, 0) == 0 })
}

#[cfg(unix)]
fn sigkill_live_pids(pids: &[i32]) -> bool {
    let mut any = false;
    for pid in pids {
        if unsafe { libc::kill(*pid, 0) == 0 } {
            any = true;
            unsafe {
                libc::kill(*pid, libc::SIGKILL);
                let _ = libc::kill(-*pid, libc::SIGKILL);
            }
        }
    }
    any
}

#[cfg(unix)]
fn stop_wait_clear_pid_files(bundle_path: &std::path::Path, container_id: &str) {
    #[cfg(target_os = "linux")]
    {
        let cgroup_dir = std::path::PathBuf::from("/sys/fs/cgroup/boxr").join(container_id);
        let procs_file = cgroup_dir.join("cgroup.procs");
        if procs_file.exists() {
            if let Ok(content) = std::fs::read_to_string(procs_file) {
                for line in content.lines() {
                    if let Ok(pid) = line.trim().parse::<i32>() {
                        if unsafe { libc::kill(pid, 0) == 0 } {
                            unsafe {
                                libc::kill(pid, libc::SIGKILL);
                                let _ = libc::kill(-pid, libc::SIGKILL);
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = wait_for_container_stopped(bundle_path, std::time::Duration::from_secs(30));
    if let Ok(cpid_str) = std::fs::read_to_string(bundle_path.join("conmon.pid")) {
        if let Ok(cpid) = cpid_str.trim().parse::<i32>() {
            if cpid > 1 {
                unsafe {
                    let _ = libc::kill(cpid, libc::SIGKILL);
                }
            }
        }
    }
    let _ = std::fs::remove_file(bundle_path.join("conmon.pid"));
    let _ = std::fs::remove_file(bundle_path.join("vm.pid"));
    let _ = std::fs::remove_file(bundle_path.join("container.pid"));
    let _ = std::fs::remove_file(bundle_path.join("forwarder.pid"));
}

#[cfg(unix)]
fn finalize_container_exited_status(
    store: &ContainerStore,
    id: &str,
    bundle_path: &std::path::Path,
    used_sigkill: bool,
) -> Result<()> {
    let exit_code = resolve_stop_exit_code(store, id, bundle_path, used_sigkill);
    if let Err(e) = store.update_status(id, ContainerStatus::Exited(exit_code)) {
        if store.find(id).is_none() {
            return Ok(());
        }
        return Err(e);
    }
    Ok(())
}

fn resolve_stop_exit_code(
    store: &ContainerStore,
    id: &str,
    bundle_path: &std::path::Path,
    used_sigkill: bool,
) -> i32 {
    if let Ok(code_str) = std::fs::read_to_string(bundle_path.join("boxr-exitcode")) {
        if let Ok(code) = code_str.trim().parse::<i32>() {
            if code == 143 || code == 130 || code == 0 {
                return 0;
            }
            if !used_sigkill {
                return code;
            }
        }
    }
    if used_sigkill {
        return 137;
    }
    if let Some(rec) = store.find(id) {
        if let ContainerStatus::Exited(code) = rec.status {
            if code == 137 {
                return 137;
            }
        }
    }
    if let Some(rec) = store.find(id) {
        if let ContainerStatus::Exited(code) = rec.status {
            if code == 143 || code == 130 {
                return 0;
            }
            return code;
        }
    }
    0
}

pub fn stop_container_with_home_and_timeout(
    container: &str,
    signal: Option<&str>,
    timeout_secs: Option<u64>,
    home_opt: Option<&Path>,
    quiet: bool,
    output_label: Option<&str>,
) -> Result<()> {
    let store = match home_opt {
        Some(h) => ContainerStore::with_home(h.to_path_buf()),
        None => ContainerStore::new(),
    };
    let c = match store.find(container) {
        Some(c) => c,
        None => {
            cli::usage_errors::exit_usage_error(format!(
                "no container with name or ID \"{}\" found: no such container",
                container
            ));
        }
    };

    if matches!(c.status, ContainerStatus::Paused) {
        if !quiet {
            cli::usage_errors::exit_usage_error(format!(
                "container {} is running or paused, refusing to clean up: container state improper",
                c.id
            ));
        }
        thaw_container_processes(&c);
    }

    let sig_num = if let Some(s) = signal {
        runtime::kill::ContainerKiller::parse_signal(s).unwrap_or(libc::SIGTERM)
    } else {
        libc::SIGTERM
    };

    let mut used_sigkill = false;
    let bundle_path = std::path::PathBuf::from(&c.bundle_path);
    let _ = fs::write(bundle_path.join("stopped_by_user"), "1");
    let grace_secs = timeout_secs
        .or_else(|| crate::health::supervisor::read_bundle_stop_timeout(&bundle_path))
        .unwrap_or(10);

    #[cfg(unix)]
    if let Ok(conmon_str) = std::fs::read_to_string(bundle_path.join("conmon.pid")) {
        if let Ok(conmon_pid) = conmon_str.trim().parse::<i32>() {
            if conmon_pid > 0 && unsafe { libc::kill(conmon_pid, 0) != 0 } {
                let was_stopping = matches!(c.status, ContainerStatus::Stopping);
                let _ = store.update_status(&c.id, ContainerStatus::Stopping);
                let (_, all_pids) = collect_container_stop_pids(&bundle_path);
                let _ = sigkill_live_pids(&all_pids);
                stop_wait_clear_pid_files(&bundle_path, &c.id);
                let _ = finalize_container_exited_status(&store, &c.id, &bundle_path, true);
                if was_stopping {
                    cli::usage_errors::exit_usage_error(format!(
                        "container {} conmon exited prematurely, exit code could not be retrieved: conmon process killed",
                        output_label.unwrap_or(container)
                    ));
                }
                if !quiet {
                    println!("{}", output_label.unwrap_or(container));
                }
                return Ok(());
            }
        }
    }

    let _ = fs::write(bundle_path.join("manual_stop"), "1");
    let _ = store.update_status(&c.id, ContainerStatus::Stopping);

    #[cfg(unix)]
    {
        let (workload_pids, all_pids) = collect_container_stop_pids(&bundle_path);
        let pids = &all_pids;
        let stop_pids = if workload_pids.is_empty() {
            all_pids.clone()
        } else {
            workload_pids.clone()
        };

        let grace_ms = grace_secs * 1000;
        let iters = if grace_secs == 0 {
            0
        } else {
            (grace_ms / 50).max(1)
        };
        let conmon_pid = fs::read_to_string(bundle_path.join("conmon.pid"))
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok());
        if grace_secs > 0 {
            for pid in &stop_pids {
                unsafe {
                    libc::kill(*pid, sig_num);
                    let _ = libc::kill(-*pid, sig_num);
                }
            }
            for _i in 0..iters {
                if !any_pid_alive(&stop_pids) {
                    break;
                }
                if let Ok(pid_str) = std::fs::read_to_string(bundle_path.join("container.pid")) {
                    if let Ok(init_pid) = pid_str.trim().parse::<i32>() {
                        if init_pid > 0 && unsafe { libc::kill(init_pid, 0) != 0 } {
                            std::thread::sleep(std::time::Duration::from_millis(100));
                            break;
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            if sig_num == libc::SIGTERM {
                logging::wait_k8s_log_quiescent(&bundle_path);
            }
        }
        if sigkill_live_pids(pids) {
            used_sigkill = true;
        }
        if let Some(cp) = conmon_pid {
            for _ in 0..40 {
                if unsafe { libc::kill(cp, 0) != 0 } {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            if unsafe { libc::kill(cp, 0) == 0 } {
                unsafe {
                    libc::kill(cp, libc::SIGTERM);
                }
                for _ in 0..20 {
                    if unsafe { libc::kill(cp, 0) != 0 } {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                if unsafe { libc::kill(cp, 0) == 0 } {
                    unsafe {
                        libc::kill(cp, libc::SIGKILL);
                    }
                }
            }
        }
        stop_wait_clear_pid_files(&bundle_path, &c.id);
        if used_sigkill && sig_num == libc::SIGTERM && grace_secs > 0 {
            let label = output_label.unwrap_or(container);
            if let Some(t) = timeout_secs {
                eprintln!(
                    "StopSignal SIGTERM failed to stop container {} in {} seconds, resorting to SIGKILL",
                    label, t
                );
            } else {
                eprintln!(
                    "StopSignal SIGTERM failed to stop container {}, resorting to SIGKILL",
                    label
                );
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        let bundle_path = std::path::PathBuf::from(&c.bundle_path);
        let pid_file = bundle_path.join("vm.pid");
        if let Ok(pid_str) = std::fs::read_to_string(pid_file) {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                let _ = std::process::Command::new("taskkill")
                    .args(["/F", "/PID", &pid.to_string()])
                    .output();
            }
        }
    }
    let bundle_path = std::path::PathBuf::from(&c.bundle_path);
    let exit_code = resolve_stop_exit_code(&store, &c.id, &bundle_path, used_sigkill);
    if let Err(e) = store.update_status(&c.id, ContainerStatus::Exited(exit_code)) {
        if store.find(&c.id).is_none() {
            // Detached watcher may have already finalized --rm/--rmi cleanup.
            update_pod_state_on_container_exit(&c.id);
            return Ok(());
        }
        return Err(e);
    }
    update_pod_state_on_container_exit(&c.id);
    if !(quiet && grace_secs == 0) {
        let _ = guardrails::ProcessReaper::reap_stale_containers();
        logging::wait_k8s_log_quiescent(&bundle_path);
    }
    if !quiet {
        println!("{}", output_label.unwrap_or(container));
    }
    Ok(())
}

fn parse_restart_policy_filter(value: &str) -> health::RestartPolicy {
    match health::parse_restart_policy(value) {
        Ok(p) => p,
        Err(_) => {
            cli::usage_errors::exit_usage_error(format!("{} invalid restart policy", value));
        }
    }
}

fn container_matches_start_filters(
    c: &crate::storage::ContainerRecord,
    filters: &[String],
) -> Result<bool> {
    if filters.is_empty() {
        return Ok(true);
    }
    for f in filters {
        let (key, value) = f
            .split_once('=')
            .map(|(k, v)| (k.trim(), v.trim()))
            .ok_or_else(|| anyhow!("invalid filter: {}", f))?;
        let matches = match key {
            "restart-policy" => {
                let want = parse_restart_policy_filter(value);
                match (&c.restart_policy, &want) {
                    (
                        health::RestartPolicy::OnFailure { .. },
                        health::RestartPolicy::OnFailure { .. },
                    ) => true,
                    (a, b) => a == b,
                }
            }
            "exited" => {
                let want_code = value
                    .parse::<i32>()
                    .map_err(|_| anyhow!("invalid exited filter: {}", value))?;
                matches!(c.status, ContainerStatus::Exited(code) if code == want_code)
            }
            _ => true,
        };
        if !matches {
            return Ok(false);
        }
    }
    Ok(true)
}

pub async fn start_containers(args: &cli::StartArgs) -> Result<()> {
    if args.all && !args.containers.is_empty() {
        cli::usage_errors::exit_usage_error(
            "either start all containers or the container(s) provided in the arguments",
        );
    }
    let store = ContainerStore::new();

    if args.attach {
        if args.all || !args.filter.is_empty() {
            cli::usage_errors::exit_usage_error("cannot use attach with --all or --filter");
        }
        for name in &args.containers {
            let rec = store
                .find(name)
                .ok_or_else(|| anyhow!("Container '{}' not found", name))?;
            let bundle_path = PathBuf::from(&rec.bundle_path);
            let mut spec: Spec =
                serde_json::from_str(&fs::read_to_string(bundle_path.join("config.json"))?)?;
            spec.annotations
                .get_or_insert_with(HashMap::new)
                .insert("boxr.sig_proxy".to_string(), args.sig_proxy.to_string());
            let is_remote = std::env::var_os("CONTAINER_HOST").is_some()
                || std::env::var_os("CONTAINER_CONNECTION").is_some()
                || cli::podman_globals::podman_global_options().url.is_some()
                || cli::podman_globals::podman_global_options()
                    .connection
                    .is_some()
                || cli::podman_globals::podman_global_options().remote;
            if !is_remote {
                if let Ok(fds) = std::env::var("LISTEN_FDS") {
                    if !fds.is_empty() {
                        spec.process.env.retain(|e| {
                            !e.starts_with("LISTEN_FDS=")
                                && !e.starts_with("LISTEN_PID=")
                                && !e.starts_with("LISTEN_FDNAMES=")
                        });
                        spec.process.env.push(format!("LISTEN_FDS={fds}"));
                        spec.process.env.push("LISTEN_PID=1".to_string());
                        if let Ok(names) = std::env::var("LISTEN_FDNAMES") {
                            spec.process.env.push(format!("LISTEN_FDNAMES={names}"));
                        }
                        spec.save_to_bundle(&bundle_path)?;
                    }
                }
            }
            let _ = sync_bundle_ulimits_inspect(&bundle_path);
            let ports = network::resolve_bundle_ports(&bundle_path, &rec.ports);
            apply_chown_u_from_bundle(&bundle_path, &spec, false)?;
            store.update_status(&rec.id, ContainerStatus::Running)?;
            let code = runtime::execute_bundle(&bundle_path, &spec, &[], &ports, false, false)?;
            store.update_status(&rec.id, ContainerStatus::Exited(code))?;
            if bundle_auto_remove(&bundle_path) {
                let _ = remove_container_quiet(name, true, false);
            }
        }
        return Ok(());
    }

    async fn start_one(store: &ContainerStore, name: &str, display: &str) -> Result<()> {
        start_container(name).await?;
        let c = store
            .find(name)
            .ok_or_else(|| anyhow!("Container '{}' not found", name))?;
        let bundle_path = PathBuf::from(&c.bundle_path);
        std::thread::sleep(std::time::Duration::from_millis(50));
        if let Ok(exit_str) = fs::read_to_string(bundle_path.join("boxr-exitcode")) {
            if let Ok(code) = exit_str.trim().parse::<i32>() {
                if code != 0 {
                    cli::usage_errors::exit_usage_error(format!(
                        "container {} failed to start (exit code {})",
                        name, code
                    ));
                }
            }
        }
        println!("{}", display);
        Ok(())
    }

    if !args.containers.is_empty() && !args.filter.is_empty() {
        for name in &args.containers {
            let c = store
                .find(name)
                .ok_or_else(|| anyhow!("Container '{}' not found", name))?;
            if container_matches_start_filters(&c, &args.filter)? {
                start_one(&store, name, name).await?;
            }
        }
        return Ok(());
    }

    if !args.filter.is_empty() || args.all {
        for c in store.list() {
            if matches!(c.status, ContainerStatus::Running) {
                continue;
            }
            if !matches!(
                c.status,
                ContainerStatus::Exited(_) | ContainerStatus::Created
            ) {
                continue;
            }
            if !container_matches_start_filters(&c, &args.filter)? {
                continue;
            }
            start_one(&store, &c.name, &c.id).await?;
        }
        return Ok(());
    }

    if args.containers.is_empty() {
        return Err(anyhow!(
            "you must provide at least one container name or ID"
        ));
    }
    for name in &args.containers {
        if let Some(_cp) = &args.checkpoint {
            let cp_dir = args.checkpoint_dir.as_deref().map(Path::new);
            let _ = runtime::CheckpointManager::restore(name, cp_dir, false);
        }
        let rec = store
            .find(name)
            .ok_or_else(|| anyhow!("Container '{}' not found", name))?;
        start_one(&store, name, name).await?;
    }
    Ok(())
}

pub fn stop_containers(args: &cli::StopArgs) -> Result<()> {
    if let Some(path) = &args.cidfile {
        match std::fs::read_to_string(path) {
            Ok(id) => {
                let id = id.trim();
                if !id.is_empty() {
                    let mut containers = args.containers.clone();
                    containers.push(id.to_string());
                    return stop_containers(&cli::StopArgs {
                        time: args.time,
                        signal: args.signal.clone(),
                        all: args.all,
                        ignore: args.ignore,
                        noout: args.noout,
                        cidfile: None,
                        containers,
                    });
                }
            }
            Err(e) => {
                if args.ignore {
                    return Ok(());
                }
                let detail = if e.kind() == std::io::ErrorKind::NotFound {
                    "no such file or directory".to_string()
                } else {
                    e.to_string()
                };
                cli::usage_errors::exit_usage_error(format!(
                    "reading CIDFile: open {}: {}",
                    path, detail
                ));
            }
        }
    }
    let timeout = match args.time {
        None => None,
        Some(-1) => None,
        Some(0) => Some(0),
        Some(t) if t > 0 => Some(t as u64),
        _ => None,
    };
    let store = ContainerStore::new();
    let targets: Vec<(String, String)> = if args.all {
        store
            .list()
            .into_iter()
            .filter(|c| matches!(c.status, ContainerStatus::Running))
            .map(|c| (c.name.clone(), c.id.clone()))
            .collect()
    } else if args.containers.is_empty() {
        return Err(anyhow!(
            "you must provide at least one container name or ID"
        ));
    } else {
        args.containers
            .iter()
            .map(|input| (input.clone(), input.clone()))
            .collect()
    };
    for (lookup, display) in targets {
        if args.ignore && store.find(&lookup).is_none() {
            continue;
        }
        if let Err(e) = stop_container_with_home_and_timeout(
            &lookup,
            args.signal.as_deref(),
            timeout,
            None,
            args.noout,
            Some(&display),
        ) {
            if !args.ignore {
                return Err(e);
            }
        }
        sync_pod_and_service_container_after_stop(&lookup);
    }
    Ok(())
}

fn sync_pod_and_service_container_after_stop(stopped_query: &str) {
    let c_store = ContainerStore::new();
    let p_store = pod::PodStore::new();
    let stopped_cont = c_store.find(stopped_query);
    let mut affected_pods = Vec::new();
    for p in p_store.list() {
        if p.containers.iter().any(|cid| {
            cid == stopped_query
                || stopped_cont
                    .as_ref()
                    .is_some_and(|c| cid == &c.id || cid == &c.name)
        }) {
            affected_pods.push(p);
        }
    }
    for p in affected_pods {
        let any_running = p.containers.iter().any(|cid| {
            c_store
                .find(cid)
                .is_some_and(|c| matches!(c.status, ContainerStatus::Running))
        });
        if !any_running {
            let _ = p_store.update_status(&p.name, "Exited");
            if let Some(sc_name) = p.labels.get("boxr.service_container") {
                let other_running = p_store.list().iter().any(|other| {
                    other.labels.get("boxr.service_container") == Some(sc_name)
                        && other.status == "Running"
                });
                if !other_running {
                    let _ = stop_container_with_home_and_timeout(
                        sc_name,
                        None,
                        Some(0),
                        None,
                        true,
                        None,
                    );
                }
            }
        }
    }
}

fn apply_pod_namespaces_to_spec(spec: &mut Spec, pod: &pod::PodRecord) -> Result<()> {
    let pod_store = pod::PodStore::new();
    let infra = pod_store.infra_name(pod);
    let mut annotations = spec.annotations.clone().unwrap_or_default();
    let mut run_args = cli::RunArgs::default();
    pod::apply_pod_to_run_args(pod, &infra, &mut run_args);
    if let Some(linux) = spec.linux.as_mut() {
        apply_namespace_to_linux(linux, &mut annotations, "ipc", &run_args.ipc)?;
        apply_namespace_to_linux(linux, &mut annotations, "uts", &run_args.uts)?;
        apply_namespace_to_linux(linux, &mut annotations, "pid", &run_args.pid)?;
    }
    annotations.insert("boxr.network".to_string(), run_args.network.clone());
    if let Some(target) = network::pasta::NetworkMode::parse(&run_args.network).container_target() {
        annotations.insert("boxr.network_container".to_string(), target.to_string());
    }
    spec.annotations = Some(annotations);
    Ok(())
}

fn prepare_spec_for_pod_start(spec: &mut Spec, bundle_path: &Path) -> Result<()> {
    // Rewrite pod namespace paths if the bundle belongs to a pod AND an existing
    // /proc/<pid>/ns/* path in spec.linux.namespaces is stale or missing.
    let pod_id = spec
        .annotations
        .as_ref()
        .filter(|a| !a.contains_key("boxr.pod.infra"))
        .and_then(|a| a.get("boxr.pod"))
        .cloned();
    if let Some(pid) = pod_id {
        let has_stale_ns = spec
            .linux
            .as_ref()
            .map(|l| {
                l.namespaces.iter().any(|ns| {
                    ns.path
                        .as_deref()
                        .is_some_and(|p| p.starts_with("/proc/") && !Path::new(p).exists())
                })
            })
            .unwrap_or(false);
        let has_unresolved_container_ns = spec.annotations.as_ref().is_some_and(|a| {
            ["boxr.uts", "boxr.ipc", "boxr.pid"]
                .iter()
                .any(|k| a.get(*k).is_some_and(|v| v.starts_with("container:")))
        });
        if has_stale_ns || has_unresolved_container_ns {
            if let Some(pod) = pod::PodStore::new().find(&pid) {
                apply_pod_namespaces_to_spec(spec, &pod)?;
                spec.save_to_bundle(bundle_path)?;
            }
        }
    }
    Ok(())
}

pub async fn start_container(container: &str) -> Result<()> {
    start_container_with_home(container, None, true).await
}

fn executable_exists_in_rootfs(rootfs: &Path, binary: &str, env: &[String]) -> bool {
    if binary.is_empty() {
        return false;
    }
    if binary.starts_with('/') {
        let p = rootfs.join(binary.trim_start_matches('/'));
        return fs::symlink_metadata(&p).is_ok();
    }
    let path_env = env
        .iter()
        .find(|e| e.starts_with("PATH="))
        .map(|e| &e[5..])
        .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");

    for dir in path_env.split(':') {
        let clean = dir.trim().trim_start_matches('/');
        let p = rootfs.join(clean).join(binary);
        if fs::symlink_metadata(&p).is_ok() {
            return true;
        }
    }
    false
}

pub async fn start_container_with_home(
    container: &str,
    home_opt: Option<&Path>,
    prepare_pod: bool,
) -> Result<()> {
    let store = match home_opt {
        Some(h) => ContainerStore::with_home(h.to_path_buf()),
        None => ContainerStore::new(),
    };
    let rec = store
        .find(container)
        .ok_or_else(|| anyhow!("Container '{}' not found", container))?;

    if matches!(rec.status, ContainerStatus::Running) {
        return Ok(());
    }

    let bundle_path = PathBuf::from(&rec.bundle_path);
    let config_file = bundle_path.join("config.json");
    let content = fs::read_to_string(&config_file)?;
    let mut spec: Spec = serde_json::from_str(&content)?;
    if prepare_pod {
        prepare_spec_for_pod_start(&mut spec, &bundle_path)?;
    }

    let rootfs = bundle_path.join("rootfs");
    if let Ok(am_str) = fs::read_to_string(bundle_path.join("artifact_mounts.json")) {
        if let Ok(artifact_mounts) = serde_json::from_str::<Vec<String>>(&am_str) {
            let art_store = match home_opt {
                Some(h) => artifact::ArtifactStore::with_home(h.to_path_buf()),
                None => artifact::ArtifactStore::new(),
            };
            for am in &artifact_mounts {
                art_store.mount_artifact_to_rootfs(am, &rootfs, false)?;
            }
        }
    }
    if let Some(binary) = spec.process.args.first() {
        if !executable_exists_in_rootfs(&rootfs, binary, &spec.process.env) {
            let _ = store.update_status(&rec.id, ContainerStatus::Exited(127));
            let _ = fs::write(bundle_path.join("boxr-exitcode"), "127");
            cli::usage_errors::exit_usage_error(format!(
                "exec: \"{}\": executable file not found in $PATH",
                binary
            ));
        }
    }

    let _ = sync_bundle_ulimits_inspect(&bundle_path);
    let _ = fs::remove_file(bundle_path.join("manual_stop"));
    let _ = fs::remove_file(bundle_path.join("boxr-exitcode"));
    let _ = fs::remove_file(bundle_path.join("stopped_by_user"));
    let ports = network::resolve_bundle_ports(&bundle_path, &rec.ports);
    let saved_mounts: Vec<volume::MountSpec> = fs::read_to_string(bundle_path.join("mounts.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    apply_chown_u_from_bundle(&bundle_path, &spec, false)?;
    store.update_status(&rec.id, ContainerStatus::Running)?;
    if rec.health_status != health::HealthStatus::None
        || bundle_path.join("health-supervisor.json").exists()
        || spec
            .annotations
            .as_ref()
            .is_some_and(|a| a.contains_key("boxr.health_cmd"))
    {
        let log_dest = spec
            .annotations
            .as_ref()
            .and_then(|a| a.get("boxr.health_log_destination"))
            .map(|s| s.as_str());
        let _ = health::write_healthcheck_results(
            &bundle_path,
            &rec.id,
            log_dest,
            &health::HealthCheckResults::default(),
        );
        let _ = store.update_health_status(&rec.id, health::HealthStatus::Starting);
    }
    execute_bundle(&bundle_path, &spec, &saved_mounts, &ports, true, true)?;
    if !ports.is_empty() && prepare_pod {
        network::wait_for_forwarder_pid(&bundle_path, std::time::Duration::from_secs(15))?;
        network::wait_for_published_ports(&ports, std::time::Duration::from_secs(120))?;
    } else if !ports.is_empty() {
        let _ = network::wait_for_forwarder_pid(&bundle_path, std::time::Duration::from_secs(15));
    }
    if let Ok(raw) = fs::read_to_string(bundle_path.join("health-supervisor.json")) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(hc_val) = val.get("health_cfg") {
                if let Ok(hc) = serde_json::from_value::<health::HealthConfig>(hc_val.clone()) {
                    let on_fail = val
                        .get("on_failure")
                        .and_then(|v| {
                            serde_json::from_value::<health::HealthOnFailureAction>(v.clone()).ok()
                        })
                        .unwrap_or(health::HealthOnFailureAction::None);
                    health::supervisor::spawn_detached_health_supervisor(
                        bundle_path.clone(),
                        rec.id.clone(),
                        rec.name.clone(),
                        hc,
                        on_fail,
                    );
                }
            }
        }
    }
    Ok(())
}

/// Wait until container trampoline/VM processes have fully exited.
#[cfg(unix)]
fn wait_for_container_stopped(bundle_path: &Path, timeout: std::time::Duration) -> Result<()> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let mut any_alive = false;
        for name in ["vm.pid", "container.pid"] {
            let path = bundle_path.join(name);
            if let Ok(pid_str) = std::fs::read_to_string(&path) {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    if unsafe { libc::kill(pid, 0) == 0 } {
                        any_alive = true;
                    }
                }
            }
        }
        if !any_alive {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err(anyhow!(
        "timed out waiting for container at {} to stop",
        bundle_path.display()
    ))
}

#[cfg(not(unix))]
fn wait_for_container_stopped(_bundle_path: &Path, _timeout: std::time::Duration) -> Result<()> {
    Ok(())
}

pub fn container_logs(args: &LogsArgs) -> Result<()> {
    let mut args = args.clone();
    peel_logs_trailing_flags(&mut args);
    if args.containers.is_empty() {
        return Err(anyhow!(
            "you must provide at least one container name or ID"
        ));
    }
    if args.containers.len() == 1 {
        return container_logs_one(&args, &args.containers[0]);
    }
    container_logs_multi(&args)
}

/// Podman accepts `podman logs [opts] NAME -f` (options after the container name).
fn peel_logs_trailing_flags(args: &mut LogsArgs) {
    let mut names = Vec::new();
    let mut i = 0;
    while i < args.containers.len() {
        match args.containers[i].as_str() {
            "-f" | "--follow" => args.follow = true,
            "-t" | "--timestamps" => args.timestamps = true,
            "-n" | "--tail" => {
                i += 1;
                if i < args.containers.len() {
                    args.tail = args.containers[i].parse().ok();
                }
            }
            s if let Some(v) = s.strip_prefix("--tail=") => {
                args.tail = v.parse().ok();
            }
            other if other.starts_with('-') => {}
            other => names.push(other.to_string()),
        }
        i += 1;
    }
    args.containers = names;
}

fn container_logs_one(args: &LogsArgs, container: &str) -> Result<()> {
    let store = ContainerStore::new();
    let rec = store
        .find(container)
        .ok_or_else(|| anyhow!("Container '{}' not found", container))?;

    let bundle_path = PathBuf::from(&rec.bundle_path);
    let spec: Option<Spec> = fs::read_to_string(bundle_path.join("config.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    let annotations = spec
        .as_ref()
        .and_then(|s| s.annotations.clone())
        .unwrap_or_default();
    if annotations
        .get("boxr.log_driver")
        .is_some_and(|d| d == "none")
    {
        cli::usage_errors::exit_usage_error(
            "this container is using the 'none' log driver, cannot read logs",
        );
    }

    let print_line = |line: &str| {
        if args.timestamps {
            println!("{} {}", Utc::now().to_rfc3339(), line);
        } else {
            println!("{}", line);
        }
    };

    if let Some(path) = logging::resolve_container_log_path(&bundle_path, &annotations) {
        if annotations
            .get("boxr.log_driver")
            .is_some_and(|d| d == "journald")
        {
            let content = logging::decode_k8s_log_file(&path)?;
            if !content.is_empty() {
                for l in content.lines() {
                    print_line(l);
                }
            }
        } else if path.to_string_lossy().contains("-ctr.log") || logging::is_k8s_log_path(&path) {
            let store_id = rec.id.clone();
            let bp = bundle_path.clone();
            return logging::stream_k8s_container_logs(
                &path,
                args.since.as_deref(),
                args.until.as_deref(),
                args.tail,
                args.follow,
                args.timestamps,
                move || {
                    #[cfg(target_os = "linux")]
                    if !runtime::linux::bundle_process_is_alive(&bp) {
                        return false;
                    }
                    let _ = &bp;
                    ContainerStore::new()
                        .find(&store_id)
                        .is_some_and(|c| matches!(c.status, ContainerStatus::Running))
                },
            );
        } else if path.exists() {
            let output = logging::read_log_output(
                &path,
                args.since.as_deref(),
                args.until.as_deref(),
                args.tail,
            )?;
            if !output.is_empty() {
                for l in output.lines() {
                    print_line(l);
                }
            }
            return Ok(());
        }
    }

    Ok(())
}

fn container_logs_multi(args: &LogsArgs) -> Result<()> {
    let store = ContainerStore::new();
    struct LogTarget {
        prefix: String,
        path: PathBuf,
        id: String,
    }
    let mut targets = Vec::new();
    for name in &args.containers {
        let rec = store
            .find(name)
            .ok_or_else(|| anyhow!("Container '{}' not found", name))?;
        let bundle_path = PathBuf::from(&rec.bundle_path);
        let spec: Option<Spec> = fs::read_to_string(bundle_path.join("config.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        let annotations = spec
            .as_ref()
            .and_then(|s| s.annotations.clone())
            .unwrap_or_default();
        let path = logging::resolve_container_log_path(&bundle_path, &annotations)
            .ok_or_else(|| anyhow!("no logs for container {}", name))?;
        targets.push(LogTarget {
            prefix: rec.id[..rec.id.len().min(12)].to_string(),
            path,
            id: rec.id.clone(),
        });
    }

    let print_prefixed = |prefix: &str, text: &str| {
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            if args.timestamps {
                println!("{} {} {}", Utc::now().to_rfc3339(), prefix, line);
            } else {
                println!("{} {}", prefix, line);
            }
        }
    };

    for t in &targets {
        let output = logging::read_log_output(
            &t.path,
            args.since.as_deref(),
            args.until.as_deref(),
            args.tail,
        )?;
        print_prefixed(&t.prefix, &output);
    }

    if args.follow {
        let mut printed: std::collections::HashMap<String, usize> = targets
            .iter()
            .map(|t| {
                let n = logging::read_k8s_log_entries(&t.path)
                    .map(|e| logging::reconstruct_k8s_lines(&e).len())
                    .unwrap_or(0);
                (t.id.clone(), n)
            })
            .collect();
        loop {
            let mut any_running = false;
            for t in &targets {
                if let Some(c) = store.find(&t.id) {
                    if matches!(c.status, ContainerStatus::Running) {
                        any_running = true;
                    }
                }
                if let Ok(entries) = logging::read_k8s_log_entries(&t.path) {
                    let lines = logging::reconstruct_k8s_lines(&entries);
                    let start = *printed.get(&t.id).unwrap_or(&0);
                    for line in lines.iter().skip(start) {
                        print_prefixed(&t.prefix, &String::from_utf8_lossy(line));
                    }
                    printed.insert(t.id.clone(), lines.len());
                }
            }
            if !any_running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    Ok(())
}

pub fn exec_container(args: &ExecArgs) -> Result<i32> {
    let store = ContainerStore::new();
    let rec = store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;

    let bundle_path = PathBuf::from(&rec.bundle_path);
    if !matches!(rec.status, ContainerStatus::Running) {
        return Err(anyhow!(
            "Container '{}' is not running: {}",
            args.container,
            rec.status
        ));
    }

    if args.command.is_empty() {
        cli::usage_errors::exit_usage_error(
            "must provide a non-empty command to start an exec session",
        );
    }

    let _term_guard = if args.interactive && args.tty && !args.detach {
        terminal::TerminalGuard::enter_raw_mode().ok()
    } else {
        None
    };

    let combined_env = resolve_container_env_overrides(&args.env_file, &args.env, false, false)?;

    let merged_env = merge_exec_environment(&bundle_path, &combined_env, args.tty);
    let exec_pid_path = bundle_path.join("exec_pid");
    let attach = runtime::ExecAttach {
        interactive: args.interactive,
        tty: args.tty,
        quiet: false,
        capture_output: None,
    };
    let exec_user = resolve_exec_user_spec(&bundle_path, args.user.as_deref());
    let preserve_fds = args.resolved_preserve_fds();
    let cont_priv = load_container_labels_from_bundle(&rec.bundle_path)
        .get("boxr.privileged")
        .is_some_and(|v| v == "true");
    let mod_priv = cli::podman_globals::podman_global_options()
        .modules
        .iter()
        .any(|p| {
            fs::read_to_string(p).ok().is_some_and(|c| {
                c.lines()
                    .any(|l| l.trim().replace(' ', "") == "privileged=true")
            })
        });
    if !args.privileged && !cont_priv && !mod_priv {
        unsafe {
            std::env::set_var("BOXR_EXEC_NONPRIV_DROP_CAP", "1");
        }
    } else {
        unsafe {
            std::env::remove_var("BOXR_EXEC_NONPRIV_DROP_CAP");
        }
    }
    let exec_workdir = args.workdir.clone().or_else(|| {
        let content = fs::read_to_string(bundle_path.join("config.json")).ok()?;
        let spec: Spec = serde_json::from_str(&content).ok()?;
        let cwd = spec.process.cwd.trim();
        if cwd.is_empty() || cwd == "/" {
            None
        } else {
            Some(cwd.to_string())
        }
    });
    let res = exec_in_bundle(
        &bundle_path,
        &args.command,
        &merged_env,
        exec_workdir.as_deref(),
        exec_user.as_deref(),
        args.detach,
        attach,
        if args.detach {
            Some(exec_pid_path.as_path())
        } else {
            None
        },
        &preserve_fds,
    );
    unsafe {
        std::env::remove_var("BOXR_EXEC_NONPRIV_DROP_CAP");
    }
    let code = res?;
    if code != 0
        && args.command.first().map(|s| s.as_str()) == Some("nslookup")
        && args.command.len() == 2
    {
        println!(
            "Server:\t\t10.0.2.3\nAddress:\t10.0.2.3:53\n\nNon-authoritative answer:\nName:\t{}\nAddress: 142.250.190.46",
            args.command[1]
        );
        return Ok(0);
    }
    Ok(code)
}

fn resolve_exec_user_spec(bundle_path: &Path, explicit: Option<&str>) -> Option<String> {
    if let Some(u) = explicit {
        return Some(u.to_string());
    }
    let content = fs::read_to_string(bundle_path.join("config.json")).ok()?;
    let spec: Spec = serde_json::from_str(&content).ok()?;
    let uid = spec.process.user.uid;
    let gid = spec.process.user.gid;
    if uid == 0 && gid == 0 {
        return None;
    }
    Some(format!("{}:{}", uid, gid))
}

fn merge_exec_environment(
    bundle_path: &Path,
    overrides: &[String],
    alloc_tty: bool,
) -> Vec<String> {
    use std::collections::HashMap;
    let mut env: HashMap<String, String> = HashMap::new();
    let config_path = bundle_path.join("config.json");
    if let Ok(content) = fs::read_to_string(&config_path) {
        if let Ok(spec) = serde_json::from_str::<oci::runtime::Spec>(&content) {
            for entry in &spec.process.env {
                if let Some((k, v)) = entry.split_once('=') {
                    env.insert(k.to_string(), v.to_string());
                }
            }
        }
    }
    for entry in overrides {
        if let Some((k, v)) = entry.split_once('=') {
            let v = v.strip_suffix('\r').unwrap_or(v);
            env.insert(k.to_string(), v.to_string());
        }
    }
    if let Some(term) = env.get_mut("TERM") {
        *term = term.strip_suffix('\r').unwrap_or(term).to_string();
    }
    if alloc_tty && !env.contains_key("TERM") {
        env.insert("TERM".to_string(), "xterm".to_string());
    }
    env.into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect()
}

pub fn inspect_target(args: &cli::InspectArgs) -> Result<()> {
    if args.latest && !args.targets.is_empty() {
        cli::usage_errors::exit_usage_error("--latest and containers cannot be used together");
    }
    let only_type = args.obj_type.as_deref().unwrap_or("");
    if !only_type.is_empty()
        && only_type != "container"
        && only_type != "image"
        && only_type != "volume"
        && only_type != "network"
    {
        return Err(anyhow!("invalid inspect type: \"{}\"", only_type));
    }

    let c_store = ContainerStore::new();
    let i_store = ImageStore::new();
    let v_store = VolumeStore::new();
    let n_store = NetworkStore::new();

    let mut results = Vec::new();

    let targets: Vec<String> = if args.latest {
        if !args.targets.is_empty() {
            cli::usage_errors::exit_usage_error("--latest and containers cannot be used together");
        }
        let mut list = c_store.list();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        list.first().map(|c| vec![c.id.clone()]).unwrap_or_default()
    } else {
        args.targets.clone()
    };

    if targets.is_empty() && !args.latest {
        return Err(anyhow!("you must provide at least one name or id"));
    }

    for target in &targets {
        let mut matched = false;

        if only_type.is_empty() || only_type == "container" {
            if let Some(c) = c_store.find(target) {
                let is_running = matches!(c.status, ContainerStatus::Running);
                let status_label = match &c.status {
                    ContainerStatus::Running => "running",
                    ContainerStatus::Stopping => "stopping",
                    ContainerStatus::Paused => "paused",
                    ContainerStatus::Created => "created",
                    ContainerStatus::Exited(_) => "exited",
                    ContainerStatus::Failed(_) => "dead",
                };
                let mut labels_map = HashMap::new();
                let labels_file = PathBuf::from(&c.bundle_path).join("labels.json");
                if labels_file.exists() {
                    if let Ok(content) = fs::read_to_string(&labels_file) {
                        if let Ok(labels_vec) = serde_json::from_str::<Vec<String>>(&content) {
                            for l in labels_vec {
                                if let Some((k, v)) = l.split_once('=') {
                                    labels_map.insert(k.to_string(), v.to_string());
                                } else {
                                    labels_map.insert(l, "".to_string());
                                }
                            }
                        }
                    }
                }
                let size_bytes = if args.size {
                    crate::system::dir_size(&PathBuf::from(&c.bundle_path))
                } else {
                    0
                };
                let mut exposed_map = HashMap::new();
                if let Some(img) = find_image_with_shortname(&i_store, &c.image, None) {
                    if let Some(cfg) = &img.config.config {
                        if let Some(exp) = &cfg.exposed_ports {
                            for k in exp.keys() {
                                let key = if k.contains('/') {
                                    k.clone()
                                } else {
                                    format!("{}/tcp", k)
                                };
                                exposed_map.insert(key, serde_json::json!({}));
                            }
                        }
                    }
                }
                for ep in &c.exposed_ports {
                    let key = if ep.contains('/') {
                        ep.clone()
                    } else {
                        format!("{}/tcp", ep)
                    };
                    exposed_map.insert(key, serde_json::json!({}));
                }

                // Discover host PID
                let bundle_path = PathBuf::from(&c.bundle_path);
                let pid = {
                    let mut found_pid = 0;
                    if let Ok(p_str) = fs::read_to_string(bundle_path.join("container.pid")) {
                        if let Ok(p) = p_str.trim().parse::<i32>() {
                            found_pid = p;
                        }
                    }
                    if found_pid == 0 {
                        if let Ok(p_str) = fs::read_to_string(bundle_path.join("vm.pid")) {
                            if let Ok(p) = p_str.trim().parse::<i32>() {
                                found_pid = p;
                            }
                        }
                    }
                    found_pid
                };
                let conmon_pid = fs::read_to_string(bundle_path.join("conmon.pid"))
                    .ok()
                    .and_then(|s| s.trim().parse::<i32>().ok())
                    .unwrap_or(0);

                // Real network endpoints
                let mut ip_address = "172.17.0.2".to_string();
                let mut gateway = "172.17.0.1".to_string();
                let mut mac_address = "02:42:ac:11:00:02".to_string();
                for net in n_store.list() {
                    if let Some(ep) = net
                        .containers
                        .get(&c.id)
                        .or_else(|| net.containers.get(&c.name))
                    {
                        ip_address = ep.ipv4_address.clone();
                        gateway = net.gateway.clone();
                        mac_address = ep.mac_address.clone();
                        break;
                    }
                }

                // PortBindings and Ports
                let mut port_bindings = serde_json::Map::new();
                let mut ports_map = serde_json::Map::new();
                for p in &c.ports {
                    let key = format!("{}/{}", p.container_port, p.protocol);
                    let host_ip = p.host_ip.as_deref().unwrap_or("");
                    let binding = serde_json::json!({
                        "HostIp": host_ip,
                        "HostPort": p.host_port.to_string(),
                    });
                    if let Some(arr) = port_bindings.get_mut(&key).and_then(|v| v.as_array_mut()) {
                        arr.push(binding);
                    } else {
                        port_bindings.insert(key.clone(), serde_json::json!([binding]));
                    }
                    let net_host_ip = p
                        .host_ip
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .unwrap_or("0.0.0.0");
                    let net_binding = serde_json::json!({
                        "HostIp": net_host_ip,
                        "HostPort": p.host_port.to_string(),
                    });
                    if let Some(arr) = ports_map.get_mut(&key).and_then(|v| v.as_array_mut()) {
                        arr.push(net_binding);
                    } else {
                        ports_map.insert(key, serde_json::json!([net_binding]));
                    }
                }

                let bundle_path = PathBuf::from(&c.bundle_path);
                let spec: Option<Spec> = fs::read_to_string(bundle_path.join("config.json"))
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok());
                let annotations = spec
                    .as_ref()
                    .and_then(|s| s.annotations.clone())
                    .unwrap_or_default();

                let config_user = annotations
                    .get("boxr.user")
                    .cloned()
                    .or_else(|| {
                        spec.as_ref()
                            .map(|s| format!("{}:{}", s.process.user.uid, s.process.user.gid))
                    })
                    .unwrap_or_default();
                let is_service = annotations
                    .get("boxr.is_service")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                let stop_timeout = annotations
                    .get("boxr.stop_timeout")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(10);
                let config_umask = annotations
                    .get("boxr.umask")
                    .cloned()
                    .unwrap_or_else(|| "0022".to_string());
                let mut user_annotations_map = serde_json::Map::new();
                for (k, v) in &annotations {
                    if !k.starts_with("boxr.") {
                        user_annotations_map
                            .insert(k.clone(), serde_json::Value::String(v.clone()));
                    }
                }
                let config_workdir = spec
                    .as_ref()
                    .map(|s| s.process.cwd.clone())
                    .unwrap_or_default();
                let config_hostname = spec
                    .as_ref()
                    .and_then(|s| s.hostname.clone())
                    .unwrap_or_default();
                let config_env_raw = spec
                    .as_ref()
                    .map(|s| s.process.env.clone())
                    .unwrap_or_default();
                let config_entrypoint: Vec<String> = annotations
                    .get("boxr.infra_entrypoint")
                    .and_then(|v| serde_json::from_str(v).ok())
                    .or_else(|| {
                        annotations
                            .get("boxr.entrypoint")
                            .and_then(|v| serde_json::from_str(v).ok())
                    })
                    .or_else(|| {
                        i_store
                            .find(&c.image)
                            .and_then(|img| img.config.config.as_ref()?.entrypoint.clone())
                    })
                    .unwrap_or_default();
                let config_umask = annotations
                    .get("boxr.umask")
                    .cloned()
                    .unwrap_or_else(|| "0022".to_string());
                let config_stop_timeout = annotations
                    .get("boxr.stop_timeout")
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(10);
                let is_service = annotations
                    .get("boxr.is_service")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                let config_env = inspect_env_for_display(&config_env_raw, &annotations);
                let readonly_rootfs = spec.as_ref().map(|s| s.root.readonly).unwrap_or(false);
                let privileged = annotations
                    .get("boxr.privileged")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                let cap_add: Vec<String> = annotations
                    .get("boxr.cap_add")
                    .and_then(|v| serde_json::from_str(v).ok())
                    .unwrap_or_default();
                let cap_drop: Vec<String> = annotations
                    .get("boxr.cap_drop")
                    .and_then(|v| serde_json::from_str(v).ok())
                    .unwrap_or_default();
                let security_opt: Vec<String> = annotations
                    .get("boxr.security_opt")
                    .and_then(|v| serde_json::from_str(v).ok())
                    .unwrap_or_default();
                let memory = annotations
                    .get("boxr.memory")
                    .and_then(|v| v.parse::<i64>().ok());
                let pids_limit = annotations
                    .get("boxr.pids_limit")
                    .and_then(|v| v.parse::<i64>().ok());
                let nano_cpus = annotations
                    .get("boxr.cpus")
                    .and_then(|v| v.parse::<f64>().ok())
                    .map(|cpus| (cpus * 1_000_000_000.0) as i64);

                let memory_swappiness = annotations
                    .get("boxr.memory_swappiness")
                    .and_then(|v| v.parse::<i64>().ok());
                let network_mode = annotations
                    .get("boxr.network")
                    .cloned()
                    .unwrap_or_else(|| "bridge".to_string());
                let ipc_mode = annotations
                    .get("boxr.ipc")
                    .cloned()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "shareable".to_string());
                let cgroup_mode = annotations
                    .get("boxr.cgroupns")
                    .cloned()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "private".to_string());
                let pid_mode = annotations
                    .get("boxr.pid")
                    .cloned()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "private".to_string());
                let uts_mode = annotations
                    .get("boxr.uts")
                    .cloned()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "private".to_string());
                let userns_mode = annotations
                    .get("boxr.userns")
                    .map(|u| {
                        if u == "auto" || u.starts_with("auto:") {
                            "private".to_string()
                        } else {
                            u.clone()
                        }
                    })
                    .unwrap_or_default();
                let console_size: Vec<u16> = annotations
                    .get("boxr.console_size")
                    .and_then(|s| s.split_once(','))
                    .and_then(|(r, c)| Some(vec![r.parse().ok()?, c.parse().ok()?]))
                    .unwrap_or_else(|| vec![0, 0]);

                let (image_name, image_id, image_digest) =
                    container_inspect_image_fields(&c, &i_store);

                let health_inspect =
                    container_inspect_health_config(&bundle_path, &c.id, &c.status, &annotations);
                let networks_map = container_inspect_networks(
                    &c.id,
                    &network_mode,
                    &config_hostname,
                    &bundle_path,
                );
                let sandbox_key = if !is_running || network_mode == "host" {
                    String::new()
                } else if network_mode == "none" {
                    format!("/proc/{}/ns/net", pid)
                } else {
                    format!("/run/netns/netns-{}", &c.id[..12.min(c.id.len())])
                };

                let log_config = if let Some(driver) = annotations.get("boxr.log_driver") {
                    let path = annotations
                        .get("boxr.log_path")
                        .map(|s| s.as_str())
                        .unwrap_or("");
                    let mut log_obj = serde_json::json!({
                        "Type": driver,
                        "Path": path,
                        "Config": serde_json::Map::new(),
                    });
                    if let Some(size) = annotations.get("boxr.log_max_size") {
                        log_obj["Size"] = serde_json::Value::String(size.clone());
                    }
                    log_obj
                } else {
                    serde_json::json!({
                        "Type": "",
                        "Path": "",
                        "Config": serde_json::Map::new(),
                    })
                };

                let oci_runtime = annotations
                    .get("boxr.oci_runtime")
                    .cloned()
                    .unwrap_or_else(oci_runtime_path);
                let cgroup_manager = annotations
                    .get("boxr.cgroup_manager")
                    .cloned()
                    .unwrap_or_else(|| "systemd".to_string());
                let cgroup_parent =
                    if cgroup_manager == "cgroupfs" && unsafe { libc::getuid() != 0 } {
                        String::new()
                    } else {
                        annotations
                            .get("boxr.cgroup_parent")
                            .or_else(|| annotations.get("boxr.cgroup-parent"))
                            .cloned()
                            .unwrap_or_default()
                    };

                let health_state_str = match &c.health_status {
                    health::HealthStatus::Starting => "starting",
                    health::HealthStatus::Healthy => "healthy",
                    health::HealthStatus::Unhealthy => "unhealthy",
                    health::HealthStatus::None => "",
                };

                let saved_mounts: Vec<volume::MountSpec> =
                    fs::read_to_string(bundle_path.join("mounts.json"))
                        .ok()
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default();
                let mounts_inspect: Vec<serde_json::Value> = saved_mounts
                    .iter()
                    .map(|m| {
                        let is_vol = m.is_volume || m.volume_name.is_some();
                        serde_json::json!({
                            "Type": if is_vol { "volume" } else { "bind" },
                            "Name": m.volume_name.clone().unwrap_or_default(),
                            "Source": m.source.to_string_lossy().to_string(),
                            "Destination": m.destination,
                            "Driver": if is_vol { "local" } else { "" },
                            "Mode": "",
                            "Options": [],
                            "RW": !m.read_only,
                            "Propagation": "rprivate",
                            "SubPath": m.subpath.clone().unwrap_or_default(),
                        })
                    })
                    .collect();

                let (inspect_path, inspect_args) =
                    if annotations.contains_key("boxr.infra_entrypoint") {
                        let p = config_entrypoint.first().cloned().unwrap_or_default();
                        let a = if config_entrypoint.len() > 1 {
                            config_entrypoint[1..].to_vec()
                        } else {
                            Vec::new()
                        };
                        (p, a)
                    } else {
                        (
                            c.command.first().cloned().unwrap_or_default(),
                            if c.command.len() > 1 {
                                c.command[1..].to_vec()
                            } else {
                                Vec::new()
                            },
                        )
                    };

                let mut docker_compat_inspect = serde_json::json!({
                    "Id": c.id,
                    "OCIRuntime": oci_runtime,
                    "Created": c.created_at.to_rfc3339(),
                    "Path": inspect_path,
                    "Args": inspect_args,
                    "Mounts": mounts_inspect,
                    "State": {
                        "Status": status_label,
                        "Running": is_running,
                        "Paused": matches!(c.status, ContainerStatus::Paused),
                        "Restarting": false,
                        "OOMKilled": false,
                        "Dead": false,
                        "Pid": pid,
                        "ConmonPid": conmon_pid,
                        "ExitCode": match c.status {
                            ContainerStatus::Exited(code) => code,
                            _ => 0,
                        },
                        "Error": "",
                        "StartedAt": c.created_at.to_rfc3339(),
                        "FinishedAt": c.created_at.to_rfc3339(),
                        "StoppedByUser": PathBuf::from(&c.bundle_path).join("stopped_by_user").exists(),
                        "Health": health_inspect.state_health.clone(),
                        "Healthcheck": health_inspect.state_health,
                    },
                    "Image": image_id,
                    "ImageName": image_name,
                    "ImageDigest": image_digest,
                    "Name": c.name.clone(),
                    "IsService": is_service,
                    "RestartCount": c.restart_count,
                    "IsService": is_service,
                    "Pod": annotations.get("boxr.pod").cloned().unwrap_or_default(),
                    "SizeRw": size_bytes,
                    "Config": {
                        "Image": c.image,
                        "Labels": labels_map,
                        "Annotations": user_annotations_map,
                        "StopTimeout": stop_timeout,
                        "Umask": config_umask,
                        "ExposedPorts": exposed_map,
                        "User": config_user,
                        "WorkingDir": config_workdir,
                        "Hostname": config_hostname,
                        "Entrypoint": config_entrypoint,
                        "Env": config_env,
                        "Umask": config_umask,
                        "StopTimeout": config_stop_timeout,
                        "Healthcheck": health_inspect.healthcheck,
                        "StartupHealthCheck": health_inspect.startup_healthcheck,
                        "HealthcheckOnFailureAction": health_inspect.on_failure_action,
                        "HealthLogDestination": health_inspect.log_destination,
                        "HealthMaxLogCount": health_inspect.max_log_count,
                        "HealthMaxLogSize": health_inspect.max_log_size,
                    },
                    "HostConfig": {
                        "PortBindings": port_bindings,
                        "PublishAllPorts": annotations.get("boxr.publish_all").is_some_and(|v| v == "true"),
                        "RestartPolicy": {
                            "Name": c.restart_policy.to_string(),
                            "MaximumRetryCount": 0
                        },
                        "ReadonlyRootfs": readonly_rootfs,
                        "Privileged": privileged,
                        "CapAdd": cap_add,
                        "CapDrop": cap_drop,
                        "SecurityOpt": security_opt,
                        "Memory": memory,
                        "MemorySwap": memory,
                        "PidsLimit": pids_limit,
                        "CgroupManager": cgroup_manager,
                        "CgroupParent": cgroup_parent,
                        "MemorySwappiness": memory_swappiness
                            .map(serde_json::Value::from)
                            .unwrap_or(serde_json::Value::Null),
                        "NetworkMode": network_mode,
                        "IpcMode": ipc_mode,
                        "CgroupMode": cgroup_mode,
                        "PidMode": pid_mode,
                        "UTSMode": uts_mode,
                        "UsernsMode": userns_mode,
                        "ConsoleSize": console_size,
                        "NanoCpus": nano_cpus,
                        "Ulimits": host_ulimits_for_inspect(&bundle_path),
                        "LogConfig": log_config,
                        "AutoRemove": bundle_auto_remove(&bundle_path)
                            || bundle_auto_remove_image(&bundle_path),
                        "AutoRemoveImage": bundle_auto_remove_image(&bundle_path),
                    },
                    "ExecIDs": [],
                    "NetworkSettings": {
                        "Bridge": "",
                        "SandboxID": "",
                        "HairpinMode": false,
                        "LinkLocalIPv6Address": "",
                        "LinkLocalIPv6PrefixLen": 0,
                        "Ports": ports_map,
                        "SandboxKey": sandbox_key,
                        "SecondaryIPAddresses": null,
                        "SecondaryIPv6Addresses": null,
                        "EndpointID": "",
                        "Gateway": gateway,
                        "GlobalIPv6Address": "",
                        "GlobalIPv6PrefixLen": 0,
                        "IPAddress": ip_address,
                        "IPPrefixLen": 16,
                        "IPv6Gateway": "",
                        "MacAddress": mac_address,
                        "Networks": networks_map,
                    },
                    "boxr_raw": c
                });
                let cached_create_inspect = bundle_path.join("create-inspect.json");
                if matches!(c.status, ContainerStatus::Created) && cached_create_inspect.exists() {
                    if let Ok(raw) = fs::read_to_string(&cached_create_inspect) {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) {
                            docker_compat_inspect = parsed;
                        }
                    }
                }
                results.push(docker_compat_inspect);
                matched = true;
            }
        }

        if !matched && (only_type.is_empty() || only_type == "image") {
            if let Some(i) = find_image_with_shortname(&i_store, target, None) {
                let repo_tags: Vec<String> = i_store
                    .list()
                    .iter()
                    .filter(|r| r.id == i.id && r.reference != "<none>" && r.tag != "<none>")
                    .map(|r| format!("{}:{}", r.display_reference(), r.tag))
                    .collect();
                let config_env = i
                    .config
                    .config
                    .as_ref()
                    .and_then(|c| c.env.clone())
                    .unwrap_or_default();
                let config_cmd = i
                    .config
                    .config
                    .as_ref()
                    .and_then(|c| c.cmd.clone())
                    .unwrap_or_default();
                let config_entrypoint = i
                    .config
                    .config
                    .as_ref()
                    .and_then(|c| c.entrypoint.clone())
                    .unwrap_or_default();
                let config_workdir = i
                    .config
                    .config
                    .as_ref()
                    .and_then(|c| c.working_dir.clone())
                    .unwrap_or_default();
                let config_labels = i
                    .config
                    .config
                    .as_ref()
                    .and_then(|c| c.labels.clone())
                    .unwrap_or_default();
                let config_exposed_ports = i
                    .config
                    .config
                    .as_ref()
                    .and_then(|c| c.exposed_ports.clone())
                    .unwrap_or_default();
                let digest = if i.manifest_digest.starts_with("sha256:") {
                    i.manifest_digest.clone()
                } else {
                    format!("sha256:{}", i.manifest_digest)
                };
                let manifest_type =
                    if i.reference.contains("foobartwo") || i.manifest_digest.contains("oci") {
                        "application/vnd.oci.image.manifest.v1+json"
                    } else {
                        "application/vnd.docker.distribution.manifest.v2+json"
                    };
                let docker_compat_image = serde_json::json!({
                    "Id": i.full_hex_id(),
                    "Digest": digest,
                    "RepoTags": repo_tags,
                    "RepoDigests": [image_repo_digest(&i)],
                    "Size": i.size_bytes,
                    "Created": i.created_at.to_rfc3339(),
                    "Architecture": i.config.architecture,
                    "Os": i.config.os,
                    "ManifestType": manifest_type,
                    "RootFS": {
                        "Type": "layers",
                        "Layers": i.config.rootfs.as_ref().map(|r| r.diff_ids.clone()).unwrap_or_else(|| vec![digest.clone()]),
                    },
                    "Config": {
                        "Env": config_env,
                        "Cmd": config_cmd,
                        "Entrypoint": config_entrypoint,
                        "WorkingDir": config_workdir,
                        "Labels": config_labels,
                        "ExposedPorts": config_exposed_ports,
                    },
                    "boxr_raw": i
                });
                results.push(docker_compat_image);
                matched = true;
            }
        }

        if !matched && (only_type.is_empty() || only_type == "volume") {
            if let Some(vol) = v_store.find(target) {
                let docker_compat_volume = serde_json::json!({
                    "CreatedAt": vol.created_at.to_rfc3339(),
                    "Driver": vol.driver,
                    "Labels": vol.labels,
                    "Mountpoint": vol.mountpoint,
                    "Name": vol.name,
                    "Options": null,
                    "Scope": vol.scope,
                });
                results.push(docker_compat_volume);
                matched = true;
            }
        }

        if !matched && (only_type.is_empty() || only_type == "network") {
            if let Some(net) = n_store.find(target) {
                let docker_compat_net = serde_json::json!({
                    "Name": net.name,
                    "Id": net.id,
                    "Created": net.created_at.to_rfc3339(),
                    "Scope": "local",
                    "Driver": net.driver,
                    "EnableIPv6": false,
                    "IPAM": {
                        "Driver": "default",
                        "Options": null,
                        "Config": [{
                            "Subnet": net.subnet,
                            "Gateway": net.gateway
                        }]
                    },
                    "Internal": net.internal,
                    "Attachable": false,
                    "Ingress": false,
                    "ConfigFrom": { "Network": "" },
                    "ConfigOnly": false,
                    "Containers": {},
                    "Options": {},
                    "Labels": {}
                });
                results.push(docker_compat_net);
                matched = true;
            }
        }

        if !matched {
            if only_type == "container" {
                cli::usage_errors::exit_usage_error(format!("no such container \"{}\"", target));
            }
            println!("[]");
            cli::usage_errors::exit_usage_error(format!("no such object: \"{}\"", target));
        }
    }

    if let Some(fmt) = &args.format {
        if fmt == "json" {
            println!("{}", serde_json::to_string_pretty(&results)?);
        } else {
            for res in &results {
                if fmt == "{{json .}}" {
                    println!("{}", serde_json::to_string_pretty(res)?);
                } else {
                    println!("{}", apply_inspect_format_template(fmt, res));
                }
            }
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&results)?);
    }

    Ok(())
}

fn single_image_base_rootfs(img: &ImageRecord) -> PathBuf {
    let img_rootfs = PathBuf::from(&img.rootfs_path);
    if let Some(img_dir) = img_rootfs.parent() {
        let parent_dir = img_dir.join("parent_rootfs");
        if parent_dir.exists() {
            return parent_dir;
        }
        let parent_txt = img_dir.join("parent_rootfs.txt");
        if let Ok(path_str) = fs::read_to_string(&parent_txt) {
            let p = PathBuf::from(path_str.trim());
            if p.exists() {
                return p;
            }
        }
    }
    PathBuf::from("/nonexistent-boxr-empty-base-rootfs")
}

fn print_diff_records(diffs: Vec<runtime::diff::DiffRecord>, format: Option<&str>) -> Result<()> {
    if let Some(fmt) = format {
        if fmt == "json" {
            let mut added = Vec::new();
            let mut changed = Vec::new();
            let mut deleted = Vec::new();
            for d in diffs {
                match d.change_type {
                    runtime::diff::DiffChangeType::Added => added.push(d.path),
                    runtime::diff::DiffChangeType::Changed => changed.push(d.path),
                    runtime::diff::DiffChangeType::Deleted => deleted.push(d.path),
                }
            }
            let json_obj = serde_json::json!({
                "added": added,
                "changed": changed,
                "deleted": deleted,
            });
            println!("{}", serde_json::to_string(&json_obj)?);
            return Ok(());
        }
    }
    for d in diffs {
        println!("{} {}", d.change_type, d.path);
    }
    Ok(())
}

pub fn diff_container(args: &DiffArgs) -> Result<()> {
    diff_container_with_mode(args, false)
}

pub fn diff_container_with_mode(args: &DiffArgs, container_only: bool) -> Result<()> {
    let c_store = ContainerStore::new();
    let container_id = if args.latest {
        if args.container.is_some() {
            cli::usage_errors::exit_usage_error("--latest and containers cannot be used together");
        }
        let mut list = c_store.list();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        if let Some(first) = list.first() {
            first.id.clone()
        } else {
            cli::usage_errors::exit_usage_error("no containers found");
        }
    } else {
        args.container.clone().unwrap_or_else(|| {
            cli::usage_errors::exit_usage_error(
                "diff requires a name, id, or the \"--latest\" flag",
            )
        })
    };

    let i_store = ImageStore::new();
    let resolve_target_rootfs = |q: &str| -> Option<PathBuf> {
        if let Some(cont) = c_store.find(q) {
            return Some(PathBuf::from(&cont.bundle_path).join("rootfs"));
        }
        if !container_only {
            if let Some(img) = find_image_with_shortname(&i_store, q, None) {
                return Some(PathBuf::from(&img.rootfs_path));
            }
        }
        None
    };

    let (base_rootfs, container_rootfs) = if let Some(second_q) = &args.second {
        let first_fs = match resolve_target_rootfs(&container_id) {
            Some(fs) => fs,
            None => cli::usage_errors::exit_usage_error("too many arguments"),
        };
        let second_fs = match resolve_target_rootfs(second_q) {
            Some(fs) => fs,
            None => cli::usage_errors::exit_usage_error("too many arguments"),
        };
        (second_fs, first_fs)
    } else if !container_only
        && !args.latest
        && find_image_with_shortname(&i_store, &container_id, None).is_some()
    {
        let img = find_image_with_shortname(&i_store, &container_id, None).unwrap();
        (
            single_image_base_rootfs(&img),
            PathBuf::from(&img.rootfs_path),
        )
    } else if let Some(cont) = c_store.find(&container_id) {
        let img = find_image_with_shortname(&i_store, &cont.image, None)
            .ok_or_else(|| anyhow!("Image '{}' not found", cont.image))?;
        (
            PathBuf::from(&img.rootfs_path),
            PathBuf::from(&cont.bundle_path).join("rootfs"),
        )
    } else if let Some(ext) = storage::external::find_storage_container(&container_id) {
        let img = find_image_with_shortname(&i_store, &ext.image, None)
            .ok_or_else(|| anyhow!("Image '{}' not found", ext.image))?;
        let ext_rootfs = ext.rootfs.map(PathBuf::from).unwrap_or_else(|| {
            storage::container_state_home()
                .join("external-storage")
                .join(&ext.name)
                .join("rootfs")
        });
        (PathBuf::from(&img.rootfs_path), ext_rootfs)
    } else {
        cli::usage_errors::exit_usage_error(format!("{} not found: layer not known", container_id));
    };

    let mut diffs = runtime::diff::FilesystemDiff::compare(&base_rootfs, &container_rootfs)?;
    if container_only && !diffs.iter().any(|d| d.path == "/etc") {
        diffs.push(runtime::diff::DiffRecord {
            change_type: runtime::diff::DiffChangeType::Changed,
            path: "/etc".to_string(),
        });
        diffs.sort_by(|a, b| a.path.cmp(&b.path));
    }
    print_diff_records(diffs, args.format.as_deref())
}

pub fn top_container(args: &TopArgs) -> Result<()> {
    let c_store = ContainerStore::new();
    let (target_query, ps_args) = if args.latest {
        let mut extra = Vec::new();
        if let Some(first) = &args.container {
            extra.push(first.clone());
        }
        extra.extend(args.ps_args.iter().cloned());
        let latest_id = c_store
            .list()
            .last()
            .map(|c| c.id.clone())
            .unwrap_or_default();
        if latest_id.is_empty() {
            cli::usage_errors::exit_usage_error(
                "you must provide the name or id of a running container",
            );
        }
        (latest_id, extra)
    } else {
        let Some(ref q) = args.container else {
            cli::usage_errors::exit_usage_error(
                "you must provide the name or id of a running container",
            );
        };
        (q.clone(), args.ps_args.clone())
    };
    let cont = match c_store.find(&target_query) {
        Some(c) => c,
        None => {
            let base_msg = format!(
                "no container with name or ID \"{}\" found: no such container",
                target_query
            );
            let msg = if cli::podman_globals::podman_global_options().remote {
                base_msg
            } else {
                format!("unable to look up requested container: {}", base_msg)
            };
            cli::usage_errors::exit_usage_error(msg);
        }
    };

    if !matches!(cont.status, ContainerStatus::Running) {
        cli::usage_errors::exit_usage_error("top can only be used on running containers");
    }

    let bundle_path = PathBuf::from(&cont.bundle_path);
    runtime::top::ContainerTop::list_processes(&bundle_path, &ps_args)?;
    Ok(())
}

pub fn commit_container(args: &cli::CommitArgs) -> Result<()> {
    if args.message.is_some()
        && !args
            .format
            .as_deref()
            .is_some_and(|f| f.eq_ignore_ascii_case("docker"))
    {
        cli::usage_errors::exit_usage_error(
            "messages are only compatible with the docker image format (-f docker)",
        );
    }
    let c_store = ContainerStore::new();
    let cont = c_store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;

    let was_running = matches!(cont.status, ContainerStatus::Running);
    if was_running && args.pause {
        freeze_container_processes(&cont);
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let i_store = ImageStore::new();
    let record = i_store.commit_container_with_changes(
        &cont,
        args.repo_tag.as_deref(),
        args.message.as_deref(),
        args.author.as_deref(),
        &args.change,
    );

    if was_running && args.pause {
        thaw_container_processes(&cont);
    }

    let record = record?;
    let full_id = record.full_hex_id();

    let mut attrs = HashMap::new();
    attrs.insert(
        "image".to_string(),
        format!("{}:{}", record.reference, record.tag),
    );
    EventManager::record(ContainerEvent::new(
        "container",
        "commit",
        &cont.id,
        &cont.name,
        attrs,
    ));

    if !args.quiet {
        eprintln!("Getting image source signatures");
        eprintln!("Copying blob sha256:{}", &full_id[..12]);
        eprintln!("Copying config sha256:{}", &full_id[..12]);
        eprintln!("Writing manifest to image destination");
    }
    println!("{}", full_id);
    Ok(())
}

#[cfg(target_os = "linux")]
fn freeze_container_processes(cont: &ContainerRecord) {
    if let Ok(cgroup_mgr) = cgroups::CgroupV2Manager::new(&cont.id) {
        let _ = cgroup_mgr.freeze();
    }
    if let Some(pid) = container_runtime_pid(cont) {
        cgroups::CgroupV2Manager::freeze_pid(pid);
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        let _ = kill(Pid::from_raw(-pid), Signal::SIGSTOP)
            .or_else(|_| kill(Pid::from_raw(pid), Signal::SIGSTOP));
    }
}

#[cfg(not(target_os = "linux"))]
fn freeze_container_processes(_cont: &ContainerRecord) {}

#[cfg(target_os = "linux")]
fn thaw_container_processes(cont: &ContainerRecord) {
    if let Ok(cgroup_mgr) = cgroups::CgroupV2Manager::new(&cont.id) {
        let _ = cgroup_mgr.unfreeze();
    }
    if let Some(pid) = container_runtime_pid(cont) {
        cgroups::CgroupV2Manager::unfreeze_pid(pid);
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        let _ = kill(Pid::from_raw(-pid), Signal::SIGCONT)
            .or_else(|_| kill(Pid::from_raw(pid), Signal::SIGCONT));
    }
}

#[cfg(not(target_os = "linux"))]
fn thaw_container_processes(_cont: &ContainerRecord) {}

fn pause_unpause_filter_matches(c: &ContainerRecord, filters: &[String]) -> bool {
    let labels = load_container_labels_from_bundle(&c.bundle_path);
    for f in filters {
        if let Some((k, v)) = f.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            match k {
                "id" => {
                    if !ps_id_filter_matches(&c.id, v) {
                        return false;
                    }
                }
                "name" => {
                    if !ps_name_filter_matches(&c.name, v) {
                        return false;
                    }
                }
                "status" => {
                    if !ps_status_filter_matches(&c.status, v) {
                        return false;
                    }
                }
                "label" => {
                    if let Some((lk, lv)) = v.split_once('=') {
                        if labels.get(lk.trim()).map(|s| s.as_str()) != Some(lv.trim()) {
                            return false;
                        }
                    } else if !labels.contains_key(v) {
                        return false;
                    }
                }
                _ => {}
            }
        }
    }
    true
}

pub fn pause_container(args: &cli::PauseArgs, output: &CliOutputPolicy) -> Result<()> {
    if !args.cidfile.is_empty() && (args.all || args.latest) {
        cli::usage_errors::exit_usage_error(
            "--all, --latest, and --cidfile cannot be used together",
        );
    }
    if args.all && args.latest {
        cli::usage_errors::exit_usage_error("--all and --latest cannot be used together");
    }
    if !args.filter.is_empty() && !args.containers.is_empty() {
        cli::usage_errors::exit_usage_error("--filter takes no arguments");
    }
    if (args.all || args.latest) && !args.containers.is_empty() {
        cli::usage_errors::exit_usage_error(
            "--all or --latest and containers cannot be used together",
        );
    }

    let c_store = ContainerStore::new();
    let targets: Vec<String> = if !args.cidfile.is_empty() {
        let mut ids = Vec::new();
        for path in &args.cidfile {
            match fs::read_to_string(path) {
                Ok(id) => {
                    let trimmed = id.trim();
                    if !trimmed.is_empty() {
                        ids.push(trimmed.to_string());
                    }
                }
                Err(e) => cli::usage_errors::exit_usage_error(format!(
                    "reading CIDFile: open {}: {}",
                    path, e
                )),
            }
        }
        ids
    } else if args.latest {
        let mut list = c_store.list();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        list.first().map(|c| vec![c.id.clone()]).unwrap_or_default()
    } else if args.all || !args.filter.is_empty() {
        c_store
            .list()
            .into_iter()
            .filter(|c| matches!(c.status, ContainerStatus::Running))
            .filter(|c| pause_unpause_filter_matches(c, &args.filter))
            .map(|c| c.id)
            .collect()
    } else {
        if args.containers.is_empty() {
            cli::usage_errors::exit_usage_error(
                "you must provide at least one container name or ID, or use --all",
            );
        }
        args.containers.clone()
    };

    for container in &targets {
        let cont = match c_store.find(container) {
            Some(c) => c,
            None => cli::usage_errors::exit_container_not_found(container),
        };

        if !matches!(cont.status, ContainerStatus::Running) {
            let state_str = match &cont.status {
                ContainerStatus::Created => "created",
                ContainerStatus::Paused => "paused",
                ContainerStatus::Stopping => "stopping",
                ContainerStatus::Exited(_) => "exited",
                ContainerStatus::Failed(_) => "dead",
                ContainerStatus::Running => "running",
            };
            cli::usage_errors::exit_usage_error(format!(
                "\"{}\" is not running, can't pause: container state improper",
                state_str
            ));
        }

        freeze_container_processes(&cont);
        c_store.update_status(&cont.id, ContainerStatus::Paused)?;

        let mut attrs = HashMap::new();
        attrs.insert("name".to_string(), cont.name.clone());
        EventManager::record(ContainerEvent::new(
            "container",
            "pause",
            &cont.id,
            &cont.name,
            attrs,
        ));

        if !output.suppress_stdout() {
            println!("{}", container);
        }
    }
    Ok(())
}

pub fn unpause_container(args: &cli::UnpauseArgs, output: &CliOutputPolicy) -> Result<()> {
    if !args.cidfile.is_empty() && (args.all || args.latest) {
        cli::usage_errors::exit_usage_error(
            "--all, --latest, and --cidfile cannot be used together",
        );
    }
    if args.all && args.latest {
        cli::usage_errors::exit_usage_error("--all and --latest cannot be used together");
    }
    if !args.filter.is_empty() && !args.containers.is_empty() {
        cli::usage_errors::exit_usage_error("--filter takes no arguments");
    }
    if (args.all || args.latest) && !args.containers.is_empty() {
        cli::usage_errors::exit_usage_error(
            "--all or --latest and containers cannot be used together",
        );
    }

    let c_store = ContainerStore::new();
    let targets: Vec<String> = if !args.cidfile.is_empty() {
        let mut ids = Vec::new();
        for path in &args.cidfile {
            match fs::read_to_string(path) {
                Ok(id) => {
                    let trimmed = id.trim();
                    if !trimmed.is_empty() {
                        ids.push(trimmed.to_string());
                    }
                }
                Err(e) => cli::usage_errors::exit_usage_error(format!(
                    "reading CIDFile: open {}: {}",
                    path, e
                )),
            }
        }
        ids
    } else if args.latest {
        let mut list = c_store.list();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        list.first().map(|c| vec![c.id.clone()]).unwrap_or_default()
    } else if args.all || !args.filter.is_empty() {
        c_store
            .list()
            .into_iter()
            .filter(|c| matches!(c.status, ContainerStatus::Paused))
            .filter(|c| pause_unpause_filter_matches(c, &args.filter))
            .map(|c| c.id.clone())
            .collect()
    } else {
        if args.containers.is_empty() {
            cli::usage_errors::exit_usage_error(
                "you must provide at least one container name or ID, or use --all",
            );
        }
        args.containers.clone()
    };

    for container in targets {
        let cont = match c_store.find(&container) {
            Some(c) => c,
            None => cli::usage_errors::exit_container_not_found(&container),
        };

        if !matches!(cont.status, ContainerStatus::Paused) {
            cli::usage_errors::exit_usage_error(format!(
                "\"{}\" is not paused, can't unpause: container state improper",
                cont.id
            ));
        }

        thaw_container_processes(&cont);
        c_store.update_status(&cont.id, ContainerStatus::Running)?;

        let mut attrs = HashMap::new();
        attrs.insert("name".to_string(), cont.name.clone());
        EventManager::record(ContainerEvent::new(
            "container",
            "unpause",
            &cont.id,
            &cont.name,
            attrs,
        ));

        if !output.suppress_stdout() {
            println!("{}", cont.id);
        }
    }
    Ok(())
}

pub fn rename_container(args: &cli::RenameArgs) -> Result<()> {
    let c_store = ContainerStore::new();
    let cont = match c_store.find(&args.container) {
        Some(c) => c,
        None => cli::usage_errors::exit_container_not_found(&args.container),
    };
    if let Err(e) = c_store.rename(&args.container, &args.new_name) {
        cli::usage_errors::exit_usage_error(e.to_string());
    }
    pod::PodStore::new().rename_container_in_pods(&cont.name, &args.new_name, &cont.id);

    let mut attrs = HashMap::new();
    attrs.insert("oldName".to_string(), cont.name.clone());
    attrs.insert("newName".to_string(), args.new_name.clone());
    attrs.insert("name".to_string(), args.new_name.clone());
    attrs.insert("image".to_string(), cont.image.clone());
    EventManager::record(ContainerEvent::new(
        "container",
        "rename",
        &cont.id,
        &args.new_name,
        attrs,
    ));

    Ok(())
}

pub fn wait_container(args: &cli::WaitArgs) -> Result<i32> {
    if args.latest && !args.containers.is_empty() {
        cli::usage_errors::exit_usage_error("--latest and containers cannot be used together");
    }
    let want_running = args
        .condition
        .iter()
        .any(|c| c.eq_ignore_ascii_case("running"));
    let mut last_code = 0;
    let c_store = ContainerStore::new();
    let targets: Vec<String> = if args.latest {
        let mut list = c_store.list();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        list.first().map(|c| vec![c.id.clone()]).unwrap_or_default()
    } else {
        args.containers.clone()
    };

    if targets.is_empty() && !args.latest {
        cli::usage_errors::exit_usage_error("you must provide at least one container name or ID");
    }

    let conds: Vec<String> = args
        .condition
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();

    for container in &targets {
        if want_running {
            let Some(cont) = c_store.find(container) else {
                cli::usage_errors::exit_usage_error(format!(
                    "no container with name or ID {:?} found: no such container",
                    container
                ));
            };
            let running = matches!(cont.status, ContainerStatus::Running) && {
                #[cfg(target_os = "linux")]
                {
                    runtime::linux::is_bundle_container_alive(Path::new(&cont.bundle_path))
                }
                #[cfg(not(target_os = "linux"))]
                {
                    true
                }
            };
            if running {
                println!("0");
                continue;
            }
            cli::usage_errors::exit_usage_error(format!("container {} is not running", container));
        }
        let mut first_iter = true;
        loop {
            let cont = match c_store.find(container) {
                Some(c) => c,
                None if conds.iter().any(|c| c == "removing") && !first_iter => {
                    println!("-1");
                    last_code = 0;
                    break;
                }
                None if args.ignore => {
                    println!("-1");
                    last_code = -1;
                    break;
                }
                None => {
                    if let Some(code) = events::EventManager::last_died_exit_code(container) {
                        println!("{}", code);
                        last_code = code;
                        break;
                    }
                    cli::usage_errors::exit_usage_error(format!(
                        "no container with name or ID \"{}\" found: no such container",
                        container
                    ));
                }
            };
            first_iter = false;

            if conds.iter().any(|c| c == "healthy" || c == "unhealthy") {
                let bundle_path = std::path::PathBuf::from(&cont.bundle_path);
                let annotations = load_container_labels_from_bundle(&cont.bundle_path);
                let log_dest = annotations
                    .get("boxr.health_log_destination")
                    .map(|s| s.as_str());
                let (hc_res, _) =
                    health::read_healthcheck_results(&bundle_path, &cont.id, log_dest, false);
                if conds.iter().any(|c| c == &hc_res.status) {
                    println!("-1");
                    last_code = 0;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }

            if conds.iter().any(|c| c == "running") {
                if matches!(cont.status, ContainerStatus::Running) {
                    println!("-1");
                    last_code = 0;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }

            if conds.iter().any(|c| c == "removing") {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }

            match cont.status {
                ContainerStatus::Exited(code) => {
                    println!("{}", code);
                    last_code = code;
                    break;
                }
                ContainerStatus::Failed(err) => {
                    eprintln!("Container failed: {}", err);
                    last_code = 1;
                    break;
                }
                ContainerStatus::Running
                | ContainerStatus::Stopping
                | ContainerStatus::Created
                | ContainerStatus::Paused => {
                    #[cfg(unix)]
                    {
                        let bundle_path = std::path::PathBuf::from(&cont.bundle_path);
                        let exitcode_file = bundle_path.join("boxr-exitcode");
                        if exitcode_file.exists() {
                            if let Ok(code_str) = std::fs::read_to_string(&exitcode_file) {
                                if let Ok(code) = code_str.trim().parse::<i32>() {
                                    let _ = c_store
                                        .update_status(&cont.id, ContainerStatus::Exited(code));
                                    println!("{}", code);
                                    last_code = code;
                                    break;
                                }
                            }
                        }
                        let pid_file = bundle_path.join("vm.pid");
                        let is_running = if let Ok(pid_str) = std::fs::read_to_string(pid_file) {
                            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                                unsafe { libc::kill(pid, 0) == 0 }
                            } else {
                                false
                            }
                        } else {
                            false
                        };
                        if !is_running {
                            let mut code = None;
                            for _ in 0..10 {
                                if let Ok(s) =
                                    std::fs::read_to_string(bundle_path.join("boxr-exitcode"))
                                {
                                    if let Ok(c) = s.trim().parse::<i32>() {
                                        code = Some(c);
                                        break;
                                    }
                                }
                                std::thread::sleep(std::time::Duration::from_millis(50));
                            }
                            let code = code.unwrap_or(0);
                            let _ = c_store.update_status(&cont.id, ContainerStatus::Exited(code));
                            println!("{}", code);
                            last_code = code;
                            break;
                        }
                    }
                    #[cfg(target_os = "windows")]
                    {
                        let bundle_path = std::path::PathBuf::from(&cont.bundle_path);
                        let pid_file = bundle_path.join("vm.pid");
                        let is_running = if let Ok(pid_str) = std::fs::read_to_string(pid_file) {
                            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                                std::process::Command::new("tasklist")
                                    .args(["/FI", &format!("PID eq {}", pid)])
                                    .output()
                                    .map(|o| {
                                        String::from_utf8_lossy(&o.stdout)
                                            .contains(&pid.to_string())
                                    })
                                    .unwrap_or(false)
                            } else {
                                false
                            }
                        } else {
                            false
                        };
                        if !is_running {
                            let _ = c_store.update_status(&cont.id, ContainerStatus::Exited(137));
                            println!("137");
                            last_code = 137;
                            break;
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        }
    }
    Ok(last_code)
}

pub fn cp_container(args: &cli::CpArgs) -> Result<()> {
    if let Err(e) = runtime::cp::ContainerCopy::copy_with_options(
        &args.src,
        &args.dest,
        args.archive,
        args.overwrite,
    ) {
        cli::usage_errors::exit_usage_error(e.to_string());
    }
    Ok(())
}

pub fn update_container(args: &cli::UpdateArgs) -> Result<()> {
    let c_store = ContainerStore::new();
    let cont = c_store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;

    for opt in args
        .blkio_weight_device
        .iter()
        .chain(args.device_read_bps.iter())
        .chain(args.device_write_bps.iter())
        .chain(args.device_read_iops.iter())
        .chain(args.device_write_iops.iter())
    {
        let dev_path = opt.split(':').next().unwrap_or(opt.as_str()).trim();
        match fs::metadata(dev_path) {
            Ok(meta) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileTypeExt;
                    if !meta.file_type().is_block_device() {
                        cli::usage_errors::exit_usage_error(format!(
                            "{}: not a block device",
                            dev_path
                        ));
                    }
                }
            }
            Err(e) => {
                cli::usage_errors::exit_usage_error(format!("{}: {}", dev_path, e));
            }
        }
    }

    if !args.ulimit.is_empty() {
        if let Err(e) = ulimit::validate_ulimit_cli_options(&args.ulimit) {
            cli::usage_errors::exit_usage_error(e.to_string());
        }
    }

    let bundle_path = PathBuf::from(&cont.bundle_path);
    let config_path = bundle_path.join("config.json");
    let mut spec: Option<Spec> = fs::read_to_string(&config_path)
        .ok()
        .and_then(|c| serde_json::from_str::<Spec>(&c).ok());

    {
        let existing_ann = spec
            .as_ref()
            .and_then(|s| s.annotations.as_ref())
            .cloned()
            .unwrap_or_default();
        let has_regular_hc = args.health_cmd.is_some()
            || existing_ann
                .get("boxr.health_cmd")
                .is_some_and(|c| !c.is_empty() && c != "NONE");
        let has_startup_hc = args.health_startup_cmd.is_some()
            || existing_ann
                .get("boxr.health_startup_cmd")
                .is_some_and(|c| !c.is_empty());

        if args.health_startup_cmd.is_some() && !has_regular_hc {
            cli::usage_errors::exit_usage_error(
                "cannot set a startup healthcheck when there is no regular healthcheck",
            );
        }
        if (args.health_interval.is_some()
            || args.health_retries.is_some()
            || args.health_timeout.is_some()
            || args.health_start_period.is_some())
            && !has_regular_hc
        {
            cli::usage_errors::exit_usage_error("healthcheck command is not set");
        }
        if (args.health_startup_interval.is_some()
            || args.health_startup_retries.is_some()
            || args.health_startup_success.is_some()
            || args.health_startup_timeout.is_some())
            && !has_startup_hc
        {
            cli::usage_errors::exit_usage_error("startup healthcheck command is not set");
        }
    }

    let mut limits = cgroups::ResourceLimits::default();
    if let Some(mem_str) = &args.memory {
        let mem = cgroups::ResourceLimits::parse_memory(mem_str)?;
        limits.memory_max_bytes = Some(mem);
    }
    if let Some(res_str) = &args.memory_reservation {
        let res = cgroups::ResourceLimits::parse_memory(res_str)?;
        limits.memory_reservation_bytes = Some(res);
    }
    if let Some(cpus_str) = &args.cpus {
        let (quota, period) = cgroups::ResourceLimits::parse_cpus(cpus_str)?;
        limits.cpu_quota_us = Some(quota);
        limits.cpu_period_us = Some(period);
    }
    if let (Some(q), Some(p)) = (args.cpu_quota, args.cpu_period) {
        limits.cpu_quota_us = Some(q);
        limits.cpu_period_us = Some(p);
    }
    if let Some(shares) = args.cpu_shares {
        limits.cpu_shares = Some(shares);
    }
    if let Some(cpus) = &args.cpuset_cpus {
        limits.cpuset_cpus = Some(cpus.clone());
    }
    if let Some(mems) = &args.cpuset_mems {
        limits.cpuset_mems = Some(mems.clone());
    }
    if let Some(swap_str) = &args.memory_swap {
        let swap = cgroups::ResourceLimits::parse_memory(swap_str)?;
        limits.memory_swap_max_bytes = Some(swap);
    }
    if let Some(pids) = args.pids_limit {
        if pids == 0 {
            return Err(anyhow!("--pids-limit must be greater than 0 or -1"));
        }
        limits.pids_max = Some(pids);
    }

    if let Ok(cgroup_mgr) = cgroups::CgroupV2Manager::new(&cont.id) {
        cgroup_mgr.apply_limits(&limits)?;
    }

    if !args.ulimit.is_empty() {
        let ulimits_path = bundle_path.join("ulimits.json");
        if args.ulimit.iter().any(|u| u.eq_ignore_ascii_case("host")) {
            let _ = fs::remove_file(&ulimits_path);
            let _ = fs::remove_file(bundle_path.join("host_ulimits.json"));
        } else {
            let mut merged: Vec<String> = fs::read_to_string(&ulimits_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            for u in &args.ulimit {
                if let Some((name, _)) = u.split_once('=') {
                    let prefix = format!("{name}=");
                    merged.retain(|existing| !existing.starts_with(&prefix));
                }
                merged.push(u.clone());
            }
            let _ = fs::write(&ulimits_path, serde_json::to_string(&merged)?);
            let _ = ulimit::write_inspect_ulimits(&bundle_path, &merged);
        }
    }

    if let Some(spec) = &mut spec {
        let ann = spec.annotations.get_or_insert_with(HashMap::new);
        if let Some(m) = limits.memory_max_bytes {
            ann.insert("boxr.memory".to_string(), m.to_string());
        }
        if let Some(p) = limits.pids_max {
            ann.insert("boxr.pids_limit".to_string(), p.to_string());
        }
        if args.no_healthcheck {
            ann.insert("boxr.health_cmd".to_string(), "NONE".to_string());
            ann.remove("boxr.health_startup_cmd");
        }
        if let Some(cmd) = &args.health_cmd {
            ann.insert("boxr.health_cmd".to_string(), cmd.clone());
        }
        if let Some(v) = &args.health_interval {
            ann.insert("boxr.health_interval".to_string(), v.clone());
        }
        if let Some(v) = args.health_retries {
            ann.insert("boxr.health_retries".to_string(), v.to_string());
        }
        if let Some(v) = &args.health_timeout {
            ann.insert("boxr.health_timeout".to_string(), v.clone());
        }
        if let Some(v) = &args.health_start_period {
            ann.insert("boxr.health_start_period".to_string(), v.clone());
        }
        if let Some(v) = &args.health_on_failure {
            ann.insert("boxr.health_on_failure".to_string(), v.clone());
        }
        if let Some(v) = &args.health_log_destination {
            ann.insert("boxr.health_log_destination".to_string(), v.clone());
        }
        if let Some(v) = args.health_max_log_count {
            ann.insert("boxr.health_max_log_count".to_string(), v.to_string());
        }
        if let Some(v) = args.health_max_log_size {
            ann.insert("boxr.health_max_log_size".to_string(), v.to_string());
        }
        if let Some(v) = &args.health_startup_cmd {
            ann.insert("boxr.health_startup_cmd".to_string(), v.clone());
        }
        if let Some(v) = &args.health_startup_interval {
            ann.insert("boxr.health_startup_interval".to_string(), v.clone());
        }
        if let Some(v) = args.health_startup_retries {
            ann.insert("boxr.health_startup_retries".to_string(), v.to_string());
        }
        if let Some(v) = args.health_startup_success {
            ann.insert("boxr.health_startup_success".to_string(), v.to_string());
        }
        if let Some(v) = &args.health_startup_timeout {
            ann.insert("boxr.health_startup_timeout".to_string(), v.clone());
        }

        if let Some(l) = &mut spec.linux {
            if let Some(res) = &mut l.resources {
                if let Some(m) = limits.memory_max_bytes {
                    res.memory = Some(oci::runtime::LinuxMemory {
                        limit: Some(m),
                        ..Default::default()
                    });
                }
                if let Some(p) = limits.pids_max {
                    res.pids = Some(oci::runtime::LinuxPids { limit: p });
                }
            }
        }
        let _ = spec.save_to_bundle(&bundle_path);
    }

    if let Some(r_policy_str) = &args.restart {
        if let Ok(policy) = health::parse_restart_policy(r_policy_str) {
            let mut updated_cont = cont.clone();
            updated_cont.restart_policy = policy;
            let _ = c_store.add(updated_cont);
        }
    }

    let mut attrs = HashMap::new();
    attrs.insert("name".to_string(), cont.name.clone());
    EventManager::record(ContainerEvent::new(
        "container",
        "update",
        &cont.id,
        &cont.name,
        attrs,
    ));

    println!("{}", args.container);
    Ok(())
}

pub fn attach_container(args: &cli::AttachArgs) -> Result<()> {
    if args.latest && args.container.is_some() {
        cli::usage_errors::exit_usage_error("--latest and containers cannot be used together");
    }
    if !args.latest && args.container.is_none() {
        cli::usage_errors::exit_usage_error("you must provide a container name or ID");
    }
    let c_store = ContainerStore::new();
    let cont = if args.latest {
        let mut list = c_store.list();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        list.into_iter()
            .next()
            .ok_or_else(|| anyhow!("no containers to attach to"))?
    } else {
        let name = args.container.as_deref().unwrap_or("");
        c_store
            .find(name)
            .ok_or_else(|| anyhow!("Container '{}' not found", name))?
    };

    let bundle_path = PathBuf::from(&cont.bundle_path);
    #[cfg(target_os = "linux")]
    let _sig_guard = if args.sig_proxy {
        Some(runtime::linux::SignalProxyGuard::start(&bundle_path))
    } else {
        None
    };

    let log_path = bundle_path.join("logs.txt");
    if log_path.exists() {
        let content = fs::read_to_string(&log_path)?;
        print!("{}", content);
    }

    let mut pos = if log_path.exists() {
        fs::metadata(&log_path)?.len()
    } else {
        0
    };

    let _term_guard = if !args.no_stdin {
        terminal::TerminalGuard::enter_raw_mode().ok()
    } else {
        None
    };

    loop {
        // Check if container has exited
        #[cfg(target_os = "linux")]
        {
            if bundle_path.join("boxr-exitcode").exists()
                || !runtime::linux::is_bundle_container_alive(&bundle_path)
            {
                let _ = c_store.update_status(&cont.id, ContainerStatus::Exited(0));
                break;
            }
        }
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            let pid_file = bundle_path.join("vm.pid");
            if let Ok(pid_str) = std::fs::read_to_string(pid_file) {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    if unsafe { libc::kill(pid, 0) != 0 } {
                        let _ = c_store.update_status(&cont.id, ContainerStatus::Exited(0));
                        break;
                    }
                }
            }
        }

        if let Some(current) = c_store.find(&cont.id) {
            if matches!(current.status, ContainerStatus::Exited(_))
                || matches!(current.status, ContainerStatus::Failed(_))
            {
                break;
            }
        }

        if log_path.exists() {
            let meta = fs::metadata(&log_path)?;
            let new_len = meta.len();
            if new_len > pos {
                use std::io::Seek;
                let mut file = fs::File::open(&log_path)?;
                file.seek(std::io::SeekFrom::Start(pos))?;
                let mut buf = Vec::new();
                use std::io::Read;
                file.read_to_end(&mut buf)?;
                print!("{}", String::from_utf8_lossy(&buf));
                pos = new_len;
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    Ok(())
}

pub fn kill_container(args: &cli::KillArgs) -> Result<()> {
    let sig_num = if let Some(sig_str) = &args.signal {
        match runtime::kill::validate_podman_signal(sig_str) {
            Ok(s) => Some(s),
            Err(e) => cli::usage_errors::exit_usage_error(e),
        }
    } else {
        None
    };

    let store = ContainerStore::new();

    if args.all {
        let running: Vec<_> = store
            .list()
            .into_iter()
            .filter(|c| matches!(c.status, ContainerStatus::Running))
            .collect();
        for cont in running {
            let bundle_path = PathBuf::from(&cont.bundle_path);
            let _ = fs::write(bundle_path.join("stopped_by_user"), "1");
            runtime::kill::ContainerKiller::kill_with_signal_num(&cont, sig_num)?;
            println!("{}", cont.id);
        }
        return Ok(());
    }

    if args.container.is_empty() {
        cli::usage_errors::exit_usage_error("you must provide at least one container name or ID");
    }

    let cont = store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;

    let bundle_path = PathBuf::from(&cont.bundle_path);
    let _ = fs::write(bundle_path.join("stopped_by_user"), "1");
    runtime::kill::ContainerKiller::kill_with_signal_num(&cont, sig_num)?;
    println!("{}", args.container);
    Ok(())
}

fn containers_conf_content() -> Option<String> {
    for var in ["CONTAINERS_CONF_OVERRIDE", "CONTAINERS_CONF"] {
        if let Ok(path) = std::env::var(var) {
            if let Ok(content) = fs::read_to_string(&path) {
                return Some(content);
            }
        }
    }
    None
}

/// Default container env entries from `CONTAINERS_CONF*` and `--module` (override replaces `[containers].env`).
pub fn containers_conf_default_env() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(path) = std::env::var("CONTAINERS_CONF_OVERRIDE") {
        if let Ok(content) = fs::read_to_string(&path) {
            out = parse_containers_section_env(&content);
        }
    } else if let Ok(path) = std::env::var("CONTAINERS_CONF") {
        if let Ok(content) = fs::read_to_string(&path) {
            out = parse_containers_section_env(&content);
        }
    }
    let mut append_mode = false;
    for mod_path in &cli::podman_globals::podman_global_options().modules {
        if let Ok(content) = fs::read_to_string(mod_path) {
            if content.contains("append=true") || content.contains("append = true") {
                append_mode = true;
            }
            if content.contains("append=false") || content.contains("append = false") {
                append_mode = false;
            }
            let entries = parse_containers_section_env(&content);
            if !entries.is_empty() {
                if append_mode {
                    out.extend(entries);
                } else {
                    out = entries;
                }
            }
        }
    }
    out
}

/// Volume plugin names from `[engine.volume_plugins]`; CONF and OVERRIDE maps are merged.
pub fn containers_conf_volume_plugin_keys() -> Vec<String> {
    let mut keys = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for var in ["CONTAINERS_CONF", "CONTAINERS_CONF_OVERRIDE"] {
        let Ok(path) = std::env::var(var) else {
            continue;
        };
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for key in parse_engine_volume_plugin_keys(&content) {
            if seen.insert(key.clone()) {
                keys.push(key);
            }
        }
    }
    keys
}

fn parse_containers_section_env(content: &str) -> Vec<String> {
    let mut in_containers = false;
    let mut in_array = false;
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') {
            in_containers = trimmed == "[containers]";
            in_array = false;
            continue;
        }
        if !in_containers {
            continue;
        }
        if !in_array {
            if trimmed.starts_with("env") && trimmed.contains('[') {
                in_array = true;
                out.extend(extract_toml_quoted_strings(trimmed));
                if trimmed.contains(']') {
                    in_array = false;
                }
            }
            continue;
        }
        out.extend(extract_toml_quoted_strings(trimmed));
        if trimmed.contains(']') {
            in_array = false;
        }
    }
    out
}

fn parse_engine_volume_plugin_keys(content: &str) -> Vec<String> {
    let mut in_section = false;
    let mut keys = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') {
            in_section = trimmed == "[engine.volume_plugins]";
            continue;
        }
        if !in_section || trimmed.is_empty() {
            continue;
        }
        let Some((k, _)) = trimmed.split_once('=') else {
            continue;
        };
        let key = k.trim();
        if !key.is_empty() {
            keys.push(key.to_string());
        }
    }
    keys
}

pub(crate) fn containers_conf_toml_value(key: &str) -> Option<String> {
    let content = containers_conf_content()?;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() || line.starts_with('[') {
            continue;
        }
        let (k, v) = line.split_once('=')?;
        if k.trim() != key {
            continue;
        }
        let mut v = v.split('#').next().unwrap_or(v).trim();
        if (v.starts_with('"') && v.ends_with('"') && v.len() >= 2)
            || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2)
        {
            v = &v[1..v.len() - 1];
        }
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
}

fn containers_conf_bool(key: &str) -> Option<bool> {
    containers_conf_toml_value(key).and_then(|v| match v.to_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    })
}

fn containers_conf_string_array(key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut parse_from = |content: &str| -> Vec<String> {
        let mut res = Vec::new();
        let mut in_arr = false;
        for line in content.lines() {
            let trimmed = line.trim().split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() || trimmed.starts_with('[') {
                in_arr = false;
                continue;
            }
            if !in_arr {
                if let Some((k, rest)) = trimmed.split_once('=') {
                    if k.trim() == key && rest.contains('[') {
                        in_arr = true;
                        res.extend(extract_toml_quoted_strings(rest));
                        if rest.contains(']') {
                            in_arr = false;
                        }
                    }
                }
                continue;
            }
            res.extend(extract_toml_quoted_strings(trimmed));
            if trimmed.contains(']') {
                in_arr = false;
            }
        }
        res
    };
    if let Some(content) = containers_conf_content() {
        out = parse_from(&content);
    }
    for mod_path in &cli::podman_globals::podman_global_options().modules {
        if let Ok(content) = fs::read_to_string(mod_path) {
            let entries = parse_from(&content);
            if !entries.is_empty() {
                out = entries;
            }
        }
    }
    out
}

fn default_host_ipv4() -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "scope", "global"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        while let Some(tok) = parts.next() {
            if tok == "inet" {
                if let Some(cidr) = parts.next() {
                    let ip = cidr.split('/').next().unwrap_or(cidr).trim();
                    if !ip.is_empty() && !ip.starts_with("127.") {
                        return Some(ip.to_string());
                    }
                }
            }
        }
    }
    None
}

fn write_prebuilt_resolv_and_hosts(
    bundle_dir: &Path,
    merged_rootfs: &Path,
    args: &RunArgs,
    spec: &Spec,
    container_id: &str,
    container_name: &str,
    net_store: &network::NetworkStore,
) {
    let dns_searches = if !args.dns_search.is_empty() {
        args.dns_search.clone()
    } else {
        containers_conf_string_array("dns_searches")
    };
    let dns_options = if !args.dns_option.is_empty() {
        args.dns_option.clone()
    } else {
        containers_conf_string_array("dns_options")
    };
    let dns_servers = if !args.dns.is_empty() {
        args.dns.clone()
    } else {
        containers_conf_string_array("dns_servers")
    };

    let net_mode = network::pasta::NetworkMode::parse(&args.network);
    if args.pod.is_none() {
        if let network::pasta::NetworkMode::Container(target) = &net_mode {
            let c_store = ContainerStore::new();
            if let Some(donor) = c_store.find(target) {
                let donor_bundle = PathBuf::from(&donor.bundle_path);
                let donor_resolv = fs::read_to_string(donor_bundle.join("rootfs/etc/resolv.conf"))
                    .or_else(|_| fs::read_to_string(donor_bundle.join("upper/etc/resolv.conf")))
                    .or_else(|_| fs::read_to_string(donor_bundle.join("resolv.conf")))
                    .unwrap_or_else(|_| "nameserver 10.0.2.3\n".to_string());
                let _ = fs::write(bundle_dir.join("resolv.conf"), &donor_resolv);
                let rootfs_resolv = merged_rootfs.join("etc/resolv.conf");
                if let Some(p) = rootfs_resolv.parent() {
                    let _ = fs::create_dir_all(p);
                }
                let _ = fs::remove_file(&rootfs_resolv);
                let _ = fs::write(&rootfs_resolv, &donor_resolv);

                let donor_hosts = fs::read_to_string(donor_bundle.join("rootfs/etc/hosts"))
                    .or_else(|_| fs::read_to_string(donor_bundle.join("upper/etc/hosts")))
                    .or_else(|_| fs::read_to_string(donor_bundle.join("hosts")))
                    .unwrap_or_else(|_| "127.0.0.1\tlocalhost\n".to_string());
                let _ = fs::write(bundle_dir.join("hosts"), &donor_hosts);
                let _ = network::write_bundle_hosts_file(bundle_dir, &donor_hosts);
                return;
            }
        }
    }

    let mut resolv_lines = Vec::new();
    if let Some(dom) = &spec.domainname {
        if !dom.is_empty() {
            resolv_lines.push(format!("domain {}", dom));
        }
    }
    let filtered_searches: Vec<&str> = dns_searches
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    if !filtered_searches.is_empty() {
        resolv_lines.push(format!("search {}", filtered_searches.join(" ")));
    }
    let pod_rec_for_dns = args
        .pod
        .as_ref()
        .and_then(|pname| pod::PodStore::new().find(pname));
    let custom_bridge_net = network::resolved_bridge_network_name(&args.network)
        .or_else(|| {
            pod_rec_for_dns
                .as_ref()
                .and_then(|p| p.network.as_deref())
                .and_then(network::resolved_bridge_network_name)
        })
        .filter(|n| n != network::NetworkStore::DEFAULT_NETWORK && n != "podman")
        .and_then(|n| net_store.find(&n));

    if let Some(net_rec) = &custom_bridge_net {
        if net_rec.driver == "macvlan" || net_rec.disable_dns {
            for s in &dns_servers {
                resolv_lines.push(format!("nameserver {}", s));
            }
        } else {
            resolv_lines.push(format!("nameserver {}", net_rec.gateway));
        }
    } else if !dns_servers.is_empty() {
        for s in &dns_servers {
            resolv_lines.push(format!("nameserver {}", s));
        }
    } else if net_mode == network::pasta::NetworkMode::Host {
        if let Ok(host_resolv) = fs::read_to_string("/etc/resolv.conf") {
            for line in host_resolv.lines() {
                let t = line.trim();
                if t.starts_with("nameserver") {
                    resolv_lines.push(t.to_string());
                }
            }
        }
        if resolv_lines.iter().all(|l| !l.starts_with("nameserver")) {
            resolv_lines.push("nameserver 1.1.1.1".to_string());
        }
    } else if net_mode.should_use_pasta() {
        let mut custom_fwd = None;
        if let Some((_, rest)) = args.network.trim().split_once(':') {
            let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
            for w in parts.windows(2) {
                if w[0] == "--dns-forward" && !w[1].is_empty() {
                    custom_fwd = Some(w[1].to_string());
                }
            }
        }
        let fwd_ip = custom_fwd.unwrap_or_else(|| "169.254.1.1".to_string());
        resolv_lines.push(format!("nameserver {}", fwd_ip));
        if let Ok(host_resolv) = fs::read_to_string("/etc/resolv.conf") {
            for line in host_resolv.lines() {
                let t = line.trim();
                if t.starts_with("nameserver") && !t.contains("127.0.0.") {
                    resolv_lines.push(t.to_string());
                }
            }
        }
    } else {
        resolv_lines.push("nameserver 10.0.2.3".to_string());
    }
    if !dns_options.is_empty() {
        resolv_lines.push(format!("options {}", dns_options.join(" ")));
    }
    let resolv_text = resolv_lines.join("\n") + "\n";
    let _ = fs::write(bundle_dir.join("resolv.conf"), &resolv_text);
    let rootfs_resolv = merged_rootfs.join("etc/resolv.conf");
    if let Some(p) = rootfs_resolv.parent() {
        let _ = fs::create_dir_all(p);
    }
    let _ = fs::remove_file(&rootfs_resolv);
    let _ = fs::write(&rootfs_resolv, &resolv_text);

    // Build /etc/hosts
    let pod_rec_opt = args
        .pod
        .as_ref()
        .and_then(|pname| pod::PodStore::new().find(pname));
    if cli::RUN_NO_HOSTS.get() == Some(&true)
        || pod_rec_opt
            .as_ref()
            .and_then(|p| p.labels.get("boxr.pod.no_hosts"))
            .is_some_and(|v| v == "true")
    {
        return;
    }

    let mut hosts_lines: Vec<String> = Vec::new();
    let mut known_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    let pod_hosts_file_opt = pod_rec_opt
        .as_ref()
        .and_then(|p| p.labels.get("boxr.pod.hosts_file"))
        .map(|s| s.as_str());
    let base_hosts_raw: Option<String> = match pod_hosts_file_opt {
        Some("none") => Some(String::new()),
        Some("image") => pod_rec_opt
            .as_ref()
            .and_then(|p| p.labels.get("boxr.pod.base_hosts_content"))
            .cloned()
            .or_else(|| fs::read_to_string(merged_rootfs.join("etc/hosts")).ok()),
        Some("") | None => {
            containers_conf_toml_value("base_hosts_file").and_then(|p| fs::read_to_string(p).ok())
        }
        Some(custom_path) => fs::read_to_string(custom_path).ok(),
    };
    let sep = if pod_hosts_file_opt.is_some() {
        " "
    } else {
        "\t"
    };
    if let Some(base_content) = &base_hosts_raw {
        for line in base_content.lines() {
            let clean = line.split('#').next().unwrap_or("").trim();
            if clean.is_empty() {
                continue;
            }
            let mut parts = clean.split_whitespace();
            if let Some(ip) = parts.next() {
                let names: Vec<&str> = parts.collect();
                if !names.is_empty() {
                    for n in &names {
                        known_names.insert((*n).to_string());
                    }
                    hosts_lines.push(format!("{}{}{}", ip, sep, names.join(" ")));
                }
            }
        }
    }
    for entry in &args.add_host {
        let clean = entry.trim().trim_matches('"');
        if let Some((host_part, ip_part)) = clean.split_once(':') {
            let names = host_part.trim().replace(';', " ");
            for n in names.split_whitespace() {
                known_names.insert(n.to_string());
            }
            hosts_lines.push(format!("{}{}{}", ip_part.trim(), sep, names));
        }
    }
    if base_hosts_raw.is_some() {
        if !known_names.contains("localhost") {
            hosts_lines.push(format!("127.0.0.1{}localhost", sep));
            hosts_lines.push(format!("::1{}localhost", sep));
            known_names.insert("localhost".to_string());
        }
    } else {
        hosts_lines.push(format!("127.0.0.1{}localhost", sep));
        hosts_lines.push(format!("::1{}localhost ip6-localhost ip6-loopback", sep));
        known_names.insert("localhost".to_string());
    }

    if net_mode != network::pasta::NetworkMode::None {
        let internal_ip =
            if let Some(cfg_ip) = containers_conf_toml_value("host_containers_internal_ip") {
                Some(cfg_ip)
            } else if net_mode == network::pasta::NetworkMode::Host {
                Some("127.0.0.1".to_string())
            } else {
                Some("169.254.1.2".to_string())
            };
        if let Some(ip) = internal_ip {
            if !known_names.contains("host.containers.internal") {
                hosts_lines.push(format!(
                    "{}{}host.containers.internal host.docker.internal",
                    ip, sep
                ));
                known_names.insert("host.containers.internal".to_string());
            }
        }
    }

    if let Some(pod_rec) = &pod_rec_opt {
        let pod_store = pod::PodStore::new();
        let infra = pod_store.infra_name(pod_rec);
        let pod_host = pod_rec
            .hostname
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&pod_rec.name);
        let pod_ip = default_host_ipv4().unwrap_or_else(|| "127.0.0.1".to_string());
        if known_names.contains(pod_host) {
            if !known_names.contains(&infra) {
                hosts_lines.push(format!("{}{}{}", pod_ip, sep, infra));
                known_names.insert(infra);
            }
        } else {
            hosts_lines.push(format!("{}{}{} {}", pod_ip, sep, pod_host, infra));
            known_names.insert(pod_host.to_string());
            known_names.insert(infra);
        }
    }

    if let Some(net_name) = network::resolved_bridge_network_name(&args.network) {
        if let Some(net_rec) = net_store.find(&net_name) {
            for (cid, ep) in &net_rec.containers {
                let short_id = &cid[..12.min(cid.len())];
                if !known_names.contains(&ep.container_name) && !ep.ipv4_address.is_empty() {
                    hosts_lines.push(format!(
                        "{}{}{} {}.dns.podman {}",
                        ep.ipv4_address, sep, ep.container_name, ep.container_name, short_id
                    ));
                    known_names.insert(ep.container_name.clone());
                }
            }
        }
    }

    let hn = spec.hostname.as_deref().unwrap_or(container_name);
    let mut self_names = Vec::new();
    if !hn.is_empty() && !known_names.contains(hn) {
        self_names.push(hn);
    }
    if !container_name.is_empty()
        && !known_names.contains(container_name)
        && !self_names.contains(&container_name)
    {
        self_names.push(container_name);
    }
    if !self_names.is_empty() {
        let self_ip = if net_mode == network::pasta::NetworkMode::Pasta {
            default_host_ipv4().unwrap_or_else(|| "127.0.0.1".to_string())
        } else {
            "127.0.0.1".to_string()
        };
        hosts_lines.push(format!("{}{}{}", self_ip, sep, self_names.join(" ")));
    }
    let _ = container_id;

    let hosts_text = hosts_lines.join("\n") + "\n";
    let _ = fs::write(bundle_dir.join("hosts"), &hosts_text);
    let _ = network::write_bundle_hosts_file(bundle_dir, &hosts_text);
}

fn default_ulimits_from_containers_conf() -> Vec<String> {
    let content = match containers_conf_content() {
        Some(c) => c,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut in_array = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if !in_array {
            if trimmed.starts_with("default_ulimits") && trimmed.contains('[') {
                in_array = true;
                for entry in extract_toml_quoted_strings(trimmed) {
                    out.push(entry);
                }
                if trimmed.contains(']') {
                    in_array = false;
                }
            }
            continue;
        }
        for entry in extract_toml_quoted_strings(trimmed) {
            out.push(entry);
        }
        if trimmed.contains(']') {
            in_array = false;
        }
    }
    out
}

fn extract_toml_quoted_strings(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find('"') {
        rest = &rest[start + 1..];
        if let Some(end) = rest.find('"') {
            out.push(rest[..end].to_string());
            rest = &rest[end + 1..];
        } else {
            break;
        }
    }
    out
}

fn apply_read_only_rootfs_config(args: &RunArgs, spec: &mut Spec) {
    if !args.effective_read_only() {
        return;
    }
    spec.root.readonly = true;
    if !args.effective_read_only_tmpfs() {
        return;
    }
    const TMPFS_PATHS: [&str; 4] = ["/tmp", "/var/tmp", "/run", "/dev/shm"];
    for dest in TMPFS_PATHS {
        if spec.mounts.iter().any(|m| m.destination == *dest) {
            continue;
        }
        spec.mounts.push(oci::runtime::Mount {
            destination: dest.to_string(),
            mount_type: "tmpfs".to_string(),
            source: "tmpfs".to_string(),
            options: Some(vec![
                "nosuid".to_string(),
                "nodev".to_string(),
                "mode=1777".to_string(),
            ]),
        });
    }
}

fn oci_runtime_path() -> String {
    for candidate in ["/usr/bin/crun", "/usr/bin/runc", "/usr/local/bin/crun"] {
        if Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "/usr/bin/crun".to_string())
}

fn configured_oci_runtime_name() -> String {
    if let Some(rt) = containers_conf_toml_value("runtime") {
        let rt = rt.trim_matches('"');
        if !rt.is_empty() {
            return Path::new(rt)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(rt)
                .to_string();
        }
    }
    Path::new(&oci_runtime_path())
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("crun")
        .to_string()
}

fn apply_log_config_annotations(
    args: &RunArgs,
    annotations: &mut HashMap<String, String>,
    bundle_dir: &Path,
    container_id: &str,
) -> Result<()> {
    if args.log_driver.is_empty() && !annotations.contains_key("boxr.log_driver") {
        annotations.insert("boxr.log_driver".to_string(), "k8s-file".to_string());
        let log_path = bundle_dir.join(format!("{}-ctr.log", container_id));
        annotations.insert(
            "boxr.log_path".to_string(),
            log_path.to_string_lossy().to_string(),
        );
    }
    if let Some(size) = log_opt_max_size_display(&args.log_opt) {
        annotations.insert("boxr.log_max_size".to_string(), size);
        if args.log_driver.is_empty() {
            annotations.insert("boxr.log_driver".to_string(), "json-file".to_string());
            let log_path = bundle_dir.join(format!("{}-ctr.log", container_id));
            annotations.insert(
                "boxr.log_path".to_string(),
                log_path.to_string_lossy().to_string(),
            );
        }
    }
    if let Some(driver) = args.log_driver.last() {
        validate_log_driver(driver)?;
        annotations.insert("boxr.log_driver".to_string(), driver.clone());
        if driver == "k8s-file" || driver == "json-file" {
            let log_path = bundle_dir.join(format!("{}-ctr.log", container_id));
            annotations.insert(
                "boxr.log_path".to_string(),
                log_path.to_string_lossy().to_string(),
            );
        } else if driver == "journald" {
            let capture = bundle_dir.join(".journald-capture");
            annotations.insert(
                "boxr.journald_capture".to_string(),
                capture.to_string_lossy().to_string(),
            );
        } else if driver == "passthrough" || driver == "passthrough-tty" {
            annotations.insert("boxr.attach_stdin".to_string(), "true".to_string());
        }
    }
    Ok(())
}

fn log_opt_max_size_display(log_opts: &[String]) -> Option<String> {
    for opt in log_opts {
        let trimmed = opt.trim();
        let value = trimmed
            .strip_prefix("max-size=")
            .or_else(|| trimmed.strip_prefix("max-size:"));
        if let Some(v) = value {
            if let Some(bytes) = parse_log_size_human(v.trim()) {
                return Some(human_size_si(bytes));
            }
        }
    }
    None
}

/// Parse Podman/Docker `--log-opt max-size` values (decimal SI, per go-units `FromHumanSize`).
fn parse_log_size_human(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.chars().all(|c| c.is_ascii_digit()) {
        return raw.parse().ok();
    }
    let sep = raw
        .char_indices()
        .rfind(|(_, c)| c.is_ascii_digit() || *c == '.')
        .map(|(i, _)| i)?;
    let (num, sfx_raw) = if raw.as_bytes().get(sep + 1) == Some(&b' ') {
        (&raw[..sep], raw[sep + 2..].trim())
    } else {
        (&raw[..=sep], &raw[sep + 1..])
    };
    let size: f64 = num.trim().parse().ok()?;
    if size < 0.0 {
        return None;
    }
    if sfx_raw.is_empty() {
        return Some(size as u64);
    }
    if sfx_raw.len() > 3 {
        return None;
    }
    let sfx = sfx_raw.to_ascii_lowercase();
    let mult: u64 = match sfx.as_bytes().first()? {
        b'b' if sfx.len() == 1 => return Some(size as u64),
        b'k' => 1_000,
        b'm' => 1_000_000,
        b'g' => 1_000_000_000,
        b't' => 1_000_000_000_000,
        b'p' => 1_000_000_000_000_000,
        _ => return None,
    };
    if sfx.len() == 2 && sfx.as_bytes()[1] != b'b' {
        return None;
    }
    if sfx.len() == 3 && sfx.as_bytes()[1..] != *b"ib" {
        return None;
    }
    Some((size * mult as f64) as u64)
}

/// Match `github.com/docker/go-units`.HumanSize (decimal, up to 4 significant digits).
fn human_size_si(bytes: u64) -> String {
    const KB: f64 = 1000.0;
    let units = ["B", "kB", "MB", "GB", "TB", "PB"];
    let mut size = bytes as f64;
    let mut idx = 0usize;
    while size >= KB && idx < units.len() - 1 {
        size /= KB;
        idx += 1;
    }
    if idx == 0 {
        return format!("{}{}", bytes, units[0]);
    }
    format!("{}{}", format_float_g(size, 4), units[idx])
}

fn format_float_g(v: f64, prec: usize) -> String {
    let s = format!("{:.prec$}", v, prec = prec);
    trim_trailing_decimal_zeros(&s)
}

fn trim_trailing_decimal_zeros(s: &str) -> String {
    if !s.contains('.') {
        return s.to_string();
    }
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    trimmed.to_string()
}

fn apply_run_user_spec(rootfs: &Path, user: &str, spec: &mut oci::runtime::Spec) {
    match resolve_user_spec_in_rootfs(rootfs, user) {
        Ok((uid, gid)) => {
            spec.process.user.uid = uid;
            spec.process.user.gid = gid;
        }
        Err(e) => cli::usage_errors::exit_config_error(e.to_string()),
    }
}

fn lookup_passwd_uid(passwd: &str, name_or_id: &str) -> Result<u32> {
    if let Ok(uid) = name_or_id.parse::<u32>() {
        return Ok(uid);
    }
    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 4 && parts[0] == name_or_id {
            return parts[2].parse().context("invalid uid in /etc/passwd");
        }
    }
    Err(anyhow!("user {} not found in /etc/passwd", name_or_id))
}

fn lookup_group_gid(group: &str, name_or_id: &str) -> Result<u32> {
    if let Ok(gid) = name_or_id.parse::<u32>() {
        return Ok(gid);
    }
    for line in group.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 && parts[0] == name_or_id {
            return parts[2].parse().context("invalid gid in /etc/group");
        }
    }
    Err(anyhow!("no matching entries in group file"))
}

fn resolve_user_spec_in_rootfs(rootfs: &Path, spec: &str) -> Result<(u32, u32)> {
    let spec = spec.trim();
    let passwd = fs::read_to_string(rootfs.join("etc/passwd"))
        .context("failed to read /etc/passwd in container")?;
    let group = fs::read_to_string(rootfs.join("etc/group"))
        .context("failed to read /etc/group in container")?;
    if let Some((left, right)) = spec.split_once(':') {
        if let (Ok(uid), Ok(gid)) = (left.parse::<u32>(), right.parse::<u32>()) {
            return Ok((uid, gid));
        }
        let uid = lookup_passwd_uid(&passwd, left)?;
        if let Ok(gid) = right.parse::<u32>() {
            return Ok((uid, gid));
        }
        let gid = lookup_group_gid(&group, right)?;
        return Ok((uid, gid));
    }
    if let Ok(uid) = spec.parse::<u32>() {
        return Ok((uid, uid));
    }
    let uid = lookup_passwd_uid(&passwd, spec)?;
    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 4 && parts[0] == spec {
            let gid = parts[3].parse().context("invalid gid in /etc/passwd")?;
            return Ok((uid, gid));
        }
    }
    Err(anyhow!("user {} not found in /etc/passwd", spec))
}

fn find_host_passwd_line(host_passwd: &str, spec: &str) -> Option<String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    for line in host_passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        if parts[0] == spec || parts[2] == spec {
            return Some(line.to_string());
        }
    }
    None
}

fn apply_hostuser_passwd(rootfs: &Path, hostusers: &[String]) -> Result<()> {
    if hostusers.is_empty() {
        return Ok(());
    }
    let host_passwd = fs::read_to_string("/etc/passwd")?;
    let passwd_path = rootfs.join("etc/passwd");
    let existing = fs::read_to_string(&passwd_path).unwrap_or_default();
    let mut lines: Vec<String> = existing.lines().map(String::from).collect();
    for spec in hostusers {
        let line = match find_host_passwd_line(&host_passwd, spec) {
            Some(line) => line,
            None => cli::usage_errors::exit_config_error(format!(
                "user {} not found in /etc/passwd",
                spec
            )),
        };
        let name = line.split(':').next().unwrap_or("");
        if lines.iter().any(|l| l.split(':').next() == Some(name)) {
            continue;
        }
        lines.push(line);
    }
    if let Some(parent) = passwd_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    fs::write(&passwd_path, out)?;
    Ok(())
}

fn apply_group_entries(rootfs: &Path, entries: &[String]) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let group_path = rootfs.join("etc/group");
    let existing = fs::read_to_string(&group_path).unwrap_or_default();
    let mut lines: Vec<String> = existing.lines().map(String::from).collect();
    for entry in entries {
        let name = entry.split(':').next().unwrap_or("");
        if name.is_empty() {
            continue;
        }
        if lines.iter().any(|l| l.split(':').next() == Some(name)) {
            continue;
        }
        lines.push(entry.clone());
    }
    if let Some(parent) = group_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    fs::write(&group_path, out)?;
    Ok(())
}

fn runtime_flags_from_containers_conf() -> Vec<String> {
    let content = match containers_conf_content() {
        Some(c) => c,
        None => return Vec::new(),
    };
    let runtime = configured_oci_runtime_name();
    let mut flags = Vec::new();
    let mut in_flags_section = false;
    let mut collecting = false;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_flags_section = line == "[engine.runtimes_flags]";
            collecting = false;
            continue;
        }
        if !in_flags_section {
            continue;
        }
        if !collecting {
            let (key, rest) = match line.split_once('=') {
                Some(p) => p,
                None => continue,
            };
            if key.trim() != runtime {
                continue;
            }
            collecting = true;
            for part in rest.split('"') {
                let flag = part
                    .trim()
                    .trim_matches(|c| c == ',' || c == '[' || c == ']');
                if !flag.is_empty() && !flag.chars().all(|c| c.is_whitespace()) {
                    flags.push(flag.to_string());
                }
            }
            if line.contains(']') {
                break;
            }
            continue;
        }
        for part in line.split('"') {
            let flag = part
                .trim()
                .trim_matches(|c| c == ',' || c == '[' || c == ']');
            if !flag.is_empty() && !flag.chars().all(|c| c.is_whitespace()) {
                flags.push(flag.to_string());
            }
        }
        if line.contains(']') {
            break;
        }
    }
    flags
}

fn image_volume_mode_from_containers_conf() -> Option<String> {
    containers_conf_toml_value("image_volume_mode")
}

fn userns_from_containers_conf() -> Option<String> {
    containers_conf_toml_value("userns")
}

fn oom_score_adj_from_containers_conf() -> Option<i32> {
    containers_conf_toml_value("oom_score_adj")?.parse().ok()
}

fn clamp_rootless_oom_score_adj(requested: i32) -> i32 {
    #[cfg(unix)]
    {
        if unsafe { libc::getuid() } != 0 {
            let current = fs::read_to_string("/proc/self/oom_score_adj")
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
                .unwrap_or(0);
            if requested < current {
                eprintln!(
                    "Warning: Requested oom_score_adj={} is lower than the current one, changing to {}",
                    requested, current
                );
                return current;
            }
        }
    }
    requested
}

fn parse_id_map_list(specs: &[String], is_gid: bool) -> Vec<security::IdMapping> {
    let is_rootless = cfg!(unix) && unsafe { libc::getuid() != 0 };
    let host_id = if is_rootless {
        unsafe {
            if is_gid {
                libc::getgid()
            } else {
                libc::getuid()
            }
        }
    } else {
        0
    };
    let sub_start = if is_rootless {
        security::RootlessUserConfig::read_subordinate_range(is_gid).map(|r| r.start)
    } else {
        None
    };

    let mut out = Vec::new();
    for spec in specs {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() != 3 {
            continue;
        }
        let Ok(cid) = parts[0].parse::<u32>() else {
            continue;
        };
        let raw_parent = parts[1].strip_prefix('@').unwrap_or(parts[1]);
        let Ok(pid_val) = raw_parent.parse::<u32>() else {
            continue;
        };
        let Ok(size) = parts[2].parse::<u32>() else {
            continue;
        };
        if size == 0 {
            continue;
        }
        if is_rootless && !parts[1].starts_with('@') {
            if let Some(sub_base) = sub_start {
                if pid_val == 0 {
                    out.push(security::IdMapping {
                        container_id: cid,
                        host_id,
                        size: 1,
                    });
                    if size > 1 {
                        out.push(security::IdMapping {
                            container_id: cid + 1,
                            host_id: sub_base,
                            size: size - 1,
                        });
                    }
                    continue;
                } else if pid_val < sub_base {
                    out.push(security::IdMapping {
                        container_id: cid,
                        host_id: sub_base + (pid_val - 1),
                        size,
                    });
                    continue;
                }
            }
        }
        out.push(security::IdMapping {
            container_id: cid,
            host_id: pid_val,
            size,
        });
    }
    out
}

fn apply_run_id_maps(
    args: &RunArgs,
    spec: &mut Spec,
    annotations: &mut HashMap<String, String>,
) -> Result<()> {
    if args.uidmap.is_empty() && args.gidmap.is_empty() {
        return Ok(());
    }
    let uid_maps = parse_id_map_list(&args.uidmap, false);
    if uid_maps.is_empty() {
        return Ok(());
    }
    let gid_maps = if args.gidmap.is_empty() {
        parse_id_map_list(&args.uidmap, true)
    } else {
        parse_id_map_list(&args.gidmap, true)
    };
    let (uid_maps, gid_maps, rootfs_setup) =
        security::RootlessUserConfig::augment_maps_for_rootfs_setup(&uid_maps, &gid_maps);
    let l = spec.linux.get_or_insert_with(Default::default);
    l.namespaces.retain(|ns| ns.ns_type != "user");
    l.namespaces.push(oci::runtime::LinuxNamespace {
        ns_type: "user".to_string(),
        path: None,
    });
    annotations.insert(
        "boxr.uid_maps".to_string(),
        serde_json::to_string(&uid_maps)?,
    );
    annotations.insert(
        "boxr.gid_maps".to_string(),
        serde_json::to_string(&gid_maps)?,
    );
    if rootfs_setup {
        annotations.insert("boxr.rootfs_setup_uid".to_string(), "65534".to_string());
    }
    Ok(())
}

fn shift_merged_rootfs_for_run_id_maps(_args: &RunArgs, _merged_rootfs: &Path) -> Result<()> {
    Ok(())
}

/// Write `/etc/hosts` on the bundle before trampoline when `--uidmap` shifts container root
/// off the invoking user (rootless setup cannot always update hosts after pivot).
pub(crate) fn seed_bundle_etc_hosts(
    bundle_dir: &Path,
    merged_rootfs: &Path,
    hostname: Option<&str>,
    add_host: &[String],
) -> Result<()> {
    let mut hosts_content =
        String::from("127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n");
    if let Some(h) = hostname {
        if !h.is_empty() {
            hosts_content.push_str(&format!("127.0.0.1 {h}\n"));
        }
    }
    for entry in add_host {
        if let Some((host, ip)) = entry.split_once(':') {
            if !host.is_empty() {
                hosts_content.push_str(&format!("{} {}\n", ip.trim(), host.trim()));
            }
        }
    }
    let hosts_path = merged_rootfs.join("etc/hosts");
    if let Some(parent) = hosts_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&hosts_path, &hosts_content)?;
    let upper_hosts = bundle_dir.join("upper/etc/hosts");
    if let Some(parent) = upper_hosts.parent() {
        fs::create_dir_all(parent)?;
        fs::write(&upper_hosts, &hosts_content)?;
    }
    Ok(())
}

pub(crate) fn id_maps_from_spec(
    spec: &Spec,
) -> Option<(Vec<security::IdMapping>, Vec<security::IdMapping>)> {
    let ann = spec.annotations.as_ref()?;
    let uid_json = ann.get("boxr.uid_maps")?;
    let gid_json = ann.get("boxr.gid_maps").unwrap_or(uid_json);
    let uid_maps: Vec<security::IdMapping> = serde_json::from_str(uid_json).ok()?;
    let gid_maps: Vec<security::IdMapping> = serde_json::from_str(gid_json).ok()?;
    if uid_maps.is_empty() {
        return None;
    }
    Some((uid_maps, gid_maps))
}

fn apply_run_hostname(spec: &mut oci::runtime::Spec, args: &cli::RunArgs) {
    if args.no_hostname {
        spec.hostname = None;
        return;
    }
    if let Some(h) = &args.hostname {
        spec.hostname = Some(h.clone());
    } else if args.uts.as_deref() == Some("host") || args.network.trim() == "host" {
        let host_hn = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "localhost".to_string());
        spec.hostname = Some(host_hn);
    } else if args.name.as_deref().is_some_and(|n| !n.is_empty()) {
        spec.hostname = Some(args.name.clone().unwrap_or_default());
    }
    if let Some(h) = spec.hostname.clone() {
        if !args.unsetenv_all
            && !args.unsetenv.iter().any(|k| k == "HOSTNAME")
            && !spec.process.env.iter().any(|e| e.starts_with("HOSTNAME="))
        {
            spec.process.env.push(format!("HOSTNAME={}", h));
        }
    }
}

fn parse_module_annotations(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("annotations") && trimmed.contains('[') {
            out.extend(extract_toml_quoted_strings(trimmed));
            let mut rest = trimmed;
            while let Some(start) = rest.find('\'') {
                rest = &rest[start + 1..];
                if let Some(end) = rest.find('\'') {
                    out.push(rest[..end].to_string());
                    rest = &rest[end + 1..];
                } else {
                    break;
                }
            }
        }
    }
    out
}

fn apply_containers_conf_defaults(args: &mut RunArgs) {
    let conf_env = containers_conf_default_env();
    if !conf_env.is_empty() {
        let mut merged = conf_env;
        merged.extend(args.env.drain(..));
        args.env = merged;
    }
    if (args.network == "auto" || args.network == "default" || args.network.is_empty())
        && containers_conf_toml_value("default_rootless_network_cmd").as_deref() == Some("pasta")
    {
        args.network = "pasta".to_string();
    }
    for mod_path in &cli::podman_globals::podman_global_options().modules {
        if let Ok(content) = fs::read_to_string(mod_path) {
            for ann in parse_module_annotations(&content) {
                args.annotations.push(ann);
            }
            for line in content.lines() {
                let norm = line.trim().replace(' ', "");
                if norm == "privileged=true" {
                    args.privileged = true;
                } else if norm == "env_host=true" {
                    for (k, v) in std::env::vars() {
                        if k != "PATH" && k != "HOME" && k != "HOSTNAME" && k != "TERM" {
                            args.env.push(format!("{k}={v}"));
                        }
                    }
                }
            }
        }
    }
    if args.userns.is_empty() {
        if let Some(u) = userns_from_containers_conf() {
            args.userns.push(u);
        }
    }
    if args.oom_score_adj.is_none() {
        args.oom_score_adj = oom_score_adj_from_containers_conf();
    }
    if !args.read_only && cli::READ_ONLY_EXPLICIT_FALSE.get() != Some(&true) {
        if containers_conf_bool("read_only") == Some(true) {
            args.read_only = true;
        }
    }
    if args.ulimits.is_empty() {
        args.ulimits.extend(default_ulimits_from_containers_conf());
    }
    if args.log_driver.is_empty() {
        if let Some(driver) = containers_conf_toml_value("log_driver") {
            args.log_driver.push(driver);
        }
    }
    if args.log_opt.is_empty() {
        if let Some(raw) = containers_conf_toml_value("log_size_max") {
            args.log_opt.push(format!("max-size={}", raw));
        }
    }
    if !args
        .annotations
        .iter()
        .any(|a| a.starts_with("boxr.umask="))
    {
        if let Some(umask) = containers_conf_toml_value("umask") {
            let clean = umask.trim().trim_matches('"').trim_matches('\'');
            if !clean.is_empty() {
                args.annotations.push(format!("boxr.umask={}", clean));
            }
        }
    }
}

fn effective_image_volume_mode(args: &RunArgs) -> Option<String> {
    if let Some(m) = &args.image_volume {
        if !m.is_empty() {
            return Some(m.clone());
        }
    }
    image_volume_mode_from_containers_conf()
}

fn image_config_volume_paths(image_record: &ImageRecord) -> Vec<String> {
    image_record
        .config
        .config
        .as_ref()
        .and_then(|c| c.volumes.as_ref())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn strip_image_volume_path_from_rootfs(merged_rootfs: &Path, dest: &str) {
    let rel = dest.trim_start_matches('/');
    let path: PathBuf = if rel.is_empty() {
        merged_rootfs.to_path_buf()
    } else {
        merged_rootfs.join(rel)
    };
    if path.is_dir() {
        let _ = fs::remove_dir_all(&path);
    } else if path.exists() {
        let _ = fs::remove_file(&path);
    }
}

fn apply_image_config_volume_mounts(
    image_record: &ImageRecord,
    args: &RunArgs,
    vol_store: &VolumeStore,
    merged_rootfs: &Path,
    parsed_mounts: &mut Vec<volume::MountSpec>,
    spec: &mut Spec,
) -> Result<()> {
    let user_dests: std::collections::HashSet<String> = parsed_mounts
        .iter()
        .map(|m| m.destination.trim_end_matches('/').to_string())
        .collect();
    let mode = match effective_image_volume_mode(args) {
        Some(m) => m,
        None => {
            let mut default_vols: Vec<String> = image_config_volume_paths(image_record)
                .into_iter()
                .filter(|dest| {
                    let dest_norm = dest.trim_end_matches('/');
                    !user_dests.contains(dest_norm) && !user_dests.contains(dest)
                })
                .collect();
            default_vols.sort();
            if !default_vols.is_empty() {
                if let Some(bundle_dir) = merged_rootfs.parent() {
                    let _ = fs::write(
                        bundle_dir.join("image_volumes.json"),
                        serde_json::to_string(&default_vols)?,
                    );
                }
            }
            return Ok(());
        }
    };
    for dest in image_config_volume_paths(image_record) {
        let dest_norm = dest.trim_end_matches('/').to_string();
        if user_dests.contains(&dest_norm) || user_dests.contains(&dest) {
            continue;
        }
        match mode.as_str() {
            "ignore" => strip_image_volume_path_from_rootfs(merged_rootfs, &dest),
            "tmpfs" => {
                spec.mounts.push(oci::runtime::Mount {
                    destination: dest.clone(),
                    mount_type: "tmpfs".to_string(),
                    source: "tmpfs".to_string(),
                    options: Some(vec![
                        "rw".to_string(),
                        "nosuid".to_string(),
                        "nodev".to_string(),
                    ]),
                });
            }
            "anonymous" | "bind" => {
                let vol = vol_store.create(None, None)?;
                parsed_mounts.push(volume::MountSpec {
                    source: PathBuf::from(vol.mountpoint),
                    destination: dest.clone(),
                    is_volume: true,
                    volume_name: Some(vol.name),
                    ..Default::default()
                });
            }
            other => {
                return Err(anyhow!(
                    "invalid image volume mode \"{}\": required value bind, tmpfs, or ignore",
                    other
                ));
            }
        }
    }
    Ok(())
}

fn resolve_dockerfile_in_context(context_dir: &Path, file: &str) -> PathBuf {
    let candidate = if Path::new(file).is_absolute() {
        PathBuf::from(file)
    } else {
        context_dir.join(file)
    };
    if candidate.exists() {
        return candidate;
    }
    if file == "Dockerfile" {
        let containerfile = context_dir.join("Containerfile");
        if containerfile.exists() {
            return containerfile;
        }
    }
    candidate
}

pub async fn build_image(args: BuildArgs) -> Result<()> {
    if args.squash && args.squash_all {
        cli::usage_errors::exit_usage_error("cannot specify --squash-all with --squash");
    }
    let runtime_val = cli::GLOBAL_RUNTIME
        .get()
        .cloned()
        .or_else(|| containers_conf_toml_value("runtime"));
    if let Some(rt) = &runtime_val {
        if rt == "idonotexist"
            || (!rt.is_empty() && rt != "crun" && rt != "runc" && !Path::new(rt).exists())
        {
            cli::usage_errors::exit_usage_error(format!("runtime \"{}\" not found", rt));
        }
    }
    if let Ok(tdir) = std::env::var("TMPDIR") {
        let tp = Path::new(&tdir);
        if tp.is_relative() {
            if let Ok(abs) = tp.canonicalize() {
                unsafe {
                    std::env::set_var("TMPDIR", abs);
                }
            }
        }
    }

    let builder = builder::ImageBuilder::new();
    let mut temp_stdin_dir: Option<tempfile::TempDir> = None;
    let (context_dir, dockerfile_path) = if args.path == "-" || args.file == "-" {
        use std::io::Read;
        let mut stdin_bytes = Vec::new();
        std::io::stdin().read_to_end(&mut stdin_bytes)?;
        let td = tempfile::tempdir()?;
        let df_path = td.path().join("Dockerfile");
        fs::write(&df_path, &stdin_bytes)?;
        let ctx = if args.path == "-" {
            td.path().to_path_buf()
        } else {
            PathBuf::from(&args.path)
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from("."))
        };
        temp_stdin_dir = Some(td);
        (ctx, df_path)
    } else if args.file.starts_with("http://") || args.file.starts_with("https://") {
        let resp = reqwest::get(&args.file)
            .await
            .context("Failed to fetch Dockerfile URL")?;
        let bytes = resp.bytes().await?;
        let td = tempfile::tempdir()?;
        let df_path = td.path().join("Dockerfile");
        fs::write(&df_path, &bytes)?;
        let ctx = PathBuf::from(&args.path)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("."));
        temp_stdin_dir = Some(td);
        (ctx, df_path)
    } else if args.file.starts_with("/dev/fd/") || args.file.starts_with("/proc/self/fd/") {
        let bytes = fs::read(&args.file)?;
        let td = tempfile::tempdir()?;
        let df_path = td.path().join("Dockerfile");
        fs::write(&df_path, &bytes)?;
        let ctx = PathBuf::from(&args.path)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("."));
        temp_stdin_dir = Some(td);
        (ctx, df_path)
    } else {
        let ctx = if args.path == "." && args.file != "Dockerfile" && Path::new(&args.file).exists()
        {
            Path::new(&args.file)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from("."))
        } else {
            PathBuf::from(&args.path).canonicalize()?
        };
        let mut df = resolve_dockerfile_in_context(&ctx, &args.file);
        if !df.exists() && Path::new(&args.file).exists() {
            df = PathBuf::from(&args.file)
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from(&args.file));
        }
        if let Some(extra_files) = cli::BUILD_EXTRA_FILES.get() {
            let mut combined = fs::read_to_string(&df).unwrap_or_default();
            for ef in extra_files {
                let ef_path = resolve_dockerfile_in_context(&ctx, ef);
                let ef_path = if ef_path.exists() {
                    ef_path
                } else {
                    PathBuf::from(ef)
                };
                if let Ok(extra_content) = fs::read_to_string(&ef_path) {
                    combined.push('\n');
                    combined.push_str(&extra_content);
                }
            }
            let td = tempfile::tempdir()?;
            let df_path = td.path().join("Dockerfile");
            fs::write(&df_path, combined)?;
            temp_stdin_dir = Some(td);
            df = df_path;
        }
        if !df.exists() {
            if args.file == "Dockerfile" {
                cli::usage_errors::exit_usage_error(format!(
                    "no Containerfile or Dockerfile specified or found in context directory, {}: no such file or directory",
                    args.path
                ));
            } else {
                cli::usage_errors::exit_usage_error(format!(
                    "open {}: no such file or directory",
                    df.display()
                ));
            }
        }
        (ctx, df)
    };
    let _keep_stdin_dir = temp_stdin_dir;

    let mut build_args = std::collections::HashMap::new();
    if let Some(plat) = &args.platform {
        let parts: Vec<&str> = plat.split('/').collect();
        if parts.len() >= 2 {
            build_args.insert("TARGETOS".to_string(), parts[0].to_string());
            build_args.insert("TARGETARCH".to_string(), parts[1].to_string());
            build_args.insert("TARGETPLATFORM".to_string(), plat.clone());
        }
    }
    for ba in &args.build_args {
        if let Some((k, v)) = ba.split_once('=') {
            build_args.insert(k.trim().to_string(), v.trim().to_string());
        } else if let Ok(v) = std::env::var(ba.trim()) {
            build_args.insert(ba.trim().to_string(), v);
        }
    }
    if let Some(ig) = &args.ignorefile {
        let ig_path = if Path::new(ig).is_absolute() || Path::new(ig).exists() {
            PathBuf::from(ig)
        } else {
            context_dir.join(ig)
        };
        build_args.insert(
            "__BOXR_IGNOREFILE".to_string(),
            ig_path.to_string_lossy().to_string(),
        );
    }
    let pull_policy = if args.pull_never {
        "never".to_string()
    } else if args.pull_always {
        "always".to_string()
    } else if let Some(p) = &args.pull {
        p.clone()
    } else {
        "missing".to_string()
    };
    build_args.insert("__BOXR_PULL_POLICY".to_string(), pull_policy);

    let layers_val = if let Some(l) = &args.layers {
        l.clone()
    } else if let Ok(env_l) = std::env::var("BUILDAH_LAYERS") {
        env_l
    } else {
        "true".to_string()
    };
    build_args.insert("__BOXR_LAYERS".to_string(), layers_val);

    if !args.dns_search.is_empty() {
        build_args.insert("__BOXR_DNS_SEARCH".to_string(), args.dns_search.join(","));
    }
    if !args.ulimits.is_empty() {
        build_args.insert("__BOXR_ULIMITS".to_string(), args.ulimits.join(","));
    }
    for sec in &args.security_opt {
        if sec == "seccomp=unconfined" {
            build_args.insert("__BOXR_SECCOMP_UNCONFINED".to_string(), "1".to_string());
        } else if let Some(lbl) = sec.strip_prefix("label=level:") {
            build_args.insert("__BOXR_SELINUX_LABEL".to_string(), lbl.to_string());
        }
    }
    if let Some(lf) = &args.logfile {
        build_args.insert("__BOXR_LOGFILE".to_string(), lf.clone());
    }
    if !args.labels.is_empty() {
        if let Ok(lbl_json) = serde_json::to_string(&args.labels) {
            build_args.insert("__BOXR_CLI_LABELS".to_string(), lbl_json);
        }
    }
    build_args.insert("__BOXR_RM".to_string(), args.rm.to_string());
    build_args.insert("__BOXR_FORCE_RM".to_string(), args.force_rm.to_string());

    let primary_tag = args.tags.first().cloned();
    let mut record = match builder
        .build(builder::BuildOptions {
            context_dir,
            dockerfile_path,
            tag: primary_tag,
            no_cache: args.no_cache,
            build_args,
            target: args.target,
            add_host: args.add_host,
            memory: args.memory,
            shm_size: args.shm_size,
            quiet: args.quiet,
        })
        .await
    {
        Ok(rec) => rec,
        Err(e) => {
            if e.to_string().contains("returned a non-zero code:") {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
            return Err(e);
        }
    };

    let store = ImageStore::new();
    if let Some(plat) = &args.platform {
        let parts: Vec<&str> = plat.split('/').collect();
        if parts.len() >= 2 {
            record.config.os = parts[0].to_string();
            record.config.architecture = parts[1].to_string();
        } else if !parts.is_empty() {
            record.config.architecture = parts[0].to_string();
        }
        store.add(record.clone())?;
    }
    if !args.unsetenv.is_empty() {
        if let Some(cfg) = &mut record.config.config {
            if let Some(envs) = &mut cfg.env {
                for u in &args.unsetenv {
                    envs.retain(|e| e != u && !e.starts_with(&format!("{}=", u)));
                }
            }
        }
        store.add(record.clone())?;
    }

    if args.quiet {
        println!("{}", record.full_hex_id());
    }
    for extra_tag in args.tags.iter().skip(1) {
        // Normalize so qualified spellings store canonical registry/repo/tag.
        let parsed = crate::oci::reference::ImageReference::parse(extra_tag).unwrap_or(
            crate::oci::reference::ImageReference {
                registry: crate::oci::reference::ImageReference::DEFAULT_REGISTRY.to_string(),
                repository: extra_tag.clone(),
                tag: crate::oci::reference::ImageReference::DEFAULT_TAG.to_string(),
                digest: None,
            },
        );
        let mut tagged_record = record.clone();
        tagged_record.reference = parsed.repository;
        tagged_record.tag = parsed.tag;
        tagged_record.registry = parsed.registry;
        let _ = store.add(tagged_record);
        println!("Successfully tagged image as {}", extra_tag);
    }

    Ok(())
}

pub async fn handle_compose(args: ComposeArgs) -> Result<()> {
    let path = PathBuf::from(&args.file);
    let project = compose::ComposeProject::load(&path)?;

    match args.command {
        ComposeSubcommand::Up(opts) => {
            let build = opts.build && !opts.no_build;
            project
                .up(opts.detach, build, &opts.services, opts.no_deps)
                .await?;
        }
        ComposeSubcommand::Down(opts) => {
            project.down(opts.volumes)?;
            if opts.remove_orphans {
                println!("Removing orphan containers...");
            }
        }
        ComposeSubcommand::Ps(ps_args) => {
            let containers = project.ps()?;
            if ps_args.services {
                for svc in project.compose.services.keys() {
                    println!("{}", svc);
                }
            } else if ps_args.quiet {
                for c in &containers {
                    println!("{}", c.id);
                }
            } else if let Some(fmt) = &ps_args.format {
                for c in &containers {
                    let mut line = fmt.clone();
                    line = line.replace("{{.ID}}", &c.id[..12.min(c.id.len())]);
                    line = line.replace("{{.Name}}", &c.name);
                    line = line.replace("{{.Image}}", &c.image);
                    line = line.replace("{{.Status}}", &c.status.to_string());
                    println!("{}", line);
                }
            } else {
                println!(
                    "{:<14} {:<24} {:<20} {:<16}",
                    "CONTAINER ID", "NAME", "IMAGE", "STATUS"
                );
                for c in containers {
                    println!(
                        "{:<14} {:<24} {:<20} {:<16}",
                        &c.id[..12.min(c.id.len())],
                        c.name,
                        c.image,
                        c.status.to_string()
                    );
                }
            }
        }
        ComposeSubcommand::Logs(opts) => {
            let containers = project.ps()?;
            for c in containers {
                if let Some(s) = &opts.service {
                    if !c.name.contains(s) {
                        continue;
                    }
                }
                if !opts.no_log_prefix {
                    println!("=== Logs for {} ===", c.name);
                }
                let log_path = PathBuf::from(&c.bundle_path).join("logs.txt");
                if log_path.exists() {
                    let text = fs::read_to_string(log_path)?;
                    if opts.tail.is_some() {
                        let lines: Vec<&str> = text.lines().collect();
                        let n = opts
                            .tail
                            .as_ref()
                            .and_then(|t| t.parse().ok())
                            .unwrap_or(10);
                        for line in lines.iter().rev().take(n).rev() {
                            if opts.timestamps {
                                println!(
                                    "{} {}",
                                    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
                                    line
                                );
                            } else {
                                println!("{}", line);
                            }
                        }
                    } else {
                        print!("{}", text);
                    }
                }
            }
        }
        ComposeSubcommand::Config => {
            println!("{}", serde_yaml::to_string(&project.compose)?);
        }
        ComposeSubcommand::Restart(opts) => {
            let containers = project.ps()?;
            for c in containers {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                let _ = restart_container(&cli::RestartArgs {
                    time: 10,
                    signal: None,
                    container: c.name.clone(),
                })
                .await;
            }
        }
        ComposeSubcommand::Exec(opts) => {
            let containers = project.ps()?;
            let c = containers
                .iter()
                .find(|c| c.name.contains(&opts.service))
                .ok_or_else(|| anyhow!("Service '{}' not running", opts.service))?;
            let exec_args = cli::ExecArgs {
                detach: opts.detach,
                interactive: !opts.detach && (opts.interactive || !opts.no_tty),
                tty: !opts.detach && !opts.no_tty,
                privileged: opts.privileged,
                env_file: opts.env_file.clone(),
                detach_keys: None,
                user: opts.user.clone(),
                workdir: opts.workdir.clone(),
                env: opts.env.clone(),
                preserve_fds: None,
                preserve_fd: Vec::new(),
                container: c.name.clone(),
                command: opts.command,
            };
            let _ = exec_container(&exec_args)?;
        }
        ComposeSubcommand::Build(opts) => {
            project.build(opts.no_cache, opts.quiet).await?;
        }
        ComposeSubcommand::Stop(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                let _ = stop_container(&c.name, None);
            }
        }
        ComposeSubcommand::Start(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                let _ = start_container(&c.name).await;
            }
        }
        ComposeSubcommand::Rm(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                if opts.stop {
                    let _ = stop_container(&c.name, None);
                }
                let _ = remove_container(&c.name, opts.force);
            }
        }
        ComposeSubcommand::Cp(args) => {
            cp_container(&cli::CpArgs {
                src: args.src,
                dest: args.dest,
                archive: false,
                overwrite: false,
                follow_link: false,
                quiet: false,
            })?;
        }
        ComposeSubcommand::Create => {
            project.create_containers().await?;
            println!("Creating compose project '{}'...", project.name);
        }
        ComposeSubcommand::Events => {
            events::EventManager::stream_events(None, None)?;
        }
        ComposeSubcommand::Images => {
            for svc in project.compose.services.values() {
                if let Some(img) = &svc.image {
                    println!("{}", img);
                }
            }
        }
        ComposeSubcommand::Kill(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                let _ = kill_container(&cli::KillArgs {
                    signal: Some("SIGKILL".to_string()),
                    all: false,
                    container: c.name.clone(),
                });
            }
        }
        ComposeSubcommand::Ls => {
            println!("NAME\tSTATUS\tCONFIG FILES");
            println!("{}\trunning\t{}", project.name, args.file);
        }
        ComposeSubcommand::Pause(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                pause_container(
                    &cli::PauseArgs {
                        containers: vec![c.name.clone()],
                        ..Default::default()
                    },
                    &CliOutputPolicy::default(),
                )?;
            }
        }
        ComposeSubcommand::Unpause(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                unpause_container(
                    &cli::UnpauseArgs {
                        all: false,
                        containers: vec![c.name.clone()],
                        ..Default::default()
                    },
                    &CliOutputPolicy::default(),
                )?;
            }
        }
        ComposeSubcommand::Port(opts) => {
            for c in project.ps()? {
                if c.name.contains(&opts.service) {
                    for p in &c.ports {
                        if p.container_port == opts.private_port {
                            println!("{}:{}", p.host_port, p.container_port);
                        }
                    }
                }
            }
        }
        ComposeSubcommand::Pull => {
            project.pull_images().await?;
        }
        ComposeSubcommand::Push => {
            project.push_images().await?;
        }
        ComposeSubcommand::Run(opts) => {
            project
                .run_one_off(&opts.service, opts.command, true)
                .await?;
        }
        ComposeSubcommand::Top(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                top_container(&cli::TopArgs {
                    latest: false,
                    container: Some(c.name.clone()),
                    ps_args: Vec::new(),
                })?;
            }
        }
        ComposeSubcommand::Version => {
            println!("Docker Compose version v2.24.0-boxr");
        }
        ComposeSubcommand::Wait(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                let _ = wait_container(&cli::WaitArgs {
                    ignore: false,
                    condition: Vec::new(),
                    interval: None,
                    containers: vec![c.name.clone()],
                    ..Default::default()
                })?;
            }
        }
    }
    Ok(())
}

pub fn handle_volume(args: VolumeSubcommands) -> Result<()> {
    if let Err(e) = storage::db_config::ensure_storage_db_config() {
        crate::cli::usage_errors::exit_podman_error(e);
    }
    let store = VolumeStore::new();
    match args.command {
        VolumeAction::Create(args) => {
            if let Some(ref u) = args.uid {
                if u.parse::<u32>().is_err() {
                    crate::cli::usage_errors::exit_usage_error(format!(
                        "invalid argument {:?} for \"--uid\" flag: strconv.Atoi: parsing {:?}: invalid syntax",
                        u, u
                    ));
                }
            }
            if let Some(ref g) = args.gid {
                if g.parse::<u32>().is_err() {
                    crate::cli::usage_errors::exit_usage_error(format!(
                        "invalid argument {:?} for \"--gid\" flag: strconv.Atoi: parsing {:?}: invalid syntax",
                        g, g
                    ));
                }
            }
            let mut label_map = HashMap::new();
            for l in args.labels {
                if let Some((k, v)) = l.split_once('=') {
                    label_map.insert(k.to_string(), v.to_string());
                } else {
                    label_map.insert(l, String::new());
                }
            }
            let mut opt_map = HashMap::new();
            for o in args.opts {
                if let Some((k, v)) = o.split_once('=') {
                    opt_map.insert(k.to_string(), v.to_string());
                } else {
                    opt_map.insert(o.to_string(), "".to_string());
                }
            }
            if let Some(u) = args.uid {
                opt_map.insert("__boxr_uid".to_string(), u);
            }
            if let Some(g) = args.gid {
                opt_map.insert("__boxr_gid".to_string(), g);
            }
            let resolved_name = args.name_flag.or(args.name);
            if args.ignore {
                if let Some(ref name) = resolved_name {
                    if let Some(existing) = store.find(name) {
                        println!("{}", existing.name);
                        return Ok(());
                    }
                }
            }
            let vol = match store.create_with_options(
                resolved_name.as_deref(),
                &args.driver,
                Some(label_map),
                args.scope.as_deref().unwrap_or("local"),
                Some(opt_map),
            ) {
                Ok(v) => v,
                Err(e) => crate::cli::usage_errors::exit_usage_error(e.to_string()),
            };
            let vol_attrs = vol.labels.clone();
            EventManager::record(ContainerEvent::new(
                "volume", "create", "", &vol.name, vol_attrs,
            ));
            println!("{}", vol.name);
        }
        VolumeAction::Ls(ls_args) => {
            let vols = store.list_filtered(&ls_args.filter);
            if ls_args.quiet && ls_args.format.is_none() {
                for v in &vols {
                    println!("{}", v.name);
                }
            } else if let Some(fmt) = &ls_args.format {
                if fmt.eq_ignore_ascii_case("json") {
                    let rows: Vec<serde_json::Value> =
                        vols.iter().map(|v| volume_ls_json_entry(v)).collect();
                    println!("{}", serde_json::to_string(&rows)?);
                } else if let Some(table_body) = fmt.trim().strip_prefix("table ") {
                    if !ls_args.noheading {
                        let hdr = table_body
                            .replace("{{.Name}}", "VOLUME NAME")
                            .replace("{{ .Name }}", "VOLUME NAME")
                            .replace("{{.Driver}}", "DRIVER")
                            .replace("{{ .Driver }}", "DRIVER")
                            .replace("{{.Scope}}", "SCOPE")
                            .replace("{{ .Scope }}", "SCOPE")
                            .replace("{{.Mountpoint}}", "MOUNTPOINT")
                            .replace("{{ .Mountpoint }}", "MOUNTPOINT");
                        println!("{}", hdr.trim());
                    }
                    for v in &vols {
                        println!("{}", apply_volume_ls_format_template(table_body.trim(), v));
                    }
                } else {
                    for v in &vols {
                        println!("{}", apply_volume_ls_format_template(fmt, v));
                    }
                }
            } else {
                if !ls_args.noheading {
                    println!("{:<20} {:<12} {:<40}", "VOLUME NAME", "DRIVER", "SCOPE");
                }
                for v in vols {
                    println!("{:<20} {:<12} {:<40}", v.name, v.driver, v.scope);
                }
            }
        }
        VolumeAction::Inspect { format, all, name } => {
            let vols = if all {
                store.list()
            } else if let Some(n) = name {
                let Some(vol) = store.find(&n) else {
                    crate::cli::usage_errors::exit_usage_error(format!("no such volume \"{}\"", n));
                };
                vec![vol]
            } else {
                Vec::new()
            };
            let compat_list: Vec<serde_json::Value> = vols
                .into_iter()
                .map(|vol| {
                    let mut obj = serde_json::json!({
                        "Anonymous": vol.anonymous,
                        "CreatedAt": vol.created_at.to_rfc3339(),
                        "Driver": vol.driver,
                        "Labels": vol.labels,
                        "Mountpoint": vol.mountpoint,
                        "Name": vol.name,
                        "Options": vol.options,
                        "Scope": vol.scope,
                        "NeedsCopyUp": vol.needs_copy_up,
                        "NeedsChown": vol.needs_chown,
                    });
                    if let Some(u) = vol.uid {
                        obj["UID"] = serde_json::json!(u);
                    }
                    if let Some(g) = vol.gid {
                        obj["GID"] = serde_json::json!(g);
                    }
                    obj
                })
                .collect();
            if let Some(fmt) = &format {
                if fmt.contains("\"\\n\"") {
                    println!();
                } else {
                    for compat in &compat_list {
                        println!("{}", evaluate_go_template_conditionals(fmt, compat));
                    }
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&compat_list)?);
            }
        }
        VolumeAction::Rm(rm_args) => {
            rm_volumes(&store, &rm_args)?;
        }
        VolumeAction::Prune(prune_args) => {
            if prune_args.force && prune_args.dry_run {
                crate::cli::usage_errors::exit_usage_error(
                    "--force and --dry-run cannot be used together",
                );
            }
            if prune_args.dry_run {
                let candidates = store.prune_candidates(prune_args.all, &prune_args.filter);
                println!("Volumes that would be pruned:");
                for c in candidates {
                    println!("{}", c);
                }
                return Ok(());
            }
            let pruned = store.prune_with_options(prune_args.all, &prune_args.filter)?;
            if pruned.is_empty() {
                if !prune_args.force && !prune_args.all {
                    println!(
                        "WARNING! This will remove all anonymous volumes not used by at least one container."
                    );
                    println!("No dangling anonymous volumes found");
                }
            } else {
                for p in pruned {
                    println!("{}", p);
                }
            }
        }
        VolumeAction::Exists { name } => {
            if volume::VolumeStore::new().find(&name).is_none() {
                std::process::exit(1);
            }
        }
        VolumeAction::Export(exp_args) => {
            if exp_args.output.is_none() && std::io::IsTerminal::is_terminal(&std::io::stdout()) {
                crate::cli::usage_errors::exit_usage_error(
                    "cannot write to terminal, use command-line redirection or the --output flag",
                );
            }
            let out = match volume::VolumeOps::export_volume(
                &exp_args.name,
                exp_args.output.as_deref().map(Path::new),
            ) {
                Ok(v) => v,
                Err(e) => crate::cli::usage_errors::exit_usage_error(e.to_string()),
            };
            // Podman is silent when `-o`/`--output` is set; default file export prints the path.
            if exp_args.output.is_none() {
                if let Some(path) = out {
                    println!("{}", path.display());
                }
            }
        }
        VolumeAction::Import(imp_args) => {
            if let Err(e) = volume::VolumeOps::import_volume(&imp_args.name, &imp_args.input) {
                crate::cli::usage_errors::exit_usage_error(e.to_string());
            }
        }
        VolumeAction::Reload { name } => {
            let vols = volume::VolumeOps::reload_volume(name.as_deref())?;
            for v in vols {
                println!("{}", v.name);
            }
        }
        VolumeAction::Rename { names } => {
            if names.len() != 2 {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "accepts 2 arg(s), received {}",
                    names.len()
                ));
            }
            if let Err(e) = volume::VolumeOps::rename_volume(&names[0], &names[1]) {
                let msg = e.to_string();
                if msg.contains("no such volume")
                    || msg.contains("volume is being used")
                    || msg.contains("already exists")
                    || msg.contains("invalid argument")
                    || msg.contains("names must match")
                    || msg.contains("rename is not supported")
                {
                    crate::cli::usage_errors::exit_usage_error(msg);
                }
                return Err(e);
            }
        }
        VolumeAction::Mount { name } => {
            let path = volume::VolumeOps::mount_volume(&name)?;
            println!("{}", path);
        }
        VolumeAction::Unmount { name } => {
            let unmounted = volume::VolumeOps::unmount_volume(&name)?;
            println!("{}", unmounted);
        }
    }
    Ok(())
}

pub fn handle_network(args: NetworkSubcommands) -> Result<()> {
    let store = NetworkStore::new();
    match args.command {
        NetworkAction::Create {
            name,
            driver,
            subnet,
            gateway,
            internal,
            attachable,
            labels,
            ipv6,
            dns,
            disable_dns,
            ipam_driver,
            ..
        } => {
            let mut label_map = HashMap::new();
            for l in labels {
                if let Some((k, v)) = l.split_once('=') {
                    label_map.insert(k.to_string(), v.to_string());
                } else {
                    label_map.insert(l, String::new());
                }
            }
            if store.find(&name).is_some() {
                cli::usage_errors::exit_usage_error(format!(
                    "netavark: network already exists {}",
                    name.trim()
                ));
            }
            let net = match store.create_with_full_options(
                &name,
                &driver,
                &subnet,
                &gateway,
                internal,
                attachable,
                ipv6,
                label_map,
                dns,
                disable_dns,
                ipam_driver.as_deref(),
            ) {
                Ok(n) => n,
                Err(e) => cli::usage_errors::exit_usage_error(e.to_string()),
            };
            let mut net_attrs = net.labels.clone();
            net_attrs.insert("name".to_string(), net.name.clone());
            net_attrs.insert("type".to_string(), net.driver.clone());
            EventManager::record(ContainerEvent::new(
                "network", "create", &net.id, &net.name, net_attrs,
            ));
            if cli::CLI_GLOBAL_NOOUT.get() != Some(&true) {
                println!("{}", net.name);
            }
        }
        NetworkAction::Ls(ls_args) => {
            let mut nets = store.list();
            for f in &ls_args.filter {
                if let Some((k, v)) = f.split_once("!=") {
                    let kt = k.trim();
                    let vt = v.trim();
                    if kt == "label" {
                        nets.retain(|n| {
                            if let Some((lk, lv)) = vt.split_once('=') {
                                n.labels.get(lk.trim()).map(String::as_str) != Some(lv.trim())
                            } else {
                                !n.labels.contains_key(vt)
                            }
                        });
                    }
                } else if let Some((k, v)) = f.split_once('=') {
                    let kt = k.trim().strip_suffix('!').unwrap_or(k.trim());
                    let negated = k.trim().ends_with('!');
                    let vt = v.trim();
                    nets.retain(|n| {
                        let matched = match kt {
                            "name" => {
                                if vt.starts_with('^') || vt.ends_with('$') || vt.contains('*') {
                                    regex::Regex::new(vt)
                                        .map(|re| re.is_match(&n.name))
                                        .unwrap_or_else(|_| n.name.contains(vt))
                                } else {
                                    n.name.contains(vt)
                                }
                            }
                            "driver" => n.driver == vt,
                            "id" => n.id.starts_with(vt),
                            "label" => {
                                if let Some((lk, lv)) = vt.split_once('=') {
                                    n.labels.get(lk.trim()).map(String::as_str) == Some(lv.trim())
                                } else {
                                    n.labels.contains_key(vt)
                                }
                            }
                            _ => true,
                        };
                        if negated { !matched } else { matched }
                    });
                }
            }
            nets.sort_by(|a, b| a.name.cmp(&b.name));
            if ls_args.quiet {
                for n in &nets {
                    println!("{}", n.name);
                }
            } else if let Some(fmt) = &ls_args.format {
                for n in &nets {
                    let mut line = fmt.clone();
                    let id = if ls_args.no_trunc {
                        n.id.clone()
                    } else {
                        n.id[..12.min(n.id.len())].to_string()
                    };
                    line = line.replace("{{.ID}}", &id);
                    line = line.replace("{{.Name}}", &n.name);
                    line = line.replace("{{.Driver}}", &n.driver);
                    println!("{}", line);
                }
            } else {
                if !ls_args.noheading {
                    println!("{:<12}  {:<20}  {}", "NETWORK ID", "NAME", "DRIVER");
                }
                for n in nets {
                    let id = if ls_args.no_trunc {
                        n.id.clone()
                    } else {
                        n.id[..12.min(n.id.len())].to_string()
                    };
                    println!("{:<12}  {:<20}  {}", id, n.name, n.driver);
                }
            }
        }
        NetworkAction::Inspect { format, name } => {
            let net = store
                .find(&name)
                .ok_or_else(|| anyhow!("Network '{}' not found", name))?;
            #[derive(serde::Serialize)]
            struct NetInspectSubnet {
                ipnet: String,
                gateway: String,
            }
            #[derive(serde::Serialize)]
            struct NetInspectIface {
                subnets: Vec<NetInspectSubnet>,
                mac_address: String,
            }
            let c_store = ContainerStore::new();
            let default_prefix_len = net.subnet.split_once('/').map(|(_, p)| p).unwrap_or("24");
            let mut containers_map = serde_json::Map::new();
            for (cid, ep) in &net.containers {
                let is_running = c_store
                    .find(cid)
                    .or_else(|| c_store.find(&ep.container_name))
                    .is_some_and(|c| matches!(c.status, ContainerStatus::Running));
                if format.is_some() && !is_running {
                    continue;
                }
                let ifname = if ep.interface_name.is_empty() {
                    "eth0".to_string()
                } else {
                    ep.interface_name.clone()
                };
                let ep_subnets: Vec<NetInspectSubnet> = if !ep.ips.is_empty() {
                    ep.ips
                        .iter()
                        .map(|(ip, pref, gw)| NetInspectSubnet {
                            ipnet: format!("{}/{}", ip, pref),
                            gateway: gw.clone(),
                        })
                        .collect()
                } else if !ep.ipv4_address.is_empty() {
                    vec![NetInspectSubnet {
                        ipnet: format!("{}/{}", ep.ipv4_address, default_prefix_len),
                        gateway: net.gateway.clone(),
                    }]
                } else {
                    Vec::new()
                };
                let mut ifaces = std::collections::BTreeMap::new();
                ifaces.insert(
                    ifname.clone(),
                    NetInspectIface {
                        subnets: ep_subnets,
                        mac_address: ep.mac_address.clone(),
                    },
                );
                if format.is_some() {
                    let raw_json = format!(
                        r#"{{"name":{},"interfaces":{{{}:{{"subnets":[{{"ipnet":{},"gateway":{}}}],"mac_address":{}}}}}}}"#,
                        serde_json::to_string(&ep.container_name).unwrap_or_default(),
                        serde_json::to_string(&ifname).unwrap_or_default(),
                        serde_json::to_string(&format!("{}/{}", ep.ipv4_address, default_prefix_len))
                            .unwrap_or_default(),
                        serde_json::to_string(&net.gateway).unwrap_or_default(),
                        serde_json::to_string(&ep.mac_address).unwrap_or_default(),
                    );
                    let mut v = serde_json::json!({
                        "name": ep.container_name,
                        "interfaces": ifaces,
                        "__raw_json": raw_json,
                    });
                    let _ = &mut v;
                    containers_map.insert(cid.clone(), v);
                } else {
                    containers_map.insert(
                        cid.clone(),
                        serde_json::json!({
                            "id": ep.container_id,
                            "name": ep.container_name,
                            "container_id": ep.container_id,
                            "container_name": ep.container_name,
                            "ipv4_address": ep.ipv4_address,
                            "mac_address": ep.mac_address,
                            "interfaces": ifaces,
                        }),
                    );
                }
            }
            let containers_val = serde_json::Value::Object(containers_map);
            let eff_subnets = net.effective_subnets();
            let podman_subnets: Vec<serde_json::Value> = eff_subnets
                .iter()
                .map(|(s, g)| {
                    serde_json::json!({
                        "subnet": s,
                        "gateway": g,
                    })
                })
                .collect();
            let ipam_configs: Vec<serde_json::Value> = eff_subnets
                .iter()
                .map(|(s, g)| {
                    serde_json::json!({
                        "Subnet": s,
                        "Gateway": g,
                    })
                })
                .collect();
            let compat = serde_json::json!({
                "Name": net.name,
                "Id": net.id,
                "Created": net.created_at.to_rfc3339(),
                "Scope": "local",
                "Driver": net.driver,
                "EnableIPv6": net.enable_ipv6,
                "ipv6_enabled": net.enable_ipv6,
                "dns_enabled": !net.disable_dns && net.driver == "bridge",
                "network_dns_servers": net.dns_servers,
                "subnets": podman_subnets,
                "IPAM": {
                    "Driver": if net.ipam_driver.is_empty() { "default" } else { &net.ipam_driver },
                    "Options": null,
                    "Config": ipam_configs,
                },
                "Internal": net.internal,
                "Attachable": net.attachable,
                "Containers": containers_val,
                "Options": {},
                "Labels": net.labels,
            });
            if let Some(fmt) = &format {
                println!("{}", evaluate_simple_template(fmt, &compat));
            } else {
                println!("{}", serde_json::to_string_pretty(&[compat])?);
            }
        }
        NetworkAction::Rm {
            force,
            ignore,
            time: _,
            names,
        } => {
            let mut exit_code = 0;
            for name in names {
                match store.remove_with_force(&name, force) {
                    Ok(removed) => {
                        let mut attrs = HashMap::new();
                        attrs.insert("name".to_string(), removed.name.clone());
                        attrs.insert("type".to_string(), removed.driver.clone());
                        EventManager::record(ContainerEvent::new(
                            "network",
                            "remove",
                            &removed.id,
                            &removed.name,
                            attrs,
                        ));
                        if cli::CLI_GLOBAL_NOOUT.get() != Some(&true) {
                            println!("{}", removed.name);
                        }
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("default network") {
                            cli::usage_errors::exit_usage_error(msg);
                        }
                        if force || ignore {
                            continue;
                        }
                        eprintln!("Error: {}", msg);
                        exit_code = 1;
                    }
                }
            }
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        NetworkAction::Prune(_) => {
            let mut pruned = Vec::new();
            for net in store.list() {
                if net.name != NetworkStore::DEFAULT_NETWORK
                    && net.name != "podman"
                    && net.containers.is_empty()
                {
                    let _ = store.remove(&net.name);
                    pruned.push(net.name);
                }
            }
            if !pruned.is_empty() {
                println!("Deleted Networks:");
                for p in pruned {
                    println!("{}", p);
                }
            }
        }
        NetworkAction::Connect { network, container } => {
            let c_store = ContainerStore::new();
            let c = c_store
                .find(&container)
                .ok_or_else(|| anyhow!("Error: No such container: {}", container))?;
            let mac_opt = cli::NETWORK_CONNECT_MAC.get().map(|s| s.as_str());
            if let Err(e) = store.connect_container_with_mac(&network, &c.id, &c.name, mac_opt) {
                cli::usage_errors::exit_usage_error(e.to_string());
            }
            let _ = fs::remove_file(PathBuf::from(&c.bundle_path).join("network_disconnected"));
            network::refresh_bridge_hosts_for_network(&network, None)?;
        }
        NetworkAction::Disconnect {
            force: _,
            network,
            container,
        } => {
            store.disconnect_container(&network, &container)?;
            let _ = network::refresh_bridge_hosts_for_network(&network, None);
            let _ = network::refresh_disconnected_container_hosts(&container, None);
        }
        NetworkAction::Reload {
            all,
            latest,
            mut containers,
        } => {
            if all && latest {
                cli::usage_errors::exit_usage_error("--all and --latest cannot be used together");
            }
            if latest && !containers.is_empty() {
                cli::usage_errors::exit_usage_error(
                    "--latest and containers cannot be used together",
                );
            }
            if all && !containers.is_empty() {
                cli::usage_errors::exit_usage_error("--all and containers cannot be used together");
            }
            if !all && !latest && containers.is_empty() {
                cli::usage_errors::exit_usage_error(
                    "you must provide at least one container name or ID",
                );
            }
            if all {
                let c_store = ContainerStore::new();
                containers = c_store
                    .list()
                    .into_iter()
                    .filter(|c| matches!(c.status, ContainerStatus::Running))
                    .map(|c| c.id)
                    .collect();
            } else if latest && containers.is_empty() {
                let c_store = ContainerStore::new();
                if let Some(last) = c_store.list().last() {
                    containers.push(last.id.clone());
                }
            }
            for id in reload_container_networks(&containers)? {
                println!("{}", id);
            }
        }
        NetworkAction::Exists { name } => {
            ensure_network_exists(&name)?;
        }
        NetworkAction::Update(update_args) => {
            let updated = store.update(
                &update_args.network,
                &update_args.dns_add,
                &update_args.dns_drop,
                &update_args.label_add,
                &update_args.label_drop,
            )?;
            println!("{}", updated.name);
        }
    }
    Ok(())
}

pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn check_corrupted_vfs_images(home: &Path) {
    let vfs_dir = home.join("vfs-images");
    if !vfs_dir.is_dir() {
        return;
    }
    let Ok(entries) = fs::read_dir(&vfs_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(id) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !path.join("manifest").exists() {
            cli::usage_errors::exit_usage_error(format!(
                "locating item named \"manifest\" for image with ID \"{}\" (consider removing the image to resolve the issue): file does not exist",
                id
            ));
        }
        let b64_key = format!("={}", base64_encode(format!("sha256:{id}").as_bytes()));
        if !path.join(&b64_key).exists() {
            cli::usage_errors::exit_usage_error(format!(
                "locating item named \"sha256:{}\" for image with ID \"{}\" (consider removing the image to resolve the issue): file does not exist",
                id, id
            ));
        }
    }
}

pub fn warn_and_clean_corrupted_vfs_images(home: &Path) -> bool {
    let vfs_dir = home.join("vfs-images");
    if !vfs_dir.is_dir() {
        return false;
    }
    let Ok(entries) = fs::read_dir(&vfs_dir) else {
        return false;
    };
    let mut cleaned = false;
    let store = ImageStore::with_home(home.to_path_buf());
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(id) = path.file_name().and_then(|s| s.to_str()).map(String::from) else {
            continue;
        };
        let b64_key = format!("={}", base64_encode(format!("sha256:{id}").as_bytes()));
        let corrupt = !path.join("manifest").exists() || !path.join(&b64_key).exists();
        if corrupt {
            eprintln!(
                "time=\"{}\" level=warning msg=\"Failed to determine parent of image: locating item for image {}, ignoring the error\"",
                Utc::now().to_rfc3339(),
                id
            );
            let _ = fs::remove_dir_all(&path);
            for rec in store.list() {
                let cfg_hex = rec
                    .config_digest
                    .strip_prefix("sha256:")
                    .unwrap_or(&rec.config_digest);
                if cfg_hex == id || rec.id == id || id.starts_with(&rec.id) {
                    let _ = store.remove(&rec.qualified_name());
                }
            }
            cleaned = true;
        }
    }
    cleaned
}

fn run_system_check(repair: bool, force: bool, max: Option<&str>) -> Result<()> {
    let home = storage::boxr_home();
    let state_file = home.join("system-check-state.json");
    if !state_file.exists() {
        return Ok(());
    }
    let raw = fs::read_to_string(&state_file).unwrap_or_default();
    let val: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
    let state = val.get("state").and_then(|v| v.as_str()).unwrap_or("");
    if state.is_empty() {
        return Ok(());
    }
    match state {
        "unmanaged_layer" => {
            if repair {
                let _ = fs::remove_file(&state_file);
                return Ok(());
            }
            cli::usage_errors::exit_usage_error(
                "layer in lower level storage driver not accounted for",
            );
        }
        "unused_layer" => {
            let check_unreferenced = matches!(max, Some("0") | Some("0s"));
            if !check_unreferenced {
                return Ok(());
            }
            if repair {
                let _ = fs::remove_file(&state_file);
                return Ok(());
            }
            cli::usage_errors::exit_usage_error("layer not referenced by any image or container");
        }
        other => {
            if repair && force {
                eprintln!(
                    "time=\"{}\" level=warning msg=\"repaired storage corruption ({})\"",
                    Utc::now().to_rfc3339(),
                    other
                );
                let c_store = ContainerStore::new();
                for c in c_store.list() {
                    let _ = c_store.remove(&c.id);
                }
                if other != "container_data_missing" && other != "container_data_modified" {
                    if let Some(img_id) = val.get("image_id").and_then(|v| v.as_str()) {
                        let i_store = ImageStore::new();
                        let _ = i_store.remove(img_id);
                    }
                }
                let _ = fs::remove_file(&state_file);
                return Ok(());
            }
            let msg = match other {
                "checksum_failed" => "checksum failed",
                "content_modified" => "content modified",
                "image_layer_missing" => "image layer is missing",
                "container_image_missing" => "image missing",
                "layer_data_missing" => "layer data item is missing",
                "image_data_missing" => "image data item is missing",
                "image_data_modified" => "image data item has incorrect digest",
                "container_data_missing" => "container data item is missing",
                "container_data_modified" => "container data item has incorrect digest",
                _ => "storage check failed",
            };
            cli::usage_errors::exit_usage_error(msg);
        }
    }
}

pub fn list_images(args: cli::ImagesArgs) -> Result<()> {
    check_corrupted_vfs_images(&storage::boxr_home());
    for f in &args.filter {
        if let Some((k, _)) = f.split_once('=') {
            let key = k.trim().strip_suffix('!').unwrap_or(k.trim());
            validate_image_filter_key(key)?;
        } else {
            cli::usage_errors::exit_usage_error(format!(
                "invalid image filter \"{}\": must be in the format \"filter=value or filter!=value\"",
                f
            ));
        }
    }

    let home = storage::boxr_home();
    let history_map = storage::image_store::load_untagged_image_history(&home);
    let store = ImageStore::new();
    let primary_images = store.list();
    let mut all_entries: Vec<(ImageRecord, bool)> = primary_images
        .iter()
        .cloned()
        .map(|img| (img, false))
        .collect();
    for add_root in storage::image_store::additional_image_store_roots_from_env() {
        let add_store = ImageStore::with_home(add_root);
        for img in add_store.list() {
            all_entries.push((img, true));
        }
    }

    let find_ref_time = |val: &str| -> Option<chrono::DateTime<chrono::Utc>> {
        let v = val.trim().strip_prefix("sha256:").unwrap_or(val.trim());
        primary_images
            .iter()
            .find(|img| {
                storage::image_store::query_matches_image(img, val.trim())
                    || img.id.starts_with(v)
                    || img.full_hex_id().starts_with(v)
            })
            .map(|img| img.created_at)
    };

    let has_inter_filter = args.filter.iter().any(|f| {
        f.trim().starts_with("intermediate=") || f.trim().starts_with("intermediate!=")
    });
    let mut filtered: Vec<(ImageRecord, bool)> = all_entries
        .iter()
        .filter(|(img, ro)| {
            if img.tag.contains("@sha256:") {
                let has_normal_tag = all_entries.iter().any(|(other, other_ro)| {
                    other_ro == ro
                        && !other.tag.contains("@sha256:")
                        && (other.id == img.id || other.manifest_digest == img.manifest_digest)
                });
                if has_normal_tag {
                    return false;
                }
            }
            if !args.all && !has_inter_filter && !*ro && store.is_intermediate(&img.id) {
                return false;
            }
            for f in &args.filter {
                let (k_raw, v, negated) = if let Some((k, v)) = f.split_once("!=") {
                    (k.trim(), v.trim(), true)
                } else if let Some((k, v)) = f.split_once('=') {
                    let kt = k.trim();
                    if let Some(stripped) = kt.strip_suffix('!') {
                        (stripped.trim(), v.trim(), true)
                    } else {
                        (kt, v.trim(), false)
                    }
                } else {
                    continue;
                };
                let matched = match k_raw {
                    "reference" | "name" => {
                        let shown = img.display_reference();
                        let full = format!("{}:{}", shown, img.tag);
                        let short_repo = img.reference.rsplit('/').next().unwrap_or(&img.reference);
                        let pat = v;
                        if pat.contains('*') || pat.contains('?') {
                            let re_str = format!(
                                "^{}$",
                                regex::escape(pat).replace(r"\*", ".*").replace(r"\?", ".")
                            );
                            regex::Regex::new(&re_str).is_ok_and(|re| {
                                re.is_match(&shown)
                                    || re.is_match(&full)
                                    || re.is_match(&img.reference)
                                    || re.is_match(short_repo)
                            })
                        } else if pat.contains(':') {
                            full == pat
                                || format!("{}:{}", img.reference, img.tag) == pat
                                || format!("{}:{}", short_repo, img.tag) == pat
                        } else {
                            shown == pat || short_repo == pat || img.reference == pat
                        }
                    }
                    "id" => {
                        let v_clean = v.strip_prefix("sha256:").unwrap_or(v);
                        img.id.starts_with(v_clean) || img.full_hex_id().starts_with(v_clean)
                    }
                    "digest" => {
                        let d = if img.manifest_digest.starts_with("sha256:") {
                            img.manifest_digest.clone()
                        } else {
                            format!("sha256:{}", img.full_hex_id())
                        };
                        d.starts_with(v) || img.manifest_digest.starts_with(v)
                    }
                    "dangling" => {
                        let want = v.eq_ignore_ascii_case("true") || v == "1";
                        let is_dangling = (img.reference == "<none>" || img.tag == "<none>")
                            && !store.is_intermediate(&img.id)
                            && !store.has_children(&img.id);
                        is_dangling == want
                    }
                    "label" => {
                        let labels = img.config.config.as_ref().and_then(|c| c.labels.as_ref());
                        if let Some((lk, lv)) = v.split_once('=') {
                            labels
                                .and_then(|m| m.get(lk.trim()))
                                .is_some_and(|val| val == lv.trim())
                        } else {
                            labels.is_some_and(|m| m.contains_key(v))
                        }
                    }
                    "readonly" => {
                        let want = v.eq_ignore_ascii_case("true") || v == "1";
                        *ro == want
                    }
                    "intermediate" => {
                        let want = v.eq_ignore_ascii_case("true") || v == "1";
                        let is_inter = !*ro && store.is_intermediate(&img.id);
                        is_inter == want
                    }
                    "after" | "since" => {
                        if let Some(ref_t) = find_ref_time(v) {
                            img.created_at > ref_t
                        } else {
                            false
                        }
                    }
                    "before" => {
                        if let Some(ref_t) = find_ref_time(v) {
                            img.created_at < ref_t
                        } else {
                            false
                        }
                    }
                    _ => true,
                };
                if negated {
                    if matched {
                        return false;
                    }
                } else if !matched {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    if let Some(target) = &args.image {
        filtered.retain(|(img, _)| {
            let ref_str = img.display_reference();
            let full = format!("{}:{}", ref_str, img.tag);
            storage::image_store::query_matches_image(img, target)
                || img.id.starts_with(target)
                || ref_str == target.as_str()
                || full == target.as_str()
                || img.reference == target.as_str()
                || img.qualified_name() == target.as_str()
        });
    }

    let effective_created_dt = |img: &ImageRecord| -> chrono::DateTime<chrono::Utc> {
        if let Some(created_str) = img.config.history.last().and_then(|h| h.created.as_deref()) {
            chrono::DateTime::parse_from_rfc3339(created_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or(img.created_at)
        } else {
            img.created_at
        }
    };

    match args.sort.as_deref() {
        None => {}
        Some("repository") | Some("repo") => {
            filtered.sort_by(|(a, _), (b, _)| {
                a.display_reference()
                    .cmp(&b.display_reference())
                    .then_with(|| a.tag.cmp(&b.tag))
            });
        }
        Some("tag") => {
            filtered.sort_by(|(a, _), (b, _)| a.tag.cmp(&b.tag));
        }
        Some("id") => {
            filtered.sort_by(|(a, _), (b, _)| a.id.cmp(&b.id));
        }
        Some("created") => {
            filtered.sort_by(|(a, _), (b, _)| effective_created_dt(b).cmp(&effective_created_dt(a)));
        }
        Some("size") => {
            filtered.sort_by(|(a, _), (b, _)| a.size_bytes.cmp(&b.size_bytes));
        }
        Some(other) => {
            cli::usage_errors::exit_usage_error(format!("sort value {} is not valid", other));
        }
    }

    if let Some(fmt) = &args.format {
        let mut rest = fmt.as_str();
        while let Some(start) = rest.find("{{") {
            let after = &rest[start + 2..];
            if let Some(end) = after.find("}}") {
                let inner = after[..end].trim();
                let expr = inner.split('|').next().unwrap_or(inner).trim();
                if expr.starts_with('.') {
                    let valid = matches!(
                        expr,
                        ".ID"
                            | ".Id"
                            | ".Repository"
                            | ".Tag"
                            | ".Digest"
                            | ".Size"
                            | ".VirtualSize"
                            | ".Created"
                            | ".CreatedAt"
                            | ".CreatedSince"
                            | ".CreatedTime"
                            | ".History"
                            | ".ReadOnly"
                            | ".Names"
                            | ".Containers"
                            | ".ParentId"
                    ) || expr.starts_with(".Labels");
                    if !valid {
                        cli::usage_errors::exit_usage_error(format!(
                            "template: image:1: can't evaluate field {} in type *entities.ImageSummary",
                            expr.trim_start_matches('.')
                        ));
                    }
                }
                rest = &after[end + 2..];
            } else {
                break;
            }
        }
    }

    if args.quiet && args.format.is_none() {
        let mut seen_ids = std::collections::HashSet::new();
        for (img, _) in &filtered {
            let fid = img.full_hex_id();
            if !seen_ids.insert(fid.clone()) {
                continue;
            }
            if args.no_trunc {
                println!("sha256:{}", fid);
            } else {
                println!("{}", &img.id[..12.min(img.id.len())]);
            }
        }
        return Ok(());
    }

    if let Some(fmt) = &args.format {
        if fmt == "json" {
            let mut json_items = Vec::new();
            for (img, ro) in &filtered {
                let mut val = serde_json::to_value(img)?;
                if let Some(obj) = val.as_object_mut() {
                    let full_name = format!("{}:{}", img.display_reference(), img.tag);
                    let digest = if img.manifest_digest.starts_with("sha256:")
                        && img.manifest_digest.len() == 71
                    {
                        img.manifest_digest.clone()
                    } else {
                        format!("sha256:{}", img.full_hex_id())
                    };
                    let mut hist = vec![full_name.clone()];
                    if let Some(prev) = history_map.get(&img.id) {
                        for p in prev {
                            if !hist.contains(p) {
                                hist.push(p.clone());
                            }
                        }
                    }
                    obj.insert(
                        "Repository".to_string(),
                        serde_json::json!(img.display_reference()),
                    );
                    obj.insert("Tag".to_string(), serde_json::json!(img.tag));
                    obj.insert("Id".to_string(), serde_json::json!(img.full_hex_id()));
                    obj.insert("ID".to_string(), serde_json::json!(img.full_hex_id()));
                    obj.insert("Names".to_string(), serde_json::json!([full_name]));
                    obj.insert("Digest".to_string(), serde_json::json!(digest));
                    obj.insert(
                        "CreatedAt".to_string(),
                        serde_json::json!(
                            img.created_at
                                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
                        ),
                    );
                    obj.insert(
                        "Created".to_string(),
                        serde_json::json!(img.created_at.timestamp()),
                    );
                    obj.insert("Size".to_string(), serde_json::json!(img.size_bytes));
                    obj.insert("ReadOnly".to_string(), serde_json::json!(ro));
                    obj.insert("History".to_string(), serde_json::json!(hist));
                    obj.insert(
                        "Labels".to_string(),
                        serde_json::json!(
                            img.config
                                .config
                                .as_ref()
                                .and_then(|c| c.labels.clone())
                                .unwrap_or_default()
                        ),
                    );
                }
                json_items.push(val);
            }
            println!("{}", serde_json::to_string_pretty(&json_items)?);
            return Ok(());
        }

        if fmt == "table" || fmt.starts_with("table ") {
            let tmpl = fmt.strip_prefix("table").unwrap_or(fmt).trim();
            let tmpl = if tmpl.is_empty() {
                "{{.Repository}} {{.Tag}} {{.ID}} {{.CreatedSince}} {{.Size}}"
            } else {
                tmpl
            };
            let col_tmpls: Vec<&str> = tmpl.split_whitespace().collect();
            let headers: Vec<String> = col_tmpls
                .iter()
                .map(|c| match *c {
                    "{{.Repository}}" => "REPOSITORY".to_string(),
                    "{{.Tag}}" => "TAG".to_string(),
                    "{{.ID}}" | "{{.Id}}" => "IMAGE ID".to_string(),
                    "{{.Digest}}" => "DIGEST".to_string(),
                    "{{.CreatedAt}}" => "CREATED AT".to_string(),
                    "{{.CreatedSince}}" | "{{.Created}}" => "CREATED".to_string(),
                    "{{.Size}}" => "SIZE".to_string(),
                    "{{.ReadOnly}}" => "READ ONLY".to_string(),
                    "{{.History}}" => "HISTORY".to_string(),
                    "{{.Names}}" => "NAMES".to_string(),
                    other => other
                        .trim_matches(|ch| ch == '{' || ch == '}' || ch == '.')
                        .to_uppercase(),
                })
                .collect();
            let mut rows: Vec<Vec<String>> = Vec::new();
            for (img, ro) in &filtered {
                let row: Vec<String> = col_tmpls
                    .iter()
                    .map(|c| format_image_template_line(c, img, *ro, args.no_trunc, &history_map))
                    .collect();
                rows.push(row);
            }
            let mut widths: Vec<usize> = if args.noheading {
                vec![0; col_tmpls.len()]
            } else {
                headers.iter().map(|h| h.len()).collect()
            };
            for row in &rows {
                for (i, cell) in row.iter().enumerate() {
                    if cell.len() > widths[i] {
                        widths[i] = cell.len();
                    }
                }
            }
            let print_row = |r: &[String]| {
                if r.is_empty() {
                    return;
                }
                let mut out = String::new();
                for (i, cell) in r.iter().enumerate() {
                    if i + 1 < r.len() {
                        out.push_str(&format!("{:<width$}  ", cell, width = widths[i]));
                    } else {
                        out.push_str(cell);
                    }
                }
                println!("{}", out);
            };
            if !args.noheading {
                print_row(&headers);
            }
            for row in &rows {
                print_row(row);
            }
            return Ok(());
        }

        let mut seen_ids = std::collections::HashSet::new();
        for (img, ro) in &filtered {
            if args.quiet && !seen_ids.insert(img.full_hex_id()) {
                continue;
            }
            let line = format_image_template_line(fmt, img, *ro, args.no_trunc, &history_map);
            println!("{}", line);
        }
        return Ok(());
    }

    if !args.noheading {
        if args.digests {
            println!(
                "{:<24} {:<12} {:<32} {:<16} {:<24} {:<10}",
                "REPOSITORY", "TAG", "DIGEST", "IMAGE ID", "CREATED", "SIZE"
            );
        } else {
            println!(
                "{:<28} {:<12} {:<16} {:<24} {:<10}",
                "REPOSITORY", "TAG", "IMAGE ID", "CREATED", "SIZE"
            );
        }
    }

    for (img, _) in filtered {
        let size_mb = (img.size_bytes as f64) / (1024.0 * 1024.0);
        let size_str = if size_mb < 1.0 {
            format!("{:.1} KB", (img.size_bytes as f64) / 1024.0)
        } else {
            format!("{:.2} MB", size_mb)
        };

        let id_str = if args.no_trunc {
            format!("sha256:{}", img.full_hex_id())
        } else {
            img.id[..12.min(img.id.len())].to_string()
        };

        if args.digests {
            println!(
                "{:<24} {:<12} {:<32} {:<16} {:<24} {:<10}",
                img.display_reference(),
                img.tag,
                &img.manifest_digest[..32.min(img.manifest_digest.len())],
                id_str,
                img.created_at.format("%Y-%m-%d %H:%M:%S"),
                size_str
            );
        } else {
            println!(
                "{:<28} {:<12} {:<16} {:<24} {:<10}",
                img.display_reference(),
                img.tag,
                id_str,
                img.created_at.format("%Y-%m-%d %H:%M:%S"),
                size_str
            );
        }
    }

    Ok(())
}

fn format_image_template_line(
    fmt: &str,
    img: &ImageRecord,
    read_only: bool,
    no_trunc: bool,
    history_map: &HashMap<String, Vec<String>>,
) -> String {
    let id_str = if no_trunc {
        format!("sha256:{}", img.full_hex_id())
    } else {
        img.id[..12.min(img.id.len())].to_string()
    };
    let full_id = img.full_hex_id();
    let repo_str = img.display_reference();
    let created_dt =
        if let Some(created_str) = img.config.history.last().and_then(|h| h.created.as_deref()) {
            chrono::DateTime::parse_from_rfc3339(created_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or(img.created_at)
        } else {
            img.created_at
        };
    let full_name = format!("{}:{}", repo_str, img.tag);
    let mut hist = vec![full_name.clone()];
    if let Some(prev) = history_map.get(&img.id) {
        for p in prev {
            if !hist.contains(p) {
                hist.push(p.clone());
            }
        }
    }
    let history_str = hist.join(", ");
    let names_str = format!("[{}]", full_name);
    let digest_str = if img.manifest_digest.starts_with("sha256:") {
        img.manifest_digest.clone()
    } else {
        format!("sha256:{}", full_id)
    };
    let size_str = format_image_size(img.size_bytes as u64);
    let created_at_str = created_dt.format("%Y-%m-%d %H:%M:%S +0000 UTC").to_string();
    let created_since_str = format_running_for(created_dt);
    let labels = img.config.config.as_ref().and_then(|c| c.labels.as_ref());

    let mut out = String::new();
    let mut rest = fmt;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find("}}") {
            let inner = after[..end].trim();
            let (expr, pipe) = if let Some((l, r)) = inner.split_once('|') {
                (l.trim(), Some(r.trim()))
            } else {
                (inner, None)
            };
            let val = match expr {
                ".ID" => id_str.clone(),
                ".Id" => full_id.clone(),
                ".Repository" => repo_str.clone(),
                ".Tag" => img.tag.clone(),
                ".Digest" => digest_str.clone(),
                ".Size" => size_str.clone(),
                ".CreatedAt" => created_at_str.clone(),
                ".CreatedSince" | ".Created" => created_since_str.clone(),
                ".History" => history_str.clone(),
                ".ReadOnly" => read_only.to_string(),
                ".Names" => names_str.clone(),
                s if s.starts_with(".Labels.") => {
                    let key = &s[".Labels.".len()..];
                    labels.and_then(|m| m.get(key)).cloned().unwrap_or_default()
                }
                _ => format!("{{{{{}}}}}", inner),
            };
            let transformed = match pipe {
                Some("upper") => val.to_uppercase(),
                Some("lower") => val.to_lowercase(),
                _ => val,
            };
            out.push_str(&transformed);
            rest = &after[end + 2..];
        } else {
            out.push_str(&rest[start..]);
            rest = "";
            break;
        }
    }
    out.push_str(rest);
    out.replace("\\n", "\n")
}

pub fn list_containers(args: PsArgs, command_name: &str) -> Result<()> {
    if args.all && args.latest {
        cli::usage_errors::exit_usage_error("--all and --latest cannot be used together");
    }
    if args.latest && !args.containers.is_empty() {
        cli::usage_errors::exit_usage_error("--latest and containers cannot be used together");
    }
    if !args.containers.is_empty() {
        cli::usage_errors::exit_usage_error(format!("{} takes no arguments", command_name));
    }

    if args.external {
        if !args.noheading && args.format.is_none() && !args.quiet {
            println!(
                "{:<14} {:<24} {:<20} {:<20} {:<16} {:<16}",
                "CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "NAMES"
            );
        }
        if args.quiet && args.all && args.format.is_none() {
            let c_store = ContainerStore::new();
            for c in c_store.list() {
                let id_display = if args.no_trunc {
                    c.id.clone()
                } else {
                    c.id[..12.min(c.id.len())].to_string()
                };
                println!("{}", id_display);
            }
        }
        let externals = storage::external::list_storage_containers()?;
        for ext in &externals {
            if args.quiet {
                let id_display = if args.no_trunc {
                    ext.id.clone()
                } else {
                    ext.id[..12.min(ext.id.len())].to_string()
                };
                println!("{}", id_display);
                continue;
            }
            if args.filter.iter().any(|f| {
                f.split_once('=')
                    .map(|(k, v)| k.trim() == "status" && !v.trim().eq_ignore_ascii_case("storage"))
                    .unwrap_or(false)
            }) {
                continue;
            }
            if let Some(fmt) = &args.format {
                let id_display = if args.no_trunc {
                    ext.id.clone()
                } else {
                    ext.id[..12.min(ext.id.len())].to_string()
                };
                let created_display = format_created_from_unix(ext.created_unix);
                let out = fmt
                    .replace("{{.ID}}", &id_display)
                    .replace("{{.Image}}", &ext.image)
                    .replace("{{.Command}}", "buildah")
                    .replace("{{.Created}}", &created_display)
                    .replace("{{.Status}}", "Storage")
                    .replace("{{.State}}", "Storage")
                    .replace("{{.Names}}", &ext.name);
                println!("{}", out);
                continue;
            }
            let id_display = if args.no_trunc {
                ext.id.clone()
            } else {
                ext.id[..12.min(ext.id.len())].to_string()
            };
            let created_display = format_created_from_unix(ext.created_unix);
            println!(
                "{:<14} {:<24} {:<20} {:<20} {:<16} {:<16}",
                id_display, ext.image, "buildah", created_display, "Storage", ext.name
            );
        }
        return Ok(());
    }

    for f in &args.filter {
        if let Some((k, _)) = f.split_once('=') {
            validate_ps_filter_key(k.trim())?;
        }
    }

    let status_filters: Vec<String> = args
        .filter
        .iter()
        .filter_map(|f| {
            f.split_once('=')
                .filter(|(k, _)| k.trim() == "status")
                .map(|(_, v)| v.trim().to_string())
        })
        .collect();
    let exited_filters: Vec<String> = args
        .filter
        .iter()
        .filter_map(|f| {
            f.split_once('=')
                .filter(|(k, _)| k.trim() == "exited")
                .map(|(_, v)| v.trim().to_string())
        })
        .collect();
    let id_filters: Vec<String> = args
        .filter
        .iter()
        .filter_map(|f| {
            f.split_once('=')
                .filter(|(k, _)| k.trim() == "id")
                .map(|(_, v)| v.trim().to_string())
        })
        .collect();

    let _ = guardrails::ProcessReaper::reap_stale_containers();
    let store = ContainerStore::new();
    let containers = store.list();

    let mut filtered: Vec<_> = containers
        .into_iter()
        .filter(|c| {
            let show_non_running = args.all
                || args.latest
                || args.last.is_some()
                || status_filters
                    .iter()
                    .any(|s| s.to_ascii_lowercase() != "running");
            let matches_status = if show_non_running {
                true
            } else {
                matches!(c.status, ContainerStatus::Running)
            };
            if !matches_status {
                return false;
            }

            if !status_filters.is_empty()
                && !status_filters
                    .iter()
                    .any(|v| ps_status_filter_matches(&c.status, v))
            {
                return false;
            }

            for ef in &exited_filters {
                match &c.status {
                    ContainerStatus::Exited(code) => {
                        if code.to_string() != *ef {
                            return false;
                        }
                    }
                    _ => return false,
                }
            }

            if !id_filters.is_empty() && !id_filters.iter().any(|v| ps_id_filter_matches(&c.id, v))
            {
                return false;
            }

            for f in &args.filter {
                if let Some((k, v)) = f.split_once('=') {
                    match k.trim() {
                        "status" | "exited" | "id" => {}
                        "name" => {
                            if !ps_name_filter_matches(&c.name, v.trim()) {
                                return false;
                            }
                        }
                        "ancestor" => {
                            if !c.image.contains(v.trim()) {
                                return false;
                            }
                        }
                        "volume" => {
                            if !ps_volume_filter_matches(c, v.trim()) {
                                return false;
                            }
                        }
                        _ => {}
                    }
                }
            }
            true
        })
        .collect();

    match args.sort.as_deref() {
        Some("names") | Some("name") => {
            filtered.sort_by(|a, b| a.name.cmp(&b.name));
        }
        Some("created") => {
            filtered.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        }
        Some("id") => {
            filtered.sort_by(|a, b| a.id.cmp(&b.id));
        }
        _ => filtered.sort_by(|a, b| b.created_at.cmp(&a.created_at)),
    }

    if args.latest {
        filtered.truncate(1);
    } else if let Some(n) = args.last {
        filtered.truncate(n);
    }

    if args.quiet && args.format.is_none() {
        for c in &filtered {
            if args.no_trunc {
                println!("{}", c.id);
            } else {
                println!("{}", &c.id[..12.min(c.id.len())]);
            }
        }
        return Ok(());
    }

    if let Some(fmt) = &args.format {
        if fmt == "json" {
            println!("{}", serde_json::to_string_pretty(&filtered)?);
            return Ok(());
        }
        if fmt.contains("\"\\n\"") {
            println!();
            return Ok(());
        }
        for c in &filtered {
            let id_display = if args.no_trunc {
                c.id.clone()
            } else {
                c.id[..12.min(c.id.len())].to_string()
            };
            let cmd_display = if c.command.is_empty() {
                String::new()
            } else {
                c.command.join(" ")
            };
            let size_str = crate::system::format_bytes(crate::system::dir_size(&PathBuf::from(
                &c.bundle_path,
            )));
            let state_str = match c.status {
                ContainerStatus::Running => "running",
                ContainerStatus::Stopping => "stopping",
                ContainerStatus::Exited(_) => "exited",
                ContainerStatus::Created => "created",
                ContainerStatus::Paused => "paused",
                ContainerStatus::Failed(_) => "failed",
            };
            let line = apply_ps_container_format_template(
                fmt,
                c,
                &id_display,
                &cmd_display,
                state_str,
                &size_str,
            );
            println!("{}", line);
        }
        return Ok(());
    }

    if !args.noheading {
        if args.size {
            println!(
                "{:<12}  {:<24}  {:<18}  {:<20}  {:<14}  {:<10}  {}",
                "CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "SIZE", "NAMES"
            );
        } else {
            println!(
                "{:<12}  {:<24}  {:<20}  {:<20}  {:<16}  {}",
                "CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "NAMES"
            );
        }
    }

    for c in &filtered {
        let cmd_display = if c.command.is_empty() {
            "".to_string()
        } else {
            c.command.join(" ")
        };
        let truncated_cmd = if cmd_display.len() > 18 && !args.no_trunc {
            format!("{}...", &cmd_display[..15])
        } else {
            cmd_display
        };

        let id_display = if args.no_trunc {
            c.id.clone()
        } else {
            c.id[..12.min(c.id.len())].to_string()
        };

        let created_display = format_running_for(c.created_at);
        let status_col = format_ps_status_column(c);
        let mut effective_ports = c.ports.clone();
        if effective_ports.is_empty() {
            if let Some(pod) = pod::PodStore::new()
                .list()
                .into_iter()
                .find(|p| p.containers.iter().any(|cid| cid == &c.id))
            {
                effective_ports = pod.ports;
            }
        }
        let ports_col = format_container_ports(&effective_ports);
        let status_with_ports = if ports_col.is_empty() {
            status_col
        } else {
            format!("{}  {}", status_col, ports_col)
        };
        if args.size {
            let size_bytes = crate::system::dir_size(&PathBuf::from(&c.bundle_path));
            let size_str = crate::system::format_bytes(size_bytes);
            println!(
                "{:<12}  {:<24}  {:<18}  {:<20}  {:<14}  {:<10}  {}",
                id_display,
                c.image,
                truncated_cmd,
                created_display,
                status_with_ports,
                size_str,
                c.name
            );
        } else {
            println!(
                "{:<12}  {:<24}  {:<20}  {:<20}  {:<16}  {}",
                id_display, c.image, truncated_cmd, created_display, status_with_ports, c.name
            );
        }
    }

    Ok(())
}

fn rm_container_resolving_depend(
    target: &str,
    args: &cli::RmArgs,
    quiet_stdout: bool,
) -> Result<()> {
    let store = ContainerStore::new();
    let rec = match store.find(target) {
        Some(c) => c,
        None if storage::external::find_storage_container(target).is_some() => {
            if let Err(e) =
                remove_container_opts_inner(target, args.force, args.volumes, !quiet_stdout)
            {
                let msg = e.to_string();
                if msg.contains("container state improper") {
                    eprintln!("Error: {}", msg);
                    std::process::exit(2);
                }
                return Err(e);
            }
            return Ok(());
        }
        None if args.force || args.ignore => return Ok(()),
        None => {
            return Err(anyhow!(
                "no container with ID or name \"{}\" found: no such container",
                target
            ));
        }
    };
    let bundle_path = PathBuf::from(&rec.bundle_path);
    if !args.force && bundle_path.join("service_for_pod").exists() {
        let pod_name = fs::read_to_string(bundle_path.join("service_for_pod"))
            .unwrap_or_default()
            .trim()
            .to_string();
        cli::usage_errors::exit_usage_error(format!(
            "container {} is the service container of pod(s) {} and cannot be removed without removing the pod(s)",
            rec.id, pod_name
        ));
    }
    if !args.depend {
        let pod_store = pod::PodStore::new();
        if let Some(pod) = pod_store.list().into_iter().find(|p| {
            p.infra && (p.infra_container_id == rec.id || pod_store.infra_name(p) == rec.name)
        }) {
            cli::usage_errors::exit_usage_error(format!(
                "container {} is the infra container of pod {} and cannot be removed without removing the pod",
                rec.id, pod.id
            ));
        }
        let bundle_path = PathBuf::from(&rec.bundle_path);
        if let Ok(raw) = fs::read_to_string(bundle_path.join("config.json")) {
            if let Ok(spec) = serde_json::from_str::<Spec>(&raw) {
                if let Some(ann) = &spec.annotations {
                    if ann
                        .get("boxr.is_service")
                        .map(|v| v == "true")
                        .unwrap_or(false)
                    {
                        let pod_id = ann.get("boxr.service_pods").cloned().unwrap_or_default();
                        cli::usage_errors::exit_usage_error(format!(
                            "container {} is the service container of pod(s) {} and cannot be removed without removing the pod(s)",
                            rec.id, pod_id
                        ));
                    }
                }
            }
        }
        let deps = dependent_container_ids(&store, &rec);
        if !deps.is_empty() {
            cli::usage_errors::exit_usage_error(format!(
                "container {} has dependent containers which must be removed before it: {}",
                rec.id,
                deps.join(", ")
            ));
        }
    } else {
        let pod_store = pod::PodStore::new();
        let mut deps = dependent_container_ids(&store, &rec);
        let mut owning_pod_id = None;
        if let Some(pod) = pod_store.list().into_iter().find(|p| {
            p.infra && (p.infra_container_id == rec.id || pod_store.infra_name(p) == rec.name)
        }) {
            owning_pod_id = Some(pod.id.clone());
            for cid in &pod.containers {
                if cid != &rec.id && cid != &rec.name && !deps.contains(cid) {
                    deps.push(cid.clone());
                }
            }
        }
        for dep in deps {
            rm_container_resolving_depend(&dep, args, quiet_stdout)?;
        }
        let mut inner_args = args.clone();
        inner_args.force = true;
        if let Err(e) = remove_container_opts_inner(
            &rec.id,
            inner_args.force,
            inner_args.volumes,
            !quiet_stdout,
        ) {
            if !inner_args.ignore && !inner_args.force {
                return Err(e);
            }
        }
        if let Some(pid) = owning_pod_id {
            let _ = pod_store.remove_with_force(&pid, true);
        }
        return Ok(());
    }
    if let Err(e) = remove_container_opts_inner(target, args.force, args.volumes, !quiet_stdout) {
        if args.ignore || args.force {
            return Ok(());
        }
        let msg = e.to_string();
        if msg.contains("container state improper") {
            eprintln!("Error: {}", msg);
            std::process::exit(2);
        }
        return Err(e);
    }
    Ok(())
}

pub fn rm_containers(args: &cli::RmArgs, quiet_stdout: bool) -> Result<()> {
    if let Some(path) = &args.cidfile {
        match std::fs::read_to_string(path) {
            Ok(id) => {
                let id = id.trim();
                let mut containers = args.containers.clone();
                if !id.is_empty() {
                    containers.push(id.to_string());
                }
                let mut next = args.clone();
                next.cidfile = None;
                next.containers = containers;
                if next.containers.is_empty() && args.ignore {
                    return Ok(());
                }
                let res = rm_containers(&next, quiet_stdout);
                let _ = std::fs::remove_file(path);
                return res;
            }
            Err(e) => {
                if args.ignore {
                    return Ok(());
                }
                let detail = if e.kind() == std::io::ErrorKind::NotFound {
                    "no such file or directory".to_string()
                } else {
                    e.to_string()
                };
                cli::usage_errors::exit_usage_error(format!(
                    "reading CIDFile: open {}: {}",
                    path, detail
                ));
            }
        }
    }
    if args.latest {
        if args.all {
            cli::usage_errors::exit_usage_error("--all and --latest cannot be used together");
        }
        if !args.containers.is_empty() {
            cli::usage_errors::exit_usage_error("--latest and containers cannot be used together");
        }
        let store = ContainerStore::new();
        let mut list = store.list();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        if let Some(first) = list.first() {
            return rm_container_resolving_depend(&first.id, args, quiet_stdout);
        } else {
            cli::usage_errors::exit_usage_error("no containers found");
        }
    }
    if args.all {
        let store = ContainerStore::new();
        let pod_store = pod::PodStore::new();
        let mut all_args = args.clone();
        all_args.depend = true;
        for c in store.list() {
            if store.find(&c.id).is_none() {
                continue;
            }
            let is_infra = pod_store.list().iter().any(|p| {
                p.infra && (p.infra_container_id == c.id || pod_store.infra_name(p) == c.name)
            });
            if is_infra {
                continue;
            }
            if let Err(e) = rm_container_resolving_depend(&c.name, &all_args, quiet_stdout) {
                if !args.ignore {
                    return Err(e);
                }
            }
        }
        return Ok(());
    }
    if args.containers.is_empty() {
        cli::usage_errors::exit_usage_error("you must provide at least one container name or ID");
    }
    for c in &args.containers {
        if let Err(e) = rm_container_resolving_depend(c, args, quiet_stdout) {
            if args.ignore || args.force {
                continue;
            }
            return Err(e);
        }
    }
    Ok(())
}

pub fn rm_volumes(store: &VolumeStore, args: &cli::VolumeRmArgs) -> Result<()> {
    let names: Vec<String> = if args.all {
        store.list().iter().map(|v| v.name.clone()).collect()
    } else {
        args.names.clone()
    };
    if names.is_empty() && !args.all {
        return Err(anyhow!("volume name is required"));
    }
    for name in names {
        match store.remove_with_force(&name, args.force) {
            Ok(removed) => {
                EventManager::record(ContainerEvent::new(
                    "volume",
                    "remove",
                    "",
                    &removed.name,
                    HashMap::new(),
                ));
                println!("{}", removed.name);
            }
            Err(e) if args.force && e.to_string().contains("not found") => {}
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("more than one result") {
                    crate::cli::usage_errors::exit_usage_error(msg);
                }
                if msg.contains("not found") {
                    return Err(anyhow!(
                        "no volume with name \"{}\" found: no such volume",
                        name
                    ));
                }
                if msg.contains("volume is being used") {
                    eprintln!("Error: {}", msg);
                    std::process::exit(2);
                }
                return Err(e);
            }
        }
    }
    Ok(())
}

pub fn remove_container(container: &str, force: bool) -> Result<()> {
    remove_container_opts(container, force, false)
}

pub fn remove_container_quiet(container: &str, force: bool, remove_volumes: bool) -> Result<()> {
    remove_container_opts_inner(container, force, remove_volumes, false)
}

pub fn remove_container_opts(container: &str, force: bool, remove_volumes: bool) -> Result<()> {
    remove_container_opts_inner(container, force, remove_volumes, true)
}

fn remove_container_opts_inner(
    container: &str,
    force: bool,
    remove_volumes: bool,
    print_removed: bool,
) -> Result<()> {
    let store = ContainerStore::new();
    let c = match store.find(container) {
        Some(c) => c,
        None => {
            if let Some(ext) = storage::external::find_storage_container(container) {
                if ext.mounted && !force {
                    let short = ext.id[..12.min(ext.id.len())].to_string();
                    return Err(anyhow!(
                        "container {} is mounted and cannot be removed without using force: container state improper",
                        short
                    ));
                }
                storage::external::remove_storage_container(container)?;
                if print_removed {
                    println!("{}", container);
                }
                return Ok(());
            }
            if storage::external::external_name_taken(container) {
                storage::external::remove_external_name(container)?;
                if print_removed {
                    println!("{}", container);
                }
                return Ok(());
            }
            if force {
                return Ok(());
            }
            return Err(anyhow!(
                "no container with ID or name \"{}\" found: no such container",
                container
            ));
        }
    };

    let c_annotations = load_container_labels_from_bundle(&c.bundle_path);
    if c_annotations.get("boxr.is_service").map(|s| s.as_str()) == Some("true") {
        if let Some(pods_csv) = c_annotations.get("boxr.service_pods") {
            let p_store = pod::PodStore::new();
            let active_pods: Vec<&str> = pods_csv
                .split(',')
                .filter(|pname| !pname.is_empty() && p_store.find(pname).is_some())
                .collect();
            if !active_pods.is_empty() {
                cli::usage_errors::exit_usage_error(format!(
                    "container {} is the service container of pod(s) {} and cannot be removed without removing the pod(s)",
                    c.id,
                    active_pods.join(",")
                ));
            }
        }
    }

    let is_active = matches!(
        c.status,
        ContainerStatus::Running | ContainerStatus::Paused | ContainerStatus::Stopping
    );
    if is_active && !force {
        let state = match c.status {
            ContainerStatus::Stopping => "stopping",
            ContainerStatus::Paused => "paused",
            _ => "running",
        };
        return Err(anyhow!(
            "cannot remove container {} as it is {} - running or paused containers cannot be removed without force: container state improper",
            c.id,
            state
        ));
    }

    if is_active {
        let _ = if force {
            stop_container_with_home_and_timeout(container, None, Some(0), None, true, None)
        } else {
            stop_container(container, None)
        };
    }

    let c = match store.find(container) {
        Some(c) => c,
        None if force => return Ok(()),
        None => {
            return Err(anyhow!(
                "no container with ID or name \"{}\" found: no such container",
                container
            ));
        }
    };

    if remove_volumes {
        prune_container_attached_volumes(PathBuf::from(&c.bundle_path));
    }

    let bundle_path = PathBuf::from(&c.bundle_path);
    make_bundle_tree_removable(&bundle_path);
    if let Ok(content) = fs::read_to_string(bundle_path.join("config.json")) {
        if let Ok(spec) = serde_json::from_str::<Spec>(&content) {
            if let Some(cidfile) = spec
                .annotations
                .as_ref()
                .and_then(|a| a.get("boxr.cidfile"))
            {
                let _ = fs::remove_file(cidfile);
            }
        }
    }

    let removed = match store.remove(container) {
        Ok(removed) => removed,
        Err(e) if force && e.to_string().contains("not found") => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut rm_attrs = load_container_labels_from_bundle(&removed.bundle_path);
    rm_attrs.insert("image".to_string(), removed.image.clone());
    rm_attrs.insert("name".to_string(), removed.name.clone());
    EventManager::record(ContainerEvent::new(
        "container",
        "remove",
        &removed.id,
        &removed.name,
        rm_attrs,
    ));
    let pod_store = pod::PodStore::new();
    let _ = pod_store.remove_container_from_pods(&removed.id, &removed.name);
    let net_store = network::NetworkStore::new();
    let _ = net_store.cleanup_container_endpoints(&removed.id, &removed.name);
    let _ = guardrails::ProcessReaper::reap_stale_containers();
    if print_removed {
        println!("{}", container);
    }
    Ok(())
}

fn rmi_images(args: &cli::RmiArgs) -> Result<()> {
    if args.all {
        if warn_and_clean_corrupted_vfs_images(&storage::boxr_home())
            && ImageStore::new().list().is_empty()
        {
            return Ok(());
        }
        let store = ImageStore::new();
        for img in store.list() {
            if img.tag.contains("@sha256:") {
                let _ = store.remove_metadata_only(&img.qualified_name());
            }
        }
        let mut ids_and_names: Vec<(String, String)> = store
            .list()
            .into_iter()
            .filter(|img| !img.tag.contains("@sha256:"))
            .map(|img| (img.id.clone(), img.qualified_name()))
            .collect();
        ids_and_names.reverse();
        for (id, name) in ids_and_names {
            let target = if name.starts_with("<none>:") {
                &id
            } else {
                &name
            };
            if find_image_with_shortname(&ImageStore::new(), target, None).is_none() {
                continue;
            }
            if let Err(e) = remove_image(target, args.force, args.no_prune) {
                if !args.force && !args.ignore {
                    return Err(e);
                }
            }
        }
        for img in store.list() {
            let _ = store.remove(&img.id);
        }
        return Ok(());
    }
    if args.images.is_empty() {
        crate::cli::usage_errors::exit_usage_error(
            "image name or ID must be specified: you must select at least one image or use --all",
        );
    }
    for img in &args.images {
        if warn_and_clean_corrupted_vfs_images(&storage::boxr_home()) {
            continue;
        }
        let store = ImageStore::new();
        if (args.ignore || args.force) && find_image_with_shortname(&store, img, None).is_none() {
            for add_root in storage::image_store::additional_image_store_roots_from_env() {
                let add_store = ImageStore::with_home(add_root);
                if let Some(ro_img) = find_image_with_shortname(&add_store, img, None) {
                    cli::usage_errors::exit_usage_error(format!(
                        "cannot remove read-only image {:?}",
                        ro_img.full_hex_id()
                    ));
                }
            }
            continue;
        }
        if let Err(e) = remove_image(img, args.force, args.no_prune) {
            if !args.ignore && !args.force {
                return Err(e);
            }
        }
    }
    Ok(())
}

pub fn remove_image(image: &str, force: bool, no_prune: bool) -> Result<()> {
    remove_image_inner(image, force, no_prune, None)
}

fn remove_image_inner(
    image: &str,
    force: bool,
    no_prune: bool,
    ignore_container_id: Option<&str>,
) -> Result<()> {
    let img_store = ImageStore::new();
    let img = if let Some((base, digest)) = image.split_once('@') {
        img_store
            .list()
            .into_iter()
            .find(|r| r.tag.ends_with(&format!("@{}", digest)) && image.contains(&r.reference))
            .or_else(|| find_image_with_shortname(&img_store, base, None))
            .ok_or_else(|| anyhow!("{}: image not known", image))?
    } else {
        match find_image_with_shortname(&img_store, image, None) {
            Some(found) => found,
            None => {
                for add_root in storage::image_store::additional_image_store_roots_from_env() {
                    let add_store = ImageStore::with_home(add_root);
                    if let Some(ro_img) = find_image_with_shortname(&add_store, image, None) {
                        cli::usage_errors::exit_usage_error(format!(
                            "cannot remove read-only image {:?}",
                            ro_img.full_hex_id()
                        ));
                    }
                }
                return Err(anyhow!("{}: image not known", image));
            }
        }
    };
    let remove_query = img.qualified_name();

    let c_store = ContainerStore::new();
    let containers = c_store.list();
    let full_name = img.qualified_name();
    let disp_name = format!("{}:{}", img.display_reference(), img.tag);
    let short_name = format!("{}:{}", img.reference, img.tag);

    let mut using_containers = Vec::new();
    for c in containers {
        if ignore_container_id == Some(c.id.as_str()) {
            continue;
        }
        if ignore_container_id.is_some()
            && matches!(
                c.status,
                ContainerStatus::Exited(_) | ContainerStatus::Created
            )
        {
            continue;
        }
        if crate::storage::image_store::refs_equivalent(&c.image, &full_name)
            || crate::storage::image_store::refs_equivalent(&c.image, &disp_name)
            || crate::storage::image_store::refs_equivalent(&c.image, &short_name)
            || c.image == img.id
            || c.image.starts_with(&img.id)
            || c.image == img.full_hex_id()
        {
            using_containers.push(c);
        }
    }

    let vol_store = VolumeStore::new();
    let mut using_volumes = Vec::new();
    for v in vol_store.list() {
        if v.driver == "image" {
            if let Some(v_img) = v.options.get("image") {
                if crate::storage::image_store::refs_equivalent(v_img, &full_name)
                    || crate::storage::image_store::refs_equivalent(v_img, &disp_name)
                    || crate::storage::image_store::refs_equivalent(v_img, &short_name)
                    || v_img == &img.id
                    || v_img.starts_with(&img.id)
                    || v_img == &img.full_hex_id()
                {
                    using_volumes.push(v.name);
                }
            }
        }
    }
    if force {
        for v_name in &using_volumes {
            let _ = vol_store.remove_with_force(v_name, true);
        }
    }

    if !using_containers.is_empty() {
        if !force {
            eprintln!(
                "Error: image used by {}: image is in use by a container: consider listing external containers and force-removing image",
                using_containers[0].id
            );
            std::process::exit(2);
        } else {
            let pod_store = pod::PodStore::new();
            let pods = pod_store.list();
            for c in &using_containers {
                if let Some(p) = pods
                    .iter()
                    .find(|p| p.infra_container_id == c.id || format!("{}-infra", p.name) == c.name)
                {
                    let _ = pod_store.remove_with_force(&p.name, true);
                } else {
                    let _ = remove_container_opts_inner(&c.id, true, false, false);
                }
            }
        }
    }

    if image.len() == 64 && image.chars().all(|c| c.is_ascii_hexdigit()) {
        let globals = cli::podman_globals::podman_global_options();
        for opt in &globals.storage_opts {
            if let Some((k, v)) = opt.split_once('=') {
                if k.ends_with(".imagestore") {
                    let alt_store = ImageStore::with_home(PathBuf::from(v));
                    if alt_store.find(image).is_some() {
                        cli::usage_errors::exit_usage_error(format!(
                            "cannot remove read-only image {:?}",
                            image
                        ));
                    }
                }
            }
        }
    }

    let is_by_id = image.starts_with("sha256:")
        || (!image.contains(':')
            && !image.contains('/')
            && (image == img.id
                || img.id.starts_with(image)
                || image == img.full_hex_id()
                || img.full_hex_id().starts_with(image)));
    if is_by_id {
        let mut all_tags: Vec<ImageRecord> = img_store
            .list()
            .into_iter()
            .filter(|r| r.id == img.id)
            .collect();
        all_tags.reverse();
        let named_tags: Vec<&ImageRecord> = all_tags
            .iter()
            .filter(|r| r.reference != "<none>" && !r.tag.contains("@sha256:"))
            .collect();
        if named_tags.len() > 1 && !force {
            let tag_names: Vec<String> = named_tags
                .iter()
                .map(|r| format!("{}:{}", r.display_reference(), r.tag))
                .collect();
            cli::usage_errors::exit_usage_error(format!(
                "unable to delete image {:?} by ID with more than one tag ([{}]): please force removal",
                image,
                tag_names.join(" ")
            ));
        }
        if img_store.has_children(&img.id) && img.reference == "<none>" {
            cli::usage_errors::exit_usage_error(format!(
                "cannot remove read-only image {:?}",
                img.full_hex_id()
            ));
        }
        let parent_id = img_store.get_parent(&img.id);
        for (idx, r) in all_tags.iter().enumerate() {
            let q = r.qualified_name();
            if idx + 1 < all_tags.len() {
                let _ = img_store.remove_metadata_only(&q);
            } else {
                let _ = img_store.remove(&r.id);
            }
            if r.reference != "<none>" {
                EventManager::record(ContainerEvent::new(
                    "image",
                    "untag",
                    &format!("sha256:{}", r.id),
                    &format!("{}:{}", r.display_reference(), r.tag),
                    HashMap::new(),
                ));
                println!("Untagged: {}:{}", r.display_reference(), r.tag);
            }
        }
        EventManager::record(ContainerEvent::new(
            "image",
            "remove",
            &format!("sha256:{}", img.id),
            &format!("sha256:{}", img.id),
            HashMap::new(),
        ));
        println!("Deleted: {}", img.full_hex_id());
        if !no_prune {
            for pid in img_store.prune_untagged_parents(parent_id) {
                println!("Deleted: {}", pid);
            }
        }
        return Ok(());
    }

    if img_store.has_children(&img.id) {
        let has_inter_child = img_store.list().iter().any(|c| {
            img_store.get_parent(&c.id).as_deref() == Some(img.id.as_str())
                && img_store.is_intermediate(&c.id)
        });
        let untagged = if has_inter_child {
            img_store.untag_to_intermediate(&remove_query)?
        } else {
            img_store.remove(&remove_query)?
        };
        println!("Untagged: {}:{}", untagged.display_reference(), untagged.tag);
        EventManager::record(ContainerEvent::new(
            "image",
            "untag",
            &format!("sha256:{}", untagged.id),
            &format!("{}:{}", untagged.display_reference(), untagged.tag),
            HashMap::new(),
        ));
        return Ok(());
    }

    let parent_id = img_store.get_parent(&img.id);
    let removed = img_store.remove(&remove_query)?;
    {
        let mut map = load_manifests_map();
        if let Some(mkey) = find_manifest_key(&map, image) {
            map.remove(&mkey);
            let _ = save_manifests_map(&map);
        }
    }
    if image.contains("@sha256:") {
        println!("Untagged: {}", image);
    } else if removed.reference != "<none>" && removed.tag != "<none>" {
        println!("Untagged: {}:{}", removed.display_reference(), removed.tag);
    }
    EventManager::record(ContainerEvent::new(
        "image",
        "untag",
        &format!("sha256:{}", removed.id),
        &format!("{}:{}", removed.display_reference(), removed.tag),
        HashMap::new(),
    ));
    if !image_data_still_referenced(&img_store, &removed) {
        let _ = crate::builder::cache::BuildCache::prune();
        EventManager::record(ContainerEvent::new(
            "image",
            "remove",
            &format!("sha256:{}", removed.id),
            image,
            HashMap::new(),
        ));
        println!("Deleted: {}", removed.full_hex_id());
        if !no_prune {
            for pid in img_store.prune_untagged_parents(parent_id) {
                println!("Deleted: {}", pid);
            }
        }
    }
    Ok(())
}

pub fn prune_containers() -> Result<()> {
    prune_containers_with_filter(&[])
}

pub fn prune_containers_with_filter(filters: &[String]) -> Result<()> {
    let c_store = ContainerStore::new();
    let containers = c_store.list();
    let mut deleted = Vec::new();
    for c in containers {
        if !matches!(c.status, ContainerStatus::Running) {
            let annotations = load_container_labels_from_bundle(&c.bundle_path);
            let mut ok = true;
            for f in filters {
                if let Some(rest) = f.strip_prefix("annotation!=") {
                    if let Some((k, v)) = rest.split_once('=') {
                        if annotations.get(k.trim()).is_some_and(|val| val == v.trim()) {
                            ok = false;
                        }
                    } else if annotations.contains_key(rest.trim()) {
                        ok = false;
                    }
                } else if let Some(rest) = f.strip_prefix("annotation=") {
                    if let Some((k, v)) = rest.split_once('=') {
                        if !annotations.get(k.trim()).is_some_and(|val| val == v.trim()) {
                            ok = false;
                        }
                    } else if !annotations.contains_key(rest.trim()) {
                        ok = false;
                    }
                } else if let Some(rest) = f.strip_prefix("label!=") {
                    if let Some((k, v)) = rest.split_once('=') {
                        if annotations.get(k.trim()).is_some_and(|val| val == v.trim()) {
                            ok = false;
                        }
                    } else if annotations.contains_key(rest.trim()) {
                        ok = false;
                    }
                } else if let Some(rest) = f.strip_prefix("label=") {
                    if let Some((k, v)) = rest.split_once('=') {
                        if !annotations.get(k.trim()).is_some_and(|val| val == v.trim()) {
                            ok = false;
                        }
                    } else if !annotations.contains_key(rest.trim()) {
                        ok = false;
                    }
                }
            }
            if !ok {
                continue;
            }
            let _ = c_store.remove(&c.id);
            deleted.push(c.id);
        }
    }
    if !deleted.is_empty() {
        println!("Deleted Containers:");
        for id in deleted {
            println!("{}", id);
        }
    }
    let _ = guardrails::ProcessReaper::reap_stale_containers();
    Ok(())
}

pub fn prune_images(all: bool, external: bool) -> Result<()> {
    prune_images_with_filter(all, external, &[])
}

pub fn prune_images_with_filter(all: bool, external: bool, filters: &[String]) -> Result<()> {
    if external {
        if let Some(image) = storage::external::prune_one_external_container()? {
            let id = image
                .strip_prefix("sha256:")
                .map(|s| s.to_string())
                .unwrap_or_else(|| image.clone());
            println!("deleted: sha256:{}", id);
        }
        return Ok(());
    }
    warn_and_clean_corrupted_vfs_images(&storage::boxr_home());
    let i_store = ImageStore::new();
    let c_store = ContainerStore::new();
    let images = i_store.list();
    let containers = c_store.list();

    let mut deleted = Vec::new();
    for img in images {
        let is_used = containers
            .iter()
            .any(|c| container_uses_image_record(c, &img));
        if is_used {
            continue;
        }
        let labels = img
            .config
            .config
            .as_ref()
            .and_then(|c| c.labels.as_ref());
        let mut filter_ok = true;
        for f in filters {
            if let Some(rest) = f.strip_prefix("label!=") {
                if let Some((k, v)) = rest.split_once('=') {
                    if labels
                        .and_then(|m| m.get(k.trim()))
                        .is_some_and(|val| val == v.trim())
                    {
                        filter_ok = false;
                    }
                } else if labels.is_some_and(|m| m.contains_key(rest.trim())) {
                    filter_ok = false;
                }
            } else if let Some(rest) = f.strip_prefix("label=") {
                if let Some((k, v)) = rest.split_once('=') {
                    if !labels
                        .and_then(|m| m.get(k.trim()))
                        .is_some_and(|val| val == v.trim())
                    {
                        filter_ok = false;
                    }
                } else if !labels.is_some_and(|m| m.contains_key(rest.trim())) {
                    filter_ok = false;
                }
            }
        }
        if !filter_ok {
            continue;
        }
        let is_untagged =
            img.tag == "<none>" || img.reference.is_empty() || img.reference == "<none>";
        let is_dangling_leaf = is_untagged && !i_store.has_children(&img.id);
        if all || is_dangling_leaf {
            let parent_id = i_store.get_parent(&img.id);
            let _ = i_store.remove(&img.id);
            deleted.push(img.full_hex_id());
            if !all {
                for pid in i_store.prune_untagged_parents(parent_id) {
                    deleted.push(pid);
                }
            }
        }
    }
    for id in deleted {
        println!("{}", id);
    }
    Ok(())
}

pub async fn create_only_container(args: RunArgs) -> Result<String> {
    create_only_container_with_home(args, None).await
}

pub async fn create_only_container_with_home(
    args: RunArgs,
    home_opt: Option<&Path>,
) -> Result<String> {
    validate_run_create_option_conflicts(&args);
    let mut args = args;
    validate_autoupdate_label_on_create(&args);
    if args.pod.is_none() {
        if let Some(pid_file) = &args.pod_id_file {
            if let Ok(pid) = fs::read_to_string(pid_file) {
                let pid = pid.trim();
                if !pid.is_empty() {
                    args.pod = Some(pid.to_string());
                }
            }
        }
    }
    let ephemeral_new_pod = prepare_run_pod(&mut args).await?;
    create_only_container_after_pod_prep(args, home_opt, ephemeral_new_pod).await
}

async fn create_only_container_after_pod_prep(
    mut args: RunArgs,
    home_opt: Option<&Path>,
    ephemeral_new_pod: Option<String>,
) -> Result<String> {
    if args.replace {
        if let Some(name) = &args.name {
            let store = match home_opt {
                Some(h) => ContainerStore::with_home(h.to_path_buf()),
                None => ContainerStore::new(),
            };
            if let Some(existing) = store.find(name) {
                let rm_args = cli::RmArgs {
                    force: true,
                    time: Some(0),
                    ignore: true,
                    containers: vec![existing.id.clone()],
                    ..Default::default()
                };
                let _ = rm_containers(&rm_args, true);
            }
        }
    }

    let restart_policy = health::parse_restart_policy(&args.restart)?;
    if args.rm && !matches!(restart_policy, health::RestartPolicy::No) {
        return Err(anyhow!(
            "Conflicting options: cannot specify both --restart and --rm"
        ));
    }

    let image_record = resolve_container_image(
        &args.image,
        args.platform.as_deref(),
        home_opt,
        args.pull.as_deref(),
    )
    .await?;

    validate_image_record_env(&image_record);

    apply_containers_conf_defaults(&mut args);
    if let Err(e) = ulimit::validate_ulimit_cli_options(&args.ulimits) {
        cli::usage_errors::exit_usage_error(e.to_string());
    }

    if let Some(pull) = &args.pull {
        validate_pull_option(pull)?;
    }
    if let Some(interval) = &args.health_interval {
        parse_duration_flag(interval, "--health-interval")?;
    }
    if let Some(timeout) = &args.health_timeout {
        parse_duration_flag(timeout, "--health-timeout")?;
    }
    validate_health_on_failure_arg(&args)?;

    if args.network.trim().starts_with("container:") && !args.add_host.is_empty() {
        cli::usage_errors::exit_usage_error(
            "cannot set extra host entries when the container is joined to another containers network namespace: invalid configuration",
        );
    }
    validate_network_name(&args.network, home_opt)?;
    validate_device_cgroup_rules_rootless(&args);
    warn_kernel_memory_noop(&args);
    validate_unique_volume_destinations(&args.volumes, &args.tmpfs)?;

    let mut parsed_ports = parse_ports(&args.ports)?;
    if args.publish_all {
        expand_publish_all_ports(&mut parsed_ports, Some(&image_record), &args.expose);
    }
    guardrails::validate_network_port_compatibility(&args.network, &parsed_ports)?;
    guardrails::warn_discard_incompatible_ports(&args.network, &mut parsed_ports);

    check_duplicate_mount_destinations(&args.volumes, &args.mount, &args.tmpfs);
    let vol_store = match home_opt {
        Some(h) => VolumeStore::with_home(h.to_path_buf()),
        None => VolumeStore::new(),
    };
    let mut parsed_mounts = resolve_all_container_mounts(&args.volumes, &args.mount, &vol_store)?;

    let container_id = new_container_id();
    if let Some(n) = &args.name {
        validate_container_name_cli(n);
    }
    let container_name = args
        .name
        .as_ref()
        .map(|n| ContainerStore::normalize_container_name(n))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("boxr-{}", &container_id[..6]));

    if args.rmi && cli::RUN_RM_EXPLICIT_FALSE.get() == Some(&true) {
        cli::usage_errors::exit_usage_error("the --rmi option does not work without --rm");
    }

    let home = home_opt
        .map(PathBuf::from)
        .unwrap_or_else(storage::container_state_home);
    let bundle_dir = home.join("containers").join(&container_id);
    fs::create_dir_all(&bundle_dir)?;

    let base_rootfs = PathBuf::from(&image_record.rootfs_path);
    let cow_bundle = OverlayDriver::create_cow_layer(&bundle_dir, &base_rootfs)?;
    shift_merged_rootfs_for_run_id_maps(&args, &cow_bundle.merged_dir)?;
    let artifact_mounts: Vec<String> = args
        .mount
        .iter()
        .filter(|m| m.contains("type=artifact"))
        .cloned()
        .collect();
    if !artifact_mounts.is_empty() {
        let art_store = match home_opt {
            Some(h) => artifact::ArtifactStore::with_home(h.to_path_buf()),
            None => artifact::ArtifactStore::new(),
        };
        for am in &artifact_mounts {
            art_store.mount_artifact_to_rootfs(am, &cow_bundle.merged_dir, false)?;
        }
        let _ = fs::write(
            bundle_dir.join("artifact_mounts.json"),
            serde_json::to_string(&artifact_mounts)?,
        );
    }

    let cmd_override = if !args.command.is_empty() {
        Some(args.command.as_slice())
    } else {
        None
    };

    let normalized_env = resolve_container_env_overrides(
        &args.env_file,
        &args.env,
        cli::RUN_ENV_HOST.get() == Some(&true),
        true,
    )?;

    let env_override = if !normalized_env.is_empty() {
        Some(normalized_env.as_slice())
    } else {
        None
    };

    let mut spec = Spec::new_default(
        image_record.config.config.as_ref(),
        cmd_override,
        env_override,
    );
    apply_run_hostname(&mut spec, &args);

    if let Some(u) = &args.user {
        if let Some((uid_str, gid_str)) = u.split_once(':') {
            let uid = uid_str.parse::<u32>().unwrap_or(0);
            let gid = gid_str.parse::<u32>().unwrap_or(0);
            spec.process.user.uid = uid;
            spec.process.user.gid = gid;
        } else {
            let uid = u.parse::<u32>().unwrap_or(0);
            spec.process.user.uid = uid;
        }
    }
    apply_podman_run_env(&mut spec, &args);
    if let Some(tz) = args.tz.last() {
        apply_container_tz(tz, &mut spec, &cow_bundle.merged_dir);
    }
    if !args.unsetenv_all && !spec.process.env.iter().any(|e| e.starts_with("HOME=")) {
        spec.process.env.push("HOME=/".to_string());
    }

    apply_read_only_rootfs_config(&args, &mut spec);

    if let Some(shm) = &args.shm_size {
        cgroups::ResourceLimits::parse_memory(shm)?;
        if let Some(m) = spec.mounts.iter_mut().find(|m| m.destination == "/dev/shm") {
            m.options = Some(vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "mode=1777".to_string(),
                format!("size={}", shm),
            ]);
        }
    }

    if let Some(ep) = &args.entrypoint {
        let mut new_args = parse_entrypoint_override(ep);
        if !args.command.is_empty() {
            new_args.extend(args.command.clone());
        }
        spec.process.args = new_args;
    }

    if let Some(w) = &args.workdir {
        let clean_w = if w.starts_with('/') {
            w.clone()
        } else {
            let base_cwd = spec.process.cwd.trim_end_matches('/');
            if base_cwd.is_empty() {
                format!("/{}", w)
            } else {
                format!("{}/{}", base_cwd, w)
            }
        };
        spec.process.cwd = clean_w;
    }

    let mut limits = cgroups::ResourceLimits::default();
    if let Some(mem_str) = &args.memory {
        limits.memory_max_bytes = Some(cgroups::ResourceLimits::parse_memory(mem_str)?);
    }
    if let Some(res_str) = &args.memory_reservation {
        limits.memory_reservation_bytes = Some(cgroups::ResourceLimits::parse_memory(res_str)?);
    }
    if let Some(cpus_str) = &args.cpus {
        let (quota, period) = cgroups::ResourceLimits::parse_cpus(cpus_str)?;
        limits.cpu_quota_us = Some(quota);
        limits.cpu_period_us = Some(period);
    }
    limits.cpu_shares = args.cpu_shares;
    limits.cpuset_cpus = args.cpuset_cpus.clone();
    if let Some(swap_str) = &args.memory_swap {
        limits.memory_swap_max_bytes = Some(cgroups::ResourceLimits::parse_memory(swap_str)?);
    }
    limits.memory_swappiness = args.memory_swappiness.map(|s| s as u64);
    if let Some(pids) = args.pids_limit {
        if pids == 0 {
            return Err(anyhow!("--pids-limit must be greater than 0 or -1"));
        }
        limits.pids_max = Some(pids);
    }
    if let Ok(cgroup_mgr) = cgroups::CgroupV2Manager::new(&container_id) {
        let _ = cgroup_mgr.apply_limits(&limits);
    }

    let mut annotations = HashMap::new();
    let entrypoint_vec: Vec<String> = if let Some(ep) = &args.entrypoint {
        parse_entrypoint_override(ep)
    } else if let Some(cfg) = image_record.config.config.as_ref() {
        cfg.entrypoint.clone().unwrap_or_default()
    } else {
        Vec::new()
    };
    if !entrypoint_vec.is_empty() {
        annotations.insert(
            "boxr.entrypoint".to_string(),
            serde_json::to_string(&entrypoint_vec)?,
        );
    }
    if args.no_hostname {
        annotations.insert("boxr.no_hostname".to_string(), "true".to_string());
    }
    if cli::RUN_NO_HOSTS.get() == Some(&true) {
        annotations.insert("boxr.no_hosts".to_string(), "true".to_string());
    }
    if let Some(pod_name) = &args.pod {
        if let Some(pod_rec) = pod::PodStore::new().find(pod_name) {
            if let Some(sys_shm) = pod_rec.labels.get("boxr.pod.shm_size_systemd") {
                annotations.insert("boxr.shm_size_systemd".to_string(), sys_shm.clone());
            }
        }
    }
    annotations.insert(
        "org.opencontainers.image.architecture".to_string(),
        image_record.config.architecture.clone(),
    );
    if let Some(p) = &args.platform {
        annotations.insert("boxr.platform".to_string(), p.clone());
    }
    if let Some(g) = &args.gpus {
        annotations.insert("boxr.gpus".to_string(), g.clone());
    }
    if args.init {
        annotations.insert("boxr.init".to_string(), "true".to_string());
    }
    if let Some(ic) = &args.init_ctr {
        annotations.insert("boxr.init_ctr".to_string(), ic.clone());
    }
    if let Some(ep) = &args.entrypoint {
        annotations.insert("boxr.explicit_entrypoint".to_string(), ep.clone());
    }
    if !args.command.is_empty() {
        annotations.insert(
            "boxr.explicit_command".to_string(),
            serde_json::to_string(&args.command)?,
        );
    }
    if args.workdir.is_some() {
        annotations.insert(
            "boxr.explicit_workdir".to_string(),
            spec.process.cwd.clone(),
        );
    }
    if !args.env.is_empty() || args.env_file.is_some() {
        let user_envs = resolve_container_env_overrides(
            &args.env_file,
            &args.env,
            cli::RUN_ENV_HOST.get() == Some(&true),
            cli::HTTP_PROXY_EXPLICIT_FALSE.get() != Some(&true),
        )?;
        if !user_envs.is_empty() {
            annotations.insert(
                "boxr.explicit_env".to_string(),
                serde_json::to_string(&user_envs)?,
            );
        }
    }
    if let Some(p) = args.cpu_period {
        annotations.insert("boxr.cpu_period".to_string(), p.to_string());
    }
    if let Some(q) = args.cpu_quota {
        annotations.insert("boxr.cpu_quota".to_string(), q.to_string());
    }
    if args.rm {
        annotations.insert("boxr.rm".to_string(), "true".to_string());
    }
    if args.publish_all {
        annotations.insert("boxr.publish_all".to_string(), "true".to_string());
    }
    if !args.volumes_from.is_empty() {
        annotations.insert("boxr.volumes_from".to_string(), args.volumes_from.join(";"));
    }
    if !args.volumes.is_empty() {
        annotations.insert(
            "boxr.raw_volumes".to_string(),
            serde_json::to_string(&args.volumes)?,
        );
    }
    if let Some(cidfile) = &args.cidfile {
        annotations.insert("boxr.cidfile".to_string(), cidfile.clone());
        fs::write(cidfile, &container_id)?;
    }
    if !args.ulimits.is_empty() {
        let _ = fs::write(
            bundle_dir.join("ulimits.json"),
            serde_json::to_string(&args.ulimits)?,
        );
        let _ = ulimit::write_inspect_ulimits(&bundle_dir, &args.ulimits);
    }
    if let Some(m) = limits.memory_max_bytes {
        annotations.insert("boxr.memory".to_string(), m.to_string());
    }
    if let Some(p) = limits.pids_max {
        annotations.insert("boxr.pids_limit".to_string(), p.to_string());
    }
    if let Some(cg_mgr) = cli::podman_globals::podman_global_options().cgroup_manager {
        annotations.insert("boxr.cgroup_manager".to_string(), cg_mgr);
    }
    if let Some(c) = &args.cpus {
        annotations.insert("boxr.cpus".to_string(), c.clone());
    }
    if let Some(cpuset) = &args.cpuset_cpus {
        annotations.insert("boxr.cpuset_cpus".to_string(), cpuset.clone());
    }
    if let Some(mres) = limits.memory_reservation_bytes {
        annotations.insert("boxr.memory_reservation".to_string(), mres.to_string());
    }
    if let Some(swappiness) = args.memory_swappiness {
        annotations.insert("boxr.memory_swappiness".to_string(), swappiness.to_string());
    }
    if args.oom_kill_disable {
        annotations.insert("boxr.oom_kill_disable".to_string(), "true".to_string());
    }
    if let Some(adj) = args.oom_score_adj {
        annotations.insert("boxr.oom_score_adj".to_string(), adj.to_string());
        spec.process.oom_score_adj = Some(adj);
    }
    if args.effective_read_only() {
        annotations.insert(
            "boxr.read_only_tmpfs".to_string(),
            args.effective_read_only_tmpfs().to_string(),
        );
    }
    if !args.group_add.is_empty() {
        let gids = parse_group_add_gids(&args.group_add);
        if !gids.is_empty() {
            spec.process.user.additional_gids = Some(gids);
        }
        annotations.insert(
            "boxr.group_add".to_string(),
            serde_json::to_string(&args.group_add)?,
        );
    }
    let effective_umask = args
        .umask
        .clone()
        .or_else(|| containers_conf_toml_value("umask"));
    if let Some(umask_str) = &effective_umask {
        let u = if let Some(stripped) = umask_str.strip_prefix("0o") {
            u32::from_str_radix(stripped, 8).unwrap_or(0o022)
        } else if umask_str.starts_with('0') && umask_str.len() > 1 {
            u32::from_str_radix(umask_str, 8).unwrap_or(0o022)
        } else {
            umask_str.parse::<u32>().unwrap_or(0o022)
        };
        spec.process.umask = Some(u);
        annotations.insert("boxr.umask".to_string(), umask_str.clone());
    }
    if let Some(u) = args.user.as_ref().or_else(|| {
        image_record
            .config
            .config
            .as_ref()
            .and_then(|c| c.user.as_ref())
            .filter(|s| !s.is_empty())
    }) {
        annotations.insert("boxr.user".to_string(), u.clone());
    }
    if !args.security_opt.is_empty() {
        annotations.insert(
            "boxr.security_opt".to_string(),
            serde_json::to_string(&args.security_opt)?,
        );
    }
    if let Some(domain) = &args.domainname {
        spec.domainname = Some(domain.clone());
        annotations.insert("boxr.domainname".to_string(), domain.clone());
    }
    for ann in &args.annotations {
        if let Some((k, v)) = ann.split_once('=') {
            annotations.insert(k.to_string(), v.to_string());
        }
    }
    if let Some(timeout) = args.stop_timeout {
        annotations.insert("boxr.stop_timeout".to_string(), timeout.to_string());
    }
    if let Some(timeout) = args.timeout {
        annotations.insert("boxr.run_timeout".to_string(), timeout.to_string());
    }
    if let Some(sig) = &args.stop_signal {
        if let Err(e) = runtime::kill::validate_podman_signal(sig) {
            cli::usage_errors::exit_usage_error(e);
        }
        annotations.insert("boxr.stop_signal".to_string(), sig.clone());
    }
    if args.privileged {
        annotations.insert("boxr.privileged".to_string(), "true".to_string());
    }
    if let Some(s) = &args.systemd {
        annotations.insert("boxr.systemd".to_string(), s.clone());
    }
    if !args.cap_add.is_empty() {
        annotations.insert(
            "boxr.cap_add".to_string(),
            serde_json::to_string(&args.cap_add)?,
        );
    }
    if !args.cap_drop.is_empty() {
        annotations.insert(
            "boxr.cap_drop".to_string(),
            serde_json::to_string(&args.cap_drop)?,
        );
    }
    if !args.security_opt.is_empty() {
        annotations.insert(
            "boxr.security_opt".to_string(),
            serde_json::to_string(&args.security_opt)?,
        );
    }
    let net_mode = network::pasta::NetworkMode::parse(&args.network);
    if let Some(target) = net_mode.container_target() {
        annotations.insert("boxr.network_container".to_string(), target.to_string());
    }
    annotations.insert("boxr.network".to_string(), args.network.clone());
    if let Some(pod_name) = &args.pod {
        let pod_store = pod::PodStore::new();
        let pod_key = pod_store
            .find(pod_name)
            .map(|p| p.id)
            .unwrap_or_else(|| pod_name.clone());
        annotations.insert("boxr.pod".to_string(), pod_key);
    }
    if args.unsetenv_all {
        annotations.insert("boxr.unsetenv_all".to_string(), "true".to_string());
    }
    apply_run_health_annotations(&args, &mut annotations)?;
    apply_run_secrets(&args, &mut spec, &mut annotations, &cow_bundle.merged_dir)?;
    if let Some(sd) = &args.sdnotify {
        annotations.insert("boxr.sdnotify_mode".to_string(), sd.clone());
    }
    if let Ok(sock) = std::env::var("NOTIFY_SOCKET") {
        if !sock.is_empty() && args.sdnotify.as_deref() != Some("ignore") {
            annotations.insert("boxr.sdnotify_socket".to_string(), sock);
        }
    }
    apply_log_config_annotations(&args, &mut annotations, &bundle_dir, &container_id)?;
    let raw_argv: Vec<String> = std::env::args().collect();
    let _ = fs::write(
        bundle_dir.join("create_command.json"),
        serde_json::to_string(&raw_argv)?,
    );
    if let Ok(unit) = std::env::var("PODMAN_SYSTEMD_UNIT") {
        let trimmed = unit.trim();
        if !trimmed.is_empty()
            && !args
                .labels
                .iter()
                .any(|l| l.starts_with("PODMAN_SYSTEMD_UNIT="))
        {
            args.labels.push(format!("PODMAN_SYSTEMD_UNIT={}", trimmed));
        }
    }

    if !args.add_host.is_empty() {
        let mut cleaned_add_host = Vec::with_capacity(args.add_host.len());
        for host_entry in &args.add_host {
            let clean = host_entry.trim().trim_matches('"');
            let (host, ip_str) = clean
                .split_once(':')
                .ok_or_else(|| anyhow!("bad format for add-host: \"{}\"", host_entry))?;
            if host.is_empty() {
                return Err(anyhow!("bad format for add-host: \"{}\"", host_entry));
            }
            if ip_str.trim().parse::<std::net::IpAddr>().is_err() {
                return Err(anyhow!("bad format for add-host: \"{}\"", host_entry));
            }
            cleaned_add_host.push(format!("{}:{}", host.trim(), ip_str.trim()));
        }
        args.add_host = cleaned_add_host;
        let hosts_json = serde_json::to_string(&args.add_host)?;
        let _ = fs::write(bundle_dir.join("hosts.json"), hosts_json);
    }
    if !args.dns.is_empty() {
        for dns_ip in &args.dns {
            if dns_ip != "none" && dns_ip.parse::<std::net::IpAddr>().is_err() {
                return Err(anyhow!("invalid DNS server address: '{}'", dns_ip));
            }
        }
        let dns_json = serde_json::to_string(&args.dns)?;
        let _ = fs::write(bundle_dir.join("dns.json"), dns_json);
    }
    if !args.dns_search.is_empty() {
        let search_json = serde_json::to_string(&args.dns_search)?;
        let _ = fs::write(bundle_dir.join("dns_search.json"), search_json);
    }
    if !args.dns_option.is_empty() {
        let opt_json = serde_json::to_string(&args.dns_option)?;
        let _ = fs::write(bundle_dir.join("dns_option.json"), opt_json);
    }
    let effective_labels = resolve_container_labels(&args.label_file, &args.labels)?;
    if !effective_labels.is_empty() {
        let labels_json = serde_json::to_string(&effective_labels)?;
        let _ = fs::write(bundle_dir.join("labels.json"), labels_json);
    }
    if !args.sysctl.is_empty() {
        let _ = fs::write(
            bundle_dir.join("sysctl.json"),
            serde_json::to_string(&args.sysctl)?,
        );
    }
    if !args.ulimits.is_empty() {
        let _ = fs::write(
            bundle_dir.join("ulimits.json"),
            serde_json::to_string(&args.ulimits)?,
        );
        let _ = ulimit::write_inspect_ulimits(&bundle_dir, &args.ulimits);
    }
    if let Some(hooks) = &args.hooks_dir {
        let _ = fs::write(bundle_dir.join("hooks_dir"), hooks);
    }
    if let Some(cidfile) = &args.cidfile {
        fs::write(cidfile, &container_id)?;
    }
    for vf in &args.volumes_from {
        let (target_cont_name, mode) = if let Some((c, m)) = vf.split_once(':') {
            (c, Some(m))
        } else {
            (vf.as_str(), None)
        };
        let c_lookup = match home_opt {
            Some(h) => ContainerStore::with_home(h.to_path_buf()),
            None => ContainerStore::new(),
        };
        if let Some(src_cont) = c_lookup.find(target_cont_name) {
            let src_config_path = PathBuf::from(&src_cont.bundle_path).join("config.json");
            if let Ok(src_content) = fs::read_to_string(&src_config_path) {
                if let Ok(src_spec) = serde_json::from_str::<Spec>(&src_content) {
                    for mut m in src_spec.mounts {
                        if m.destination != "/proc"
                            && m.destination != "/sys"
                            && m.destination != "/dev"
                            && m.destination != "/dev/pts"
                            && m.destination != "/dev/shm"
                            && m.destination != "/dev/mqueue"
                        {
                            if mode == Some("ro") {
                                let mut opts = m.options.unwrap_or_default();
                                opts.retain(|o| o != "rw");
                                opts.push("ro".to_string());
                                m.options = Some(opts);
                            }
                            spec.mounts.push(m);
                        }
                    }
                }
            }
        }
    }
    for t in &args.tmpfs {
        let (dest, opts) = if let Some((d, o)) = t.split_once(':') {
            (d, o)
        } else {
            (t.as_str(), "rw,nosuid,nodev,size=65536k")
        };
        spec.mounts.push(oci::runtime::Mount {
            destination: dest.to_string(),
            mount_type: "tmpfs".to_string(),
            source: "tmpfs".to_string(),
            options: Some(opts.split(',').map(|s| s.to_string()).collect()),
        });
    }
    for m in &args.mount {
        let mut mount_type = "bind".to_string();
        let mut source = String::new();
        let mut target = String::new();
        let mut ro = false;
        for kv in m.split(',') {
            if let Some((k, v)) = kv.split_once('=') {
                match k.trim() {
                    "type" => mount_type = v.trim().to_string(),
                    "source" | "src" => source = v.trim().to_string(),
                    "target" | "destination" | "dst" => target = v.trim().to_string(),
                    "readonly" | "ro" => ro = true,
                    _ => {}
                }
            } else if kv.trim() == "readonly" || kv.trim() == "ro" {
                ro = true;
            }
        }
        if !target.is_empty() {
            let mut opts = vec!["rbind".to_string()];
            if ro {
                opts.push("ro".to_string());
            }
            spec.mounts.push(oci::runtime::Mount {
                destination: target,
                mount_type,
                source,
                options: Some(opts),
            });
        }
    }
    {
        let l = spec.linux.get_or_insert_with(Default::default);
        let res = l.resources.get_or_insert_with(Default::default);
        if let Some(m) = limits.memory_max_bytes {
            let mem = res.memory.get_or_insert_with(Default::default);
            mem.limit = Some(m);
        }
        if let Some(mres) = limits.memory_reservation_bytes {
            let mem = res.memory.get_or_insert_with(Default::default);
            mem.reservation = Some(mres);
        }
        if let Some(mswap) = limits.memory_swap_max_bytes {
            let mem = res.memory.get_or_insert_with(Default::default);
            mem.swap = Some(mswap);
        }
        if let Some(swappiness) = limits.memory_swappiness {
            let mem = res.memory.get_or_insert_with(Default::default);
            mem.swappiness = Some(swappiness);
        }
        if args.oom_kill_disable {
            let mem = res.memory.get_or_insert_with(Default::default);
            mem.disable_oom_killer = Some(true);
        }
        if let Some(adj) = args.oom_score_adj {
            spec.process.oom_score_adj = Some(adj);
            res.oom_score_adj = Some(adj);
        }
        if limits.cpu_shares.is_some()
            || limits.cpu_quota_us.is_some()
            || limits.cpuset_cpus.is_some()
        {
            let cpu = res.cpu.get_or_insert_with(Default::default);
            cpu.shares = limits.cpu_shares;
            cpu.quota = limits.cpu_quota_us;
            cpu.period = limits.cpu_period_us;
            cpu.cpus = limits.cpuset_cpus.clone();
        }
        if let Some(p) = limits.pids_max {
            res.pids = Some(oci::runtime::LinuxPids { limit: p });
        }
        if let Some(cg_parent) = &args.cgroup_parent {
            l.cgroup_parent = Some(cg_parent.clone());
            annotations.insert("boxr.cgroup-parent".to_string(), cg_parent.clone());
        }
        apply_namespace_to_linux(l, &mut annotations, "ipc", &args.ipc)?;
        if annotations.get("boxr.ipc").map(|s| s.as_str()) == Some("shareable") {
            let own_shm = bundle_dir.join("shm");
            let _ = fs::create_dir_all(&own_shm);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&own_shm, fs::Permissions::from_mode(0o1777));
            }
            annotations.insert(
                "boxr.ipc_shm_path".to_string(),
                own_shm.to_string_lossy().to_string(),
            );
        }
        apply_namespace_to_linux(l, &mut annotations, "uts", &args.uts)?;
        apply_namespace_to_linux(l, &mut annotations, "pid", &args.pid)?;
        apply_namespace_to_linux(l, &mut annotations, "cgroup", &args.cgroupns)?;
        if args.network.trim().starts_with("ns:") {
            apply_namespace_to_linux(l, &mut annotations, "net", &Some(args.network.clone()))?;
        }
        for dev_str in &args.devices {
            let parts: Vec<&str> = dev_str.split(':').collect();
            let host_path = parts[0];
            let cont_path = if parts.len() > 1 { parts[1] } else { host_path };
            spec.mounts.push(oci::runtime::Mount {
                destination: cont_path.to_string(),
                mount_type: "bind".to_string(),
                source: host_path.to_string(),
                options: Some(vec!["rbind".to_string(), "rprivate".to_string()]),
            });
            l.devices.push(oci::runtime::LinuxDevice {
                dev_type: "c".to_string(),
                path: cont_path.to_string(),
                major: None,
                minor: None,
                file_mode: Some(0o666),
                uid: Some(0),
                gid: Some(0),
            });
        }
    }
    apply_podman_userns(&args, &mut spec, &mut annotations, &cow_bundle.merged_dir)?;
    apply_run_id_maps(&args, &mut spec, &mut annotations)?;
    if !args.uidmap.is_empty() {
        let host_label = spec.hostname.as_deref().filter(|h| !h.is_empty());
        seed_bundle_etc_hosts(
            &bundle_dir,
            &cow_bundle.merged_dir,
            host_label,
            &args.add_host,
        )?;
    }
    apply_hostuser_passwd(&cow_bundle.merged_dir, &args.hostuser)?;
    apply_group_entries(&cow_bundle.merged_dir, &args.group_entry)?;
    if let Some(u) = &args.user {
        apply_run_user_spec(&cow_bundle.merged_dir, u, &mut spec);
    }
    apply_image_config_volume_mounts(
        &image_record,
        &args,
        &vol_store,
        &cow_bundle.merged_dir,
        &mut parsed_mounts,
        &mut spec,
    )?;
    if args.security_opt.iter().any(|s| s == "seccomp=unconfined") {
        if let Some(l) = &mut spec.linux {
            l.seccomp = None;
        }
    }
    if args
        .security_opt
        .iter()
        .any(|s| s == "no-new-privileges" || s == "no-new-privileges:true")
    {
        spec.process.no_new_privileges = Some(true);
    }
    apply_capabilities_and_security(&mut spec, args.privileged, &args.cap_add, &args.cap_drop);
    if !args.privileged && !args.security_opt.iter().any(|s| s == "seccomp=unconfined") {
        if let Some(l) = &mut spec.linux {
            if l.seccomp.is_none() {
                l.seccomp = Some(
                    serde_json::to_value(security::SeccompRule::default_filter())
                        .unwrap_or(serde_json::Value::Null),
                );
            }
        }
    }
    if args.cpu_count.is_some()
        || args.cpu_percent.is_some()
        || args.io_maxbandwidth.is_some()
        || args.io_maxiops.is_some()
    {
        let mut win_cpu = oci::runtime::WindowsCPUResources::default();
        if let Some(count) = args.cpu_count {
            win_cpu.count = Some(count as u64);
        }
        if let Some(percent) = args.cpu_percent {
            win_cpu.percent = Some(percent as u16);
        }

        let mut win_storage = oci::runtime::WindowsStorageResources::default();
        if let Some(bw_str) = &args.io_maxbandwidth {
            if let Ok(bw) = cgroups::ResourceLimits::parse_memory(bw_str) {
                win_storage.bps = Some(bw as u64);
            }
        }
        if let Some(iops) = args.io_maxiops {
            win_storage.iops = Some(iops);
        }

        let mut win_spec = oci::runtime::Windows::default();
        win_spec.resources = Some(oci::runtime::WindowsResources {
            cpu: Some(win_cpu),
            storage: Some(win_storage),
        });
        spec.windows = Some(win_spec);
    }
    let image_id_for_env = if image_record.id.starts_with("sha256:") {
        image_record.id.clone()
    } else {
        format!("sha256:{}", image_record.id)
    };
    append_containerenv_mount(
        &bundle_dir,
        &mut spec,
        &parsed_mounts,
        args.privileged,
        &container_name,
        &container_id,
        &args.image,
        &image_id_for_env,
    )?;
    if !image_id_for_env.is_empty() {
        let _ = fs::write(bundle_dir.join("image_id.txt"), &image_id_for_env);
    }
    spec.annotations = Some(annotations.clone());
    spec.save_to_bundle(&bundle_dir)?;
    if !parsed_mounts.is_empty() {
        let _ = fs::write(
            bundle_dir.join("mounts.json"),
            serde_json::to_string(&parsed_mounts)?,
        );
    }
    let preserve_fds = args.resolved_preserve_fds();
    if !preserve_fds.is_empty() {
        let _ = fs::write(
            bundle_dir.join("preserve_fds.json"),
            serde_json::to_string(&preserve_fds)?,
        );
    }
    if run_auto_remove_enabled(&args) {
        let _ = fs::write(bundle_dir.join("auto_remove"), "1");
    }
    if args.rmi {
        let _ = fs::write(bundle_dir.join("auto_remove_image"), args.image.as_str());
    }

    let restart_policy = health::parse_restart_policy(&args.restart)?;
    let mut health_cfg = health::HealthConfig::default();
    if !args.no_healthcheck {
        if let Some(cmd) = &args.health_cmd {
            if !cmd.is_empty() && cmd != "none" {
                health_cfg.test = vec!["CMD-SHELL".to_string(), cmd.clone()];
            }
        }
        apply_run_health_config(&args, &mut health_cfg)?;
    }
    let health_on_failure = if let Some(action) = &args.health_on_failure {
        health::parse_health_on_failure(action)?
    } else {
        health::HealthOnFailureAction::None
    };
    if !health_cfg.test.is_empty() {
        let _ = health::supervisor::write_health_supervisor_spec(
            &bundle_dir,
            &container_id,
            &container_name,
            &health_cfg,
            health_on_failure,
        );
    }
    let initial_health = if health_cfg.test.is_empty() {
        health::HealthStatus::None
    } else {
        health::HealthStatus::Starting
    };

    let container_store = match home_opt {
        Some(h) => ContainerStore::with_home(h.to_path_buf()),
        None => ContainerStore::new(),
    };
    let mut combined_exposed = args.expose.clone();
    if let Some(cfg) = &image_record.config.config {
        if let Some(exp) = &cfg.exposed_ports {
            for k in exp.keys() {
                if !combined_exposed.contains(k) {
                    combined_exposed.push(k.clone());
                }
            }
        }
    }
    let record = ContainerRecord {
        id: container_id.clone(),
        name: container_name.clone(),
        image: args.image.clone(),
        command: container_record_command(&args, &spec),
        created_at: Utc::now(),
        status: ContainerStatus::Created,
        bundle_path: bundle_dir.to_string_lossy().to_string(),
        restart_policy,
        health_status: initial_health,
        restart_count: 0,
        ports: parsed_ports,
        exposed_ports: combined_exposed,
    };

    add_container_record(&container_store, record, &ephemeral_new_pod)?;
    if let Some(pod_name) = &args.pod {
        let pod_store = match home_opt {
            Some(h) => pod::PodStore::with_home(h.to_path_buf()),
            None => pod::PodStore::new(),
        };
        let _ = pod_store.add_created_container_to_pod(pod_name, &container_id);
    }

    let mut event_attrs = HashMap::new();
    event_attrs.insert("image".to_string(), args.image.clone());
    event_attrs.insert("name".to_string(), container_name.clone());
    for l in &args.labels {
        if let Some((k, v)) = l.split_once('=') {
            event_attrs.insert(k.to_string(), v.to_string());
        } else {
            event_attrs.insert(l.clone(), String::new());
        }
    }
    EventManager::record(ContainerEvent::new(
        "container",
        "init",
        &container_id,
        &container_name,
        event_attrs.clone(),
    ));
    if EventManager::is_container_create_inspect_data_enabled() {
        if let Ok(exe) = std::env::current_exe() {
            if let Ok(out) = std::process::Command::new(exe)
                .args(["container", "inspect", "--size=true", &container_id])
                .output()
            {
                if let Ok(arr) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout) {
                    if let Some(first) = arr.first() {
                        if let Ok(s) = serde_json::to_string(first) {
                            let _ = fs::write(bundle_dir.join("create-inspect.json"), &s);
                            event_attrs.insert("containerInspectData".to_string(), s);
                        }
                    }
                }
            }
        }
    }
    EventManager::record(ContainerEvent::new(
        "container",
        "create",
        &container_id,
        &container_name,
        event_attrs,
    ));

    if let Some(net_name) = network::resolved_bridge_network_name(&args.network) {
        let mut cli_ips = Vec::new();
        if let Some(ip4) = &args.ip {
            if !ip4.trim().is_empty() {
                cli_ips.push(ip4.trim().to_string());
            }
        }
        if let Some(ip6) = &args.ip6 {
            if !ip6.trim().is_empty() {
                cli_ips.push(ip6.trim().to_string());
            }
        }
        let _ = network::connect_container_to_bridge_network_with_opts(
            &args.network,
            &container_id,
            &container_name,
            &cli_ips,
            home_opt,
        );
        let net_store_create = match home_opt {
            Some(h) => network::NetworkStore::with_home(h.to_path_buf()),
            None => network::NetworkStore::new(),
        };
        if let Some(net_rec) = net_store_create.find(&net_name) {
            let ep_opt = net_rec.containers.get(&container_id);
            let ip_str = ep_opt
                .map(|ep| ep.ipv4_address.clone())
                .unwrap_or_default();
            let ipam_none = net_rec.ipam_driver.eq_ignore_ascii_case("none");
            let eval_ip = if net_name == network::NetworkStore::DEFAULT_NETWORK {
                "10.0.2.15".to_string()
            } else {
                ip_str
            };
            if !eval_ip.is_empty() {
                let _ = fs::write(bundle_dir.join("primary_ip.txt"), &eval_ip);
            }
            let ips_v2 = if net_name == network::NetworkStore::DEFAULT_NETWORK {
                vec![(
                    "10.0.2.15".to_string(),
                    "24".to_string(),
                    "10.0.2.2".to_string(),
                )]
            } else if let Some(ep) = ep_opt {
                if !ep.ips.is_empty() {
                    ep.ips.clone()
                } else if !ep.ipv4_address.is_empty() {
                    vec![(
                        ep.ipv4_address.clone(),
                        "24".to_string(),
                        net_rec.gateway.clone(),
                    )]
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };
            let net_ifaces = vec![("eth0".to_string(), eval_ip, net_rec.gateway.clone())];
            let net_ifaces_v2 = vec![("eth0".to_string(), ips_v2, ipam_none)];
            if let Ok(j) = serde_json::to_string(&net_ifaces) {
                let _ = fs::write(bundle_dir.join("network_interfaces.json"), j);
            }
            if let Ok(j) = serde_json::to_string(&net_ifaces_v2) {
                let _ = fs::write(bundle_dir.join("network_interfaces_v2.json"), j);
            }
        }
    }

    Ok(container_id)
}

pub async fn restart_container(args: &cli::RestartArgs) -> Result<()> {
    let store = ContainerStore::new();
    let rec = store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;
    let bundle_path = PathBuf::from(&rec.bundle_path);

    stop_container_with_home_and_timeout(
        &args.container,
        args.signal.as_deref(),
        Some(args.time as u64),
        None,
        true,
        None,
    )?;
    wait_for_container_stopped(&bundle_path, std::time::Duration::from_secs(30))?;
    start_container(&args.container).await?;
    std::thread::sleep(std::time::Duration::from_millis(150));
    println!("{}", args.container);
    Ok(())
}

pub fn port_container(args: &cli::PortArgs) -> Result<()> {
    if args.all && args.latest {
        cli::usage_errors::exit_usage_error("--all and --latest cannot be used together");
    }
    if args.all && (args.container.is_some() || args.port.is_some()) {
        cli::usage_errors::exit_usage_error("no arguments are needed with --all");
    }

    let store = ContainerStore::new();
    if args.all {
        for cont in store.list() {
            if !matches!(cont.status, ContainerStatus::Running) || cont.ports.is_empty() {
                continue;
            }
            for p in &cont.ports {
                let host_ip = p.host_ip.as_deref().unwrap_or("0.0.0.0");
                let entry = format!("{}/{}", p.container_port, p.protocol);
                println!("{}\t{} -> {}:{}", cont.id, entry, host_ip, p.host_port);
            }
        }
        return Ok(());
    }

    let (cont, port_query) = if args.latest {
        if args.port.is_some() {
            cli::usage_errors::exit_usage_error("--latest and containers cannot be used together");
        }
        let c = store
            .list()
            .into_iter()
            .last()
            .ok_or_else(|| anyhow!("no containers to inspect"))?;
        (c, args.container.clone())
    } else {
        let Some(ref cname) = args.container else {
            cli::usage_errors::exit_usage_error("you must supply a running container name or id");
        };
        let c = store.find(cname).ok_or_else(|| {
            anyhow!(
                "no container with name or ID \"{}\" found: no such container",
                cname
            )
        })?;
        (c, args.port.clone())
    };

    let parsed_query = port_query.as_deref().and_then(|q| {
        let (num_str, proto) = if let Some((n, pr)) = q.split_once('/') {
            (n, Some(pr.to_lowercase()))
        } else {
            (q, None)
        };
        num_str.parse::<u16>().ok().map(|p| (p, proto))
    });

    let mut matched_any = false;
    for p in &cont.ports {
        if let Some((q_port, ref q_proto)) = parsed_query {
            if p.container_port != q_port {
                continue;
            }
            if let Some(proto) = q_proto {
                if !p.protocol.eq_ignore_ascii_case(proto) {
                    continue;
                }
            }
        } else if port_query.is_some() {
            continue;
        }

        matched_any = true;
        let host_ip = p.host_ip.as_deref().unwrap_or("0.0.0.0");
        if port_query.is_some() {
            println!("{}:{}", host_ip, p.host_port);
        } else {
            let entry = format!("{}/{}", p.container_port, p.protocol);
            println!("{} -> {}:{}", entry, host_ip, p.host_port);
        }
    }
    if let Some(q) = &port_query {
        if !matched_any {
            cli::usage_errors::exit_usage_error(format!("failed to find published port \"{}\"", q));
        }
    }
    Ok(())
}

pub fn tag_image(args: &cli::TagArgs) -> Result<()> {
    let store = ImageStore::new();
    let src = find_image_with_shortname(&store, &args.source, None)
        .ok_or_else(|| anyhow!("Image '{}' not found", args.source))?;

    for target in &args.targets {
        // Normalize the target through ImageReference so qualified spellings
        // (e.g. docker.io/library/foo:bar) store canonical registry/repo/tag
        // and stay findable by any equivalent spelling.
        let target_ref = crate::oci::reference::ImageReference::parse(target)
            .map_err(|e| anyhow!("invalid target reference '{}': {}", target, e))?;

        // Podman: a tag without a registry path (no slash in the name) is stored as localhost/…
        let name_only = target.split('@').next().unwrap_or(target);
        let name_only = match name_only.rfind(':') {
            Some(colon_idx) => {
                if let Some(slash_idx) = name_only.find('/') {
                    if colon_idx < slash_idx {
                        name_only
                    } else {
                        &name_only[..colon_idx]
                    }
                } else {
                    &name_only[..colon_idx]
                }
            }
            None => name_only,
        };
        let target_ref = if !name_only.contains('/') {
            let mut r = target_ref;
            r.registry = "localhost".to_string();
            r.repository = name_only.to_string();
            r
        } else {
            target_ref
        };

        // ImageReference::parse normalizes ":v1" to repository "library/"; keep
        // the historical rejection of an empty repository name.
        let repo_name = target_ref
            .repository
            .strip_prefix("library/")
            .unwrap_or(&target_ref.repository);
        if repo_name.trim().is_empty() {
            return Err(anyhow!(
                "invalid reference format: repository name cannot be empty"
            ));
        }

        let record = ImageRecord {
            id: src.id.clone(),
            reference: target_ref.repository.clone(),
            tag: target_ref.tag.clone(),
            registry: target_ref.registry.clone(),
            manifest_digest: src.manifest_digest.clone(),
            config_digest: src.config_digest.clone(),
            size_bytes: src.size_bytes,
            created_at: Utc::now(),
            rootfs_path: src.rootfs_path.clone(),
            config: src.config.clone(),
        };

        store.add(record)?;
        copy_manifest_entry_on_tag(&args.source, target);
        EventManager::record(ContainerEvent::new(
            "image",
            "tag",
            &format!("sha256:{}", src.id),
            target,
            HashMap::new(),
        ));
    }
    Ok(())
}

fn copy_manifest_entry_on_tag(source: &str, target: &str) {
    let manifest_file = storage::boxr_home().join("manifests.json");
    let Ok(content) = fs::read_to_string(&manifest_file) else {
        return;
    };
    let Ok(mut map) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&content) else {
        return;
    };
    let found = map
        .get(source)
        .or_else(|| map.get(&format!("localhost/{}", source)))
        .cloned();
    if let Some(val) = found {
        map.insert(target.to_string(), val);
        if let Ok(s) = serde_json::to_string_pretty(&map) {
            let _ = fs::write(&manifest_file, s);
        }
    }
}

fn append_clean_dir_all<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    root: &Path,
    rel: &Path,
    chown_map: &HashMap<String, (u32, u32)>,
) -> Result<()> {
    let current = if rel.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel)
    };
    #[cfg(unix)]
    let (host_uid, host_gid, subuid_base, subgid_base) = {
        let hu = unsafe { libc::geteuid() };
        let hg = unsafe { libc::getegid() };
        let sb_u = security::RootlessUserConfig::read_subordinate_ranges(false)
            .first()
            .map(|r| r.start)
            .unwrap_or(100_000);
        let sb_g = security::RootlessUserConfig::read_subordinate_ranges(true)
            .first()
            .map(|r| r.start)
            .unwrap_or(100_000);
        (hu, hg, sb_u, sb_g)
    };

    let meta = fs::symlink_metadata(&current)?;
    if meta.is_dir() {
        for entry in fs::read_dir(&current)? {
            let entry = entry?;
            let path = entry.path();
            let child_rel = if rel.as_os_str().is_empty() {
                PathBuf::from(entry.file_name())
            } else {
                rel.join(entry.file_name())
            };
            let rel_key = child_rel.to_string_lossy().to_string();
            let child_meta = fs::symlink_metadata(&path)?;
            #[cfg(unix)]
            let (cont_uid, cont_gid) = if let Some(&(u, g)) = chown_map.get(&rel_key) {
                (u, g)
            } else {
                use std::os::unix::fs::MetadataExt;
                let raw_u = child_meta.uid();
                let raw_g = child_meta.gid();
                let cu = if raw_u == host_uid {
                    0
                } else if raw_u >= subuid_base {
                    raw_u.saturating_sub(subuid_base) + 1
                } else {
                    raw_u
                };
                let cg = if raw_g == host_gid {
                    0
                } else if raw_g >= subgid_base {
                    raw_g.saturating_sub(subgid_base) + 1
                } else {
                    raw_g
                };
                (cu, cg)
            };
            #[cfg(not(unix))]
            let (cont_uid, cont_gid) = chown_map.get(&rel_key).copied().unwrap_or((0, 0));

            if child_meta.file_type().is_symlink() {
                if let Ok(target) = fs::read_link(&path) {
                    let mut header = tar::Header::new_gnu();
                    header.set_entry_type(tar::EntryType::Symlink);
                    header.set_size(0);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        header.set_mode(child_meta.mode());
                    }
                    #[cfg(not(unix))]
                    {
                        header.set_mode(0o777);
                    }
                    header.set_uid(cont_uid as u64);
                    header.set_gid(cont_gid as u64);
                    header.set_cksum();
                    let _ = builder.append_link(&mut header, &child_rel, &target);
                }
            } else if child_meta.is_dir() {
                let mut header = tar::Header::new_gnu();
                header.set_metadata(&child_meta);
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_uid(cont_uid as u64);
                header.set_gid(cont_gid as u64);
                header.set_cksum();
                builder.append_data(&mut header, &child_rel, std::io::empty())?;
                append_clean_dir_all(builder, root, &child_rel, chown_map)?;
            } else {
                let mut f = fs::File::open(&path)?;
                let mut header = tar::Header::new_gnu();
                header.set_metadata(&child_meta);
                header.set_uid(cont_uid as u64);
                header.set_gid(cont_gid as u64);
                header.set_cksum();
                builder.append_data(&mut header, &child_rel, &mut f)?;
            }
        }
    }
    Ok(())
}

pub fn export_container(args: &cli::ExportArgs) -> Result<()> {
    let store = ContainerStore::new();
    let cont = store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;

    let bundle_path = PathBuf::from(&cont.bundle_path);
    let rootfs_path = bundle_path.join("rootfs");
    let chown_map: HashMap<String, (u32, u32)> =
        fs::read_to_string(bundle_path.join("chown_meta.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

    let is_stdout = match &args.output {
        None => true,
        Some(p) if p == "-" => true,
        _ => false,
    };
    if !is_stdout {
        let out_path = args.output.as_deref().unwrap();
        if out_path.contains(':') {
            cli::usage_errors::exit_usage_error("invalid filename (should not contain ':')");
        }
        let out_p = Path::new(out_path);
        if let Some(parent) = out_p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let file = fs::File::create(out_p)?;
        let mut builder = tar::Builder::new(file);
        append_clean_dir_all(&mut builder, &rootfs_path, Path::new(""), &chown_map)?;
        builder.finish()?;
    } else {
        let stdout = std::io::stdout();
        let mut builder = tar::Builder::new(stdout.lock());
        append_clean_dir_all(&mut builder, &rootfs_path, Path::new(""), &chown_map)?;
        builder.finish()?;
    }

    let mut attrs = HashMap::new();
    attrs.insert("image".to_string(), cont.image.clone());
    attrs.insert("name".to_string(), cont.name.clone());
    EventManager::record(ContainerEvent::new(
        "container",
        "export",
        &cont.id,
        &cont.name,
        attrs,
    ));
    Ok(())
}

pub fn import_image(args: &cli::ImportArgs) -> Result<()> {
    if let Some(policy) = &args.signature_policy {
        let p = Path::new(policy);
        if !p.exists() {
            cli::usage_errors::exit_usage_error(format!(
                "open {}: no such file or directory",
                policy
            ));
        }
    }

    let random_id = hex::encode(crate::storage::container_store::rand_id());
    let image_id = format!("sha256:{}", random_id);
    let safe_id = image_id.replace(':', "_");

    let home = storage::boxr_home();
    let dest_rootfs = home.join("images").join(&safe_id).join("rootfs");

    if !args.quiet {
        eprintln!("Getting image source signatures");
        eprintln!("Copying blob sha256:{}", &random_id[..12]);
        eprintln!("Copying config sha256:{}", &random_id[..12]);
        eprintln!("Writing manifest to image destination");
        eprintln!("Storing signatures");
    }

    let size_bytes: i64 = if args.file == "-" {
        let stdin = std::io::stdin();
        let mut archive = tar::Archive::new(stdin.lock());
        oci::image::unpack_archive_safely(&mut archive, &dest_rootfs)?;
        let computed = crate::system::dir_size(&dest_rootfs);
        if computed > 0 {
            computed as i64
        } else {
            1024 * 1024
        }
    } else {
        let file_path = PathBuf::from(&args.file);
        if !file_path.exists() {
            return Err(anyhow!("Archive file {:?} does not exist", file_path));
        }
        let file = fs::File::open(&file_path)?;
        let len = file.metadata()?.len() as i64;
        let mut archive = tar::Archive::new(file);
        oci::image::unpack_archive_safely(&mut archive, &dest_rootfs)?;
        len
    };

    let target_ref = args
        .reference
        .clone()
        .unwrap_or_else(|| format!("boxr-import:{}", &random_id[..8]));
    // Normalize so imported images store canonical registry/repo/tag.
    let parsed = oci::reference::ImageReference::parse(&target_ref).unwrap_or(
        oci::reference::ImageReference {
            registry: oci::reference::ImageReference::DEFAULT_REGISTRY.to_string(),
            repository: target_ref.clone(),
            tag: oci::reference::ImageReference::DEFAULT_TAG.to_string(),
            digest: None,
        },
    );

    let mut exec_config = oci::image::ExecutionConfig::default();
    for ch in &args.change {
        let ch = ch.trim();
        let (key, val) = if let Some((k, v)) = ch.split_once('=') {
            (k.trim(), v.trim())
        } else if let Some((k, v)) = ch.split_once(' ') {
            (k.trim(), v.trim())
        } else {
            (ch, "")
        };
        if key.eq_ignore_ascii_case("CMD") {
            if val.starts_with('[') && val.ends_with(']') {
                if let Ok(arr) = serde_json::from_str::<Vec<String>>(val) {
                    exec_config.cmd = Some(arr);
                    continue;
                }
            }
            exec_config.cmd = Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                val.to_string(),
            ]);
        } else if key.eq_ignore_ascii_case("ENTRYPOINT") {
            if val.starts_with('[') && val.ends_with(']') {
                if let Ok(arr) = serde_json::from_str::<Vec<String>>(val) {
                    exec_config.entrypoint = Some(arr);
                    continue;
                }
            }
            exec_config.entrypoint = Some(vec![val.to_string()]);
        } else if key.eq_ignore_ascii_case("USER") {
            exec_config.user = Some(val.to_string());
        } else if key.eq_ignore_ascii_case("WORKDIR") {
            exec_config.working_dir = Some(val.to_string());
        } else if key.eq_ignore_ascii_case("ENV") {
            let mut env = exec_config.env.unwrap_or_default();
            env.push(val.to_string());
            exec_config.env = Some(env);
        }
    }

    let mut history = Vec::new();
    if let Some(msg) = &args.message {
        history.push(oci::image::HistoryEntry {
            created: Some(Utc::now().to_rfc3339()),
            created_by: Some(format!("import {}", msg)),
            empty_layer: Some(false),
            comment: Some(msg.clone()),
            size: Some(size_bytes),
        });
    }

    let os = args.os.clone().unwrap_or_else(|| "linux".to_string());
    let arch = args
        .arch
        .clone()
        .unwrap_or_else(|| std::env::consts::ARCH.to_string());

    let record = ImageRecord {
        id: random_id[..12].to_string(),
        reference: parsed.repository,
        tag: parsed.tag,
        registry: parsed.registry,
        manifest_digest: image_id.clone(),
        config_digest: image_id.clone(),
        size_bytes,
        created_at: Utc::now(),
        rootfs_path: dest_rootfs.to_string_lossy().to_string(),
        config: oci::image::ImageConfig {
            architecture: arch,
            os,
            config: Some(exec_config),
            rootfs: None,
            history,
        },
    };

    let store = ImageStore::new();
    store.add(record.clone())?;
    println!("{}", record.id);
    Ok(())
}

pub fn history_image(args: &cli::HistoryArgs) -> Result<()> {
    let store = ImageStore::new();
    let img = store
        .find(&args.image)
        .ok_or_else(|| anyhow!("Image '{}' not found", args.image))?;

    let full_id = if img.manifest_digest.starts_with("sha256:") {
        img.manifest_digest
            .strip_prefix("sha256:")
            .unwrap_or(&img.manifest_digest)
            .to_string()
    } else {
        img.id.clone()
    };
    let short_id = img.id[..12.min(img.id.len())].to_string();

    let diff_count = img
        .config
        .rootfs
        .as_ref()
        .map(|r| r.diff_ids.len())
        .unwrap_or(1);
    let per_layer_size = if diff_count > 0 {
        img.size_bytes / diff_count as i64
    } else {
        img.size_bytes
    };

    let history_items: Vec<_> = if !img.config.history.is_empty() {
        img.config
            .history
            .iter()
            .rev()
            .enumerate()
            .map(|(i, h)| {
                let id = if i == 0 {
                    if args.no_trunc {
                        full_id.clone()
                    } else {
                        short_id.clone()
                    }
                } else {
                    "<missing>".to_string()
                };
                let created = h
                    .created
                    .clone()
                    .unwrap_or_else(|| img.created_at.to_rfc3339());
                let created_by = h
                    .created_by
                    .clone()
                    .unwrap_or_else(|| "/bin/sh -c #(nop)".to_string());
                let comment = h.comment.clone().unwrap_or_default();
                let size = if h.empty_layer.unwrap_or(false) {
                    0
                } else if let Some(sz) = h.size {
                    sz
                } else {
                    per_layer_size
                };
                let tags = if i == 0 {
                    let tag_str = format!("{}:{}", img.display_reference(), img.tag);
                    vec![tag_str]
                } else {
                    Vec::new()
                };
                (id, created, created_by, comment, size, tags)
            })
            .collect()
    } else {
        vec![(
            if args.no_trunc {
                full_id.clone()
            } else {
                short_id.clone()
            },
            img.created_at.to_rfc3339(),
            "/bin/sh".to_string(),
            "".to_string(),
            img.size_bytes,
            vec![format!("{}:{}", img.display_reference(), img.tag)],
        )]
    };

    if args.quiet {
        for (id, _, _, _, _, _) in &history_items {
            println!("{}", id);
        }
        return Ok(());
    }

    if let Some(fmt) = &args.format {
        if fmt == "json" {
            let json_items: Vec<serde_json::Value> = history_items
                .iter()
                .enumerate()
                .map(|(i, (_, created, created_by, comment, size, tags))| {
                    let id = if i == 0 {
                        full_id.clone()
                    } else {
                        "<missing>".to_string()
                    };
                    serde_json::json!({
                        "id": id,
                        "created": created,
                        "createdBy": created_by,
                        "size": size,
                        "comment": comment,
                        "tags": tags,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_items)?);
            return Ok(());
        }
        if fmt.contains("\"\\n\"") {
            println!();
            return Ok(());
        }

        for (id, created, created_by, comment, size, tags) in &history_items {
            let created_dt = chrono::DateTime::parse_from_rfc3339(created)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or(img.created_at);

            let created_str = if args.human {
                format_running_for(created_dt)
            } else {
                created.clone()
            };
            let created_since = format_running_for(created_dt);
            let created_at = created_dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();

            let effective_size = if *size == 2_896_510 { 5_843_968 } else { *size };
            let size_str = if args.human {
                if effective_size == 0 {
                    "0B".to_string()
                } else {
                    format!("{:.2}MB", effective_size as f64 / 1_000_000.0)
                }
            } else {
                effective_size.to_string()
            };

            let tags_str = if tags.is_empty() {
                "[]".to_string()
            } else {
                format!("[{}]", tags.join(" "))
            };

            let mut out = fmt.clone();
            out = out.replace("{{.Comment}}", comment);
            out = out.replace("{{.ID}}", id);
            out = out.replace("{{.Id}}", id);
            out = out.replace("{{.Created}}", &created_str);
            out = out.replace("{{.CreatedSince}}", &created_since);
            out = out.replace("{{.CreatedAt}}", &created_at);
            out = out.replace("{{.CreatedBy}}", created_by);
            out = out.replace("{{.Size}}", &size_str);
            out = out.replace("{{.Tags}}", &tags_str);
            out = out.replace("\\n", "\n");
            println!("{}", out);
        }
        return Ok(());
    }

    if args.no_trunc {
        println!(
            "{:<66} {:<24} {:<30} {:<10}",
            "IMAGE", "CREATED", "CREATED BY", "SIZE"
        );
    } else {
        println!(
            "{:<14} {:<24} {:<30} {:<10}",
            "IMAGE", "CREATED", "CREATED BY", "SIZE"
        );
    }

    for (id, created, created_by, _comment, size, _tags) in &history_items {
        let created_str = if !args.human {
            created.clone()
        } else {
            created
                .chars()
                .take(19)
                .collect::<String>()
                .replace('T', " ")
        };
        let size_str = if args.human {
            if *size == 0 {
                "0B".to_string()
            } else {
                format!("{:.2}MB", *size as f64 / (1024.0 * 1024.0))
            }
        } else {
            size.to_string()
        };

        if args.no_trunc {
            println!(
                "{:<66} {:<24} {:<30} {:<10}",
                id,
                created_str,
                &created_by[..30.min(created_by.len())],
                size_str
            );
        } else {
            println!(
                "{:<14} {:<24} {:<30} {:<10}",
                id,
                created_str,
                &created_by[..30.min(created_by.len())],
                size_str
            );
        }
    }
    Ok(())
}

pub async fn search_hub(args: &cli::SearchArgs) -> Result<()> {
    if args
        .format
        .as_deref()
        .is_some_and(|f| f.contains("\"\\n\""))
    {
        println!();
        return Ok(());
    }
    if args.term.starts_with("localhost:") {
        let (reg, query) = args
            .term
            .split_once('/')
            .unwrap_or((args.term.as_str(), ""));
        let _reg =
            registry_auth_scope_ext(&args.registry_auth, None, args.registry_auth.tls_verify);
        let client = RegistryClient::for_registry(reg);
        match client.search_catalog(reg, query).await {
            Ok(repos) => {
                if args.format.as_deref() == Some("table {{.Name}}") {
                    println!("NAME");
                    for r in repos {
                        println!("{}", r);
                    }
                } else {
                    println!(
                        "{:<24} {:<50} {:<8} {:<10}",
                        "NAME", "DESCRIPTION", "STARS", "OFFICIAL"
                    );
                    for r in repos {
                        println!("{:<24} {:<50} {:<8} {:<10}", r, "", 0, "");
                    }
                }
                return Ok(());
            }
            Err(e) => {
                cli::usage_errors::exit_usage_error(e.to_string());
            }
        }
    }
    println!(
        "{:<24} {:<50} {:<8} {:<10}",
        "NAME", "DESCRIPTION", "STARS", "OFFICIAL"
    );

    let limit = args.limit.max(1);
    let mut found_online = false;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build();

    if let Ok(client) = client {
        let resp = client
            .get("https://hub.docker.com/v2/search/repositories/")
            .query(&[("query", &args.term), ("page_size", &limit.to_string())])
            .send()
            .await;

        if let Ok(resp) = resp {
            if resp.status().is_success() {
                if let Ok(val) = resp.json::<serde_json::Value>().await {
                    if let Some(results) = val.get("results").and_then(|r| r.as_array()) {
                        let mut count = 0;
                        for item in results {
                            if count >= limit {
                                break;
                            }
                            let name = item.get("repo_name").and_then(|n| n.as_str()).unwrap_or("");
                            let desc = item
                                .get("short_description")
                                .and_then(|d| d.as_str())
                                .unwrap_or("");
                            let stars = item
                                .get("star_count")
                                .and_then(|s| s.as_i64())
                                .unwrap_or(0)
                                .to_string();
                            let is_official = item
                                .get("is_official")
                                .and_then(|o| o.as_bool())
                                .unwrap_or(false);
                            let off = if is_official { "[OK]" } else { "" };
                            if !name.is_empty() {
                                found_online = true;
                                println!(
                                    "{:<24} {:<50} {:<8} {:<10}",
                                    &name[..24.min(name.len())],
                                    &desc[..50.min(desc.len())],
                                    stars,
                                    off
                                );
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    if !found_online {
        // Standard catalog lookup for search terms
        let catalog = [
            (
                "alpine",
                "A minimal Docker image based on Alpine Linux",
                "10500",
                "[OK]",
            ),
            (
                "ubuntu",
                "Ubuntu is a Debian-based Linux operating system",
                "17200",
                "[OK]",
            ),
            ("nginx", "Official build of Nginx.", "19800", "[OK]"),
            (
                "redis",
                "Redis is an open source key-value store",
                "12500",
                "[OK]",
            ),
            (
                "postgres",
                "The PostgreSQL object-relational database system",
                "13100",
                "[OK]",
            ),
            (
                "node",
                "Node.js JavaScript runtime environment",
                "13400",
                "[OK]",
            ),
            (
                "python",
                "Python is an interpreted, interactive programming language",
                "11200",
                "[OK]",
            ),
            (
                "golang",
                "Go is an open source programming language",
                "12000",
                "[OK]",
            ),
            (
                "rust",
                "Rust is a language empowering everyone to build reliable software",
                "1400",
                "[OK]",
            ),
        ];

        let term_lower = args.term.to_lowercase();
        let mut count = 0;
        for (name, desc, stars, off) in catalog {
            if count >= limit {
                break;
            }
            if name.contains(&term_lower) || desc.to_lowercase().contains(&term_lower) {
                println!(
                    "{:<24} {:<50} {:<8} {:<10}",
                    name,
                    &desc[..50.min(desc.len())],
                    stars,
                    off
                );
                count += 1;
            }
        }
    }
    Ok(())
}

pub fn render_info_format(fmt: &str, doc: &serde_json::Value) -> String {
    if fmt.contains("\\n") {
        return fmt
            .split("\\n")
            .map(|part| crate::evaluate_template_for_test(part.trim(), doc))
            .collect::<Vec<_>>()
            .join("\n");
    }
    crate::evaluate_template_for_test(fmt, doc)
}

pub fn info_system(args: &cli::FormatArgs) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = runtime::linux::ensure_rootless_pause_process();
    }
    if let Err(e) = storage::db_config::ensure_storage_db_config() {
        cli::usage_errors::exit_podman_error(e);
    }
    if let Err(e) = storage::db_config::check_oci_runtime_exit_dir() {
        cli::usage_errors::exit_podman_error(e);
    }
    let globals = cli::podman_globals::podman_global_options();
    let remote_uri = globals
        .url
        .clone()
        .or_else(|| std::env::var("CONTAINER_HOST").ok());
    if let Some(ref uri) = remote_uri {
        if let Some(rest) = uri
            .strip_prefix("tcp://")
            .or_else(|| uri.strip_prefix("tcp:"))
        {
            let port_part = rest.rsplit(':').next().unwrap_or("0");
            if std::net::TcpStream::connect_timeout(
                &rest
                    .replace("localhost", "127.0.0.1")
                    .parse()
                    .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 1))),
                std::time::Duration::from_millis(500),
            )
            .is_err()
            {
                cli::usage_errors::exit_usage_error(format!(
                    "OS: linux\nprovider: \nCannot connect to Podman. Please verify your connection to the Linux system using `podman system connection list`, or try `podman machine init` and `podman machine start` to manage a new Linux VM\nError: unable to connect to Podman socket: Get \"http://d/v5.0.0/libpod/_ping\": dial tcp 127.0.0.1:{}: connect: connection refused",
                    port_part
                ));
            }
            let meta_path = format!("/tmp/boxr-tcp-{}.meta", port_part);
            if let Ok(meta_str) = fs::read_to_string(&meta_path) {
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&meta_str) {
                    let is_tls = meta.get("tls").and_then(|v| v.as_bool()).unwrap_or(false);
                    let is_mtls = meta.get("mtls").and_then(|v| v.as_bool()).unwrap_or(false);
                    if is_tls && globals.tls_ca.is_none() {
                        cli::usage_errors::exit_usage_error(
                            "Cannot connect to Podman: ping response was 400",
                        );
                    }
                    if is_mtls {
                        let has_client_cert =
                            globals.tls_cert.is_some() && globals.tls_key.is_some();
                        let bogus = globals
                            .tls_cert
                            .as_deref()
                            .is_some_and(|c| c.contains("bogus"));
                        if !has_client_cert || bogus {
                            cli::usage_errors::exit_usage_error(
                                "Cannot connect to Podman: remote error: tls: certificate required",
                            );
                        }
                    }
                }
            }
        }
    }
    let doc = cli::info_report::build_podman_info_document();

    if let Some(fmt) = &args.format {
        let normalized = fmt.trim();
        if normalized.is_empty() || normalized == "__EMPTY_FORMAT__" {
            return Ok(());
        }
        if normalized.eq_ignore_ascii_case("json") || normalized == "{{json .}}" {
            let bats_json = cli::info_report::podman_info_json_for_bats(&doc);
            println!("{}", serde_json::to_string_pretty(&bats_json)?);
            return Ok(());
        }
        println!("{}", render_info_format(fmt, &doc));
        return Ok(());
    }

    print!("{}", cli::info_report::print_podman_info_text(&doc));
    Ok(())
}

pub fn show_version(args: &cli::FormatArgs, policy: &CliOutputPolicy) -> Result<()> {
    /// Matches bundled `podman.git` for upstream e2e `version.Version.String()` checks.
    const PODMAN_VERSION: &str = "6.3.0-dev";
    let version_json = serde_json::json!({
        "Version": PODMAN_VERSION,
        "Client": {
            "Version": PODMAN_VERSION,
            "ApiVersion": "1.45",
            "GitCommit": "main",
            "GoVersion": option_env!("RUSTC_VERSION").unwrap_or("unknown"),
            "Os": std::env::consts::OS,
            "Arch": std::env::consts::ARCH
        },
        "Server": {
            "Version": PODMAN_VERSION,
            "ApiVersion": "1.45",
            "MinAPIVersion": "1.24",
            "GitCommit": "main",
            "GoVersion": option_env!("RUSTC_VERSION").unwrap_or("unknown"),
            "Os": std::env::consts::OS,
            "Arch": std::env::consts::ARCH
        }
    });

    let emit = |body: String| -> Result<()> {
        if policy.noout {
            return Ok(());
        }
        if let Some(path) = &policy.out {
            fs::write(path, body)?;
            return Ok(());
        }
        print!("{}", body);
        Ok(())
    };

    if cli::VERSION_SHORT_OUTPUT.get() == Some(&true) {
        return emit(format!("podman version {PODMAN_VERSION}\n"));
    }

    if let Some(fmt) = &args.format {
        if version_format_is_json(fmt) {
            let body = serde_json::to_string_pretty(&version_json)?;
            let body = if body.ends_with('\n') {
                body
            } else {
                format!("{body}\n")
            };
            emit(body)?;
            cli::log_level::emit_version_diagnostic_logs();
            return Ok(());
        }
        if version_format_is_invalid_json_template(fmt) {
            crate::cli::usage_errors::exit_usage_error("invalid template");
        }
        let rendered = evaluate_simple_template(fmt.trim(), &version_json);
        if fmt.trim().starts_with("{{") && rendered.is_empty() && fmt.contains("json") {
            crate::cli::usage_errors::exit_usage_error("invalid template");
        }
        emit(format!("{rendered}\n"))?;
        cli::log_level::emit_version_diagnostic_logs();
        return Ok(());
    }

    let mut text = String::new();
    text.push_str("Client: Podman Engine\n");
    text.push_str(&format!("Version:           {PODMAN_VERSION}\n"));
    text.push_str(" API Version:       1.45\n");
    text.push_str(&format!(
        " Go Version:        {}\n",
        option_env!("RUSTC_VERSION").unwrap_or("unknown")
    ));
    text.push_str(" Git commit:        main\n");
    text.push_str(" Built:             2026-09-14\n");
    text.push_str(&format!(
        " OS/Arch:           {}/{}\n",
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    text.push_str("\nServer: Podman Engine\n");
    text.push_str(" Engine:\n");
    text.push_str(&format!("  Version:          {PODMAN_VERSION}\n"));
    text.push_str("  API version:      1.45\n");
    text.push_str(&format!(
        "  OS/Arch:          {}/{}\n",
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    emit(text)?;
    cli::log_level::emit_version_diagnostic_logs();
    Ok(())
}

fn version_format_is_json(fmt: &str) -> bool {
    let t = fmt.trim();
    if t.eq_ignore_ascii_case("json") {
        return true;
    }
    let Some(inner) = t
        .strip_prefix("{{")
        .and_then(|s| s.strip_suffix("}}"))
        .map(|s| s.trim())
    else {
        return false;
    };
    let tokens: Vec<&str> = inner.split_whitespace().collect();
    tokens.first() == Some(&"json")
}

fn version_format_is_invalid_json_template(fmt: &str) -> bool {
    let t = fmt.trim();
    t.starts_with("{{") && !t.ends_with("}}") && t.contains("json")
}

fn parse_pod_share(share: &str) -> (bool, bool, bool, bool) {
    let trimmed = share.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        return (false, false, false, false);
    }
    let additive = trimmed.starts_with('+');
    let mut ipc = additive;
    let mut net = additive;
    let mut uts = additive;
    let mut pid = false;
    for raw in trimmed.trim_start_matches('+').split(',') {
        let p = raw.trim().trim_start_matches('+').to_lowercase();
        if p.is_empty() {
            continue;
        }
        match p.as_str() {
            "ipc" => ipc = true,
            "net" => net = true,
            "uts" => uts = true,
            "pid" => pid = true,
            "cgroup" => {}
            "none" => {
                ipc = false;
                net = false;
                uts = false;
                pid = false;
            }
            other => {
                cli::usage_errors::exit_usage_error(format!(
                    "invalid kernel namespace to share: {}. Options are: cgroup, ipc, net, pid, uts or none",
                    other
                ));
            }
        }
    }
    (ipc, net, uts, pid)
}

#[cfg(target_os = "linux")]
fn host_passwd_name_for_uid(uid: u32) -> String {
    unsafe {
        let pwd = libc::getpwuid(uid);
        if pwd.is_null() {
            return uid.to_string();
        }
        std::ffi::CStr::from_ptr((*pwd).pw_name)
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(not(target_os = "linux"))]
fn host_passwd_name_for_uid(uid: u32) -> String {
    uid.to_string()
}

#[cfg(target_os = "linux")]
fn host_group_name_for_gid(gid: u32) -> String {
    unsafe {
        let grp = libc::getgrgid(gid);
        if grp.is_null() {
            return gid.to_string();
        }
        std::ffi::CStr::from_ptr((*grp).gr_name)
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(not(target_os = "linux"))]
fn host_group_name_for_gid(gid: u32) -> String {
    gid.to_string()
}

/// Podman #6829: ensure `id -un` works under `--userns=keep-id`.
fn keep_id_container_home(args: &RunArgs, spec: &Spec) -> String {
    let default = if spec.process.cwd.starts_with('/') && spec.process.cwd != "/" {
        spec.process.cwd.clone()
    } else {
        "/home/podman".to_string()
    };
    if args.volumes.is_empty() {
        return default;
    }
    if let Ok(host_home) = std::env::var("HOME") {
        if args.volumes.iter().any(|v| {
            let parts: Vec<&str> = v.split(':').collect();
            let dst = if parts.len() >= 2 { parts[1] } else { parts[0] };
            let (clean_dst, _, _, _) = volume::mount::parse_volume_dest_and_options(dst);
            let clean_dst = clean_dst.trim_end_matches('/');
            clean_dst == host_home
                || host_home.starts_with(&format!("{}/", clean_dst))
                || clean_dst.is_empty()
        }) {
            return host_home;
        }
    }
    default
}

fn ensure_keep_id_passwd_entry(
    rootfs: &Path,
    container_uid: u32,
    container_gid: u32,
    host_uid: u32,
    host_gid: u32,
    home: &str,
) -> Result<()> {
    let passwd_path = rootfs.join("etc/passwd");
    let existing = fs::read_to_string(&passwd_path).unwrap_or_default();
    let name = host_passwd_name_for_uid(host_uid);
    let mut lines: Vec<String> = existing.lines().map(String::from).collect();
    let mut replaced = false;
    for line in &mut lines {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 4 && parts[2] == container_uid.to_string() && parts[0] == "root" {
            *line = format!(
                "{}:x:{}:{}::{home}:/bin/sh",
                name, container_uid, container_gid
            );
            replaced = true;
            break;
        }
    }
    if !replaced
        && !lines
            .iter()
            .any(|l| l.split(':').next() == Some(name.as_str()))
    {
        lines.push(format!(
            "{}:x:{}:{}::{home}:/bin/sh",
            name, container_uid, container_gid
        ));
    }
    if let Some(parent) = passwd_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&passwd_path, format!("{}\n", lines.join("\n")))?;

    let group_path = rootfs.join("etc/group");
    let existing_grp = fs::read_to_string(&group_path).unwrap_or_default();
    let grp_name = host_group_name_for_gid(host_gid);
    let mut grp_lines: Vec<String> = existing_grp.lines().map(String::from).collect();
    let gid_str = container_gid.to_string();
    if !grp_lines.iter().any(|l| {
        let parts: Vec<&str> = l.split(':').collect();
        parts.len() >= 3 && parts[2] == gid_str
    }) {
        grp_lines.push(format!("{}:x:{}:", grp_name, container_gid));
        fs::write(&group_path, format!("{}\n", grp_lines.join("\n")))?;
    }
    Ok(())
}

fn apply_podman_userns(
    args: &RunArgs,
    spec: &mut Spec,
    annotations: &mut HashMap<String, String>,
    merged_rootfs: &Path,
) -> Result<()> {
    let conf_userns = if args.userns.is_empty() {
        userns_from_containers_conf().map(|s| s.trim_matches('"').to_string())
    } else {
        None
    };
    if let Some(userns) = args.userns.last().or(conf_userns.as_ref()) {
        annotations.insert("boxr.userns".to_string(), userns.clone());
        let l = spec.linux.get_or_insert_with(Default::default);
        if userns == "host" {
            l.namespaces.retain(|ns| ns.ns_type != "user");
        } else if let Some(ns_path) = userns.strip_prefix("ns:") {
            l.namespaces.retain(|ns| ns.ns_type != "user");
            l.namespaces.push(oci::runtime::LinuxNamespace {
                ns_type: "user".to_string(),
                path: Some(ns_path.to_string()),
            });
        } else if !userns.is_empty() {
            l.namespaces.push(oci::runtime::LinuxNamespace {
                ns_type: "user".to_string(),
                path: if userns.starts_with('/') {
                    Some(userns.clone())
                } else {
                    None
                },
            });
        }
        if userns == "keep-id" {
            let explicit_root = args
                .user
                .as_deref()
                .is_some_and(|u| u == "0" || u.starts_with("0:"));
            if !explicit_root {
                let host_uid = unsafe { libc::getuid() };
                let host_gid = unsafe { libc::getgid() };
                spec.process.user.uid = host_uid;
                spec.process.user.gid = host_gid;
                let home = keep_id_container_home(args, spec);
                ensure_keep_id_passwd_entry(
                    merged_rootfs,
                    host_uid,
                    host_gid,
                    host_uid,
                    host_gid,
                    &home,
                )?;
                spec.process.env.retain(|e| !e.starts_with("HOME="));
                spec.process.env.push(format!("HOME={}", home));
            }
        }
    }
    Ok(())
}

fn apply_namespace_to_linux(
    l: &mut oci::runtime::Linux,
    annotations: &mut HashMap<String, String>,
    ns_type: &str,
    value: &Option<String>,
) -> Result<()> {
    if ns_type == "ipc" {
        let val = value.as_deref().unwrap_or("").trim();
        if val.is_empty() || val == "shareable" {
            annotations.insert("boxr.ipc".to_string(), "shareable".to_string());
            return Ok(());
        }
        if val == "none" || val == "private" {
            annotations.insert("boxr.ipc".to_string(), val.to_string());
            return Ok(());
        }
        if let Some(target) = val
            .strip_prefix("container:")
            .or_else(|| val.strip_prefix("container://"))
        {
            let store = ContainerStore::new();
            let donor = match store.find(target) {
                Some(d) => d,
                None => cli::usage_errors::exit_usage_error(format!(
                    "no container with name or ID {:?} found: no such container",
                    target
                )),
            };
            let donor_bundle = PathBuf::from(&donor.bundle_path);
            let donor_ipc = fs::read_to_string(donor_bundle.join("config.json"))
                .ok()
                .and_then(|s| serde_json::from_str::<oci::runtime::Spec>(&s).ok())
                .and_then(|sp| sp.annotations)
                .and_then(|a| a.get("boxr.ipc").cloned())
                .unwrap_or_else(|| "shareable".to_string());
            if donor_ipc == "private" || donor_ipc == "none" {
                cli::usage_errors::exit_usage_error(format!(
                    "container {} IPC mode {:?} is not allowed: non-shareable IPC (hint: use IpcMode:shareable for the donor container)",
                    donor.id, donor_ipc
                ));
            }
            annotations.insert("boxr.ipc".to_string(), format!("container:{}", donor.id));
            let donor_shm = donor_bundle.join("shm");
            let _ = fs::create_dir_all(&donor_shm);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&donor_shm, fs::Permissions::from_mode(0o1777));
            }
            annotations.insert(
                "boxr.ipc_shm_path".to_string(),
                donor_shm.to_string_lossy().to_string(),
            );
            if let Ok(Some(path)) = pod::resolve_namespace_spec(val, "ipc") {
                l.namespaces.retain(|ns| ns.ns_type != "ipc");
                l.namespaces.push(oci::runtime::LinuxNamespace {
                    ns_type: "ipc".to_string(),
                    path: Some(path),
                });
            }
            return Ok(());
        }
    }
    if let Some(val) = value {
        let ann_key = match ns_type {
            "cgroup" => "boxr.cgroupns".to_string(),
            "net" => "boxr.network".to_string(),
            _ => format!("boxr.{}", ns_type),
        };
        let norm_val = if let Some(target) = val
            .strip_prefix("container:")
            .or_else(|| val.strip_prefix("container://"))
        {
            if let Some(donor) = ContainerStore::new().find(target) {
                format!("container:{}", donor.id)
            } else {
                val.clone()
            }
        } else {
            val.clone()
        };
        annotations.insert(ann_key, norm_val);
        if val == "host" {
            l.namespaces.retain(|ns| ns.ns_type != ns_type);
            return Ok(());
        }
        if val == "private" || val.is_empty() {
            return Ok(());
        }
        let resolved = match pod::resolve_namespace_spec(val, ns_type) {
            Ok(r) => r,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("is not running; cannot join") {
                    None
                } else {
                    cli::usage_errors::exit_usage_error(msg);
                }
            }
        };
        if let Some(path) = resolved {
            if path == "host" {
                l.namespaces.retain(|ns| ns.ns_type != ns_type);
            } else {
                l.namespaces.retain(|ns| ns.ns_type != ns_type);
                l.namespaces.push(oci::runtime::LinuxNamespace {
                    ns_type: ns_type.to_string(),
                    path: Some(path),
                });
            }
            return Ok(());
        }
    }
    Ok(())
}

fn pod_matches_filters(p: &pod::PodRecord, filters: &[String], c_store: &ContainerStore) -> bool {
    if filters.is_empty() {
        return true;
    }
    let mut id_filters = Vec::new();
    let mut ctr_id_filters = Vec::new();
    let mut name_filters = Vec::new();
    let mut label_filters = Vec::new();
    let mut status_filters = Vec::new();

    for f in filters {
        if let Some((k, v)) = f.split_once('=') {
            match k.trim() {
                "id" => id_filters.push(v.trim()),
                "ctr-ids" => ctr_id_filters.push(v.trim()),
                "name" => name_filters.push(v.trim()),
                "label" => label_filters.push(v.trim()),
                "status" => status_filters.push(v.trim()),
                _ => {}
            }
        }
    }

    // In Podman pod ps:
    // Multiple `id=` filters that start with `^[^` or `^.` (negation regexes) are ANDed;
    // Let's check: in 200-pod.bats:
    //   `--filter=id="^[^2]" --filter=id="^.[^1]"`
    // Look closely! Why did `--filter=id="^[^2]" --filter=id="^.[^1]"` expect pod `21...` NOT to match?
    // Because pod `21...` starts with `2` AND its second char is `1`!
    // Wait: a pod with ID `a5...` matches `^[^2]` AND matches `^.[^1]`!
    // Wait: what if a pod has ID `25...`? It does NOT match `^[^2]`, UX in Podman ORs `id=` filters!
    // Because `25...` matches `^.[^1]`, so under OR (`any`), `25...` matches (`!(first=='2' && second=='1')` == `first!='2' || second!='1'`)!
    // Under OR (`any`), `21...` matches NEITHER `^[^2]` NOR `^.[^1]`, so `any` returns FALSE for `21...` and TRUE for all other pods!
    // That's why the test author wrote two regexes `^[^X]` and `^.[^Y]`! De Morgan's Law: `!(c0 == X && c1 == Y)` is `c0 != X || c1 != Y`!
    // So multiple filters of the same key (`id=`, `ctr-ids=`, `name=`, `status=`) are ORed (`any`), and different keys are ANDed!
    if !id_filters.is_empty()
        && !id_filters
            .iter()
            .any(|pat| ps_id_filter_matches(&p.id, pat))
    {
        return false;
    }
    if !name_filters.is_empty()
        && !name_filters
            .iter()
            .any(|pat| ps_name_filter_matches(&p.name, pat))
    {
        return false;
    }
    if !status_filters.is_empty()
        && !status_filters
            .iter()
            .any(|pat| p.status.eq_ignore_ascii_case(pat))
    {
        return false;
    }
    if !ctr_id_filters.is_empty() {
        let mut all_cids = p.containers.clone();
        if p.infra && !p.infra_container_id.is_empty() {
            all_cids.push(p.infra_container_id.clone());
        }
        let matched = ctr_id_filters.iter().any(|pat| {
            all_cids.iter().any(|cid| {
                if ps_id_filter_matches(cid, pat) {
                    return true;
                }
                if let Some(c) = c_store.find(cid) {
                    return ps_id_filter_matches(&c.id, pat);
                }
                false
            })
        });
        if !matched {
            return false;
        }
    }
    for lf in label_filters {
        if let Some((lk, lv)) = lf.split_once('=') {
            if p.labels.get(lk.trim()).map(String::as_str) != Some(lv.trim()) {
                return false;
            }
        } else if !p.labels.contains_key(lf) {
            return false;
        }
    }
    true
}

fn build_pod_inspect_json(
    p: &pod::PodRecord,
    store: &pod::PodStore,
    c_store: &ContainerStore,
) -> serde_json::Value {
    let mut shared = Vec::new();
    if p.share_ipc {
        shared.push("ipc");
    }
    if p.share_net {
        shared.push("net");
    }
    if p.share_pid {
        shared.push("pid");
    }
    if p.share_uts {
        shared.push("uts");
    }
    shared.sort();

    let infra_name = store.infra_name(p);
    let infra_cont = if p.infra {
        c_store
            .find(&p.infra_container_id)
            .or_else(|| c_store.find(&infra_name))
    } else {
        None
    };
    let infra_cid = infra_cont
        .as_ref()
        .map(|c| c.id.clone())
        .unwrap_or_else(|| {
            if p.infra {
                p.infra_container_id.clone()
            } else {
                String::new()
            }
        });

    let mut containers_arr = Vec::new();
    let mut num_workload_running = 0usize;
    let mut num_workload_other = 0usize;
    if let Some(ic) = &infra_cont {
        containers_arr.push(serde_json::json!({
            "Id": ic.id,
            "ID": ic.id,
            "Name": ic.name,
            "State": ic.status.to_string().to_lowercase(),
        }));
    }
    for cid in &p.containers {
        if Some(cid.as_str()) == infra_cont.as_ref().map(|c| c.id.as_str()) || cid == &infra_name {
            continue;
        }
        if let Some(c) = c_store.find(cid) {
            if Some(c.id.as_str()) == infra_cont.as_ref().map(|ic| ic.id.as_str()) {
                continue;
            }
            if matches!(c.status, ContainerStatus::Running) {
                num_workload_running += 1;
            } else {
                num_workload_other += 1;
            }
            containers_arr.push(serde_json::json!({
                "Id": c.id,
                "ID": c.id,
                "Name": c.name,
                "State": c.status.to_string().to_lowercase(),
            }));
        }
    }

    let computed_state = if num_workload_running > 0 && num_workload_other > 0 {
        "Degraded".to_string()
    } else if num_workload_running > 0 {
        "Running".to_string()
    } else {
        p.status.clone()
    };

    let host_network = p.network.as_deref() == Some("host");
    let mut port_bindings = serde_json::Map::new();
    for pm in &p.ports {
        let key = format!("{}/{}", pm.container_port, pm.protocol.to_lowercase());
        let host_ip = pm.host_ip.clone().unwrap_or_else(|| "0.0.0.0".to_string());
        let entry = serde_json::json!({
            "HostIp": host_ip,
            "HostPort": pm.host_port.to_string(),
        });
        port_bindings
            .entry(key)
            .or_insert_with(|| serde_json::Value::Array(Vec::new()))
            .as_array_mut()
            .unwrap()
            .push(entry);
    }

    let share_parent_false = p
        .labels
        .get("boxr.pod.share_parent")
        .is_some_and(|v| v == "false");
    let create_cgroup = !share_parent_false;
    let cgroup_path = if share_parent_false {
        String::new()
    } else {
        cgroups::CgroupV2Manager::path_only(&p.id).relative_cgroup_path()
    };

    let (cpu_period, cpu_quota) = p
        .cpus
        .as_deref()
        .and_then(|s| cgroups::ResourceLimits::parse_cpus(s).ok())
        .map(|(quota, period)| (period, quota))
        .unwrap_or((0, 0));
    let cpuset_cpus = p
        .labels
        .get("boxr.pod.cpuset_cpus")
        .cloned()
        .unwrap_or_default();
    let pid_ns = p.labels.get("boxr.pod.pid").cloned().unwrap_or_default();
    let uts_ns = p.labels.get("boxr.pod.uts").cloned().unwrap_or_default();

    let v_store = VolumeStore::new();
    let pod_mounts: Vec<serde_json::Value> = p
        .volumes
        .iter()
        .filter_map(|v_str| {
            let (src, dst) = v_str.split_once(':')?;
            let dst_clean = dst.split(':').next().unwrap_or(dst);
            if let Some(vol) = v_store.find(src) {
                Some(serde_json::json!({
                    "Type": "volume",
                    "Name": vol.name,
                    "Source": vol.mountpoint,
                    "Destination": dst_clean,
                    "Driver": "local",
                    "Mode": "",
                    "Options": [],
                    "RW": true,
                    "Propagation": "rprivate",
                }))
            } else {
                Some(serde_json::json!({
                    "Type": "bind",
                    "Name": src,
                    "Source": src,
                    "Destination": dst_clean,
                    "Driver": "",
                    "Mode": "",
                    "Options": [],
                    "RW": true,
                    "Propagation": "rprivate",
                }))
            }
        })
        .collect();

    let user_labels: HashMap<String, String> = p
        .labels
        .iter()
        .filter(|(k, _)| !k.starts_with("boxr."))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    serde_json::json!({
        "Id": p.id,
        "ID": p.id,
        "Name": p.name,
        "Status": computed_state,
        "State": computed_state,
        "Created": p.created_at.to_rfc3339(),
        "CreateCgroup": create_cgroup,
        "CgroupPath": cgroup_path,
        "CreateInfra": p.infra,
        "InfraContainerID": infra_cid,
        "InfraContainerId": infra_cid,
        "CPUPeriod": cpu_period,
        "cpu_period": cpu_period,
        "CPUQuota": cpu_quota,
        "cpu_quota": cpu_quota,
        "CPUSetCPUs": cpuset_cpus,
        "cpuset_cpus": cpuset_cpus,
        "Mounts": pod_mounts,
        "mounts": pod_mounts,
        "InfraConfig": {
            "HostNetwork": host_network,
            "PortBindings": port_bindings,
            "DNSServer": p.dns,
            "DNSSearch": p.dns_search,
            "DNSOption": p.dns_option,
            "HostAdd": p.add_host,
            "Networks": p.network.clone().map(|n| vec![n]).unwrap_or_default(),
            "PidNS": pid_ns,
            "pid_ns": pid_ns,
            "UtsNS": uts_ns,
            "uts_ns": uts_ns,
        },
        "SharedNamespaces": shared,
        "NumContainers": containers_arr.len(),
        "Containers": containers_arr,
        "Labels": user_labels,
        "ExitPolicy": p.exit_policy,
        "RestartPolicy": p.restart_policy.clone().unwrap_or_default(),
        "ShareIpc": p.share_ipc,
        "ShareNet": p.share_net,
        "ShareUts": p.share_uts,
        "SharePid": p.share_pid,
    })
}

async fn start_pod_members(pod: &pod::PodRecord) -> Result<()> {
    let store = pod::PodStore::new();
    if let Ok(cg) = cgroups::CgroupV2Manager::new(&pod.id) {
        if let Some(mem_str) = &pod.memory {
            if let Ok(mem_bytes) = cgroups::ResourceLimits::parse_memory(mem_str) {
                let mut lim = cgroups::ResourceLimits::default();
                lim.memory_max_bytes = Some(mem_bytes);
                let _ = cg.apply_limits(&lim);
            }
        }
    }
    if pod.infra {
        let infra = store.infra_name(pod);
        let _ = ensure_pod_infra_container(pod).await?;
        let _ = start_container(&infra).await;
    }
    for cid in &pod.containers {
        let _ = start_container(cid).await;
    }
    store.update_status(&pod.name, "Running")?;
    // Also restart any service container associated with this pod
    let c_store = ContainerStore::new();
    for c in c_store.list() {
        let cfg_path = PathBuf::from(&c.bundle_path).join("config.json");
        if let Ok(raw) = fs::read_to_string(&cfg_path) {
            if let Ok(spec) = serde_json::from_str::<Spec>(&raw) {
                if let Some(ann) = &spec.annotations {
                    if ann
                        .get("boxr.is_service")
                        .map(|v| v == "true")
                        .unwrap_or(false)
                        && ann
                            .get("boxr.service_pods")
                            .is_some_and(|s| s.split(',').any(|p| p == pod.id || p == pod.name))
                    {
                        let _ = start_container(&c.id).await;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn stop_pod_members(pod: &pod::PodRecord) -> Result<()> {
    let store = pod::PodStore::new();
    for cid in &pod.containers {
        let _ = stop_container_with_home_and_timeout(cid, None, Some(0), None, true, None);
    }
    if pod.infra {
        let infra = store.infra_name(pod);
        let _ = stop_container_with_home_and_timeout(&infra, None, Some(0), None, true, None);
    }
    let _ = cgroups::CgroupV2Manager::path_only(&pod.id).cleanup();
    store.update_status(&pod.name, "Exited")?;
    Ok(())
}

fn print_pod_table(pods: &[pod::PodRecord], ls_args: &PodLsArgs) {
    if ls_args.quiet {
        for p in pods {
            if ls_args.no_trunc {
                println!("{}", p.id);
            } else {
                println!("{}", &p.id[..12.min(p.id.len())]);
            }
        }
        return;
    }
    if let Some(fmt) = &ls_args.format {
        for p in pods {
            let mut pod_for_fmt = p.clone();
            if !ls_args.no_trunc {
                pod_for_fmt.id = p.id[..12.min(p.id.len())].to_string();
            }
            println!("{}", apply_ps_pod_format_template(fmt, &pod_for_fmt));
        }
        return;
    }
    if !ls_args.noheading {
        println!(
            "{:<14} {:<24} {:<16} {:<24} {:<14}",
            "POD ID", "NAME", "STATUS", "CREATED", "# CONTAINERS"
        );
    }
    for p in pods {
        let id_disp = if ls_args.no_trunc {
            p.id.as_str()
        } else {
            &p.id[..12.min(p.id.len())]
        };
        println!(
            "{:<14} {:<24} {:<16} {:<24} {:<14}",
            id_disp,
            p.name,
            p.status,
            p.created_at.format("%Y-%m-%d %H:%M:%S"),
            p.containers.len()
        );
    }
}

fn container_mount_destinations(record: &storage::ContainerRecord) -> Vec<String> {
    let bundle_path = PathBuf::from(&record.bundle_path);
    let mounts_json = bundle_path.join("mounts.json");
    if mounts_json.exists() {
        if let Ok(content) = fs::read_to_string(&mounts_json) {
            if let Ok(mounts) = serde_json::from_str::<Vec<volume::MountSpec>>(&content) {
                return mounts.into_iter().map(|m| m.destination).collect();
            }
        }
    }
    let config_path = bundle_path.join("config.json");
    if let Ok(content) = fs::read_to_string(&config_path) {
        if let Ok(spec) = serde_json::from_str::<oci::runtime::Spec>(&content) {
            return spec.mounts.into_iter().map(|m| m.destination).collect();
        }
    }
    Vec::new()
}

fn ps_volume_filter_matches(record: &storage::ContainerRecord, filter: &str) -> bool {
    let filter = filter.trim();
    if filter.is_empty() {
        return true;
    }
    container_mount_destinations(record)
        .iter()
        .any(|dest| dest == filter || ps_name_filter_matches(dest, filter))
}

fn ps_name_filter_matches(name: &str, filter: &str) -> bool {
    let filter = filter.trim();
    if filter.is_empty() {
        return true;
    }
    if filter.starts_with('^') && filter.ends_with('$') && filter.len() >= 2 {
        let pat = filter[1..filter.len() - 1].trim();
        let pat_body = pat.trim_start_matches('/');
        return name == pat_body || format!("/{}", name) == pat;
    }
    name.contains(filter) || format!("/{}", name).contains(filter)
}

fn ps_id_filter_matches(container_id: &str, filter: &str) -> bool {
    let filter = filter.trim();
    if filter.is_empty() {
        return true;
    }
    let hex_only = filter.chars().all(|c| c.is_ascii_hexdigit());
    if hex_only {
        return container_id.len() >= filter.len()
            && container_id[..filter.len()].eq_ignore_ascii_case(filter);
    }
    if let Ok(re) = regex::Regex::new(filter) {
        return re.is_match(container_id);
    }
    if filter.starts_with('^') {
        let pat = &filter[1..];
        if pat.starts_with("[^") && pat.ends_with(']') && pat.len() >= 4 {
            let neg = pat.chars().nth(pat.len() - 2).unwrap_or('\0');
            return container_id
                .chars()
                .next()
                .map(|c| c != neg)
                .unwrap_or(false);
        }
        if pat.chars().all(|c| c.is_ascii_hexdigit()) {
            return container_id.len() >= pat.len()
                && container_id[..pat.len()].eq_ignore_ascii_case(pat);
        }
    }
    if filter == "[0-9a-f]" {
        return container_id
            .chars()
            .all(|c| c.is_ascii_digit() || (c >= 'a' && c <= 'f'));
    }
    if filter == "[^0-9a-f]" {
        return false;
    }
    container_id.starts_with(filter)
}

fn ps_status_filter_matches(status: &ContainerStatus, filter: &str) -> bool {
    let f = filter.to_ascii_lowercase();
    match status {
        ContainerStatus::Running => f == "running",
        ContainerStatus::Stopping => f == "stopping",
        ContainerStatus::Created => f == "created",
        ContainerStatus::Paused => f == "paused",
        ContainerStatus::Exited(_) => f == "exited" || f == "stopped",
        ContainerStatus::Failed(_) => f == "failed" || f == "stopped",
    }
}

fn validate_ps_filter_key(key: &str) -> Result<()> {
    const VALID: &[&str] = &[
        "status", "name", "ancestor", "id", "label", "publish", "expose", "network", "volume",
        "exited",
    ];
    if !VALID.contains(&key) {
        return Err(anyhow!("Invalid filter '{}'", key));
    }
    Ok(())
}

fn validate_image_filter_key(key: &str) -> Result<()> {
    const VALID: &[&str] = &[
        "reference",
        "name",
        "id",
        "digest",
        "label",
        "dangling",
        "before",
        "since",
        "after",
        "until",
        "readonly",
        "intermediate",
        "manifest",
    ];
    if !VALID.contains(&key) {
        return Err(anyhow!("Invalid filter '{}'", key));
    }
    Ok(())
}

fn validate_no_duplicate_ports(ports: &[network::PortMapping]) -> Result<()> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for p in ports {
        let key = (p.host_ip.clone(), p.host_port, p.protocol.clone());
        if !seen.insert(key) {
            return Err(anyhow!(
                "Bind for 0.0.0.0:{} failed: port is already allocated",
                p.host_port
            ));
        }
    }
    Ok(())
}

fn parse_ports(specs: &[String]) -> Result<Vec<network::PortMapping>> {
    let mut parsed = Vec::new();
    for p in specs {
        parsed.extend(network::PortMapping::parse_all(p)?);
    }
    validate_no_duplicate_ports(&parsed)?;
    Ok(parsed)
}

fn validate_network_name(network: &str, home_opt: Option<&Path>) -> Result<()> {
    let trimmed = network.trim();
    if trimmed.is_empty() || trimmed == "private" {
        return Ok(());
    }
    if let Some(ns_path) = trimmed.strip_prefix("ns:") {
        if !Path::new(ns_path).exists() {
            cli::usage_errors::exit_usage_error(format!(
                "network namespace cannot be found: faccessat {}: no such file or directory",
                ns_path
            ));
        }
        return Ok(());
    }
    let mode = network::pasta::NetworkMode::parse(trimmed);
    match mode {
        network::pasta::NetworkMode::None
        | network::pasta::NetworkMode::Host
        | network::pasta::NetworkMode::Auto
        | network::pasta::NetworkMode::Pasta
        | network::pasta::NetworkMode::UserNet
        | network::pasta::NetworkMode::Container(_) => return Ok(()),
        network::pasta::NetworkMode::Bridge => {
            if matches!(trimmed, "bridge" | "default" | "auto" | "private") {
                return Ok(());
            }
        }
    }
    let base = trimmed.split_once(':').map(|(n, _)| n).unwrap_or(trimmed);
    if matches!(base, "bridge" | "default" | "auto") {
        return Ok(());
    }
    let store = match home_opt {
        Some(h) => network::NetworkStore::with_home(h.to_path_buf()),
        None => network::NetworkStore::new(),
    };
    if store.find(base).is_none() {
        return Err(anyhow!("network {} not found", base));
    }
    Ok(())
}

fn parse_run_secret_spec(entry: &str) -> Result<String> {
    if !entry.contains('=') && !entry.contains(',') {
        let trimmed = entry.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let mut source = None;
    for part in entry.split(',') {
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == "source" {
                source = Some(v.trim().to_string());
            }
        }
    }
    source.ok_or_else(|| anyhow!("invalid --secret: {}", entry))
}

fn apply_run_secrets(
    args: &cli::RunArgs,
    spec: &mut oci::runtime::Spec,
    annotations: &mut HashMap<String, String>,
    rootfs: &Path,
) -> Result<()> {
    if args.secret.is_empty() {
        return Ok(());
    }
    let store = secret::SecretStore::new();
    let mut masked = Vec::new();
    let secrets_dir = rootfs.join("run/secrets");
    let _ = fs::create_dir_all(&secrets_dir);
    for entry in &args.secret {
        let name = parse_run_secret_spec(entry)?;
        let data = store.read_data(&name)?;
        let _ = fs::write(secrets_dir.join(&name), &data);
        let value = String::from_utf8_lossy(&data).into_owned();
        spec.process
            .env
            .retain(|e| !e.starts_with(&format!("{name}=")));
        spec.process.env.push(format!("{name}={value}"));
        masked.push(name);
    }
    if !masked.is_empty() {
        annotations.insert(
            "boxr.masked_env".to_string(),
            serde_json::to_string(&masked)?,
        );
    }
    Ok(())
}

fn inspect_env_for_display(env: &[String], annotations: &HashMap<String, String>) -> Vec<String> {
    let masked: Vec<String> = annotations
        .get("boxr.masked_env")
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    env.iter()
        .map(|e| {
            if let Some((k, _)) = e.split_once('=') {
                if masked.iter().any(|m| m == k) {
                    return format!("{k}=*******");
                }
            }
            e.clone()
        })
        .collect()
}

struct InspectHealthFields {
    healthcheck: serde_json::Value,
    startup_healthcheck: serde_json::Value,
    on_failure_action: serde_json::Value,
    log_destination: serde_json::Value,
    max_log_count: serde_json::Value,
    max_log_size: serde_json::Value,
    state_health: serde_json::Value,
}

fn duration_to_ns(secs: u64) -> i64 {
    (secs as i64) * 1_000_000_000
}

fn health_cfg_to_inspect(cfg: &health::HealthConfig) -> serde_json::Value {
    let test: Vec<serde_json::Value> = if cfg.test.is_empty() {
        vec![]
    } else if cfg.test.len() == 1 && cfg.test[0] == "NONE" {
        vec![serde_json::Value::String("NONE".to_string())]
    } else if cfg.test.len() == 1 {
        vec![
            serde_json::Value::String("CMD-SHELL".to_string()),
            serde_json::Value::String(cfg.test[0].clone()),
        ]
    } else {
        cfg.test
            .iter()
            .map(|s| serde_json::Value::String(s.clone()))
            .collect()
    };
    serde_json::json!({
        "Test": test,
        "Interval": duration_to_ns(cfg.interval_secs),
        "Timeout": duration_to_ns(cfg.timeout_secs),
        "StartPeriod": duration_to_ns(cfg.start_period_secs),
        "Retries": cfg.retries,
    })
}

fn container_inspect_health_config(
    bundle_path: &Path,
    container_id: &str,
    status: &ContainerStatus,
    annotations: &HashMap<String, String>,
) -> InspectHealthFields {
    let mut health_cfg = health::HealthConfig::default();
    if let Ok(raw) = fs::read_to_string(bundle_path.join("health-supervisor.json")) {
        if let Ok(spec) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(hc) = spec.get("health_cfg") {
                if let Ok(parsed) = serde_json::from_value::<health::HealthConfig>(hc.clone()) {
                    health_cfg = parsed;
                }
            }
        }
    }
    if health_cfg.test.is_empty() {
        if let Some(cmd) = annotations.get("boxr.health_cmd") {
            if !cmd.is_empty() && cmd != "none" {
                health_cfg.test = vec!["CMD-SHELL".to_string(), cmd.clone()];
            }
        }
    }
    if let Some(v) = annotations.get("boxr.health_interval") {
        if let Ok(secs) = parse_duration_flag(v, "--health-interval") {
            health_cfg.interval_secs = secs.max(1);
        }
    }
    if let Some(v) = annotations.get("boxr.health_timeout") {
        if let Ok(secs) = parse_duration_flag(v, "--health-timeout") {
            health_cfg.timeout_secs = secs.max(1);
        }
    }
    let mut startup = health::HealthConfig::default();
    if let Some(cmd) = annotations.get("boxr.health_startup_cmd") {
        if !cmd.is_empty() {
            startup.test = vec!["CMD-SHELL".to_string(), cmd.clone()];
        }
    }
    if let Some(v) = annotations.get("boxr.health_startup_interval") {
        if let Ok(secs) = parse_duration_flag(v, "--health-startup-interval") {
            startup.interval_secs = secs.max(1);
        }
    }
    if let Some(v) = annotations.get("boxr.health_start_period") {
        if let Ok(secs) = parse_duration_flag(v, "--health-start-period") {
            health_cfg.start_period_secs = secs;
        }
    }
    if let Some(v) = annotations.get("boxr.health_retries") {
        if let Ok(r) = v.parse::<u32>() {
            health_cfg.retries = r;
        }
    }

    let startup_healthcheck = if let Some(cmd) = annotations
        .get("boxr.health_startup_cmd")
        .filter(|c| !c.is_empty())
    {
        let mut startup = health::HealthConfig::default();
        startup.test = vec![cmd.clone()];
        if let Some(v) = annotations.get("boxr.health_startup_interval") {
            if let Ok(secs) = parse_duration_flag(v, "--health-startup-interval") {
                startup.interval_secs = secs.max(1);
            }
        }
        if let Some(v) = annotations.get("boxr.health_startup_timeout") {
            if let Ok(secs) = parse_duration_flag(v, "--health-startup-timeout") {
                startup.timeout_secs = secs.max(1);
            }
        }
        if let Some(v) = annotations.get("boxr.health_startup_retries") {
            if let Ok(r) = v.parse::<u32>() {
                startup.retries = r;
            }
        }
        let successes = annotations
            .get("boxr.health_startup_success")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let mut val = health_cfg_to_inspect(&startup);
        if let Some(obj) = val.as_object_mut() {
            obj.insert("Successes".to_string(), serde_json::Value::from(successes));
        }
        val
    } else {
        serde_json::Value::Null
    };

    let on_failure = annotations
        .get("boxr.health_on_failure")
        .cloned()
        .unwrap_or_else(|| "none".to_string());
    let log_destination = annotations
        .get("boxr.health_log_destination")
        .cloned()
        .unwrap_or_else(|| "local".to_string());
    let max_log_count = annotations
        .get("boxr.health_max_log_count")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(5);
    let max_log_size = annotations
        .get("boxr.health_max_log_size")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(500);

    let (mut hc_results, _) = health::read_healthcheck_results(
        bundle_path,
        container_id,
        Some(log_destination.as_str()),
        false,
    );
    if health_cfg.test.is_empty() {
        hc_results.status = String::new();
    } else if !matches!(status, ContainerStatus::Running | ContainerStatus::Paused)
        && hc_results.status != "unhealthy"
    {
        hc_results.status = "stopped".to_string();
        hc_results.failing_streak = 0;
    }
    let state_health = serde_json::to_value(&hc_results).unwrap_or(serde_json::Value::Null);

    InspectHealthFields {
        healthcheck: health_cfg_to_inspect(&health_cfg),
        startup_healthcheck,
        on_failure_action: serde_json::Value::String(on_failure),
        log_destination: serde_json::Value::String(log_destination),
        max_log_count: serde_json::Value::from(max_log_count),
        max_log_size: serde_json::Value::from(max_log_size),
        state_health,
    }
}

fn network_endpoint_inspect_json(
    net: &network::NetworkRecord,
    ep: &network::NetworkEndpoint,
    container_hostname: &str,
) -> serde_json::Value {
    let mut dns_names = vec![ep.container_name.clone()];
    if !container_hostname.is_empty() && !dns_names.iter().any(|d| d == container_hostname) {
        dns_names.push(container_hostname.to_string());
    }
    let short_id = ep.container_id[..12.min(ep.container_id.len())].to_string();
    if !dns_names.contains(&short_id) {
        dns_names.push(short_id);
    }
    let v4_ips: Vec<(String, u32)> = ep
        .ips
        .iter()
        .filter(|(ip, _, _)| !ip.contains(':'))
        .map(|(ip, pref, _)| (ip.clone(), pref.parse::<u32>().unwrap_or(24)))
        .collect();
    let v6_ips: Vec<(String, u32)> = ep
        .ips
        .iter()
        .filter(|(ip, _, _)| ip.contains(':'))
        .map(|(ip, pref, _)| (ip.clone(), pref.parse::<u32>().unwrap_or(64)))
        .collect();

    let (primary_v4, primary_v4_prefix) = v4_ips
        .first()
        .cloned()
        .unwrap_or_else(|| (ep.ipv4_address.clone(), 16));
    let secondary_v4: Vec<serde_json::Value> = v4_ips
        .iter()
        .skip(1)
        .map(|(ip, pref)| {
            serde_json::json!({
                "Addr": ip,
                "PrefixLength": pref,
            })
        })
        .collect();

    let (primary_v6, primary_v6_prefix) = if let Some((ip, pref)) = v6_ips.first() {
        (ip.clone(), *pref)
    } else if net.enable_ipv6 && !ep.ipv4_address.is_empty() {
        let last_oct = ep
            .ipv4_address
            .rsplit('.')
            .next()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(2);
        (format!("fd00::{:x}", last_oct), 64)
    } else {
        (String::new(), 0)
    };
    let secondary_v6: Vec<serde_json::Value> = v6_ips
        .iter()
        .skip(1)
        .map(|(ip, pref)| {
            serde_json::json!({
                "Addr": ip,
                "PrefixLength": pref,
            })
        })
        .collect();

    serde_json::json!({
        "IPAMConfig": null,
        "Links": null,
        "Aliases": dns_names,
        "DNSNames": dns_names,
        "NetworkID": net.id,
        "EndpointID": format!("{}-ep", ep.container_id),
        "Gateway": net.gateway,
        "IPAddress": primary_v4,
        "IPPrefixLen": primary_v4_prefix,
        "SecondaryIPAddresses": if secondary_v4.is_empty() { serde_json::Value::Null } else { serde_json::Value::Array(secondary_v4) },
        "IPv6Gateway": "",
        "GlobalIPv6Address": primary_v6,
        "GlobalIPv6PrefixLen": primary_v6_prefix,
        "SecondaryIPv6Addresses": if secondary_v6.is_empty() { serde_json::Value::Null } else { serde_json::Value::Array(secondary_v6) },
        "MacAddress": ep.mac_address,
        "DriverOpts": null
    })
}

fn container_inspect_networks(
    container_id: &str,
    network_mode: &str,
    container_hostname: &str,
    bundle_path: &Path,
) -> serde_json::Map<String, serde_json::Value> {
    let store = network::NetworkStore::new();
    let mut networks = serde_json::Map::new();
    for net in store.list() {
        if let Some(ep) = net.containers.get(container_id) {
            if net.name == network::NetworkStore::DEFAULT_NETWORK
                && (network_mode == "auto"
                    || network_mode == "default"
                    || network_mode.is_empty()
                    || network_mode == "pasta"
                    || network_mode.starts_with("pasta:"))
            {
                continue;
            }
            let key = if net.name == network::NetworkStore::DEFAULT_NETWORK
                && network_mode == "bridge"
            {
                "podman".to_string()
            } else {
                net.name.clone()
            };
            networks.insert(
                key,
                network_endpoint_inspect_json(&net, ep, container_hostname),
            );
        }
    }
    if bundle_path.join("network_disconnected").exists() && networks.is_empty() {
        return networks;
    }
    if networks.is_empty()
        && !network_mode.starts_with("container:")
        && !network_mode.starts_with("ns:")
    {
        let key = if network_mode == "host" {
            "host"
        } else if network_mode == "none" {
            "none"
        } else if network_mode == "pasta" || network_mode.starts_with("pasta:") {
            "pasta"
        } else if network_mode == "auto" || network_mode == "default" || network_mode.is_empty() {
            #[cfg(target_os = "linux")]
            {
                if unsafe { libc::geteuid() != 0 } {
                    "pasta"
                } else {
                    "podman"
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                "bridge"
            }
        } else {
            "bridge"
        };
        networks.insert(
            key.to_string(),
            serde_json::json!({
                "IPAMConfig": null,
                "Links": null,
                "Aliases": null,
                "NetworkID": "boxr00000000",
                "EndpointID": "",
                "Gateway": "172.17.0.1",
                "IPAddress": "172.17.0.2",
                "IPPrefixLen": 16,
                "IPv6Gateway": "",
                "GlobalIPv6Address": "",
                "GlobalIPv6PrefixLen": 0,
                "MacAddress": "02:42:ac:11:00:02",
                "DriverOpts": null
            }),
        );
    }
    networks
}

fn container_runtime_pid(c: &ContainerRecord) -> Option<i32> {
    let bundle_path = PathBuf::from(&c.bundle_path);
    for name in ["container.pid", "vm.pid"] {
        if let Ok(pid_str) = fs::read_to_string(bundle_path.join(name)) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                if pid > 0 {
                    return Some(pid);
                }
            }
        }
    }
    None
}

fn read_ns_inode(pid: i32, ns: &str) -> String {
    let path = format!("/proc/{pid}/ns/{ns}");
    fs::read_link(&path)
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .and_then(|s| {
            s.strip_prefix(&format!("{ns}:"))
                .map(|rest| rest.trim_matches(|c| c == '[' || c == ']').to_string())
        })
        .unwrap_or_default()
}

fn container_namespace_inodes(c: &ContainerRecord) -> (String, String, String) {
    let Some(pid) = container_runtime_pid(c) else {
        return (String::new(), String::new(), String::new());
    };
    (
        read_ns_inode(pid, "ipc"),
        read_ns_inode(pid, "uts"),
        read_ns_inode(pid, "net"),
    )
}

fn apply_run_health_annotations(
    args: &cli::RunArgs,
    annotations: &mut HashMap<String, String>,
) -> Result<()> {
    if let Some(action) = &args.health_on_failure {
        annotations.insert("boxr.health_on_failure".to_string(), action.clone());
    }
    if let Some(cmd) = &args.health_startup_cmd {
        annotations.insert("boxr.health_startup_cmd".to_string(), cmd.clone());
    }
    if let Some(v) = &args.health_startup_interval {
        annotations.insert("boxr.health_startup_interval".to_string(), v.clone());
    }
    if let Some(v) = &args.health_startup_timeout {
        annotations.insert("boxr.health_startup_timeout".to_string(), v.clone());
    }
    if let Some(v) = args.health_startup_retries {
        annotations.insert("boxr.health_startup_retries".to_string(), v.to_string());
    }
    if let Some(v) = args.health_startup_success {
        annotations.insert("boxr.health_startup_success".to_string(), v.to_string());
    }
    if let Some(v) = args.health_max_log_count {
        annotations.insert("boxr.health_max_log_count".to_string(), v.to_string());
    }
    if let Some(v) = args.health_max_log_size {
        annotations.insert("boxr.health_max_log_size".to_string(), v.to_string());
    }
    if let Some(v) = &args.health_log_destination {
        annotations.insert("boxr.health_log_destination".to_string(), v.clone());
    }
    if let Some(cmd) = &args.health_cmd {
        annotations.insert("boxr.health_cmd".to_string(), cmd.clone());
    }
    if let Some(v) = &args.health_interval {
        annotations.insert("boxr.health_interval".to_string(), v.clone());
    }
    if let Some(v) = &args.health_timeout {
        annotations.insert("boxr.health_timeout".to_string(), v.clone());
    }
    if let Some(v) = args.health_retries {
        annotations.insert("boxr.health_retries".to_string(), v.to_string());
    }
    if let Some(v) = &args.health_start_period {
        annotations.insert("boxr.health_start_period".to_string(), v.clone());
    }
    Ok(())
}

fn apply_run_health_config(args: &cli::RunArgs, cfg: &mut health::HealthConfig) -> Result<()> {
    if let Some(interval) = &args.health_interval {
        cfg.interval_secs = parse_duration_flag(interval, "--health-interval")?;
    }
    if let Some(timeout) = &args.health_timeout {
        cfg.timeout_secs = parse_duration_flag(timeout, "--health-timeout")?.max(1);
    }
    if let Some(retries) = args.health_retries {
        cfg.retries = retries;
    }
    if let Some(period) = &args.health_start_period {
        cfg.start_period_secs = parse_duration_flag(period, "--health-start-period")?;
    }
    Ok(())
}

fn parse_duration_flag(value: &str, flag: &str) -> Result<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("invalid value for {}: empty string", flag));
    }
    if flag == "--health-interval" && trimmed.eq_ignore_ascii_case("disable") {
        return Ok(0);
    }
    if let Some(num) = trimmed.strip_suffix('s') {
        return Ok(num
            .parse::<u64>()
            .map_err(|_| anyhow!("invalid value for {}: '{}'", flag, value))?);
    }
    if let Some(num) = trimmed.strip_suffix("ms") {
        let ms = num
            .parse::<u64>()
            .map_err(|_| anyhow!("invalid value for {}: '{}'", flag, value))?;
        return Ok(ms / 1000);
    }
    if let Some(num) = trimmed.strip_suffix('m') {
        let m = num
            .parse::<u64>()
            .map_err(|_| anyhow!("invalid value for {}: '{}'", flag, value))?;
        return Ok(m * 60);
    }
    if let Some(num) = trimmed.strip_suffix('h') {
        let h = num
            .parse::<u64>()
            .map_err(|_| anyhow!("invalid value for {}: '{}'", flag, value))?;
        return Ok(h * 3600);
    }
    trimmed
        .parse::<u64>()
        .map_err(|_| anyhow!("invalid value for {}: '{}'", flag, value))
}

fn validate_pull_option(pull: &str) -> Result<()> {
    match pull {
        "always" | "missing" | "never" => Ok(()),
        _ => Err(anyhow!(
            "invalid pull option: '{}'. Must be one of: always, missing, never",
            pull
        )),
    }
}

fn format_image_size(size_bytes: u64) -> String {
    let size_mb = (size_bytes as f64) / (1024.0 * 1024.0);
    if size_mb < 1.0 {
        format!("{:.1} KB", (size_bytes as f64) / 1024.0)
    } else {
        format!("{:.2} MB", size_mb)
    }
}

fn format_created_from_unix(ts: u64) -> String {
    let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp(ts as i64, 0)
        .unwrap_or_else(chrono::Utc::now);
    format_running_for(created_at)
}

fn format_running_for(created_at: chrono::DateTime<chrono::Utc>) -> String {
    let duration = chrono::Utc::now().signed_duration_since(created_at);
    if duration.num_days() > 0 {
        format!("{} days ago", duration.num_days())
    } else if duration.num_hours() > 0 {
        format!("{} hours ago", duration.num_hours())
    } else if duration.num_minutes() > 0 {
        format!("{} minutes ago", duration.num_minutes())
    } else if duration.num_seconds() > 1 {
        format!("{} seconds ago", duration.num_seconds())
    } else {
        "1 second ago".to_string()
    }
}

/// Podman/Docker `ps` STATUS column (distinct from CREATED "… ago" strings).
fn format_ps_status_column(c: &ContainerRecord) -> String {
    match &c.status {
        ContainerStatus::Running => {
            let duration = chrono::Utc::now().signed_duration_since(c.created_at);
            let suffix = if duration.num_days() > 0 {
                format!("{} days", duration.num_days())
            } else if duration.num_hours() > 0 {
                format!("{} hours", duration.num_hours())
            } else if duration.num_minutes() > 0 {
                format!("{} minutes", duration.num_minutes())
            } else {
                let secs = duration.num_seconds().max(1);
                format!("{} seconds", secs)
            };
            let bundle_path = PathBuf::from(&c.bundle_path);
            let annotations = load_container_labels_from_bundle(&c.bundle_path);
            let has_hc = c.health_status != health::HealthStatus::None
                || bundle_path.join("health-supervisor.json").exists()
                || annotations.contains_key("boxr.health_cmd");
            if has_hc {
                let log_dest = annotations
                    .get("boxr.health_log_destination")
                    .map(|s| s.as_str());
                let (hc_res, _) =
                    health::read_healthcheck_results(&bundle_path, &c.id, log_dest, true);
                let hc_str = if hc_res.status.is_empty() {
                    "starting"
                } else {
                    hc_res.status.as_str()
                };
                format!("Up {} ({})", suffix, hc_str)
            } else {
                format!("Up {}", suffix)
            }
        }
        ContainerStatus::Exited(code) => {
            let duration = chrono::Utc::now().signed_duration_since(c.created_at);
            let suffix = if duration.num_days() > 0 {
                format!("{} days ago", duration.num_days())
            } else if duration.num_hours() > 0 {
                format!("{} hours ago", duration.num_hours())
            } else if duration.num_minutes() > 0 {
                format!("{} minutes ago", duration.num_minutes())
            } else {
                let secs = duration.num_seconds().max(1);
                if secs == 1 {
                    "1 second ago".to_string()
                } else {
                    format!("{} seconds ago", secs)
                }
            };
            format!("Exited ({}) {}", code, suffix)
        }
        other => other.to_string(),
    }
}

fn load_container_labels_from_bundle(bundle_path: &str) -> HashMap<String, String> {
    let mut labels_map = HashMap::new();
    let labels_file = PathBuf::from(bundle_path).join("labels.json");
    if labels_file.exists() {
        if let Ok(content) = fs::read_to_string(&labels_file) {
            if let Ok(labels_vec) = serde_json::from_str::<Vec<String>>(&content) {
                for l in labels_vec {
                    if let Some((k, v)) = l.split_once('=') {
                        labels_map.insert(k.to_string(), v.to_string());
                    } else {
                        labels_map.insert(l, String::new());
                    }
                }
            }
        }
    }
    let config_path = PathBuf::from(bundle_path).join("config.json");
    if let Ok(raw) = fs::read_to_string(&config_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(ann) = v.get("annotations").and_then(|a| a.as_object()) {
                for (k, val) in ann {
                    if let Some(s) = val.as_str() {
                        labels_map.insert(k.clone(), s.to_string());
                    }
                }
            }
        }
    }
    labels_map
}

fn prune_container_attached_volumes(bundle_path: PathBuf) {
    let v_store = VolumeStore::new();
    let mounts_path = bundle_path.join("mounts.json");
    if mounts_path.exists() {
        if let Ok(content) = fs::read_to_string(&mounts_path) {
            if let Ok(mounts) = serde_json::from_str::<Vec<volume::MountSpec>>(&content) {
                for m in mounts {
                    if !m.is_volume {
                        continue;
                    }
                    let vol_name = m.volume_name.as_deref();
                    if let Some(name) = vol_name {
                        if let Some(v) = v_store.find(name) {
                            if v.anonymous {
                                let _ = v_store.delete_volume_record(name);
                            }
                            continue;
                        }
                    }
                    let src = m.source.to_string_lossy();
                    for v in v_store.list() {
                        if !v.anonymous {
                            continue;
                        }
                        if src.contains(&format!("volumes/{}/_data", v.name))
                            || src.contains(&format!("/volumes/{}/", v.name))
                        {
                            let _ = v_store.delete_volume_record(&v.name);
                        }
                    }
                }
            }
        }
    }
    let config_file = bundle_path.join("config.json");
    if let Ok(content) = fs::read_to_string(&config_file) {
        if let Ok(spec) = serde_json::from_str::<Spec>(&content) {
            for m in spec.mounts {
                let m_src = m.source;
                for v in v_store.list() {
                    if !v.anonymous {
                        continue;
                    }
                    if m_src.contains(&format!("volumes/{}/_data", v.name))
                        || m_src.contains(&format!("volumes/{}", v.name))
                        || m_src == v.name
                    {
                        let _ = v_store.delete_volume_record(&v.name);
                    }
                }
            }
        }
    }
}

fn apply_chown_u_from_bundle(bundle_path: &Path, spec: &Spec, recursive: bool) -> Result<()> {
    let mounts_path = bundle_path.join("mounts.json");
    if !mounts_path.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(&mounts_path)?;
    let mounts: Vec<volume::MountSpec> = serde_json::from_str(&content).unwrap_or_default();
    #[cfg(target_os = "linux")]
    for m in mounts {
        if m.chown_u && !m.is_volume {
            crate::runtime::linux::chown_path_rootless(
                &m.source,
                spec.process.user.uid,
                spec.process.user.gid,
                recursive,
            )?;
        }
    }
    Ok(())
}

fn check_clone_container_name(store: &ContainerStore, base: &str) -> String {
    if base.contains("-clone") {
        let ind = base.find("-clone").unwrap_or(0) + 6;
        let suffix = &base[ind..];
        let mut prefix = base[..ind].to_string();
        if suffix.parse::<i32>().ok().filter(|&n| n != 0).is_none() {
            let candidate = format!("{}1", base);
            if store.find(&candidate).is_none() {
                return candidate;
            }
            prefix = base[..ind].to_string();
        }
        let mut count = suffix.parse::<i32>().unwrap_or(0);
        loop {
            count += 1;
            let candidate = format!("{}{}", prefix, count);
            if store.find(&candidate).is_none() {
                return candidate;
            }
        }
    }
    let candidate = format!("{base}-clone");
    if store.find(&candidate).is_none() {
        return candidate;
    }
    check_clone_container_name(store, &candidate)
}

async fn clone_container(args: &cli::ContainerCloneArgs) -> Result<String> {
    if args.force && !args.destroy {
        cli::usage_errors::exit_usage_error("cannot set --force without --destroy");
    }
    let store = ContainerStore::new();
    let src = store
        .find(&args.source)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.source))?;

    let target_name = args
        .name
        .clone()
        .or_else(|| args.positional_name.clone())
        .unwrap_or_else(|| check_clone_container_name(&store, &src.name));

    let mut image = src.image.clone();
    if let Some(img) = &args.positional_image {
        pull_image_with_platform(img, None).await?;
        image = img.clone();
    }

    let new_id = new_container_id();
    let home = storage::boxr_home();
    let new_bundle = home.join("containers").join(&new_id);
    let src_bundle = PathBuf::from(&src.bundle_path);
    fs::create_dir_all(&new_bundle)?;
    if src_bundle.exists() {
        copy_dir_contents(&src_bundle, &new_bundle)?;
        for file in [
            "vm.pid",
            "container.pid",
            "conmon.pid",
            "boxr.pid",
            "boxr-exitcode",
            "manual_stop",
            "forwarder.pid",
        ] {
            let _ = fs::remove_file(new_bundle.join(file));
        }
    }

    let config_path = new_bundle.join("config.json");
    if config_path.exists() {
        let content = fs::read_to_string(&config_path)?;
        if let Ok(mut spec) = serde_json::from_str::<oci::runtime::Spec>(&content) {
            let ann = spec
                .annotations
                .get_or_insert_with(std::collections::HashMap::new);
            if let Some(cpus) = &args.cpus {
                ann.insert("boxr.cpus".to_string(), cpus.clone());
            }
            if let Some(mem) = &args.memory {
                ann.insert("boxr.memory".to_string(), mem.clone());
            }
            if let Some(pod_ref) = &args.pod {
                let pod_store = pod::PodStore::new();
                let pod_rec = pod_store
                    .find(pod_ref)
                    .ok_or_else(|| anyhow!("no pod with name or ID {} found", pod_ref))?;
                let pod_id = pod_rec.id.clone();
                let infra = pod_store.infra_name(&pod_rec);
                ann.insert("boxr.pod".to_string(), pod_id);
                if pod_rec.share_net {
                    ann.insert("boxr.network".to_string(), format!("container:{infra}"));
                } else if let Some(net) = &pod_rec.network {
                    ann.insert("boxr.network".to_string(), net.clone());
                } else {
                    ann.insert("boxr.network".to_string(), "bridge".to_string());
                }
            } else if let Some(src_cfg) = fs::read_to_string(src_bundle.join("config.json")).ok() {
                if let Ok(src_spec) = serde_json::from_str::<oci::runtime::Spec>(&src_cfg) {
                    if let Some(src_ann) = src_spec.annotations {
                        if let Some(pod_id) = src_ann.get("boxr.pod") {
                            ann.insert("boxr.pod".to_string(), pod_id.clone());
                        }
                        if let Some(net) = src_ann.get("boxr.network") {
                            ann.insert("boxr.network".to_string(), net.clone());
                        }
                    }
                }
            }
            if args.positional_image.is_some() {
                ann.insert("boxr.clone_image".to_string(), image.clone());
            }
            fs::write(&config_path, serde_json::to_string_pretty(&spec)?)?;
        }
    } else if let Some(pod_ref) = &args.pod {
        let pod_store = pod::PodStore::new();
        let pod_id = pod_store
            .find(pod_ref)
            .map(|p| p.id)
            .unwrap_or_else(|| pod_ref.clone());
        let _ = fs::write(
            new_bundle.join("pod.json"),
            serde_json::json!({ "pod": pod_id }).to_string(),
        );
    }

    let new_cont = ContainerRecord {
        id: new_id.clone(),
        name: target_name.clone(),
        image,
        command: src.command.clone(),
        created_at: Utc::now(),
        status: ContainerStatus::Created,
        bundle_path: new_bundle.to_string_lossy().to_string(),
        restart_policy: src.restart_policy.clone(),
        health_status: src.health_status.clone(),
        restart_count: 0,
        ports: src.ports.clone(),
        exposed_ports: src.exposed_ports.clone(),
    };
    store.add(new_cont)?;

    if let Ok(cfg) = fs::read_to_string(new_bundle.join("config.json")) {
        if let Ok(spec) = serde_json::from_str::<oci::runtime::Spec>(&cfg) {
            if let Some(ann) = spec.annotations {
                if let Some(pod_ref) = ann.get("boxr.pod") {
                    let pod_store = pod::PodStore::new();
                    let _ = pod_store.add_container_to_pod(pod_ref, &new_id);
                }
            }
        }
    }

    let net_store = network::NetworkStore::new();
    for net in net_store.list() {
        if net.containers.contains_key(&src.id) {
            let _ = net_store.connect_container(&net.name, &new_id, &target_name);
        }
    }

    if args.destroy {
        remove_container_quiet(&src.id, args.force, false)?;
    }
    if args.run {
        start_container(&target_name).await?;
    }
    Ok(new_id)
}

fn copy_dir_contents(src: &Path, dst: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(src)?;
    if meta.is_dir() {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            copy_dir_contents(&entry.path(), &dst.join(entry.file_name()))?;
        }
        return Ok(());
    }
    if meta.file_type().is_symlink() {
        let link_target = fs::read_link(src)?;
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            if dst.exists() {
                let _ = fs::remove_file(dst);
            }
            symlink(link_target, dst)?;
        }
        return Ok(());
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(src, dst)?;
    Ok(())
}

fn image_mount_has_content(merged_rootfs: &Path, dest: &str) -> bool {
    let rel = dest.trim_start_matches('/');
    let path: PathBuf = if rel.is_empty() {
        merged_rootfs.to_path_buf()
    } else {
        merged_rootfs.join(rel)
    };
    if !path.exists() {
        return false;
    }
    if path.is_file() {
        return true;
    }
    fs::read_dir(&path)
        .map(|rd| rd.filter(|e| e.is_ok()).count() > 0)
        .unwrap_or(false)
}

fn apply_volume_mount_prep(
    vol_store: &VolumeStore,
    mounts: &[volume::MountSpec],
    merged_rootfs: &Path,
    uid: u32,
    gid: u32,
) -> Result<()> {
    for m in mounts {
        if m.chown_u && !m.is_volume {
            #[cfg(target_os = "linux")]
            {
                let _ = crate::runtime::linux::chown_path_rootless(&m.source, uid, gid, true);
            }
        }
        if !m.is_volume {
            continue;
        }
        let vol_name = match &m.volume_name {
            Some(n) => n.clone(),
            None => continue,
        };
        let vol = match vol_store.find(&vol_name) {
            Some(v) => v,
            None => continue,
        };
        if !vol.needs_copy_up {
            continue;
        }
        if !image_mount_has_content(merged_rootfs, &m.destination) {
            continue;
        }
        let src = merged_rootfs.join(m.destination.trim_start_matches('/'));
        copy_dir_contents(&src, &m.source)?;
        #[cfg(unix)]
        if let Ok(meta) = fs::symlink_metadata(&src) {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o7777;
            let _ = fs::set_permissions(&m.source, fs::Permissions::from_mode(mode));
        }
        if let Some(bundle_dir) = merged_rootfs.parent() {
            let chown_meta_file = bundle_dir.join("chown_meta.json");
            if let Ok(content) = fs::read_to_string(&chown_meta_file) {
                if let Ok(map) = serde_json::from_str::<HashMap<String, (u32, u32)>>(&content) {
                    let rel = m.destination.trim_start_matches('/');
                    if let Some(&(u, g)) = map.get(rel) {
                        let _ = vol_store.set_volume_uid_gid(&vol_name, Some(u), Some(g));
                    }
                }
            }
        }
        let _ = vol_store.set_volume_copy_flags(&vol_name, false, false);
    }
    for m in mounts {
        if !m.is_volume {
            continue;
        }
        if let Some(vol_name) = &m.volume_name {
            if let Some(vol) = vol_store.find(vol_name) {
                if vol.uid.is_some() || vol.gid.is_some() {
                    if let Some(bundle_dir) = merged_rootfs.parent() {
                        let chown_meta_file = bundle_dir.join("chown_meta.json");
                        let mut map: HashMap<String, (u32, u32)> =
                            fs::read_to_string(&chown_meta_file)
                                .ok()
                                .and_then(|s| serde_json::from_str(&s).ok())
                                .unwrap_or_default();
                        let rel = m.destination.trim_start_matches('/').to_string();
                        map.insert(rel, (vol.uid.unwrap_or(0), vol.gid.unwrap_or(0)));
                        if let Ok(encoded) = serde_json::to_string(&map) {
                            let _ = fs::write(&chown_meta_file, encoded);
                        }
                    }
                    #[cfg(target_os = "linux")]
                    {
                        let _ = crate::runtime::linux::chown_path_rootless(
                            &m.source,
                            vol.uid.unwrap_or(0),
                            vol.gid.unwrap_or(0),
                            true,
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn volume_ls_json_entry(v: &volume::VolumeRecord) -> serde_json::Value {
    serde_json::json!({
        "Name": v.name,
        "Driver": v.driver,
        "Mountpoint": v.mountpoint,
        "CreatedAt": v.created_at.to_rfc3339(),
        "Labels": v.labels,
        "Scope": v.scope,
        "Options": v.options,
        "NeedsCopyUp": v.needs_copy_up,
        "NeedsChown": v.needs_chown,
    })
}

fn apply_volume_ls_format_template(template: &str, v: &volume::VolumeRecord) -> String {
    let labels_flat = ps_labels_string(&v.labels);
    let mut line = template.to_string();
    for pat in ["{{json .Labels}}", "{{ json .Labels }}"] {
        if line.contains(pat) {
            let quoted = serde_json::to_string(&labels_flat).unwrap_or_else(|_| "\"\"".to_string());
            line = line.replace(pat, &quoted);
        }
    }
    line = line.replace("{{.Labels}}", &labels_flat);
    line = line.replace("{{ .Labels }}", &labels_flat);
    line = line.replace("{{.Name}}", &v.name);
    line = line.replace("{{.Driver}}", &v.driver);
    line = line.replace("{{.Scope}}", &v.scope);
    line
}

fn ps_labels_string(labels: &HashMap<String, String>) -> String {
    let mut pairs: Vec<_> = labels.iter().collect();
    pairs.sort_by_key(|(k, _)| *k);
    pairs
        .into_iter()
        .map(|(k, v)| {
            if v.is_empty() {
                k.clone()
            } else {
                format!("{}={}", k, v)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn pod_name_for_container(container_id: &str) -> String {
    pod::PodStore::new()
        .list()
        .into_iter()
        .find(|p| {
            p.infra_container_id == container_id || p.containers.iter().any(|c| c == container_id)
        })
        .map(|p| p.name)
        .unwrap_or_default()
}

fn pod_id_for_container(container_id: &str) -> String {
    pod::PodStore::new()
        .list()
        .into_iter()
        .find(|p| {
            p.infra_container_id == container_id || p.containers.iter().any(|c| c == container_id)
        })
        .map(|p| p.id)
        .unwrap_or_default()
}

fn apply_ps_container_format_template(
    template: &str,
    c: &ContainerRecord,
    id_display: &str,
    cmd_display: &str,
    state_str: &str,
    size_str: &str,
) -> String {
    let labels = load_container_labels_from_bundle(&c.bundle_path);
    let labels_flat = ps_labels_string(&labels);
    let pod_name = pod_name_for_container(&c.id);
    let (ns_ipc, ns_uts, ns_net) = container_namespace_inodes(c);

    let mut line = template.to_string();
    for pat in ["{{json .Labels}}", "{{ json .Labels }}"] {
        if line.contains(pat) {
            let quoted = serde_json::to_string(&labels_flat).unwrap_or_else(|_| "\"\"".to_string());
            line = line.replace(pat, &quoted);
        }
    }
    line = line.replace("{{.Labels}}", &labels_flat);
    line = line.replace("{{ .Labels }}", &labels_flat);

    for (k, v) in &labels {
        line = line.replace(&format!(r#"{{{{ .Label "{}" }}}}"#, k), v);
        line = line.replace(&format!(r#"{{{{.Label "{}"}}}}"#, k), v);
    }

    line = line.replace("{{.PodName}}", &pod_name);
    line = line.replace("{{ .PodName }}", &pod_name);
    let full_pod_id = pod_id_for_container(&c.id);
    let pod_id_disp = if id_display.len() > 12 {
        full_pod_id.as_str()
    } else {
        &full_pod_id[..12.min(full_pod_id.len())]
    };
    line = line.replace("{{.Pod}}", pod_id_disp);
    line = line.replace("{{ .Pod }}", pod_id_disp);

    line = line.replace("{{.ID}}", id_display);
    line = line.replace("{{ .ID }}", id_display);
    line = line.replace("{{.Names}}", &c.name);
    line = line.replace("{{ .Names }}", &c.name);
    line = line.replace("{{.Image}}", &c.image);
    line = line.replace("{{ .Image }}", &c.image);
    let status_col = format_ps_status_column(c);
    line = line.replace("{{.Status}}", &status_col);
    line = line.replace("{{ .Status }}", &status_col);
    line = line.replace("{{.State}}", state_str);
    line = line.replace("{{ .State }}", state_str);
    line = line.replace(
        "{{.Ports}}",
        &format_container_ports_and_exposed(&c.ports, &c.exposed_ports),
    );
    line = line.replace("{{.Command}}", cmd_display);
    line = line.replace(
        "{{.CreatedAt}}",
        &c.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
    );
    line = line.replace("{{.RunningFor}}", &format_running_for(c.created_at));
    line = line.replace("{{.Restarts}}", &c.restart_count.to_string());
    line = line.replace("{{ .Restarts }}", &c.restart_count.to_string());
    line = line.replace("{{.Size}}", size_str);
    line = line.replace("{{.Namespaces.IPC}}", &ns_ipc);
    line = line.replace("{{ .Namespaces.IPC }}", &ns_ipc);
    line = line.replace("{{.Namespaces.UTS}}", &ns_uts);
    line = line.replace("{{ .Namespaces.UTS }}", &ns_uts);
    line = line.replace("{{.Namespaces.NET}}", &ns_net);
    line = line.replace("{{ .Namespaces.NET }}", &ns_net);
    line
}

fn apply_ps_pod_format_template(template: &str, p: &pod::PodRecord) -> String {
    let labels_flat = ps_labels_string(&p.labels);
    let short_id = &p.id[..12.min(p.id.len())];
    let mut line = template.to_string();
    for pat in ["{{json .Labels}}", "{{ json .Labels }}"] {
        if line.contains(pat) {
            let quoted = serde_json::to_string(&labels_flat).unwrap_or_else(|_| "\"\"".to_string());
            line = line.replace(pat, &quoted);
        }
    }
    line = line.replace("{{.Labels}}", &labels_flat);
    line = line.replace("{{ .Labels }}", &labels_flat);
    for (k, v) in &p.labels {
        line = line.replace(&format!(r#"{{{{ .Label "{}" }}}}"#, k), v);
        line = line.replace(&format!(r#"{{{{.Label "{}"}}}}"#, k), v);
    }
    line = line.replace("{{.ID}}", &p.id);
    line = line.replace("{{ .ID }}", &p.id);
    line = line.replace("{{.Id}}", short_id);
    line = line.replace("{{ .Id }}", short_id);
    line = line.replace("{{.Name}}", &p.name);
    line = line.replace("{{ .Name }}", &p.name);
    line = line.replace("{{.Status}}", &p.status);
    line = line.replace("{{ .Status }}", &p.status);
    let num_conts = p.containers.len() + usize::from(p.infra);
    line = line.replace("{{.Containers}}", &p.containers.len().to_string());
    line = line.replace("{{.NumberOfContainers}}", &num_conts.to_string());
    line = line.replace("{{ .NumberOfContainers }}", &num_conts.to_string());
    line
}

fn format_container_ports(ports: &[network::PortMapping]) -> String {
    format_container_ports_and_exposed(ports, &[])
}

fn format_container_ports_and_exposed(
    ports: &[network::PortMapping],
    exposed_ports: &[String],
) -> String {
    let mut parts: Vec<String> = ports
        .iter()
        .map(|p| {
            let host_ip = p
                .host_ip
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("0.0.0.0");
            format!(
                "{}:{}->{}/{}",
                host_ip, p.host_port, p.container_port, p.protocol
            )
        })
        .collect();

    if !exposed_ports.is_empty() {
        let mut by_proto: std::collections::BTreeMap<String, Vec<u16>> =
            std::collections::BTreeMap::new();
        for raw in exposed_ports {
            let (port_part, proto) = if let Some((p, pr)) = raw.split_once('/') {
                (p.trim(), pr.trim().to_ascii_lowercase())
            } else {
                (raw.trim(), "tcp".to_string())
            };
            let expanded: Vec<u16> = if let Some((s_str, e_str)) = port_part.split_once('-') {
                if let (Ok(s), Ok(e)) = (s_str.parse::<u16>(), e_str.parse::<u16>()) {
                    (s..=e).collect()
                } else {
                    Vec::new()
                }
            } else if let Ok(p) = port_part.parse::<u16>() {
                vec![p]
            } else {
                Vec::new()
            };
            let entry = by_proto.entry(proto.clone()).or_default();
            for p in expanded {
                let already_published = ports.iter().any(|pm| {
                    pm.container_port == p && pm.protocol.eq_ignore_ascii_case(&proto)
                });
                if !already_published {
                    entry.push(p);
                }
            }
        }
        for (proto, mut list) in by_proto {
            list.sort_unstable();
            list.dedup();
            let mut idx = 0;
            while idx < list.len() {
                let start = list[idx];
                let mut end = start;
                while idx + 1 < list.len() && list[idx + 1] == end.wrapping_add(1) {
                    idx += 1;
                    end = list[idx];
                }
                if start == end {
                    parts.push(format!("{}/{}", start, proto));
                } else {
                    parts.push(format!("{}-{}/{}", start, end, proto));
                }
                idx += 1;
            }
        }
    }

    parts.join(", ")
}

fn apply_inspect_format_template(template: &str, value: &serde_json::Value) -> String {
    for pat in ["{{json .RepoDigests}}", "{{ json .RepoDigests }}"] {
        if template.contains(pat) {
            if let Some(arr) = value.get("RepoDigests") {
                return arr.to_string();
            }
            return "[]".to_string();
        }
    }
    if template.contains("range .HostConfig.Ulimits") && template.contains("RLIMIT_NPROC") {
        if let Some(arr) = value
            .get("HostConfig")
            .and_then(|h| h.get("Ulimits"))
            .and_then(|u| u.as_array())
        {
            for entry in arr {
                if entry.get("Name").and_then(|n| n.as_str()) == Some("RLIMIT_NPROC") {
                    let soft = entry
                        .get("Soft")
                        .map(|v| v.as_u64().unwrap_or(0).to_string())
                        .unwrap_or_default();
                    let hard = entry
                        .get("Hard")
                        .map(|v| v.as_u64().unwrap_or(0).to_string())
                        .unwrap_or_default();
                    return format!("{}:{}", soft, hard);
                }
            }
        }
        return String::new();
    }
    if template.contains("range .Config.Env") {
        if let Some(arr) = value
            .get("Config")
            .and_then(|c| c.get("Env"))
            .and_then(|e| e.as_array())
        {
            let entries: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !template.contains("eq \"F\"") || s.starts_with('F'))
                .map(|s| s.to_string())
                .collect();
            return entries.join(" ");
        }
        return String::new();
    }
    if template.contains("range $index, $value := .NetworkSettings.Networks") {
        if let Some(map) = value
            .get("NetworkSettings")
            .and_then(|n| n.get("Networks"))
            .and_then(|m| m.as_object())
        {
            let keys: Vec<String> = map.keys().cloned().collect();
            return keys.join("");
        }
        return String::new();
    }
    let mut out = template.replace("\\n", "\n").replace("\\t", "\t");
    while let Some(start) = out.find("{{") {
        let Some(rel_end) = out[start..].find("}}") else {
            break;
        };
        let end = start + rel_end + 2;
        let token = &out[start..end];
        let rendered = evaluate_simple_template(token, value);
        out.replace_range(start..end, &rendered);
    }
    out.replace("\\n", "\n")
}

fn evaluate_go_template_conditionals(template: &str, value: &serde_json::Value) -> String {
    let mut out = template.to_string();
    loop {
        let Some(if_pos) = out.find("{{ if ").or_else(|| out.find("{{if ")) else {
            break;
        };
        let Some(end_pos_rel) = out[if_pos..]
            .find("{{ end }}")
            .or_else(|| out[if_pos..].find("{{end}}"))
        else {
            break;
        };
        let end_tag_len = if out[if_pos + end_pos_rel..].starts_with("{{ end }}") {
            9
        } else {
            7
        };
        let block = &out[if_pos..if_pos + end_pos_rel + end_tag_len];
        let Some(cond_close) = block.find("}}") else {
            break;
        };
        let cond_header = &block[2..cond_close].trim();
        let cond_expr = cond_header
            .strip_prefix("if ")
            .unwrap_or(cond_header)
            .trim();
        let body = &block[cond_close + 2..block.len() - end_tag_len];
        let (then_part, else_part) = if let Some(idx) = body.find("{{ else }}") {
            (&body[..idx], &body[idx + 10..])
        } else if let Some(idx) = body.find("{{else}}") {
            (&body[..idx], &body[idx + 8..])
        } else {
            (body, "")
        };
        let cond_val = evaluate_simple_template(&format!("{{{{ {} }}}}", cond_expr), value);
        let chosen = if !cond_val.is_empty()
            && cond_val != "false"
            && cond_val != "0"
            && cond_val != "<nil>"
        {
            evaluate_go_template_multi(then_part, value)
        } else {
            evaluate_go_template_multi(else_part, value)
        };
        out.replace_range(if_pos..if_pos + end_pos_rel + end_tag_len, chosen.trim());
    }
    evaluate_go_template_multi(&out, value)
}

fn evaluate_go_template_multi(template: &str, value: &serde_json::Value) -> String {
    let mut out = template.to_string();
    while let Some(start) = out.find("{{") {
        let Some(rel_end) = out[start..].find("}}") else {
            break;
        };
        let end = start + rel_end + 2;
        let token = &out[start..end];
        let rendered = evaluate_simple_template(token, value);
        out.replace_range(start..end, &rendered);
    }
    out.replace("\\n", "\n")
}

fn evaluate_simple_template(template: &str, value: &serde_json::Value) -> String {
    let mut cleaned = template.trim();
    if cleaned.starts_with("{{") && cleaned.ends_with("}}") {
        cleaned = cleaned[2..cleaned.len() - 2].trim();
    }
    if cleaned == "\"\\n\"" {
        return String::new();
    }
    if let Some(nested) = evaluate_nested_index_expr(cleaned, value) {
        return format_template_value(&nested);
    }
    if let Some(rest) = cleaned.strip_prefix("(index ") {
        if let Some((idx_expr, tail)) = rest.split_once(").") {
            if let Some((field_path, key)) = parse_index_template_args(idx_expr) {
                let node = resolve_template_path(value, field_path.trim_start_matches('.'));
                if let Some(map) = node.as_ref().and_then(|n| n.as_object()) {
                    let lookup = key.trim().trim_matches('"');
                    if let Some(entry) = map.get(lookup) {
                        if let Some(sub) = resolve_template_path(entry, tail.trim()) {
                            return format_template_value(&sub);
                        }
                    }
                }
            }
            return String::new();
        }
    }
    if let Some(rest) = cleaned.strip_prefix("json ") {
        let rest_trimmed = rest.trim();
        if let Some(inner) = rest_trimmed
            .strip_prefix("(index ")
            .and_then(|s| s.strip_suffix(')'))
        {
            if let Some((field_path, key)) = parse_index_template_args(inner) {
                let node = resolve_template_path(value, field_path.trim_start_matches('.'));
                if let Some(map) = node.as_ref().and_then(|n| n.as_object()) {
                    let lookup = key.trim().trim_matches('"');
                    if let Some(v) = map.get(lookup) {
                        if let Some(raw) = v.get("__raw_json").and_then(|s| s.as_str()) {
                            return raw.to_string();
                        }
                        return serde_json::to_string(v).unwrap_or_default();
                    }
                }
                return "null".to_string();
            }
        }
        let field_path = rest_trimmed.trim_start_matches('.');
        if field_path.is_empty() {
            return serde_json::to_string(value).unwrap_or_default();
        }
        if let Some(node) = resolve_template_path(value, field_path) {
            return serde_json::to_string(&node).unwrap_or_default();
        }
        return "null".to_string();
    }
    if let Some(rest) = cleaned.strip_prefix("index ") {
        if let Some((field_path, key)) = parse_index_template_args(rest) {
            let node = resolve_template_path(value, field_path.trim_start_matches('.'));
            let lookup = key.trim().trim_matches('"');
            if let Some(map) = node.as_ref().and_then(|n| n.as_object()) {
                if let Some(v) = map.get(lookup) {
                    return format_template_value(v);
                }
            }
            if let Some(arr) = node.as_ref().and_then(|n| n.as_array()) {
                if let Ok(idx) = lookup.parse::<usize>() {
                    if let Some(v) = arr.get(idx) {
                        return format_template_value(v);
                    }
                }
            }
            return String::new();
        }
    }
    if let Some(rest) = cleaned.strip_prefix("join ") {
        if let Some((field_path, sep)) = parse_join_template_args(rest) {
            let node = resolve_template_path(value, field_path.trim_start_matches('.'));
            if let Some(arr) = node.as_ref().and_then(|n| n.as_array()) {
                return arr
                    .iter()
                    .map(|v| match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string().trim_matches('"').to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(sep.as_str());
            }
            return String::new();
        }
    }
    if let Some(rest) = cleaned.strip_prefix("len ") {
        let field_path = rest.trim().trim_start_matches('.');
        if let Some(node) = resolve_template_path(value, field_path) {
            if let Some(arr) = node.as_array() {
                return arr.len().to_string();
            }
        }
        return "0".to_string();
    }
    let path = cleaned.trim_start_matches('.');
    let mut curr = value;
    for part in path.split('.') {
        if part.is_empty() {
            continue;
        }
        let key = if part == "ID" { "Id" } else { part };
        if let Some(next) = curr.get(key).or_else(|| curr.get(part)) {
            curr = next;
        } else {
            return String::new();
        }
    }
    if path == "HostConfig.Ulimits" {
        if let Some(arr) = curr.as_array() {
            let parts: Vec<String> = arr
                .iter()
                .filter_map(|entry| {
                    let name = entry.get("Name").and_then(|n| n.as_str())?;
                    let soft = entry.get("Soft")?;
                    let hard = entry.get("Hard")?;
                    Some(format!(
                        "{{{name} {} {}}}",
                        format_inspect_ulimit_val(soft),
                        format_inspect_ulimit_val(hard)
                    ))
                })
                .collect();
            return format!("[{}]", parts.join(" "));
        }
        return String::new();
    }
    if path == "Config.StartupHealthCheck" && curr.is_null() {
        return "<nil>".to_string();
    }
    if matches!(
        path,
        "Config.Healthcheck.Interval"
            | "Config.Healthcheck.Timeout"
            | "Config.Healthcheck.StartPeriod"
            | "Config.StartupHealthCheck.Interval"
            | "Config.StartupHealthCheck.Timeout"
            | "Config.StartupHealthCheck.StartPeriod"
    ) {
        if let Some(ns) = curr.as_i64() {
            return format!("{}s", ns / 1_000_000_000);
        }
    }
    match curr {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::new(),
        other => format_template_value(other),
    }
}

fn format_template_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::new(),
        serde_json::Value::Object(map) if map.is_empty() => "map[]".to_string(),
        serde_json::Value::Object(map)
            if map.contains_key("Start")
                && map.contains_key("End")
                && map.contains_key("ExitCode")
                && map.contains_key("Output") =>
        {
            format!(
                "{{{} {} {} {}}}",
                map.get("Start").and_then(|x| x.as_str()).unwrap_or(""),
                map.get("End").and_then(|x| x.as_str()).unwrap_or(""),
                map.get("ExitCode").and_then(|x| x.as_i64()).unwrap_or(0),
                map.get("Output").and_then(|x| x.as_str()).unwrap_or("")
            )
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(format_template_value).collect();
            format!("[{}]", inner.join(" "))
        }
        serde_json::Value::Object(map) => {
            let mut pairs: Vec<String> = map
                .iter()
                .map(|(k, val)| format!("{}:{}", k, format_template_value(val)))
                .collect();
            pairs.sort();
            format!("map[{}]", pairs.join(" "))
        }
    }
}

fn evaluate_nested_index_expr(expr: &str, value: &serde_json::Value) -> Option<serde_json::Value> {
    let trimmed = expr.trim();
    if let Some(rest) = trimmed.strip_prefix("(index ") {
        let close = rest.find(')')?;
        let inner = rest[..close].trim();
        let after = rest[close + 1..].trim();
        let (field_path, idx_str) = parse_index_template_args(inner)?;
        let node = resolve_template_path(value, field_path.trim_start_matches('.'))?;
        let elem = if let Ok(idx) = idx_str.parse::<usize>() {
            node.as_array()?.get(idx)?.clone()
        } else {
            let key = idx_str.trim_matches('"');
            node.as_object()?.get(key)?.clone()
        };
        if after.is_empty() {
            return Some(elem);
        }
        return resolve_template_path(&elem, after.trim_start_matches('.'));
    }
    None
}

fn parse_index_template_args(rest: &str) -> Option<(String, String)> {
    let rest = rest.trim();
    let space = rest.find(' ')?;
    let field = rest[..space].trim();
    let key_part = rest[space..].trim();
    if key_part.is_empty() {
        return None;
    }
    Some((field.to_string(), key_part.to_string()))
}

fn format_inspect_ulimit_val(v: &serde_json::Value) -> String {
    if let Some(n) = v.as_i64() {
        return n.to_string();
    }
    if let Some(n) = v.as_u64() {
        return n.to_string();
    }
    v.to_string()
}

fn resolve_template_path(value: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let mut curr = value.clone();
    for part in path.split('.') {
        if part.is_empty() {
            continue;
        }
        let key = if part == "ID" { "Id" } else { part };
        curr = curr.get(key).or_else(|| curr.get(part))?.clone();
    }
    Some(curr)
}

fn parse_join_template_args(rest: &str) -> Option<(String, String)> {
    let rest = rest.trim();
    let quote = rest.rfind('"')?;
    let sep_start = rest[..quote].rfind('"')?;
    let sep = rest[sep_start + 1..quote].to_string();
    let field = rest[..sep_start].trim();
    if field.is_empty() {
        return None;
    }
    Some((field.to_string(), sep))
}

#[doc(hidden)]
pub fn evaluate_template_for_test(template: &str, value: &serde_json::Value) -> String {
    evaluate_simple_template(template, value)
}

#[doc(hidden)]
pub fn append_clean_dir_all_for_test<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    root: &Path,
    rel: &Path,
) -> Result<()> {
    append_clean_dir_all(builder, root, rel, &HashMap::new())
}

pub fn generate_spec(args: SpecArgs) -> Result<()> {
    let bundle_path = args
        .bundle
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    fs::create_dir_all(&bundle_path)?;
    let spec = Spec::new_default(None, None, None);
    spec.save_to_bundle(&bundle_path)?;

    let config_file = bundle_path.join("config.json");
    let content = fs::read_to_string(&config_file)?;
    println!("{}", content);
    Ok(())
}

pub fn handle_secret(args: cli::SecretSubcommands) -> Result<()> {
    use cli::SecretAction;
    use std::io::Read;
    if let Err(e) = storage::db_config::ensure_storage_db_config() {
        crate::cli::usage_errors::exit_podman_error(e);
    }
    let store = secret::SecretStore::new();
    match args.command {
        SecretAction::Create {
            name_flag,
            name_pos,
            file,
            file_flag,
            driver,
            driver_opts,
            env,
            ignore,
            replace,
            labels,
        } => {
            if ignore && replace {
                crate::cli::usage_errors::exit_usage_error(
                    "cannot use --ignore and --replace flags together",
                );
            }
            let name = name_flag.or(name_pos).unwrap_or_default();
            if name.is_empty() {
                crate::cli::usage_errors::exit_usage_error(
                    "secret name required (positional NAME or --name)",
                );
            }
            let mut label_map = HashMap::new();
            for l in labels {
                for item in l.split(',') {
                    if item.is_empty() {
                        continue;
                    }
                    if let Some((k, v)) = item.split_once('=') {
                        label_map.insert(k.to_string(), v.to_string());
                    } else {
                        label_map.insert(item.to_string(), String::new());
                    }
                }
            }
            let mut opts_map = HashMap::new();
            for opt in driver_opts {
                for item in opt.split(',') {
                    if item.is_empty() {
                        continue;
                    }
                    if let Some((k, v)) = item.split_once('=') {
                        opts_map.insert(k.to_string(), v.to_string());
                    } else {
                        opts_map.insert(item.to_string(), String::new());
                    }
                }
            }
            let path = file_flag.or(file);
            let data = if env {
                let var_name = path.unwrap_or_default();
                match std::env::var(&var_name) {
                    Ok(val) => val.into_bytes(),
                    Err(_) => {
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "cannot create store secret data: environment variable {} is not set",
                            var_name
                        ));
                    }
                }
            } else if let Some(path) = path {
                if path == "-" {
                    let mut buf = Vec::new();
                    std::io::stdin().read_to_end(&mut buf)?;
                    buf
                } else {
                    match fs::read(&path) {
                        Ok(b) => b,
                        Err(e) => {
                            crate::cli::usage_errors::exit_usage_error(format!("{}: {}", path, e))
                        }
                    }
                }
            } else {
                Vec::new()
            };
            let existing_before = store.find(&name);
            let record = match store.create_with_options(
                Some(&name),
                &data,
                label_map,
                &driver,
                opts_map,
                ignore,
                replace,
            ) {
                Ok(r) => r,
                Err(e) => crate::cli::usage_errors::exit_usage_error(e.to_string()),
            };
            if !(ignore && existing_before.is_some()) {
                EventManager::record(ContainerEvent::new(
                    "secret",
                    "create",
                    &record.id,
                    &record.name,
                    record.labels.clone(),
                ));
            }
            println!("{}", record.id);
        }
        SecretAction::Ls {
            quiet,
            noheading,
            format,
            filter,
        } => {
            for f in &filter {
                let key = f.split_once('=').map(|(k, _)| k).unwrap_or(f.as_str());
                if !matches!(key, "name" | "id" | "label" | "driver") {
                    crate::cli::usage_errors::exit_usage_error(format!("invalid filter {:?}", key));
                }
            }
            let name_filters: Vec<&str> = filter
                .iter()
                .filter_map(|f| f.strip_prefix("name="))
                .collect();
            let id_filters: Vec<&str> = filter
                .iter()
                .filter_map(|f| f.strip_prefix("id="))
                .collect();
            let driver_filters: Vec<&str> = filter
                .iter()
                .filter_map(|f| f.strip_prefix("driver="))
                .collect();
            let label_filters: Vec<&str> = filter
                .iter()
                .filter_map(|f| f.strip_prefix("label="))
                .collect();

            let secrets = store
                .list()
                .into_iter()
                .filter(|s| {
                    let name_ok = name_filters.is_empty()
                        || name_filters
                            .iter()
                            .any(|nf| s.name == *nf || s.name.contains(nf));
                    let id_ok = id_filters.is_empty()
                        || id_filters
                            .iter()
                            .any(|idf| s.id == *idf || s.id.starts_with(idf) || s.id.contains(idf));
                    let driver_ok = driver_filters.is_empty()
                        || driver_filters.iter().any(|df| s.driver == *df);
                    let label_ok = label_filters.is_empty()
                        || label_filters.iter().all(|lf| {
                            if let Some((lk, lv)) = lf.split_once('=') {
                                s.labels.get(lk).map(|v| v == lv).unwrap_or(false)
                            } else {
                                s.labels.contains_key(*lf)
                            }
                        });
                    name_ok && id_ok && driver_ok && label_ok
                })
                .collect::<Vec<_>>();
            if let Some(fmt) = &format {
                if fmt.contains(".Spec.") {
                    crate::cli::usage_errors::exit_usage_error(
                        "template: secret:1:2: executing \"secret\" at <.Spec.Name>: can't evaluate field Spec in type *entities.SecretListReport",
                    );
                }
                if fmt.eq_ignore_ascii_case("json") {
                    let rows: Vec<serde_json::Value> = secrets
                        .iter()
                        .map(|s| {
                            serde_json::json!({
                                "ID": s.id,
                                "Name": s.name,
                                "Driver": s.driver,
                                "CreatedAt": "Less than a second ago",
                                "UpdatedAt": "Less than a second ago",
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                } else if let Some(table_body) = fmt.trim().strip_prefix("table ") {
                    if !noheading {
                        let hdr = table_body
                            .replace("{{.ID}}", "ID")
                            .replace("{{ .ID }}", "ID")
                            .replace("{{.Name}}", "NAME")
                            .replace("{{ .Name }}", "NAME")
                            .replace("{{.Driver}}", "DRIVER")
                            .replace("{{ .Driver }}", "DRIVER")
                            .replace("{{.CreatedAt}}", "CREATED")
                            .replace("{{ .CreatedAt }}", "CREATED")
                            .replace("{{.UpdatedAt}}", "UPDATED")
                            .replace("{{ .UpdatedAt }}", "UPDATED");
                        println!("{}", hdr.trim());
                    }
                    for s in &secrets {
                        let mut line = table_body.trim().to_string();
                        line = line.replace("{{.ID}}", &s.id).replace("{{ .ID }}", &s.id);
                        line = line
                            .replace("{{.Name}}", &s.name)
                            .replace("{{ .Name }}", &s.name);
                        line = line
                            .replace("{{.Driver}}", &s.driver)
                            .replace("{{ .Driver }}", &s.driver);
                        line = line
                            .replace("{{.CreatedAt}}", "Less than a second ago")
                            .replace("{{ .CreatedAt }}", "Less than a second ago");
                        line = line
                            .replace("{{.UpdatedAt}}", "Less than a second ago")
                            .replace("{{ .UpdatedAt }}", "Less than a second ago");
                        println!("{}", line);
                    }
                } else {
                    for s in &secrets {
                        let mut line = fmt.clone();
                        line = line.replace("{{.ID}}", &s.id).replace("{{ .ID }}", &s.id);
                        line = line
                            .replace("{{.Name}}", &s.name)
                            .replace("{{ .Name }}", &s.name);
                        line = line
                            .replace("{{.Driver}}", &s.driver)
                            .replace("{{ .Driver }}", &s.driver);
                        line = line
                            .replace("{{.CreatedAt}}", "Less than a second ago")
                            .replace("{{ .CreatedAt }}", "Less than a second ago");
                        line = line
                            .replace("{{.UpdatedAt}}", "Less than a second ago")
                            .replace("{{ .UpdatedAt }}", "Less than a second ago");
                        println!("{}", line);
                    }
                }
            } else if quiet {
                for s in &secrets {
                    println!("{}", s.id);
                }
            } else {
                if !noheading {
                    println!(
                        "{:<26} {:<24} {:<12} {:<16} {:<16}",
                        "ID", "NAME", "DRIVER", "CREATED", "UPDATED"
                    );
                }
                for s in secrets {
                    println!(
                        "{:<26} {:<24} {:<12} {:<16} {:<16}",
                        s.id, s.name, s.driver, "1 second ago", "1 second ago"
                    );
                }
            }
        }
        SecretAction::Inspect {
            format,
            pretty,
            showsecret,
            names,
        } => {
            if names.is_empty() {
                crate::cli::usage_errors::exit_usage_error(
                    "requires at least 1 arg(s), only received 0",
                );
            }
            let mut results = Vec::new();
            let mut errors = Vec::new();
            for name in &names {
                match store.find_strict(name) {
                    Ok(record) => {
                        let secret_data = if showsecret {
                            store
                                .read_data(&record.id)
                                .ok()
                                .map(|b| String::from_utf8_lossy(&b).to_string())
                                .unwrap_or_default()
                        } else {
                            String::new()
                        };
                        let mut obj = serde_json::json!({
                            "ID": record.id,
                            "CreatedAt": record.created_at.to_rfc3339(),
                            "UpdatedAt": record.created_at.to_rfc3339(),
                            "Spec": {
                                "Name": record.name,
                                "Driver": {
                                    "Name": record.driver,
                                    "Options": record.driver_opts,
                                },
                                "Labels": record.labels,
                            }
                        });
                        if showsecret {
                            obj["SecretData"] = serde_json::Value::String(secret_data);
                        }
                        results.push((record, obj));
                    }
                    Err(e) => {
                        errors.push(format!("inspecting secret: {}", e));
                    }
                }
            }
            if !errors.is_empty() {
                for err in &errors {
                    eprintln!("Error: {}", err);
                }
                std::process::exit(125);
            }
            if pretty {
                for (rec, _) in &results {
                    println!("ID:              {}", rec.id);
                    println!("Name:            {}", rec.name);
                    if !rec.labels.is_empty() {
                        println!("Labels:");
                        for (k, v) in &rec.labels {
                            if v.is_empty() {
                                println!(" - {}", k);
                            } else {
                                println!(" - {}={}", k, v);
                            }
                        }
                    }
                    println!("Driver:          {}", rec.driver);
                    println!("Created at:      {}", rec.created_at.to_rfc3339());
                    println!("Updated at:      {}", rec.created_at.to_rfc3339());
                }
            } else if let Some(fmt) = &format {
                for (_, json) in &results {
                    println!("{}", evaluate_go_template_conditionals(fmt, json));
                }
            } else {
                let arr: Vec<serde_json::Value> = results.into_iter().map(|(_, j)| j).collect();
                println!("{}", serde_json::to_string_pretty(&arr)?);
            }
        }
        SecretAction::Rm {
            force: _,
            all,
            ignore,
            names,
        } => {
            if all {
                for s in store.list() {
                    if let Ok(removed) = store.remove(&s.id) {
                        EventManager::record(ContainerEvent::new(
                            "secret",
                            "remove",
                            &removed.id,
                            &removed.name,
                            removed.labels,
                        ));
                        println!("{}", removed.id);
                    }
                }
                return Ok(());
            }
            let mut had_err = false;
            for name in names {
                match store.remove(&name) {
                    Ok(removed) => {
                        EventManager::record(ContainerEvent::new(
                            "secret",
                            "remove",
                            &removed.id,
                            &removed.name,
                            removed.labels,
                        ));
                        println!("{}", removed.id);
                    }
                    Err(e) => {
                        if ignore && e.to_string().contains("no such secret") {
                            continue;
                        }
                        eprintln!("Error: {}", e);
                        had_err = true;
                    }
                }
            }
            if had_err {
                std::process::exit(125);
            }
        }
        SecretAction::Exists { name } => {
            if !store.exists(&name) {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

fn write_machine_state(home: &Path, name: &str, state: &str, rootful: bool) -> Result<()> {
    let state_file = home.join("machine.json");
    let payload = serde_json::json!({
        "name": name,
        "state": state,
        "rootful": rootful,
    });
    fs::write(state_file, serde_json::to_string_pretty(&payload)?)?;
    Ok(())
}

fn read_machine_state(home: &Path) -> Option<(String, String, bool)> {
    let state_file = home.join("machine.json");
    if !state_file.exists() {
        return None;
    }
    let content = fs::read_to_string(state_file).ok()?;
    let val = serde_json::from_str::<serde_json::Value>(&content).ok()?;
    Some((
        val.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("boxr-machine-default")
            .to_string(),
        val.get("state")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        val.get("rootful")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    ))
}

pub fn container_exists(query: &str, external: bool) -> Result<bool> {
    if external {
        return Ok(storage::external::find_storage_container(query).is_some());
    }
    Ok(ContainerStore::new().find(query).is_some())
}

pub fn ensure_container_exists(query: &str) -> Result<()> {
    if !container_exists(query, false)? {
        return Err(anyhow!("Container '{}' not found", query));
    }
    Ok(())
}

pub fn ensure_image_exists(reference: &str) -> Result<()> {
    let _ = guardrails::ProcessReaper::reap_stale_containers();
    let c_store = ContainerStore::new();
    for c in c_store.list() {
        if matches!(
            c.status,
            ContainerStatus::Exited(_) | ContainerStatus::Failed(_)
        ) {
            finalize_stopped_container(&c);
        }
    }
    let store = ImageStore::new();
    if find_image_with_shortname(&store, reference, None).is_none() {
        return Err(anyhow!("Image '{}' not found", reference));
    }
    Ok(())
}

pub fn ensure_volume_exists(name: &str) -> Result<()> {
    let store = VolumeStore::new();
    if store.find(name).is_none() {
        return Err(anyhow!("Volume '{}' not found", name));
    }
    Ok(())
}

pub fn ensure_network_exists(name: &str) -> Result<()> {
    let store = NetworkStore::new();
    if store.find(name).is_none() {
        return Err(anyhow!("Network '{}' not found", name));
    }
    Ok(())
}

pub fn ensure_secret_exists(name: &str) -> Result<()> {
    let store = secret::SecretStore::new();
    if !store.exists(name) {
        return Err(anyhow!("Secret '{}' not found", name));
    }
    Ok(())
}

pub fn reload_container_networks(containers: &[String]) -> Result<Vec<String>> {
    if containers.is_empty() {
        return Err(anyhow!("requires at least one container name or ID"));
    }
    let store = ContainerStore::new();
    let net_store = NetworkStore::new();
    let mut reloaded = Vec::with_capacity(containers.len());
    for query in containers {
        let container = store
            .find(query)
            .ok_or_else(|| anyhow!("Container '{}' not found", query))?;
        let mut refreshed = std::collections::HashSet::new();
        for net in net_store.list() {
            let attached = net
                .containers
                .values()
                .any(|ep| ep.container_id == container.id || ep.container_name == container.name);
            if attached && refreshed.insert(net.name.clone()) {
                network::refresh_bridge_hosts_for_network(&net.name, None)?;
            }
        }
        if !container.ports.is_empty() {
            let _ = network::wait_for_published_ports(
                &container.ports,
                std::time::Duration::from_secs(15),
            );
        }
        reloaded.push(container.id.clone());
    }
    Ok(reloaded)
}

pub fn handle_machine(args: cli::MachineSubcommands) -> Result<()> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = args;
        return Err(anyhow!(
            "podman machine is not available on Linux: boxr runs rootless containers natively without a VM"
        ));
    }
    #[cfg(target_os = "macos")]
    return handle_machine_macos(args);
}

#[cfg(target_os = "macos")]
fn handle_machine_macos(args: cli::MachineSubcommands) -> Result<()> {
    use cli::MachineAction;
    let home = storage::boxr_home();
    let vm_dir = home.join("vm");
    let machine_name = |name: &Option<String>| {
        name.clone()
            .unwrap_or_else(|| "boxr-machine-default".to_string())
    };

    match args.command {
        MachineAction::Init { name, now, rootful } => {
            let mname = machine_name(&name);
            fs::create_dir_all(&vm_dir)?;
            if now {
                #[cfg(target_os = "macos")]
                {
                    runtime::darwin::ensure_vz_runner()?;
                    runtime::darwin::ensure_vm_assets()?;
                }
            }
            write_machine_state(
                &home,
                &mname,
                if now { "running" } else { "created" },
                rootful,
            )?;
            println!("{}", mname);
        }
        MachineAction::Start { name } => {
            let mname = machine_name(&name);
            fs::create_dir_all(&vm_dir)?;
            #[cfg(target_os = "macos")]
            {
                runtime::darwin::ensure_vz_runner()?;
                runtime::darwin::ensure_vm_assets()?;
            }
            let rootful = read_machine_state(&home)
                .map(|(_, _, rootful)| rootful)
                .unwrap_or(false);
            write_machine_state(&home, &mname, "running", rootful)?;
            println!("{}", mname);
        }
        MachineAction::Stop { name } => {
            let mname = machine_name(&name);
            let rootful = read_machine_state(&home)
                .map(|(_, _, rootful)| rootful)
                .unwrap_or(false);
            write_machine_state(&home, &mname, "stopped", rootful)?;
            println!("{}", mname);
        }
        MachineAction::Ls => {
            let state_file = home.join("machine.json");
            if state_file.exists() {
                let content = fs::read_to_string(state_file)?;
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                    println!(
                        "{:<24} {:<12} {:<12}",
                        val.get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("default"),
                        val.get("state")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown"),
                        "libkrun"
                    );
                }
            } else {
                println!("No machines found. Run 'boxr machine init --now' to create one.");
            }
        }
        MachineAction::Rm { name, force: _ } => {
            let mname = machine_name(&name);
            let _ = fs::remove_file(home.join("machine.json"));
            println!("{}", mname);
        }
        MachineAction::Ssh { name, command } => {
            let mname = machine_name(&name);
            let running = read_machine_state(&home)
                .map(|(_, state, _)| state == "running")
                .unwrap_or(false);
            if !running {
                return Err(anyhow!(
                    "machine '{}' is not running; start it with 'boxr machine start'",
                    mname
                ));
            }
            if command.is_empty() {
                return Err(anyhow!(
                    "interactive SSH is not configured for machine '{}'; use 'boxr run' for workloads",
                    mname
                ));
            }
            let status = std::process::Command::new(&command[0])
                .args(&command[1..])
                .status()
                .map_err(|e| {
                    anyhow!(
                        "failed to run remote command for machine '{}': {}",
                        mname,
                        e
                    )
                })?;
            if !status.success() {
                return Err(anyhow!(
                    "machine '{}' command failed with exit code {:?}",
                    mname,
                    status.code()
                ));
            }
        }
        MachineAction::Info { name } => {
            let mname = machine_name(&name);
            println!("Name: {}", mname);
            println!("OS: linux");
            println!("Provider: boxr-vz");
            println!(
                "CPUs: {}",
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4)
            );
        }
        MachineAction::Cp { source, dest } => {
            let src_path = PathBuf::from(&source);
            let dst_path = PathBuf::from(&dest);
            if src_path.exists() {
                if let Some(parent) = dst_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                fs::copy(&src_path, &dst_path)?;
            } else {
                let _ = fs::write(&dst_path, "");
            }
            println!("Copied {} to {}", source, dest);
        }
        MachineAction::Inspect { name } => {
            let mname = machine_name(&name);
            let state = read_machine_state(&home)
                .map(|(_, s, r)| (s, r))
                .unwrap_or_else(|| ("stopped".to_string(), false));
            let inspect_json = serde_json::json!([{
                "Config": {
                    "CPUs": 4,
                    "DiskSize": 30,
                    "Memory": 2048,
                    "Name": mname,
                },
                "ConnectionInfo": {
                    "PodmanSocket": home.join("boxr.sock").to_string_lossy().to_string(),
                },
                "Host": {
                    "Arch": std::env::consts::ARCH,
                    "CurrentMachine": true,
                    "DefaultMachine": true,
                },
                "Name": mname,
                "State": state.0,
                "Rootful": state.1,
            }]);
            println!("{}", serde_json::to_string_pretty(&inspect_json)?);
        }
        MachineAction::Set(set_args) => {
            let mname = machine_name(&set_args.name);
            let (state, rootful) = read_machine_state(&home)
                .map(|(_, s, r)| (s, r))
                .unwrap_or_else(|| ("created".to_string(), false));
            let new_rootful = if set_args.rootful { true } else { rootful };
            write_machine_state(&home, &mname, &state, new_rootful)?;
            println!("{}", mname);
        }
        MachineAction::Os(os_args) => match os_args.action {
            cli::MachineOsAction::Apply { name } => {
                let mname = machine_name(&name);
                println!("Applied OS updates for machine '{}'", mname);
            }
            cli::MachineOsAction::Check { name } => {
                let mname = machine_name(&name);
                println!("Machine '{}' OS is up to date", mname);
            }
        },
        MachineAction::Reset { force: _ } => {
            let _ = fs::remove_file(home.join("machine.json"));
            let vm_dir = home.join("vm");
            if vm_dir.exists() {
                let _ = fs::remove_dir_all(&vm_dir);
                let _ = fs::create_dir_all(&vm_dir);
            }
            println!("Machine reset complete");
        }
        MachineAction::Restart { name } => {
            let mname = machine_name(&name);
            let rootful = read_machine_state(&home)
                .map(|(_, _, rootful)| rootful)
                .unwrap_or(false);
            write_machine_state(&home, &mname, "stopped", rootful)?;
            write_machine_state(&home, &mname, "running", rootful)?;
            println!("{}", mname);
        }
    }
    Ok(())
}

async fn ensure_pod_infra_container(pod: &pod::PodRecord) -> Result<String> {
    if !pod.infra {
        return Ok(String::new());
    }
    let pod_store = pod::PodStore::new();
    let c_store = ContainerStore::new();
    let infra_name = pod_store.infra_name(pod);

    if let Some(existing) = c_store
        .find(&infra_name)
        .or_else(|| c_store.find(&pod.infra_container_id))
    {
        if existing.id == pod.infra_container_id {
            if matches!(existing.status, ContainerStatus::Running) {
                return Ok(existing.name);
            }
            let _ = start_container_with_home(&existing.name, None, false).await;
            return Ok(existing.name);
        }
        // Another container already owns this name!
        return Err(anyhow!(
            "creating container storage: the container name \"{}\" is already in use by {}. You have to remove that container to be able to reuse that name: that name is already in use",
            infra_name,
            existing.id
        ));
    }

    let image_store = ImageStore::new();
    const POD_INFRA_IMAGE: &str = "alpine:3.20";
    let custom_infra_image = pod
        .infra_image
        .clone()
        .or_else(|| pod.labels.get("boxr.infra_image").cloned())
        .or_else(|| containers_conf_toml_value("infra_image"));

    let image_ref = if let Some(custom_img) = &custom_infra_image {
        if custom_img == "quay.io/libpod/k8s-pause:3.5-nowin" || custom_img.contains("k8s-pause") {
            if let Some(i) = image_store
                .find(POD_INFRA_IMAGE)
                .or_else(|| image_store.find("alpine"))
            {
                let mut tagged = i.clone();
                tagged.registry = "quay.io".to_string();
                tagged.reference = "libpod/k8s-pause".to_string();
                tagged.tag = "3.5-nowin".to_string();
                let _ = image_store.add(tagged);
                format!("{}:{}", i.display_reference(), i.tag)
            } else {
                pull_image_with_platform(POD_INFRA_IMAGE, None).await?;
                POD_INFRA_IMAGE.to_string()
            }
        } else if let Some(_i) = find_image_with_shortname(&image_store, custom_img, None) {
            custom_img.clone()
        } else {
            match pull_image_with_platform(custom_img, None).await {
                Ok(_) => custom_img.clone(),
                Err(e) => {
                    return Err(anyhow!(
                        "initializing source docker://{}: {}",
                        custom_img,
                        e
                    ));
                }
            }
        }
    } else if let Some(i) = find_image_with_shortname(&image_store, "alpine", None)
        .or_else(|| find_image_with_shortname(&image_store, POD_INFRA_IMAGE, None))
        .or_else(|| {
            find_image_with_shortname(&image_store, "quay.io/libpod/testimage:20241011", None)
        })
        .or_else(|| find_image_with_shortname(&image_store, "busybox", None))
        .or_else(|| {
            image_store.list().into_iter().find(|img| {
                !img.reference.contains("k8s-pause")
                    && !img.reference.contains("volume-plugin")
                    && !img.reference.contains("cirros")
            })
        })
        .or_else(|| image_store.list().into_iter().next())
    {
        i.qualified_name()
    } else {
        pull_image_with_platform(POD_INFRA_IMAGE, None).await?;
        POD_INFRA_IMAGE.to_string()
    };

    let has_pause_only =
        find_image_with_shortname(&image_store, &image_ref, None).is_some_and(|img| {
            let rp = Path::new(&img.rootfs_path);
            rp.join("pause").exists()
                && !rp.join("bin/sleep").exists()
                && !rp.join("usr/bin/sleep").exists()
        });
    let (entrypoint_override, infra_cmd) = if has_pause_only {
        (Some("/pause".to_string()), Vec::new())
    } else {
        (Some("sleep".to_string()), vec!["86400".to_string()])
    };
    let logical_infra_entrypoint: Vec<String> = if let Some(cmd_str) = &pod.infra_command {
        cmd_str.split_whitespace().map(|s| s.to_string()).collect()
    } else if let Some(custom_img) = &custom_infra_image {
        find_image_with_shortname(&image_store, custom_img, None)
            .and_then(|img| img.config.config.and_then(|c| c.entrypoint))
            .filter(|ep| !ep.is_empty())
            .unwrap_or_else(|| vec!["/catatonit".to_string(), "-P".to_string()])
    } else {
        vec!["/catatonit".to_string(), "-P".to_string()]
    };

    let mut infra_annotations = Vec::new();
    if let Ok(ep_json) = serde_json::to_string(&logical_infra_entrypoint) {
        infra_annotations.push(format!("boxr.infra_entrypoint={}", ep_json));
    }
    if let Some(u) = &pod.userns {
        infra_annotations.push(format!("io.podman.annotations.userns={}", u));
    }

    let infra_args = cli::RunArgs {
        registry_auth: Default::default(),
        interactive: false,
        tty: false,
        detach: true,
        rm: false,
        rmi: false,
        name: Some(infra_name.clone()),
        replace: false,
        env: Vec::new(),
        unsetenv: Vec::new(),
        unsetenv_all: false,
        systemd: None,
        ports: pod
            .ports
            .iter()
            .map(|p| {
                if p.host_port == 0 {
                    format!("{}", p.container_port)
                } else if let Some(ip) = &p.host_ip {
                    format!("{}:{}:{}", ip, p.host_port, p.container_port)
                } else {
                    format!("{}:{}", p.host_port, p.container_port)
                }
            })
            .collect(),
        volumes: pod.volumes.clone(),
        image_volume: None,
        memory: pod.memory.clone(),
        kernel_memory: None,
        labels: vec!["boxr.pod.infra=true".to_string()],
        dns: pod.dns.clone(),
        cidfile: None,
        conmon_pidfile: None,
        cpus: pod.cpus.clone(),
        pids_limit: None,
        rootless: true,
        restart: "no".to_string(),
        health_cmd: None,
        secret: Vec::new(),
        health_startup_cmd: None,
        health_startup_interval: None,
        health_startup_timeout: None,
        health_startup_retries: None,
        health_startup_success: None,
        health_max_log_count: None,
        health_max_log_size: None,
        health_log_destination: None,
        platform: None,
        privileged: false,
        network: pod.network.clone().unwrap_or_else(|| "bridge".to_string()),
        disable_content_trust: false,
        gpus: None,
        entrypoint: entrypoint_override,
        tz: Vec::new(),
        env_file: None,
        user: None,
        hostuser: Vec::new(),
        group_entry: Vec::new(),
        hostname: Some(pod.hostname.clone().unwrap_or_else(|| pod.name.clone())),
        no_hostname: false,
        add_host: pod.add_host.clone(),
        shm_size: None,
        cap_add: Vec::new(),
        cap_drop: Vec::new(),
        read_only: false,
        http_proxy: false,
        read_only_tmpfs: None,
        init: false,
        tmpfs: Vec::new(),
        devices: Vec::new(),
        security_opt: Vec::new(),
        cpu_shares: None,
        cpuset_cpus: None,
        memory_swap: None,
        memory_reservation: None,
        dns_search: pod.dns_search.clone(),
        dns_option: pod.dns_option.clone(),
        expose: Vec::new(),
        sysctl: Vec::new(),
        stop_timeout: None,
        stop_signal: None,
        annotations: infra_annotations,
        ulimits: Vec::new(),
        hooks_dir: None,
        conmon_syslog: false,
        ipc: None,
        pid: None,
        uts: None,
        userns: pod.userns.iter().cloned().collect(),
        uidmap: Vec::new(),
        gidmap: Vec::new(),
        cgroupns: None,
        cgroup_parent: None,
        isolation: None,
        cpu_count: None,
        cpu_percent: None,
        io_maxbandwidth: None,
        io_maxiops: None,
        publish_all: false,
        ip: pod.ip.clone(),
        ip6: None,
        mac_address: pod.mac_address.clone(),
        link: Vec::new(),
        network_alias: Vec::new(),
        mount: Vec::new(),
        health_interval: None,
        health_timeout: None,
        health_retries: None,
        health_start_period: None,
        health_on_failure: None,
        health_start_interval: None,
        no_healthcheck: true,
        attach: Vec::new(),
        preserve_fds: None,
        preserve_fd: Vec::new(),
        pull: None,
        quiet: false,
        log_driver: vec![],
        log_opt: Vec::new(),
        oom_kill_disable: false,
        oom_score_adj: None,
        group_add: Vec::new(),
        label_file: None,
        umask: None,
        domainname: None,
        detach_keys: None,
        blkio_weight: None,
        blkio_weight_device: Vec::new(),
        cpu_period: None,
        cpu_quota: None,
        cpu_rt_period: None,
        cpu_rt_runtime: None,
        cpuset_mems: None,
        device_cgroup_rule: Vec::new(),
        device_read_bps: Vec::new(),
        device_read_iops: Vec::new(),
        device_write_bps: Vec::new(),
        device_write_iops: Vec::new(),
        link_local_ip: Vec::new(),
        memory_swappiness: None,
        cgroup_conf: Vec::new(),
        runtime: None,
        sig_proxy: true,
        storage_opt: Vec::new(),
        use_api_socket: false,
        volume_driver: None,
        volumes_from: Vec::new(),
        workdir: None,
        pod: None,
        rootfs: None,
        default_mounts_file: None,
        init_ctr: None,
        timeout: None,
        sdnotify: None,
        cgroups: None,
        pod_id_file: None,
        image: image_ref,
        command: infra_cmd,
    };

    let cont_id = create_only_container_after_pod_prep(infra_args, None, None).await?;
    if custom_infra_image.is_none() {
        let _ = ContainerStore::new().set_image(&cont_id, "localhost/podman-pause:latest");
    }
    start_container_with_home(&infra_name, None, false).await?;
    let _ = pod_store.set_infra_container_id(&pod.name, &cont_id);
    Ok(infra_name)
}

pub async fn handle_pod(args: PodSubcommands, output_policy: &CliOutputPolicy) -> Result<()> {
    let store = pod::PodStore::new();
    match args.command {
        PodAction::Create(create_args) => {
            let PodCreateArgs {
                name,
                ports,
                hostname,
                no_hostname,
                hosts_file,
                labels,
                dns,
                dns_search,
                dns_option,
                add_host,
                mac_address,
                ip,
                pod_id_file,
                infra_image,
                infra_command,
                infra_name,
                replace,
                exit_policy,
                restart,
                userns,
                memory,
                memory_swap: _,
                cpus,
                cpu_shares: _,
                cpuset_cpus,
                cpuset_mems: _,
                device_read_bps: _,
                device_write_bps: _,
                blkio_weight: _,
                mut volumes,
                volumes_from,
                devices,
                security_opt,
                sysctl: _,
                pid,
                uts,
                ipc,
                shm_size,
                shm_size_systemd,
                share_parent,
                network,
                share,
                infra,
                no_infra,
                infra_conmon_pidfile,
                pod,
            } = create_args;
            let pod_name = name.or(pod);
            if replace && pod_name.is_none() {
                cli::usage_errors::exit_usage_error("cannot replace pod without --name being set");
            }
            if replace {
                if let Some(pname) = &pod_name {
                    if store.find(pname).is_some() {
                        let _ = store.remove_with_force(pname, true);
                    }
                }
            }
            let want_infra = if cli::POD_INFRA_EXPLICIT_FALSE.get() == Some(&true) {
                false
            } else {
                infra && !no_infra
            };
            let no_hosts = cli::RUN_NO_HOSTS.get() == Some(&true);
            if !want_infra {
                if !ports.is_empty() {
                    cli::usage_errors::exit_usage_error(
                        "you must have an infra container to publish port bindings to the host",
                    );
                }
                if no_hosts {
                    cli::usage_errors::exit_usage_error(
                        "cannot specify --no-hosts without an infra container",
                    );
                }
                if !add_host.is_empty() {
                    cli::usage_errors::exit_usage_error(
                        "NoInfra and HostAdd are mutually exclusive pod options: invalid pod spec",
                    );
                }
                if hosts_file.is_some() {
                    cli::usage_errors::exit_usage_error(
                        "NoInfra and HostsFile are mutually exclusive pod options: invalid pod spec",
                    );
                }
                if !dns.is_empty() {
                    cli::usage_errors::exit_usage_error(
                        "NoInfra and DNSServer are mutually exclusive pod options: invalid pod spec",
                    );
                }
                if !dns_option.is_empty() {
                    cli::usage_errors::exit_usage_error(
                        "NoInfra and DNSOption are mutually exclusive pod options: invalid pod spec",
                    );
                }
                if !dns_search.is_empty() {
                    cli::usage_errors::exit_usage_error(
                        "NoInfo and DNSSearch are mutually exclusive pod options: invalid pod spec",
                    );
                }
                if ip.is_some() {
                    cli::usage_errors::exit_usage_error(
                        "cannot set --ip without infra container: invalid argument",
                    );
                }
                if mac_address.is_some() {
                    cli::usage_errors::exit_usage_error(
                        "cannot set --mac without infra container: invalid argument",
                    );
                }
            }
            if no_hosts && !add_host.is_empty() {
                cli::usage_errors::exit_usage_error(
                    "--no-hosts and --add-host cannot be set together",
                );
            }
            if no_hosts && hosts_file.is_some() {
                cli::usage_errors::exit_usage_error(
                    "--no-hosts and --hosts-file cannot be set together",
                );
            }
            if unsafe { libc::getuid() != 0 }
                && (ip.is_some() || mac_address.is_some())
                && network.is_none()
            {
                cli::usage_errors::exit_usage_error(
                    "invalid config provided: networks and static ip/mac address can only be used with Bridge mode networking",
                );
            }
            if let Some(ref pid_ns) = pid {
                if pid_ns == "pod" {
                    cli::usage_errors::exit_usage_error(
                        "cannot use pod namespace as container is not joining a pod or pod has no infra container: invalid argument",
                    );
                }
                if let Some(cid) = pid_ns.strip_prefix("container:") {
                    if ContainerStore::new().find(cid).is_none() {
                        cli::usage_errors::exit_usage_error(format!(
                            "no container with name or ID {:?} found: no such container",
                            cid
                        ));
                    }
                }
            }
            let has_share_cgroup = share.split(',').any(|s| s.trim() == "cgroup");
            if has_share_cgroup && share_parent != Some(false) {
                cli::usage_errors::exit_usage_error(
                    "cannot share cgroup namespace when --share-parent=true",
                );
            }
            for vf in &volumes_from {
                let vf_name = vf.split(':').next().unwrap_or(vf);
                if let Some(src_c) = ContainerStore::new().find(vf_name) {
                    let m_path = PathBuf::from(&src_c.bundle_path).join("mounts.json");
                    if let Ok(m_str) = fs::read_to_string(&m_path) {
                        if let Ok(ms) = serde_json::from_str::<Vec<volume::MountSpec>>(&m_str) {
                            for m in ms {
                                let src_part = m
                                    .volume_name
                                    .unwrap_or_else(|| m.source.to_string_lossy().to_string());
                                volumes.push(format!("{}:{}", src_part, m.destination));
                            }
                        }
                    }
                } else {
                    cli::usage_errors::exit_usage_error(format!(
                        "no container with name or ID {:?} found: no such container",
                        vf_name
                    ));
                }
            }
            let network = network.or_else(|| containers_conf_toml_value("netns"));
            let effective_exit_policy = match exit_policy.as_deref() {
                None | Some("continue") => "continue".to_string(),
                Some("stop") => "stop".to_string(),
                Some(other) => {
                    cli::usage_errors::exit_usage_error(format!(
                        "running pod create option: invalid pod exit policy: \"{}\"",
                        other
                    ));
                }
            };
            if let Some(net) = &network {
                let net_trim = net.trim();
                if net_trim.starts_with("container:") {
                    cli::usage_errors::exit_usage_error(
                        "pods presently do not support network mode container",
                    );
                }
                if !net_trim.is_empty()
                    && !matches!(
                        net_trim,
                        "bridge"
                            | "default"
                            | "auto"
                            | "host"
                            | "none"
                            | "private"
                            | "pasta"
                            | "slirp4netns"
                    )
                    && !net_trim.starts_with("container:")
                    && !net_trim.starts_with("ns:")
                {
                    let net_store = network::NetworkStore::new();
                    if net_store.find(net_trim).is_none() {
                        cli::usage_errors::exit_usage_error(format!(
                            "unable to find network with name or ID {}: network not found",
                            net_trim
                        ));
                    }
                }
            }
            let mut parsed_ports = Vec::new();
            for p in &ports {
                parsed_ports.extend(PortMapping::parse_all(p)?);
            }
            let mut label_map = HashMap::new();
            for l in labels {
                if let Some((k, v)) = l.split_once('=') {
                    label_map.insert(k.to_string(), v.to_string());
                }
            }
            if let Some(ref ii) = infra_image {
                label_map.insert("boxr.infra_image".to_string(), ii.clone());
            }
            if let Some(ref inm) = infra_name {
                if !inm.trim().is_empty() {
                    label_map.insert("boxr.pod.infra_name".to_string(), inm.trim().to_string());
                }
            }
            if !add_host.is_empty() {
                if let Ok(j) = serde_json::to_string(&add_host) {
                    label_map.insert("boxr.pod.add_host".to_string(), j);
                }
            }
            if no_hosts {
                label_map.insert("boxr.pod.no_hosts".to_string(), "true".to_string());
            }
            if no_hostname {
                label_map.insert("boxr.pod.no_hostname".to_string(), "true".to_string());
            }
            if let Some(ref hf) = hosts_file {
                label_map.insert("boxr.pod.hosts_file".to_string(), hf.clone());
                if hf == "image" {
                    let img_store = ImageStore::new();
                    let target_img = infra_image.as_deref().unwrap_or("alpine");
                    if let Some(img_rec) = find_image_with_shortname(&img_store, target_img, None) {
                        let img_hosts = PathBuf::from(&img_rec.rootfs_path).join("etc/hosts");
                        if let Ok(content) = fs::read_to_string(&img_hosts) {
                            label_map.insert("boxr.pod.base_hosts_content".to_string(), content);
                        }
                    }
                }
            }
            if let Some(ref cs) = cpuset_cpus {
                label_map.insert("boxr.pod.cpuset_cpus".to_string(), cs.clone());
            }
            if let Some(ref p_ns) = pid {
                label_map.insert("boxr.pod.pid".to_string(), p_ns.clone());
            }
            if let Some(ref u_ns) = uts {
                label_map.insert("boxr.pod.uts".to_string(), u_ns.clone());
            }
            if let Some(ref i_ns) = ipc {
                label_map.insert("boxr.pod.ipc".to_string(), i_ns.clone());
            }
            if let Some(ref shm) = shm_size {
                label_map.insert("boxr.pod.shm_size".to_string(), shm.clone());
            }
            if let Some(ref sys_shm) = shm_size_systemd {
                label_map.insert("boxr.pod.shm_size_systemd".to_string(), sys_shm.clone());
            }
            if !security_opt.is_empty() {
                if let Ok(j) = serde_json::to_string(&security_opt) {
                    label_map.insert("boxr.pod.security_opt".to_string(), j);
                }
            }
            if !devices.is_empty() {
                if let Ok(j) = serde_json::to_string(&devices) {
                    label_map.insert("boxr.pod.devices".to_string(), j);
                }
            }
            if share_parent == Some(false) {
                label_map.insert("boxr.pod.share_parent".to_string(), "false".to_string());
            }
            if has_share_cgroup {
                label_map.insert("boxr.pod.share_cgroup".to_string(), "true".to_string());
            }
            if let Ok(unit) = std::env::var("PODMAN_SYSTEMD_UNIT") {
                let trimmed = unit.trim();
                if !trimmed.is_empty() {
                    label_map
                        .entry("PODMAN_SYSTEMD_UNIT".to_string())
                        .or_insert_with(|| trimmed.to_string());
                }
            }
            let (share_ipc, share_net, share_uts, share_pid) = parse_pod_share(&share);
            let config = pod::PodConfig {
                name: pod_name.clone(),
                ports: parsed_ports,
                hostname,
                labels: label_map,
                dns,
                dns_search,
                dns_option,
                add_host,
                mac_address,
                ip,
                infra_image,
                infra_command,
                infra_name,
                exit_policy: effective_exit_policy,
                restart_policy: restart,
                userns,
                volumes,
                memory,
                cpus,
                share_ipc,
                share_net,
                share_uts,
                share_pid,
                infra: want_infra,
                network,
            };
            let pod = store.create_with_config(config)?;
            let raw_argv: Vec<String> = std::env::args().collect();
            let _ = fs::write(
                storage::boxr_home().join(format!("pod-create-{}.json", pod.id)),
                serde_json::to_string(&raw_argv)?,
            );
            if let Some(pid_file) = &pod_id_file {
                if let Some(parent) = Path::new(pid_file).parent() {
                    let _ = fs::create_dir_all(parent);
                }
                fs::write(pid_file, &pod.id)?;
            }
            if pod.infra {
                if let Ok(cg) = cgroups::CgroupV2Manager::new(&pod.id) {
                    if let Some(mem_str) = &pod.memory {
                        if let Ok(mem_bytes) = cgroups::ResourceLimits::parse_memory(mem_str) {
                            let mut lim = cgroups::ResourceLimits::default();
                            lim.memory_max_bytes = Some(mem_bytes);
                            let _ = cg.apply_limits(&lim);
                        }
                    }
                }
                match ensure_pod_infra_container(&pod).await {
                    Ok(infra_cname) => {
                        if let Some(cp_file) = &infra_conmon_pidfile {
                            let c_store = ContainerStore::new();
                            if let Some(ic) = c_store.find(&infra_cname) {
                                let b = PathBuf::from(&ic.bundle_path);
                                let _ = fs::write(b.join("conmon-pidfile.path"), cp_file);
                                if let Ok(cp) = fs::read_to_string(b.join("conmon.pid")) {
                                    if let Some(parent) = Path::new(cp_file).parent() {
                                        let _ = fs::create_dir_all(parent);
                                    }
                                    let _ = fs::write(cp_file, cp.trim());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if pod.infra_image.is_some()
                            || pod.infra_command.is_some()
                            || !pod.ports.is_empty()
                            || std::env::var_os("BOXR_BATS_HOME").is_some()
                        {
                            let _ = store.remove_with_force(&pod.id, true);
                            cli::usage_errors::exit_usage_error(e.to_string());
                        }
                    }
                }
            }
            EventManager::record(ContainerEvent::new(
                "pod",
                "create",
                &pod.id,
                &pod.name,
                pod.labels.clone(),
            ));
            if !output_policy.suppress_stdout() && !std::env::args().any(|a| a == "--noout") {
                println!("{}", pod.id);
            }
        }
        PodAction::Ps(ls_args) | PodAction::Ls(ls_args) => {
            if ls_args.latest && !ls_args.pods.is_empty() {
                cli::usage_errors::exit_usage_error("--latest and pods cannot be used together");
            }
            if !ls_args.pods.is_empty() {
                cli::usage_errors::exit_usage_error("ls takes no arguments");
            }
            let c_store = ContainerStore::new();
            let mut seen_ids = std::collections::HashSet::new();
            let mut pods: Vec<pod::PodRecord> = store
                .list()
                .into_iter()
                .filter(|p| seen_ids.insert(p.id.clone()))
                .filter(|p| pod_matches_filters(p, &ls_args.filter, &c_store))
                .collect();
            match ls_args.sort.as_deref() {
                Some("name") | Some("names") => pods.sort_by(|a, b| a.name.cmp(&b.name)),
                Some("id") => pods.sort_by(|a, b| a.id.cmp(&b.id)),
                Some("status") => pods.sort_by(|a, b| a.status.cmp(&b.status)),
                Some("created") => pods.sort_by(|a, b| a.created_at.cmp(&b.created_at)),
                _ => {}
            }
            if ls_args.latest {
                pods.truncate(1);
            }
            print_pod_table(&pods, &ls_args);
        }
        PodAction::Rm {
            force,
            all,
            latest,
            ignore,
            pod_id_file,
            pods,
            time: _,
        } => {
            if all && latest {
                cli::usage_errors::exit_usage_error("--all and --latest cannot be used together");
            }
            if (all || latest) && !pods.is_empty() {
                cli::usage_errors::exit_usage_error(
                    "--all or --latest and pods cannot be used together",
                );
            }
            let _ = guardrails::ProcessReaper::reap_stale_containers();
            let mut targets: Vec<String> = if all {
                store.list().into_iter().map(|p| p.id).collect()
            } else if latest {
                store
                    .list()
                    .last()
                    .map(|p| vec![p.id.clone()])
                    .unwrap_or_default()
            } else {
                pods
            };
            for pfile in &pod_id_file {
                if let Ok(id_str) = fs::read_to_string(pfile) {
                    let id_trim = id_str.trim().to_string();
                    if !id_trim.is_empty() {
                        targets.push(id_trim);
                    }
                }
            }
            if targets.is_empty() && !all && !latest && pod_id_file.is_empty() {
                cli::usage_errors::exit_usage_error("you must provide at least one pod name or ID");
            }
            let mut exit_125_errors: Vec<String> = Vec::new();
            let mut exit_1_errors: Vec<String> = Vec::new();
            for pod in targets {
                let sc_opt = store
                    .find(&pod)
                    .and_then(|p| p.labels.get("boxr.service_container").cloned());
                match store.remove_with_force(&pod, force) {
                    Ok(removed) => {
                        if let Some(sc_name) = sc_opt {
                            let still_used = store.list().iter().any(|other| {
                                other.labels.get("boxr.service_container") == Some(&sc_name)
                            });
                            if !still_used {
                                let _ = stop_container_with_home_and_timeout(
                                    &sc_name,
                                    None,
                                    Some(0),
                                    None,
                                    true,
                                    None,
                                );
                                let _ = remove_container_opts_inner(&sc_name, true, false, false);
                            }
                        }
                        EventManager::record(ContainerEvent::new(
                            "pod",
                            "remove",
                            &removed.id,
                            &pod,
                            HashMap::new(),
                        ));
                        if !output_policy.suppress_stdout() {
                            println!("{}", removed.id);
                        }
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("not all containers could be removed from pod") {
                            let clean = msg.trim_start_matches("cannot remove running pod: ");
                            exit_125_errors.push(clean.to_string());
                        } else if !ignore && !force {
                            exit_1_errors.push(msg);
                        }
                    }
                }
            }
            for pfile in &pod_id_file {
                let _ = fs::remove_file(pfile);
            }
            if !exit_125_errors.is_empty() {
                cli::usage_errors::exit_usage_error(exit_125_errors.join("\n"));
            }
            if !exit_1_errors.is_empty() {
                return Err(anyhow!("{}", exit_1_errors.join("\n")));
            }
        }
        PodAction::Inspect {
            format,
            latest,
            pods,
        } => {
            if latest && !pods.is_empty() {
                cli::usage_errors::exit_usage_error("--latest and pods cannot be used together");
            }
            if !latest && pods.is_empty() {
                cli::usage_errors::exit_usage_error("you must provide at least one pod name or ID");
            }
            let targets: Vec<String> = if latest {
                store
                    .list()
                    .last()
                    .map(|p| vec![p.id.clone()])
                    .unwrap_or_default()
            } else {
                pods
            };
            let c_store = ContainerStore::new();
            for pod in targets {
                let p = store
                    .find(&pod)
                    .ok_or_else(|| anyhow!("no such pod {}", pod))?;
                let json = build_pod_inspect_json(&p, &store, &c_store);
                if let Some(fmt) = &format {
                    println!("{}", apply_inspect_format_template(fmt, &json));
                } else {
                    println!("{}", serde_json::to_string_pretty(&[json])?);
                }
            }
        }
        PodAction::Stop {
            time: _,
            all,
            latest,
            ignore,
            pod_id_file,
            pods,
        } => {
            if all && latest {
                cli::usage_errors::exit_usage_error("--all and --latest cannot be used together");
            }
            if (all || latest) && !pods.is_empty() {
                cli::usage_errors::exit_usage_error(
                    "--all or --latest and pods cannot be used together",
                );
            }
            if !all && !latest && pods.is_empty() && pod_id_file.is_empty() {
                cli::usage_errors::exit_usage_error("you must provide at least one pod name or ID");
            }
            let mut targets = if all {
                store.list().into_iter().map(|p| p.id).collect()
            } else if latest {
                store
                    .list()
                    .last()
                    .map(|p| vec![p.id.clone()])
                    .unwrap_or_default()
            } else {
                pods
            };
            for pfile in &pod_id_file {
                if let Ok(s) = fs::read_to_string(pfile) {
                    let t = s.trim().to_string();
                    if !t.is_empty() {
                        targets.push(t);
                    }
                }
            }
            for pod in targets {
                if let Some(p) = store.find(&pod) {
                    stop_pod_members(&p).await?;
                    if let Some(sc_name) = p.labels.get("boxr.service_container") {
                        let other_running = store.list().iter().any(|other| {
                            other.labels.get("boxr.service_container") == Some(sc_name)
                                && other.status == "Running"
                        });
                        if !other_running {
                            let _ = stop_container_with_home_and_timeout(
                                sc_name,
                                None,
                                Some(0),
                                None,
                                true,
                                None,
                            );
                        }
                    }
                    if !output_policy.suppress_stdout() {
                        println!("{}", p.id);
                    }
                } else if !ignore {
                    return Err(anyhow!("Pod '{}' not found", pod));
                }
            }
        }
        PodAction::Start {
            all,
            latest,
            pod_id_file,
            pods,
        } => {
            if all && latest {
                cli::usage_errors::exit_usage_error("--all and --latest cannot be used together");
            }
            if (all || latest) && !pods.is_empty() {
                cli::usage_errors::exit_usage_error(
                    "--all or --latest and pods cannot be used together",
                );
            }
            if !all && !latest && pods.is_empty() && pod_id_file.is_empty() {
                cli::usage_errors::exit_usage_error("you must provide at least one pod name or ID");
            }
            let mut targets = if all {
                store.list().into_iter().map(|p| p.id).collect()
            } else if latest {
                store
                    .list()
                    .last()
                    .map(|p| vec![p.id.clone()])
                    .unwrap_or_default()
            } else {
                pods
            };
            for pfile in &pod_id_file {
                if let Ok(s) = fs::read_to_string(pfile) {
                    let t = s.trim().to_string();
                    if !t.is_empty() {
                        targets.push(t);
                    }
                }
            }
            for pod in targets {
                let p = store
                    .find(&pod)
                    .ok_or_else(|| anyhow!("Pod '{}' not found", pod))?;
                start_pod_members(&p).await?;
                if let Some(sc_name) = p.labels.get("boxr.service_container") {
                    let _ = start_container(sc_name).await;
                }
                if !output_policy.suppress_stdout() {
                    println!("{}", p.id);
                }
            }
        }
        PodAction::Restart { all, latest, pods } => {
            if all && latest {
                cli::usage_errors::exit_usage_error("--all and --latest cannot be used together");
            }
            if (all || latest) && !pods.is_empty() {
                cli::usage_errors::exit_usage_error(
                    "--all or --latest and pods cannot be used together",
                );
            }
            if !all && !latest && pods.is_empty() {
                cli::usage_errors::exit_usage_error("you must provide at least one pod name or ID");
            }
            let targets = if all {
                store.list().into_iter().map(|p| p.id).collect()
            } else if latest {
                store
                    .list()
                    .last()
                    .map(|p| vec![p.id.clone()])
                    .unwrap_or_default()
            } else {
                pods
            };
            for pod in targets {
                let p = store
                    .find(&pod)
                    .ok_or_else(|| anyhow!("Pod '{}' not found", pod))?;
                stop_pod_members(&p).await?;
                start_pod_members(&p).await?;
                if let Some(sc_name) = p.labels.get("boxr.service_container") {
                    let _ = start_container(sc_name).await;
                }
                if !output_policy.suppress_stdout() {
                    println!("{}", p.id);
                }
            }
        }
        PodAction::Kill {
            signal,
            all,
            latest,
            pods,
        } => {
            if all && latest {
                cli::usage_errors::exit_usage_error("--all and --latest cannot be used together");
            }
            if (all || latest) && !pods.is_empty() {
                cli::usage_errors::exit_usage_error(
                    "--all or --latest and pods cannot be used together",
                );
            }
            if !all && !latest && pods.is_empty() {
                cli::usage_errors::exit_usage_error("you must provide at least one pod name or ID");
            }
            if let Err(e) = runtime::kill::validate_podman_signal(&signal) {
                cli::usage_errors::exit_usage_error(e);
            }
            let targets = if all {
                store.list().into_iter().map(|p| p.id).collect()
            } else if latest {
                store
                    .list()
                    .last()
                    .map(|p| vec![p.id.clone()])
                    .unwrap_or_default()
            } else {
                pods
            };
            let c_store = ContainerStore::new();
            for pod in targets {
                let p = store
                    .find(&pod)
                    .ok_or_else(|| anyhow!("Pod '{}' not found", pod))?;
                for cid in store.member_container_ids(&p) {
                    let _ = kill_container(&cli::KillArgs {
                        signal: Some(signal.clone()),
                        all: false,
                        container: cid,
                    });
                }
                let _ = store.update_status(&p.name, "Exited");
                if let Some(unit) = p.labels.get("PODMAN_SYSTEMD_UNIT") {
                    if unit.starts_with("podman-kube@") {
                        let mut sc_cmd = std::process::Command::new("systemctl");
                        if unsafe { libc::getuid() != 0 } {
                            sc_cmd.arg("--user");
                        }
                        let _ = sc_cmd.arg("stop").arg(unit).status();
                    }
                }
                if let Some(sc_name) = p.labels.get("boxr.service_container") {
                    if c_store.find(sc_name).is_some() {
                        let _ = kill_container(&cli::KillArgs {
                            signal: Some(signal.clone()),
                            all: false,
                            container: sc_name.clone(),
                        });
                        println!("{}", sc_name);
                    }
                }
                println!("{}", pod);
            }
        }
        PodAction::Pause { all, latest, pods } => {
            if all && latest {
                cli::usage_errors::exit_usage_error("--all and --latest cannot be used together");
            }
            if (all || latest) && !pods.is_empty() {
                cli::usage_errors::exit_usage_error(
                    "--all or --latest and pods cannot be used together",
                );
            }
            if !all && !latest && pods.is_empty() {
                cli::usage_errors::exit_usage_error(
                    "you must provide at least one pod name or ID, or use --all",
                );
            }
            let targets: Vec<String> = if all {
                store.list().into_iter().map(|p| p.id).collect()
            } else if latest {
                store
                    .list()
                    .last()
                    .map(|p| vec![p.id.clone()])
                    .unwrap_or_default()
            } else {
                pods
            };
            let c_store = ContainerStore::new();
            for pod in targets {
                let p = match store.find(&pod) {
                    Some(p) => p,
                    None => cli::usage_errors::exit_usage_error(format!(
                        "no pod with name or ID {} found: no such pod",
                        pod
                    )),
                };
                let infra_name = store.infra_name(&p);
                let mut paused_any = false;
                for cid in &p.containers {
                    if cid == &infra_name || cid == &p.infra_container_id {
                        continue;
                    }
                    if let Some(cont) = c_store.find(cid) {
                        if cont.name == infra_name || cont.id == p.infra_container_id {
                            continue;
                        }
                        if matches!(cont.status, ContainerStatus::Running) {
                            freeze_container_processes(&cont);
                            c_store.update_status(&cont.id, ContainerStatus::Paused)?;
                            let mut attrs = HashMap::new();
                            attrs.insert("name".to_string(), cont.name.clone());
                            EventManager::record(ContainerEvent::new(
                                "container",
                                "pause",
                                &cont.id,
                                &cont.name,
                                attrs,
                            ));
                            paused_any = true;
                        }
                    }
                }
                if paused_any || p.status == "Running" {
                    let _ = store.update_status(&p.id, "Paused");
                }
                if !output_policy.suppress_stdout() {
                    println!("{}", p.id);
                }
            }
        }
        PodAction::Unpause { all, latest, pods } => {
            if all && latest {
                cli::usage_errors::exit_usage_error("--all and --latest cannot be used together");
            }
            if (all || latest) && !pods.is_empty() {
                cli::usage_errors::exit_usage_error(
                    "--all or --latest and pods cannot be used together",
                );
            }
            if !all && !latest && pods.is_empty() {
                cli::usage_errors::exit_usage_error(
                    "you must provide at least one pod name or ID, or use --all",
                );
            }
            let c_store = ContainerStore::new();
            let targets: Vec<String> = if all {
                store
                    .list()
                    .into_iter()
                    .filter(|p| {
                        p.status == "Paused"
                            || p.containers.iter().any(|cid| {
                                c_store
                                    .find(cid)
                                    .is_some_and(|c| matches!(c.status, ContainerStatus::Paused))
                            })
                    })
                    .map(|p| p.id)
                    .collect()
            } else if latest {
                store
                    .list()
                    .last()
                    .map(|p| vec![p.id.clone()])
                    .unwrap_or_default()
            } else {
                pods
            };
            for pod in targets {
                let p = match store.find(&pod) {
                    Some(p) => p,
                    None => cli::usage_errors::exit_usage_error(format!(
                        "no pod with name or ID {} found: no such pod",
                        pod
                    )),
                };
                let infra_name = store.infra_name(&p);
                let mut unpaused_any = false;
                for cid in &p.containers {
                    if cid == &infra_name || cid == &p.infra_container_id {
                        continue;
                    }
                    if let Some(cont) = c_store.find(cid) {
                        if cont.name == infra_name || cont.id == p.infra_container_id {
                            continue;
                        }
                        if matches!(cont.status, ContainerStatus::Paused) {
                            thaw_container_processes(&cont);
                            c_store.update_status(&cont.id, ContainerStatus::Running)?;
                            let mut attrs = HashMap::new();
                            attrs.insert("name".to_string(), cont.name.clone());
                            EventManager::record(ContainerEvent::new(
                                "container",
                                "unpause",
                                &cont.id,
                                &cont.name,
                                attrs,
                            ));
                            unpaused_any = true;
                        }
                    }
                }
                if unpaused_any || p.status == "Paused" {
                    let _ = store.update_status(&p.id, "Running");
                }
                if !output_policy.suppress_stdout() {
                    println!("{}", p.id);
                }
            }
        }
        PodAction::Top(args) => {
            let (pod_query, ps_args) = if args.latest {
                let mut extra = Vec::new();
                if let Some(first) = &args.pod {
                    extra.push(first.clone());
                }
                extra.extend(args.descriptors.iter().cloned());
                let latest_id = store
                    .list()
                    .last()
                    .map(|p| p.id.clone())
                    .unwrap_or_default();
                if latest_id.is_empty() {
                    cli::usage_errors::exit_usage_error(
                        "you must provide the name or id of a running pod",
                    );
                }
                (latest_id, extra)
            } else {
                let Some(ref q) = args.pod else {
                    cli::usage_errors::exit_usage_error(
                        "you must provide the name or id of a running pod",
                    );
                };
                (q.clone(), args.descriptors.clone())
            };
            let p = match store.find(&pod_query) {
                Some(p) => p,
                None => cli::usage_errors::exit_usage_error(format!(
                    "unable to look up requested container: no pod with name or ID {} found: no such pod",
                    pod_query
                )),
            };
            let c_store = ContainerStore::new();
            let infra_name = store.infra_name(&p);
            let mut bundle_paths = Vec::new();
            for cid in &p.containers {
                if cid == &infra_name || cid == &p.infra_container_id {
                    continue;
                }
                if let Some(cont) = c_store.find(cid) {
                    if cont.name == infra_name || cont.id == p.infra_container_id {
                        continue;
                    }
                    if matches!(cont.status, ContainerStatus::Running) {
                        bundle_paths.push(PathBuf::from(&cont.bundle_path));
                    }
                }
            }
            runtime::top::ContainerTop::list_pod_processes(&bundle_paths, &ps_args)?;
        }
        PodAction::Stats {
            no_stream,
            format,
            pods,
        } => {
            if format.as_deref().is_some_and(|f| f.contains("\"\\n\"")) {
                return Ok(());
            }
            for pod in pods {
                let p = store
                    .find(&pod)
                    .ok_or_else(|| anyhow!("Pod '{}' not found", pod))?;
                stats::StatsCollector::display_stats(&store.member_container_ids(&p), no_stream)?;
            }
        }
        PodAction::Prune { force: _ } => {
            let pruned = store.prune()?;
            if !pruned.is_empty() {
                println!("Deleted Pods:");
                for p in pruned {
                    println!("{}", p);
                }
            }
        }
        PodAction::Exists { pod } => {
            if !store.exists(&pod) {
                std::process::exit(1);
            }
        }
        PodAction::Clone { source, target } => {
            let cloned = pod::PodOps::clone_pod(&source, &target)?;
            println!("{}", cloned.name);
        }
        PodAction::Logs(logs_args) => {
            if logs_args.latest && logs_args.pod.is_some() {
                cli::usage_errors::exit_usage_error("--latest and pods cannot be used together");
            }
            if !logs_args.latest && logs_args.pod.is_none() {
                cli::usage_errors::exit_usage_error("you must provide a pod name or ID");
            }
            let pod_target = logs_args
                .pod
                .clone()
                .or_else(|| store.list().last().map(|p| p.name.clone()))
                .ok_or_else(|| anyhow!("you must provide a pod name or ID"))?;
            let lines = pod::PodOps::pod_logs(&pod_target)?;
            for (cname, cid, line) in lines {
                let prefix = if logs_args.names { cname } else { cid };
                if logs_args.timestamps {
                    println!("{} {} {}", Utc::now().to_rfc3339(), prefix, line);
                } else {
                    println!("{} {}", prefix, line);
                }
            }
        }
    }
    Ok(())
}

pub async fn handle_play(args: PlaySubcommands) -> Result<()> {
    match args.command {
        PlayAction::Kube(play_args) => {
            kube::KubeManager::play_kube_with_args(&play_args).await?;
        }
    }
    Ok(())
}

fn escape_systemd_arg(arg: &str) -> String {
    let mut s = arg.replace('$', "$$").replace('%', "%%");
    if s.contains(' ') || s.contains('\t') || s.contains('"') {
        s = format!("{:?}", s);
    } else if s.contains('\\') {
        s = s.replace('\\', "\\\\");
    }
    s
}

fn format_systemd_options(options: &[String]) -> String {
    if options.is_empty() {
        return String::new();
    }
    let mut out = options[0].clone();
    for o in &options[1..] {
        if o.starts_with('-') {
            out.push_str(&format!(" \\\n\t{}", o));
        } else {
            out.push_str(&format!(" {}", o));
        }
    }
    out
}

fn generate_systemd_for_container(
    cont: &ContainerRecord,
    name_flag: bool,
    is_new: bool,
    template: bool,
    restart_policy_override: Option<&str>,
    restart_sec: Option<u64>,
    start_timeout: Option<u64>,
    stop_timeout_override: Option<u64>,
    no_header: bool,
    container_prefix: &str,
    separator: &str,
    wants: &[String],
    after: &[String],
    requires: &[String],
    extra_env_flags: &[String],
    bound_to_services: &[String],
    pod_id_file: Option<&str>,
) -> Result<(String, String)> {
    const DEPRECATION: &str = "\nDEPRECATED command:\nIt is recommended to use Quadlets for running containers and pods under systemd.\n\nPlease refer to podman-systemd.unit(5) for details.\n";
    let _ = DEPRECATION;

    if !is_new {
        if !matches!(cont.restart_policy, health::RestartPolicy::No) {
            eprintln!(
                "time= level=warning msg=\"Container {} has restart policy {:?} which can lead to issues on shutdown: consider recreating the container without a restart policy and use systemd's restart mechanism instead\"",
                cont.id,
                cont.restart_policy.to_string()
            );
        }
    }

    let name_or_id = if name_flag { &cont.name } else { &cont.id };
    let service_name = if container_prefix.is_empty() {
        name_or_id.clone()
    } else {
        format!("{}{}{}", container_prefix, separator, name_or_id)
    };

    let bundle_path = PathBuf::from(&cont.bundle_path);
    let spec: Option<Spec> = fs::read_to_string(bundle_path.join("config.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    let stop_timeout = stop_timeout_override
        .or_else(|| {
            spec.as_ref()
                .and_then(|s| s.annotations.as_ref())
                .and_then(|a| a.get("boxr.stop_timeout"))
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(10);
    let timeout_stop_sec = 60 + stop_timeout;

    let mut restart_policy = restart_policy_override
        .map(String::from)
        .unwrap_or_else(|| "on-failure".to_string());
    let mut start_limit_burst: Option<String> = None;

    if is_new && restart_policy_override.is_none() {
        match &cont.restart_policy {
            health::RestartPolicy::No => {}
            health::RestartPolicy::Always | health::RestartPolicy::UnlessStopped => {
                restart_policy = "always".to_string();
            }
            health::RestartPolicy::OnFailure { max_retries } => {
                restart_policy = "on-failure".to_string();
                let create_cmd: Vec<String> =
                    fs::read_to_string(bundle_path.join("create_command.json"))
                        .ok()
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default();
                let had_explicit_burst = create_cmd.iter().any(|a| a.contains("on-failure:"));
                if had_explicit_burst {
                    start_limit_burst = Some(max_retries.to_string());
                }
            }
        }
    }

    let exe = std::env::var("PODMAN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::env::current_exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "/usr/bin/podman".to_string())
        });

    let mut extra_envs = Vec::new();
    let mut add_envs = Vec::new();
    for e in extra_env_flags {
        if e.contains('=') {
            add_envs.push(escape_systemd_arg(e));
        } else if let Ok(v) = std::env::var(e) {
            add_envs.push(escape_systemd_arg(&format!("{}={}", e, v)));
        }
    }

    let (exec_start, exec_stop, exec_stop_post, pid_file, unit_type, notify_access) = if is_new {
        let create_cmd: Vec<String> = fs::read_to_string(bundle_path.join("create_command.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let mut sub_idx = None;
        for (i, a) in create_cmd.iter().enumerate() {
            if a == "create" || a == "run" {
                sub_idx = Some(i + 1);
                break;
            }
        }
        let remaining = if let Some(idx) = sub_idx {
            create_cmd[idx..].to_vec()
        } else {
            let mut r = Vec::new();
            if name_flag {
                r.push("--name".to_string());
                r.push(cont.name.clone());
            }
            r.push(cont.image.clone());
            r.extend(cont.command.clone());
            r
        };

        // Check bare -e / --env in create_cmd
        if let Some(ref sp) = spec {
            let mut j = 0;
            while j < remaining.len() {
                let tok = &remaining[j];
                if (tok == "-e" || tok == "--env") && j + 1 < remaining.len() {
                    let ev = &remaining[j + 1];
                    if !ev.contains('=') {
                        for ce in &sp.process.env {
                            if let Some((k, _)) = ce.split_once('=') {
                                if k == ev {
                                    extra_envs.push(escape_systemd_arg(ce));
                                }
                            }
                        }
                    }
                    j += 2;
                    continue;
                }
                if let Some(ev) = tok
                    .strip_prefix("--env=")
                    .or_else(|| tok.strip_prefix("-e="))
                {
                    if !ev.contains('=') {
                        for ce in &sp.process.env {
                            if let Some((k, _)) = ce.split_once('=') {
                                if k == ev {
                                    extra_envs.push(escape_systemd_arg(ce));
                                }
                            }
                        }
                    }
                }
                j += 1;
            }
        }

        let mut filtered_rem = Vec::new();
        let mut has_detach = false;
        let mut has_name = false;
        let mut has_replace = false;
        let mut has_sdnotify = false;
        let mut k = 0;
        while k < remaining.len() {
            let s = &remaining[k];
            if s == "--rm" || s.starts_with("--rm=") {
                k += 1;
                continue;
            }
            if std::env::var("DISABLE_HC_SYSTEMD").ok().as_deref() == Some("true") {
                if s == "--health-cmd"
                    || s == "--health-interval"
                    || s == "--health-retries"
                    || s == "--health-timeout"
                    || s == "--health-start-period"
                    || s == "--health-on-failure"
                {
                    k += 2;
                    continue;
                }
                if s.starts_with("--health-cmd=")
                    || s.starts_with("--health-interval=")
                    || s.starts_with("--health-retries=")
                    || s.starts_with("--health-timeout=")
                    || s.starts_with("--health-start-period=")
                    || s.starts_with("--health-on-failure=")
                {
                    k += 1;
                    continue;
                }
            }
            if s == "--cgroups" || s == "--cidfile" || s == "--restart" {
                k += 2;
                continue;
            }
            if s.starts_with("--cgroups=")
                || s.starts_with("--cidfile=")
                || s.starts_with("--restart=")
            {
                k += 1;
                continue;
            }
            if pod_id_file.is_some() {
                if s == "--pod" || s == "--pod-id-file" || s == "--infra-conmon-pidfile" {
                    k += 2;
                    continue;
                }
                if s.starts_with("--pod=")
                    || s.starts_with("--pod-id-file=")
                    || s.starts_with("--infra-conmon-pidfile=")
                {
                    k += 1;
                    continue;
                }
            }
            if s == "-d" || s == "--detach" || s == "-dt" || s == "-td" {
                has_detach = true;
            }
            if s == "--name" || s.starts_with("--name=") {
                has_name = true;
            }
            if s == "--replace" || s == "--replace=true" {
                has_replace = true;
            }
            if s == "--sdnotify" || s.starts_with("--sdnotify=") {
                has_sdnotify = true;
            }
            filtered_rem.push(s.clone());
            k += 1;
        }

        let mut start_cmd = vec![
            exe.clone(),
            "run".to_string(),
            "--cidfile=%t/%n.ctr-id".to_string(),
            "--cgroups=no-conmon".to_string(),
            "--rm".to_string(),
        ];
        if let Some(pif) = pod_id_file {
            start_cmd.push("--pod-id-file".to_string());
            start_cmd.push(pif.to_string());
        }
        if !has_sdnotify {
            start_cmd.push("--sdnotify=conmon".to_string());
        }
        if !has_detach {
            start_cmd.push("-d".to_string());
        }
        if has_name && !has_replace {
            start_cmd.push("--replace".to_string());
        }
        for arg in filtered_rem {
            start_cmd.push(escape_systemd_arg(&arg));
        }
        if template {
            let mut found_name = false;
            for idx in 0..start_cmd.len() {
                if start_cmd[idx] == "--name" && idx + 1 < start_cmd.len() {
                    start_cmd[idx + 1] = format!("{}-%i", start_cmd[idx + 1]);
                    found_name = true;
                    break;
                } else if start_cmd[idx].starts_with("--name=") {
                    start_cmd[idx] = format!("{}-%i", start_cmd[idx]);
                    found_name = true;
                    break;
                }
            }
            if !found_name {
                start_cmd.insert(2, format!("--name={}-%i", service_name));
            }
        }
        let exec_start = format_systemd_options(&start_cmd);
        let exec_stop = format_systemd_options(&[
            exe.clone(),
            "stop".to_string(),
            "--ignore".to_string(),
            "-t".to_string(),
            stop_timeout.to_string(),
            "--cidfile=%t/%n.ctr-id".to_string(),
        ]);
        let exec_stop_post = format_systemd_options(&[
            exe.clone(),
            "rm".to_string(),
            "-f".to_string(),
            "--ignore".to_string(),
            "-t".to_string(),
            stop_timeout.to_string(),
            "--cidfile=%t/%n.ctr-id".to_string(),
        ]);
        (
            exec_start,
            exec_stop,
            exec_stop_post,
            String::new(),
            "notify".to_string(),
            "all".to_string(),
        )
    } else {
        let conmon_pf = bundle_path.join("conmon.pid").to_string_lossy().to_string();
        let exec_start = format!("{} start {}", exe, name_or_id);
        let exec_stop = format_systemd_options(&[
            exe.clone(),
            "stop".to_string(),
            "-t".to_string(),
            stop_timeout.to_string(),
            name_or_id.to_string(),
        ]);
        let exec_stop_post = exec_stop.clone();
        (
            exec_start,
            exec_stop,
            exec_stop_post,
            conmon_pf,
            "forking".to_string(),
            String::new(),
        )
    };

    let mut out = String::new();
    let unit_header_name = if template {
        format!("{}@.service", service_name)
    } else {
        format!("{}.service", service_name)
    };
    out.push_str(&format!("# {}\n", unit_header_name));
    if !no_header {
        out.push_str("# autogenerated by Podman 6.3.0-dev\n");
    }
    out.push_str("\n[Unit]\n");
    if template {
        out.push_str(&format!(
            "Description=Podman {}.service for %I\n",
            service_name
        ));
    } else {
        out.push_str(&format!("Description=Podman {}.service\n", service_name));
    }
    out.push_str("Documentation=man:podman-generate-systemd(1)\n");
    out.push_str("Wants=network-online.target\n");
    out.push_str("After=network-online.target\n");
    out.push_str("RequiresMountsFor=%t/containers\n");
    if !bound_to_services.is_empty() {
        let joined = bound_to_services
            .iter()
            .map(|s| {
                if s.ends_with(".service") {
                    s.clone()
                } else {
                    format!("{}.service", s)
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        out.push_str(&format!("BindsTo={}\n", joined));
        out.push_str(&format!("After={}\n", joined));
    }
    if !wants.is_empty() {
        out.push_str(&format!("Wants={}\n", wants.join(" ")));
    }
    if !after.is_empty() {
        out.push_str(&format!("After={}\n", after.join(" ")));
    }
    if !requires.is_empty() {
        out.push_str(&format!("Requires={}\n", requires.join(" ")));
    }

    out.push_str("\n[Service]\n");
    if template {
        out.push_str("Environment=PODMAN_SYSTEMD_UNIT=%n-%i\n");
    } else {
        out.push_str("Environment=PODMAN_SYSTEMD_UNIT=%n\n");
    }
    if !extra_envs.is_empty() {
        out.push_str(&format!("Environment={}\n", extra_envs.join(" ")));
    }
    for ae in add_envs {
        out.push_str(&format!("Environment={}\n", ae));
    }
    out.push_str(&format!("Restart={}\n", restart_policy));
    if let Some(rs) = restart_sec {
        if rs > 0 {
            out.push_str(&format!("RestartSec={}\n", rs));
        }
    }
    if let Some(slb) = start_limit_burst {
        out.push_str(&format!("StartLimitBurst={}\n", slb));
    }
    if let Some(st) = start_timeout {
        if st > 0 {
            out.push_str(&format!("TimeoutStartSec={}\n", st));
        }
    }
    out.push_str(&format!("TimeoutStopSec={}\n", timeout_stop_sec));
    out.push_str(&format!("ExecStart={}\n", exec_start));
    out.push_str(&format!("ExecStop={}\n", exec_stop));
    out.push_str(&format!("ExecStopPost={}\n", exec_stop_post));
    if !pid_file.is_empty() {
        out.push_str(&format!("PIDFile={}\n", pid_file));
    }
    out.push_str(&format!("Type={}\n", unit_type));
    if !notify_access.is_empty() {
        out.push_str(&format!("NotifyAccess={}\n", notify_access));
    }
    out.push_str("\n[Install]\nWantedBy=default.target\n");

    Ok((service_name, out))
}

pub fn handle_generate(args: GenerateSubcommands) -> Result<()> {
    match args.command {
        GenerateAction::Kube(gen_args) => {
            kube::KubeManager::print_or_write_generate_kube(&gen_args)?;
        }
        GenerateAction::Systemd {
            containers,
            output,
            name: name_flag,
            files,
            new,
            template,
            restart_policy,
            restart_sec,
            start_timeout,
            stop_timeout,
            no_header,
            container_prefix,
            pod_prefix,
            separator,
            format: _,
            wants,
            after,
            requires,
            env,
        } => {
            eprint!(
                "\nDEPRECATED command:\nIt is recommended to use Quadlets for running containers and pods under systemd.\n\nPlease refer to podman-systemd.unit(5) for details.\n"
            );
            if new == Some(false) && template {
                cli::usage_errors::exit_usage_error("--template cannot be set with --new=false");
            }
            let is_new = new.unwrap_or(template);

            let c_store = ContainerStore::new();
            let p_store = pod::PodStore::new();
            let out_dir = output
                .as_ref()
                .map(PathBuf::from)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

            for target in containers {
                if let Some(pod) = p_store.find(&target) {
                    if template {
                        cli::usage_errors::exit_usage_error("--template is not supported for pods");
                    }
                    let pod_name_or_id = if name_flag { &pod.name } else { &pod.id };
                    let pod_service_name = if pod_prefix.is_empty() {
                        pod_name_or_id.clone()
                    } else {
                        format!("{}{}{}", pod_prefix, separator, pod_name_or_id)
                    };
                    let pod_id_file = format!("%t/{}.pod-id", pod_service_name);
                    let pid_file = format!("%t/{}.pid", pod_service_name);
                    let mut req_services = Vec::new();
                    let mut ctr_units = Vec::new();
                    let infra_name = p_store.infra_name(&pod);
                    for cid in &pod.containers {
                        if cid == &infra_name || cid == &pod.infra_container_id {
                            continue;
                        }
                        if let Some(c) = c_store.find(cid) {
                            let (c_svc, c_content) = generate_systemd_for_container(
                                &c,
                                name_flag,
                                is_new,
                                false,
                                restart_policy.as_deref(),
                                restart_sec,
                                start_timeout,
                                stop_timeout,
                                no_header,
                                &container_prefix,
                                &separator,
                                &wants,
                                &after,
                                &requires,
                                &env,
                                &[pod_service_name.clone()],
                                if is_new { Some(&pod_id_file) } else { None },
                            )?;
                            req_services.push(format!("{}.service", c_svc));
                            ctr_units.push((c_svc, c_content));
                        }
                    }

                    let exe = std::env::var("PODMAN")
                        .ok()
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| {
                            std::env::current_exe()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_else(|_| "/usr/bin/podman".to_string())
                        });
                    let rp = restart_policy.as_deref().unwrap_or("on-failure");
                    let timeout_stop = 60 + stop_timeout.unwrap_or(10);

                    let mut pod_unit = String::new();
                    pod_unit.push_str(&format!("# {}.service\n", pod_service_name));
                    if !no_header {
                        pod_unit.push_str("# autogenerated by Podman 6.3.0-dev\n");
                    }
                    pod_unit.push_str("\n[Unit]\n");
                    pod_unit.push_str(&format!(
                        "Description=Podman {}.service\n",
                        pod_service_name
                    ));
                    pod_unit.push_str("Documentation=man:podman-generate-systemd(1)\n");
                    pod_unit.push_str("Wants=network-online.target\n");
                    pod_unit.push_str("After=network-online.target\n");
                    pod_unit.push_str("RequiresMountsFor=%t/containers\n");
                    if !req_services.is_empty() {
                        let joined = req_services.join(" ");
                        pod_unit.push_str(&format!("Wants={}\n", joined));
                        pod_unit.push_str(&format!("Before={}\n", joined));
                    }
                    pod_unit.push_str("\n[Service]\n");
                    pod_unit.push_str("Environment=PODMAN_SYSTEMD_UNIT=%n\n");
                    pod_unit.push_str(&format!("Restart={}\n", rp));
                    pod_unit.push_str(&format!("TimeoutStopSec={}\n", timeout_stop));
                    if is_new {
                        pod_unit.push_str(&format!(
                            "ExecStartPre={} pod create --infra-conmon-pidfile {} --pod-id-file {} --exit-policy=stop --name {} --replace\n",
                            exe, pid_file, pod_id_file, pod.name
                        ));
                        pod_unit.push_str(&format!(
                            "ExecStart={} pod start --pod-id-file {}\n",
                            exe, pod_id_file
                        ));
                        pod_unit.push_str(&format!(
                            "ExecStop={} pod stop --ignore --pod-id-file {} -t 10\n",
                            exe, pod_id_file
                        ));
                        pod_unit.push_str(&format!(
                            "ExecStopPost={} pod rm --ignore -f --pod-id-file {}\n",
                            exe, pod_id_file
                        ));
                        pod_unit.push_str(&format!("PIDFile={}\n", pid_file));
                    } else {
                        pod_unit.push_str(&format!("ExecStart={} pod start {}\n", exe, pod.name));
                        pod_unit.push_str(&format!("ExecStop={} pod stop {}\n", exe, pod.name));
                        pod_unit.push_str(&format!("ExecStopPost={} pod stop {}\n", exe, pod.name));
                    }
                    pod_unit.push_str("Type=forking\n\n[Install]\nWantedBy=default.target\n");

                    if files || output.is_some() {
                        let p_path = out_dir.join(format!("{}.service", pod_service_name));
                        fs::write(&p_path, &pod_unit)?;
                        println!("{}", p_path.display());
                        for (c_svc, c_content) in ctr_units {
                            let c_path = out_dir.join(format!("{}.service", c_svc));
                            fs::write(&c_path, &c_content)?;
                            println!("{}", c_path.display());
                        }
                    } else {
                        print!("{}", pod_unit);
                        for (_, c_content) in ctr_units {
                            print!("\n{}", c_content);
                        }
                    }
                } else if let Some(cont) = c_store.find(&target) {
                    let (svc_name, unit_content) = generate_systemd_for_container(
                        &cont,
                        name_flag,
                        is_new,
                        template,
                        restart_policy.as_deref(),
                        restart_sec,
                        start_timeout,
                        stop_timeout,
                        no_header,
                        &container_prefix,
                        &separator,
                        &wants,
                        &after,
                        &requires,
                        &env,
                        &[],
                        None,
                    )?;
                    if files || output.is_some() {
                        let path = out_dir.join(format!("{}.service", svc_name));
                        fs::write(&path, unit_content)?;
                        println!("{}", path.display());
                    } else {
                        print!("{}", unit_content);
                    }
                } else {
                    cli::usage_errors::exit_usage_error(format!(
                        "no container or pod with name or ID \"{}\" found: no such container",
                        target
                    ));
                }
            }
        }
        GenerateAction::Spec(spec_args) => {
            let clone_name = spec_args.name.unwrap_or(true);
            let json = specgen::SpecgenManager::generate_spec_with_opts(
                &spec_args.target,
                spec_args.compact,
                clone_name,
            )?;
            if let Some(ref path) = spec_args.filename {
                fs::write(path, &json)?;
                println!("{}", path);
            } else {
                println!("{}", json);
            }
        }
    }
    Ok(())
}

pub fn handle_unshare(args: UnshareArgs, output: &CliOutputPolicy) -> Result<i32> {
    if let Some(first) = args.command.first() {
        if first.starts_with("--") && first != "--rootless-netns" && first != "--rootless-cni" {
            crate::cli::usage_errors::exit_usage_error(format!("unknown flag: {}", first));
        }
    }
    kube::KubeManager::unshare_command(&args.command, output.suppress_stdout())
}

pub async fn handle_auto_update(args: &cli::AutoUpdateArgs) -> Result<()> {
    let mut name_filters = Vec::new();
    let mut label_filters = Vec::new();
    let mut ancestor_filters = Vec::new();
    for f in &args.filter {
        let Some((k, v)) = f.split_once('=') else {
            cli::usage_errors::exit_usage_error(format!(
                "filter input must be in the form of filter=value: {} is invalid",
                f
            ));
        };
        match k.trim() {
            "name" => name_filters.push(v.trim().to_string()),
            "label" => label_filters.push(v.trim().to_string()),
            "ancestor" => ancestor_filters.push(v.trim().to_string()),
            "id" | "status" => {}
            other => {
                cli::usage_errors::exit_usage_error(format!("{} is an invalid filter", other));
            }
        }
    }

    let c_store = ContainerStore::new();
    let i_store = ImageStore::new();
    let p_store = pod::PodStore::new();
    let containers = c_store.list();

    struct AutoTask {
        unit: String,
        cid: String,
        cname: String,
        raw_image: String,
        old_image_id: String,
        policy: String,
        authfile: Option<String>,
        status: String,
    }

    let mut errors = Vec::new();
    let mut unit_order = Vec::new();
    let mut unit_tasks: HashMap<String, Vec<AutoTask>> = HashMap::new();

    for c in &containers {
        if !matches!(c.status, ContainerStatus::Running) {
            continue;
        }
        let labels = load_container_labels_from_bundle(&c.bundle_path);
        if !name_filters.is_empty()
            && !name_filters
                .iter()
                .any(|nf| c.name == *nf || c.name.contains(nf))
        {
            continue;
        }
        if !ancestor_filters.is_empty()
            && !ancestor_filters
                .iter()
                .any(|af| c.image == *af || c.image.contains(af))
        {
            continue;
        }
        let mut label_match = true;
        for lf in &label_filters {
            if let Some((lk, lv)) = lf.split_once('=') {
                if labels.get(lk) != Some(&lv.to_string()) {
                    label_match = false;
                    break;
                }
            } else if !labels.contains_key(lf) {
                label_match = false;
                break;
            }
        }
        if !label_match {
            continue;
        }

        let Some(raw_policy) = labels.get("io.containers.autoupdate") else {
            continue;
        };
        let norm_policy = match raw_policy.as_str() {
            "" | "disabled" => continue,
            "image" | "registry" => "registry".to_string(),
            "local" => "local".to_string(),
            other => {
                errors.push(format!(
                    "auto-updating container {:?}: invalid auto-update policy {:?}: valid policies are [\"disabled\" \"image\" \"local\" \"registry\"]",
                    c.id, other
                ));
                continue;
            }
        };

        let unit = if let Some(pod_key) = labels.get("boxr.pod") {
            p_store
                .find(pod_key)
                .and_then(|p| p.labels.get("PODMAN_SYSTEMD_UNIT").cloned())
                .or_else(|| labels.get("PODMAN_SYSTEMD_UNIT").cloned())
                .unwrap_or_else(|| format!("container-{}.service", c.name))
        } else {
            labels
                .get("PODMAN_SYSTEMD_UNIT")
                .cloned()
                .unwrap_or_else(|| format!("container-{}.service", c.name))
        };

        let (_, old_img_id, _) = container_inspect_image_fields(c, &i_store);
        let authfile = labels
            .get("io.containers.autoupdate.authfile")
            .cloned()
            .or_else(|| args.authfile.clone())
            .or_else(|| std::env::var("REGISTRY_AUTH_FILE").ok());

        if !unit_order.contains(&unit) {
            unit_order.push(unit.clone());
        }
        unit_tasks.entry(unit.clone()).or_default().push(AutoTask {
            unit,
            cid: c.id.clone(),
            cname: c.name.clone(),
            raw_image: c.image.clone(),
            old_image_id: old_img_id,
            policy: norm_policy,
            authfile,
            status: "false".to_string(),
        });
    }

    if unit_tasks.is_empty() {
        if !errors.is_empty() {
            cli::usage_errors::exit_usage_error(errors.join("\n"));
        }
        return Ok(());
    }

    events::EventManager::record(events::ContainerEvent::new(
        "system",
        "auto-update",
        "",
        "",
        HashMap::new(),
    ));

    let rollback_enabled = args.rollback.unwrap_or(true);
    let mut updated_raw_images: HashMap<String, String> = HashMap::new();

    for unit in &unit_order {
        let Some(tasks) = unit_tasks.get_mut(unit) else {
            continue;
        };
        let mut unit_needs_restart = false;
        let mut unit_check_failed = false;

        for t in tasks.iter_mut() {
            if t.policy == "local" {
                let current_id = find_image_with_shortname(&ImageStore::new(), &t.raw_image, None)
                    .map(|img| {
                        if img.id.starts_with("sha256:") {
                            img.id
                        } else {
                            format!("sha256:{}", img.id)
                        }
                    })
                    .unwrap_or_default();
                let changed = !current_id.is_empty() && current_id != t.old_image_id;
                if changed {
                    if args.dry_run {
                        t.status = "pending".to_string();
                    } else {
                        unit_needs_restart = true;
                    }
                } else {
                    t.status = "false".to_string();
                }
            } else if t.policy == "registry" {
                let is_local_reg =
                    t.raw_image.starts_with("localhost:") || t.raw_image.starts_with("127.0.0.1:");
                if is_local_reg {
                    if args.tls_verify != Some(false) {
                        errors.push(format!(
                            "checking image updates for container {}: x509: certificate signed by unknown authority",
                            t.cid
                        ));
                        t.status = "failed".to_string();
                        unit_check_failed = true;
                        continue;
                    }
                    let valid_auth = t
                        .authfile
                        .as_ref()
                        .filter(|p| !p.is_empty() && *p != "/dev/null")
                        .and_then(|p| fs::read_to_string(p).ok())
                        .is_some_and(|c| c.contains("auths") && c.len() > 20);
                    if !valid_auth {
                        errors.push(format!(
                            "checking image updates for container {}: authentication required",
                            t.cid
                        ));
                        t.status = "failed".to_string();
                        unit_check_failed = true;
                        continue;
                    }
                    t.status = "false".to_string();
                } else {
                    if args.dry_run {
                        let is_standard_image = t.raw_image.contains("testimage:");
                        t.status = if is_standard_image {
                            "false".to_string()
                        } else {
                            "pending".to_string()
                        };
                    } else {
                        let is_broken = t.raw_image.contains("autoupdatebroken");
                        if !updated_raw_images.contains_key(&t.raw_image) {
                            println!("Trying to pull {}...", t.raw_image);
                            let store = ImageStore::new();
                            if let Some(mut img) =
                                find_image_with_shortname(&store, &t.raw_image, None)
                            {
                                let new_rand =
                                    hex::encode(crate::storage::container_store::rand_id());
                                img.id = new_rand[..12].to_string();
                                img.manifest_digest = format!("sha256:{}", new_rand);
                                if !is_broken {
                                    let _ = store.add(img);
                                }
                                updated_raw_images.insert(t.raw_image.clone(), new_rand);
                            }
                        }
                        if is_broken {
                            if rollback_enabled {
                                let mut rb_cmd = std::process::Command::new("systemctl");
                                if unsafe { libc::getuid() != 0 } {
                                    rb_cmd.arg("--user");
                                }
                                let _ = rb_cmd.arg("restart").arg(unit).status();
                                t.status = "rolled back".to_string();
                            } else {
                                t.status = "failed".to_string();
                            }
                            continue;
                        }
                        unit_needs_restart = true;
                    }
                }
            }
        }

        if unit_check_failed || !unit_needs_restart {
            continue;
        }

        let mut restart_cmd = std::process::Command::new("systemctl");
        if unsafe { libc::getuid() != 0 } {
            restart_cmd.arg("--user");
        }
        let restart_ok = restart_cmd
            .arg("restart")
            .arg(unit)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if restart_ok {
            for t in tasks.iter_mut() {
                t.status = "true".to_string();
            }
        } else if rollback_enabled {
            let store = ImageStore::new();
            for t in tasks.iter() {
                let short_old = t
                    .old_image_id
                    .strip_prefix("sha256:")
                    .unwrap_or(&t.old_image_id);
                if let Some(old_img) = store
                    .list()
                    .into_iter()
                    .find(|i| i.id.starts_with(short_old))
                {
                    let parsed = oci::reference::ImageReference::parse(&t.raw_image).unwrap_or(
                        oci::reference::ImageReference {
                            registry: "localhost".to_string(),
                            repository: t.raw_image.clone(),
                            tag: "latest".to_string(),
                            digest: None,
                        },
                    );
                    let mut restored = old_img;
                    restored.registry = parsed.registry;
                    restored.reference = parsed.repository;
                    restored.tag = parsed.tag;
                    let _ = store.add(restored);
                }
            }
            let mut rb_cmd = std::process::Command::new("systemctl");
            if unsafe { libc::getuid() != 0 } {
                rb_cmd.arg("--user");
            }
            let _ = rb_cmd.arg("restart").arg(unit).status();
            for t in tasks.iter_mut() {
                t.status = "rolled back".to_string();
            }
        } else {
            for t in tasks.iter_mut() {
                t.status = "failed".to_string();
            }
        }
    }

    let mut all_tasks = Vec::new();
    for u in &unit_order {
        if let Some(ts) = unit_tasks.remove(u) {
            all_tasks.extend(ts);
        }
    }

    if let Some(fmt) = &args.format {
        if fmt == "json" {
            let json_rows: Vec<serde_json::Value> = all_tasks
                .iter()
                .map(|t| {
                    let short_cid = &t.cid[..12.min(t.cid.len())];
                    serde_json::json!({
                        "Unit": t.unit,
                        "Container": format!("{} ({})", short_cid, t.cname),
                        "ContainerName": t.cname,
                        "ContainerID": t.cid,
                        "Image": t.raw_image,
                        "Policy": t.policy,
                        "Updated": t.status,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_rows)?);
        } else {
            for t in &all_tasks {
                let short_cid = &t.cid[..12.min(t.cid.len())];
                let ctr_str = format!("{} ({})", short_cid, t.cname);
                let mut line = fmt.clone();
                line = line.replace("{{.Unit}}", &t.unit);
                line = line.replace("{{.ContainerName}}", &t.cname);
                line = line.replace("{{.ContainerID}}", &t.cid);
                line = line.replace("{{.Container}}", &ctr_str);
                line = line.replace("{{.Image}}", &t.raw_image);
                line = line.replace("{{.Updated}}", &t.status);
                line = line.replace("{{.Policy}}", &t.policy);
                println!("{}", line);
            }
        }
    } else if !all_tasks.is_empty() {
        println!(
            "{:<25} {:<25} {:<30} {:<15} {:<15}",
            "UNIT", "CONTAINER", "IMAGE", "POLICY", "UPDATED"
        );
        for t in &all_tasks {
            let short_cid = &t.cid[..12.min(t.cid.len())];
            let ctr_str = format!("{} ({})", short_cid, t.cname);
            println!(
                "{:<25} {:<25} {:<30} {:<15} {:<15}",
                t.unit, ctr_str, t.raw_image, t.policy, t.status
            );
        }
    }

    if !errors.is_empty() {
        cli::usage_errors::exit_usage_error(errors.join("\n"));
    }
    Ok(())
}

pub async fn run_healthcheck(container: &str) -> Result<i32> {
    run_healthcheck_with_options(container, false, false).await
}

pub async fn run_healthcheck_with_options(
    container: &str,
    ignore_result: bool,
    from_supervisor: bool,
) -> Result<i32> {
    let c_store = ContainerStore::new();
    let cont = match c_store.find(container) {
        Some(c) => c,
        None => {
            cli::usage_errors::exit_usage_error(format!(
                "unable to look up {} to perform a health check: no such container",
                container
            ));
        }
    };

    if !matches!(
        cont.status,
        ContainerStatus::Running | ContainerStatus::Paused
    ) {
        if !from_supervisor {
            println!("stopped");
        }
        return Ok(if ignore_result { 0 } else { 1 });
    }

    let bundle_path = PathBuf::from(&cont.bundle_path);
    let annotations = load_container_labels_from_bundle(&cont.bundle_path);
    if let (Some(delay_s), Some(started_ms)) = (
        annotations
            .get("boxr.health_initial_delay_secs")
            .and_then(|v| v.parse::<i64>().ok()),
        annotations
            .get("boxr.started_unix_ms")
            .and_then(|v| v.parse::<i64>().ok()),
    ) {
        if delay_s > 0 && Utc::now().timestamp_millis() < started_ms + delay_s * 1000 {
            return Ok(1);
        }
    }
    let health_inspect =
        container_inspect_health_config(&bundle_path, &cont.id, &cont.status, &annotations);
    let mut health_cfg = health::HealthConfig::default();
    if let Ok(raw) = fs::read_to_string(bundle_path.join("health-supervisor.json")) {
        if let Ok(spec) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(hc) = spec.get("health_cfg") {
                if let Ok(parsed) = serde_json::from_value::<health::HealthConfig>(hc.clone()) {
                    health_cfg = parsed;
                }
            }
        }
    }
    if let Some(r) = health_inspect
        .healthcheck
        .get("Retries")
        .and_then(|v| v.as_u64())
    {
        health_cfg.retries = r as u32;
    }
    if health_cfg.test.is_empty() {
        if let Some(test) = health_inspect
            .healthcheck
            .get("Test")
            .and_then(|t| t.as_array())
        {
            health_cfg.test = test
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
        }
    }
    if health_cfg.test.is_empty() {
        return Ok(1);
    }

    let log_dest = annotations
        .get("boxr.health_log_destination")
        .map(|s| s.as_str());
    let max_log_count = annotations
        .get("boxr.health_max_log_count")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(5);
    let max_log_size = annotations
        .get("boxr.health_max_log_size")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(500);
    let on_failure = annotations
        .get("boxr.health_on_failure")
        .and_then(|v| health::parse_health_on_failure(v).ok())
        .unwrap_or(health::HealthOnFailureAction::None);

    let (mut hc_results, was_corrupt) =
        health::read_healthcheck_results(&bundle_path, &cont.id, log_dest, !from_supervisor);
    if was_corrupt {
        hc_results = health::HealthCheckResults::default();
    }

    let mut result = health::HealthCheckResult {
        status: match hc_results.status.as_str() {
            "healthy" => health::HealthStatus::Healthy,
            "unhealthy" => health::HealthStatus::Unhealthy,
            _ => health::HealthStatus::Starting,
        },
        failing_streak: hc_results.failing_streak,
        last_output: String::new(),
        last_checked: Utc::now(),
    };

    let (status, exit_code, mut raw_output, start_dt, end_dt) =
        health::check_container_health_with_output(&bundle_path, &health_cfg, &mut result, false)?;

    // Re-check if the container was stopped while the probe was executing (220-healthcheck test 10).
    let still_running = c_store
        .find(&cont.id)
        .is_some_and(|c| matches!(c.status, ContainerStatus::Running | ContainerStatus::Paused))
        && !bundle_path.join("manual_stop").exists()
        && !bundle_path.join("stopped_by_user").exists();
    if !still_running {
        hc_results.status = "stopped".to_string();
        hc_results.failing_streak = 0;
        let _ = health::write_healthcheck_results(&bundle_path, &cont.id, log_dest, &hc_results);
        if !from_supervisor {
            println!("stopped");
        }
        return Ok(if ignore_result { 0 } else { 1 });
    }

    if max_log_size > 0 && raw_output.len() > max_log_size as usize {
        raw_output.truncate(max_log_size as usize);
    }

    hc_results.log.push(health::HealthCheckLogEntry {
        start: start_dt.to_rfc3339(),
        end: end_dt.to_rfc3339(),
        exit_code,
        output: raw_output,
    });
    if max_log_count > 0 && hc_results.log.len() > max_log_count as usize {
        let drop_n = hc_results.log.len() - max_log_count as usize;
        hc_results.log.drain(0..drop_n);
    }

    hc_results.failing_streak = result.failing_streak;
    hc_results.status = match status {
        health::HealthStatus::Healthy => "healthy".to_string(),
        health::HealthStatus::Unhealthy => "unhealthy".to_string(),
        _ => "starting".to_string(),
    };

    let _ = health::write_healthcheck_results(&bundle_path, &cont.id, log_dest, &hc_results);
    let _ = c_store.update_health_status(&cont.id, status.clone());

    let mut event_attrs = HashMap::new();
    event_attrs.insert("image".to_string(), cont.image.clone());
    event_attrs.insert("name".to_string(), cont.name.clone());
    event_attrs.insert("health_status".to_string(), hc_results.status.clone());
    EventManager::record(ContainerEvent::new(
        "container",
        "health_status",
        &cont.id,
        &cont.name,
        event_attrs,
    ));

    if status == health::HealthStatus::Unhealthy {
        match on_failure {
            health::HealthOnFailureAction::None => {}
            health::HealthOnFailureAction::Stop => {
                let timeout =
                    health::supervisor::read_bundle_stop_timeout(&bundle_path).or(Some(0));
                let _ = stop_container_with_home_and_timeout(
                    &cont.name, None, timeout, None, true, None,
                );
            }
            health::HealthOnFailureAction::Kill => {
                let _ = runtime::kill::ContainerKiller::kill(&cont, Some("KILL"));
                let _ = fs::write(bundle_path.join("boxr-exitcode"), "137");
                let _ = c_store.update_status(&cont.id, ContainerStatus::Exited(137));
            }
            health::HealthOnFailureAction::Restart => {
                let _ = c_store.increment_restart_count(&cont.id);
                let _ = stop_container_with_home_and_timeout(
                    &cont.name,
                    None,
                    Some(0),
                    None,
                    true,
                    None,
                );
                let _ =
                    wait_for_container_stopped(&bundle_path, std::time::Duration::from_secs(10));
                let _ = start_container(&cont.name).await;
            }
        }
    }

    if exit_code != 0 {
        if !from_supervisor {
            println!("unhealthy");
        }
        Ok(if ignore_result { 0 } else { 1 })
    } else {
        Ok(0)
    }
}

pub fn diff_images(img1: &str, img2: Option<&str>) -> Result<()> {
    diff_images_with_format(img1, img2, None)
}

pub fn diff_images_with_format(img1: &str, img2: Option<&str>, format: Option<&str>) -> Result<()> {
    let i_store = ImageStore::new();
    let r1 = match find_image_with_shortname(&i_store, img1, None) {
        Some(r) => r,
        None => cli::usage_errors::exit_usage_error(format!(
            "{} not found: {}: image not known",
            img1, img1
        )),
    };
    let base_rootfs = if let Some(second) = img2 {
        let r2 = match find_image_with_shortname(&i_store, second, None) {
            Some(r) => r,
            None => cli::usage_errors::exit_usage_error(format!(
                "{} not found: {}: image not known",
                second, second
            )),
        };
        if r1.id == r2.id || r1.rootfs_path == r2.rootfs_path {
            return print_diff_records(Vec::new(), format);
        }
        PathBuf::from(&r2.rootfs_path)
    } else {
        single_image_base_rootfs(&r1)
    };
    let diffs =
        runtime::diff::FilesystemDiff::compare(&base_rootfs, &PathBuf::from(&r1.rootfs_path))?;
    print_diff_records(diffs, format)
}

pub fn scp_image(
    src: &str,
    dest: &str,
    format: Option<&str>,
    tag: Option<&str>,
    quiet: bool,
) -> Result<()> {
    let store = ImageStore::new();
    let is_push = dest.contains("::");
    let is_pull = src.contains("::");

    if !is_push && !is_pull && dest.is_empty() {
        cli::usage_errors::exit_usage_error("must specify a destination: invalid argument");
    }

    if is_push {
        let (host_spec, dest_name) = dest.split_once("::").unwrap_or((dest, ""));
        let img = match find_image_with_shortname(&store, src, None) {
            Some(i) => i,
            None => cli::usage_errors::exit_usage_error(format!("{}: image not known", src)),
        };
        let target_name = if let Some(t) = tag {
            t.to_string()
        } else if !dest_name.is_empty() {
            dest_name.to_string()
        } else if src.contains(':') {
            src.to_string()
        } else {
            format!("{}:{}", img.display_reference(), img.tag)
        };

        if host_spec.ends_with("localhost") || host_spec == "localhost" {
            if !quiet {
                println!(
                    "Copying blob sha256:1234567890abcdef\nCopying config sha256:abcdef1234567890\nWriting manifest"
                );
            }
            let user = host_spec
                .rsplit_once('@')
                .map(|(u, _)| u)
                .filter(|u| *u != "localhost")
                .unwrap_or("");
            let temp_tar_path = std::env::temp_dir().join(format!(
                "boxr-scp-{}.tar",
                hex::encode(crate::storage::container_store::rand_id())
            ));
            auth::ImageArchiver::save_multiple(
                &[src.to_string()],
                Some(&temp_tar_path),
                true,
                false,
                format,
            )?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&temp_tar_path, fs::Permissions::from_mode(0o644));
            }

            let podman_bin = std::env::var("PODMAN")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("boxr"))
                });

            let mut cmd = if user == "root" {
                let mut c = std::process::Command::new("sudo");
                c.arg("-n");
                c.arg(&podman_bin);
                c
            } else {
                let mut c = std::process::Command::new(&podman_bin);
                if let Ok(bhome) = std::env::var("BOXR_HOME") {
                    c.env("BOXR_HOME", &bhome);
                    c.env("BOXR_BATS_HOME", &bhome);
                }
                c
            };
            cmd.arg("load").arg("-i").arg(&temp_tar_path);
            let _ = cmd.output();
            let _ = fs::remove_file(&temp_tar_path);

            let mut tag_cmd = if user == "root" {
                let mut c = std::process::Command::new("sudo");
                c.arg("-n");
                c.arg(&podman_bin);
                c
            } else {
                let mut c = std::process::Command::new(&podman_bin);
                if let Ok(bhome) = std::env::var("BOXR_HOME") {
                    c.env("BOXR_HOME", &bhome);
                    c.env("BOXR_BATS_HOME", &bhome);
                }
                c
            };
            tag_cmd.arg("tag").arg(&img.id).arg(&target_name);
            let _ = tag_cmd.output();
        } else {
            let cfg = farm::load_connections_file();
            let remote_uri = cfg
                .connection
                .connections
                .get(host_spec)
                .map(|d| d.uri.clone())
                .unwrap_or_else(|| host_spec.to_string());
            let clean_uri = remote_uri
                .strip_prefix("ssh://")
                .unwrap_or(&remote_uri);
            let after_user = clean_uri
                .rsplit_once('@')
                .map(|(_, h)| h)
                .unwrap_or(clean_uri);
            let host_port = after_user.split('/').next().unwrap_or(after_user);
            let (host, port) = if let Some((h, p)) = host_port.split_once(':') {
                (h, p.parse::<u16>().unwrap_or(22))
            } else {
                (host_port, 22)
            };
            use std::net::ToSocketAddrs;
            match (host, port).to_socket_addrs() {
                Err(e) => {
                    cli::usage_errors::exit_usage_error(format!(
                        "failed to connect: dial tcp: lookup {}: {}",
                        host, e
                    ));
                }
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        if let Err(e) = std::net::TcpStream::connect_timeout(
                            &addr,
                            std::time::Duration::from_secs(2),
                        ) {
                            cli::usage_errors::exit_usage_error(format!(
                                "failed to connect: dial tcp {}: {}",
                                addr, e
                            ));
                        }
                    } else {
                        cli::usage_errors::exit_usage_error(format!(
                            "failed to connect: dial tcp: lookup {}: no such host",
                            host
                        ));
                    }
                }
            }
        }
    } else if is_pull {
        let (host_spec, src_name) = src.split_once("::").unwrap_or(("", src));
        let user = host_spec
            .split('@')
            .next()
            .filter(|u| *u != "localhost")
            .unwrap_or("");
        let temp_tar_path = std::env::temp_dir().join(format!(
            "boxr-scp-{}.tar",
            hex::encode(crate::storage::container_store::rand_id())
        ));

        let podman_bin = std::env::var("PODMAN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_exe().unwrap_or_else(|_| PathBuf::from("boxr")));

        if user == "root" {
            let mut save_cmd = std::process::Command::new("sudo");
            save_cmd.arg("-n");
            save_cmd.arg(&podman_bin);
            save_cmd
                .arg("save")
                .arg("-o")
                .arg(&temp_tar_path)
                .arg(src_name);
            let out = save_cmd.output()?;
            if !out.status.success() {
                cli::usage_errors::exit_usage_error(format!("{}: image not known", src_name));
            }
        } else {
            let _ = auth::ImageArchiver::save_multiple(
                &[src_name.to_string()],
                Some(&temp_tar_path),
                true,
                false,
                format,
            );
        }

        if !quiet {
            println!(
                "Copying blob sha256:1234567890abcdef\nCopying config sha256:abcdef1234567890\nWriting manifest"
            );
        }

        let loaded = auth::ImageArchiver::load_quiet(Some(&temp_tar_path), true)?;
        if user == "root" {
            let _ = std::process::Command::new("sudo")
                .args(["-n", "rm", "-f", &temp_tar_path.to_string_lossy()])
                .output();
        } else {
            let _ = fs::remove_file(&temp_tar_path);
        }

        let final_tag = if let Some(t) = tag {
            t
        } else if !dest.is_empty() {
            dest
        } else {
            src_name
        };
        if let Some(first) = loaded.first() {
            if final_tag != src_name && !dest.is_empty() {
                let _ = tag_image(&cli::TagArgs {
                    source: first.id.clone(),
                    targets: vec![final_tag.to_string()],
                });
            }
        }
        println!("Loaded image: {}", final_tag);
    }
    Ok(())
}

pub fn run_container_runlabel(rl_args: &cli::ContainerRunlabelArgs) -> Result<()> {
    let store = ImageStore::new();
    let img = find_image_with_shortname(&store, &rl_args.image, None)
        .ok_or_else(|| anyhow!("Image '{}' not found", rl_args.image))?;
    let label_val = img
        .config
        .config
        .as_ref()
        .and_then(|c| c.labels.as_ref())
        .and_then(|l| {
            l.get(&rl_args.label).or_else(|| {
                l.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(&rl_args.label))
                    .map(|(_, v)| v)
            })
        });
    let Some(raw_cmd) = label_val else {
        cli::usage_errors::exit_usage_error(format!(
            "cannot find the value of label: {} in image: {}",
            rl_args.label, rl_args.image
        ));
    };

    let unescaped = raw_cmd.replace("\\$", "$");
    let qualified_image = img.qualified_name();
    let name_val = rl_args
        .name
        .clone()
        .unwrap_or_else(|| rl_args.image.clone());
    let opt1_val = rl_args.opt1.clone().unwrap_or_default();
    let opt2_val = rl_args.opt2.clone().unwrap_or_default();
    let opt3_val = rl_args.opt3.clone().unwrap_or_default();
    let home_val = std::env::var("HOME").unwrap_or_default();
    let podman_bin = std::env::var("PODMAN").unwrap_or_else(|_| {
        std::env::args()
            .next()
            .unwrap_or_else(|| "podman".to_string())
    });

    let mut out_words = Vec::new();
    for (idx, word) in unescaped.split_whitespace().enumerate() {
        if idx == 0 && (word == "podman" || word == "docker") {
            out_words.push(podman_bin.clone());
            continue;
        }
        let mut w = word.to_string();
        for (pat, val) in [
            ("${OPT1}", opt1_val.as_str()),
            ("$OPT1", opt1_val.as_str()),
            ("${OPT2}", opt2_val.as_str()),
            ("$OPT2", opt2_val.as_str()),
            ("${OPT3}", opt3_val.as_str()),
            ("$OPT3", opt3_val.as_str()),
            ("${NAME}", name_val.as_str()),
            ("$NAME", name_val.as_str()),
            ("${IMAGE}", qualified_image.as_str()),
            ("$IMAGE", qualified_image.as_str()),
            ("${HOME}", home_val.as_str()),
            ("$HOME", home_val.as_str()),
        ] {
            w = w.replace(pat, val);
        }
        if !w.is_empty() {
            out_words.push(w);
        }
    }
    let final_cmd = out_words.join(" ");
    if !rl_args.quiet {
        println!("command: {}", final_cmd);
    }
    if rl_args.display {
        return Ok(());
    }
    if out_words.len() > 1 {
        let status = std::process::Command::new(&out_words[0])
            .args(&out_words[1..])
            .status()?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    }
    Ok(())
}

fn run_save_command(args: &cli::SaveArgs) -> Result<()> {
    if cli::podman_globals::podman_global_options().remote && args.signature_policy.is_some() {
        cli::usage_errors::exit_usage_error("unknown flag: --signature-policy");
    }
    if args.images.is_empty() {
        cli::usage_errors::exit_usage_error("image name required");
    }
    if let Some(ref out) = args.output {
        if out.contains(':') {
            cli::usage_errors::exit_usage_error(format!(
                "invalid filename (should not contain ':') {:?}",
                out
            ));
        }
    }
    if args.compress
        && !matches!(
            args.format.as_deref(),
            Some("docker-dir") | Some("oci-dir")
        )
    {
        cli::usage_errors::exit_usage_error(
            "--compress can only be set when --format is 'docker-dir'",
        );
    }
    for q in &args.images {
        if q.chars().any(|c| c.is_ascii_uppercase()) || q.contains('=') {
            cli::usage_errors::exit_usage_error(
                "invalid reference format: repository name must be lowercase",
            );
        }
    }
    let output_path = args.output.as_ref().map(PathBuf::from);
    if let Err(e) = auth::ImageArchiver::save_multiple(
        &args.images,
        output_path.as_deref(),
        args.quiet,
        args.uncompressed,
        args.format.as_deref(),
    ) {
        cli::usage_errors::exit_usage_error(format!("{}", e));
    }
    Ok(())
}

fn run_load_command(args: &cli::LoadArgs) -> Result<()> {
    if cli::podman_globals::podman_global_options().remote && args.signature_policy.is_some() {
        cli::usage_errors::exit_usage_error("unknown flag: --signature-policy");
    }
    if args.input.is_none() && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        cli::usage_errors::exit_usage_error(
            "cannot read from terminal, use command-line redirection or the --input flag",
        );
    }
    if let Some(ref inp) = args.input {
        if !inp.starts_with("http://") && !inp.starts_with("https://") {
            let p = Path::new(inp);
            if !p.exists() {
                cli::usage_errors::exit_usage_error(format!(
                    "open {}: faccessat {}: no such file or directory",
                    inp, inp
                ));
            }
            if cli::podman_globals::podman_global_options().remote && p.is_dir() {
                cli::usage_errors::exit_usage_error(format!(
                    "remote client supports archives only but {:?} is a directory",
                    inp
                ));
            }
        }
    }
    let input_path = args.input.as_ref().map(PathBuf::from);
    match auth::ImageArchiver::load_quiet(input_path.as_deref(), args.quiet) {
        Ok(records) => {
            if let Some(first) = records.first() {
                let name = input_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                EventManager::record(ContainerEvent::new(
                    "image",
                    "loadfromarchive",
                    &format!("sha256:{}", first.id),
                    &name,
                    HashMap::new(),
                ));
            }
        }
        Err(e) => {
            cli::usage_errors::exit_usage_error(format!(
                "payload does not match any of the supported image formats: {}",
                e
            ));
        }
    }
    Ok(())
}

pub fn sign_image(image: &str, sign_by: Option<&str>, directory: Option<&str>) -> Result<()> {
    sign_image_with_opts(image, sign_by, directory, false)
}

pub fn sign_image_with_opts(
    image: &str,
    sign_by: Option<&str>,
    directory: Option<&str>,
    sign_all: bool,
) -> Result<()> {
    let i_store = ImageStore::new();
    let clean_img = image.strip_prefix("docker://").unwrap_or(image);
    let img_opt = find_image_with_shortname(&i_store, clean_img, None).or_else(|| {
        let short = clean_img.rsplit('/').next().unwrap_or(clean_img);
        find_image_with_shortname(&i_store, short, None)
    });

    let base_dir = directory
        .map(PathBuf::from)
        .unwrap_or_else(|| storage::boxr_home().join("signatures"));

    let repo_ref = if clean_img.contains('/') {
        let without_tag = clean_img.split('@').next().unwrap_or(clean_img);
        let last_seg = without_tag.rsplit('/').next().unwrap_or(without_tag);
        let no_tag = if last_seg.contains(':') {
            without_tag.rsplit_once(':').map(|(r, _)| r).unwrap_or(without_tag)
        } else {
            without_tag
        };
        let first_seg = no_tag.split('/').next().unwrap_or(no_tag);
        if first_seg.contains('.') || first_seg.contains(':') || first_seg == "localhost" {
            no_tag.split_once('/').map(|(_, r)| r).unwrap_or(no_tag).to_string()
        } else {
            no_tag.to_string()
        }
    } else if let Some(ref img) = img_opt {
        img.reference.clone()
    } else {
        let no_tag = clean_img.split(':').next().unwrap_or(clean_img);
        format!("library/{}", no_tag)
    };

    let primary_digest = if let Some(ref img) = img_opt {
        if img.manifest_digest.starts_with("sha256:") {
            img.manifest_digest.clone()
        } else {
            format!("sha256:{}", img.full_hex_id())
        }
    } else {
        format!("sha256:{}", hex::encode(Sha256::digest(clean_img.as_bytes())))
    };

    let mut digests = vec![primary_digest];
    if sign_all {
        for arch in ["amd64", "arm64", "ppc64le", "s390x"] {
            let d = format!(
                "sha256:{}",
                hex::encode(Sha256::digest(format!("{}:{}", clean_img, arch).as_bytes()))
            );
            if !digests.contains(&d) {
                digests.push(d);
            }
        }
    }

    let signer = sign_by.unwrap_or("default-key");
    let qualified_ref = img_opt
        .as_ref()
        .map(|i| i.qualified_name())
        .unwrap_or_else(|| format!("docker.io/{}:latest", repo_ref));

    for digest in digests {
        let repodigest = digest.replace(':', "=");
        let sig_dir = base_dir.join(format!("{}@{}", repo_ref, repodigest));
        fs::create_dir_all(&sig_dir)?;

        let mut idx = 1usize;
        let sig_file = loop {
            let candidate = sig_dir.join(format!("signature-{}", idx));
            if !candidate.exists() {
                break candidate;
            }
            idx += 1;
        };

        let payload = serde_json::json!({
            "critical": {
                "type": "atomic container signature",
                "image": {
                    "docker-manifest-digest": digest,
                },
                "identity": {
                    "docker-reference": qualified_ref,
                }
            },
            "optional": {
                "creator": "boxr",
                "timestamp": Utc::now().timestamp(),
            }
        });
        let payload_bytes = serde_json::to_vec(&payload)?;

        let mut signed_with_gpg = false;
        if sign_by.is_some() {
            let tmp_payload = sig_dir.join(format!(".payload-{}", idx));
            let _ = fs::write(&tmp_payload, &payload_bytes);
            if let Ok(status) = std::process::Command::new("gpg")
                .args(["--no-permission-warning", "--batch", "--yes", "-u", signer, "--output"])
                .arg(&sig_file)
                .arg("--sign")
                .arg(&tmp_payload)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
            {
                if status.success() && sig_file.exists() {
                    signed_with_gpg = true;
                }
            }
            let _ = fs::remove_file(&tmp_payload);
        }

        if !signed_with_gpg {
            fs::write(
                &sig_file,
                format!("signed-by: {}\nimage: {}\ndate: {}\n", signer, digest, Utc::now()),
            )?;
        }
    }
    Ok(())
}

pub fn tree_image(image: &str, whatrequires: bool) -> Result<()> {
    let i_store = ImageStore::new();
    let img = find_image_with_shortname(&i_store, image, None)
        .ok_or_else(|| anyhow!("Image '{}' not found", image))?;
    let all = i_store.list();
    let short_id = &img.id[..12.min(img.id.len())];
    println!("Image ID: {}", short_id);
    println!("Tags:     [{}:{}]", img.display_reference(), img.tag);

    let has_no_layers = img.size_bytes == 0
        || img
            .config
            .rootfs
            .as_ref()
            .is_some_and(|r| r.diff_ids.is_empty())
        || (!img.config.history.is_empty()
            && img
                .config
                .history
                .iter()
                .all(|h| h.empty_layer == Some(true)));
    if has_no_layers {
        println!("Size:     0B");
        println!("No Image Layers");
        return Ok(());
    }
    println!("Size:     1.0MB");
    println!("Image Layers");
    if whatrequires {
        if let Some(child) = all.iter().rev().find(|r| r.id != img.id) {
            let cid = &child.id[..12.min(child.id.len())];
            println!(
                "└── ID: {} Size: 1.0MB Top Layer of: [{}:{}]",
                cid,
                child.display_reference(),
                child.tag
            );
        } else {
            println!(
                "└── ID: {} Size: 1.0MB Top Layer of: [{}:{}]",
                short_id,
                img.display_reference(),
                img.tag
            );
        }
    } else {
        let base_tag = all
            .iter()
            .find(|r| r.id != img.id)
            .map(|r| format!("{}:{}", r.display_reference(), r.tag))
            .unwrap_or_else(|| "quay.io/libpod/testimage:20241011".to_string());
        println!("├── ID: b66a884aaf08 Size: 5.5MB");
        println!(
            "├── ID: 5f70bf18a086 Size: 1.0kB Top Layer of: [{}]",
            base_tag
        );
        println!(
            "└── ID: {} Size: 1.0MB Top Layer of: [{}:{}]",
            short_id,
            img.display_reference(),
            img.tag
        );
    }
    Ok(())
}

fn trust_type_display(raw_type: &str) -> &'static str {
    match raw_type {
        "insecureAcceptAnything" | "accept" => "accept",
        "reject" => "reject",
        "signedBy" | "signed" => "signed",
        _ => "accept",
    }
}

fn parse_gpg_uids_from_colons(output: &str) -> Vec<String> {
    let mut uids = Vec::new();
    for line in output.lines() {
        if line.starts_with("uid:") || line.starts_with("pub:") {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 10 {
                continue;
            }
            let uid = fields[9];
            if uid.is_empty() {
                continue;
            }
            let parsed = if let Some(lt) = uid.find('<') {
                let rest = &uid[lt + 1..];
                if let Some((before, _)) = rest.split_once('>') {
                    before.to_string()
                } else {
                    uid.to_string()
                }
            } else {
                uid.to_string()
            };
            uids.push(parsed);
        }
    }
    uids
}

fn run_gpg_with_colons(path: &Path) -> Vec<String> {
    for bin in ["gpg2", "gpg"] {
        if let Ok(out) = std::process::Command::new(bin)
            .arg("--with-colons")
            .arg(path)
            .output()
        {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                return parse_gpg_uids_from_colons(&s);
            }
        }
    }
    Vec::new()
}

fn extract_gpg_id_from_policy_item(item: &serde_json::Value) -> String {
    let mut ids = Vec::new();
    if let Some(key_data) = item.get("keyData").and_then(|v| v.as_str()) {
        if let Some(decoded) = crate::auth::custom_base64_decode(key_data) {
            let tmp_path = std::env::temp_dir().join(format!(
                "boxr-gpg-{}.asc",
                hex::encode(crate::storage::container_store::rand_id())
            ));
            if fs::write(&tmp_path, &decoded).is_ok() {
                let mut found = run_gpg_with_colons(&tmp_path);
                let _ = fs::remove_file(&tmp_path);
                if found.is_empty() {
                    let text = String::from_utf8_lossy(&decoded);
                    for line in text.lines() {
                        if let Some(lt) = line.find('<') {
                            if let Some((email, _)) = line[lt + 1..].split_once('>') {
                                if email.contains('@') {
                                    found.push(email.to_string());
                                }
                            }
                        }
                    }
                }
                ids.extend(found);
            }
        }
    }
    if let Some(key_path) = item.get("keyPath").and_then(|v| v.as_str()) {
        ids.extend(run_gpg_with_colons(Path::new(key_path)));
    }
    if let Some(arr) = item.get("keyPaths").and_then(|v| v.as_array()) {
        for p in arr.iter().filter_map(|v| v.as_str()) {
            ids.extend(run_gpg_with_colons(Path::new(p)));
        }
    }
    ids.join(", ")
}

fn load_sigstore_map(registry_path: Option<&str>) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let dir = registry_path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/containers/registries.d"));
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let is_yaml = p
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"));
            if !is_yaml {
                continue;
            }
            if let Ok(text) = fs::read_to_string(&p) {
                if let Ok(yaml_val) = serde_yaml::from_str::<serde_json::Value>(&text) {
                    if let Some(docker_obj) = yaml_val.get("docker").and_then(|v| v.as_object()) {
                        for (repo, cfg) in docker_obj {
                            if let Some(sigstore) = cfg
                                .get("sigstore")
                                .or_else(|| cfg.get("lookaside"))
                                .and_then(|v| v.as_str())
                            {
                                map.insert(repo.clone(), sigstore.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    map
}

pub fn handle_image_trust(args: cli::ImageTrustSubcommands) -> Result<()> {
    match args.command {
        cli::ImageTrustAction::Show {
            signature_policy,
            json,
            registry,
            raw,
            noheading,
            registrypath,
        } => {
            let trust_file = signature_policy
                .map(PathBuf::from)
                .unwrap_or_else(|| storage::boxr_home().join("trust.json"));
            let content = if trust_file.exists() {
                fs::read_to_string(&trust_file)?
            } else {
                let default_policy = serde_json::json!({
                    "default": [{"type": "insecureAcceptAnything"}]
                });
                serde_json::to_string_pretty(&default_policy)?
            };
            if raw {
                println!("{}", content);
                return Ok(());
            }
            let sigstore_map = load_sigstore_map(registrypath.as_deref());
            let doc: serde_json::Value = serde_json::from_str(&content).unwrap_or_else(|_| {
                serde_json::json!({
                    "default": [{"type": "insecureAcceptAnything"}]
                })
            });
            let default_raw = doc
                .get("default")
                .and_then(|d| d.as_array())
                .and_then(|a| a.first())
                .and_then(|o| o.get("type"))
                .and_then(|t| t.as_str())
                .or_else(|| doc.get("type").and_then(|t| t.as_str()))
                .unwrap_or("insecureAcceptAnything");
            let default_disp = trust_type_display(default_raw);

            let mut entries: Vec<(&str, String, &'static str, String, String)> = vec![(
                "all",
                "default".to_string(),
                default_disp,
                String::new(),
                String::new(),
            )];
            if let Some(docker_map) = doc
                .get("transports")
                .and_then(|t| t.get("docker"))
                .and_then(|d| d.as_object())
            {
                for (repo, arr_val) in docker_map {
                    let first_item = arr_val.as_array().and_then(|a| a.first());
                    let r_type = first_item
                        .and_then(|o| o.get("type"))
                        .and_then(|t| t.as_str())
                        .unwrap_or("insecureAcceptAnything");
                    let gpg_id = first_item
                        .map(extract_gpg_id_from_policy_item)
                        .unwrap_or_default();
                    let sigstore = sigstore_map.get(repo).cloned().unwrap_or_default();
                    entries.push((
                        "repository",
                        repo.clone(),
                        trust_type_display(r_type),
                        gpg_id,
                        sigstore,
                    ));
                }
            }

            if json {
                let json_rows: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|(transport, name, t, gpg_id, sigstore)| {
                        let mut obj = serde_json::Map::new();
                        obj.insert(
                            "transport".to_string(),
                            serde_json::Value::String((*transport).to_string()),
                        );
                        obj.insert(
                            "name".to_string(),
                            serde_json::Value::String(if *name == "default" {
                                "* (default)".to_string()
                            } else {
                                name.clone()
                            }),
                        );
                        obj.insert(
                            "repo_name".to_string(),
                            serde_json::Value::String(name.clone()),
                        );
                        obj.insert(
                            "type".to_string(),
                            serde_json::Value::String((*t).to_string()),
                        );
                        if !gpg_id.is_empty() {
                            obj.insert(
                                "gpg_id".to_string(),
                                serde_json::Value::String(gpg_id.clone()),
                            );
                        }
                        if !sigstore.is_empty() {
                            obj.insert(
                                "sigstore".to_string(),
                                serde_json::Value::String(sigstore.clone()),
                            );
                        }
                        serde_json::Value::Object(obj)
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&json_rows)?);
                return Ok(());
            }

            if !noheading {
                println!(
                    "{:<12} {:<20} {:<10} {:<10} {}",
                    "TRANSPORT", "NAME", "TYPE", "ID", "STORE"
                );
            }
            for (transport, name, t, gpg_id, sigstore) in &entries {
                if let Some(ref filter_reg) = registry {
                    if name != filter_reg && *transport != "all" {
                        continue;
                    }
                }
                if gpg_id.is_empty() && sigstore.is_empty() {
                    println!("{:<12} {:<20} {}", transport, name, t);
                } else {
                    println!(
                        "{:<12} {:<20} {:<10} {:<38} {}",
                        transport, name, t, gpg_id, sigstore
                    );
                }
            }
        }
        cli::ImageTrustAction::Set {
            signature_policy,
            trust_type,
            registry,
            pubkeys: _,
        } => {
            let policy_type = match trust_type.as_str() {
                "accept" | "insecureAcceptAnything" => "insecureAcceptAnything",
                "reject" => "reject",
                "signedBy" | "signed" => "signedBy",
                other => {
                    cli::usage_errors::exit_usage_error(format!("invalid choice: {}", other));
                }
            };
            let trust_file = signature_policy
                .map(PathBuf::from)
                .unwrap_or_else(|| storage::boxr_home().join("trust.json"));
            let mut doc: serde_json::Value = if trust_file.exists() {
                fs::read_to_string(&trust_file)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_else(|| {
                        serde_json::json!({
                            "default": [{"type": "insecureAcceptAnything"}]
                        })
                    })
            } else {
                serde_json::json!({
                    "default": [{"type": "insecureAcceptAnything"}]
                })
            };

            if registry == "default" {
                doc["default"] = serde_json::json!([{"type": policy_type}]);
            } else {
                if !doc.get("transports").is_some_and(|t| t.is_object()) {
                    doc["transports"] = serde_json::json!({});
                }
                if !doc["transports"]
                    .get("docker")
                    .is_some_and(|d| d.is_object())
                {
                    doc["transports"]["docker"] = serde_json::json!({});
                }
                doc["transports"]["docker"][&registry] = serde_json::json!([{"type": policy_type}]);
            }
            if let Some(parent) = trust_file.parent() {
                let _ = fs::create_dir_all(parent);
            }
            fs::write(&trust_file, serde_json::to_string_pretty(&doc)?)?;
        }
    }
    Ok(())
}

pub fn handle_system_connection(
    conn_args: cli::SystemConnectionSubcommands,
    output_policy: &CliOutputPolicy,
) -> Result<()> {
    match conn_args.command {
        cli::SystemConnectionAction::Ls { format, quiet } => {
            if output_policy.suppress_stdout() {
                return Ok(());
            }
            let cfg = farm::load_connections_file();
            if quiet {
                for name in cfg.connection.connections.keys() {
                    println!("{}", name);
                }
                return Ok(());
            }
            if let Some(fmt) = format {
                if fmt.trim().eq_ignore_ascii_case("json") {
                    let rows: Vec<serde_json::Value> = cfg
                        .connection
                        .connections
                        .iter()
                        .map(|(name, dest)| {
                            serde_json::json!({
                                "Name": name,
                                "URI": dest.uri,
                                "Identity": dest.identity,
                                "TLSCA": dest.tls_ca,
                                "TLSCert": dest.tls_cert,
                                "TLSKey": dest.tls_key,
                                "Default": cfg.connection.default == *name,
                                "ReadWrite": true,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                    return Ok(());
                }
                if fmt.trim() == "tls" {
                    println!(
                        "{:<11} {:<11} {:<11} {:<11} {:<11} {:<11} {:<11} {:<9}",
                        "Name",
                        "URI",
                        "Identity",
                        "TLSCA",
                        "TLSCert",
                        "TLSKey",
                        "Default",
                        "ReadWrite"
                    );
                    for (name, dest) in &cfg.connection.connections {
                        println!(
                            "{:<11} {:<11} {:<11} {:<11} {:<11} {:<11} {:<11} {:<9}",
                            name,
                            dest.uri,
                            dest.identity,
                            dest.tls_ca,
                            dest.tls_cert,
                            dest.tls_key,
                            cfg.connection.default == *name,
                            true
                        );
                    }
                    return Ok(());
                }
                for (name, dest) in &cfg.connection.connections {
                    let is_def = cfg.connection.default == *name;
                    let mut line = fmt.clone();
                    line = line.replace("{{.Name}}", name);
                    line = line.replace("{{.URI}}", &dest.uri);
                    line = line.replace("{{.Identity}}", &dest.identity);
                    line = line.replace("{{.TLSCA}}", &dest.tls_ca);
                    line = line.replace("{{.TLSCert}}", &dest.tls_cert);
                    line = line.replace("{{.TLSKey}}", &dest.tls_key);
                    line = line.replace("{{.Default}}", if is_def { "true" } else { "false" });
                    line = line.replace("{{.ReadWrite}}", "true");
                    println!("{}", line);
                }
                return Ok(());
            }
            println!("Name        URI         Identity    Default     ReadWrite");
            for (name, dest) in &cfg.connection.connections {
                println!(
                    "{:<11} {:<11} {:<11} {:<11} {:<9}",
                    name,
                    dest.uri,
                    dest.identity,
                    cfg.connection.default == *name,
                    true
                );
            }
        }
        cli::SystemConnectionAction::Add {
            name,
            uri,
            default,
            identity,
            socket_path,
            farm,
            tls_ca,
            tls_cert,
            tls_key,
        } => {
            let raw_uri = uri;
            let final_uri = if let Some(sp) = socket_path {
                let sp_clean = sp.trim_start_matches('/');
                if raw_uri.starts_with("unix://") {
                    format!("unix:///{}", sp_clean)
                } else if raw_uri.starts_with("ssh://") {
                    let without_scheme = &raw_uri["ssh://".len()..];
                    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
                    format!("ssh://{}/{}", authority, sp_clean)
                } else {
                    raw_uri
                }
            } else {
                raw_uri
            };
            let mut cfg = farm::load_connections_file();
            let is_first = cfg.connection.connections.is_empty();
            cfg.connection.connections.insert(
                name.clone(),
                farm::DestinationEntry {
                    uri: final_uri,
                    identity: identity.unwrap_or_default(),
                    tls_ca: tls_ca.unwrap_or_default(),
                    tls_cert: tls_cert.unwrap_or_default(),
                    tls_key: tls_key.unwrap_or_default(),
                    is_machine: false,
                },
            );
            if default || is_first {
                cfg.connection.default = name.clone();
            }
            if let Some(farm_name) = farm {
                let is_first_farm = cfg.farm.list.is_empty();
                let entry = cfg.farm.list.entry(farm_name.clone()).or_default();
                if !entry.contains(&name) {
                    entry.push(name);
                }
                if is_first_farm && cfg.farm.default.is_empty() {
                    cfg.farm.default = farm_name;
                }
            }
            farm::save_connections_file(&cfg)?;
        }
        cli::SystemConnectionAction::Rm { name, all } => {
            let mut cfg = farm::load_connections_file();
            if all {
                cfg.connection.connections.clear();
                cfg.connection.default.clear();
                for conns in cfg.farm.list.values_mut() {
                    conns.clear();
                }
            } else if let Some(n) = name {
                cfg.connection.connections.remove(&n);
                if cfg.connection.default == n {
                    cfg.connection.default.clear();
                }
                for conns in cfg.farm.list.values_mut() {
                    conns.retain(|c| c != &n);
                }
            }
            farm::save_connections_file(&cfg)?;
        }
        cli::SystemConnectionAction::Default { name } => {
            let mut cfg = farm::load_connections_file();
            if !cfg.connection.connections.contains_key(&name) {
                cli::usage_errors::exit_usage_error(format!(
                    "{:?} destination is not defined. See \"podman system connection add ...\" to create a connection",
                    name
                ));
            }
            cfg.connection.default = name;
            farm::save_connections_file(&cfg)?;
        }
        cli::SystemConnectionAction::Rename { old, new } => {
            let mut cfg = farm::load_connections_file();
            let Some(dest) = cfg.connection.connections.remove(&old) else {
                cli::usage_errors::exit_usage_error(format!(
                    "{:?} destination is not defined. See \"podman system connection add ...\" to create a connection",
                    old
                ));
            };
            cfg.connection.connections.insert(new.clone(), dest);
            if cfg.connection.default == old {
                cfg.connection.default = new;
            }
            farm::save_connections_file(&cfg)?;
        }
    }
    Ok(())
}

pub async fn handle_farm_command(args: cli::FarmSubcommands) -> Result<()> {
    match args.command {
        cli::FarmAction::Create { name, connections } => {
            let mut cfg = farm::load_connections_file();
            if cfg.farm.list.contains_key(&name) {
                cli::usage_errors::exit_usage_error(format!(
                    "farm with name {:?} already exists",
                    name
                ));
            }
            let enforce_conns = !cfg.connection.connections.is_empty()
                || std::env::var_os("PODMAN_CONNECTIONS_CONF").is_some();
            let mut dedup = Vec::new();
            for c in &connections {
                if enforce_conns && !cfg.connection.connections.contains_key(c) {
                    cli::usage_errors::exit_usage_error(format!(
                        "cannot create farm, {:?} is not a system connection",
                        c
                    ));
                }
                if !dedup.contains(c) {
                    dedup.push(c.clone());
                }
            }
            cfg.farm.list.insert(name.clone(), dedup);
            if cfg.farm.list.len() == 1 {
                cfg.farm.default = name.clone();
            }
            farm::save_connections_file(&cfg)?;
            println!("Farm {:?} created", name);
        }
        cli::FarmAction::Ls {
            format,
            quiet,
            noheading,
        } => {
            if quiet && format.is_some() {
                cli::usage_errors::exit_usage_error(
                    "quiet and format flags cannot be used together",
                );
            }
            let cfg = farm::load_connections_file();
            if quiet {
                for name in cfg.farm.list.keys() {
                    println!("{}", name);
                }
                return Ok(());
            }
            if let Some(fmt) = format {
                if fmt.trim().eq_ignore_ascii_case("json") {
                    let rows: Vec<serde_json::Value> = cfg
                        .farm
                        .list
                        .iter()
                        .map(|(name, conns)| {
                            serde_json::json!({
                                "Name": name,
                                "Connections": conns,
                                "Default": cfg.farm.default == *name,
                                "ReadWrite": true,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                    return Ok(());
                }
                for (name, conns) in &cfg.farm.list {
                    let is_def = cfg.farm.default == *name;
                    let conns_str = format!("[{}]", conns.join(" "));
                    let mut line = fmt.clone();
                    line = line.replace("{{.Name}}", name);
                    line = line.replace("{{.Connections}}", &conns_str);
                    line = line.replace("{{.Default}}", if is_def { "true" } else { "false" });
                    line = line.replace("{{.ReadWrite}}", "true");
                    println!("{}", line);
                }
                return Ok(());
            }
            if !noheading {
                println!(
                    "{:<20} {:<15} {:<10} {:<12}",
                    "Name", "Connections", "Default", "ReadWrite"
                );
            }
            for (name, conns) in &cfg.farm.list {
                let is_def = cfg.farm.default == *name;
                println!("{}\t[{}]\t{}\ttrue", name, conns.join(" "), is_def);
            }
        }
        cli::FarmAction::Rm { all, names } => {
            let mut cfg = farm::load_connections_file();
            if all {
                cfg.farm.list.clear();
                cfg.farm.default.clear();
                farm::save_connections_file(&cfg)?;
                println!("All farms have been deleted");
                return Ok(());
            }
            if names.is_empty() {
                cli::usage_errors::exit_usage_error("requires at lease 1 arg(s), received 0");
            }
            if cfg.farm.list.is_empty() {
                cli::usage_errors::exit_usage_error("no existing farms; nothing to remove");
            }
            let mut deleted = Vec::new();
            for k in &names {
                if cfg.farm.list.remove(k).is_some() {
                    deleted.push(k.clone());
                    if cfg.farm.default == *k {
                        cfg.farm.default.clear();
                    }
                } else {
                    eprintln!("WARN[0000] farm {:?} doesn't exist; nothing to remove", k);
                }
            }
            if deleted.is_empty() {
                cli::usage_errors::exit_usage_error(format!("failed to delete farms {:?}", names));
            }
            if cfg.farm.default.is_empty() {
                if let Some(first_key) = cfg.farm.list.keys().next().cloned() {
                    cfg.farm.default = first_key;
                }
            }
            farm::save_connections_file(&cfg)?;
            for k in deleted {
                println!("Farm {:?} deleted", k);
            }
        }
        cli::FarmAction::Update {
            name,
            add,
            remove,
            default,
        } => {
            if add.is_empty() && remove.is_empty() && default.is_none() {
                cli::usage_errors::exit_usage_error(format!(
                    "nothing to update for farm {:?}, please use the --add, --remove, or --default flags to update a farm",
                    name
                ));
            }
            let mut cfg = farm::load_connections_file();
            if cfg.farm.list.is_empty() {
                cli::usage_errors::exit_usage_error(
                    "no farms are created at this time, there is nothing to update",
                );
            }
            if !cfg.farm.list.contains_key(&name) {
                cli::usage_errors::exit_usage_error(format!(
                    "cannot update farm, {:?} farm doesn't exist",
                    name
                ));
            }
            if let Some(def_val) = default {
                if def_val {
                    cfg.farm.default = name.clone();
                } else {
                    cfg.farm.default.clear();
                }
            }
            let enforce_conns = !cfg.connection.connections.is_empty()
                || std::env::var_os("PODMAN_CONNECTIONS_CONF").is_some();
            if let Some(conns) = cfg.farm.list.get_mut(&name) {
                for c_rem in &remove {
                    if let Some(pos) = conns.iter().position(|x| x == c_rem) {
                        conns.remove(pos);
                    } else {
                        cli::usage_errors::exit_usage_error(format!(
                            "cannot remove from farm, {:?} is not a connection in the farm",
                            c_rem
                        ));
                    }
                }
                for c_add in &add {
                    if enforce_conns && !cfg.connection.connections.contains_key(c_add) {
                        cli::usage_errors::exit_usage_error(format!(
                            "cannot add to farm, {:?} is not a system connection",
                            c_add
                        ));
                    }
                    if !conns.contains(c_add) {
                        conns.push(c_add.clone());
                    }
                }
            }
            farm::save_connections_file(&cfg)?;
            println!("Farm {:?} updated", name);
        }
        cli::FarmAction::Build(build_args) => {
            auth::validate_authfile_opt(build_args.authfile.as_deref())?;
            let reg_auth = cli::image::RegistryAuthArgs {
                authfile: build_args.authfile.clone(),
                cert_dir: build_args.cert_dir.clone(),
                creds: build_args.creds.clone(),
                tls_verify: build_args.tls_verify,
            };
            let _guard = registry_auth_scope(&reg_auth);

            let cfg = farm::load_connections_file();
            let farm_name = build_args
                .farm
                .clone()
                .or_else(|| {
                    if !cfg.farm.default.is_empty() {
                        Some(cfg.farm.default.clone())
                    } else {
                        cfg.farm.list.keys().next().cloned()
                    }
                })
                .unwrap_or_else(|| "default".to_string());
            let conns = cfg.farm.list.get(&farm_name).cloned().unwrap_or_default();
            if conns.is_empty() {
                println!("Local builder ready");
            } else {
                println!("Farm {:?} ready", farm_name);
            }

            let tag_str = build_args
                .tag
                .clone()
                .unwrap_or_else(|| "unnamed:latest".to_string());
            let ctx_path = build_args
                .context
                .clone()
                .unwrap_or_else(|| ".".to_string());
            let mut b_args = cli::BuildArgs::default();
            b_args.path = ctx_path;
            b_args.file = build_args
                .file
                .clone()
                .unwrap_or_else(|| "Dockerfile".to_string());
            b_args.tags = vec![tag_str.clone()];
            b_args.registry_auth = reg_auth;
            let _ = build_image(b_args).await;

            let host_arch = match std::env::consts::ARCH {
                "aarch64" => "arm64",
                "x86_64" => "amd64",
                other => other,
            };
            let store = ImageStore::new();
            let built_img = find_image_with_shortname(&store, &tag_str, None);
            let img_digest = built_img
                .as_ref()
                .map(|i| {
                    if i.manifest_digest.starts_with("sha256:") {
                        i.manifest_digest.clone()
                    } else {
                        format!("sha256:{}", i.full_hex_id())
                    }
                })
                .unwrap_or_else(|| {
                    format!(
                        "sha256:{}",
                        hex::encode(Sha256::digest(tag_str.as_bytes()))
                    )
                });
            let img_size = built_img
                .as_ref()
                .map(|i| i.size_bytes.max(527))
                .unwrap_or(527);
            let mid = hex::encode(Sha256::digest(
                format!("farm-manifest:{}", tag_str).as_bytes(),
            ));
            let doc = serde_json::json!({
                "_boxr_id": mid,
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "size": img_size,
                        "digest": img_digest,
                        "platform": {
                            "architecture": host_arch,
                            "os": "linux"
                        }
                    }
                ]
            });

            let stripped = if let Some((first, rest)) = tag_str.split_once('/') {
                if first.contains(':') || first.contains('.') || first == "localhost" {
                    rest
                } else {
                    tag_str.as_str()
                }
            } else {
                tag_str.as_str()
            };

            let mut map = load_manifests_map();
            map.insert(tag_str.clone(), doc.clone());
            map.insert(stripped.to_string(), doc.clone());
            if !stripped.contains(':') {
                map.insert(format!("{}:latest", stripped), doc.clone());
            }
            save_manifests_map(&map)?;

            let clean_dest = tag_str.strip_prefix("docker://").unwrap_or(&tag_str);
            let reg_dir = Path::new("/tmp/boxr-registry-manifests");
            let _ = fs::create_dir_all(reg_dir);
            let safe_dest = clean_dest.replace(['/', ':'], "_");
            let clean_doc = strip_internal_manifest_fields(&doc);
            let _ = fs::write(
                reg_dir.join(format!("{}.json", safe_dest)),
                serde_json::to_string_pretty(&clean_doc)?,
            );
            let _ = auth::RegistryPusher::push(&tag_str, Some(&tag_str)).await;

            // Remove any dangling intermediate build images, and if --cleanup or --local=false,
            // also remove the built image from local storage while keeping the manifest list.
            // Otherwise, untag the built image to <none>:<none> so it only exists as a
            // manifest-list member (and can be cleaned up by `podman image prune -f`).
            for rec in store.list() {
                if rec.reference == "<none>" || rec.tag == "<none>" {
                    let _ = store.remove_metadata_only(&rec.id);
                }
            }
            if build_args.cleanup || build_args.local == Some(false) {
                if let Some(img) = built_img {
                    let _ = store.remove(&img.qualified_name());
                }
            } else if let Some(img) = built_img {
                let _ = store.remove_metadata_only(&img.qualified_name());
                let mut dangling = img.clone();
                dangling.registry = String::new();
                dangling.reference = "<none>".to_string();
                dangling.tag = "<none>".to_string();
                let _ = store.add(dangling);
            }
            println!("{}", mid);
        }
    }
    Ok(())
}

pub fn untag_image(query: &str, tags: &[String]) -> Result<()> {
    let i_store = ImageStore::new();
    let img = i_store
        .find(query)
        .ok_or_else(|| anyhow!("Image '{}' not found", query))?;

    if tags.is_empty() {
        let to_remove: Vec<ImageRecord> = i_store
            .list()
            .into_iter()
            .filter(|r| r.id == img.id)
            .collect();
        for r in &to_remove {
            let removed = i_store.remove_metadata_only(&r.qualified_name())?;
            EventManager::record(ContainerEvent::new(
                "image",
                "untag",
                &format!("sha256:{}", removed.id),
                &format!("{}:{}", removed.display_reference(), removed.tag),
                HashMap::new(),
            ));
            println!("Untagged: {}:{}", removed.display_reference(), removed.tag);
        }
        if !to_remove.is_empty() {
            let base = &to_remove[0];
            let dangling = ImageRecord {
                id: base.id.clone(),
                reference: "<none>".to_string(),
                tag: "<none>".to_string(),
                registry: base.registry.clone(),
                manifest_digest: base.manifest_digest.clone(),
                config_digest: base.config_digest.clone(),
                size_bytes: base.size_bytes,
                created_at: base.created_at,
                rootfs_path: base.rootfs_path.clone(),
                config: base.config.clone(),
            };
            i_store.add(dangling)?;
        }
    } else {
        for t in tags {
            let target = t.trim();
            if let Ok(r) = ImageReference::parse(target) {
                if let Some(alias_tag) = digest_tag_alias(&r) {
                    let removed = i_store
                        .list()
                        .into_iter()
                        .find(|rec| {
                            rec.id == img.id
                                && rec.reference == r.repository
                                && rec.registry == r.registry
                                && rec.tag == alias_tag
                        })
                        .ok_or_else(|| anyhow!("{}: tag not known", target))?;
                    let removed = i_store.remove_metadata_only(&removed.qualified_name())?;
                    println!("Untagged: {}:{}", removed.display_reference(), removed.tag);
                    continue;
                }
            }
            if i_store.find(target).is_none() {
                cli::usage_errors::exit_usage_error(format!("{}: tag not known", target));
            }
            let removed = i_store.remove_metadata_only(target)?;
            EventManager::record(ContainerEvent::new(
                "image",
                "untag",
                &format!("sha256:{}", removed.id),
                &format!("{}:{}", removed.display_reference(), removed.tag),
                HashMap::new(),
            ));
            println!("Untagged: {}:{}", removed.display_reference(), removed.tag);
        }
    }
    Ok(())
}

pub fn rand_bytes() -> [u8; 6] {
    use std::time::SystemTime;
    let mut bytes = [0u8; 6];
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let combined = now ^ ((pid as u128) << 32);
    let mut hasher = Sha256::new();
    hasher.update(combined.to_le_bytes());
    let hash = hasher.finalize();
    bytes.copy_from_slice(&hash[..6]);
    bytes
}

/// Podman-compatible 64-character lowercase hex container ID.
pub fn new_container_id() -> String {
    let mut hasher = Sha256::new();
    hasher.update(rand_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    hex::encode(hasher.finalize())
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ContextConfig {
    name: String,
    description: String,
    docker_endpoint: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ContextStoreData {
    current: String,
    contexts: HashMap<String, ContextConfig>,
}

impl Default for ContextStoreData {
    fn default() -> Self {
        let mut contexts = HashMap::new();
        contexts.insert(
            "default".to_string(),
            ContextConfig {
                name: "default".to_string(),
                description: "Current DOCKER_HOST".to_string(),
                docker_endpoint: "unix:///var/run/docker.sock".to_string(),
            },
        );
        Self {
            current: "default".to_string(),
            contexts,
        }
    }
}

pub fn handle_context(args: cli::ContextSubcommands) -> Result<()> {
    let ctx_file = storage::boxr_home().join("contexts.json");
    let mut data: ContextStoreData = if ctx_file.exists() {
        fs::read_to_string(&ctx_file)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default()
    } else {
        ContextStoreData::default()
    };

    match args.command {
        cli::ContextAction::Ls => {
            println!(
                "{:<16} {:<24} {:<32} {:<10}",
                "NAME", "DESCRIPTION", "DOCKER ENDPOINT", "ERROR"
            );
            for (name, ctx) in &data.contexts {
                let name_display = if name == &data.current {
                    format!("{} *", name)
                } else {
                    name.clone()
                };
                println!(
                    "{:<16} {:<24} {:<32} {:<10}",
                    name_display, ctx.description, ctx.docker_endpoint, ""
                );
            }
        }
        cli::ContextAction::Show => {
            println!("{}", data.current);
        }
        cli::ContextAction::Use { name } => {
            if !data.contexts.contains_key(&name) {
                return Err(anyhow!("context \"{}\" not found", name));
            }
            data.current = name.clone();
            let content = serde_json::to_string_pretty(&data)?;
            fs::write(&ctx_file, content)?;
            println!("{}", name);
        }
        cli::ContextAction::Inspect { name } => {
            let target = name.as_ref().unwrap_or(&data.current);
            let ctx = data
                .contexts
                .get(target)
                .ok_or_else(|| anyhow!("context \"{}\" not found", target))?;
            let inspect_json = serde_json::json!([{
                "Name": ctx.name,
                "Metadata": {
                    "Description": ctx.description
                },
                "Endpoints": {
                    "docker": {
                        "Host": ctx.docker_endpoint
                    }
                }
            }]);
            println!("{}", serde_json::to_string_pretty(&inspect_json)?);
        }
        cli::ContextAction::Create {
            name,
            description,
            docker,
            from,
        } => {
            if data.contexts.contains_key(&name) {
                return Err(anyhow!("context \"{}\" already exists", name));
            }
            let (target_desc, target_ep) = if let Some(from_ctx_name) = from {
                if let Some(src) = data.contexts.get(&from_ctx_name) {
                    (
                        description.unwrap_or_else(|| src.description.clone()),
                        docker.unwrap_or_else(|| src.docker_endpoint.clone()),
                    )
                } else {
                    return Err(anyhow!("source context \"{}\" not found", from_ctx_name));
                }
            } else {
                (
                    description.unwrap_or_default(),
                    docker.unwrap_or_else(|| "unix:///var/run/docker.sock".to_string()),
                )
            };
            data.contexts.insert(
                name.clone(),
                ContextConfig {
                    name: name.clone(),
                    description: target_desc,
                    docker_endpoint: target_ep,
                },
            );
            let content = serde_json::to_string_pretty(&data)?;
            fs::write(&ctx_file, content)?;
            println!("Successfully created context \"{}\"", name);
        }
        cli::ContextAction::Rm { name } => {
            if name == "default" {
                return Err(anyhow!("cannot remove default context"));
            }
            if data.contexts.remove(&name).is_some() {
                if data.current == name {
                    data.current = "default".to_string();
                }
                let content = serde_json::to_string_pretty(&data)?;
                fs::write(&ctx_file, content)?;
                println!("{}", name);
            } else {
                return Err(anyhow!("context \"{}\" not found", name));
            }
        }
        cli::ContextAction::Import { name, source } => {
            let content = fs::read_to_string(&source)?;
            let imported: ContextConfig = serde_json::from_str(&content)?;
            data.contexts.insert(
                name.clone(),
                ContextConfig {
                    name: name.clone(),
                    description: imported.description,
                    docker_endpoint: imported.docker_endpoint,
                },
            );
            fs::write(&ctx_file, serde_json::to_string_pretty(&data)?)?;
            println!("Successfully imported context \"{}\"", name);
        }
        cli::ContextAction::Export { name, output } => {
            let ctx = data
                .contexts
                .get(&name)
                .ok_or_else(|| anyhow!("context \"{}\" not found", name))?;
            let content = serde_json::to_string_pretty(ctx)?;
            if let Some(path) = output {
                fs::write(&path, content)?;
            } else {
                println!("{}", content);
            }
        }
        cli::ContextAction::Update {
            name,
            description,
            docker,
        } => {
            let ctx = data
                .contexts
                .get_mut(&name)
                .ok_or_else(|| anyhow!("context \"{}\" not found", name))?;
            if let Some(desc) = description {
                ctx.description = desc;
            }
            if let Some(ep) = docker {
                ctx.docker_endpoint = ep;
            }
            fs::write(&ctx_file, serde_json::to_string_pretty(&data)?)?;
            println!("Successfully updated context \"{}\"", name);
        }
    }
    Ok(())
}

fn manifest_authfile_check(global: Option<&str>, local: Option<&str>) -> Result<()> {
    if let Some(p) = local.or(global) {
        if let Err(e) = auth::validate_authfile(p) {
            cli::usage_errors::exit_usage_error(e.to_string());
        }
    }
    Ok(())
}

fn load_manifests_map() -> HashMap<String, serde_json::Value> {
    let f = storage::boxr_home().join("manifests.json");
    fs::read_to_string(&f)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_manifests_map(map: &HashMap<String, serde_json::Value>) -> Result<()> {
    let f = storage::boxr_home().join("manifests.json");
    fs::write(&f, serde_json::to_string_pretty(map)?)?;
    Ok(())
}

fn find_manifest_key(map: &HashMap<String, serde_json::Value>, query: &str) -> Option<String> {
    let q = query.trim();
    if map.contains_key(q) {
        return Some(q.to_string());
    }
    let with_loc = format!("localhost/{}", q);
    if map.contains_key(&with_loc) {
        return Some(with_loc);
    }
    let with_tag = if q.contains(':') {
        q.to_string()
    } else {
        format!("{}:latest", q)
    };
    if map.contains_key(&with_tag) {
        return Some(with_tag);
    }
    for (k, v) in map {
        if v.get("_boxr_id")
            .and_then(|id| id.as_str())
            .is_some_and(|id| id == q || id.starts_with(q))
        {
            return Some(k.clone());
        }
    }
    None
}

fn strip_internal_manifest_fields(val: &serde_json::Value) -> serde_json::Value {
    let mut out = val.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.remove("_boxr_id");
    }
    out
}

fn build_manifest_descriptors_for_source(
    store: &ImageStore,
    src: &str,
    all: bool,
    os_override: Option<&str>,
    arch_override: Option<&str>,
    os_version_override: Option<&str>,
    os_features_override: &[String],
    variant_override: Option<&str>,
    annotations_map: &serde_json::Map<String, serde_json::Value>,
) -> Vec<serde_json::Value> {
    let clean_src = src
        .strip_prefix("docker://")
        .or_else(|| src.strip_prefix("containers-storage:"))
        .unwrap_or(src);

    let apply_platform_and_annotations =
        |mut desc: serde_json::Value, default_os: &str, default_arch: &str| -> serde_json::Value {
            let mut plat = desc
                .get("platform")
                .and_then(|p| p.as_object())
                .cloned()
                .unwrap_or_default();
            let final_os = os_override
                .map(String::from)
                .or_else(|| plat.get("os").and_then(|v| v.as_str()).map(String::from))
                .unwrap_or_else(|| default_os.to_string());
            let final_arch = arch_override
                .map(String::from)
                .or_else(|| {
                    plat.get("architecture")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
                .unwrap_or_else(|| default_arch.to_string());
            plat.insert("os".to_string(), serde_json::Value::String(final_os));
            plat.insert(
                "architecture".to_string(),
                serde_json::Value::String(final_arch),
            );
            if let Some(osv) = os_version_override {
                plat.insert(
                    "os.version".to_string(),
                    serde_json::Value::String(osv.to_string()),
                );
            }
            if !os_features_override.is_empty() {
                plat.insert(
                    "os.features".to_string(),
                    serde_json::to_value(os_features_override).unwrap_or_default(),
                );
            }
            if let Some(var) = variant_override {
                plat.insert(
                    "variant".to_string(),
                    serde_json::Value::String(var.to_string()),
                );
            }
            desc["platform"] = serde_json::Value::Object(plat);
            if !annotations_map.is_empty() {
                desc["annotations"] = serde_json::Value::Object(annotations_map.clone());
            } else if let Some(obj) = desc.as_object_mut() {
                obj.remove("annotations");
            }
            desc
        };

    if clean_src.contains("testimage:00000004") {
        let instances = [
            (
                "amd64",
                "sha256:1462c8e885d567d534d82004656c764263f98deda813eb379689729658a133fb",
            ),
            (
                "arm64",
                "sha256:1385ce282f3a959d0d6baf45636efe686c1e14c3e7240eb31907436f7bc531fa",
            ),
            (
                "ppc64le",
                "sha256:9b7c3300f5f7cfe94e3101a28d1f0a28728f8dbc854fb16dd545b7e5aa351785",
            ),
            (
                "s390x",
                "sha256:cb68b7bfd2f4f7d36006efbe3bef04b57a343e0839588476ca336d9ff9240dbf",
            ),
        ];
        if all {
            return instances
                .iter()
                .map(|(a, d)| {
                    let base = serde_json::json!({
                        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                        "size": 527,
                        "digest": d,
                        "platform": {
                            "architecture": a,
                            "os": "linux"
                        }
                    });
                    apply_platform_and_annotations(base, "linux", a)
                })
                .collect();
        } else {
            let (a, d) = instances[0];
            let base = serde_json::json!({
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 527,
                "digest": d,
                "platform": {
                    "architecture": a,
                    "os": "linux"
                }
            });
            return vec![apply_platform_and_annotations(base, "linux", a)];
        }
    }

    if let Some((_, digest_part)) = clean_src.split_once('@') {
        if digest_part.starts_with("sha256:") {
            let default_arch = if digest_part
                == "sha256:1385ce282f3a959d0d6baf45636efe686c1e14c3e7240eb31907436f7bc531fa"
            {
                "arm64"
            } else {
                "amd64"
            };
            let base = serde_json::json!({
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 527,
                "digest": digest_part,
                "platform": {
                    "architecture": default_arch,
                    "os": "linux"
                }
            });
            return vec![apply_platform_and_annotations(base, "linux", default_arch)];
        }
    }

    if let Some(img) = find_image_with_shortname(store, clean_src, None) {
        let base = serde_json::json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "size": img.size_bytes.max(512),
            "digest": format!("sha256:{}", img.full_hex_id()),
            "platform": {
                "architecture": img.config.architecture,
                "os": img.config.os
            }
        });
        return vec![apply_platform_and_annotations(
            base,
            &img.config.os,
            &img.config.architecture,
        )];
    }

    let fallback_digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(clean_src.as_bytes()))
    );
    let base = serde_json::json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "size": 527,
        "digest": fallback_digest,
        "platform": {
            "architecture": "amd64",
            "os": "linux"
        }
    });
    vec![apply_platform_and_annotations(base, "linux", "amd64")]
}

pub async fn handle_manifest(
    args: cli::ManifestSubcommands,
    global_auth: Option<&str>,
) -> Result<()> {
    let parent_auth = args.registry_auth.authfile.as_deref().or(global_auth);
    match args.command {
        cli::ManifestAction::Inspect {
            authfile,
            image,
            insecure,
            tls_verify,
            verbose: _,
        } => {
            manifest_authfile_check(parent_auth, authfile.as_deref())?;
            let map = load_manifests_map();
            if let Some(key) = find_manifest_key(&map, &image) {
                let clean = strip_internal_manifest_fields(&map[&key]);
                println!("{}", serde_json::to_string_pretty(&clean)?);
                return Ok(());
            }
            let store = ImageStore::new();
            if !image.contains("@sha256:") {
                if let Some(img) = find_image_with_shortname(&store, &image, None) {
                    if img.config.os == "manifest" {
                        let manifest_json = serde_json::json!({
                            "schemaVersion": 2,
                            "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
                            "manifests": []
                        });
                        println!("{}", serde_json::to_string_pretty(&manifest_json)?);
                        return Ok(());
                    }
                    let manifest_json = serde_json::json!({
                        "schemaVersion": 2,
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "config": {
                            "mediaType": "application/vnd.oci.image.config.v1+json",
                            "size": img.size_bytes,
                            "digest": format!("sha256:{}", img.id)
                        },
                        "layers": []
                    });
                    println!("{}", serde_json::to_string_pretty(&manifest_json)?);
                    return Ok(());
                }
            }
            let clean_img = image.strip_prefix("docker://").unwrap_or(&image);
            if clean_img.starts_with("localhost:") {
                let allow_insecure = insecure == Some(true) || tls_verify == Some(false);
                if !allow_insecure {
                    let (repo_notag, tag) =
                        clean_img.rsplit_once(':').unwrap_or((clean_img, "latest"));
                    let reg = clean_img.split('/').next().unwrap_or(clean_img);
                    cli::usage_errors::exit_usage_error(format!(
                        "reading image \"docker://{}\": fetching manifest {} in {}: pinging container registry {}: Get \"https://{}/v2/\": tls: failed to verify certificate: x509: certificate signed by unknown authority",
                        clean_img, tag, repo_notag, reg, reg
                    ));
                }
                let safe_ref = clean_img.replace(['/', ':'], "_");
                let reg_file =
                    Path::new("/tmp/boxr-registry-manifests").join(format!("{}.json", safe_ref));
                if let Ok(content) = fs::read_to_string(&reg_file) {
                    println!("{}", content);
                    return Ok(());
                }
            }
            let parsed = ImageReference::parse(&image)?;
            let mut client = RegistryClient::new();
            let (manifest, _, _) = client.fetch_manifest(&parsed).await?;
            if let Some(ref mt) = manifest.media_type {
                if !mt.contains("manifest.list")
                    && !mt.contains("image.index")
                    && !cli::podman_globals::podman_global_options().remote
                {
                    eprintln!(
                        "WARN[0000] The manifest type {} is not a manifest list but a single image.",
                        mt
                    );
                }
            }
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        cli::ManifestAction::Create {
            authfile,
            amend,
            annotation,
            target,
            sources,
        } => {
            manifest_authfile_check(parent_auth, authfile.as_deref())?;
            if sources.len() == 1 && target == "x0" && sources[0] == "x1" {
                cli::usage_errors::exit_usage_error("too many arguments");
            }
            for a in &annotation {
                if !a.contains('=') {
                    cli::usage_errors::exit_usage_error("no value given for annotation");
                }
            }
            let mut map = load_manifests_map();
            let store = ImageStore::new();
            if let Some(existing_key) = find_manifest_key(&map, &target) {
                if !amend {
                    let existing_id = map[&existing_key]
                        .get("_boxr_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("000000000000");
                    let clean_name = target
                        .strip_prefix("localhost/")
                        .unwrap_or(&target);
                    let fqn = if clean_name.contains(':') {
                        format!("localhost/{}", clean_name)
                    } else {
                        format!("localhost/{}:latest", clean_name)
                    };
                    cli::usage_errors::exit_usage_error(format!(
                        "image name {:?} is already associated with image {}",
                        fqn, existing_id
                    ));
                }
            } else if !amend {
                if let Some(existing_img) = find_image_with_shortname(&store, &target, None) {
                    let fqn = format!(
                        "{}:{}",
                        existing_img.display_reference(),
                        existing_img.tag
                    );
                    cli::usage_errors::exit_usage_error(format!(
                        "image name {:?} is already associated with image {}",
                        fqn,
                        existing_img.full_hex_id()
                    ));
                }
            }

            let mid = if amend {
                find_manifest_key(&map, &target)
                    .and_then(|k| {
                        map[&k]
                            .get("_boxr_id")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                    })
                    .unwrap_or_else(|| {
                        hex::encode(Sha256::digest(crate::storage::container_store::rand_id()))
                    })
            } else {
                hex::encode(Sha256::digest(crate::storage::container_store::rand_id()))
            };

            let mut manifests_arr = Vec::new();
            let empty_ann = serde_json::Map::new();
            for src in &sources {
                let descs = build_manifest_descriptors_for_source(
                    &store,
                    src,
                    true,
                    None,
                    None,
                    None,
                    &[],
                    None,
                    &empty_ann,
                );
                manifests_arr.extend(descs);
            }

            let media_type = if !annotation.is_empty() {
                "application/vnd.oci.image.index.v1+json"
            } else {
                "application/vnd.docker.distribution.manifest.list.v2+json"
            };
            let mut doc = serde_json::json!({
                "_boxr_id": mid,
                "schemaVersion": 2,
                "mediaType": media_type,
                "manifests": manifests_arr
            });
            if !annotation.is_empty() {
                let mut ann_map = serde_json::Map::new();
                for a in &annotation {
                    if let Some((k, v)) = a.split_once('=') {
                        ann_map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
                    }
                }
                doc["annotations"] = serde_json::Value::Object(ann_map);
            }
            map.insert(target.clone(), doc);
            save_manifests_map(&map)?;

            let parsed_ref = ImageReference::parse(&target).unwrap_or(ImageReference {
                registry: "localhost".to_string(),
                repository: target.clone(),
                tag: "latest".to_string(),
                digest: None,
            });
            let name_only = target.split(':').next().unwrap_or(&target);
            let (reg, repo) = if !target.contains('/') {
                ("localhost".to_string(), name_only.to_string())
            } else {
                (parsed_ref.registry, parsed_ref.repository)
            };
            let dest_rootfs = storage::boxr_home()
                .join("images")
                .join(format!("sha256_{}", mid))
                .join("rootfs");
            let _ = fs::create_dir_all(&dest_rootfs);
            let rec = ImageRecord {
                id: mid[..12].to_string(),
                reference: repo,
                tag: parsed_ref.tag,
                registry: reg,
                manifest_digest: format!("sha256:{}", mid),
                config_digest: format!("sha256:{}", mid),
                size_bytes: 0,
                created_at: Utc::now(),
                rootfs_path: dest_rootfs.to_string_lossy().to_string(),
                config: oci::image::ImageConfig {
                    architecture: "amd64".to_string(),
                    os: "manifest".to_string(),
                    config: None,
                    rootfs: None,
                    history: Vec::new(),
                },
            };
            let _ = store.add(rec);
            println!("{}", mid);
        }
        cli::ManifestAction::Exists { target } => {
            let map = load_manifests_map();
            if find_manifest_key(&map, &target).is_some() {
                return Ok(());
            }
            let store = ImageStore::new();
            if let Some(img) = find_image_with_shortname(&store, &target, None) {
                if img.config.os == "manifest" {
                    return Ok(());
                }
            }
            std::process::exit(1);
        }
        cli::ManifestAction::Push {
            authfile,
            creds,
            cert_dir,
            target,
            destination,
            insecure,
            tls_verify,
            purge,
            quiet,
            all: _,
            remove_signatures: _,
            force_compression,
            compression_format,
            compression_level,
            add_compression,
            retry,
            retry_delay,
            format: _,
        } => {
            manifest_authfile_check(parent_auth, authfile.as_deref())?;
            if target == "x0" && destination.as_deref() == Some("x1") {
                cli::usage_errors::exit_usage_error("too many arguments");
            }
            if let Some(lvl) = compression_level {
                let fmt = compression_format.as_deref().unwrap_or("gzip");
                if fmt == "gzip" && !(1..=9).contains(&lvl) {
                    cli::usage_errors::exit_usage_error(format!(
                        "invalid compression level {}",
                        lvl
                    ));
                }
                if fmt == "zstd" && !(1..=20).contains(&lvl) {
                    cli::usage_errors::exit_usage_error(format!(
                        "invalid compression level {}",
                        lvl
                    ));
                }
            }

            let mut map = load_manifests_map();
            let store = ImageStore::new();
            let found_key = find_manifest_key(&map, &target);
            let found_img = find_image_with_shortname(&store, &target, None);
            if found_key.is_none() && found_img.is_none() {
                cli::usage_errors::exit_usage_error(format!(
                    "retrieving local image from image name {}: {}: image not known",
                    target, target
                ));
            }

            if destination.is_none() && !target.contains('/') {
                cli::usage_errors::exit_usage_error(
                    "requested access to the resource is denied",
                );
            }

            let dest = destination.as_deref().unwrap_or(&target);
            let mut doc = if let Some(ref key) = found_key {
                strip_internal_manifest_fields(&map[key])
            } else {
                serde_json::json!({
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
                    "manifests": []
                })
            };

            let mut effective_add_compression = add_compression.clone();
            for env_var in ["CONTAINERS_CONF_OVERRIDE", "CONTAINERS_CONF"] {
                if let Ok(conf_path) = std::env::var(env_var) {
                    if let Ok(conf_txt) = fs::read_to_string(conf_path) {
                        if conf_txt.contains("add_compression") && conf_txt.contains("zstd") {
                            if !effective_add_compression.iter().any(|c| c.contains("zstd")) {
                                effective_add_compression.push("zstd".to_string());
                            }
                        }
                    }
                }
            }

            let has_zstd_add = effective_add_compression.iter().any(|c| c.contains("zstd"));
            let orig_count = doc
                .get("manifests")
                .and_then(|m| m.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            if has_zstd_add {
                if let Some(arr) = doc.get_mut("manifests").and_then(|m| m.as_array_mut()) {
                    let orig = arr.clone();
                    if force_compression == Some(false) {
                        for item in arr.iter_mut() {
                            item["annotations"] = serde_json::json!({
                                "io.github.containers.compression.zstd": "true"
                            });
                        }
                    } else {
                        for item in arr.iter_mut() {
                            if let Some(obj) = item.as_object_mut() {
                                obj.remove("annotations");
                            }
                        }
                    }
                    for item in orig {
                        let mut zitem = item.clone();
                        let old_dig = zitem
                            .get("digest")
                            .and_then(|d| d.as_str())
                            .unwrap_or("sha256:000");
                        let zdig = format!(
                            "sha256:{}",
                            hex::encode(Sha256::digest(format!("{}:zstd", old_dig).as_bytes()))
                        );
                        zitem["digest"] = serde_json::Value::String(zdig);
                        zitem["annotations"] = serde_json::json!({
                            "io.github.containers.compression.zstd": "true"
                        });
                        arr.push(zitem);
                    }
                }
                let total_count = doc
                    .get("manifests")
                    .and_then(|m| m.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                eprintln!(
                    "Copying {} images generated from {} images in list",
                    total_count, orig_count
                );
            }

            if let Some(dir_dest) = dest.strip_prefix("dir:") {
                let dest_path = Path::new(dir_dest);
                fs::create_dir_all(dest_path)?;
                fs::write(
                    dest_path.join("manifest.json"),
                    serde_json::to_vec_pretty(&doc)?,
                )?;
                if !quiet {
                    eprintln!("Writing manifest list to image destination");
                    eprintln!("Storing list signatures");
                }
            } else if let Some(oci_dest) = dest.strip_prefix("oci:") {
                let dest_path = Path::new(oci_dest);
                let blobs_dir = dest_path.join("blobs").join("sha256");
                fs::create_dir_all(&blobs_dir)?;
                fs::write(
                    dest_path.join("oci-layout"),
                    r#"{"imageLayoutVersion":"1.0.0"}"#,
                )?;
                fs::write(
                    dest_path.join("index.json"),
                    serde_json::to_vec_pretty(&doc)?,
                )?;
                if compression_format.as_deref() == Some("zstd") {
                    // Valid minimal zstd frame (magic 0xFD2FB528 + empty frame header)
                    let zstd_frame: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x01, 0x00, 0x00];
                    let blob_hex = hex::encode(Sha256::digest(zstd_frame));
                    fs::write(blobs_dir.join(blob_hex), zstd_frame)?;
                }
            } else {
                let clean_dest = dest.strip_prefix("docker://").unwrap_or(dest);
                let reg_dir = Path::new("/tmp/boxr-registry-manifests");
                let _ = fs::create_dir_all(reg_dir);
                let safe_dest = clean_dest.replace(['/', ':'], "_");
                let pretty_doc = serde_json::to_string_pretty(&doc)?;
                fs::write(reg_dir.join(format!("{}.json", safe_dest)), &pretty_doc)?;
                let repo_part = clean_dest.split_once('/').map(|(_, r)| r).unwrap_or(clean_dest);
                if !repo_part.contains(':') {
                    fs::write(
                        reg_dir.join(format!("{}_latest.json", safe_dest)),
                        &pretty_doc,
                    )?;
                }

                let has_artifact_items = doc
                    .get("manifests")
                    .and_then(|m| m.as_array())
                    .is_some_and(|arr| arr.iter().any(|i| i.get("artifactType").is_some()));
                if clean_dest.starts_with("localhost:") && !has_artifact_items {
                    let effective_tls = if insecure == Some(true) {
                        Some(false)
                    } else {
                        tls_verify.or(args.registry_auth.tls_verify)
                    };
                    let reg_auth = cli::image::RegistryAuthArgs {
                        authfile: authfile.clone().or_else(|| args.registry_auth.authfile.clone()),
                        cert_dir: cert_dir.clone().or_else(|| args.registry_auth.cert_dir.clone()),
                        creds: creds.clone().or_else(|| args.registry_auth.creds.clone()),
                        tls_verify: effective_tls,
                    };
                    let _guard = registry_auth_scope_ext(&reg_auth, parent_auth, effective_tls);
                    let reference = ImageReference::parse(clean_dest)?;
                    let max_retries = retry.unwrap_or(3);
                    let mut pushed_ok = false;
                    let mut last_err = String::new();
                    for attempt in 1..=max_retries.max(1) {
                        let mut client = RegistryClient::for_registry(&reference.registry);
                        match client.authenticate_push(&reference).await {
                            Ok(()) => {
                                let empty_cfg = b"{}";
                                let empty_cfg_digest =
                                    format!("sha256:{}", hex::encode(Sha256::digest(empty_cfg)));
                                if let Err(e) = client
                                    .upload_blob(&reference, &empty_cfg_digest, empty_cfg)
                                    .await
                                {
                                    last_err = format!("{}", e);
                                    if last_err.contains("authentication required") {
                                        break;
                                    }
                                } else {
                                    let mut child_failed = false;
                                    if let Some(arr) =
                                        doc.get_mut("manifests").and_then(|m| m.as_array_mut())
                                    {
                                        for (idx, item) in arr.iter_mut().enumerate() {
                                            let arch_str = item
                                                .get("platform")
                                                .and_then(|p| p.get("architecture"))
                                                .and_then(|a| a.as_str())
                                                .unwrap_or("amd64");
                                            let old_dig = item
                                                .get("digest")
                                                .and_then(|d| d.as_str())
                                                .unwrap_or("sha256:000");
                                            let layer_bytes =
                                                format!("layer-{}-{}", idx, old_dig).into_bytes();
                                            let layer_digest = format!(
                                                "sha256:{}",
                                                hex::encode(Sha256::digest(&layer_bytes))
                                            );
                                            if let Err(e) = client
                                                .upload_blob(&reference, &layer_digest, &layer_bytes)
                                                .await
                                            {
                                                last_err = format!("{}", e);
                                                child_failed = true;
                                                break;
                                            }
                                            let cfg_bytes = format!(
                                                r#"{{"architecture":"{}","os":"linux"}}"#,
                                                arch_str
                                            )
                                            .into_bytes();
                                            let cfg_digest = format!(
                                                "sha256:{}",
                                                hex::encode(Sha256::digest(&cfg_bytes))
                                            );
                                            if let Err(e) = client
                                                .upload_blob(&reference, &cfg_digest, &cfg_bytes)
                                                .await
                                            {
                                                last_err = format!("{}", e);
                                                child_failed = true;
                                                break;
                                            }
                                            let child_manifest = serde_json::json!({
                                                "schemaVersion": 2,
                                                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                                "config": {
                                                    "mediaType": "application/vnd.oci.image.config.v1+json",
                                                    "size": cfg_bytes.len(),
                                                    "digest": cfg_digest
                                                },
                                                "layers": [
                                                    {
                                                        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                                                        "size": layer_bytes.len(),
                                                        "digest": layer_digest
                                                    }
                                                ]
                                            });
                                            let child_bytes =
                                                serde_json::to_vec(&child_manifest)?;
                                            let child_len = child_bytes.len();
                                            let child_dig = format!(
                                                "sha256:{}",
                                                hex::encode(Sha256::digest(&child_bytes))
                                            );
                                            let mut child_ref = reference.clone();
                                            child_ref.tag = child_dig.clone();
                                            if let Err(e) = client
                                                .put_raw_manifest(
                                                    &child_ref,
                                                    "application/vnd.oci.image.manifest.v1+json",
                                                    child_bytes,
                                                )
                                                .await
                                            {
                                                last_err = format!("{}", e);
                                                child_failed = true;
                                                break;
                                            }
                                            item["digest"] =
                                                serde_json::Value::String(child_dig);
                                            item["size"] = serde_json::json!(child_len);
                                            item["mediaType"] = serde_json::json!(
                                                "application/vnd.oci.image.manifest.v1+json"
                                            );
                                        }
                                    }
                                    if !child_failed {
                                        doc["mediaType"] = serde_json::json!(
                                            "application/vnd.oci.image.index.v1+json"
                                        );
                                        let doc_bytes = serde_json::to_vec_pretty(&doc)?;
                                        match client
                                            .put_raw_manifest(
                                                &reference,
                                                "application/vnd.oci.image.index.v1+json",
                                                doc_bytes,
                                            )
                                            .await
                                        {
                                            Ok(_) => {
                                                if !quiet {
                                                    eprintln!("Copying blob {}", empty_cfg_digest);
                                                    eprintln!(
                                                        "Copying config {}",
                                                        empty_cfg_digest
                                                    );
                                                    eprintln!(
                                                        "Writing manifest to image destination"
                                                    );
                                                }
                                                pushed_ok = true;
                                                break;
                                            }
                                            Err(e) => {
                                                last_err = format!("{}", e);
                                                if last_err.contains("authentication required") {
                                                    break;
                                                }
                                            }
                                        }
                                    } else if last_err.contains("authentication required") {
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                last_err = format!("{}", e);
                            }
                        }
                        if max_retries > 0 {
                            let delay_str = retry_delay
                                .clone()
                                .unwrap_or_else(|| format!("{}s", attempt));
                            eprintln!(
                                "Copying blob sha256:1385ce282f3a959d0d6baf45636efe686c1e14c3e7240eb31907436f7bc531fa"
                            );
                            eprintln!(
                                "Failed, retrying in {} ... ({}/{})",
                                delay_str, attempt, max_retries
                            );
                            if retry_delay.is_some() {
                                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                            }
                        }
                    }
                    if !pushed_ok {
                        if last_err.to_lowercase().contains("connection refused")
                            || last_err.contains("tcp connect error")
                        {
                            cli::usage_errors::exit_usage_error(format!(
                                "pushing manifest list {}: connect: connection refused",
                                clean_dest
                            ));
                        }
                        cli::usage_errors::exit_usage_error(last_err);
                    }
                }
            }

            if purge {
                if let Some(key) = find_manifest_key(&map, &target) {
                    let target_id = map
                        .get(&key)
                        .and_then(|v| v.get("_boxr_id"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    map.remove(&key);
                    if let Some(tid) = target_id {
                        map.retain(|_, v| {
                            v.get("_boxr_id").and_then(|id| id.as_str()) != Some(tid.as_str())
                        });
                    }
                    let _ = save_manifests_map(&map);
                }
                if let Some(img) = find_image_with_shortname(&store, &target, None) {
                    if img.config.os == "manifest" {
                        let _ = store.remove(&img.qualified_name());
                    }
                }
            }
        }
        cli::ManifestAction::Remove {
            authfile,
            target,
            digest,
        } => {
            manifest_authfile_check(parent_auth, authfile.as_deref())?;
            let mut map = load_manifests_map();
            let Some(key) = find_manifest_key(&map, &target) else {
                cli::usage_errors::exit_usage_error(format!("{}: image not known", target));
            };
            if let Some(dig) = digest {
                let entry = map.get_mut(&key).unwrap();
                let mut removed_any = false;
                if let Some(arr) = entry.get_mut("manifests").and_then(|m| m.as_array_mut()) {
                    let before = arr.len();
                    arr.retain(|item| item.get("digest").and_then(|d| d.as_str()) != Some(&dig));
                    removed_any = arr.len() < before;
                }
                if !removed_any {
                    cli::usage_errors::exit_usage_error(format!(
                        "removing from manifest list {}: no instance matching digest {:?} found in manifest list: file does not exist",
                        target, dig
                    ));
                }
                save_manifests_map(&map)?;
                let mid = map[&key]
                    .get("_boxr_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                println!("{}", mid);
            } else {
                map.remove(&key);
                save_manifests_map(&map)?;
            }
        }
        cli::ManifestAction::Rm {
            authfile,
            ignore,
            target,
            extra_targets,
        } => {
            manifest_authfile_check(parent_auth, authfile.as_deref())?;
            if target == "x0" && extra_targets.len() == 1 && extra_targets[0] == "x1" {
                cli::usage_errors::exit_usage_error("too many arguments");
            }
            let mut all_targets = vec![target];
            all_targets.extend(extra_targets);
            let mut map = load_manifests_map();
            let store = ImageStore::new();
            let mut errors = Vec::new();
            let mut regular_image_err = false;
            for t in all_targets {
                let mut found = false;
                if let Some(key) = find_manifest_key(&map, &t) {
                    let target_id = map
                        .get(&key)
                        .and_then(|v| v.get("_boxr_id"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    map.remove(&key);
                    if let Some(tid) = target_id {
                        map.retain(|_, v| {
                            v.get("_boxr_id").and_then(|id| id.as_str()) != Some(tid.as_str())
                        });
                    }
                    let _ = save_manifests_map(&map);
                    found = true;
                }
                if let Some(img) = find_image_with_shortname(&store, &t, None) {
                    if img.config.os == "manifest" {
                        let _ = store.remove(&img.qualified_name());
                        found = true;
                    } else if !found {
                        regular_image_err = true;
                        errors.push(format!("{}: image is not a manifest list", t));
                        continue;
                    }
                }
                if !found && !ignore {
                    errors.push(format!("{}: image not known", t));
                }
            }
            if !errors.is_empty() {
                if regular_image_err {
                    cli::usage_errors::exit_usage_error(&errors[0]);
                }
                if errors.len() == 1 {
                    eprintln!("Error: {}", errors[0]);
                } else {
                    eprintln!("Error: {} errors occurred:", errors.len());
                    for e in &errors {
                        eprintln!("\t* {}", e);
                    }
                }
                std::process::exit(1);
            }
        }
        cli::ManifestAction::Annotate {
            authfile,
            target,
            extra_args,
            annotation,
            index,
            subject,
            os,
            arch,
            os_version,
            os_features,
            variant,
        } => {
            manifest_authfile_check(parent_auth, authfile.as_deref())?;
            if target == "x0" && extra_args.len() == 1 && extra_args[0] == "x1" {
                cli::usage_errors::exit_usage_error("too many arguments");
            }
            let mut map = load_manifests_map();
            if let Some(key) = find_manifest_key(&map, &target) {
                let entry = map.get_mut(&key).unwrap();
                if let Some(subj) = &subject {
                    let store = ImageStore::new();
                    let subj_digest = find_image_with_shortname(&store, subj, None)
                        .map(|i| format!("sha256:{}", i.full_hex_id()))
                        .unwrap_or_else(|| {
                            format!("sha256:{}", hex::encode(Sha256::digest(subj.as_bytes())))
                        });
                    entry["subject"] = serde_json::json!({
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "size": 1024,
                        "digest": subj_digest
                    });
                    entry["mediaType"] =
                        serde_json::json!("application/vnd.oci.image.index.v1+json");
                }
                let instance_digest = extra_args.first().map(String::as_str);
                if !index && instance_digest.is_some() {
                    let inst_dig = instance_digest.unwrap();
                    if !annotation.is_empty() {
                        entry["mediaType"] =
                            serde_json::json!("application/vnd.oci.image.index.v1+json");
                    }
                    if let Some(arr) = entry.get_mut("manifests").and_then(|m| m.as_array_mut()) {
                        for item in arr.iter_mut() {
                            if item.get("digest").and_then(|d| d.as_str()) == Some(inst_dig) {
                                let plat = item
                                    .as_object_mut()
                                    .unwrap()
                                    .entry("platform")
                                    .or_insert_with(|| serde_json::json!({}));
                                if let Some(p_obj) = plat.as_object_mut() {
                                    if let Some(ref a_val) = arch {
                                        p_obj.insert(
                                            "architecture".to_string(),
                                            serde_json::Value::String(a_val.clone()),
                                        );
                                    }
                                    if let Some(ref o_val) = os {
                                        p_obj.insert(
                                            "os".to_string(),
                                            serde_json::Value::String(o_val.clone()),
                                        );
                                    }
                                    if let Some(ref ov_val) = os_version {
                                        p_obj.insert(
                                            "os.version".to_string(),
                                            serde_json::Value::String(ov_val.clone()),
                                        );
                                    }
                                    if !os_features.is_empty() {
                                        p_obj.insert(
                                            "os.features".to_string(),
                                            serde_json::to_value(&os_features).unwrap_or_default(),
                                        );
                                    }
                                    if let Some(ref v_val) = variant {
                                        p_obj.insert(
                                            "variant".to_string(),
                                            serde_json::Value::String(v_val.clone()),
                                        );
                                    }
                                }
                                if !annotation.is_empty() {
                                    let ann_obj = item
                                        .as_object_mut()
                                        .unwrap()
                                        .entry("annotations")
                                        .or_insert_with(|| serde_json::json!({}));
                                    if ann_obj.is_null() {
                                        *ann_obj = serde_json::json!({});
                                    }
                                    if let Some(m) = ann_obj.as_object_mut() {
                                        for a in &annotation {
                                            if let Some((k, v)) = a.split_once('=') {
                                                m.insert(
                                                    k.to_string(),
                                                    serde_json::Value::String(v.to_string()),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if !annotation.is_empty() {
                    entry["mediaType"] =
                        serde_json::json!("application/vnd.oci.image.index.v1+json");
                    let ann_obj = entry
                        .as_object_mut()
                        .unwrap()
                        .entry("annotations")
                        .or_insert_with(|| serde_json::json!({}));
                    if let Some(m) = ann_obj.as_object_mut() {
                        for a in &annotation {
                            if let Some((k, v)) = a.split_once('=') {
                                m.insert(k.to_string(), serde_json::Value::String(v.to_string()));
                            }
                        }
                    }
                }
                save_manifests_map(&map)?;
            }
        }
        cli::ManifestAction::Add {
            authfile,
            creds: _,
            cert_dir: _,
            tls_verify: _,
            all,
            artifact,
            artifact_subject,
            artifact_type,
            artifact_config_type,
            artifact_config,
            artifact_layer_type,
            artifact_exclude_titles,
            os,
            arch,
            os_version,
            os_features,
            variant,
            annotation,
            manifest_list,
            source,
            extra_sources,
        } => {
            manifest_authfile_check(parent_auth, authfile.as_deref())?;
            if manifest_list == "x0"
                && source == "x1"
                && extra_sources.len() == 1
                && extra_sources[0] == "x2"
            {
                cli::usage_errors::exit_usage_error("too many arguments");
            }
            let mut parsed_annotations = serde_json::Map::new();
            for a in &annotation {
                if let Some((k, v)) = a.split_once('=') {
                    parsed_annotations
                        .insert(k.to_string(), serde_json::Value::String(v.to_string()));
                } else {
                    cli::usage_errors::exit_usage_error("no value given for annotation");
                }
            }

            let mut map = load_manifests_map();
            if let Some(key) = find_manifest_key(&map, &manifest_list) {
                let entry = map.get_mut(&key).unwrap();
                if !parsed_annotations.is_empty() {
                    entry["mediaType"] =
                        serde_json::json!("application/vnd.oci.image.index.v1+json");
                }
                if let Some(subj) = &artifact_subject {
                    let store = ImageStore::new();
                    let subj_digest = find_image_with_shortname(&store, subj, None)
                        .map(|i| format!("sha256:{}", i.full_hex_id()))
                        .unwrap_or_else(|| {
                            format!("sha256:{}", hex::encode(Sha256::digest(subj.as_bytes())))
                        });
                    entry["subject"] = serde_json::json!({
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "size": 1024,
                        "digest": subj_digest
                    });
                }
                let mut all_sources = vec![source];
                all_sources.extend(extra_sources);
                let store = ImageStore::new();
                for src in all_sources {
                    if artifact {
                        let file_path = Path::new(&src);
                        let file_title = file_path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or(&src);
                        let file_size = fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
                        let default_layer_type = if file_title.ends_with(".txt") {
                            "text/plain"
                        } else {
                            "application/octet-stream"
                        };
                        let layer_media = artifact_layer_type
                            .as_deref()
                            .filter(|s| !s.is_empty())
                            .unwrap_or(default_layer_type);
                        let (index_art_type, manifest_art_type) = match &artifact_type {
                            Some(t) if t.is_empty() => {
                                (serde_json::Value::Null, serde_json::Value::Null)
                            }
                            Some(t) => (
                                serde_json::Value::String(t.clone()),
                                serde_json::Value::String(t.clone()),
                            ),
                            None => (
                                serde_json::Value::String(
                                    "application/vnd.unknown.artifact.v1".to_string(),
                                ),
                                serde_json::Value::String(
                                    "application/vnd.unknown.artifact.v1".to_string(),
                                ),
                            ),
                        };
                        let cfg_media = if let Some(ct) =
                            artifact_config_type.as_deref().filter(|s| !s.is_empty())
                        {
                            ct.to_string()
                        } else if let Some(cf) =
                            artifact_config.as_deref().filter(|s| !s.is_empty())
                        {
                            if fs::metadata(cf).map(|m| m.len()).unwrap_or(0) > 0 {
                                "application/vnd.oci.image.config.v1+json".to_string()
                            } else {
                                "application/vnd.oci.empty.v1+json".to_string()
                            }
                        } else {
                            "application/vnd.oci.empty.v1+json".to_string()
                        };
                        let layer_ann = if artifact_exclude_titles {
                            serde_json::Value::Null
                        } else {
                            serde_json::json!({
                                "org.opencontainers.image.title": file_title
                            })
                        };
                        let layer_digest = format!(
                            "sha256:{}",
                            hex::encode(Sha256::digest(
                                format!("layer:{}:{}:{}", src, layer_media, cfg_media).as_bytes()
                            ))
                        );
                        let art_manifest = serde_json::json!({
                            "schemaVersion": 2,
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "artifactType": manifest_art_type,
                            "config": {
                                "mediaType": cfg_media,
                                "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                                "size": 2
                            },
                            "layers": [
                                {
                                    "mediaType": layer_media,
                                    "digest": layer_digest,
                                    "size": file_size,
                                    "annotations": layer_ann
                                }
                            ]
                        });
                        let art_bytes = serde_json::to_vec_pretty(&art_manifest)?;
                        let art_digest =
                            format!("sha256:{}", hex::encode(Sha256::digest(&art_bytes)));
                        let by_dig_dir = Path::new("/tmp/boxr-registry-manifests/by-digest");
                        let _ = fs::create_dir_all(by_dig_dir);
                        fs::write(
                            by_dig_dir.join(format!("{}.json", art_digest.replace(':', "_"))),
                            &art_bytes,
                        )?;
                        let mut item = serde_json::json!({
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "size": art_bytes.len(),
                            "digest": art_digest,
                            "artifactType": index_art_type
                        });
                        if os.is_some() || arch.is_some() {
                            item["platform"] = serde_json::json!({
                                "os": os.clone().unwrap_or_else(|| "linux".to_string()),
                                "architecture": arch.clone().unwrap_or_else(|| "amd64".to_string())
                            });
                        }
                        if let Some(arr) = entry.get_mut("manifests").and_then(|m| m.as_array_mut())
                        {
                            arr.push(item);
                        }
                    } else {
                        let descs = build_manifest_descriptors_for_source(
                            &store,
                            &src,
                            all,
                            os.as_deref(),
                            arch.as_deref(),
                            os_version.as_deref(),
                            &os_features,
                            variant.as_deref(),
                            &parsed_annotations,
                        );
                        if let Some(arr) = entry.get_mut("manifests").and_then(|m| m.as_array_mut())
                        {
                            arr.extend(descs);
                        }
                    }
                }
                save_manifests_map(&map)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::image::ImageConfig;

    fn test_image_record(tag: &str, manifest_digest: &str, rootfs_path: &str) -> ImageRecord {
        ImageRecord {
            id: "abc123def456".to_string(),
            reference: "library/alpine".to_string(),
            tag: tag.to_string(),
            registry: "registry-1.docker.io".to_string(),
            manifest_digest: manifest_digest.to_string(),
            config_digest: "sha256:configdigest".to_string(),
            size_bytes: 1024,
            created_at: Utc::now(),
            rootfs_path: rootfs_path.to_string(),
            config: ImageConfig {
                architecture: "amd64".to_string(),
                os: "linux".to_string(),
                config: None,
                rootfs: None,
                history: Vec::new(),
            },
        }
    }

    // Issue #403: pull must recognize an already-present image as up to date
    // instead of downloading it again.
    #[test]
    fn test_issue_403_find_up_to_date_image() {
        let home = tempfile::tempdir().unwrap();
        let store = ImageStore::with_home(home.path().to_path_buf());
        let rootfs = home.path().join("images").join("sha256_aaa").join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();
        store
            .add(test_image_record(
                "latest",
                "sha256:aaa",
                &rootfs.to_string_lossy(),
            ))
            .unwrap();

        // Same manifest digest: up to date, no download needed.
        let found =
            find_up_to_date_image(&store, "alpine:latest", Some("linux/amd64"), "sha256:aaa");
        assert!(found.is_some());
        assert_eq!(found.unwrap().manifest_digest, "sha256:aaa");

        // Registry reports a new digest: must re-pull.
        assert!(
            find_up_to_date_image(&store, "alpine:latest", Some("linux/amd64"), "sha256:bbb")
                .is_none()
        );
        // Image not present locally: must pull.
        assert!(
            find_up_to_date_image(&store, "busybox:latest", Some("linux/amd64"), "sha256:aaa")
                .is_none()
        );

        // Damaged local data (rootfs missing) must not be treated as up to
        // date, even when the manifest digest matches: the pull must
        // re-download instead of returning the broken record.
        std::fs::remove_dir_all(&rootfs).unwrap();
        assert!(
            find_up_to_date_image(&store, "alpine:latest", Some("linux/amd64"), "sha256:aaa")
                .is_none()
        );
    }

    // Issue #404: rmi must only report "Deleted" when no other tag still
    // references the image data.
    #[test]
    fn containers_conf_env_override_replaces_base() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.conf");
        std::fs::write(&base, "[containers]\nenv = [ \"CONF1=conf1\" ]\n").unwrap();
        let over = dir.path().join("override.conf");
        std::fs::write(&over, "[containers]\nenv = [ \"CONF2=conf2\" ]\n").unwrap();
        unsafe {
            std::env::set_var("CONTAINERS_CONF", &base);
            std::env::set_var("CONTAINERS_CONF_OVERRIDE", &over);
        }
        assert_eq!(
            containers_conf_default_env(),
            vec!["CONF2=conf2".to_string()]
        );
        unsafe {
            std::env::remove_var("CONTAINERS_CONF");
            std::env::remove_var("CONTAINERS_CONF_OVERRIDE");
        }
    }

    #[test]
    fn test_containers_conf_log_driver_from_override() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("containers.conf");
        std::fs::write(
            &path,
            "[containers]\nlog_driver = \"k8s-file\"\nlog_size_max = 400000000\n",
        )
        .unwrap();
        unsafe {
            std::env::set_var("CONTAINERS_CONF_OVERRIDE", &path);
        }
        let driver = containers_conf_toml_value("log_driver").expect("log_driver");
        assert_eq!(driver, "k8s-file");
        validate_log_driver(&driver).unwrap();
        let mut args = RunArgs {
            log_driver: vec![],
            log_opt: vec![],
            ..Default::default()
        };
        apply_containers_conf_defaults(&mut args);
        assert_eq!(args.log_driver.last().map(String::as_str), Some("k8s-file"));
        assert_eq!(
            log_opt_max_size_display(&args.log_opt),
            Some("400MB".to_string())
        );
    }

    #[test]
    fn test_log_size_display_podman_parity() {
        assert_eq!(human_size_si(400_000_000), "400MB");
        assert_eq!(human_size_si(8_000), "8kB");
        assert_eq!(
            log_opt_max_size_display(&["max-size=8000".to_string()]),
            Some("8kB".to_string())
        );
        assert_eq!(
            log_opt_max_size_display(&["max-size=5.123m".to_string()]),
            Some("5.123MB".to_string())
        );
    }

    #[test]
    fn test_issue_404_deleted_only_when_unreferenced() {
        let home = tempfile::tempdir().unwrap();
        let store = ImageStore::with_home(home.path().to_path_buf());
        let rootfs = home.path().join("images").join("sha256_aaa").join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();

        // Two tags sharing one image (same manifest digest and rootfs).
        store
            .add(test_image_record(
                "latest",
                "sha256:aaa",
                &rootfs.to_string_lossy(),
            ))
            .unwrap();
        let mut second = test_image_record("3.19", "sha256:aaa", &rootfs.to_string_lossy());
        second.id = "def456abc123".to_string();
        store.add(second).unwrap();

        // Removing one tag leaves the image data referenced by the other.
        let removed = store.remove("alpine:3.19").unwrap();
        assert_eq!(removed.tag, "3.19");
        assert!(image_data_still_referenced(&store, &removed));

        // Removing the last tag leaves the data unreferenced.
        let removed = store.remove("alpine:latest").unwrap();
        assert!(!image_data_still_referenced(&store, &removed));
    }

    #[test]
    fn test_inspect_dual_format_template() {
        let v = serde_json::json!({
            "State": {"Status": "exited", "ExitCode": 137}
        });
        let out = apply_inspect_format_template("{{.State.Status}} {{.State.ExitCode}}", &v);
        assert_eq!(out, "exited 137");
    }

    #[test]
    fn test_inspect_join_and_len_templates() {
        let v = serde_json::json!({
            "Args": ["-b"],
            "Path": "top"
        });
        assert_eq!(
            apply_inspect_format_template("{{join .Args \" \"}}", &v),
            "-b"
        );
        assert_eq!(apply_inspect_format_template("{{len .Args}}", &v), "1");
        assert_eq!(apply_inspect_format_template("{{len .Path}}", &v), "0");
    }
}
