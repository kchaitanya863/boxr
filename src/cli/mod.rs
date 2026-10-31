pub mod artifact;
pub mod container;
pub mod farm;
pub mod image;
pub mod image_ops;
pub mod info_report;
pub mod kube;
pub mod log_level;
pub mod machine;
pub mod manifest;
pub mod podman_globals;
pub mod quadlet;
pub mod secret;
pub mod system;
pub mod trust;
pub mod usage_errors;
pub mod volumes_networks;

pub use artifact::*;
pub use container::*;
pub use farm::*;
pub use image::*;
pub use image_ops::*;
pub use kube::*;
pub use machine::*;
pub use manifest::*;
pub use quadlet::*;
pub use secret::*;
pub use system::*;
pub use trust::*;
pub use volumes_networks::*;

use clap::{Args, Parser, Subcommand};
use std::sync::OnceLock;

/// When argv contains `--rm=false`, clap would otherwise treat `--rm` as a boolean flag.
pub static RUN_RM_EXPLICIT_FALSE: OnceLock<bool> = OnceLock::new();
pub static RUN_TTY_EXPLICIT_FALSE: OnceLock<bool> = OnceLock::new();
/// Set when argv uses `-v` (Podman short version line).
pub static VERSION_SHORT_OUTPUT: OnceLock<bool> = OnceLock::new();

/// Podman `run --read-only=false` (clap `SetTrue` cannot represent this).
pub static READ_ONLY_EXPLICIT_FALSE: OnceLock<bool> = OnceLock::new();

/// Podman `pod create --infra=false` (clap `SetTrue` cannot represent this).
pub static POD_INFRA_EXPLICIT_FALSE: OnceLock<bool> = OnceLock::new();

/// Podman `run --http-proxy=false` (accepted for e2e; boxr does not inject proxy env).
pub static HTTP_PROXY_EXPLICIT_FALSE: OnceLock<bool> = OnceLock::new();

/// Podman `run/create --no-hosts`
pub static RUN_NO_HOSTS: OnceLock<bool> = OnceLock::new();

/// Podman `run/create --env-host`
pub static RUN_ENV_HOST: OnceLock<bool> = OnceLock::new();

/// Podman `create/pull --arch` or `--os`
pub static CLI_ARCH_OR_OS_SET: OnceLock<bool> = OnceLock::new();

/// Podman `--config` global directory for docker config.json
pub static DOCKER_CONFIG_DIR: OnceLock<String> = OnceLock::new();

/// Podman `--default-mounts-file` global option
pub static GLOBAL_DEFAULT_MOUNTS_FILE: OnceLock<String> = OnceLock::new();

/// Podman `--runtime` global option
pub static GLOBAL_RUNTIME: OnceLock<String> = OnceLock::new();

/// Extra `-f` / `--file` values when multiple `-f` flags are passed to `build`
pub static BUILD_EXTRA_FILES: OnceLock<Vec<String>> = OnceLock::new();

/// Strip `--rm=false` before clap parsing (Podman accepts `run --rmi --rm=false`).
/// Podman global flags that take a value; stripped before clap (e2e / storage init).
/// Expand Podman/Docker combined short options (e.g. `run -td` → `-t` `-d`).
fn expand_combined_short_flags(arg: &str) -> Vec<String> {
    if arg.len() < 3 || !arg.starts_with('-') || arg.starts_with("--") {
        return vec![arg.to_string()];
    }
    let body = &arg[1..];
    if body.contains('=') {
        return vec![arg.to_string()];
    }
    const RUN_EXEC_FLAGS: &[char] = &['a', 'd', 'i', 'q', 't'];
    if body.len() > 1 && body.chars().all(|c| RUN_EXEC_FLAGS.contains(&c)) {
        return body.chars().map(|c| format!("-{}", c)).collect();
    }
    const BULK_RM_FLAGS: &[char] = &['a', 'f', 't', 'v'];
    if body.len() > 1 && body.chars().all(|c| BULK_RM_FLAGS.contains(&c)) {
        return body.chars().map(|c| format!("-{}", c)).collect();
    }
    vec![arg.to_string()]
}

const PODMAN_GLOBAL_VALUE_FLAGS: &[&str] = &[
    "--root",
    "--runroot",
    "--tmpdir",
    "--volumepath",
    "--storage-driver",
    "--storage-opt",
    "--conmon",
    "--network-config-dir",
    "--cgroup-manager",
    "--events-backend",
    "--transient-store",
    "--runtime",
    "--log-level",
    "--syslog",
    "--url",
    "--connection",
];

fn is_podman_global_flag_token(a: &str) -> bool {
    if PODMAN_GLOBAL_VALUE_FLAGS.iter().any(|f| *f == a) {
        return true;
    }
    if a == "--remote" {
        return true;
    }
    a.starts_with("--log-level=") || a.starts_with("--syslog=")
}

/// Index of the first Podman subcommand token (skip flags before it).
pub(crate) fn podman_subcommand_index(argv: &[String]) -> usize {
    const SUBCOMMANDS: &[&str] = &[
        "help",
        "pull",
        "run",
        "create",
        "restart",
        "port",
        "tag",
        "export",
        "import",
        "history",
        "search",
        "info",
        "version",
        "stop",
        "start",
        "logs",
        "ps",
        "inspect",
        "rm",
        "kill",
        "wait",
        "pause",
        "unpause",
        "commit",
        "cp",
        "exec",
        "attach",
        "stats",
        "top",
        "update",
        "mount",
        "unmount",
        "generate",
        "init",
        "login",
        "logout",
        "push",
        "save",
        "load",
        "build",
        "buildx",
        "manifest",
        "volume",
        "network",
        "pod",
        "container",
        "image",
        "images",
        "rmi",
        "system",
        "events",
        "farm",
        "artifact",
        "machine",
        "kube",
        "compose",
        "quadlet",
        "unshare",
        "checkpoint",
        "healthcheck",
        "secret",
        "trust",
        "diff",
        "rename",
        "daemon",
        "builder",
        "completion",
        "alias",
        "service",
        "spec",
        "context",
        "play",
        "swarm",
        "plugin",
        "config",
        "node",
        "auto-update",
        "untag",
    ];
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--module"
            || a == "--root"
            || a == "--runroot"
            || a == "--tmpdir"
            || a == "--volumepath"
            || a == "--storage-driver"
            || a == "--storage-opt"
            || a == "--pull-option"
            || a == "--runtime"
            || a == "--log-level"
        {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        if SUBCOMMANDS.contains(&a) {
            return i;
        }
        i += 1;
    }
    argv.len()
}

pub static EXTRA_NETWORK_SPECS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
pub static NETWORK_CONNECT_MAC: std::sync::OnceLock<String> = std::sync::OnceLock::new();
pub static CLI_GLOBAL_NOOUT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub fn preprocess_argv(argv: Vec<String>) -> Vec<String> {
    if argv.iter().any(|a| a == "--noout") {
        let _ = CLI_GLOBAL_NOOUT.set(true);
    }
    let mut globals = podman_globals::parse_podman_global_options(&argv);
    if !argv.iter().any(|a| a == "__completeNoDesc") && !globals.raw_modules.is_empty() {
        globals.modules = podman_globals::resolve_and_validate_modules(&globals.raw_modules);
    }
    let _ = podman_globals::set_podman_global_options(globals);

    let hide_remote = std::env::var_os("CONTAINER_HOST").is_some()
        || std::env::var_os("CONTAINER_CONNECTION").is_some()
        || argv
            .iter()
            .any(|a| a.starts_with("--url") || a.starts_with("--connection"));
    crate::cli::usage_errors::set_hide_remote_help(hide_remote);

    if argv.len() == 2 && argv[1] == "-v" {
        let _ = VERSION_SHORT_OUTPUT.set(true);
        return vec![argv[0].clone(), "version".to_string()];
    }
    let mut out = Vec::new();
    let mut rm_false = false;
    let mut read_only_false = false;
    let mut env_files: Vec<String> = Vec::new();
    let mut label_files: Vec<String> = Vec::new();
    let mut build_files: Vec<String> = Vec::new();
    let mut seen_first_net = false;
    let mut extra_nets = Vec::new();
    let is_net_connect = argv
        .windows(2)
        .any(|w| w[0] == "network" && w[1] == "connect");
    let subcommand_idx = podman_subcommand_index(&argv);
    let sub_name = argv.get(subcommand_idx).map(String::as_str).unwrap_or("");
    let sub2_name = argv.get(subcommand_idx + 1).map(String::as_str).unwrap_or("");
    if sub_name == "buildx" {
        if sub2_name == "version" {
            println!("buildah 1.36.0");
            std::process::exit(0);
        }
        if sub2_name == "build" {
            let mut rewritten = Vec::new();
            for (idx, tok) in argv.into_iter().enumerate() {
                if idx == subcommand_idx {
                    continue;
                }
                if tok == "--load" {
                    continue;
                }
                rewritten.push(tok);
            }
            return preprocess_argv(rewritten);
        }
    }
    let is_build = sub_name == "build"
        || (sub_name == "image" && sub2_name == "build")
        || (sub_name == "builder" && sub2_name == "build");
    let is_run_or_create = sub_name == "run"
        || sub_name == "create"
        || (sub_name == "container" && (sub2_name == "run" || sub2_name == "create"));
    let is_exec = sub_name == "exec" || (sub_name == "container" && sub2_name == "exec");
    let mut seen_positional_after_sub = false;
    let sub_start = if sub_name == "container" && (sub2_name == "run" || sub2_name == "create" || sub2_name == "exec") {
        subcommand_idx + 1
    } else {
        subcommand_idx
    };

    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a.is_empty() && i < subcommand_idx {
            i += 1;
            continue;
        }
        if i >= subcommand_idx && (a == "-p" || a == "--publish") && i + 1 < argv.len() && argv[i + 1].is_empty() {
            i += 2;
            continue;
        }
        if is_net_connect {
            if a == "--mac-address" && i + 1 < argv.len() {
                let _ = NETWORK_CONNECT_MAC.set(argv[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(mac) = a.strip_prefix("--mac-address=") {
                let _ = NETWORK_CONNECT_MAC.set(mac.to_string());
                i += 1;
                continue;
            }
        }
        if i >= subcommand_idx && (a == "--net" || a == "--network") && i + 1 < argv.len() {
            if !seen_first_net {
                seen_first_net = true;
                out.push(a.clone());
                out.push(argv[i + 1].clone());
            } else {
                extra_nets.push(argv[i + 1].clone());
            }
            i += 2;
            continue;
        }
        if i >= subcommand_idx
            && (a.starts_with("--net=") || a.starts_with("--network="))
        {
            let val = a.split_once('=').map(|(_, v)| v).unwrap_or("");
            if !seen_first_net {
                seen_first_net = true;
                out.push(a.clone());
            } else {
                extra_nets.push(val.to_string());
            }
            i += 1;
            continue;
        }
        if i < subcommand_idx {
            if a == "--config" && i + 1 < argv.len() {
                let _ = DOCKER_CONFIG_DIR.set(argv[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(v) = a.strip_prefix("--config=") {
                let _ = DOCKER_CONFIG_DIR.set(v.to_string());
                i += 1;
                continue;
            }
            if a == "--default-mounts-file" && i + 1 < argv.len() {
                let _ = GLOBAL_DEFAULT_MOUNTS_FILE.set(argv[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(v) = a.strip_prefix("--default-mounts-file=") {
                let _ = GLOBAL_DEFAULT_MOUNTS_FILE.set(v.to_string());
                i += 1;
                continue;
            }
            if a == "--runtime" && i + 1 < argv.len() {
                let _ = GLOBAL_RUNTIME.set(argv[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(v) = a.strip_prefix("--runtime=") {
                let _ = GLOBAL_RUNTIME.set(v.to_string());
                i += 1;
                continue;
            }
            if a == "--pull-option" && i + 1 < argv.len() {
                i += 2;
                continue;
            }
            if a.starts_with("--pull-option=") {
                i += 1;
                continue;
            }
        }
        if i > sub_start && is_build {
            if (a == "-f" || a == "--file") && i + 1 < argv.len() {
                build_files.push(argv[i + 1].clone());
                if build_files.len() > 1 {
                    i += 2;
                    continue;
                }
            } else if let Some(v) = a.strip_prefix("--file=").or_else(|| a.strip_prefix("-f=")) {
                build_files.push(v.to_string());
                if build_files.len() > 1 {
                    i += 1;
                    continue;
                }
            }
        }
        if i > sub_start && (is_run_or_create || is_exec) && !seen_positional_after_sub {
            if a == "-h" && is_run_or_create {
                if i + 1 >= argv.len() {
                    let bin = if hide_remote { "podman-remote" } else { "podman" };
                    let verb = if sub_name == "container" {
                        format!("container {}", sub2_name)
                    } else {
                        sub_name.to_string()
                    };
                    eprintln!("Error: flag needs an argument: 'h' in -h");
                    eprintln!("See '{} {} --help'", bin, verb);
                    std::process::exit(125);
                }
                out.push("--hostname".to_string());
                out.push(argv[i + 1].clone());
                i += 2;
                continue;
            }
            if a == "--no-hosts" && is_run_or_create {
                let _ = RUN_NO_HOSTS.set(true);
                i += 1;
                continue;
            }
            if a == "--env-host" && is_run_or_create {
                let _ = RUN_ENV_HOST.set(true);
                i += 1;
                continue;
            }
            if (a == "--arch" || a == "--os") && is_run_or_create && i + 1 < argv.len() {
                let _ = CLI_ARCH_OR_OS_SET.set(true);
                i += 2;
                continue;
            }
            if (a.starts_with("--arch=") || a.starts_with("--os=")) && is_run_or_create {
                let _ = CLI_ARCH_OR_OS_SET.set(true);
                i += 1;
                continue;
            }
            if a == "--env-file" && i + 1 < argv.len() {
                env_files.push(argv[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(v) = a.strip_prefix("--env-file=") {
                env_files.push(v.to_string());
                i += 1;
                continue;
            }
            if a == "--label-file" && is_run_or_create && i + 1 < argv.len() {
                label_files.push(argv[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(v) = a.strip_prefix("--label-file=") {
                if is_run_or_create {
                    label_files.push(v.to_string());
                    i += 1;
                    continue;
                }
            }
            // Multiple --name options: last one wins (010-images.bats line 76)
            if a == "--name" && is_run_or_create && i + 1 < argv.len() {
                if let Some(pos) = out.iter().position(|x| x == "--name") {
                    out.remove(pos);
                    if pos < out.len() {
                        out.remove(pos);
                    }
                }
                out.push("--name".to_string());
                out.push(argv[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(v) = a.strip_prefix("--name=") {
                if is_run_or_create {
                    if let Some(pos) = out.iter().position(|x| x == "--name") {
                        out.remove(pos);
                        if pos < out.len() {
                            out.remove(pos);
                        }
                    }
                    out.push("--name".to_string());
                    out.push(v.to_string());
                    i += 1;
                    continue;
                }
            }
            if !a.starts_with('-') {
                // Check if previous token in `out` is a flag that takes a value on run/create/exec
                let prev = out.last().map(String::as_str).unwrap_or("");
                let prev_takes_val = matches!(
                    prev,
                    "-e" | "--env"
                        | "-p"
                        | "--publish"
                        | "-v"
                        | "--volume"
                        | "-w"
                        | "--workdir"
                        | "-m"
                        | "--memory"
                        | "-l"
                        | "--label"
                        | "-u"
                        | "--user"
                        | "-a"
                        | "--attach"
                        | "-c"
                        | "--cpu-shares"
                        | "--name"
                        | "--hostname"
                        | "--network"
                        | "--net"
                        | "--pod"
                        | "--entrypoint"
                        | "--restart"
                        | "--pull"
                        | "--platform"
                        | "--userns"
                        | "--uidmap"
                        | "--gidmap"
                        | "--ipc"
                        | "--pid"
                        | "--uts"
                        | "--cgroupns"
                        | "--cgroup-parent"
                        | "--log-driver"
                        | "--log-opt"
                        | "--security-opt"
                        | "--ulimit"
                        | "--sysctl"
                        | "--add-host"
                        | "--dns"
                        | "--dns-search"
                        | "--dns-option"
                        | "--device"
                        | "--tmpfs"
                        | "--mount"
                        | "--volumes-from"
                        | "--cap-add"
                        | "--cap-drop"
                        | "--annotation"
                        | "--group-add"
                        | "--tz"
                        | "--umask"
                        | "--domainname"
                        | "--stop-signal"
                        | "--stop-timeout"
                        | "--timeout"
                        | "--shm-size"
                        | "--cpus"
                        | "--cpu-period"
                        | "--cpu-quota"
                        | "--cpuset-cpus"
                        | "--cpuset-mems"
                        | "--memory-swap"
                        | "--memory-reservation"
                        | "--memory-swappiness"
                        | "--pids-limit"
                        | "--oom-score-adj"
                        | "--cidfile"
                        | "--conmon-pidfile"
                        | "--hooks-dir"
                        | "--image-volume"
                        | "--rootfs"
                        | "--default-mounts-file"
                        | "--secret"
                        | "--hostuser"
                        | "--group-entry"
                        | "--unsetenv"
                        | "--systemd"
                        | "--preserve-fds"
                        | "--preserve-fd"
                        | "--authfile"
                        | "--cert-dir"
                        | "--creds"
                );
                if !prev_takes_val {
                    seen_positional_after_sub = true;
                    if !env_files.is_empty() {
                        out.push("--env-file".to_string());
                        out.push(env_files.drain(..).collect::<Vec<_>>().join("\0"));
                    }
                    if !label_files.is_empty() {
                        out.push("--label-file".to_string());
                        out.push(label_files.drain(..).collect::<Vec<_>>().join("\0"));
                    }
                }
            }
        }
        // Multiple --format / -f options on non-run/exec commands: last one wins (010-images.bats line 113, 070-build.bats line 515)
        if !is_run_or_create && !is_exec && i > subcommand_idx {
            if (a == "--format" || (a == "-f" && matches!(sub_name, "inspect" | "info" | "version" | "history")))
                && i + 1 < argv.len()
            {
                if let Some(pos) = out.iter().position(|x| x == "--format") {
                    out.remove(pos);
                    if pos < out.len() {
                        out.remove(pos);
                    }
                }
                out.push("--format".to_string());
                out.push(argv[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(v) = a.strip_prefix("--format=") {
                if let Some(pos) = out.iter().position(|x| x == "--format") {
                    out.remove(pos);
                    if pos < out.len() {
                        out.remove(pos);
                    }
                }
                out.push("--format".to_string());
                out.push(v.to_string());
                i += 1;
                continue;
            }
        }
        if a == "--rm=false" {
            rm_false = true;
            i += 1;
            continue;
        }
        if a == "--read-only=false" {
            read_only_false = true;
            i += 1;
            continue;
        }
        if a == "--read-only=true" {
            out.push("--read-only".to_string());
            i += 1;
            continue;
        }
        if (a == "--debug" || a == "-D") && i < subcommand_idx {
            i += 1;
            continue;
        }
        if a == "--infra=false" {
            let _ = POD_INFRA_EXPLICIT_FALSE.set(true);
            i += 1;
            continue;
        }
        if a == "--http-proxy=false" {
            let _ = HTTP_PROXY_EXPLICIT_FALSE.set(true);
            i += 1;
            continue;
        }
        if a == "-t=false" || a == "--tty=false" {
            let _ = RUN_TTY_EXPLICIT_FALSE.set(true);
            i += 1;
            continue;
        }
        if a == "-t=true" || a == "--tty=true" {
            out.push("-t".to_string());
            i += 1;
            continue;
        }
        if a == "-i=false" || a == "--interactive=false" {
            i += 1;
            continue;
        }
        if a == "-i=true" || a == "--interactive=true" {
            out.push("-i".to_string());
            i += 1;
            continue;
        }
        if podman_globals::should_strip_global_flag_at(&argv, i, subcommand_idx) {
            let skip = podman_globals::global_flag_skip_width(a).unwrap_or(1);
            i += skip;
            continue;
        }
        out.extend(expand_combined_short_flags(a));
        i += 1;
    }
    if !env_files.is_empty() {
        out.push("--env-file".to_string());
        out.push(env_files.join("\0"));
    }
    if !label_files.is_empty() {
        out.push("--label-file".to_string());
        out.push(label_files.join("\0"));
    }
    if rm_false {
        let _ = RUN_RM_EXPLICIT_FALSE.set(true);
    }
    if read_only_false {
        let _ = READ_ONLY_EXPLICIT_FALSE.set(true);
    }
    if build_files.len() > 1 {
        let _ = BUILD_EXTRA_FILES.set(build_files[1..].to_vec());
    }
    if !extra_nets.is_empty() {
        let _ = EXTRA_NETWORK_SPECS.set(extra_nets);
    }
    if subcommand_idx == argv.len() && out.len() >= 2 && out[out.len() - 1] == "-v" {
        let _ = VERSION_SHORT_OUTPUT.set(true);
        let last = out.len() - 1;
        out[last] = "version".to_string();
    } else if out.len() == 2 && out[1] == "--version" {
        out[1] = "version".to_string();
    }
    out
}

/// Help layout expected by Podman `test/system/015-help.bats` (`grep -A1 '^Usage:'`).
pub const PODMAN_LEAF_HELP: &str = "\
{about-with-newline}\
Usage:\n  \
{usage}\n\
\n\
{all-args}\
";

/// Empty Podman stub commands (swarm, plugin, …) for help-test compatibility.
#[derive(Args, Debug, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct StubCommandArgs {}

/// `podman help [command]` (Podman BATS 015-help).
#[derive(Args, Debug, Default)]
#[command(
    about = "Help about any command",
    help_template = crate::cli::PODMAN_LEAF_HELP,
    override_usage = "podman help [command] [options]"
)]
pub struct HelpArgs {
    #[arg(value_name = "command")]
    pub command: Vec<String>,
}

pub const PODMAN_GROUP_HELP: &str = "\
{about-with-newline}\
Usage:\n  \
{usage}\n\
\n\
Available Commands:\n\
{subcommands}\n\
\n\
Options:\n\
{options}\
";

#[derive(Parser, Debug)]
#[command(
    name = "podman",
    bin_name = "podman",
    author = "Boxr Contributors",
    version = "6.3.0-dev",
    about = "Manage pods, containers and images",
    long_about = "Manage pods, containers and images",
    subcommand_required = true,
    arg_required_else_help = false,
    disable_help_subcommand = true,
    help_template = crate::cli::PODMAN_GROUP_HELP
)]
pub struct Cli {
    /// Path of the authentication file (Podman-compatible global flag)
    #[arg(global = true, long = "authfile")]
    pub authfile: Option<String>,
    /// Suppress stdout from supported commands (Podman global flag)
    #[arg(global = true, long = "noout")]
    pub noout: bool,
    /// Write container ID to a file instead of stdout (Podman global flag)
    #[arg(global = true, long = "out", value_name = "FILE")]
    pub out: Option<String>,
    /// Flags passed through to the OCI runtime (Podman global flag)
    #[arg(global = true, long = "runtime-flag", value_name = "FLAG")]
    pub runtime_flag: Vec<String>,
    /// Log container output via syslog (accepted for Podman BATS; no-op in boxr)
    #[arg(global = true, long = "syslog")]
    pub syslog: bool,
    /// Remote client (Podman-compatible; local engine only in boxr)
    #[arg(global = true, long = "remote")]
    pub remote: bool,
    /// URL to remote Podman service (accepted for help/CLI parity)
    #[arg(global = true, long = "url")]
    pub url: Option<String>,
    /// Connection name (accepted for help/CLI parity)
    #[arg(global = true, long = "connection")]
    pub connection: Option<String>,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Help about any command
    Help(HelpArgs),

    /// Pull an image from an OCI registry (Docker Hub, GHCR, Quay, etc.)
    Pull(PullArgs),

    /// Run a command in a new container
    Run(RunArgs),

    /// Create a new container without starting it
    Create(RunArgs),

    /// Restart one or more containers
    Restart(RestartArgs),

    /// List port mappings or a specific mapping for the container
    Port(PortArgs),

    /// Create a tag TARGET_IMAGE that refers to SOURCE_IMAGE
    Tag(TagArgs),

    /// Export a container's filesystem as a tar archive
    Export(ExportArgs),

    /// Import the contents from a tarball to create a filesystem image
    Import(ImportArgs),

    /// Show the history of an image
    History(HistoryArgs),

    /// Search Docker Hub for images
    Search(SearchArgs),

    /// Display system-wide information
    Info(FormatArgs),

    /// Display the Podman version information
    Version(FormatArgs),

    /// Stop a running container
    Stop(StopArgs),

    /// Start a stopped container
    Start(StartArgs),

    /// Fetch the logs of a container
    Logs(LogsArgs),

    /// Run a command in an existing container
    Exec(ExecArgs),

    /// Return low-level information on Boxr objects
    Inspect(InspectArgs),

    /// Build an image from a Dockerfile
    Build(BuildArgs),

    /// Manage Docker Compose projects
    Compose(ComposeArgs),

    /// Save one or more images to a tar archive
    Save(SaveArgs),

    /// Load an image from a tar archive or STDIN
    Load(LoadArgs),

    /// Push an image to an OCI registry
    Push(PushArgs),

    /// Log in to a Docker registry
    Login(LoginArgs),

    /// Log out from a Docker registry
    Logout(LogoutArgs),

    /// Manage volumes
    Volume(VolumeSubcommands),

    /// Manage networks
    Network(NetworkSubcommands),

    /// Start the Boxr daemon process
    Daemon(DaemonArgs),

    /// List containers
    Ps(PsArgs),

    /// List images
    Images(ImagesArgs),

    /// Remove one or more containers
    Rm(RmArgs),

    /// Remove one or more images
    Rmi(RmiArgs),

    /// Manage containers
    Container(ContainerSubcommands),

    /// Manage images
    Image(ImageSubcommands),

    /// Manage builds
    Builder(BuilderSubcommands),

    /// Display a live stream of container(s) resource usage statistics
    Stats(StatsArgs),

    /// Get real time events from the server
    Events(EventsArgs),

    /// Generate shell auto-completion scripts
    Completion(CompletionArgs),

    /// Set up a transparent docker alias wrapper
    Alias(AliasArgs),

    /// Inspect changes to files on a container's filesystem
    Diff(DiffArgs),

    /// Display the running processes of a container
    #[command(trailing_var_arg = true)]
    Top(TopArgs),

    /// Create a new image from a container's changes
    Commit(CommitArgs),

    /// Pause all processes within one or more containers
    Pause(PauseArgs),

    /// Unpause all processes within one or more containers
    Unpause(UnpauseArgs),

    /// Rename a container
    Rename(RenameArgs),

    /// Block until one or more containers stop, then print their exit codes
    Wait(WaitArgs),

    /// Copy files/folders between a container and the local filesystem
    Cp(CpArgs),

    /// Update configuration of one or more containers
    Update(UpdateArgs),

    /// Attach local standard input, output, and error streams to a running container
    Attach(AttachArgs),

    /// Kill one or more running containers
    Kill(KillArgs),

    /// Manage system disk usage and cleanups
    System(SystemSubcommands),

    /// Manage pods
    Pod(PodSubcommands),

    /// Play a pod from a structured file
    Play(PlaySubcommands),

    /// Generate structured specifications for containers or pods
    Generate(GenerateSubcommands),

    /// Run a command in a user namespace
    Unshare(UnshareArgs),

    /// Generate a standard OCI runtime specification (config.json)
    Spec(SpecArgs),

    /// Manage Docker contexts
    Context(ContextSubcommands),

    /// Manage Docker image manifests and manifest lists
    Manifest(ManifestSubcommands),

    /// Manage the Boxr background daemon service (launchd on macOS, systemd on Linux)
    Service(ServiceArgs),

    /// Manage Swarm (stub)
    Swarm(StubCommandArgs),

    /// Manage plugins (stub)
    Plugin(StubCommandArgs),

    /// Manage Swarm configs (stub)
    Config(StubCommandArgs),

    /// Manage secrets
    Secret(SecretSubcommands),

    /// Manage Swarm nodes (stub)
    Node(StubCommandArgs),

    /// Manage trust (stub)
    Trust(StubCommandArgs),

    /// Manage Podman-style virtual machines (macOS / Windows)
    Machine(MachineSubcommands),

    /// Mount a container's root filesystem and return the mount path
    Mount(MountArgs),

    /// Unmount a container's root filesystem
    #[command(alias = "umount")]
    Unmount(UnmountArgs),

    /// Manage OCI artifacts
    Artifact(ArtifactSubcommands),

    /// Farm out builds to machines running podman for different architectures
    Farm(FarmSubcommands),

    /// Auto-update containers based on updated images
    #[command(name = "auto-update")]
    AutoUpdate(AutoUpdateArgs),

    /// Run health check on a container
    Healthcheck(HealthcheckSubcommands),

    /// Manage Quadlet systemd unit files
    Quadlet(QuadletSubcommands),

    /// Modern Kubernetes YAML resources manager (play, down, generate, apply)
    Kube(KubeSubcommands),

    /// Initialize a container
    Init(InitArgs),

    /// Remove one or more tags from an image
    Untag(UntagArgs),
}
