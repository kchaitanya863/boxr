//! Podman global CLI flags stripped before clap (BATS / e2e init).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Default, Clone)]
pub struct PodmanGlobalOptions {
    pub root: Option<PathBuf>,
    pub runroot: Option<PathBuf>,
    pub tmpdir: Option<PathBuf>,
    pub volumepath: Option<PathBuf>,
    pub imagestore: Option<PathBuf>,
    pub storage_driver: Option<String>,
    pub storage_opts: Vec<String>,
    pub events_backend: Option<String>,
    pub cgroup_manager: Option<String>,
    pub network_config_dir: Option<PathBuf>,
    pub debug: bool,
    pub raw_modules: Vec<String>,
    pub modules: Vec<PathBuf>,
    pub url: Option<String>,
    pub connection: Option<String>,
    pub remote: bool,
    pub transient_store: bool,
    pub tls_ca: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub tls_details: Option<String>,
    pub pull_options: Vec<String>,
    pub cdi_spec_dirs: Vec<PathBuf>,
}

static PARSED_GLOBALS: Mutex<Option<PodmanGlobalOptions>> = Mutex::new(None);

pub fn podman_global_options() -> PodmanGlobalOptions {
    PARSED_GLOBALS
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_default()
}

pub fn set_podman_global_options(opts: PodmanGlobalOptions) {
    if let Some(ref r) = opts.root {
        unsafe {
            std::env::set_var("BOXR_HOME", r);
        }
    }
    if let Some(ref nd) = opts.network_config_dir {
        unsafe {
            std::env::set_var("BOXR_NETWORK_CONFIG_DIR", nd);
        }
    }
    if let Ok(mut guard) = PARSED_GLOBALS.lock() {
        *guard = Some(opts);
    }
}

const VALUE_FLAGS: &[&str] = &[
    "--root",
    "--runroot",
    "--tmpdir",
    "--volumepath",
    "--imagestore",
    "--storage-driver",
    "--storage-opt",
    "--pull-option",
    "--module",
    "--conmon",
    "--network-config-dir",
    "--cdi-spec-dir",
    "--cgroup-manager",
    "--events-backend",
    "--runtime",
    "--log-level",
    "--syslog",
    "--url",
    "--host",
    "-H",
    "--connection",
    "--context",
    "--tls-ca",
    "--tls-cert",
    "--tls-key",
    "--tls-details",
    "--ssh",
    "--cdi-spec-dir",
];

fn is_global_value_flag(token: &str) -> bool {
    if token == "--remote"
        || token == "--transient-store"
        || token.starts_with("--transient-store=")
    {
        return true;
    }
    if token.starts_with("--log-level=") || token.starts_with("--syslog=") {
        return true;
    }
    VALUE_FLAGS
        .iter()
        .any(|f| *f == token || token.starts_with(&format!("{f}=")))
}

pub fn parse_podman_global_options(argv: &[String]) -> PodmanGlobalOptions {
    let mut opts = PodmanGlobalOptions::default();
    let sub_idx = crate::cli::podman_subcommand_index(argv);
    let mut i = 1usize;
    while i < argv.len() {
        let a = argv[i].as_str();
        if i < sub_idx {
            if let Some(v) = a.strip_prefix("--module=") {
                opts.raw_modules.push(v.to_string());
                i += 1;
                continue;
            }
            if a == "--module" {
                if i + 1 < argv.len() {
                    opts.raw_modules.push(argv[i + 1].clone());
                    i += 2;
                    continue;
                }
            }
        }
        if a == "--debug" || a == "-D" || a == "--log-level=debug" {
            opts.debug = true;
            i += 1;
            continue;
        }
        if a == "--log-level" {
            if i + 1 < argv.len() && argv[i + 1] == "debug" {
                opts.debug = true;
            }
            i += 2;
            continue;
        }
        if let Some(v) = a.strip_prefix("--tls-details=") {
            opts.tls_details = Some(v.to_string());
            i += 1;
            continue;
        }
        if a == "--tls-details" {
            if i + 1 < argv.len() {
                opts.tls_details = Some(argv[i + 1].clone());
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--pull-option=") {
            opts.pull_options.push(v.to_string());
            i += 1;
            continue;
        }
        if a == "--pull-option" {
            if i + 1 < argv.len() {
                opts.pull_options.push(argv[i + 1].clone());
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--root=") {
            opts.root = Some(PathBuf::from(v));
            i += 1;
            continue;
        }
        if a == "--root" {
            if i + 1 < argv.len() {
                opts.root = Some(PathBuf::from(&argv[i + 1]));
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--runroot=") {
            opts.runroot = Some(PathBuf::from(v));
            i += 1;
            continue;
        }
        if a == "--runroot" {
            if i + 1 < argv.len() {
                opts.runroot = Some(PathBuf::from(&argv[i + 1]));
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--tmpdir=") {
            opts.tmpdir = Some(PathBuf::from(v));
            i += 1;
            continue;
        }
        if a == "--tmpdir" {
            if i + 1 < argv.len() {
                opts.tmpdir = Some(PathBuf::from(&argv[i + 1]));
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--volumepath=") {
            opts.volumepath = Some(PathBuf::from(v));
            i += 1;
            continue;
        }
        if a == "--volumepath" {
            if i + 1 < argv.len() {
                opts.volumepath = Some(PathBuf::from(&argv[i + 1]));
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--imagestore=") {
            opts.imagestore = Some(PathBuf::from(v));
            i += 1;
            continue;
        }
        if a == "--imagestore" {
            if i + 1 < argv.len() {
                opts.imagestore = Some(PathBuf::from(&argv[i + 1]));
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--storage-driver=") {
            opts.storage_driver = Some(v.to_string());
            i += 1;
            continue;
        }
        if a == "--storage-driver" {
            if i + 1 < argv.len() {
                opts.storage_driver = Some(argv[i + 1].clone());
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--storage-opt=") {
            opts.storage_opts.push(v.to_string());
            i += 1;
            continue;
        }
        if a == "--storage-opt" {
            if i + 1 < argv.len() {
                opts.storage_opts.push(argv[i + 1].clone());
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--events-backend=") {
            opts.events_backend = Some(v.to_string());
            i += 1;
            continue;
        }
        if a == "--events-backend" {
            if i + 1 < argv.len() {
                opts.events_backend = Some(argv[i + 1].clone());
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--cgroup-manager=") {
            opts.cgroup_manager = Some(v.to_string());
            i += 1;
            continue;
        }
        if a == "--cgroup-manager" {
            if i + 1 < argv.len() {
                opts.cgroup_manager = Some(argv[i + 1].clone());
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--network-config-dir=") {
            opts.network_config_dir = Some(PathBuf::from(v));
            i += 1;
            continue;
        }
        if a == "--network-config-dir" {
            if i + 1 < argv.len() {
                opts.network_config_dir = Some(PathBuf::from(&argv[i + 1]));
                i += 2;
                continue;
            }
        }
        if a == "--remote" || a == "-r" {
            opts.remote = true;
            i += 1;
            continue;
        }
        if a == "--transient-store" || a == "--transient-store=true" {
            opts.transient_store = true;
            i += 1;
            continue;
        }
        if a == "--transient-store=false" {
            opts.transient_store = false;
            i += 1;
            continue;
        }
        if let Some(v) = a
            .strip_prefix("--url=")
            .or_else(|| a.strip_prefix("--host="))
            .or_else(|| a.strip_prefix("-H="))
        {
            opts.url = Some(v.to_string());
            i += 1;
            continue;
        }
        if a == "--url" || a == "--host" || a == "-H" {
            if i + 1 < argv.len() {
                opts.url = Some(argv[i + 1].clone());
                i += 2;
                continue;
            }
        }
        if let Some(v) = a
            .strip_prefix("--connection=")
            .or_else(|| a.strip_prefix("--context="))
        {
            opts.connection = Some(v.to_string());
            i += 1;
            continue;
        }
        if a == "--connection" || a == "--context" {
            if i + 1 < argv.len() {
                opts.connection = Some(argv[i + 1].clone());
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--tls-ca=") {
            opts.tls_ca = Some(v.to_string());
            i += 1;
            continue;
        }
        if a == "--tls-ca" {
            if i + 1 < argv.len() {
                opts.tls_ca = Some(argv[i + 1].clone());
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--tls-cert=") {
            opts.tls_cert = Some(v.to_string());
            i += 1;
            continue;
        }
        if a == "--tls-cert" {
            if i + 1 < argv.len() {
                opts.tls_cert = Some(argv[i + 1].clone());
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--tls-key=") {
            opts.tls_key = Some(v.to_string());
            i += 1;
            continue;
        }
        if a == "--tls-key" {
            if i + 1 < argv.len() {
                opts.tls_key = Some(argv[i + 1].clone());
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--network-config-dir=") {
            opts.network_config_dir = Some(PathBuf::from(v));
            i += 1;
            continue;
        }
        if a == "--network-config-dir" {
            if i + 1 < argv.len() {
                opts.network_config_dir = Some(PathBuf::from(&argv[i + 1]));
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("--cdi-spec-dir=") {
            opts.cdi_spec_dirs.push(PathBuf::from(v));
            i += 1;
            continue;
        }
        if a == "--cdi-spec-dir" {
            if i + 1 < argv.len() {
                opts.cdi_spec_dirs.push(PathBuf::from(&argv[i + 1]));
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    opts
}

fn strip_globals_after_subcommand(sub: &str) -> bool {
    matches!(
        sub,
        "info"
            | "version"
            | "images"
            | "ps"
            | "system"
            | "volume"
            | "pull"
            | "kube"
            | "play"
            | "push"
            | "load"
            | "save"
            | "tag"
            | "rmi"
            | "image"
            | "rm"
            | "stop"
            | "start"
            | "wait"
            | "inspect"
            | "container"
            | "healthcheck"
    )
}

pub fn global_flag_skip_width(token: &str) -> Option<usize> {
    if token == "--remote"
        || token == "--transient-store"
        || token.starts_with("--transient-store=")
    {
        return Some(1);
    }
    if token.contains('=') {
        return Some(1);
    }
    if is_global_value_flag(token) {
        return Some(2);
    }
    None
}

pub fn should_strip_global_flag_at(argv: &[String], i: usize, subcommand_idx: usize) -> bool {
    if i >= argv.len() || i == 0 {
        return false;
    }
    let a = argv[i].as_str();
    if a == "--transient-store"
        || a.starts_with("--transient-store=")
        || a == "--pull-option"
        || a.starts_with("--pull-option=")
        || a == "--imagestore"
        || a.starts_with("--imagestore=")
    {
        return true;
    }
    if a == "--module" || a.starts_with("--module=") {
        return i < subcommand_idx;
    }
    if !is_global_value_flag(a) {
        return false;
    }
    if i < subcommand_idx {
        return true;
    }
    if i <= subcommand_idx {
        return false;
    }
    let sub = argv.get(subcommand_idx).map(String::as_str).unwrap_or("");
    if sub == "system"
        && argv.get(subcommand_idx + 1).map(String::as_str) == Some("service")
        && (a.starts_with("--tls-cert") || a.starts_with("--tls-key"))
    {
        return false;
    }
    if sub == "system"
        && argv.get(subcommand_idx + 1).map(String::as_str) == Some("connection")
        && (a.starts_with("--tls-ca") || a.starts_with("--tls-cert") || a.starts_with("--tls-key"))
    {
        return false;
    }
    if !strip_globals_after_subcommand(sub) {
        return false;
    }
    true
}

fn validate_module_toml(path: &std::path::Path) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let mut section = String::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed[1..trimmed.len() - 1].trim().to_string();
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            if v.trim().is_empty() {
                let key_name = if section.is_empty() {
                    k.trim().to_string()
                } else {
                    format!("{}.{}", section, k.trim())
                };
                eprintln!(
                    "Failed to obtain podman configuration: parsing containers.conf: decode configuration \"{}\": toml: line {} (last key \"{}\"): expected value but found '\\n' instead",
                    path.display(),
                    idx + 1,
                    key_name
                );
                std::process::exit(1);
            }
        }
    }
}

pub fn resolve_and_validate_modules(raw_modules: &[String]) -> Vec<PathBuf> {
    let mut resolved = Vec::new();
    for m in raw_modules {
        if m.starts_with('/') || m.starts_with("./") || m.starts_with("../") {
            let p = PathBuf::from(m);
            if !p.exists() {
                eprintln!(
                    "Failed to obtain podman configuration: parsing containers.conf: could not resolve module: open {}: no such file or directory",
                    m
                );
                std::process::exit(1);
            }
            validate_module_toml(&p);
            resolved.push(p);
        } else {
            let xdg = std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| {
                format!("{}/.config", std::env::var("HOME").unwrap_or_default())
            });
            let dirs = [xdg.as_str(), "/etc", "/usr/share"];
            let mut found = None;
            for d in dirs {
                let cand = PathBuf::from(format!("{}/containers/containers.conf.modules/{}", d, m));
                if cand.exists() {
                    found = Some(cand);
                    break;
                }
            }
            if let Some(p) = found {
                validate_module_toml(&p);
                resolved.push(p);
            } else {
                let mut msg = String::from(
                    "Failed to obtain podman configuration: parsing containers.conf: could not resolve module: ",
                );
                for (idx, d) in dirs.iter().enumerate() {
                    if idx > 0 {
                        msg.push('\n');
                    }
                    msg.push_str(&format!(
                        "open {}/containers/containers.conf.modules/{}: no such file or directory",
                        d, m
                    ));
                }
                eprintln!("{}", msg);
                std::process::exit(1);
            }
        }
    }
    resolved
}

pub fn graph_options_from_storage_opts(opts: &[String]) -> BTreeMap<String, serde_json::Value> {
    let mut imagestores: Vec<(String, String)> = Vec::new();
    for opt in opts {
        let Some((key, val)) = opt.split_once('=') else {
            continue;
        };
        if key.ends_with(".imagestore") {
            let driver = key.split('.').next().unwrap_or("overlay");
            imagestores.push((driver.to_string(), val.to_string()));
        }
    }
    let mut map: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    if imagestores.is_empty() {
        return map;
    }
    let driver = imagestores[0].0.clone();
    let paths: Vec<String> = imagestores.into_iter().map(|(_, p)| p).collect();
    if paths.len() > 1 {
        map.insert(
            format!("{driver}.additionalImageStores"),
            serde_json::Value::Array(
                paths
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if let Some(last) = paths.last() {
        map.insert(
            format!("{driver}.imagestore"),
            serde_json::Value::String(last.clone()),
        );
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_root_and_volumepath() {
        let argv = vec![
            "boxr".into(),
            "--storage-driver=vfs".into(),
            "--root".into(),
            "/tmp/root".into(),
            "--volumepath".into(),
            "/tmp/vol".into(),
            "info".into(),
        ];
        let opts = parse_podman_global_options(&argv);
        assert_eq!(opts.storage_driver.as_deref(), Some("vfs"));
        assert_eq!(
            opts.root.as_ref().map(|p| p.to_str().unwrap()),
            Some("/tmp/root")
        );
        assert_eq!(
            opts.volumepath.as_ref().map(|p| p.to_str().unwrap()),
            Some("/tmp/vol")
        );
    }
}
