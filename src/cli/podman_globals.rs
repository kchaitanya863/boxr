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
    pub storage_driver: Option<String>,
    pub storage_opts: Vec<String>,
    pub events_backend: Option<String>,
    pub cgroup_manager: Option<String>,
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
    if let Ok(mut guard) = PARSED_GLOBALS.lock() {
        *guard = Some(opts);
    }
}

const VALUE_FLAGS: &[&str] = &[
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

fn is_global_value_flag(token: &str) -> bool {
    if token == "--remote" {
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
    let mut i = 1usize;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--debug" || a == "-D" {
            i += 1;
            continue;
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
        i += 1;
    }
    opts
}

fn strip_globals_after_subcommand(sub: &str) -> bool {
    matches!(
        sub,
        "info" | "version" | "images" | "ps" | "system" | "volume" | "pull" | "push"
    )
}

pub fn global_flag_skip_width(token: &str) -> Option<usize> {
    if token == "--remote" {
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
    if !strip_globals_after_subcommand(sub) {
        return false;
    }
    true
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
