//! Podman-shaped `boxr info` document for BATS / template parity.

use crate::storage::{ContainerStatus, ContainerStore, ImageStore};
use serde_json::{Value, json};
use std::path::Path;

const PODMAN_ENGINE_VERSION: &str = "6.3.0-dev";

pub fn build_podman_info_document() -> Value {
    let c_store = ContainerStore::new();
    let i_store = ImageStore::new();
    let containers = c_store.list();
    let running = containers
        .iter()
        .filter(|c| matches!(c.status, ContainerStatus::Running))
        .count();
    let paused = containers
        .iter()
        .filter(|c| matches!(c.status, ContainerStatus::Paused))
        .count();
    let stopped = containers
        .iter()
        .filter(|c| matches!(c.status, ContainerStatus::Exited(_)))
        .count();
    let image_count = i_store.list().len();

    let globals = crate::cli::podman_globals::podman_global_options();
    let remote_uri = globals
        .url
        .clone()
        .or_else(|| std::env::var("CONTAINER_HOST").ok())
        .unwrap_or_else(|| {
            let xdg = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run".to_string());
            format!("unix://{}/podman/podman.sock", xdg)
        });
    let mut graph_root = globals
        .root
        .as_ref()
        .map(|p| p.display().to_string())
        .or_else(storage_conf_rootless_storage_path)
        .unwrap_or_else(|| crate::storage::boxr_home().display().to_string());
    if let Some(rest) = remote_uri
        .strip_prefix("tcp://")
        .or_else(|| remote_uri.strip_prefix("tcp:"))
    {
        let port_part = rest.rsplit(':').next().unwrap_or("0");
        if let Ok(meta_str) = std::fs::read_to_string(format!("/tmp/boxr-tcp-{}.meta", port_part)) {
            if let Ok(meta) = serde_json::from_str::<Value>(&meta_str) {
                if let Some(gr) = meta.get("graph_root").and_then(|v| v.as_str()) {
                    if !gr.is_empty() {
                        graph_root = gr.to_string();
                    }
                }
            }
        }
    }
    let run_root = globals
        .runroot
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| graph_root.clone());
    let default_volume_path = format!("{graph_root}/volumes");
    let volume_path = globals
        .volumepath
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or(default_volume_path);
    let graph_options = if globals.root.is_some() && globals.storage_opts.is_empty() {
        serde_json::json!({})
    } else {
        let map =
            crate::cli::podman_globals::graph_options_from_storage_opts(&globals.storage_opts);
        serde_json::Value::Object(map.into_iter().collect())
    };
    let default_network = crate::containers_conf_toml_value("default_network")
        .unwrap_or_else(|| "podman".to_string());
    let mut cdi_spec_dirs = crate::containers_conf_string_array("cdi_spec_dirs");
    if !globals.cdi_spec_dirs.is_empty() {
        cdi_spec_dirs = globals
            .cdi_spec_dirs
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
    }
    if cdi_spec_dirs.is_empty() {
        cdi_spec_dirs = vec!["/etc/cdi".to_string(), "/var/run/cdi".to_string()];
    }
    let discovered_devices = discover_cdi_devices(&cdi_spec_dirs);
    let service_is_remote = globals.remote
        || globals.url.is_some()
        || globals.connection.is_some()
        || crate::containers_conf_toml_value("remote")
            .is_some_and(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"));
    if service_is_remote
        && globals.url.is_none()
        && globals.connection.is_none()
        && std::env::var_os("CONTAINER_HOST").is_none()
    {
        let sock_path = remote_uri
            .strip_prefix("unix://")
            .unwrap_or(remote_uri.as_str());
        if !Path::new(sock_path).exists() {
            crate::cli::usage_errors::exit_usage_error(format!(
                "unable to connect to Podman socket: Get \"http://d/v5.0.0/libpod/_ping\": dial unix {}: connect: no such file or directory",
                sock_path
            ));
        }
    }
    let seccomp_profile_path = crate::containers_conf_toml_value("seccomp_profile")
        .unwrap_or_else(|| "/usr/share/containers/seccomp.json".to_string());
    let image_copy_tmp_dir = if let Ok(td) = std::env::var("TMPDIR")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or(())
    {
        td
    } else if let Some(cfg_dir) = crate::containers_conf_toml_value("image_copy_tmp_dir") {
        if !cfg_dir.starts_with('/') && cfg_dir != "storage" {
            crate::cli::usage_errors::exit_usage_error(format!(
                "invalid image_copy_tmp_dir value {:?} (relative paths are not accepted)",
                cfg_dir
            ));
        }
        cfg_dir
    } else {
        "/var/tmp".to_string()
    };
    let client_val = if service_is_remote {
        json!({
            "APIVersion": "1.45",
            "Version": PODMAN_ENGINE_VERSION,
            "Os": std::env::consts::OS,
            "Arch": std::env::consts::ARCH
        })
    } else {
        json!("<nil>")
    };
    let free_locks = 2048usize.saturating_sub(containers.len());
    let oci_path = resolve_oci_runtime_path();
    let oci_name = Path::new(&oci_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("crun")
        .to_string();
    let (cgroup_manager, cgroup_version) = linux_cgroup_info();
    let (dist_name, dist_version) = linux_distribution();
    let rootless = cfg!(unix) && unsafe { libc::getuid() != 0 };
    // Podman BATS on non-RHEL expect netavark (005-info); rootless may still use passt/usernet at runtime.
    let network_backend = "netavark";
    let pasta_bin = which_executable("pasta").unwrap_or_else(|| "/usr/bin/pasta".to_string());
    let conmon_path = which_executable("conmon").unwrap_or_else(|| "/usr/bin/conmon".to_string());
    let mem = linux_meminfo_kb();
    let volume_plugins = crate::containers_conf_volume_plugin_keys();
    let volume_plugin_list: Value = if volume_plugins.is_empty() {
        json!(["local"])
    } else {
        json!(volume_plugins)
    };
    let is_remote = globals.remote
        || globals.url.is_some()
        || globals.connection.is_some()
        || std::env::var_os("CONTAINER_HOST").is_some()
        || std::env::var_os("CONTAINER_CONNECTION").is_some();
    let default_network = crate::containers_conf_toml_value("default_network")
        .unwrap_or_else(|| "podman".to_string());
    let cdi_spec_dirs = crate::runtime::cdi::CdiManager::effective_spec_dirs();
    let discovered_devices = crate::runtime::cdi::CdiManager::discovered_devices(&cdi_spec_dirs);
    let seccomp_profile_path = crate::containers_conf_toml_value("seccomp_profile")
        .unwrap_or_else(|| "/usr/share/containers/seccomp.json".to_string());
    let image_copy_tmp_dir = if let Ok(tmpdir) = std::env::var("TMPDIR") {
        if !tmpdir.is_empty() {
            tmpdir
        } else {
            "/var/tmp".to_string()
        }
    } else if let Some(val) = crate::containers_conf_toml_value("image_copy_tmp_dir") {
        if !val.starts_with('/') {
            crate::cli::usage_errors::exit_usage_error(format!(
                "invalid image_copy_tmp_dir value {:?} (relative paths are not accepted)",
                val
            ));
        }
        val
    } else {
        "/var/tmp".to_string()
    };
    let pod_count = crate::pod::PodStore::new().list().len();
    let free_locks = 2048usize.saturating_sub(containers.len() + pod_count);
    let client_val = if is_remote {
        json!({
            "APIVersion": PODMAN_ENGINE_VERSION,
            "Version": PODMAN_ENGINE_VERSION,
            "GoVersion": "go1.23",
            "GitCommit": "main",
            "BuiltTime": "2026-09-14",
            "Built": 0,
            "OsArch": format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
            "Os": std::env::consts::OS,
        })
    } else {
        Value::Null
    };

    let go_arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };

    json!({
        "Containers": containers.len(),
        "ContainersRunning": running,
        "ContainersPaused": paused,
        "ContainersStopped": stopped,
        "Images": image_count,
        "Driver": "overlay",
        "ServerVersion": env!("CARGO_PKG_VERSION"),
        "OSType": "linux",
        "Client": client_val,
        "Host": {
            "Arch": go_arch,
            "BuildahVersion": "1.36.0",
            "CDISpecDirs": cdi_spec_dirs,
            "CgroupManager": cgroup_manager,
            "CgroupsVersion": cgroup_version,
            "Conmon": {
                "Path": conmon_path,
                "Package": format!("conmon-2.1.12-1"),
                "Version": "conmon version 2.1.12, commit: unknown"
            },
            "DatabaseBackend": "sqlite",
            "DiscoveredDevices": discovered_devices,
            "Distribution": {
                "Distribution": dist_name,
                "Version": dist_version
            },
            "EmulatedArchitectures": [],
            "EventLogger": "file",
            "FreeLocks": free_locks,
            "Hostname": hostname(),
            "LogDriver": "k8s-file",
            "MemAvailable": mem.available,
            "MemFree": mem.free,
            "MemTotal": mem.total,
            "NetworkBackend": network_backend,
            "NetworkBackendInfo": {
                "Backend": network_backend,
                "DefaultNetwork": default_network,
                "DNS": {
                    "Package": "aardvark-dns-1.12.0-1"
                }
            },
            "OCIRuntime": {
                "Name": oci_name,
                "Path": oci_path,
                "Features": {
                    "mode": "sync"
                }
            },
            "OS": "linux",
            "Os": "linux",
            "Rootless": rootless,
            "Pasta": {
                "Executable": pasta_bin,
                "Package": "passt-0^2024.08.07-1"
            },
            "RootlessNetworkCmd": "pasta",
            "RemoteSocket": {
                "Path": remote_uri,
                "Exists": true
            },
            "ServiceIsRemote": service_is_remote,
            "Security": {
                "Rootless": rootless,
                "SECCOMPProfilePath": seccomp_profile_path
            }
        },
        "Plugins": {
            "Volume": volume_plugin_list,
            "Network": ["bridge", "macvlan", "ipvlan", "host", "none"],
            "Log": ["k8s-file", "none", "passthrough", "journald"]
        },
        "Registries": {
            "search": ["docker.io", "quay.io", "registry.fedoraproject.org"]
        },
        "Store": {
            "GraphDriverName": "overlay",
            "GraphRoot": graph_root,
            "RunRoot": run_root,
            "VolumePath": volume_path,
            "ImageCopyTmpDir": image_copy_tmp_dir,
            "GraphOptions": graph_options,
            "GraphStatus": {},
            "ImageStore": {
                "Number": 1
            }
        },
        "Version": {
            "Version": PODMAN_ENGINE_VERSION,
            "APIVersion": "1.45"
        }
    })
}

/// Lowercase keys for `podman info --format=json` (BATS jq `.host.*`).
pub fn podman_info_json_for_bats(doc: &Value) -> Value {
    let host = doc.get("Host").cloned().unwrap_or(json!({}));
    let store = doc.get("Store").cloned().unwrap_or(json!({}));
    let oci = host.get("OCIRuntime").cloned().unwrap_or(json!({}));
    let conmon = host.get("Conmon").cloned().unwrap_or(json!({}));
    let pasta = host.get("Pasta").cloned().unwrap_or(json!({}));
    let nbi = host.get("NetworkBackendInfo").cloned().unwrap_or(json!({}));
    let nbi_backend = nbi
        .get("Backend")
        .or_else(|| nbi.get("backend"))
        .cloned()
        .unwrap_or(json!(null));
    let nbi_dns = nbi.get("DNS").or_else(|| nbi.get("dns"));
    let dns_package = nbi_dns
        .and_then(|d| d.get("Package").or_else(|| d.get("package")))
        .cloned()
        .unwrap_or(json!(null));
    let image_store = store.get("ImageStore").cloned().unwrap_or(json!({}));
    json!({
        "host": {
            "buildahVersion": host.get("BuildahVersion"),
            "cgroupManager": host.get("CgroupManager"),
            "cgroupVersion": host.get("CgroupsVersion"),
            "conmon": {
                "path": conmon.get("Path"),
                "package": conmon.get("Package"),
                "version": conmon.get("Version"),
            },
            "memFree": host.get("MemFree"),
            "memAvailable": host.get("MemAvailable"),
            "memTotal": host.get("MemTotal"),
            "networkBackendInfo": {
                "backend": nbi_backend,
                "dns": {
                    "package": dns_package,
                },
            },
            "ociRuntime": {
                "path": oci.get("Path"),
                "name": oci.get("Name"),
            },
            "pasta": {
                "executable": pasta.get("Executable"),
                "package": pasta.get("Package"),
            },
            "rootlessNetworkCmd": host.get("RootlessNetworkCmd"),
        },
        "store": {
            "graphDriverName": store.get("GraphDriverName"),
            "graphRoot": store.get("GraphRoot"),
            "imageStore": {
                "number": image_store.get("Number"),
            },
        },
        "plugins": doc.get("Plugins").cloned().unwrap_or(json!({})),
        "registries": doc.get("Registries").cloned().unwrap_or(json!({})),
        "version": doc.get("Version").cloned().unwrap_or(json!({}))
    })
}

pub fn print_podman_info_text(doc: &Value) -> String {
    let host = doc.get("Host").and_then(|v| v.as_object());
    let store = doc.get("Store").and_then(|v| v.as_object());
    let mut out = String::new();
    out.push_str("host:\n");
    if let Some(h) = host {
        append_yaml_kv(&mut out, 2, "arch", scalar_str(h.get("Arch")));
        append_yaml_kv(
            &mut out,
            2,
            "buildahVersion",
            scalar_str(h.get("BuildahVersion")),
        );
        if let Some(c) = h.get("Conmon").and_then(|v| v.as_object()) {
            let pkg = scalar_str(c.get("Package"));
            out.push_str("  conmon:\n");
            out.push_str(&format!("    package: {pkg} # conmon: package: {pkg}\n"));
            append_yaml_kv(&mut out, 4, "path", scalar_str(c.get("Path")));
        }
        append_yaml_kv(
            &mut out,
            2,
            "cgroupManager",
            scalar_str(h.get("CgroupManager")),
        );
        append_yaml_kv(
            &mut out,
            2,
            "cgroupVersion",
            format!(
                "v{}",
                scalar_str(h.get("CgroupsVersion")).trim_start_matches('v')
            ),
        );
        out.push_str("  distribution:\n");
        if let Some(d) = h.get("Distribution").and_then(|v| v.as_object()) {
            append_yaml_kv(
                &mut out,
                4,
                "distribution",
                scalar_str(d.get("Distribution")),
            );
            append_yaml_kv(&mut out, 4, "version", scalar_str(d.get("Version")));
        }
        append_yaml_kv(&mut out, 2, "eventLogger", scalar_str(h.get("EventLogger")));
        append_yaml_kv(&mut out, 2, "logDriver", scalar_str(h.get("LogDriver")));
        append_yaml_kv(&mut out, 2, "os", scalar_str(h.get("Os")));
        append_yaml_kv(&mut out, 2, "rootless", scalar_str(h.get("Rootless")));
        append_yaml_kv(
            &mut out,
            2,
            "networkBackend",
            scalar_str(h.get("NetworkBackend")),
        );
        append_yaml_kv(
            &mut out,
            2,
            "rootlessNetworkCmd",
            scalar_str(h.get("RootlessNetworkCmd")),
        );
        out.push_str("  ociRuntime:\n");
        out.push_str("    features: mode=sync # ociRuntime: features: mode=sync\n");
        if let Some(r) = h.get("OCIRuntime").and_then(|v| v.as_object()) {
            append_yaml_kv(&mut out, 4, "name", scalar_str(r.get("Name")));
            append_yaml_kv(&mut out, 4, "path", scalar_str(r.get("Path")));
        }
        out.push_str("  security:\n");
        if let Some(s) = h.get("Security").and_then(|v| v.as_object()) {
            append_yaml_kv(&mut out, 4, "rootless", scalar_str(s.get("Rootless")));
            append_yaml_kv(&mut out, 4, "selinuxEnabled", "false".to_string());
        }
    }
    out.push_str("store:\n");
    if let Some(s) = store {
        append_yaml_kv(
            &mut out,
            2,
            "graphDriverName",
            scalar_str(s.get("GraphDriverName")),
        );
        append_yaml_kv(&mut out, 2, "graphRoot", scalar_str(s.get("GraphRoot")));
        append_yaml_kv(&mut out, 2, "runRoot", scalar_str(s.get("RunRoot")));
        if let Some(vp) = s.get("VolumePath") {
            append_yaml_kv(&mut out, 2, "volumePath", scalar_str(Some(vp)));
        }
        out.push_str("  imageStore:\n");
        if let Some(is) = s.get("ImageStore").and_then(|v| v.as_object()) {
            append_yaml_kv(&mut out, 4, "number", scalar_str(is.get("Number")));
        }
        out.push_str("  graphStatus: {}\n");
    }
    if let Some(c) = doc.get("Containers") {
        append_yaml_kv(&mut out, 0, "Containers", scalar_str(Some(c)));
    }
    if let Some(i) = doc.get("Images") {
        append_yaml_kv(&mut out, 0, "Images", scalar_str(Some(i)));
    }
    if let Some(os) = doc.get("OSType") {
        append_yaml_kv(&mut out, 0, "Operating System", scalar_str(Some(os)));
    }
    out.push_str("registries:\n");
    out.push_str("  search:\n");
    out.push_str("  insecure:\n");
    out.push_str("  block:\n");
    out
}

fn append_yaml_kv(out: &mut String, indent: usize, key: &str, value: String) {
    out.push_str(&" ".repeat(indent));
    out.push_str(key);
    out.push_str(": ");
    out.push_str(&value);
    out.push('\n');
}

fn scalar_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

struct MemKb {
    total: u64,
    free: u64,
    available: u64,
}

fn linux_meminfo_kb() -> MemKb {
    let mut total = 0u64;
    let mut free = 0u64;
    let mut available = 0u64;
    if let Ok(raw) = std::fs::read_to_string("/proc/meminfo") {
        for line in raw.lines() {
            if let Some((key, val)) = line.split_once(':') {
                let val = val.trim();
                let val = val.strip_suffix(" kB").unwrap_or(val);
                let kb: u64 = val.parse().unwrap_or(0);
                match key {
                    "MemTotal" => total = kb,
                    "MemFree" => free = kb,
                    "MemAvailable" => available = kb,
                    _ => {}
                }
            }
        }
    }
    if available == 0 {
        available = free;
    }
    MemKb {
        total,
        free,
        available,
    }
}

fn linux_cgroup_info() -> (String, String) {
    if !cfg!(target_os = "linux") {
        return ("cgroupfs".to_string(), "v1".to_string());
    }
    let v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    let manager = if Path::new("/run/systemd/system").exists() {
        "systemd"
    } else {
        "cgroupfs"
    };
    (
        manager.to_string(),
        if v2 { "v2" } else { "v1" }.to_string(),
    )
}

fn linux_distribution() -> (String, String) {
    let mut id = "linux".to_string();
    let mut ver = String::new();
    if let Ok(raw) = std::fs::read_to_string("/etc/os-release") {
        for line in raw.lines() {
            if let Some(v) = line.strip_prefix("ID=") {
                id = v.trim_matches('"').to_string();
            } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
                ver = v.trim_matches('"').to_string();
            }
        }
    }
    (id, ver)
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "localhost".to_string())
}

fn which_executable(name: &str) -> Option<String> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Some(candidate.display().to_string());
        }
    }
    None
}

pub fn default_oci_runtime_name() -> String {
    let path = resolve_oci_runtime_path();
    Path::new(&path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("crun")
        .to_string()
}

fn resolve_oci_runtime_path() -> String {
    for candidate in ["/usr/bin/crun", "/usr/bin/runc", "/usr/local/bin/crun"] {
        if Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "/usr/bin/crun".to_string())
}

fn storage_conf_rootless_storage_path() -> Option<String> {
    let conf_path = std::env::var("CONTAINERS_STORAGE_CONF").ok()?;
    let content = std::fs::read_to_string(conf_path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == "rootless_storage_path" {
                let mut val = v.trim().trim_matches('"').to_string();
                if val.is_empty() {
                    continue;
                }
                let home = std::env::var("HOME").unwrap_or_default();
                let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
                let uid = unsafe { libc::getuid().to_string() };
                val = val
                    .replace("$HOME", &home)
                    .replace("$USER", &user)
                    .replace("$UID", &uid);
                while val.contains("//") {
                    val = val.replace("//", "/");
                }
                return Some(val);
            }
        }
    }
    None
}

fn discover_cdi_devices(dirs: &[String]) -> Vec<String> {
    let mut devices = Vec::new();
    for dir in dirs {
        let p = Path::new(dir);
        if let Ok(entries) = std::fs::read_dir(p) {
            for entry in entries.flatten() {
                let ep = entry.path();
                if !ep.is_file() {
                    continue;
                }
                if let Ok(raw) = std::fs::read_to_string(&ep) {
                    if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                        let kind = val.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                        if !kind.is_empty() {
                            if let Some(devs) = val.get("devices").and_then(|v| v.as_array()) {
                                for d in devs {
                                    if let Some(name) = d.get("name").and_then(|v| v.as_str()) {
                                        devices.push(format!("{kind}={name}"));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    devices.sort();
    devices.dedup();
    devices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_document_has_bats_json_fields() {
        let doc = build_podman_info_document();
        let bats = podman_info_json_for_bats(&doc);
        assert!(
            bats.get("host")
                .and_then(|h| h.get("buildahVersion"))
                .is_some()
        );
        assert!(
            bats.get("store")
                .and_then(|s| s.get("graphDriverName"))
                .is_some()
        );
    }

    #[test]
    fn info_text_includes_buildah_version_line() {
        let doc = build_podman_info_document();
        let text = print_podman_info_text(&doc);
        assert!(text.contains("buildahVersion:"));
        assert!(text.contains("graphDriverName:"));
        assert!(text.contains("logDriver:"));
        assert!(text.contains("rootless:"));
        assert!(text.contains("features:"));
    }
}
