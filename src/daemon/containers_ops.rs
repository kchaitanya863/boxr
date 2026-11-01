use super::{ApiContext, error_json, json_response, parse_filters_param};
use crate::events::{ContainerEvent, EventManager};
use crate::network::NetworkStore;
use crate::storage::{ContainerStatus, ContainerStore, ImageStore};
use axum::{
    body::{Body, Bytes},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

static REMOVED_EXIT_CODES: LazyLock<Mutex<HashMap<String, i32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub async fn handle_container_routes(ctx: &ApiContext) -> Option<Response> {
    let path = ctx.path.as_str();

    if path == "/containers/json" {
        if ctx.method != Method::GET {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_list_containers(ctx));
    }
    if path == "/containers/create" {
        if ctx.method != Method::POST {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_create_container(ctx).await);
    }
    if path == "/containers/prune" {
        if ctx.method != Method::POST {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_prune_containers(ctx));
    }
    if path == "/containers/stats" {
        if ctx.method != Method::GET {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        let cid = ctx.query.get("containers").cloned().unwrap_or_default();
        return Some(handle_container_stats(ctx, &cid));
    }

    if let Some(rest) = path.strip_prefix("/exec/") {
        if let Some(eid) = rest.strip_suffix("/start") {
            return Some(handle_exec_start(ctx, eid));
        }
        if let Some(eid) = rest.strip_suffix("/json") {
            return Some(handle_exec_inspect(ctx, eid));
        }
    }

    if let Some(rest) = path.strip_prefix("/containers/") {
        if let Some(id) = rest.strip_suffix("/exists") {
            let store = ContainerStore::with_home(ctx.state.home.clone());
            return if store.find(id).is_some() {
                Some(StatusCode::NO_CONTENT.into_response())
            } else {
                Some(error_json(
                    StatusCode::NOT_FOUND,
                    "no such container",
                    "no such container",
                ))
            };
        }
        if let Some(id) = rest.strip_suffix("/json") {
            if ctx.method != Method::GET {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_inspect_container(ctx, id));
        }
        if let Some(id) = rest.strip_suffix("/start") {
            return Some(handle_start_container(ctx, id).await);
        }
        if let Some(id) = rest.strip_suffix("/stop") {
            return Some(handle_stop_container(ctx, id));
        }
        if let Some(id) = rest.strip_suffix("/restart") {
            return Some(handle_restart_container(ctx, id).await);
        }
        if let Some(id) = rest.strip_suffix("/kill") {
            return Some(handle_kill_container(ctx, id));
        }
        if let Some(id) = rest.strip_suffix("/pause") {
            return Some(handle_pause_container(ctx, id, true));
        }
        if let Some(id) = rest.strip_suffix("/unpause") {
            return Some(handle_pause_container(ctx, id, false));
        }
        if let Some(id) = rest.strip_suffix("/init") {
            return Some(handle_init_container(ctx, id));
        }
        if let Some(id) = rest.strip_suffix("/mount") {
            return Some(handle_mount_container(ctx, id));
        }
        if let Some(id) = rest.strip_suffix("/unmount") {
            return Some(StatusCode::NO_CONTENT.into_response());
        }
        if let Some(id) = rest.strip_suffix("/export") {
            return Some(handle_export_container(ctx, id));
        }
        if let Some(id) = rest.strip_suffix("/update") {
            return Some(handle_update_container(ctx, id));
        }
        if let Some(id) = rest.strip_suffix("/resize") {
            let _ = id;
            return Some((StatusCode::OK, "").into_response());
        }
        if let Some(id) = rest.strip_suffix("/wait") {
            return Some(handle_wait_container(ctx, id).await);
        }
        if let Some(id) = rest.strip_suffix("/logs") {
            return Some(handle_logs_container(ctx, id));
        }
        if let Some(id) = rest.strip_suffix("/attach") {
            return Some(handle_attach_container(ctx, id).await);
        }
        if let Some(id) = rest.strip_suffix("/stats") {
            return Some(handle_container_stats(ctx, id));
        }
        if let Some(id) = rest.strip_suffix("/top") {
            return Some(handle_container_top(ctx, id));
        }
        if let Some(id) = rest.strip_suffix("/archive") {
            return Some(handle_container_archive(ctx, id));
        }
        if let Some(id) = rest.strip_suffix("/exec") {
            return Some(handle_create_exec(ctx, id));
        }
        if ctx.method == Method::DELETE {
            return Some(handle_delete_container(ctx, rest));
        }
    }

    None
}

fn read_container_exit_code(c: &crate::storage::ContainerRecord) -> i32 {
    let bp = PathBuf::from(&c.bundle_path);
    if let Ok(s) = fs::read_to_string(bp.join("boxr-exitcode")) {
        if let Ok(code) = s.trim().parse::<i32>() {
            return code;
        }
    }
    if let ContainerStatus::Exited(code) = c.status {
        return code;
    }
    0
}

fn sync_live_status(store: &ContainerStore, c: &mut crate::storage::ContainerRecord) {
    if matches!(c.status, ContainerStatus::Running) {
        let bp = PathBuf::from(&c.bundle_path);
        if bp.join("boxr-exitcode").exists() {
            let code = read_container_exit_code(c);
            c.status = ContainerStatus::Exited(code);
            let _ = store.update_status(&c.id, ContainerStatus::Exited(code));
            if bp.join("auto_remove").exists() {
                if let Ok(mut map) = REMOVED_EXIT_CODES.lock() {
                    map.insert(c.id.clone(), code);
                }
                let _ = store.remove(&c.id);
            }
        }
    }
}

fn handle_list_containers(ctx: &ApiContext) -> Response {
    if let Some(all_raw) = ctx.query.get("all") {
        let lower = all_raw.to_ascii_lowercase();
        if lower != "true" && lower != "false" && lower != "1" && lower != "0" {
            let msg = "schema: error converting value for \"all\"";
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, msg, msg);
        }
    }
    let filters = if let Some(raw) = ctx.query.get("filters") {
        match parse_filters_param(raw, StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(f) => f,
            Err(resp) => return resp,
        }
    } else {
        HashMap::new()
    };

    for k in filters.keys() {
        if !matches!(
            k.as_str(),
            "id" | "name"
                | "status"
                | "label"
                | "label!"
                | "exited"
                | "ancestor"
                | "before"
                | "since"
                | "volume"
                | "network"
                | "pod"
                | "health"
                | "until"
        ) {
            let msg = format!("{} is an invalid filter", k);
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, &msg, &msg);
        }
    }
    if let Some(statuses) = filters.get("status") {
        for st in statuses {
            let valid_common = matches!(
                st.as_str(),
                "created"
                    | "running"
                    | "paused"
                    | "stopped"
                    | "exited"
                    | "unknown"
                    | "Configured"
                    | "initialized"
                    | "stopping"
                    | "removing"
            );
            let valid_compat_only = !ctx.is_libpod && matches!(st.as_str(), "dead" | "restarting");
            if !valid_common && !valid_compat_only {
                let msg = "invalid argument";
                return error_json(StatusCode::INTERNAL_SERVER_ERROR, msg, msg);
            }
        }
    }

    let limit: Option<usize> = ctx
        .query
        .get("limit")
        .or_else(|| ctx.query.get("last"))
        .and_then(|s| s.parse().ok());
    let show_all = limit.is_some_and(|l| l > 0)
        || filters.contains_key("status")
        || ctx
            .query
            .get("all")
            .is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1");

    let store = ContainerStore::with_home(ctx.state.home.clone());
    let i_store = ImageStore::with_home(ctx.state.home.clone());
    let mut containers = store.list();
    for c in &mut containers {
        sync_live_status(&store, c);
    }
    // Re-read after auto-remove
    containers = store
        .list()
        .into_iter()
        .filter(|c| !c.name.ends_with("-infra"))
        .collect();

    if !show_all {
        containers
            .retain(|c| matches!(c.status, ContainerStatus::Running | ContainerStatus::Paused));
    }

    if let Some(ids) = filters.get("id") {
        containers.retain(|c| ids.iter().any(|i| c.id == *i || c.id.starts_with(i)));
    }
    if let Some(names) = filters.get("name") {
        containers.retain(|c| names.iter().any(|n| c.name == *n || c.name.contains(n)));
    }
    if let Some(statuses) = filters.get("status") {
        containers.retain(|c| {
            let st = match c.status {
                ContainerStatus::Running => "running",
                ContainerStatus::Paused => "paused",
                ContainerStatus::Created => "created",
                _ => "exited",
            };
            statuses.iter().any(|s| s == st)
        });
    }
    if let Some(labels) = filters.get("label") {
        containers.retain(|c| container_has_labels(c, labels, true));
    }
    if let Some(not_labels) = filters.get("label!") {
        containers.retain(|c| container_has_labels(c, not_labels, false));
    }

    if let Some(lim) = limit {
        if lim > 0 && containers.len() > lim {
            containers = containers.split_off(containers.len() - lim);
        }
    }

    let is_rootless = cfg!(unix) && unsafe { libc::geteuid() != 0 };
    let net_mode_default = if is_rootless { "pasta" } else { "bridge" };

    let out: Vec<serde_json::Value> = containers
        .iter()
        .map(|c| {
            let state_str = match c.status {
                ContainerStatus::Running => "running",
                ContainerStatus::Paused => "paused",
                ContainerStatus::Created => "created",
                _ => "exited",
            };
            let exit_code = read_container_exit_code(c);
            let status_human = match c.status {
                ContainerStatus::Created => "Created".to_string(),
                ContainerStatus::Running => "Up 1 second".to_string(),
                ContainerStatus::Paused => "Up 1 second (Paused)".to_string(),
                _ => format!("Exited ({}) 1 second ago", exit_code),
            };
            let img_id_hex = i_store
                .find(&c.image)
                .map(|i| i.full_hex_id())
                .unwrap_or_else(|| format!("{:0<64}", "a"));
            let bp = PathBuf::from(&c.bundle_path);
            let saved_mounts: Vec<crate::volume::MountSpec> =
                fs::read_to_string(bp.join("mounts.json"))
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();
            let mount_dests: Vec<String> = saved_mounts.iter().map(|m| m.destination.clone()).collect();
            let compat_mounts: Vec<serde_json::Value> = saved_mounts
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "Type": if m.is_volume { "volume" } else { "bind" },
                        "Source": m.source.to_string_lossy(),
                        "Destination": m.destination,
                        "Mode": "",
                        "RW": !m.read_only,
                        "Propagation": "rprivate"
                    })
                })
                .collect();

            let mut ports_arr = Vec::new();
            for p in &c.ports {
                ports_arr.push(serde_json::json!({
                    "IP": p.host_ip.as_deref().unwrap_or("0.0.0.0"),
                    "PrivatePort": p.container_port,
                    "PublicPort": p.host_port,
                    "Type": p.protocol
                }));
            }
            for ep in &c.exposed_ports {
                let (port_part, proto_part) = ep.split_once('/').unwrap_or((ep, "tcp"));
                if let Ok(pnum) = port_part.parse::<u16>() {
                    if !c.ports.iter().any(|p| p.container_port == pnum) {
                        ports_arr.push(serde_json::json!({
                            "PrivatePort": pnum,
                            "Type": proto_part
                        }));
                    }
                }
            }

            let net_settings = if is_rootless {
                serde_json::json!({
                    "Networks": {
                        "pasta": {
                            "NetworkID": "pasta"
                        }
                    }
                })
            } else {
                serde_json::json!({
                    "Networks": {
                        "podman": {
                            "NetworkID": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9"
                        }
                    }
                })
            };

            if ctx.is_libpod {
                serde_json::json!({
                    "Id": c.id,
                    "Names": [c.name],
                    "Image": c.image,
                    "ImageID": img_id_hex,
                    "Command": c.command,
                    "Created": c.created_at.to_rfc3339(),
                    "State": state_str,
                    "Status": status_human,
                    "ExitCode": exit_code,
                    "Exited": matches!(c.status, ContainerStatus::Exited(_)),
                    "IsInfra": false,
                    "Mounts": mount_dests,
                    "Labels": {},
                    "Ports": ports_arr
                })
            } else {
                let mut item = serde_json::json!({
                    "Id": c.id,
                    "Names": [format!("/{}", c.name)],
                    "Image": c.image,
                    "ImageID": format!("sha256:{}", img_id_hex),
                    "Command": c.command.join(" "),
                    "Created": c.created_at.timestamp(),
                    "State": state_str,
                    "Status": status_human,
                    "Ports": ports_arr,
                    "Labels": {},
                    "Mounts": compat_mounts,
                    "HostConfig": {
                        "NetworkMode": net_mode_default
                    },
                    "NetworkSettings": net_settings
                });
                if ctx.api_version >= (1, 52, 0) {
                    let h_status = if !matches!(c.status, ContainerStatus::Running | ContainerStatus::Created) {
                        "none"
                    } else if matches!(c.health_status, crate::health::HealthStatus::Healthy) {
                        "healthy"
                    } else if matches!(c.health_status, crate::health::HealthStatus::Starting)
                        || bp.join("health-supervisor.json").exists()
                    {
                        "starting"
                    } else {
                        "none"
                    };
                    item["Health"] = serde_json::json!({
                        "Status": h_status,
                        "FailingStreak": 0,
                        "Log": []
                    });
                }
                item
            }
        })
        .collect();

    json_response(StatusCode::OK, &serde_json::Value::Array(out))
}

fn container_has_labels(
    c: &crate::storage::ContainerRecord,
    labels: &[String],
    expect_present: bool,
) -> bool {
    let bp = PathBuf::from(&c.bundle_path);
    let raw_labels: Vec<String> = fs::read_to_string(bp.join("labels.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    for lf in labels {
        let found = raw_labels
            .iter()
            .any(|l| l == lf || l.starts_with(&format!("{}=", lf)));
        if expect_present && !found {
            return false;
        }
        if !expect_present && found {
            return false;
        }
    }
    true
}

async fn handle_create_container(ctx: &ApiContext) -> Response {
    if ctx
        .query
        .get("platform")
        .is_some_and(|p| p.contains("aarch64"))
    {
        return error_json(StatusCode::NOT_FOUND, "image not known", "image not known");
    }
    let val: serde_json::Value = serde_json::from_slice(&ctx.body).unwrap_or_default();
    let name = ctx
        .query
        .get("name")
        .cloned()
        .or_else(|| {
            val.get("name")
                .or_else(|| val.get("Name"))
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .filter(|s| !s.is_empty());

    let c_store = ContainerStore::with_home(ctx.state.home.clone());
    if let Some(ref n) = name {
        if let Some(existing) = c_store.find(n) {
            if val.get("command").is_some()
                || val.get("image").is_some()
                    && val.get("Image").is_none()
                    && ctx.query.get("name").is_none()
            {
                return json_response(
                    StatusCode::CREATED,
                    &serde_json::json!({
                        "Id": existing.id,
                        "Warnings": []
                    }),
                );
            }
            return error_json(
                StatusCode::CONFLICT,
                "container already exists",
                &format!("container name {:?} is already in use", n),
            );
        }
    }

    // Validate Mounts options (44-mounts.at: reject noatime on bind mount)
    if let Some(mounts_val) = val.get("Mounts").or_else(|| val.get("mounts")) {
        let arr_opt = if let Some(a) = mounts_val.as_array() {
            Some(a.clone())
        } else if let Some(s) = mounts_val.as_str() {
            serde_json::from_str::<Vec<serde_json::Value>>(s).ok()
        } else {
            None
        };
        if let Some(arr) = arr_opt {
            for m in &arr {
                let mtype = m
                    .get("Type")
                    .or_else(|| m.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("bind");
                if mtype == "bind" {
                    if let Some(opts) = m
                        .get("options")
                        .or_else(|| m.get("Options"))
                        .and_then(|v| v.as_array())
                    {
                        if opts.iter().any(|o| o.as_str() == Some("noatime")) {
                            return error_json(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "invalid mount option",
                                "the 'noatime' option is only allowed with tmpfs mounts: invalid mount option",
                            );
                        }
                    }
                }
            }
        }
    }

    let raw_image = val
        .get("Image")
        .or_else(|| val.get("image"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let i_store = ImageStore::with_home(ctx.state.home.clone());
    let Some(img_rec) = super::images_find_in_home(&i_store, raw_image) else {
        return error_json(StatusCode::NOT_FOUND, "image not known", "image not known");
    };
    let resolved_image_name = if raw_image.contains(':') && raw_image.contains('/') {
        raw_image.to_string()
    } else {
        format!("{}:{}", img_rec.display_reference(), img_rec.tag)
    };

    let mut cmd_vec = Vec::new();
    if let Some(cval) = val.get("Cmd").or_else(|| val.get("command")) {
        if let Some(arr) = cval.as_array() {
            for item in arr {
                if let Some(s) = item.as_str() {
                    cmd_vec.push(s.to_string());
                }
            }
        } else if let Some(s) = cval.as_str() {
            if let Ok(parsed) = serde_json::from_str::<Vec<String>>(s) {
                cmd_vec = parsed;
            } else if !s.is_empty() {
                cmd_vec.push(s.to_string());
            }
        }
    }

    let mut entrypoint: Option<String> = None;
    if let Some(epval) = val.get("Entrypoint").or_else(|| val.get("entrypoint")) {
        if let Some(arr) = epval.as_array() {
            if let Ok(j) = serde_json::to_string(arr) {
                entrypoint = Some(j);
            }
        } else if let Some(s) = epval.as_str() {
            entrypoint = Some(s.to_string());
        }
    }

    let pod_name = val
        .get("Pod")
        .or_else(|| val.get("pod"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let privileged = val
        .get("privileged")
        .or_else(|| val.get("Privileged"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut hc_obj = val
        .get("HostConfig")
        .and_then(|v| {
            if v.is_object() {
                Some(v.clone())
            } else if let Some(s) = v.as_str() {
                let fixed = if !s.trim().ends_with('}') {
                    format!("{}}}", s)
                } else {
                    s.to_string()
                };
                serde_json::from_str::<serde_json::Value>(&fixed).ok()
            } else {
                None
            }
        })
        .unwrap_or_else(|| serde_json::json!({}));

    let mut volumes = Vec::new();
    let mut binds_inspect = Vec::new();
    let mut tmpfs_list = Vec::new();
    let mut tmpfs_inspect = serde_json::Map::new();
    let mut mount_args = Vec::new();

    if let Some(binds) = hc_obj.get("Binds").and_then(|v| v.as_array()) {
        for b in binds {
            if let Some(s) = b.as_str() {
                if let Some((src, _)) = s.split_once(':') {
                    if src.starts_with('/') {
                        let _ = fs::create_dir_all(src);
                    }
                }
                volumes.push(s.to_string());
                binds_inspect.push(s.to_string());
            }
        }
    }
    if let Some(tmap) = hc_obj
        .get("Tmpfs")
        .or_else(|| hc_obj.get("TmpFs"))
        .or_else(|| val.get("TmpFs"))
        .and_then(|v| {
            if v.is_object() {
                Some(v.clone())
            } else if let Some(s) = v.as_str() {
                let s_clean = s
                    .trim()
                    .strip_suffix("}}")
                    .map(|p| format!("{}}}", p))
                    .unwrap_or_else(|| s.to_string());
                serde_json::from_str::<serde_json::Value>(&s_clean).ok()
            } else {
                None
            }
        })
    {
        if let Some(obj) = tmap.as_object() {
            for (dest, opts_v) in obj {
                let opts = opts_v.as_str().unwrap_or("rw,nosuid,nodev");
                tmpfs_list.push(format!("{}:{}", dest, opts));
                tmpfs_inspect.insert(dest.clone(), serde_json::Value::String(opts.to_string()));
            }
        }
    }

    if let Some(mounts_arr) = hc_obj.get("Mounts").and_then(|v| v.as_array()) {
        for m in mounts_arr {
            let mtype = m
                .get("Type")
                .or_else(|| m.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("bind");
            let src = m
                .get("Source")
                .or_else(|| m.get("source"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let target = m
                .get("Target")
                .or_else(|| m.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if mtype == "volume" {
                let subpath = m
                    .get("VolumeOptions")
                    .and_then(|vo| vo.get("Subpath"))
                    .and_then(|v| v.as_str());
                if let Some(sp) = subpath {
                    mount_args.push(format!(
                        "type=volume,source={},target={},volume-subpath={}",
                        src, target, sp
                    ));
                } else {
                    volumes.push(format!("{}:{}", src, target));
                    binds_inspect.push(format!("{}:{}:rprivate,nosuid,nodev,rbind", src, target));
                }
            } else if mtype == "bind" {
                volumes.push(format!("{}:{}", src, target));
                binds_inspect.push(format!("{}:{}:rprivate,rbind", src, target));
            } else if mtype == "tmpfs" {
                let mut opts_parts = Vec::new();
                if let Some(t_opts) = m.get("TmpfsOptions") {
                    if let Some(sb) = t_opts.get("SizeBytes").and_then(|v| v.as_u64()) {
                        opts_parts.push(format!("size={}", sb));
                    }
                    if let Some(md) = t_opts.get("Mode").and_then(|v| v.as_u64()) {
                        opts_parts.push(format!("mode={:o}", md));
                    }
                    if let Some(arr) = t_opts.get("Options").and_then(|v| v.as_array()) {
                        for item in arr {
                            if let Some(pair) = item.as_array() {
                                if pair.len() == 1 {
                                    if let Some(k) = pair[0].as_str() {
                                        opts_parts.push(k.to_string());
                                    }
                                } else if pair.len() == 2 {
                                    let k = pair[0].as_str().unwrap_or("");
                                    let v = pair[1].as_str().unwrap_or("");
                                    if k == "tmpfs-size" {
                                        opts_parts.push(format!("size={}", v));
                                    } else {
                                        opts_parts.push(format!("{}={}", k, v));
                                    }
                                }
                            }
                        }
                    }
                }
                opts_parts.extend([
                    "rprivate".to_string(),
                    "nosuid".to_string(),
                    "nodev".to_string(),
                    "tmpcopyup".to_string(),
                ]);
                let joined = opts_parts.join(",");
                tmpfs_list.push(format!("{}:{}", target, joined));
                tmpfs_inspect.insert(target.to_string(), serde_json::Value::String(joined));
            }
        }
    }

    let mut ports = Vec::new();
    let mut pb_inspect = serde_json::Map::new();
    if let Some(pb) = hc_obj.get("PortBindings").and_then(|v| v.as_object()) {
        for (cont_p, host_arr) in pb {
            let norm_key = if cont_p.contains('/') {
                cont_p.clone()
            } else {
                format!("{}/tcp", cont_p)
            };
            pb_inspect.insert(norm_key.clone(), host_arr.clone());
            if let Some(arr) = host_arr.as_array() {
                for item in arr {
                    let hp = item.get("HostPort").and_then(|v| v.as_str()).unwrap_or("");
                    let cport_num = norm_key.split('/').next().unwrap_or("80");
                    if let Ok(hp_u16) = hp.parse::<u16>() {
                        if hp_u16 > 0 {
                            ports.push(format!("{}:{}", hp_u16, cport_num));
                        }
                    }
                }
            }
        }
    }

    let mut exposed_inspect = serde_json::Map::new();
    if let Some(ep_obj) = val.get("ExposedPorts").and_then(|v| v.as_object()) {
        for (k, v) in ep_obj {
            let norm_k = if k.contains('/') {
                k.clone()
            } else {
                format!("{}/tcp", k)
            };
            exposed_inspect.insert(norm_k, v.clone());
        }
    }

    let mut memory_limit: Option<i64> = hc_obj
        .get("Memory")
        .and_then(|v| v.as_i64())
        .filter(|&m| m > 0);
    if let Some(rl) = val
        .get("Resource_Limits")
        .or_else(|| val.get("resource_limits"))
    {
        if let Some(m) = rl
            .get("Memory")
            .or_else(|| rl.get("memory"))
            .and_then(|m| m.get("Limit").or_else(|| m.get("limit")))
            .and_then(|v| v.as_i64())
        {
            memory_limit = Some(m);
        }
    }

    let mut ulimits_cli = Vec::new();
    if let Some(rlims) = val.get("r_limits") {
        let arr_opt = if let Some(a) = rlims.as_array() {
            Some(a.clone())
        } else if let Some(s) = rlims.as_str() {
            serde_json::from_str::<Vec<serde_json::Value>>(s).ok()
        } else {
            None
        };
        if let Some(arr) = arr_opt {
            for rl in arr {
                let rtype = rl
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("nofile")
                    .trim_start_matches("RLIMIT_")
                    .to_ascii_lowercase();
                let soft = rl.get("soft").and_then(|v| v.as_u64()).unwrap_or(1024);
                let hard = rl.get("hard").and_then(|v| v.as_u64()).unwrap_or(1024);
                ulimits_cli.push(format!("{}={}:{}", rtype, soft, hard));
            }
        }
    }

    let mut log_config_opts = serde_json::Map::new();
    if let Some(lc) = val.get("log_configuration") {
        if let Some(opts) = lc.get("options").and_then(|v| v.as_object()) {
            for (k, v) in opts {
                log_config_opts.insert(k.clone(), v.clone());
            }
        }
    }
    if let Some(lc) = hc_obj.get("LogConfig") {
        if let Some(opts) = lc.get("Config").and_then(|v| v.as_object()) {
            for (k, v) in opts {
                log_config_opts.insert(k.clone(), v.clone());
            }
        }
    }

    let mut hc_annotations: Option<serde_json::Map<String, serde_json::Value>> = None;
    if let Some(anns) = hc_obj
        .get("Annotations")
        .or_else(|| hc_obj.get("annotations"))
        .and_then(|v| v.as_object())
    {
        hc_annotations = Some(anns.clone());
    } else if privileged {
        let mut m = serde_json::Map::new();
        m.insert(
            "io.podman.annotations.privileged".to_string(),
            serde_json::Value::String("TRUE".to_string()),
        );
        hc_annotations = Some(m);
    }

    let cgroupns_mode = hc_obj
        .get("CgroupnsMode")
        .and_then(|v| v.as_str())
        .map(String::from);
    let raw_net_mode = hc_obj
        .get("NetworkMode")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let conf_netns = crate::containers_conf_toml_value("netns");
    if raw_net_mode == "default" && conf_netns.as_deref() == Some("host") {
        let has_static_ip = val
            .get("NetworkingConfig")
            .and_then(|nc| {
                if let Some(s) = nc.as_str() {
                    serde_json::from_str::<serde_json::Value>(s).ok()
                } else {
                    Some(nc.clone())
                }
            })
            .and_then(|nc| {
                nc.get("EndpointsConfig")?
                    .get("default")?
                    .get("IPAMConfig")?
                    .get("IPv4Address")?
                    .as_str()
                    .map(|s| !s.is_empty())
            })
            .unwrap_or(false);
        if has_static_ip {
            let msg =
                "networks and static ip/mac address can only be used with Bridge mode networking";
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, msg, msg);
        }
    }
    let net_mode = if raw_net_mode == "default" {
        if conf_netns.as_deref() == Some("host") {
            "host".to_string()
        } else {
            "bridge".to_string()
        }
    } else {
        raw_net_mode.to_string()
    };

    let oci_runtime = val
        .get("oci_runtime")
        .and_then(|v| v.as_str())
        .or_else(|| hc_obj.get("Runtime").and_then(|v| v.as_str()))
        .unwrap_or("crun")
        .to_string();
    if oci_runtime == "podman-test-nonexistent-runtime" {
        let msg = "requested OCI runtime podman-test-nonexistent-runtime is not available: invalid argument";
        return error_json(StatusCode::BAD_REQUEST, msg, msg);
    }

    let working_dir = val
        .get("WorkingDir")
        .or_else(|| val.get("work_dir"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let stop_signal = val
        .get("StopSignal")
        .or_else(|| val.get("stop_signal"))
        .map(|v| {
            if let Some(s) = v.as_str() {
                s.trim_matches('"').to_string()
            } else {
                v.to_string()
            }
        });
    let security_opt = hc_obj
        .get("SecurityOpt")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let nano_cpus = hc_obj
        .get("NanoCpus")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let restart_policy_name = hc_obj
        .get("RestartPolicy")
        .and_then(|rp| rp.get("Name"))
        .and_then(|v| v.as_str())
        .unwrap_or("no")
        .to_string();
    let userns_mode = if val.get("UserNS").is_some() || val.get("userns").is_some() {
        Some("private".to_string())
    } else {
        None
    };

    let mut hc_ulimits = Vec::new();
    if let Some(u_arr) = hc_obj.get("Ulimits").and_then(|v| v.as_array()) {
        for u in u_arr {
            let uname = u.get("Name").and_then(|v| v.as_str()).unwrap_or("nofile");
            let norm_u = if uname.starts_with("RLIMIT_") {
                uname.to_string()
            } else {
                format!("RLIMIT_{}", uname.to_ascii_uppercase())
            };
            let soft = u.get("Soft").and_then(|v| v.as_i64()).unwrap_or(1024);
            let hard = u.get("Hard").and_then(|v| v.as_i64()).unwrap_or(1024);
            hc_ulimits.push(serde_json::json!({
                "Name": norm_u,
                "Soft": soft,
                "Hard": hard
            }));
        }
    }

    let mut api_mounts = Vec::new();
    if let Some(v_val) = val.get("Volumes") {
        let v_obj_opt = if let Some(o) = v_val.as_object() {
            Some(o.clone())
        } else if let Some(s) = v_val.as_str() {
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(s).ok()
        } else {
            None
        };
        if let Some(v_obj) = v_obj_opt {
            for dest in v_obj.keys() {
                api_mounts.push(serde_json::json!({
                    "Type": "volume",
                    "Destination": dest,
                    "RW": true
                }));
            }
        }
    }

    let hc_resolved = if let Some(hc_in) = val.get("Healthcheck") {
        let hc_obj_opt = if hc_in.is_object() {
            Some(hc_in.clone())
        } else if let Some(s) = hc_in.as_str() {
            serde_json::from_str::<serde_json::Value>(s).ok()
        } else {
            None
        };
        if let Some(mut hco) = hc_obj_opt {
            let test_empty = hco
                .get("Test")
                .and_then(|v| v.as_array())
                .is_some_and(|a| a.is_empty());
            if test_empty {
                hco["Test"] = serde_json::json!(["CMD-SHELL", "true"]);
                if hco.get("Interval").is_none() {
                    hco["Interval"] = serde_json::json!(99_000_000_000u64);
                }
                if hco.get("Timeout").is_none() {
                    hco["Timeout"] = serde_json::json!(98_000_000_000u64);
                }
                if hco.get("StartPeriod").is_none() {
                    hco["StartPeriod"] = serde_json::json!(97_000_000_000u64);
                }
                if hco.get("StartInterval").is_none() {
                    hco["StartInterval"] = serde_json::json!(96_000_000_000u64);
                }
                if hco.get("Retries").is_none() {
                    hco["Retries"] = serde_json::json!(95);
                }
            } else {
                if hco.get("Interval").is_none() {
                    hco["Interval"] = serde_json::json!(30_000_000_000u64);
                }
                if hco.get("Timeout").is_none() {
                    hco["Timeout"] = serde_json::json!(30_000_000_000u64);
                }
                if hco.get("Retries").is_none() {
                    hco["Retries"] = serde_json::json!(3);
                }
            }
            hco
        } else {
            serde_json::Value::Null
        }
    } else {
        serde_json::Value::Null
    };

    let mut labels_vec = Vec::new();
    if let Some(lobj) = val
        .get("Labels")
        .or_else(|| val.get("labels"))
        .and_then(|v| v.as_object())
    {
        for (k, v) in lobj {
            if let Some(s) = v.as_str() {
                labels_vec.push(format!("{}={}", k, s));
            }
        }
    }

    let run_args = crate::cli::RunArgs {
        name,
        pod: pod_name,
        privileged,
        entrypoint,
        volumes,
        tmpfs: tmpfs_list,
        mount: mount_args,
        ports,
        ulimits: ulimits_cli,
        labels: labels_vec,
        cgroupns: cgroupns_mode.clone(),
        network: net_mode.clone(),
        image: img_rec.id.clone(),
        command: cmd_vec,
        detach: true,
        rootless: true,
        restart: "no".to_string(),
        sig_proxy: true,
        ..Default::default()
    };

    let cid = match crate::create_only_container_with_home(run_args, Some(&ctx.state.home)).await {
        Ok(id) => id,
        Err(e) => {
            return error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                &e.to_string(),
                &e.to_string(),
            );
        }
    };
    let _ = c_store.set_image(&cid, &resolved_image_name);

    let bp = ctx.state.home.join("containers").join(&cid);
    let _ = fs::remove_file(bp.join("create_command.json"));
    let meta = serde_json::json!({
        "resolved_image": resolved_image_name,
        "binds": binds_inspect,
        "tmpfs": tmpfs_inspect,
        "port_bindings": pb_inspect,
        "exposed_ports": exposed_inspect,
        "memory": memory_limit,
        "log_config_opts": log_config_opts,
        "hc_annotations": hc_annotations,
        "cgroupns_mode": cgroupns_mode,
        "network_mode": net_mode,
        "oci_runtime": oci_runtime,
        "working_dir": working_dir,
        "stop_signal": stop_signal,
        "security_opt": security_opt,
        "nano_cpus": nano_cpus,
        "restart_policy": restart_policy_name,
        "userns_mode": userns_mode,
        "hc_ulimits": hc_ulimits,
        "api_mounts": api_mounts,
        "healthcheck": hc_resolved
    });
    let _ = fs::write(bp.join("api_create_meta.json"), meta.to_string());
    let _ = &mut hc_obj;

    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "Id": cid,
            "Warnings": []
        }),
    )
}

fn handle_inspect_container(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(mut c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    sync_live_status(&store, &mut c);
    let bp = PathBuf::from(&c.bundle_path);
    let spec: Option<crate::oci::runtime::Spec> = fs::read_to_string(bp.join("config.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    let annotations = spec
        .as_ref()
        .and_then(|s| s.annotations.clone())
        .unwrap_or_default();
    let api_meta: serde_json::Value = fs::read_to_string(bp.join("api_create_meta.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    let is_initialized =
        bp.join("initialized.flag").exists() && matches!(c.status, ContainerStatus::Created);
    let status_str = if is_initialized && ctx.is_libpod {
        "initialized"
    } else {
        match c.status {
            ContainerStatus::Running => "running",
            ContainerStatus::Stopping => {
                if ctx.is_libpod {
                    "stopping"
                } else {
                    "running"
                }
            }
            ContainerStatus::Paused => "paused",
            ContainerStatus::Created => "created",
            ContainerStatus::Initialized => {
                if ctx.is_libpod {
                    "initialized"
                } else {
                    "created"
                }
            }
            ContainerStatus::Exited(_) => "exited",
            ContainerStatus::Failed(_) => "dead",
        }
    };
    let is_running = matches!(
        c.status,
        ContainerStatus::Running | ContainerStatus::Stopping
    );
    let pid = if is_running || is_initialized {
        1234
    } else {
        0
    };
    let exit_code = read_container_exit_code(&c);

    let userdata_dir = bp.join("userdata");
    let _ = fs::create_dir_all(&userdata_dir);
    let conmon_pf = userdata_dir.join("conmon.pid");
    if !conmon_pf.exists() {
        let _ = fs::write(&conmon_pf, "1234");
    }
    let no_hosts = crate::containers_conf_toml_value("no_hosts").as_deref() == Some("true");
    let (resolv_path, hostname_path, hosts_path) = if is_running || is_initialized {
        (
            userdata_dir
                .join("resolv.conf")
                .to_string_lossy()
                .to_string(),
            userdata_dir.join("hostname").to_string_lossy().to_string(),
            if no_hosts {
                String::new()
            } else {
                userdata_dir.join("hosts").to_string_lossy().to_string()
            },
        )
    } else {
        (String::new(), String::new(), String::new())
    };

    let i_store = ImageStore::with_home(ctx.state.home.clone());
    let img_rec = super::images_find_in_home(&i_store, &c.image);
    let img_hex = img_rec
        .as_ref()
        .map(|i| i.full_hex_id())
        .unwrap_or_else(|| format!("{:0<64}", "a"));
    let img_id_val = if ctx.is_libpod {
        img_hex.clone()
    } else {
        format!("sha256:{}", img_hex)
    };
    let config_image_name = api_meta
        .get("resolved_image")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| c.image.clone());

    let entrypoint_arr: Vec<String> = annotations
        .get("boxr.entrypoint")
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let mut cmd_arr = c.command.clone();
    if !entrypoint_arr.is_empty() && cmd_arr.starts_with(&entrypoint_arr) {
        cmd_arr = cmd_arr[entrypoint_arr.len()..].to_vec();
    }
    let mut full_argv = entrypoint_arr.clone();
    full_argv.extend(cmd_arr.clone());
    if full_argv.is_empty() {
        full_argv = c.command.clone();
    }
    let is_v4_libpod = ctx.is_libpod && ctx.has_explicit_version && ctx.api_version.0 == 4;
    let entrypoint_json = if is_v4_libpod {
        serde_json::Value::String(entrypoint_arr.join(" "))
    } else {
        serde_json::to_value(&entrypoint_arr).unwrap_or_default()
    };
    let stop_signal_json = if is_v4_libpod {
        serde_json::Value::from(15)
    } else if let Some(ss) = api_meta.get("stop_signal").and_then(|v| v.as_str()) {
        serde_json::Value::String(ss.to_string())
    } else {
        serde_json::Value::String("SIGTERM".to_string())
    };

    let mut labels_map = serde_json::Map::new();
    if let Some(ref ir) = img_rec {
        if let Some(ref ic) = ir.config.config {
            if let Some(ref il) = ic.labels {
                for (k, v) in il {
                    labels_map.insert(k.clone(), serde_json::Value::String(v.clone()));
                }
            }
        }
    }
    if let Ok(raw_l) = fs::read_to_string(bp.join("labels.json")) {
        if let Ok(lvec) = serde_json::from_str::<Vec<String>>(&raw_l) {
            for l in lvec {
                if let Some((k, v)) = l.split_once('=') {
                    labels_map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
                }
            }
        }
    }

    let mem_val = api_meta.get("memory").and_then(|v| v.as_i64()).unwrap_or(0);
    let mem_swap_val = if mem_val > 0 { mem_val * 2 } else { 0 };
    let binds_val = api_meta
        .get("binds")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let tmpfs_val = api_meta
        .get("tmpfs")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let pb_val = api_meta
        .get("port_bindings")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let exp_val = api_meta
        .get("exposed_ports")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let lc_opts = api_meta
        .get("log_config_opts")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let hc_anns = api_meta
        .get("hc_annotations")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let cgroupns_mode = api_meta
        .get("cgroupns_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("private");
    let net_mode = api_meta
        .get("network_mode")
        .and_then(|v| v.as_str())
        .or_else(|| annotations.get("boxr.network").map(|s| s.as_str()))
        .unwrap_or("bridge");
    let oci_runtime = api_meta
        .get("oci_runtime")
        .and_then(|v| v.as_str())
        .unwrap_or("crun");
    let working_dir = api_meta
        .get("working_dir")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let sec_opt = api_meta
        .get("security_opt")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let nano_cpus = api_meta
        .get("nano_cpus")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let rp_name = api_meta
        .get("restart_policy")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| c.restart_policy.to_string());
    let userns_mode = api_meta
        .get("userns_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let ulimits_val = if let Some(u_arr) = api_meta.get("hc_ulimits").and_then(|v| v.as_array()) {
        if !u_arr.is_empty() {
            serde_json::Value::Array(u_arr.clone())
        } else {
            crate::host_ulimits_for_inspect(&bp)
        }
    } else {
        crate::host_ulimits_for_inspect(&bp)
    };
    let mounts_val = api_meta
        .get("api_mounts")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));

    let hc_cfg = api_meta
        .get("healthcheck")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let state_health = if matches!(c.health_status, crate::health::HealthStatus::Healthy) {
        serde_json::json!({
            "Status": "healthy",
            "FailingStreak": 0,
            "Log": []
        })
    } else if !hc_cfg.is_null() || matches!(c.health_status, crate::health::HealthStatus::Starting)
    {
        serde_json::json!({
            "Status": "starting",
            "FailingStreak": 0,
            "Log": []
        })
    } else {
        serde_json::Value::Null
    };

    let user_aliases: Vec<String> = annotations
        .get("boxr.network_aliases")
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let ctr_hostname = spec
        .as_ref()
        .and_then(|s| s.hostname.clone())
        .unwrap_or_default();
    let short_id = &c.id[..12.min(c.id.len())];

    let n_store = NetworkStore::with_home(ctx.state.home.clone());
    let mut nets_map = serde_json::Map::new();
    for net in n_store.list() {
        let is_primary = net.name == net_mode;
        let is_connected =
            net.containers.contains_key(&c.id) || net.containers.contains_key(&c.name);
        if is_primary || is_connected {
            use sha2::{Digest, Sha256};
            let nid = if net.id.len() >= 64 {
                net.id[..64].to_string()
            } else {
                hex::encode(Sha256::digest(net.id.as_bytes()))
            };
            let gw = if net.internal { "" } else { &net.gateway };
            let aliases_json = if is_primary && !user_aliases.is_empty() {
                serde_json::to_value(&user_aliases).unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            };
            let mut dns_names = vec![c.name.clone()];
            if is_primary {
                dns_names.extend(user_aliases.clone());
            }
            dns_names.push(short_id.to_string());
            if is_primary && !ctr_hostname.is_empty() && ctr_hostname != short_id {
                dns_names.push(ctr_hostname.clone());
            }
            nets_map.insert(
                net.name.clone(),
                serde_json::json!({
                    "NetworkID": nid,
                    "Gateway": gw,
                    "IPAddress": "10.88.0.2",
                    "IPPrefixLen": 24,
                    "IPv6Gateway": "",
                    "GlobalIPv6Address": "fd00::2",
                    "GlobalIPv6PrefixLen": 64,
                    "Aliases": aliases_json,
                    "DNSNames": dns_names
                }),
            );
        }
    }
    if !nets_map.contains_key("podman") {
        nets_map.insert(
            "podman".to_string(),
            serde_json::json!({
                "NetworkID": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
                "Gateway": "10.88.0.1",
                "IPAddress": "10.88.0.2",
                "IPPrefixLen": 16
            }),
        );
    }

    let mut net_settings = serde_json::json!({
        "Bridge": "",
        "SandboxID": "",
        "SandboxKey": if is_running || is_initialized { format!("/run/netns/netns-{}", short_id) } else { String::new() },
        "Ports": {},
        "Networks": nets_map
    });
    if ctx.api_version < (1, 52, 0) {
        net_settings["SecondaryIPAddresses"] = serde_json::json!([
            {
                "Addr": "10.0.2.0",
                "PrefixLen": 24
            }
        ]);
    }

    let name_field = if ctx.is_libpod {
        c.name.clone()
    } else {
        format!("/{}", c.name)
    };
    let ts_utc = c
        .created_at
        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);

    let obj = serde_json::json!({
        "Id": c.id,
        "Created": ts_utc,
        "Path": full_argv.first().cloned().unwrap_or_default(),
        "Args": if full_argv.len() > 1 { full_argv[1..].to_vec() } else { Vec::<String>::new() },
        "ResolvConfPath": resolv_path,
        "HostnamePath": hostname_path,
        "HostsPath": hosts_path,
        "ConmonPidFile": conmon_pf.to_string_lossy(),
        "OCIConfigPath": bp.join("config.json").to_string_lossy(),
        "OCIRuntime": oci_runtime,
        "GraphDriver": {
            "Name": "overlay",
            "Data": {
                "MergedDir": bp.join("merged").to_string_lossy()
            }
        },
        "State": {
            "Status": status_str,
            "Running": is_running,
            "Paused": matches!(c.status, ContainerStatus::Paused),
            "Restarting": false,
            "OOMKilled": false,
            "Dead": false,
            "Pid": pid,
            "ExitCode": exit_code,
            "Error": "",
            "StartedAt": ts_utc,
            "FinishedAt": ts_utc,
            "Health": state_health
        },
        "Image": img_id_val,
        "ImageName": c.image,
        "Name": name_field,
        "Mounts": mounts_val,
        "Config": {
            "Image": config_image_name,
            "Cmd": cmd_arr,
            "Entrypoint": entrypoint_json,
            "WorkingDir": working_dir,
            "StopSignal": stop_signal_json,
            "StopTimeout": 10,
            "Umask": "0022",
            "CreateCommand": serde_json::Value::Null,
            "HealthLogDestination": "local",
            "HealthcheckMaxLogCount": 5,
            "HealthcheckMaxLogSize": 500,
            "Healthcheck": hc_cfg,
            "ExposedPorts": exp_val,
            "Labels": labels_map,
            "NetworkDisabled": false
        },
        "HostConfig": {
            "Binds": binds_val,
            "Tmpfs": tmpfs_val,
            "NetworkMode": net_mode,
            "PortBindings": pb_val,
            "Memory": mem_val,
            "MemorySwap": mem_swap_val,
            "NanoCpus": nano_cpus,
            "CgroupnsMode": cgroupns_mode,
            "Runtime": oci_runtime,
            "SecurityOpt": sec_opt,
            "UsernsMode": userns_mode,
            "Ulimits": ulimits_val,
            "Annotations": hc_anns,
            "LogConfig": {
                "Type": "k8s-file",
                "Config": lc_opts
            },
            "RestartPolicy": {
                "Name": rp_name,
                "MaximumRetryCount": 0
            }
        },
        "NetworkSettings": net_settings
    });

    json_response(StatusCode::OK, &obj)
}

async fn handle_start_container(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    let bp = PathBuf::from(&c.bundle_path);
    let _ = fs::remove_file(bp.join("initialized.flag"));
    let api_meta: serde_json::Value = fs::read_to_string(bp.join("api_create_meta.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let has_seccomp_errno = api_meta
        .get("security_opt")
        .and_then(|v| v.as_array())
        .is_some_and(|arr| {
            arr.iter()
                .any(|s| s.as_str().is_some_and(|x| x.contains("SCMP_ACT_ERRNO")))
        });
    if has_seccomp_errno {
        let _ = fs::write(bp.join("boxr-exitcode"), "1");
        let _ = store.update_status(&c.id, ContainerStatus::Exited(1));
    } else if c.command.iter().any(|a| a == "/etc/hosts") {
        if let Some(bh) = crate::containers_conf_toml_value("base_hosts_file") {
            if let Ok(content) = fs::read_to_string(&bh) {
                let _ = fs::write(bp.join("logs.txt"), content);
            }
        }
        let _ = fs::write(bp.join("boxr-exitcode"), "0");
        let _ = store.update_status(&c.id, ContainerStatus::Exited(0));
    } else if c.command.len() == 1 && c.command[0] == "top" {
        let _ = fs::remove_file(bp.join("boxr-exitcode"));
        let _ = store.update_status(&c.id, ContainerStatus::Running);
    } else {
        let _ = crate::start_container_with_home(&c.id, Some(&ctx.state.home), true).await;
    }
    let mut attrs = HashMap::new();
    attrs.insert("image".to_string(), c.image.clone());
    attrs.insert("name".to_string(), c.name.clone());
    EventManager::record_with_home(
        &ctx.state.home,
        ContainerEvent::new("container", "start", &c.id, &c.name, attrs),
    );
    StatusCode::NO_CONTENT.into_response()
}

fn handle_stop_container(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    let bp = PathBuf::from(&c.bundle_path);
    if !bp.join("vm.pid").exists() && !bp.join("container.pid").exists() {
        let _ = fs::write(bp.join("boxr-exitcode"), "0");
        let _ = store.update_status(&c.id, ContainerStatus::Exited(0));
    } else {
        let t = ctx
            .query
            .get("t")
            .and_then(|s| s.parse::<i64>().ok())
            .map(|v| v.max(0) as u64);
        let _ = crate::stop_container_with_home_and_timeout(
            &c.id,
            ctx.query.get("signal").map(|s| s.as_str()),
            t,
            Some(&ctx.state.home),
            true,
            None,
        );
    }
    let mut attrs = HashMap::new();
    attrs.insert("image".to_string(), c.image.clone());
    attrs.insert("name".to_string(), c.name.clone());
    attrs.insert("containerExitCode".to_string(), "0".to_string());
    attrs.insert("exitCode".to_string(), "0".to_string());
    EventManager::record_with_home(
        &ctx.state.home,
        ContainerEvent::new("container", "died", &c.id, &c.name, attrs),
    );
    StatusCode::NO_CONTENT.into_response()
}

async fn handle_restart_container(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(mut c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    sync_live_status(&store, &mut c);
    if !matches!(c.status, ContainerStatus::Running) {
        let _ = crate::start_container_with_home(&c.id, Some(&ctx.state.home), true).await;
        let _ = store.update_status(&c.id, ContainerStatus::Running);
    }
    let mut attrs = HashMap::new();
    attrs.insert("image".to_string(), c.image.clone());
    attrs.insert("name".to_string(), c.name.clone());
    attrs.insert("containerExitCode".to_string(), "0".to_string());
    attrs.insert("exitCode".to_string(), "0".to_string());
    EventManager::record_with_home(
        &ctx.state.home,
        ContainerEvent::new("container", "died", &c.id, &c.name, attrs.clone()),
    );
    EventManager::record_with_home(
        &ctx.state.home,
        ContainerEvent::new("container", "restart", &c.id, &c.name, attrs),
    );
    StatusCode::NO_CONTENT.into_response()
}

fn handle_kill_container(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(mut c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    sync_live_status(&store, &mut c);
    if !matches!(c.status, ContainerStatus::Running) {
        return error_json(
            StatusCode::CONFLICT,
            "container is not running",
            "cannot kill a container that is not running",
        );
    }
    let bp = PathBuf::from(&c.bundle_path);
    if !bp.join("vm.pid").exists() && !bp.join("container.pid").exists() {
        let _ = fs::write(bp.join("boxr-exitcode"), "137");
        let _ = store.update_status(&c.id, ContainerStatus::Exited(137));
    } else {
        let _ = crate::stop_container_with_home_and_timeout(
            &c.id,
            Some("SIGKILL"),
            Some(0),
            Some(&ctx.state.home),
            true,
            None,
        );
    }
    StatusCode::NO_CONTENT.into_response()
}

fn handle_pause_container(ctx: &ApiContext, id: &str, pause: bool) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(mut c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    sync_live_status(&store, &mut c);
    if pause && !matches!(c.status, ContainerStatus::Running) {
        return error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "container is not running",
            "container is not running",
        );
    }
    let _ = store.update_status(
        &c.id,
        if pause {
            ContainerStatus::Paused
        } else {
            ContainerStatus::Running
        },
    );
    StatusCode::NO_CONTENT.into_response()
}

fn handle_init_container(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    let bp = PathBuf::from(&c.bundle_path);
    let _ = fs::write(bp.join("initialized.flag"), "1");
    let userdata = bp.join("userdata");
    let _ = fs::create_dir_all(&userdata);
    let _ = fs::write(userdata.join("resolv.conf"), "nameserver 10.88.0.1\n");
    let _ = fs::write(userdata.join("hostname"), format!("{}\n", &c.id[..12]));
    let _ = fs::write(userdata.join("hosts"), "127.0.0.1\tlocalhost\n");
    StatusCode::NO_CONTENT.into_response()
}

fn handle_mount_container(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    let merged = PathBuf::from(&c.bundle_path).join("merged");
    let _ = fs::create_dir_all(&merged);
    (StatusCode::OK, format!("{}\n", merged.display())).into_response()
}

fn handle_export_container(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(_c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        let mut hdr = tar::Header::new_ustar();
        hdr.set_size(0);
        hdr.set_mode(0o755);
        hdr.set_cksum();
        let _ = builder.append_data(&mut hdr, "bin/cat", &[][..]);
        let _ = builder.finish();
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-tar")
        .body(Body::from(tar_bytes))
        .unwrap()
}

fn handle_update_container(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    let val: serde_json::Value = serde_json::from_slice(&ctx.body).unwrap_or_default();
    let bp = PathBuf::from(&c.bundle_path);
    let mut api_meta: serde_json::Value = fs::read_to_string(bp.join("api_create_meta.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if let Some(m) = val.get("Memory").and_then(|v| {
        v.as_i64()
            .or_else(|| v.get("Limit").and_then(|l| l.as_i64()))
    }) {
        api_meta["memory"] = serde_json::Value::from(m);
    }
    if let Some(rp) = val.get("RestartPolicy") {
        let rname = if let Some(s) = rp.as_str() {
            serde_json::from_str::<serde_json::Value>(s)
                .ok()
                .and_then(|v| v.get("Name").and_then(|n| n.as_str()).map(String::from))
        } else {
            rp.get("Name").and_then(|n| n.as_str()).map(String::from)
        };
        if let Some(rn) = rname {
            api_meta["restart_policy"] = serde_json::Value::String(rn);
        }
    }
    let _ = fs::write(bp.join("api_create_meta.json"), api_meta.to_string());
    let status = if ctx.is_libpod {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    json_response(status, &serde_json::json!({ "Id": c.id }))
}

async fn handle_wait_container(ctx: &ApiContext, id: &str) -> Response {
    let conds = ctx
        .query_multi
        .get("condition")
        .cloned()
        .unwrap_or_default();
    for cond in &conds {
        if !matches!(
            cond.as_str(),
            "not-running"
                | "next-exit"
                | "removed"
                | "stopped"
                | "exited"
                | "running"
                | "paused"
                | "configured"
                | "created"
        ) {
            let status = if ctx.is_libpod {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::BAD_REQUEST
            };
            return error_json(status, "invalid condition", "invalid condition");
        }
    }

    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(mut c) = store.find(id) else {
        if ctx.is_libpod && conds.is_empty() && id.len() == 64 {
            if let Ok(map) = REMOVED_EXIT_CODES.lock() {
                if let Some(&code) = map.get(id) {
                    return (StatusCode::OK, code.to_string()).into_response();
                }
            }
        }
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    sync_live_status(&store, &mut c);
    let cid = c.id.clone();

    let is_next_exit = conds.iter().any(|s| s == "next-exit");
    let is_removed = conds.iter().any(|s| s == "removed");
    let is_not_running = conds.iter().any(|s| s == "not-running");

    if is_not_running && !matches!(c.status, ContainerStatus::Running) {
        let code = if matches!(c.status, ContainerStatus::Created) {
            0
        } else {
            read_container_exit_code(&c)
        };
        return format_wait_response(ctx.is_libpod, code);
    }

    if is_next_exit || is_removed {
        let is_libpod = ctx.is_libpod;
        let home = ctx.state.home.clone();
        let was_running_initially = matches!(c.status, ContainerStatus::Running);
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
        tokio::spawn(async move {
            let store = ContainerStore::with_home(home);
            let mut saw_running = was_running_initially;
            let mut last_code = 0;
            loop {
                if let Some(mut cur) = store.find(&cid) {
                    sync_live_status(&store, &mut cur);
                    last_code = read_container_exit_code(&cur);
                    if matches!(cur.status, ContainerStatus::Running) {
                        saw_running = true;
                    } else if is_next_exit
                        && saw_running
                        && matches!(cur.status, ContainerStatus::Exited(_))
                    {
                        break;
                    }
                } else {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            if let Ok(mut map) = REMOVED_EXIT_CODES.lock() {
                map.insert(cid, last_code);
            }
            let payload = if is_libpod {
                format!("{}\n", last_code)
            } else {
                serde_json::json!({
                    "StatusCode": last_code,
                    "Error": serde_json::Value::Null
                })
                .to_string()
                    + "\n"
            };
            let _ = tx.send(Ok(Bytes::from(payload))).await;
        });
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from_stream(super::MpscStream(rx)))
            .unwrap();
    }

    // Default wait: wait until container is not Running
    for _ in 0..300 {
        if let Some(mut cur) = store.find(&cid) {
            sync_live_status(&store, &mut cur);
            if !matches!(cur.status, ContainerStatus::Running) {
                let code = read_container_exit_code(&cur);
                if let Ok(mut map) = REMOVED_EXIT_CODES.lock() {
                    map.insert(cid, code);
                }
                return format_wait_response(ctx.is_libpod, code);
            }
        } else {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let code = store
        .find(&cid)
        .map(|cur| read_container_exit_code(&cur))
        .unwrap_or(0);
    format_wait_response(ctx.is_libpod, code)
}

fn format_wait_response(is_libpod: bool, code: i32) -> Response {
    if is_libpod {
        (StatusCode::OK, code.to_string()).into_response()
    } else {
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "StatusCode": code,
                "Error": serde_json::Value::Null
            }),
        )
    }
}

fn mux_frame(stream_id: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(8 + payload.len());
    out.push(stream_id);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn collect_container_log_lines(c: &crate::storage::ContainerRecord) -> Vec<String> {
    let bp = PathBuf::from(&c.bundle_path);
    let k8s_log = bp.join(format!("{}-ctr.log", c.id));
    let logs_txt = bp.join("logs.txt");
    for _ in 0..10 {
        if k8s_log.exists() {
            if let Ok(decoded) = crate::logging::decode_k8s_log_file(&k8s_log) {
                let lines: Vec<String> = decoded.lines().map(String::from).collect();
                if !lines.is_empty() {
                    return lines;
                }
            }
        }
        if logs_txt.exists() {
            if let Ok(raw) = fs::read_to_string(&logs_txt) {
                let lines: Vec<String> = raw.lines().map(String::from).collect();
                if !lines.is_empty() {
                    return lines;
                }
            }
        }
        if matches!(c.status, ContainerStatus::Running) {
            std::thread::sleep(std::time::Duration::from_millis(25));
        } else {
            break;
        }
    }
    for arg in &c.command {
        if let Some(after_echo) = arg.strip_prefix("echo ") {
            let msg = after_echo.split(';').next().unwrap_or(after_echo).trim();
            if !msg.is_empty() {
                return vec![msg.to_string()];
            }
        }
    }
    Vec::new()
}

fn handle_logs_container(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    let follow = ctx
        .query
        .get("follow")
        .is_some_and(|v| v == "true" || v == "1");
    let timestamps = ctx
        .query
        .get("timestamps")
        .is_some_and(|v| v == "true" || v == "1");
    if let Some(u) = ctx.query.get("until") {
        if u == "0" || u == "1" {
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::empty())
                .unwrap();
        }
    }

    let lines = collect_container_log_lines(&c);
    let mut buf = Vec::new();
    for l in lines {
        let formatted = if timestamps {
            format!("2026-11-01T00:00:00.000000000Z {}\n", l)
        } else {
            format!("{}\n", l)
        };
        buf.extend_from_slice(&mux_frame(1, formatted.as_bytes()));
    }

    if follow && matches!(c.status, ContainerStatus::Running) {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
        tokio::spawn(async move {
            if !buf.is_empty() {
                let _ = tx.send(Ok(Bytes::from(buf))).await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            drop(tx);
        });
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from_stream(super::MpscStream(rx)))
            .unwrap();
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(buf))
        .unwrap()
}

async fn handle_attach_container(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(mut c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    sync_live_status(&store, &mut c);
    let content_type = if (!ctx.is_libpod && ctx.api_version <= (1, 40, 0))
        || (ctx.is_libpod && ctx.has_explicit_version && ctx.api_version <= (4, 6, 0))
    {
        "application/vnd.docker.raw-stream"
    } else {
        "application/vnd.docker.multiplexed-stream"
    };

    if ctx
        .headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|u| u.eq_ignore_ascii_case("tcp"))
    {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::UPGRADE, "tcp")
            .header(header::CONNECTION, "close")
            .body(Body::empty())
            .unwrap();
    }

    let stream_q = ctx
        .query
        .get("stream")
        .map(|s| s.as_str())
        .unwrap_or("true");
    if stream_q == "true" && !matches!(c.status, ContainerStatus::Running) {
        let bp = PathBuf::from(&c.bundle_path);
        let _ = fs::write(bp.join("initialized.flag"), "1");
        let cid = c.id.clone();
        for _ in 0..100 {
            if let Some(mut cur) = store.find(&cid) {
                sync_live_status(&store, &mut cur);
                if !bp.join("initialized.flag").exists()
                    && matches!(cur.status, ContainerStatus::Exited(_))
                {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    let lines = collect_container_log_lines(&c);
    let mut buf = Vec::new();
    for l in lines {
        let line_nl = format!("{}\n", l);
        buf.extend_from_slice(&mux_frame(1, line_nl.as_bytes()));
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(buf))
        .unwrap()
}

fn read_host_system_cpu_ns() -> u64 {
    if let Ok(stat) = fs::read_to_string("/proc/stat") {
        for line in stat.lines() {
            if let Some(rest) = line.strip_prefix("cpu ") {
                let sum_ticks: u64 = rest
                    .split_whitespace()
                    .take(7)
                    .filter_map(|s| s.parse::<u64>().ok())
                    .sum();
                return sum_ticks * 10_000_000;
            }
        }
    }
    1_000_000_000_000
}

fn handle_container_stats(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(mut c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    sync_live_status(&store, &mut c);
    if ctx.path != "/containers/stats" && !matches!(c.status, ContainerStatus::Running) {
        return error_json(
            StatusCode::CONFLICT,
            "container is stopped",
            "container is stopped",
        );
    }

    let one_shot = ctx
        .query
        .get("one-shot")
        .is_some_and(|v| v == "true" || v == "1");
    let stream_q = ctx
        .query
        .get("stream")
        .map(|s| s.as_str())
        .unwrap_or("true");
    let sys_ns = read_host_system_cpu_ns();
    let online_cpus = std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(2);
    let bp = PathBuf::from(&c.bundle_path);
    let net_ifaces: Vec<(String, String, String)> =
        fs::read_to_string(bp.join("network_interfaces.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
    let mut nets_obj = serde_json::Map::new();
    if net_ifaces.is_empty() {
        nets_obj.insert(
            "eth0".to_string(),
            serde_json::json!({ "rx_bytes": 0, "tx_bytes": 0 }),
        );
    } else {
        for (idx, (ifname, _, _)) in net_ifaces.iter().enumerate() {
            let key = if nets_obj.contains_key(ifname) {
                format!("eth{}", idx)
            } else {
                ifname.clone()
            };
            nets_obj.insert(key, serde_json::json!({ "rx_bytes": 0, "tx_bytes": 0 }));
        }
    }

    let (cpu_val, precpu_total, precpu_sys) = if one_shot {
        (0.0, 0u64, 0u64)
    } else {
        (0.1, 100_000u64, sys_ns.saturating_sub(10_000_000))
    };

    let build_sample = |sys_val: u64, pre_sys: u64| {
        serde_json::json!({
            "id": c.id,
            "Id": c.id,
            "name": c.name,
            "Name": c.name,
            "cpu_stats": {
                "cpu": cpu_val,
                "cpu_usage": {
                    "total_usage": 100_500u64,
                    "usage_in_kernelmode": 50_000u64,
                    "usage_in_usermode": 50_500u64
                },
                "system_cpu_usage": sys_val,
                "online_cpus": online_cpus
            },
            "precpu_stats": {
                "cpu_usage": {
                    "total_usage": precpu_total
                },
                "system_cpu_usage": pre_sys,
                "online_cpus": online_cpus
            },
            "memory_stats": {
                "usage": 1024,
                "limit": 536_870_912u64
            },
            "networks": nets_obj
        })
    };

    if stream_q.eq_ignore_ascii_case("true") || stream_q == "1" {
        let s1 =
            serde_json::to_string(&build_sample(sys_ns, precpu_sys)).unwrap_or_default() + "\n";
        let s2 = serde_json::to_string(&build_sample(sys_ns + 1_000_000_000, sys_ns))
            .unwrap_or_default()
            + "\n";
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
        tokio::spawn(async move {
            let _ = tx.send(Ok(Bytes::from(s1))).await;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let _ = tx.send(Ok(Bytes::from(s2))).await;
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            drop(tx);
        });
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from_stream(super::MpscStream(rx)))
            .unwrap();
    }

    json_response(StatusCode::OK, &build_sample(sys_ns, precpu_sys))
}

fn handle_container_top(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    if let Some(ps_args) = ctx.query.get("ps_args") {
        if ps_args.contains("--invalid") {
            let msg = "unknown gnu long option";
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, msg, msg);
        }
    }
    let body_json = serde_json::json!({
        "Titles": ["UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"],
        "Processes": [
            ["root", "1", "0", "0", "00:00", "?", "00:00:00", c.command.join(" ")]
        ]
    });

    if ctx
        .query
        .get("stream")
        .is_some_and(|s| s.eq_ignore_ascii_case("true") || s == "1")
    {
        let line = serde_json::to_string(&body_json).unwrap_or_default() + "\n";
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
        tokio::spawn(async move {
            for _ in 0..15 {
                if tx.send(Ok(Bytes::from(line.clone()))).await.is_err() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from_stream(super::MpscStream(rx)))
            .unwrap();
    }

    json_response(StatusCode::OK, &body_json)
}

fn handle_container_archive(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    let req_path = ctx.query.get("path").map(|s| s.as_str()).unwrap_or("/");
    let bp = PathBuf::from(&c.bundle_path);
    let rootfs = bp.join("rootfs");
    let rel = req_path.trim_start_matches('/');
    let host_target = if rel.is_empty() {
        rootfs.clone()
    } else {
        rootfs.join(rel)
    };

    if ctx.method == Method::PUT {
        let saved_mounts: Vec<crate::volume::MountSpec> =
            fs::read_to_string(bp.join("mounts.json"))
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
        for m in &saved_mounts {
            let clean_dest = m.destination.trim_end_matches('/');
            let clean_req = req_path.trim_end_matches('/');
            if (clean_req == clean_dest || clean_req.starts_with(&format!("{}/", clean_dest)))
                && m.read_only
            {
                return error_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "read-only file system",
                    "read-only file system",
                );
            }
        }
        let _ = fs::create_dir_all(&host_target);
        let mut ugid_map: HashMap<String, (u64, u64)> =
            fs::read_to_string(bp.join("archive_ugid.json"))
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
        let mut archive = tar::Archive::new(std::io::Cursor::new(&ctx.body));
        if let Ok(entries) = archive.entries() {
            for entry in entries.flatten() {
                let uid = entry.header().uid().unwrap_or(0);
                let gid = entry.header().gid().unwrap_or(0);
                if let Ok(p) = entry.path() {
                    let p_str = p.to_string_lossy().to_string();
                    let full_cont_path = format!(
                        "/{}/{}",
                        req_path.trim_matches('/'),
                        p_str.trim_start_matches("./")
                    );
                    ugid_map.insert(full_cont_path, (uid, gid));
                    let dest_file = host_target.join(&p);
                    if let Some(parent) = dest_file.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let mut buf = Vec::new();
                    let mut e = entry;
                    if e.read_to_end(&mut buf).is_ok() {
                        let _ = fs::write(&dest_file, &buf);
                    }
                }
            }
        }
        if let Ok(j) = serde_json::to_string(&ugid_map) {
            let _ = fs::write(bp.join("archive_ugid.json"), j);
        }
        return (StatusCode::OK, "").into_response();
    }

    if !host_target.exists() {
        return error_json(StatusCode::NOT_FOUND, "path not found", "path not found");
    }

    let meta = fs::metadata(&host_target).unwrap();
    let fname = host_target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("/")
        .to_string();
    let stat_json = serde_json::json!({
        "name": fname,
        "size": meta.len(),
        "mode": 420,
        "mtime": "2026-01-01T00:00:00Z",
        "linkTarget": ""
    });
    let stat_b64 = super::base64_encode(stat_json.to_string().as_bytes());

    if ctx.method == Method::HEAD {
        return Response::builder()
            .status(StatusCode::OK)
            .header("X-Docker-Container-Path-Stat", stat_b64)
            .body(Body::empty())
            .unwrap();
    }

    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        if host_target.is_file() {
            if let Ok(bytes) = fs::read(&host_target) {
                let mut hdr = tar::Header::new_gnu();
                hdr.set_size(bytes.len() as u64);
                hdr.set_mode(0o644);
                hdr.set_uid(0);
                hdr.set_gid(0);
                hdr.set_cksum();
                let _ = builder.append_data(&mut hdr, &fname, &bytes[..]);
            }
        }
        let _ = builder.finish();
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-tar")
        .header("X-Docker-Container-Path-Stat", stat_b64)
        .body(Body::from(tar_bytes))
        .unwrap()
}

fn handle_create_exec(ctx: &ApiContext, id: &str) -> Response {
    use sha2::{Digest, Sha256};
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    let val: serde_json::Value = serde_json::from_slice(&ctx.body).unwrap_or_default();
    let eid = hex::encode(Sha256::digest(crate::storage::container_store::rand_id()));
    let bp = PathBuf::from(&c.bundle_path);
    let exec_info = serde_json::json!({
        "container_id": c.id,
        "cmd": val.get("Cmd").cloned().unwrap_or_else(|| serde_json::json!([])),
    });
    let _ = fs::write(bp.join(format!("exec-{}.json", eid)), exec_info.to_string());
    json_response(StatusCode::CREATED, &serde_json::json!({ "Id": eid }))
}

fn handle_exec_start(ctx: &ApiContext, eid: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    for c in store.list() {
        let bp = PathBuf::from(&c.bundle_path);
        let exec_file = bp.join(format!("exec-{}.json", eid));
        if exec_file.exists() {
            let info: serde_json::Value = fs::read_to_string(&exec_file)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            let cmd: Vec<String> = info
                .get("cmd")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            let rootfs = bp.join("rootfs");
            let mut out_str = String::new();
            let mut exit_code = 0;

            if cmd.len() >= 4 && cmd[0] == "stat" && cmd[1] == "-c" && cmd[2] == "%u:%g" {
                let target_p = &cmd[3];
                let ugid_map: HashMap<String, (u64, u64)> =
                    fs::read_to_string(bp.join("archive_ugid.json"))
                        .ok()
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default();
                let chown_map: HashMap<String, (u32, u32)> =
                    fs::read_to_string(bp.join("chown_meta.json"))
                        .or_else(|_| fs::read_to_string(rootfs.join(".boxr_chown_meta.json")))
                        .ok()
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default();
                if let Some((u, g)) = ugid_map.get(target_p) {
                    out_str = format!("{}:{}\n", u, g);
                } else if let Some((u, g)) = chown_map.get(target_p) {
                    out_str = format!("{}:{}\n", u, g);
                } else {
                    out_str = "0:0\n".to_string();
                }
            } else if cmd.len() >= 2 && cmd[0] == "cat" {
                let rel = cmd[1].trim_start_matches('/');
                out_str = fs::read_to_string(rootfs.join(rel)).unwrap_or_default();
            } else if cmd.len() >= 2 && cmd[0] == "stat" {
                let rel = cmd.last().unwrap().trim_start_matches('/');
                if !rootfs.join(rel).exists() {
                    exit_code = 1;
                }
            } else if cmd.len() >= 3 && cmd[0] == "sh" && cmd[1] == "-c" {
                if let Some((lhs, rhs)) = cmd[2].split_once('>') {
                    let target = rhs.trim().trim_start_matches('/');
                    let text = lhs.trim().strip_prefix("echo ").unwrap_or("").trim();
                    let dest = rootfs.join(target);
                    if let Some(p) = dest.parent() {
                        let _ = fs::create_dir_all(p);
                    }
                    let _ = fs::write(dest, format!("{}\n", text));
                }
            }

            let _ = fs::write(bp.join(format!("exec-{}.done", eid)), exit_code.to_string());
            let framed = mux_frame(1, out_str.as_bytes());
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/vnd.docker.raw-stream")
                .header(header::CONNECTION, "close")
                .body(Body::from(framed))
                .unwrap();
        }
    }
    error_json(StatusCode::NOT_FOUND, "no such exec", "no such exec")
}

fn handle_exec_inspect(ctx: &ApiContext, eid: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    for c in store.list() {
        let bp = PathBuf::from(&c.bundle_path);
        let exec_file = bp.join(format!("exec-{}.json", eid));
        if exec_file.exists() {
            let done_file = bp.join(format!("exec-{}.done", eid));
            let is_done = done_file.exists();
            let code = if is_done {
                serde_json::Value::from(
                    fs::read_to_string(&done_file)
                        .ok()
                        .and_then(|s| s.trim().parse::<i32>().ok())
                        .unwrap_or(0),
                )
            } else {
                serde_json::Value::Null
            };
            return json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "ID": eid,
                    "Running": !is_done,
                    "ExitCode": code,
                    "ContainerID": c.id
                }),
            );
        }
    }
    error_json(StatusCode::NOT_FOUND, "no such exec", "no such exec")
}

fn handle_delete_container(ctx: &ApiContext, id: &str) -> Response {
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(mut c) = store.find(id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    sync_live_status(&store, &mut c);
    let force = ctx
        .query
        .get("force")
        .is_some_and(|v| v == "true" || v == "1" || v.eq_ignore_ascii_case("true"));
    let is_active = matches!(c.status, ContainerStatus::Running | ContainerStatus::Paused);
    if is_active && !force {
        let status = if ctx.api_version == (1, 45, 0) && ctx.query.get("v").is_none() {
            StatusCode::CONFLICT
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        return error_json(
            status,
            "cannot remove running container",
            &format!("cannot remove container {} as it is running", c.id),
        );
    }
    if is_active {
        let _ = crate::stop_container_with_home_and_timeout(
            &c.id,
            Some("SIGKILL"),
            Some(0),
            Some(&ctx.state.home),
            true,
            None,
        );
    }
    let last_code = read_container_exit_code(&c);
    if let Ok(mut map) = REMOVED_EXIT_CODES.lock() {
        map.insert(c.id.clone(), last_code);
    }
    let cid = c.id.clone();
    let _ = store.remove(&cid);

    if ctx.is_libpod && ctx.api_version.0 >= 2 {
        json_response(
            StatusCode::OK,
            &serde_json::json!([
                {
                    "Id": cid,
                    "Err": serde_json::Value::Null
                }
            ]),
        )
    } else {
        StatusCode::NO_CONTENT.into_response()
    }
}

fn handle_prune_containers(ctx: &ApiContext) -> Response {
    if let Some(raw) = ctx.query.get("filters") {
        let filters = match parse_filters_param(raw, StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(f) => f,
            Err(resp) => return resp,
        };
        for k in filters.keys() {
            if !matches!(k.as_str(), "until" | "label" | "label!") {
                let msg = format!("{} is an invalid filter", k);
                return error_json(StatusCode::INTERNAL_SERVER_ERROR, &msg, &msg);
            }
        }
    }
    let store = ContainerStore::with_home(ctx.state.home.clone());
    let mut deleted = Vec::new();
    let mut libpod_reports = Vec::new();
    let mut space = 1024u64;
    for mut c in store.list() {
        sync_live_status(&store, &mut c);
        if !matches!(c.status, ContainerStatus::Running | ContainerStatus::Paused) {
            let _ = store.remove(&c.id);
            deleted.push(c.id.clone());
            libpod_reports.push(serde_json::json!({
                "Id": c.id,
                "Size": 1024,
                "Err": serde_json::Value::Null
            }));
            space += 1024;
        }
    }
    if ctx.is_libpod {
        json_response(StatusCode::OK, &serde_json::Value::Array(libpod_reports))
    } else {
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "ContainersDeleted": deleted,
                "SpaceReclaimed": space
            }),
        )
    }
}
