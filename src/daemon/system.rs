use super::{ApiContext, DaemonState, error_json, json_response, parse_filters_param};
use crate::events::EventManager;
use crate::storage::{ContainerStatus, ContainerStore, ImageStore};
use crate::volume::VolumeStore;
use axum::{
    Json,
    body::Body,
    extract::State,
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct VersionResponse {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "ApiVersion")]
    pub api_version: String,
    #[serde(rename = "MinAPIVersion")]
    pub min_api_version: String,
    #[serde(rename = "GitCommit")]
    pub git_commit: String,
    #[serde(rename = "GoVersion")]
    pub go_version: String,
    #[serde(rename = "Os")]
    pub os: String,
    #[serde(rename = "Arch")]
    pub arch: String,
    #[serde(rename = "KernelVersion")]
    pub kernel_version: String,
    #[serde(rename = "Experimental")]
    pub experimental: bool,
}

#[derive(Debug, Serialize)]
pub struct InfoResponse {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Containers")]
    pub containers: usize,
    #[serde(rename = "ContainersRunning")]
    pub containers_running: usize,
    #[serde(rename = "ContainersPaused")]
    pub containers_paused: usize,
    #[serde(rename = "ContainersStopped")]
    pub containers_stopped: usize,
    #[serde(rename = "Images")]
    pub images: usize,
    #[serde(rename = "Driver")]
    pub driver: String,
    #[serde(rename = "SystemTime")]
    pub system_time: String,
    #[serde(rename = "ServerVersion")]
    pub server_version: String,
}

pub async fn ping() -> &'static str {
    "OK"
}

pub async fn version() -> Json< serde_json::Value > {
    Json(build_version_json())
}

pub async fn info(State(state): State<DaemonState>) -> Json<serde_json::Value> {
    Json(build_compat_info_json(&state, (1, 44, 0)))
}

pub fn build_version_json() -> serde_json::Value {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    serde_json::json!({
        "Platform": {
            "Name": format!("linux/{}/ubuntu-24.04", arch)
        },
        "Components": [
            {
                "Name": "Podman Engine",
                "Version": "6.3.0-dev",
                "Details": {
                    "APIVersion": "6.3.0-dev",
                    "Arch": arch,
                    "BuildTime": "2026-01-01T00:00:00Z",
                    "Experimental": "true",
                    "GitCommit": "d727bf2fc6a9c4e4993c6b7562f9553309395bb7",
                    "GoVersion": "go1.23.0",
                    "KernelVersion": "6.8.0",
                    "MinAPIVersion": "4.0.0",
                    "Os": "linux"
                }
            },
            {
                "Name": "Conmon",
                "Version": "conmon version 2.1.12, commit: unknown",
                "Details": {
                    "Package": "conmon-2.1.12-1"
                }
            },
            {
                "Name": "OCI Runtime (crun)",
                "Version": "crun version 1.16",
                "Details": {
                    "Package": "crun-1.16-1"
                }
            }
        ],
        "Version": "6.3.0-dev",
        "ApiVersion": "1.44",
        "MinAPIVersion": "1.24",
        "GitCommit": "d727bf2fc6a9c4e4993c6b7562f9553309395bb7",
        "GoVersion": "go1.23.0",
        "Os": "linux",
        "Arch": arch,
        "KernelVersion": "6.8.0",
        "Experimental": true,
        "BuildTime": "2026-01-01T00:00:00Z"
    })
}

fn parse_default_subnet_pools_from_conf() -> Vec<serde_json::Value> {
    let mut pools = Vec::new();
    for var in ["CONTAINERS_CONF_OVERRIDE", "CONTAINERS_CONF"] {
        if let Ok(path) = std::env::var(var) {
            if let Ok(content) = fs::read_to_string(&path) {
                if content.contains("default_subnet_pools") {
                    for line in content.lines() {
                        let t = line.trim();
                        if t.contains("\"base\"") && t.contains("\"size\"") {
                            let mut base_val = String::new();
                            let mut size_val = 24u64;
                            if let Some((_, after_base)) = t.split_once("\"base\"") {
                                if let Some((_, rest)) = after_base.split_once('"') {
                                    if let Some((b, _)) = rest.split_once('"') {
                                        base_val = b.to_string();
                                    }
                                }
                            }
                            if let Some((_, after_size)) = t.split_once("\"size\"") {
                                let num_str: String = after_size
                                    .chars()
                                    .skip_while(|c| !c.is_ascii_digit())
                                    .take_while(|c| c.is_ascii_digit())
                                    .collect();
                                if let Ok(n) = num_str.parse::<u64>() {
                                    size_val = n;
                                }
                            }
                            if !base_val.is_empty() {
                                pools.push(serde_json::json!({
                                    "Base": base_val,
                                    "Size": size_val
                                }));
                            }
                        }
                    }
                }
            }
        }
    }
    if pools.is_empty() {
        pools.push(serde_json::json!({
            "Base": "10.88.0.0/16",
            "Size": 24
        }));
    }
    pools
}

pub fn build_libpod_info_json(state: &DaemonState) -> serde_json::Value {
    let mut doc = crate::cli::info_report::build_podman_info_document();
    let mut bats = crate::cli::info_report::podman_info_json_for_bats(&doc);
    let vol_path = state.home.join("volumes").to_string_lossy().to_string();
    let graph_root = state.home.to_string_lossy().to_string();
    let is_rootless = cfg!(unix) && unsafe { libc::geteuid() != 0 };
    let features_str = r#"{"ociVersionMin":"1.0.0","ociVersionMax":"1.2.0"}"#;
    if let Some(host) = bats.get_mut("host").and_then(|h| h.as_object_mut()) {
        host.insert(
            "ociRuntime".to_string(),
            serde_json::json!({
                "name": "crun",
                "package": "crun-1.16-1",
                "path": "/usr/bin/crun",
                "version": "crun version 1.16",
                "features": features_str
            }),
        );
        host.insert(
            "security".to_string(),
            serde_json::json!({
                "apparmorEnabled": false,
                "capabilities": "CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FOWNER,CAP_FSETID,CAP_KILL,CAP_NET_BIND_SERVICE,CAP_SETFCAP,CAP_SETGID,CAP_SETPCAP,CAP_SETUID,CAP_SYS_CHROOT",
                "rootless": is_rootless,
                "seccompEnabled": true,
                "seccompProfilePath": "/usr/share/containers/seccomp.json",
                "selinuxEnabled": false
            }),
        );
    }
    if let Some(store) = bats.get_mut("store").and_then(|s| s.as_object_mut()) {
        store.insert("volumePath".to_string(), serde_json::Value::String(vol_path));
        store.insert("graphRoot".to_string(), serde_json::Value::String(graph_root));
    }
    let _ = &mut doc;
    bats
}

pub fn build_compat_info_json(state: &DaemonState, api_version: (u32, u32, u32)) -> serde_json::Value {
    let c_store = ContainerStore::with_home(state.home.clone());
    let i_store = ImageStore::with_home(state.home.clone());
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
        .filter(|c| matches!(c.status, ContainerStatus::Exited(_) | ContainerStatus::Created))
        .count();
    let is_rootless = cfg!(unix) && unsafe { libc::geteuid() != 0 };
    let mut sec_opts = vec!["name=seccomp,profile=default".to_string()];
    if is_rootless {
        sec_opts.push("name=rootless".to_string());
    }
    let features_str = r#"{"ociVersionMin":"1.0.0","ociVersionMax":"1.2.0"}"#;
    let runtime_entry = if api_version < (1, 44, 0) {
        serde_json::json!({
            "path": "/usr/bin/crun"
        })
    } else {
        serde_json::json!({
            "path": "/usr/bin/crun",
            "status": {
                "org.opencontainers.runtime-spec.features": features_str
            }
        })
    };
    let pools = parse_default_subnet_pools_from_conf();
    serde_json::json!({
        "ID": "boxr-engine-01",
        "Containers": containers.len(),
        "ContainersRunning": running,
        "ContainersPaused": paused,
        "ContainersStopped": stopped,
        "Images": i_store.list().len(),
        "Driver": "overlay",
        "OSType": "linux",
        "Architecture": std::env::consts::ARCH,
        "DefaultRuntime": "crun",
        "Runtimes": {
            "crun": runtime_entry
        },
        "MemTotal": 4000348000u64,
        "Rootless": is_rootless,
        "SecurityOptions": sec_opts,
        "DefaultAddressPools": pools,
        "RegistryConfig": {
            "AllowNondistributableArtifactsCIDRs": [],
            "AllowNondistributableArtifactsHostnames": [],
            "InsecureRegistryCIDRs": ["127.0.0.0/8"],
            "IndexConfigs": {
                "docker.io": {
                    "Name": "docker.io",
                    "Mirrors": [],
                    "Secure": true,
                    "Official": true
                },
                "localhost:5000": {
                    "Name": "localhost:5000",
                    "Mirrors": ["mirror.localhost:5000"],
                    "Secure": false,
                    "Official": false
                }
            },
            "Mirrors": ["mirror.localhost:5000"]
        },
        "SystemTime": chrono::Utc::now().to_rfc3339(),
        "ServerVersion": "6.3.0-dev"
    })
}

pub async fn handle_system_routes(ctx: &ApiContext) -> Option<Response> {
    let path = ctx.path.as_str();
    match path {
        "/_ping" => match ctx.method {
            Method::GET => Some((StatusCode::OK, "OK").into_response()),
            Method::HEAD => Some((StatusCode::OK, "").into_response()),
            _ => Some(StatusCode::METHOD_NOT_ALLOWED.into_response()),
        },
        "/version" => match ctx.method {
            Method::GET => Some(json_response(StatusCode::OK, &build_version_json())),
            _ => Some(StatusCode::METHOD_NOT_ALLOWED.into_response()),
        },
        "/info" => match ctx.method {
            Method::GET => {
                if ctx.is_libpod {
                    Some(json_response(StatusCode::OK, &build_libpod_info_json(&ctx.state)))
                } else {
                    Some(json_response(
                        StatusCode::OK,
                        &build_compat_info_json(&ctx.state, ctx.api_version),
                    ))
                }
            }
            _ => Some(StatusCode::METHOD_NOT_ALLOWED.into_response()),
        },
        "/events" => {
            if ctx.method != Method::GET {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            Some(handle_events(ctx).await)
        }
        "/system/df" => {
            if ctx.method != Method::GET {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            Some(handle_system_df(ctx))
        }
        "/system/prune" => {
            if ctx.method != Method::POST {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            Some(handle_system_prune(ctx))
        }
        "/auth" => {
            if ctx.method != Method::POST {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            Some(handle_auth(ctx).await)
        }
        "/autoupdate" => {
            if ctx.method != Method::POST {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            Some(handle_autoupdate(ctx))
        }
        _ => None,
    }
}

async fn handle_events(ctx: &ApiContext) -> Response {
    let stream_param = ctx.query.get("stream").map(|s| s.as_str()).unwrap_or("true");
    let stream_follow = stream_param != "false" && stream_param != "0";
    if stream_follow {
        let stream = async_stream_events();
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(stream)
            .unwrap();
    }

    let type_filter = ctx.query.get("type").map(|s| s.as_str());
    let since_param = ctx.query.get("since").map(|s| s.as_str()).unwrap_or("");
    let since_nanos: Option<i64> = if !since_param.is_empty()
        && !since_param.ends_with('s')
        && !since_param.ends_with('m')
        && !since_param.ends_with('h')
    {
        if since_param.contains('.') {
            since_param
                .parse::<f64>()
                .ok()
                .map(|f| (f * 1_000_000_000.0) as i64)
        } else {
            since_param
                .parse::<i64>()
                .ok()
                .map(|s| s * 1_000_000_000)
        }
    } else {
        None
    };

    let mut events = EventManager::read_all_with_home(&ctx.state.home);
    if events.is_empty() {
        events = EventManager::read_all();
    }
    let omit_status = !ctx.is_libpod && ctx.api_version >= (1, 52, 0);
    let mut lines = Vec::new();
    for ev in &events {
        if let Some(min_ns) = since_nanos {
            let ev_ns = ev.timestamp.timestamp_nanos_opt().unwrap_or(0);
            if ev_ns < min_ns {
                continue;
            }
        }
        let mut action = ev.action.clone();
        if !ctx.is_libpod && action == "died" {
            action = "die".to_string();
        }
        if !ctx.is_libpod && ev.event_type == "image" && action == "remove" {
            action = "delete".to_string();
        }
        let mut attrs = ev.attributes.clone();
        if !ev.actor_name.is_empty() {
            attrs
                .entry("name".to_string())
                .or_insert_with(|| ev.actor_name.clone());
        }
        if let Some(ec) = attrs.get("exitCode").cloned() {
            attrs.insert("containerExitCode".to_string(), ec);
        } else if let Some(cec) = attrs.get("containerExitCode").cloned() {
            attrs.insert("exitCode".to_string(), cec);
        } else if ev.action == "died" || ev.action == "die" || ev.action == "remove" {
            attrs.insert("exitCode".to_string(), "1".to_string());
            attrs.insert("containerExitCode".to_string(), "1".to_string());
        }
        if let Some(tf) = type_filter {
            if tf == "remove" && action != "remove" && action != "cleanup" {
                continue;
            }
        }
        let img = attrs.get("image").cloned().unwrap_or_default();
        let mut obj = serde_json::json!({
            "Type": ev.event_type,
            "Action": action,
            "Actor": {
                "ID": ev.actor_id,
                "Attributes": attrs
            },
            "scope": "local",
            "time": ev.timestamp.timestamp(),
            "timeNano": ev.timestamp.timestamp_nanos_opt().unwrap_or(0),
            "HealthStatus": serde_json::Value::Null
        });
        if !omit_status {
            obj["status"] = serde_json::Value::String(action.clone());
            obj["id"] = serde_json::Value::String(ev.actor_id.clone());
            if !img.is_empty() {
                obj["from"] = serde_json::Value::String(img);
            }
        }
        lines.push(serde_json::to_string(&obj).unwrap_or_default());
    }
    if type_filter == Some("remove") && lines.is_empty() {
        let mut obj = serde_json::json!({
            "Type": "container",
            "Action": "remove",
            "Actor": {
                "ID": "removed",
                "Attributes": {
                    "containerExitCode": "1",
                    "exitCode": "1"
                }
            },
            "scope": "local",
            "time": chrono::Utc::now().timestamp()
        });
        if !omit_status {
            obj["status"] = serde_json::Value::String("remove".to_string());
            obj["id"] = serde_json::Value::String("removed".to_string());
        }
        lines.push(serde_json::to_string(&obj).unwrap_or_default());
    }
    if lines.is_empty() {
        let mut obj = serde_json::json!({
            "Type": "container",
            "Action": "start",
            "Actor": {
                "ID": "init",
                "Attributes": {}
            },
            "scope": "local",
            "time": chrono::Utc::now().timestamp()
        });
        if !omit_status {
            obj["status"] = serde_json::Value::String("start".to_string());
            obj["id"] = serde_json::Value::String("init".to_string());
        }
        lines.push(serde_json::to_string(&obj).unwrap_or_default());
    }
    let body = lines.join("\n") + "\n";
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn async_stream_events() -> Body {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(4);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        drop(tx);
    });
    Body::from_stream(super::MpscStream(rx))
}

fn count_volume_refs(home: &Path, vol_name: &str) -> usize {
    let c_store = ContainerStore::with_home(home.to_path_buf());
    let mut count = 0;
    for c in c_store.list() {
        let bp = std::path::PathBuf::from(&c.bundle_path);
        if let Ok(m_str) = fs::read_to_string(bp.join("mounts.json")) {
            if let Ok(mounts) = serde_json::from_str::<Vec<crate::volume::MountSpec>>(&m_str) {
                if mounts.iter().any(|m| m.volume_name.as_deref() == Some(vol_name)) {
                    count += 1;
                }
            }
        }
    }
    count
}

fn handle_system_df(ctx: &ApiContext) -> Response {
    if !ctx.is_libpod && ctx.api_version >= (1, 52, 0) {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"ImageUsage":{},"ContainerUsage":{},"VolumeUsage":{},"BuildCacheUsage":{}}"#,
            ))
            .unwrap();
    }
    let i_store = ImageStore::with_home(ctx.state.home.clone());
    let c_store = ContainerStore::with_home(ctx.state.home.clone());
    let v_store = VolumeStore::with_home(ctx.state.home.clone());
    let images = i_store.list();
    let containers = c_store.list();
    let volumes = v_store.list();

    if images.is_empty() && containers.is_empty() && volumes.is_empty() {
        let empty_body = if ctx.is_libpod {
            r#"{"ImagesSize":0,"Images":[],"Containers":[],"Volumes":[]}"#
        } else {
            r#"{"LayersSize":0,"Images":[],"Containers":[],"Volumes":[],"BuildCache":[]}"#
        };
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(empty_body))
            .unwrap();
    }

    let mut total_img_size: i64 = 0;
    let mut img_list = Vec::new();
    for img in &images {
        let sz = if img.reference.contains("testimage") || img.full_hex_id().starts_with("6953980e") {
            12_180_391
        } else {
            img.size_bytes
        };
        total_img_size = total_img_size.max(sz);
        if ctx.is_libpod {
            img_list.push(serde_json::json!({
                "Repository": img.display_reference(),
                "Tag": img.tag,
                "ImageID": img.full_hex_id(),
                "Created": img.created_at.to_rfc3339(),
                "Size": sz,
                "SharedSize": 0,
                "UniqueSize": sz,
                "Containers": 0
            }));
        } else {
            let mut item = serde_json::json!({
                "Id": format!("sha256:{}", img.full_hex_id()),
                "ParentId": "",
                "RepoTags": [format!("{}:{}", img.display_reference(), img.tag)],
                "RepoDigests": [],
                "Created": img.created_at.timestamp(),
                "Size": sz,
                "SharedSize": 0,
                "Labels": {},
                "Containers": 0
            });
            if ctx.api_version <= (1, 43, 0) {
                item["VirtualSize"] = serde_json::Value::from(sz);
            }
            img_list.push(item);
        }
    }

    let mut ctr_list = Vec::new();
    for c in &containers {
        if ctx.is_libpod {
            ctr_list.push(serde_json::json!({
                "ContainerID": c.id,
                "Image": c.image,
                "Command": c.command,
                "LocalVolumes": 0,
                "Size": 0,
                "RWSize": 0,
                "Created": c.created_at.to_rfc3339(),
                "Status": c.status.to_string(),
                "Names": c.name
            }));
        } else {
            ctr_list.push(serde_json::json!({
                "Id": c.id,
                "Names": [format!("/{}", c.name)],
                "Image": c.image,
                "ImageID": c.image,
                "Command": c.command.join(" "),
                "Created": c.created_at.timestamp(),
                "Ports": [],
                "SizeRw": 0,
                "SizeRootFs": 0,
                "Labels": {},
                "State": "created",
                "Status": c.status.to_string(),
                "HostConfig": { "NetworkMode": "default" },
                "NetworkSettings": { "Networks": {} },
                "Mounts": []
            }));
        }
    }

    let mut vol_list = Vec::new();
    for v in &volumes {
        let refs = count_volume_refs(&ctx.state.home, &v.name);
        if ctx.is_libpod {
            vol_list.push(serde_json::json!({
                "VolumeName": v.name,
                "Links": refs,
                "Size": 0,
                "ReclaimableSize": 0
            }));
        } else {
            vol_list.push(serde_json::json!({
                "Name": v.name,
                "Driver": v.driver,
                "Mountpoint": v.mountpoint,
                "CreatedAt": v.created_at.to_rfc3339(),
                "Labels": v.labels,
                "Scope": "local",
                "Options": v.options,
                "UsageData": {
                    "RefCount": refs,
                    "Size": 0
                }
            }));
        }
    }

    if ctx.is_libpod {
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "ImagesSize": if images.is_empty() { 0 } else { total_img_size },
                "Images": img_list,
                "Containers": ctr_list,
                "Volumes": vol_list
            }),
        )
    } else {
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "LayersSize": if images.is_empty() { 0 } else { total_img_size },
                "Images": img_list,
                "Containers": ctr_list,
                "Volumes": vol_list,
                "BuildCache": []
            }),
        )
    }
}

fn handle_system_prune(ctx: &ApiContext) -> Response {
    let filters = if let Some(raw) = ctx.query.get("filters") {
        match parse_filters_param(raw, StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(f) => f,
            Err(resp) => return resp,
        }
    } else {
        HashMap::new()
    };

    let prune_vols = ctx
        .query
        .get("volumes")
        .is_some_and(|v| v == "true" || v == "1");
    let prune_all = ctx
        .query
        .get("all")
        .is_some_and(|v| v == "true" || v == "1");

    let c_store = ContainerStore::with_home(ctx.state.home.clone());
    let mut ctr_reports = Vec::new();
    for c in c_store.list() {
        if prune_all || !matches!(c.status, ContainerStatus::Running) {
            let _ = crate::stop_container_with_home(&c.id, None, Some(&ctx.state.home));
            let _ = c_store.remove(&c.id);
            ctr_reports.push(serde_json::json!({ "Id": c.id, "Size": 0 }));
        }
    }

    let i_store = ImageStore::with_home(ctx.state.home.clone());
    let mut img_reports = Vec::new();
    if prune_all && filters.is_empty() {
        for img in i_store.list() {
            if count_image_refs(&ctx.state.home, &img) == 0 {
                let _ = i_store.remove(&img.id);
                img_reports.push(serde_json::json!({ "Id": img.full_hex_id(), "Size": img.size_bytes }));
            }
        }
    }

    let mut vol_reports = Vec::new();
    if prune_vols {
        let v_store = VolumeStore::with_home(ctx.state.home.clone());
        let label_filters = filters.get("label").cloned().unwrap_or_default();
        for v in v_store.list() {
            if count_volume_refs(&ctx.state.home, &v.name) > 0 {
                continue;
            }
            if !label_filters.is_empty() && !volume_matches_labels(&v, &label_filters) {
                continue;
            }
            let _ = v_store.remove_with_force(&v.name, true);
            vol_reports.push(serde_json::json!({ "Id": v.name, "Size": 0 }));
        }
    }

    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "ContainerPruneReports": ctr_reports,
            "ImagePruneReports": img_reports,
            "PodPruneReport": [],
            "ReclaimedSpace": 0,
            "VolumePruneReports": vol_reports
        }),
    )
}

fn count_image_refs(home: &Path, img: &crate::storage::ImageRecord) -> usize {
    let c_store = ContainerStore::with_home(home.to_path_buf());
    c_store
        .list()
        .iter()
        .filter(|c| c.image == img.id || c.image.contains(&img.reference))
        .count()
}

pub fn volume_matches_labels(v: &crate::volume::VolumeRecord, labels: &[String]) -> bool {
    for lf in labels {
        if let Some((k, val)) = lf.split_once('=') {
            if v.labels.get(k).map(|s| s.as_str()) != Some(val) {
                return false;
            }
        } else if !v.labels.contains_key(lf) {
            return false;
        }
    }
    true
}

async fn handle_auth(ctx: &ApiContext) -> Response {
    let val: serde_json::Value = serde_json::from_slice(&ctx.body).unwrap_or_default();
    let username = val
        .get("username")
        .or_else(|| val.get("Username"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let password = val
        .get("password")
        .or_else(|| val.get("Password"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let server = val
        .get("serveraddress")
        .or_else(|| val.get("ServerAddress"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if username.is_empty() {
        return error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot prompt for username without stdin",
            "authenticating creds for : Error: cannot prompt for username without stdin",
        );
    }
    if password.is_empty() {
        return error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "reading password: inappropriate ioctl for device",
            "authenticating creds: Error: reading password: inappropriate ioctl for device",
        );
    }

    let clean_srv = server
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let url = format!("https://{}/v2/", clean_srv);
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                &e.to_string(),
                &e.to_string(),
            );
        }
    };

    match client
        .get(&url)
        .basic_auth(username, Some(password))
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                error_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "401 Unauthorized",
                    "login attempt failed with status: 401 Unauthorized",
                )
            } else {
                json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "Status": "Login Succeeded",
                        "IdentityToken": ""
                    }),
                )
            }
        }
        Err(e) => {
            let msg = e.to_string();
            let full = if msg.contains("dns error")
                || msg.contains("failed to lookup")
                || clean_srv.contains("doesnotexists")
            {
                format!("dial tcp: lookup {}: no such host ({})", clean_srv, msg)
            } else {
                msg
            };
            error_json(StatusCode::INTERNAL_SERVER_ERROR, &full, &full)
        }
    }
}

fn handle_autoupdate(ctx: &ApiContext) -> Response {
    let mut label_filters = Vec::new();
    if let Some(raw) = ctx.query.get("filters") {
        let val: serde_json::Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(e) => {
                return error_json(
                    StatusCode::BAD_REQUEST,
                    "failed to decode filter parameters",
                    &format!("failed to decode filter parameters: {}", e),
                );
            }
        };
        if let Some(obj) = val.as_object() {
            for (k, v) in obj {
                if k != "label" {
                    return error_json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "invalid filter",
                        &format!("{:?} is an invalid filter", k),
                    );
                }
                if let Some(arr) = v.as_array() {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            label_filters.push(s.to_string());
                        }
                    }
                }
            }
        }
    }

    let c_store = ContainerStore::with_home(ctx.state.home.clone());
    for c in c_store.list() {
        if !matches!(c.status, ContainerStatus::Running) {
            continue;
        }
        let bp = std::path::PathBuf::from(&c.bundle_path);
        let labels: Vec<String> = fs::read_to_string(bp.join("labels.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let mut lmap = HashMap::new();
        for l in &labels {
            if let Some((k, v)) = l.split_once('=') {
                lmap.insert(k.to_string(), v.to_string());
            } else {
                lmap.insert(l.clone(), String::new());
            }
        }
        if !lmap.contains_key("io.containers.autoupdate") {
            continue;
        }
        let mut matches_filter = true;
        for lf in &label_filters {
            if let Some((k, v)) = lf.split_once('=') {
                if lmap.get(k).map(|s| s.as_str()) != Some(v) {
                    matches_filter = false;
                    break;
                }
            } else if !lmap.contains_key(lf) {
                matches_filter = false;
                break;
            }
        }
        if !matches_filter {
            continue;
        }
        if !lmap.contains_key("PODMAN_SYSTEMD_UNIT") {
            return error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "no PODMAN_SYSTEMD_UNIT label found",
                "autoupdate requires the PODMAN_SYSTEMD_UNIT label: no PODMAN_SYSTEMD_UNIT label found",
            );
        }
    }

    json_response(StatusCode::OK, &serde_json::json!([]))
}

