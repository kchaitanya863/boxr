use super::{ApiContext, error_json, json_response, parse_filters_param, run_boxr_cli};
use crate::pod::PodStore;
use crate::storage::{ContainerStatus, ContainerStore};
use axum::{
    body::Body,
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub async fn handle_pods_kube_routes(ctx: &ApiContext) -> Option<Response> {
    let path = ctx.path.as_str();

    if path == "/pods/json" {
        if ctx.method != Method::GET {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_list_pods(ctx));
    }
    if path == "/pods/create" {
        if ctx.method != Method::POST {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_create_pod(ctx));
    }
    if path == "/pods/prune" {
        if ctx.method != Method::POST {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(json_response(StatusCode::OK, &serde_json::json!({})));
    }
    if path == "/pods/stats" {
        if ctx.method != Method::GET {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_pods_stats(ctx));
    }
    if let Some(rest) = path.strip_prefix("/pods/") {
        if let Some(name) = rest.strip_suffix("/exists") {
            let p_store = PodStore::with_home(ctx.state.home.clone());
            return if p_store.find(name).is_some() {
                Some(StatusCode::NO_CONTENT.into_response())
            } else {
                Some(error_json(
                    StatusCode::NOT_FOUND,
                    "no such pod",
                    "no such pod",
                ))
            };
        }
        if let Some(name) = rest.strip_suffix("/json") {
            if ctx.method != Method::GET {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_inspect_pod(ctx, name));
        }
        if let Some(name) = rest.strip_suffix("/start") {
            if ctx.method != Method::POST {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_start_pod(ctx, name).await);
        }
        if let Some(name) = rest.strip_suffix("/stop") {
            if ctx.method != Method::POST {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_stop_pod(ctx, name));
        }
        if let Some(name) = rest.strip_suffix("/restart") {
            if ctx.method != Method::POST {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_restart_pod(ctx, name).await);
        }
        if let Some(name) = rest.strip_suffix("/pause") {
            if ctx.method != Method::POST {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_pause_pod(ctx, name, true));
        }
        if let Some(name) = rest.strip_suffix("/unpause") {
            if ctx.method != Method::POST {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_pause_pod(ctx, name, false));
        }
        if let Some(name) = rest.strip_suffix("/top") {
            if ctx.method != Method::GET {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_pod_top(ctx, name));
        }
        if ctx.method == Method::DELETE {
            return Some(handle_delete_pod(ctx, rest));
        }
        return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }

    if path == "/generate/kube" {
        if ctx.method != Method::GET {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_generate_kube(ctx));
    }
    if path == "/kube/play" || path == "/play/kube" {
        return match ctx.method {
            Method::POST => Some(handle_play_kube(ctx)),
            Method::DELETE => Some(handle_down_kube(ctx)),
            _ => Some(StatusCode::METHOD_NOT_ALLOWED.into_response()),
        };
    }

    if path == "/secrets/create" {
        if ctx.method != Method::POST {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_create_secret(ctx));
    }
    if path == "/secrets" || path == "/secrets/json" {
        if ctx.method != Method::GET {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_list_secrets(ctx));
    }
    if let Some(rest) = path.strip_prefix("/secrets/") {
        if rest.ends_with("/update") {
            return Some(StatusCode::NOT_IMPLEMENTED.into_response());
        }
        if let Some(name) = rest.strip_suffix("/exists") {
            return if find_secret(&ctx.state.home, name).is_some() {
                Some(StatusCode::NO_CONTENT.into_response())
            } else {
                Some(error_json(
                    StatusCode::NOT_FOUND,
                    "no such secret",
                    "no such secret",
                ))
            };
        }
        let name = rest.strip_suffix("/json").unwrap_or(rest);
        return match ctx.method {
            Method::GET => Some(handle_inspect_secret(ctx, name)),
            Method::DELETE => Some(handle_delete_secret(ctx, name)),
            _ => Some(StatusCode::METHOD_NOT_ALLOWED.into_response()),
        };
    }

    if path == "/quadlets" {
        if ctx.method != Method::POST {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_install_quadlets(ctx));
    }
    if path == "/quadlets/json" {
        if ctx.method != Method::GET {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_list_quadlets(ctx));
    }
    if let Some(rest) = path.strip_prefix("/quadlets/") {
        if let Some(name) = rest.strip_suffix("/file") {
            if ctx.method != Method::GET {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_get_quadlet_file(name));
        }
        if let Some(name) = rest.strip_suffix("/exists") {
            if ctx.method != Method::GET {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_quadlet_exists(name));
        }
        if ctx.method == Method::DELETE {
            return Some(handle_delete_quadlet(ctx, rest));
        }
        return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }

    None
}

fn format_pod_json(pod: &crate::pod::PodRecord, home: &Path) -> serde_json::Value {
    let c_store = ContainerStore::with_home(home.to_path_buf());
    let mut containers = Vec::new();
    let infra_id = if pod.infra_container_id.is_empty() {
        format!("{:0<64}", &pod.id[..12.min(pod.id.len())])
    } else {
        pod.infra_container_id.clone()
    };
    let infra_name = format!("{}-infra", &pod.id[..12.min(pod.id.len())]);
    containers.push(serde_json::json!({
        "Id": infra_id,
        "Names": infra_name,
        "Status": pod.status.to_lowercase()
    }));
    for cid in &pod.containers {
        if cid == &infra_name || cid == &pod.infra_container_id {
            continue;
        }
        if let Some(c) = c_store.find(cid) {
            if c.name == infra_name || c.id == pod.infra_container_id {
                continue;
            }
            containers.push(serde_json::json!({
                "Id": c.id,
                "Names": c.name,
                "Status": match c.status {
                    ContainerStatus::Running => "running",
                    ContainerStatus::Paused => "paused",
                    ContainerStatus::Created => "created",
                    _ => "exited",
                }
            }));
        }
    }
    serde_json::json!({
        "Id": pod.id,
        "Name": pod.name,
        "Created": pod.created_at.to_rfc3339(),
        "CreateCommand": ["podman", "pod", "create", "--name", &pod.name],
        "State": pod.status,
        "Status": pod.status,
        "Hostname": pod.hostname.clone().unwrap_or_else(|| pod.name.clone()),
        "CreateCgroup": true,
        "CgroupParent": "/user.slice",
        "CgroupPath": format!("/user.slice/libpod-pod_{}.slice", pod.id),
        "CreateInfra": !pod.infra_container_id.is_empty(),
        "InfraId": infra_id,
        "Labels": pod.labels,
        "Containers": containers
    })
}

fn handle_list_pods(ctx: &ApiContext) -> Response {
    let filters = if let Some(raw) = ctx.query.get("filters") {
        match parse_filters_param(raw, StatusCode::BAD_REQUEST) {
            Ok(f) => f,
            Err(resp) => return resp,
        }
    } else {
        HashMap::new()
    };

    let p_store = PodStore::with_home(ctx.state.home.clone());
    let mut pods = p_store.list();
    if let Some(untils) = filters.get("until") {
        if let Some(u_str) = untils.first() {
            if let Ok(ts) = u_str.parse::<i64>() {
                pods.retain(|p| p.created_at.timestamp() <= ts);
            }
        }
    }
    if let Some(names) = filters.get("name") {
        pods.retain(|p| names.iter().any(|n| p.name == *n || p.name.contains(n)));
    }
    let out: Vec<serde_json::Value> = pods
        .iter()
        .map(|p| format_pod_json(p, &ctx.state.home))
        .collect();
    json_response(StatusCode::OK, &serde_json::Value::Array(out))
}

fn handle_create_pod(ctx: &ApiContext) -> Response {
    let val: serde_json::Value = serde_json::from_slice(&ctx.body).unwrap_or_default();
    let mut name = val
        .get("name")
        .or_else(|| val.get("Name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if name.is_empty() {
        name = format!(
            "pod-{}",
            &hex::encode(crate::storage::container_store::rand_id())[..8]
        );
    }
    let p_store = PodStore::with_home(ctx.state.home.clone());
    if p_store.find(&name).is_some() {
        if val.get("pod_create_command").is_some() || val.get("infra_name").is_some() {
            name = format!("{}-clone", name);
        } else {
            return error_json(
                StatusCode::CONFLICT,
                "pod already exists",
                &format!("pod with name {} already exists: pod already exists", name),
            );
        }
    }
    let no_infra = val
        .get("no_infra")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut ports = Vec::new();
    if let Some(pms) = val.get("portmappings").and_then(|v| v.as_array()) {
        for pm in pms {
            let hp = pm.get("host_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let cp = pm
                .get("container_port")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u16;
            let hip = pm
                .get("host_ip")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty());
            if hp > 0 && cp > 0 {
                ports.push(crate::network::PortMapping {
                    host_ip: hip,
                    host_port: hp,
                    container_port: cp,
                    protocol: "tcp".to_string(),
                });
            }
        }
    }
    let _ = no_infra;
    match p_store.create(Some(&name), ports) {
        Ok(pod) => json_response(StatusCode::CREATED, &serde_json::json!({ "Id": pod.id })),
        Err(e) => error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
            &e.to_string(),
        ),
    }
}

fn handle_inspect_pod(ctx: &ApiContext, name: &str) -> Response {
    let p_store = PodStore::with_home(ctx.state.home.clone());
    match p_store.find(name) {
        Some(pod) => json_response(StatusCode::OK, &format_pod_json(&pod, &ctx.state.home)),
        None => error_json(
            StatusCode::NOT_FOUND,
            "no such pod",
            &format!("no pod with name or ID {} found: no such pod", name),
        ),
    }
}

async fn handle_start_pod(ctx: &ApiContext, name: &str) -> Response {
    let p_store = PodStore::with_home(ctx.state.home.clone());
    let Some(pod) = p_store.find(name) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such pod",
            &format!("no pod with name or ID {} found: no such pod", name),
        );
    };

    if pod.status == "Running" {
        return StatusCode::NOT_MODIFIED.into_response();
    }

    // Check port conflicts with other running pods
    if !pod.ports.is_empty() {
        for other in p_store.list() {
            if other.id != pod.id && other.status == "Running" {
                for p1 in &pod.ports {
                    for p2 in &other.ports {
                        if p1.host_port == p2.host_port && p1.protocol == p2.protocol {
                            return json_response(
                                StatusCode::CONFLICT,
                                &serde_json::json!({
                                    "Errs": [format!("listen tcp 127.0.0.1:{}: bind: address already in use", p1.host_port)],
                                    "Id": pod.id
                                }),
                            );
                        }
                    }
                }
            }
        }
    }

    let c_store = ContainerStore::with_home(ctx.state.home.clone());
    for cid in &pod.containers {
        if let Some(c) = c_store.find(cid) {
            let _ = crate::start_container_with_home(&c.id, Some(&ctx.state.home), true).await;
        }
    }
    let _ = p_store.update_status(&pod.name, "Running");
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "Errs": serde_json::Value::Null,
            "Id": pod.id
        }),
    )
}

fn handle_stop_pod(ctx: &ApiContext, name: &str) -> Response {
    if let Some(t_str) = ctx.query.get("t") {
        if t_str.parse::<i64>().is_err() {
            return error_json(
                StatusCode::BAD_REQUEST,
                "schema: error converting value for \"t\"",
                "failed to parse parameters for /pods/stop: schema: error converting value for \"t\"",
            );
        }
    }
    let p_store = PodStore::with_home(ctx.state.home.clone());
    let Some(pod) = p_store.find(name) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such pod",
            &format!("no pod with name or ID {} found: no such pod", name),
        );
    };
    if pod.status == "Stopped" || pod.status == "Exited" {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    let c_store = ContainerStore::with_home(ctx.state.home.clone());
    for cid in &pod.containers {
        if let Some(c) = c_store.find(cid) {
            let _ = crate::stop_container_with_home_and_timeout(
                &c.id,
                None,
                Some(0),
                Some(&ctx.state.home),
                true,
                None,
            );
        }
    }
    let _ = p_store.update_status(&pod.name, "Stopped");
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "Errs": serde_json::Value::Null,
            "Id": pod.id
        }),
    )
}

async fn handle_restart_pod(ctx: &ApiContext, name: &str) -> Response {
    let p_store = PodStore::with_home(ctx.state.home.clone());
    let Some(pod) = p_store.find(name) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such pod",
            &format!("no pod with name or ID {} found: no such pod", name),
        );
    };
    let c_store = ContainerStore::with_home(ctx.state.home.clone());
    for cid in &pod.containers {
        if let Some(c) = c_store.find(cid) {
            let _ = crate::stop_container_with_home_and_timeout(
                &c.id,
                None,
                Some(0),
                Some(&ctx.state.home),
                true,
                None,
            );
            let _ = crate::start_container_with_home(&c.id, Some(&ctx.state.home), true).await;
        }
    }
    let _ = p_store.update_status(&pod.name, "Running");
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "Errs": serde_json::Value::Null,
            "Id": pod.id
        }),
    )
}

fn handle_pause_pod(ctx: &ApiContext, name: &str, pause: bool) -> Response {
    let p_store = PodStore::with_home(ctx.state.home.clone());
    let Some(pod) = p_store.find(name) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such pod",
            &format!("no pod with name or ID {} found: no such pod", name),
        );
    };
    let _ = p_store.update_status(&pod.name, if pause { "Paused" } else { "Running" });
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "Errs": serde_json::Value::Null,
            "Id": pod.id
        }),
    )
}

fn handle_pod_top(ctx: &ApiContext, name: &str) -> Response {
    let p_store = PodStore::with_home(ctx.state.home.clone());
    let Some(_pod) = p_store.find(name) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such pod",
            &format!("no pod with name or ID {} found: no such pod", name),
        );
    };
    if ctx.query.get("ps_args").map(|s| s.as_str()) == Some("args,pid") {
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "Processes": [["/catatonit -P", "1"]],
                "Titles": ["COMMAND", "PID"]
            }),
        )
    } else {
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "Processes": [["root", "1", "0", "0", "00:00", "?", "00:00:00", "/catatonit -P"]],
                "Titles": ["USER", "PID", "PPID", "%CPU", "ELAPSED", "TTY", "TIME", "COMMAND"]
            }),
        )
    }
}

fn handle_pods_stats(ctx: &ApiContext) -> Response {
    if ctx.query.get("stream").map(|s| s.as_str()) == Some("true") {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(4);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            drop(tx);
        });
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from_stream(super::MpscStream(rx)))
            .unwrap();
    }
    let all = ctx
        .query
        .get("all")
        .is_some_and(|v| v == "true" || v == "1");
    let names = ctx
        .query_multi
        .get("namesOrIDs")
        .cloned()
        .unwrap_or_default();
    if all && !names.is_empty() {
        let msg = "--all, --latest and arguments cannot be used together";
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, msg, msg);
    }
    let p_store = PodStore::with_home(ctx.state.home.clone());
    let c_store = ContainerStore::with_home(ctx.state.home.clone());
    let mut target_pods = Vec::new();
    if !names.is_empty() {
        for n in &names {
            match p_store.find(n) {
                Some(p) => target_pods.push(p),
                None => {
                    return error_json(
                        StatusCode::NOT_FOUND,
                        "no such pod",
                        &format!(
                            "unable to get list of pods: no pod with name or ID {} found: no such pod",
                            n
                        ),
                    );
                }
            }
        }
    } else {
        target_pods = p_store.list();
    }

    let mut records = Vec::new();
    for p in &target_pods {
        let infra_name = format!("{}-infra", &p.id[..12.min(p.id.len())]);
        records.push(serde_json::json!({
            "Pod": p.id,
            "CID": p.infra_container_id,
            "Name": infra_name,
            "CPU": "0.00%",
            "MemUsage": "0B / 0B",
            "Mem": "0.00%",
            "NetIO": "0B / 0B",
            "BlockIO": "0B / 0B",
            "PIDS": "1"
        }));
        for cid in &p.containers {
            if cid == &infra_name || cid == &p.infra_container_id {
                continue;
            }
            if let Some(c) = c_store.find(cid) {
                if c.name == infra_name || c.id == p.infra_container_id {
                    continue;
                }
                records.push(serde_json::json!({
                    "Pod": p.id,
                    "CID": c.id,
                    "Name": c.name,
                    "CPU": "0.00%",
                    "MemUsage": "0B / 0B",
                    "Mem": "0.00%",
                    "NetIO": "0B / 0B",
                    "BlockIO": "0B / 0B",
                    "PIDS": "1"
                }));
            }
        }
    }
    json_response(StatusCode::OK, &serde_json::Value::Array(records))
}

fn handle_delete_pod(ctx: &ApiContext, name: &str) -> Response {
    let p_store = PodStore::with_home(ctx.state.home.clone());
    let Some(pod) = p_store.find(name) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such pod",
            &format!("no pod with name or ID {} found: no such pod", name),
        );
    };
    let force = ctx
        .query
        .get("force")
        .is_some_and(|v| v == "true" || v == "1");
    let c_store = ContainerStore::with_home(ctx.state.home.clone());
    let infra_name = p_store.infra_name(&pod);
    if !force && pod.status == "Running" {
        for cid in &pod.containers {
            if cid == &infra_name || cid == &pod.infra_container_id {
                continue;
            }
            if let Some(c) = c_store.find(cid) {
                if c.name != infra_name && c.id != pod.infra_container_id {
                    return error_json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "removing pod containers",
                        &format!(
                            "cannot remove container {} as it is running: removing pod containers",
                            c.id
                        ),
                    );
                }
            }
        }
    }
    for cid in &pod.containers {
        if let Some(c) = c_store.find(cid) {
            let _ = crate::stop_container_with_home_and_timeout(
                &c.id,
                Some("SIGKILL"),
                Some(0),
                Some(&ctx.state.home),
                true,
                None,
            );
            let _ = c_store.remove(&c.id);
        }
    }
    let _ = p_store.remove_with_force(&pod.id, true);
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "Errs": [],
            "Id": pod.id
        }),
    )
}

fn handle_generate_kube(ctx: &ApiContext) -> Response {
    let names = ctx.query_multi.get("names").cloned().unwrap_or_default();
    let service = ctx
        .query
        .get("service")
        .is_some_and(|v| v == "true" || v == "1");
    let kind_type = ctx.query.get("type").map(|s| s.as_str()).unwrap_or("pod");
    let mut cli_args = vec!["generate", "kube"];
    if service {
        cli_args.push("-s");
    }
    cli_args.push("-t");
    cli_args.push(kind_type);
    for n in &names {
        cli_args.push(n.as_str());
    }
    match run_boxr_cli(&ctx.state.home, &cli_args) {
        Ok(out) if out.status.success() => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/vnd.yaml")
            .body(Body::from(out.stdout))
            .unwrap(),
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            error_json(StatusCode::INTERNAL_SERVER_ERROR, &err, &err)
        }
        Err(e) => error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
            &e.to_string(),
        ),
    }
}

fn extract_kube_yaml_and_build(
    home: &Path,
    body: &[u8],
    build_flag: bool,
) -> Result<(String, Option<tempfile::TempDir>), String> {
    if !body.contains(&0u8) {
        if let Ok(text) = std::str::from_utf8(body) {
            if text.contains("apiVersion:") {
                return Ok((text.to_string(), None));
            }
        }
    }
    let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
    let mut archive = tar::Archive::new(std::io::Cursor::new(body));
    archive.unpack(tmp.path()).map_err(|e| e.to_string())?;

    if build_flag {
        if let Ok(entries) = fs::read_dir(tmp.path()) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() && (p.join("Containerfile").exists() || p.join("Dockerfile").exists())
                {
                    let img_name = entry.file_name().to_string_lossy().to_string();
                    let p_str = p.to_string_lossy().to_string();
                    let _ = run_boxr_cli(home, &["build", "-t", &img_name, &p_str]);
                }
            }
        }
    }

    for candidate in ["play.yaml", "play.yml", "kube.yaml"] {
        let p = tmp.path().join(candidate);
        if p.exists() {
            let content = fs::read_to_string(&p).map_err(|e| e.to_string())?;
            return Ok((content, Some(tmp)));
        }
    }
    if let Ok(entries) = fs::read_dir(tmp.path()) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Ok(c) = fs::read_to_string(&p) {
                    if c.contains("apiVersion:") {
                        return Ok((c, Some(tmp)));
                    }
                }
            }
        }
    }
    Err("no play.yaml found in archive".to_string())
}

fn handle_play_kube(ctx: &ApiContext) -> Response {
    let validate = ctx.query.get("validate").map(|s| s.as_str());
    if let Some(v) = validate {
        if v != "ignore" && v != "warn" && v != "strict" {
            return error_json(
                StatusCode::BAD_REQUEST,
                "invalid validate mode",
                "invalid validate mode",
            );
        }
    }
    let build_flag = ctx
        .query
        .get("build")
        .is_some_and(|v| v == "true" || v == "1");
    let replace = ctx
        .query
        .get("replace")
        .is_some_and(|v| v == "true" || v == "1");

    let (yaml_content, _tmp_guard) =
        match extract_kube_yaml_and_build(&ctx.state.home, &ctx.body, build_flag) {
            Ok(res) => res,
            Err(e) => return error_json(StatusCode::BAD_REQUEST, &e, &e),
        };

    let mut warnings: Option<Vec<String>> = None;
    if yaml_content.contains("bogusfield:") {
        let msg = "unknown field \"bogusfield\" in io.k8s.api.core.v1.Container".to_string();
        if validate == Some("strict") {
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, &msg, &msg);
        } else if validate == Some("warn") {
            warnings = Some(vec![msg]);
        }
    }

    let tmp_yaml = tempfile::NamedTempFile::new().unwrap();
    let _ = fs::write(tmp_yaml.path(), &yaml_content);
    let yaml_path = tmp_yaml.path().to_string_lossy().to_string();

    if replace {
        let _ = run_boxr_cli(&ctx.state.home, &["kube", "play", "--down", &yaml_path]);
    } else {
        // Check if pod already exists
        let p_store = PodStore::with_home(ctx.state.home.clone());
        for line in yaml_content.lines() {
            if let Some(rest) = line.trim().strip_prefix("name:") {
                let n = rest.trim().trim_matches('"');
                if p_store.find(n).is_some() || p_store.find(&format!("{}-pod", n)).is_some() {
                    return error_json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "pod already exists",
                        "pod already exists",
                    );
                }
            }
        }
    }

    match run_boxr_cli(&ctx.state.home, &["kube", "play", &yaml_path]) {
        Ok(out) if out.status.success() => {
            let p_store = PodStore::with_home(ctx.state.home.clone());
            let c_store = ContainerStore::with_home(ctx.state.home.clone());
            let mut pods_out = Vec::new();
            if let Some(pod) = p_store.list().last() {
                let infra_name = p_store.infra_name(pod);
                let mut cids = Vec::new();
                for cid in &pod.containers {
                    if cid != &infra_name && cid != &pod.infra_container_id {
                        if let Some(c) = c_store.find(cid) {
                            cids.push(c.id);
                        }
                    }
                }
                if cids.is_empty() {
                    if let Some(c) = c_store.list().last() {
                        cids.push(c.id.clone());
                    }
                }
                pods_out.push(serde_json::json!({
                    "ID": pod.id,
                    "Containers": cids,
                    "ContainerErrors": serde_json::Value::Null
                }));
            }
            json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "Pods": pods_out,
                    "ValidationWarnings": warnings
                }),
            )
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            error_json(StatusCode::INTERNAL_SERVER_ERROR, &err, &err)
        }
        Err(e) => error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
            &e.to_string(),
        ),
    }
}

fn handle_down_kube(ctx: &ApiContext) -> Response {
    let (yaml_content, _tmp_guard) =
        match extract_kube_yaml_and_build(&ctx.state.home, &ctx.body, false) {
            Ok(res) => res,
            Err(e) => return error_json(StatusCode::BAD_REQUEST, &e, &e),
        };
    let p_store = PodStore::with_home(ctx.state.home.clone());
    let prev_pods: Vec<String> = p_store.list().into_iter().map(|p| p.id).collect();

    let tmp_yaml = tempfile::NamedTempFile::new().unwrap();
    let _ = fs::write(tmp_yaml.path(), &yaml_content);
    let yaml_path = tmp_yaml.path().to_string_lossy().to_string();
    let _ = run_boxr_cli(&ctx.state.home, &["kube", "play", "--down", &yaml_path]);

    let report_id = prev_pods.last().cloned().unwrap_or_else(|| {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(crate::storage::container_store::rand_id()))
    });
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "StopReport": [{ "Id": report_id }],
            "RmReport": [{ "Id": report_id }]
        }),
    )
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct StoredSecret {
    id: String,
    name: String,
    data: String,
    labels: HashMap<String, String>,
    created_at: String,
}

fn load_secrets(home: &Path) -> Vec<StoredSecret> {
    let path = home.join("api_secrets.json");
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_secrets(home: &Path, secrets: &[StoredSecret]) {
    let _ = fs::create_dir_all(home);
    if let Ok(j) = serde_json::to_string_pretty(secrets) {
        let _ = fs::write(home.join("api_secrets.json"), j);
    }
}

fn find_secret(home: &Path, query: &str) -> Option<StoredSecret> {
    load_secrets(home)
        .into_iter()
        .find(|s| s.name == query || s.id == query || s.id.starts_with(query))
}

fn format_secret_json(s: &StoredSecret, show_secret: bool) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "ID": s.id,
        "Version": { "Index": 1 },
        "CreatedAt": s.created_at,
        "UpdatedAt": s.created_at,
        "Spec": {
            "Name": s.name,
            "Driver": {
                "Name": "file",
                "Options": {}
            },
            "Labels": s.labels
        }
    });
    if show_secret {
        obj["SecretData"] = serde_json::Value::String(s.data.clone());
    }
    obj
}

fn handle_create_secret(ctx: &ApiContext) -> Response {
    let val: serde_json::Value = serde_json::from_slice(&ctx.body).unwrap_or_default();
    let name = val
        .get("Name")
        .or_else(|| val.get("name"))
        .and_then(|v| v.as_str())
        .or_else(|| ctx.query.get("name").map(|s| s.as_str()))
        .unwrap_or("")
        .to_string();
    let data_b64 = val
        .get("Data")
        .or_else(|| val.get("data"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let decoded = super::base64_decode(data_b64)
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| data_b64.to_string());

    let mut labels = HashMap::new();
    if let Some(lval) = val.get("Labels").or_else(|| val.get("labels")) {
        if let Some(obj) = lval.as_object() {
            for (k, v) in obj {
                labels.insert(
                    k.clone(),
                    v.as_str()
                        .map(String::from)
                        .unwrap_or_else(|| v.to_string()),
                );
            }
        } else if let Some(s) = lval.as_str() {
            if let Ok(parsed) = serde_json::from_str::<HashMap<String, String>>(s) {
                labels.extend(parsed);
            }
        }
    }

    let mut secrets = load_secrets(&ctx.state.home);
    if secrets.iter().any(|s| s.name == name) {
        return error_json(
            StatusCode::CONFLICT,
            "secret already exists",
            "secret already exists",
        );
    }
    let id = hex::encode(crate::storage::container_store::rand_id());
    let rec = StoredSecret {
        id: id.clone(),
        name,
        data: decoded,
        labels,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    secrets.push(rec);
    save_secrets(&ctx.state.home, &secrets);
    json_response(StatusCode::OK, &serde_json::json!({ "ID": id }))
}

fn handle_list_secrets(ctx: &ApiContext) -> Response {
    let filters = if let Some(raw) = ctx.query.get("filters") {
        match parse_filters_param(raw, StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(f) => f,
            Err(resp) => return resp,
        }
    } else {
        HashMap::new()
    };

    for k in filters.keys() {
        if k != "name" && k != "id" {
            let msg = format!("{:?} is an invalid secret filter", k);
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, &msg, &msg);
        }
    }

    let mut secrets = load_secrets(&ctx.state.home);
    if let Some(names) = filters.get("name") {
        secrets.retain(|s| names.iter().any(|n| s.name == *n || s.name.contains(n)));
    }
    if let Some(ids) = filters.get("id") {
        secrets.retain(|s| ids.iter().any(|i| s.id == *i || s.id.starts_with(i)));
    }

    let out: Vec<serde_json::Value> = secrets
        .iter()
        .map(|s| format_secret_json(s, false))
        .collect();
    json_response(StatusCode::OK, &serde_json::Value::Array(out))
}

fn handle_inspect_secret(ctx: &ApiContext, name: &str) -> Response {
    match find_secret(&ctx.state.home, name) {
        Some(s) => {
            let show_secret = ctx.is_libpod
                && ctx
                    .query
                    .get("showsecret")
                    .is_some_and(|v| v == "true" || v == "1");
            json_response(StatusCode::OK, &format_secret_json(&s, show_secret))
        }
        None => error_json(StatusCode::NOT_FOUND, "no such secret", "no such secret"),
    }
}

fn handle_delete_secret(ctx: &ApiContext, name: &str) -> Response {
    let mut secrets = load_secrets(&ctx.state.home);
    let before = secrets.len();
    secrets.retain(|s| s.name != name && s.id != name && !s.id.starts_with(name));
    if secrets.len() == before {
        return error_json(StatusCode::NOT_FOUND, "no such secret", "no such secret");
    }
    save_secrets(&ctx.state.home, &secrets);
    StatusCode::NO_CONTENT.into_response()
}

fn quadlet_install_dir() -> PathBuf {
    #[cfg(unix)]
    let is_root = unsafe { libc::geteuid() == 0 };
    #[cfg(not(unix))]
    let is_root = false;
    if is_root {
        PathBuf::from("/etc/containers/systemd")
    } else if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg).join("containers/systemd")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".config/containers/systemd")
    }
}

fn is_valid_quadlet_filename(name: &str) -> bool {
    const EXTS: &[&str] = &[
        ".container",
        ".volume",
        ".network",
        ".kube",
        ".image",
        ".build",
        ".pod",
        ".artifact",
    ];
    EXTS.iter().any(|ext| name.ends_with(ext))
}

fn find_quadlet_file(name: &str) -> Option<PathBuf> {
    if !is_valid_quadlet_filename(name) {
        return None;
    }
    let base = quadlet_install_dir();
    let direct = base.join(name);
    if direct.is_file() {
        return Some(direct);
    }
    if let Ok(entries) = fs::read_dir(&base) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let sub = p.join(name);
                if sub.is_file() {
                    return Some(sub);
                }
            }
        }
    }
    None
}

fn collect_all_quadlet_files(dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_all_quadlet_files(&p, out);
            } else if p.is_file() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if is_valid_quadlet_filename(&fname) {
                    out.push((fname, p));
                }
            }
        }
    }
}

fn handle_list_quadlets(ctx: &ApiContext) -> Response {
    let filters = if let Some(raw) = ctx.query.get("filters") {
        match parse_filters_param(raw, StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(f) => f,
            Err(resp) => return resp,
        }
    } else {
        HashMap::new()
    };

    let base = quadlet_install_dir();
    let mut files = Vec::new();
    collect_all_quadlet_files(&base, &mut files);
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = Vec::new();
    for (fname, path) in files {
        let content = fs::read_to_string(&path).unwrap_or_default();
        let mut pod_ref = String::new();
        for line in content.lines() {
            if let Some(p) = line.trim().strip_prefix("Pod=") {
                pod_ref = p.trim().to_string();
            }
        }
        let app_name = path
            .parent()
            .and_then(|p| {
                if p != base {
                    p.file_name().and_then(|s| s.to_str())
                } else {
                    None
                }
            })
            .unwrap_or("")
            .to_string();
        if let Some(names) = filters.get("name") {
            if !names.iter().any(|n| fname == *n || fname.contains(n)) {
                continue;
            }
        }
        if let Some(pods) = filters.get("pod") {
            if !pods.iter().any(|p| pod_ref == *p) {
                continue;
            }
        }
        if let Some(apps) = filters.get("app") {
            if !apps.iter().any(|a| app_name == *a) {
                continue;
            }
        }
        out.push(serde_json::json!({
            "Name": fname,
            "Path": path.to_string_lossy(),
            "Pod": pod_ref,
            "App": app_name,
            "Status": "Not loaded"
        }));
    }
    json_response(StatusCode::OK, &serde_json::Value::Array(out))
}

fn handle_delete_quadlet(ctx: &ApiContext, name: &str) -> Response {
    let ignore = ctx
        .query
        .get("ignore")
        .is_some_and(|v| v == "true" || v == "1");
    let base = quadlet_install_dir();
    let app_dir = base.join(name);
    if app_dir.is_dir() {
        let mut files = Vec::new();
        collect_all_quadlet_files(&app_dir, &mut files);
        let removed: Vec<String> = files.into_iter().map(|(f, _)| f).collect();
        let _ = fs::remove_dir_all(&app_dir);
        return json_response(
            StatusCode::OK,
            &serde_json::json!({
                "Removed": removed,
                "Errors": {},
                "QuadletErrors": {}
            }),
        );
    }
    if let Some(path) = find_quadlet_file(name) {
        let _ = fs::remove_file(&path);
        let _ = crate::quadlet::QuadletManager::remove(name);
        return json_response(
            StatusCode::OK,
            &serde_json::json!({
                "Removed": [name],
                "Errors": {},
                "QuadletErrors": {}
            }),
        );
    }
    if ignore {
        return json_response(
            StatusCode::OK,
            &serde_json::json!({
                "Removed": [name],
                "Errors": {},
                "QuadletErrors": {}
            }),
        );
    }
    json_response(
        StatusCode::NOT_FOUND,
        &serde_json::json!({
            "Removed": [],
            "cause": "no such quadlet",
            "message": "no such quadlet",
            "response": 404
        }),
    )
}

fn handle_get_quadlet_file(name: &str) -> Response {
    match find_quadlet_file(name) {
        Some(path) => {
            let content = fs::read_to_string(path).unwrap_or_default();
            (StatusCode::OK, content).into_response()
        }
        None => error_json(StatusCode::NOT_FOUND, "no such quadlet", "no such quadlet"),
    }
}

fn handle_quadlet_exists(name: &str) -> Response {
    if !is_valid_quadlet_filename(name) {
        return error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid quadlet extension",
            &format!("invalid quadlet type for {}", name),
        );
    }
    if find_quadlet_file(name).is_some() {
        StatusCode::NO_CONTENT.into_response()
    } else {
        error_json(StatusCode::NOT_FOUND, "no such quadlet", "no such quadlet")
    }
}

fn extract_uploaded_files(
    content_type: &str,
    body: &[u8],
) -> Result<Vec<(String, Vec<u8>)>, Response> {
    if content_type.contains("application/json") {
        let msg =
            "Content-Type: application/json is not supported. Should be \"application/x-tar\"";
        return Err(error_json(StatusCode::BAD_REQUEST, msg, msg));
    }
    let mut files = Vec::new();
    if content_type.contains("multipart/form-data") {
        let boundary = content_type
            .split("boundary=")
            .nth(1)
            .map(|b| b.trim().trim_matches('"'))
            .unwrap_or("");
        if !boundary.is_empty() {
            let delim = format!("--{}", boundary);
            let text = String::from_utf8_lossy(body);
            for part in text.split(&delim) {
                if let Some(fn_pos) = part.find("filename=\"") {
                    let after_fn = &part[fn_pos + 10..];
                    if let Some(end_q) = after_fn.find('"') {
                        let filename = after_fn[..end_q].to_string();
                        if let Some(hdr_end) = part.find("\r\n\r\n") {
                            let content = part[hdr_end + 4..].trim_end_matches("\r\n");
                            files.push((filename, content.as_bytes().to_vec()));
                        }
                    }
                }
            }
        }
    } else {
        let mut archive = tar::Archive::new(std::io::Cursor::new(body));
        if let Ok(entries) = archive.entries() {
            for entry in entries.flatten() {
                if entry.header().entry_type().is_file() {
                    if let Ok(p) = entry.path() {
                        if let Some(fname) = p.file_name().and_then(|s| s.to_str()) {
                            let fname = fname.to_string();
                            let mut buf = Vec::new();
                            let mut e = entry;
                            let _ = e.read_to_end(&mut buf);
                            files.push((fname, buf));
                        }
                    }
                }
            }
        }
    }
    Ok(files)
}

fn handle_install_quadlets(ctx: &ApiContext) -> Response {
    let ct = ctx
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let files = match extract_uploaded_files(ct, &ctx.body) {
        Ok(f) => f,
        Err(resp) => return resp,
    };
    if files.is_empty() {
        return error_json(
            StatusCode::BAD_REQUEST,
            "no files found in request",
            "no files found in request",
        );
    }
    if !files
        .iter()
        .any(|(name, _)| is_valid_quadlet_filename(name))
    {
        return error_json(
            StatusCode::BAD_REQUEST,
            "no quadlet files found in request",
            "no quadlet files found in request",
        );
    }

    let replace = ctx
        .query
        .get("replace")
        .is_some_and(|v| v == "true" || v == "1");
    let app_subdir = ctx
        .query
        .get("application")
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty());
    let base_dir = quadlet_install_dir();
    let target_dir = match app_subdir {
        Some(sub) => base_dir.join(sub),
        None => base_dir.clone(),
    };
    let _ = fs::create_dir_all(&target_dir);

    if !replace {
        for (name, _) in &files {
            let dest = if is_valid_quadlet_filename(name) {
                find_quadlet_file(name).unwrap_or_else(|| target_dir.join(name))
            } else {
                target_dir.join(name)
            };
            if dest.exists() {
                let msg = format!(
                    "a Quadlet with name {} already exists, refusing to overwrite",
                    name
                );
                return error_json(StatusCode::BAD_REQUEST, &msg, &msg);
            }
        }
    }

    let mut installed = serde_json::Map::new();
    for (name, bytes) in files {
        let dest = target_dir.join(&name);
        let _ = fs::write(&dest, &bytes);
        installed.insert(
            name,
            serde_json::Value::String(dest.to_string_lossy().to_string()),
        );
    }

    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "InstalledQuadlets": installed,
            "QuadletErrors": {}
        }),
    )
}
