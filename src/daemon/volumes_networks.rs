use super::{ApiContext, DaemonState, error_json, json_response, parse_filters_param};
use crate::network::NetworkStore;
use crate::storage::{ContainerStatus, ContainerStore};
use crate::volume::VolumeStore;
use axum::{
    Json,
    extract::{Path, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

pub async fn list_networks(State(state): State<DaemonState>) -> Json<serde_json::Value> {
    let store = NetworkStore::with_home(state.home.clone());
    Json(serde_json::to_value(store.list()).unwrap_or_default())
}

#[derive(Deserialize)]
pub struct CreateNetworkRequest {
    #[serde(rename = "Name")]
    pub name: String,
}

pub async fn create_network(
    State(state): State<DaemonState>,
    Json(payload): Json<CreateNetworkRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = NetworkStore::with_home(state.home.clone());
    match store.create(&payload.name, None, None) {
        Ok(net) => Ok(Json(serde_json::to_value(net).unwrap())),
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

pub async fn inspect_network(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = NetworkStore::with_home(state.home.clone());
    let net = store.find(&id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(
        serde_json::to_value(net).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    ))
}

pub async fn remove_network(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> StatusCode {
    let store = NetworkStore::with_home(state.home.clone());
    match store.remove(&id) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            if msg.contains("active endpoints")
                || msg.contains("associated containers")
                || msg.contains("being used")
                || msg.contains("default bridge")
                || msg.contains("in use")
            {
                StatusCode::CONFLICT
            } else {
                StatusCode::NOT_FOUND
            }
        }
    }
}

#[derive(Deserialize)]
pub struct ConnectNetworkRequest {
    #[serde(rename = "Container")]
    pub container: String,
}

pub async fn connect_network(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    Json(payload): Json<ConnectNetworkRequest>,
) -> Result<StatusCode, StatusCode> {
    let store = NetworkStore::with_home(state.home.clone());
    let c_store = crate::storage::ContainerStore::with_home(state.home.clone());
    let c = c_store
        .find(&payload.container)
        .ok_or(StatusCode::NOT_FOUND)?;
    store.connect_container(&id, &c.id, &c.name).map_err(|e| {
        let msg = e.to_string().to_lowercase();
        if msg.contains("not found") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_REQUEST
        }
    })?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct DisconnectNetworkRequest {
    #[serde(rename = "Container")]
    pub container: String,
    #[serde(rename = "Force", default)]
    pub force: bool,
}

pub async fn disconnect_network(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    Json(payload): Json<DisconnectNetworkRequest>,
) -> Result<StatusCode, StatusCode> {
    let store = NetworkStore::with_home(state.home.clone());
    store
        .disconnect_container(&id, &payload.container)
        .map_err(|e| {
            let msg = e.to_string().to_lowercase();
            if msg.contains("not found") || msg.contains("not connected") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            }
        })?;
    Ok(StatusCode::OK)
}

pub async fn list_volumes(State(state): State<DaemonState>) -> Json<serde_json::Value> {
    let store = VolumeStore::with_home(state.home.clone());
    #[derive(Serialize)]
    struct VolResp {
        #[serde(rename = "Volumes")]
        volumes: Vec<crate::volume::VolumeRecord>,
    }
    Json(
        serde_json::to_value(VolResp {
            volumes: store.list(),
        })
        .unwrap_or_default(),
    )
}

#[derive(Deserialize)]
pub struct CreateVolumeRequest {
    #[serde(rename = "Name")]
    pub name: Option<String>,
}

pub async fn create_volume(
    State(state): State<DaemonState>,
    Json(payload): Json<CreateVolumeRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = VolumeStore::with_home(state.home.clone());
    match store.create(payload.name.as_deref(), None) {
        Ok(vol) => Ok(Json(serde_json::to_value(vol).unwrap())),
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

pub async fn inspect_volume(
    State(state): State<DaemonState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = VolumeStore::with_home(state.home.clone());
    let vol = store.find(&name).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(
        serde_json::to_value(vol).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    ))
}

pub async fn remove_volume(
    State(state): State<DaemonState>,
    Path(name): Path<String>,
) -> StatusCode {
    let store = VolumeStore::with_home(state.home.clone());
    if store.find(&name).is_none() {
        return StatusCode::NOT_FOUND;
    }
    match store.remove(&name) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            let err_msg = e.to_string().to_lowercase();
            if err_msg.contains("active")
                || err_msg.contains("in use")
                || err_msg.contains("conflict")
            {
                StatusCode::CONFLICT
            } else if err_msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            }
        }
    }
}

fn parse_lenient_json(bytes: &[u8]) -> serde_json::Value {
    if bytes.is_empty() {
        return serde_json::json!({});
    }
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) {
        return v;
    }
    let s = String::from_utf8_lossy(bytes);
    let trimmed = s.trim();
    if let Some(stripped) = trimmed.strip_suffix('}') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(stripped) {
            return v;
        }
    }
    serde_json::json!({})
}

fn format_volume_json(vol: &crate::volume::VolumeRecord, is_libpod: bool) -> serde_json::Value {
    let opts = if !is_libpod && vol.options.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::to_value(&vol.options).unwrap_or(serde_json::json!({}))
    };
    serde_json::json!({
        "Name": vol.name,
        "Driver": vol.driver,
        "Mountpoint": vol.mountpoint,
        "CreatedAt": vol.created_at.to_rfc3339(),
        "Labels": vol.labels,
        "Scope": "local",
        "Options": opts,
        "MountCount": 0,
        "NeedsCopyUp": true,
        "NeedsChown": true
    })
}

pub async fn handle_volume_network_routes(ctx: &ApiContext) -> Option<Response> {
    let path = ctx.path.as_str();
    if path == "/volumes/create" {
        if ctx.method != Method::POST {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_create_volume(ctx));
    }
    if path == "/volumes" || path == "/volumes/json" {
        if ctx.method != Method::GET {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_list_volumes(ctx));
    }
    if path == "/volumes/prune" {
        if ctx.method != Method::POST {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_prune_volumes(ctx));
    }
    if let Some(rest) = path.strip_prefix("/volumes/") {
        if let Some(name) = rest.strip_suffix("/rename") {
            if ctx.method != Method::POST {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_rename_volume(ctx, name));
        }
        if let Some(name) = rest.strip_suffix("/exists") {
            let store = VolumeStore::with_home(ctx.state.home.clone());
            return if store.find(name).is_some() {
                Some(StatusCode::NO_CONTENT.into_response())
            } else {
                Some(error_json(
                    StatusCode::NOT_FOUND,
                    "no such volume",
                    "no such volume",
                ))
            };
        }
        let name = rest.strip_suffix("/json").unwrap_or(rest);
        return match ctx.method {
            Method::GET => Some(handle_inspect_volume(ctx, name)),
            Method::DELETE => Some(handle_delete_volume(ctx, name)),
            _ => Some(StatusCode::METHOD_NOT_ALLOWED.into_response()),
        };
    }

    if path == "/networks/create" {
        if ctx.method != Method::POST {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_create_network(ctx));
    }
    if path == "/networks" || path == "/networks/json" {
        if ctx.method != Method::GET {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_list_networks(ctx));
    }
    if path == "/networks/prune" {
        if ctx.method != Method::POST {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_prune_networks(ctx));
    }
    if let Some(rest) = path.strip_prefix("/networks/") {
        if let Some(id) = rest.strip_suffix("/connect") {
            if ctx.method != Method::POST {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_connect_network(ctx, id));
        }
        if let Some(id) = rest.strip_suffix("/disconnect") {
            if ctx.method != Method::POST {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_disconnect_network(ctx, id));
        }
        if let Some(id) = rest.strip_suffix("/exists") {
            let store = NetworkStore::with_home(ctx.state.home.clone());
            return if store.find(id).is_some() {
                Some(StatusCode::NO_CONTENT.into_response())
            } else {
                Some(error_json(
                    StatusCode::NOT_FOUND,
                    "network not found",
                    "network not found",
                ))
            };
        }
        let id = rest.strip_suffix("/json").unwrap_or(rest);
        return match ctx.method {
            Method::GET => Some(handle_inspect_network(ctx, id)),
            Method::DELETE => Some(handle_delete_network(ctx, id)),
            _ => Some(StatusCode::METHOD_NOT_ALLOWED.into_response()),
        };
    }
    None
}

fn handle_create_volume(ctx: &ApiContext) -> Response {
    let val = parse_lenient_json(&ctx.body);
    let raw_name = val
        .get("Name")
        .or_else(|| val.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let store = VolumeStore::with_home(ctx.state.home.clone());
    if let Some(ref n) = raw_name {
        if ctx.is_libpod && store.find(n).is_some() {
            return error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "volume already exists",
                &format!(
                    "volume with name {} already exists: volume already exists",
                    n
                ),
            );
        }
    }
    let generated_name = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(crate::storage::container_store::rand_id()))
    };
    let final_name = raw_name.as_deref().unwrap_or(&generated_name);

    let mut labels = HashMap::new();
    for key in ["label", "Label", "labels", "Labels"] {
        if let Some(lval) = val.get(key) {
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
    }

    let mut options = HashMap::new();
    for key in ["options", "Options"] {
        if let Some(oval) = val.get(key) {
            if let Some(obj) = oval.as_object() {
                for (k, v) in obj {
                    options.insert(
                        k.clone(),
                        v.as_str()
                            .map(String::from)
                            .unwrap_or_else(|| v.to_string()),
                    );
                }
            } else if let Some(s) = oval.as_str() {
                let s_clean = s
                    .trim()
                    .strip_suffix("}}")
                    .map(|p| format!("{}}}", p))
                    .unwrap_or_else(|| s.to_string());
                if let Ok(parsed) = serde_json::from_str::<HashMap<String, String>>(&s_clean) {
                    options.extend(parsed);
                }
            }
        }
    }

    match store.create_with_options(
        Some(final_name),
        "local",
        Some(labels),
        "local",
        Some(options),
    ) {
        Ok(vol) => json_response(
            StatusCode::CREATED,
            &format_volume_json(&vol, ctx.is_libpod),
        ),
        Err(e) => error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
            &e.to_string(),
        ),
    }
}

fn handle_list_volumes(ctx: &ApiContext) -> Response {
    let filters = if let Some(raw) = ctx.query.get("filters") {
        match parse_filters_param(raw, StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(f) => f,
            Err(resp) => return resp,
        }
    } else {
        HashMap::new()
    };

    let store = VolumeStore::with_home(ctx.state.home.clone());
    let mut vols = store.list();

    if let Some(names) = filters.get("name") {
        vols.retain(|v| names.iter().any(|n| v.name == *n || v.name.contains(n)));
    }
    if let Some(labels) = filters.get("label") {
        vols.retain(|v| super::system::volume_matches_labels(v, labels));
    }
    if let Some(untils) = filters.get("until") {
        if let Some(u_str) = untils.first() {
            if let Ok(ts) = u_str.parse::<i64>() {
                vols.retain(|v| v.created_at.timestamp() <= ts);
            }
        }
    }

    let formatted: Vec<serde_json::Value> = vols
        .iter()
        .map(|v| format_volume_json(v, ctx.is_libpod))
        .collect();

    if ctx.is_libpod || ctx.path == "/volumes/json" {
        json_response(StatusCode::OK, &serde_json::Value::Array(formatted))
    } else {
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "Volumes": formatted,
                "Warnings": []
            }),
        )
    }
}

fn handle_inspect_volume(ctx: &ApiContext, name: &str) -> Response {
    let store = VolumeStore::with_home(ctx.state.home.clone());
    match store.find(name) {
        Some(vol) => json_response(StatusCode::OK, &format_volume_json(&vol, ctx.is_libpod)),
        None => error_json(StatusCode::NOT_FOUND, "no such volume", "no such volume"),
    }
}

fn handle_rename_volume(ctx: &ApiContext, old_name: &str) -> Response {
    let new_name = match ctx.query.get("newName") {
        Some(n) if !n.is_empty() => n.as_str(),
        _ => {
            return error_json(
                StatusCode::BAD_REQUEST,
                "missing newName",
                "missing newName",
            );
        }
    };
    let store = VolumeStore::with_home(ctx.state.home.clone());
    let vol = match store.find(old_name) {
        Some(v) => v,
        None => return error_json(StatusCode::NOT_FOUND, "no such volume", "no such volume"),
    };
    let _ = store.remove_with_force(old_name, true);
    match store.create_with_options(
        Some(new_name),
        &vol.driver,
        Some(vol.labels),
        "local",
        Some(vol.options),
    ) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
            &e.to_string(),
        ),
    }
}

fn handle_delete_volume(ctx: &ApiContext, name: &str) -> Response {
    let store = VolumeStore::with_home(ctx.state.home.clone());
    if store.find(name).is_none() {
        return error_json(StatusCode::NOT_FOUND, "no such volume", "no such volume");
    }
    let force = ctx
        .query
        .get("force")
        .is_some_and(|v| v == "true" || v == "1");
    let res = if force {
        store.remove_with_force(name, true)
    } else {
        store.remove(name)
    };
    match res {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => error_json(StatusCode::CONFLICT, "volume is in use", &e.to_string()),
    }
}

fn handle_prune_volumes(ctx: &ApiContext) -> Response {
    let filters = if let Some(raw) = ctx.query.get("filters") {
        match parse_filters_param(raw, StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(f) => f,
            Err(resp) => return resp,
        }
    } else {
        HashMap::new()
    };

    for invalid_key in ["name", "driver", "scope"] {
        if filters.contains_key(invalid_key) {
            let msg = format!("{:?} is an invalid volume filter", invalid_key);
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, &msg, &msg);
        }
    }

    let store = VolumeStore::with_home(ctx.state.home.clone());
    let has_label = filters.contains_key("label");
    let has_until = filters.contains_key("until");
    let has_all = filters
        .get("all")
        .is_some_and(|v| v.iter().any(|s| s == "true" || s == "1"));
    let compat_anonymous_only = !ctx.is_libpod && !has_label && !has_until && !has_all;

    let mut deleted_names = Vec::new();
    let mut libpod_reports = Vec::new();
    let mut space_reclaimed = 0u64;

    for v in store.list() {
        let is_in_use = store.remove(&v.name).is_err();
        if is_in_use {
            continue;
        }
        // Re-add temporarily until filter checks pass
        let _ = store.create_with_options(
            Some(&v.name),
            &v.driver,
            Some(v.labels.clone()),
            "local",
            Some(v.options.clone()),
        );

        if compat_anonymous_only {
            let is_anon = v.name.len() == 64 && v.name.chars().all(|c| c.is_ascii_hexdigit());
            if !is_anon {
                continue;
            }
        }
        if let Some(labels) = filters.get("label") {
            if !super::system::volume_matches_labels(&v, labels) {
                continue;
            }
        }
        if let Some(untils) = filters.get("until") {
            if let Some(u_str) = untils.first() {
                if let Ok(ts) = u_str.parse::<i64>() {
                    if v.created_at.timestamp() > ts {
                        continue;
                    }
                }
            }
        }
        let sz = crate::system::dir_size(std::path::Path::new(&v.mountpoint)).max(32);
        let _ = store.remove_with_force(&v.name, true);
        space_reclaimed += sz;
        deleted_names.push(v.name.clone());
        libpod_reports.push(serde_json::json!({
            "Id": v.name,
            "Size": sz
        }));
    }

    if ctx.is_libpod {
        json_response(StatusCode::OK, &serde_json::Value::Array(libpod_reports))
    } else {
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "VolumesDeleted": deleted_names,
                "SpaceReclaimed": space_reclaimed
            }),
        )
    }
}

fn full_net_id(id: &str) -> String {
    if id.len() >= 64 {
        id[..64].to_string()
    } else {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(id.as_bytes()))
    }
}

fn format_libpod_network(net: &crate::network::NetworkRecord) -> serde_json::Value {
    let nid = full_net_id(&net.id);
    serde_json::json!({
        "name": net.name,
        "id": nid,
        "driver": net.driver,
        "network_interface": format!("podman{}", &nid[..4]),
        "created": net.created_at.to_rfc3339(),
        "subnets": [
            {
                "subnet": net.subnet,
                "gateway": net.gateway
            }
        ],
        "ipv6_enabled": net.enable_ipv6,
        "internal": net.internal,
        "dns_enabled": true,
        "ipam_options": {
            "driver": "host-local"
        },
        "labels": net.labels
    })
}

fn format_compat_network(
    net: &crate::network::NetworkRecord,
    display_name: &str,
    home: &std::path::Path,
) -> serde_json::Value {
    let nid = full_net_id(&net.id);
    let prefix = net.subnet.split_once('/').map(|(_, p)| p).unwrap_or("24");
    let c_store = ContainerStore::with_home(home.to_path_buf());
    let mut containers_map = serde_json::Map::new();
    for (cid, ep) in &net.containers {
        let mut mac = ep.mac_address.clone();
        if let Some(c) = c_store.find(cid) {
            let bp = PathBuf::from(&c.bundle_path);
            if let Ok(cfg_str) = fs::read_to_string(bp.join("config.json")) {
                if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&cfg_str) {
                    if let Some(m) = spec
                        .annotations
                        .as_ref()
                        .and_then(|a| a.get("boxr.mac_address"))
                    {
                        mac = m.clone();
                    }
                }
            }
        }
        let ipv4 = if ep.ipv4_address.contains('/') {
            ep.ipv4_address.clone()
        } else {
            format!("{}/{}", ep.ipv4_address, prefix)
        };
        containers_map.insert(
            cid.clone(),
            serde_json::json!({
                "Name": ep.container_name,
                "EndpointID": full_net_id(cid),
                "MacAddress": mac,
                "IPv4Address": ipv4,
                "IPv6Address": ""
            }),
        );
    }
    let mut ipam_cfg = serde_json::json!({
        "Subnet": net.subnet,
        "Gateway": net.gateway
    });
    if let Some(ipr) = net.labels.get("boxr.iprange") {
        ipam_cfg["IPRange"] = serde_json::Value::String(ipr.clone());
    }
    let mut user_labels = net.labels.clone();
    user_labels.remove("boxr.iprange");
    serde_json::json!({
        "Name": display_name,
        "Id": nid,
        "Created": net.created_at.to_rfc3339(),
        "Scope": "local",
        "Driver": net.driver,
        "EnableIPv6": net.enable_ipv6,
        "IPAM": {
            "Driver": "default",
            "Options": {},
            "Config": [ipam_cfg]
        },
        "Internal": net.internal,
        "Attachable": net.attachable,
        "Ingress": false,
        "ConfigFrom": { "Network": "" },
        "ConfigOnly": false,
        "Containers": containers_map,
        "Options": {},
        "Labels": user_labels
    })
}

fn validate_cidr(cidr: &str) -> Result<String, String> {
    let Some((ip_part, mask_part)) = cidr.split_once('/') else {
        return Err(format!("invalid CIDR address: {}", cidr));
    };
    let ip: std::net::IpAddr = ip_part
        .parse()
        .map_err(|_| format!("invalid CIDR address: {}", cidr))?;
    let mask: u8 = mask_part
        .parse()
        .map_err(|_| format!("invalid CIDR address: {}", cidr))?;
    let max_mask = if ip.is_ipv4() { 32 } else { 128 };
    if mask > max_mask {
        return Err(format!("invalid CIDR address: {}", cidr));
    }
    let gw = if let std::net::IpAddr::V4(v4) = ip {
        let oct = v4.octets();
        format!("{}.{}.{}.1", oct[0], oct[1], oct[2])
    } else {
        String::new()
    };
    Ok(gw)
}

fn handle_create_network(ctx: &ApiContext) -> Response {
    if ctx.is_libpod && ctx.has_explicit_version && ctx.api_version.0 < 4 {
        return error_json(
            StatusCode::BAD_REQUEST,
            "given version is not supported",
            "given version is not supported",
        );
    }
    let val = parse_lenient_json(&ctx.body);
    let name = val
        .get("Name")
        .or_else(|| val.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            format!(
                "podman-{}",
                &hex::encode(crate::storage::container_store::rand_id())[..8]
            )
        });
    let driver = val
        .get("Driver")
        .or_else(|| val.get("driver"))
        .and_then(|v| v.as_str())
        .unwrap_or("bridge");

    let mut subnet: Option<String> = None;
    let mut gateway: Option<String> = None;
    let mut iprange: Option<String> = None;

    if let Some(subnets_val) = val.get("subnets").or_else(|| val.get("Subnets")) {
        let arr_opt = if let Some(a) = subnets_val.as_array() {
            Some(a.clone())
        } else if let Some(s) = subnets_val.as_str() {
            serde_json::from_str::<Vec<serde_json::Value>>(s).ok()
        } else {
            None
        };
        if let Some(arr) = arr_opt {
            if let Some(first) = arr.first() {
                if let Some(sub_str) = first.get("subnet").and_then(|v| v.as_str()) {
                    match validate_cidr(sub_str) {
                        Ok(default_gw) => {
                            subnet = Some(sub_str.to_string());
                            gateway = first
                                .get("gateway")
                                .and_then(|v| v.as_str())
                                .map(String::from)
                                .or(Some(default_gw));
                        }
                        Err(err) => {
                            return error_json(StatusCode::BAD_REQUEST, &err, &err);
                        }
                    }
                }
            }
        }
    }

    if let Some(ipam_val) = val.get("IPAM").or_else(|| val.get("ipam")) {
        let ipam_obj = if ipam_val.is_object() {
            Some(ipam_val.clone())
        } else if let Some(s) = ipam_val.as_str() {
            serde_json::from_str::<serde_json::Value>(s).ok()
        } else {
            None
        };
        if let Some(ipam) = ipam_obj {
            if let Some(cfgs) = ipam.get("Config").and_then(|v| v.as_array()) {
                if let Some(first) = cfgs.first() {
                    if let Some(s) = first.get("Subnet").and_then(|v| v.as_str()) {
                        subnet = Some(s.to_string());
                    }
                    if let Some(g) = first.get("Gateway").and_then(|v| v.as_str()) {
                        gateway = Some(g.to_string());
                    }
                    if let Some(r) = first.get("IPRange").and_then(|v| v.as_str()) {
                        iprange = Some(r.to_string());
                    }
                }
            }
        }
    }

    let mut labels = HashMap::new();
    for key in ["labels", "Labels"] {
        if let Some(lval) = val.get(key) {
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
    }
    if let Some(r) = iprange {
        labels.insert("boxr.iprange".to_string(), r);
    }

    let store = NetworkStore::with_home(ctx.state.home.clone());
    if store.find(&name).is_some() {
        return error_json(
            StatusCode::CONFLICT,
            "network already exists",
            &format!("network with name {} already exists", name),
        );
    }

    match store.create_with_options(
        &name,
        driver,
        subnet.as_deref(),
        gateway.as_deref(),
        false,
        false,
        labels,
    ) {
        Ok(net) => {
            if ctx.is_libpod {
                json_response(StatusCode::OK, &format_libpod_network(&net))
            } else {
                json_response(
                    StatusCode::CREATED,
                    &serde_json::json!({
                        "Id": full_net_id(&net.id),
                        "Warning": ""
                    }),
                )
            }
        }
        Err(e) => error_json(StatusCode::BAD_REQUEST, &e.to_string(), &e.to_string()),
    }
}

fn network_matches_labels(net: &crate::network::NetworkRecord, labels: &[String]) -> bool {
    for lf in labels {
        if let Some((k, val)) = lf.split_once('=') {
            if net.labels.get(k).map(|s| s.as_str()) != Some(val) {
                return false;
            }
        } else if !net.labels.contains_key(lf) {
            return false;
        }
    }
    true
}

fn handle_list_networks(ctx: &ApiContext) -> Response {
    let filters = if let Some(raw) = ctx.query.get("filters") {
        match parse_filters_param(raw, StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(f) => f,
            Err(resp) => return resp,
        }
    } else {
        HashMap::new()
    };

    if let Some(dang) = filters.get("dangling") {
        if dang.len() > 1 {
            let msg = "got more than one value for filter key \"dangling\"";
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, msg, msg);
        }
    }

    let store = NetworkStore::with_home(ctx.state.home.clone());
    let mut nets: Vec<crate::network::NetworkRecord> = store
        .list()
        .into_iter()
        .filter(|n| n.name != NetworkStore::DEFAULT_NETWORK)
        .collect();

    if let Some(names) = filters.get("name") {
        nets.retain(|n| {
            let disp = if !ctx.is_libpod && n.name == "podman" {
                "bridge"
            } else {
                &n.name
            };
            names
                .iter()
                .any(|pat| n.name == *pat || disp == pat || n.name.contains(pat))
        });
    }
    if let Some(ids) = filters.get("id") {
        nets.retain(|n| {
            let fid = full_net_id(&n.id);
            ids.iter()
                .any(|i| fid == *i || fid.starts_with(i) || n.id == *i)
        });
    }
    if let Some(labels) = filters.get("label") {
        nets.retain(|n| network_matches_labels(n, labels));
    }
    if let Some(untils) = filters.get("until") {
        if let Some(u_str) = untils.first() {
            if let Ok(ts) = u_str.parse::<i64>() {
                nets.retain(|n| n.created_at.timestamp() <= ts);
            }
        }
    }

    let out: Vec<serde_json::Value> = nets
        .iter()
        .map(|n| {
            if ctx.is_libpod || ctx.path == "/networks/json" {
                format_libpod_network(n)
            } else {
                let disp = if n.name == "podman" {
                    "bridge"
                } else {
                    &n.name
                };
                format_compat_network(n, disp, &ctx.state.home)
            }
        })
        .collect();

    json_response(StatusCode::OK, &serde_json::Value::Array(out))
}

fn find_network_by_name_or_id(
    store: &NetworkStore,
    query: &str,
) -> Option<(crate::network::NetworkRecord, String)> {
    let lookup = if query == "bridge" { "podman" } else { query };
    if let Some(n) = store.find(lookup) {
        return Some((n, query.to_string()));
    }
    for n in store.list() {
        let fid = full_net_id(&n.id);
        if fid == query || fid.starts_with(query) {
            return Some((n.clone(), n.name.clone()));
        }
    }
    None
}

fn handle_inspect_network(ctx: &ApiContext, id: &str) -> Response {
    let store = NetworkStore::with_home(ctx.state.home.clone());
    match find_network_by_name_or_id(&store, id) {
        Some((net, disp)) => {
            if ctx.is_libpod || ctx.path.ends_with("/json") {
                json_response(StatusCode::OK, &format_libpod_network(&net))
            } else {
                let final_disp = if id == "bridge" { "bridge" } else { &net.name };
                let _ = disp;
                json_response(
                    StatusCode::OK,
                    &format_compat_network(&net, final_disp, &ctx.state.home),
                )
            }
        }
        None => error_json(
            StatusCode::NOT_FOUND,
            "network not found",
            "network not found",
        ),
    }
}

fn handle_delete_network(ctx: &ApiContext, id: &str) -> Response {
    let store = NetworkStore::with_home(ctx.state.home.clone());
    let Some((net, _)) = find_network_by_name_or_id(&store, id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "network not found",
            "network not found",
        );
    };
    match store.remove(&net.name) {
        Ok(_) => {
            if ctx.is_libpod {
                json_response(
                    StatusCode::OK,
                    &serde_json::json!([
                        {
                            "Name": net.name,
                            "Err": serde_json::Value::Null
                        }
                    ]),
                )
            } else {
                StatusCode::NO_CONTENT.into_response()
            }
        }
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            let status =
                if msg.contains("active") || msg.contains("in use") || msg.contains("default") {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::NOT_FOUND
                };
            error_json(status, &e.to_string(), &e.to_string())
        }
    }
}

fn handle_connect_network(ctx: &ApiContext, id: &str) -> Response {
    let val = parse_lenient_json(&ctx.body);
    let container = val
        .get("Container")
        .or_else(|| val.get("container"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let store = NetworkStore::with_home(ctx.state.home.clone());
    let Some((net, _)) = find_network_by_name_or_id(&store, id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "network not found",
            "network not found",
        );
    };
    let c_store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(c) = c_store.find(container) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such container",
            "no such container",
        );
    };
    let already_connected = net.containers.contains_key(&c.id);
    if already_connected && matches!(c.status, ContainerStatus::Running) {
        return error_json(
            StatusCode::FORBIDDEN,
            "network is already connected",
            "network is already connected",
        );
    }
    if !already_connected {
        if let Err(e) = store.connect_container(&net.name, &c.id, &c.name) {
            return error_json(StatusCode::BAD_REQUEST, &e.to_string(), &e.to_string());
        }
    }
    (StatusCode::OK, "OK\n").into_response()
}

fn handle_disconnect_network(ctx: &ApiContext, id: &str) -> Response {
    let val = parse_lenient_json(&ctx.body);
    let container = val
        .get("Container")
        .or_else(|| val.get("container"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let store = NetworkStore::with_home(ctx.state.home.clone());
    let Some((net, _)) = find_network_by_name_or_id(&store, id) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "network not found",
            "network not found",
        );
    };
    match store.disconnect_container(&net.name, container) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => error_json(StatusCode::NOT_FOUND, &e.to_string(), &e.to_string()),
    }
}

fn handle_prune_networks(ctx: &ApiContext) -> Response {
    let filters = if let Some(raw) = ctx.query.get("filters") {
        match parse_filters_param(raw, StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(f) => f,
            Err(resp) => return resp,
        }
    } else {
        HashMap::new()
    };

    let store = NetworkStore::with_home(ctx.state.home.clone());
    let mut deleted_names = Vec::new();
    let mut libpod_reports = Vec::new();

    for net in store.list() {
        if net.name == NetworkStore::DEFAULT_NETWORK
            || net.name == "podman"
            || !net.containers.is_empty()
        {
            continue;
        }
        if let Some(labels) = filters.get("label") {
            if !network_matches_labels(&net, labels) {
                continue;
            }
        }
        if let Some(untils) = filters.get("until") {
            if let Some(u_str) = untils.first() {
                if let Ok(ts) = u_str.parse::<i64>() {
                    if net.created_at.timestamp() > ts {
                        continue;
                    }
                }
            }
        }
        let _ = store.remove(&net.name);
        deleted_names.push(net.name.clone());
        libpod_reports.push(serde_json::json!({
            "Name": net.name,
            "Error": serde_json::Value::Null
        }));
    }

    if ctx.is_libpod {
        json_response(StatusCode::OK, &serde_json::Value::Array(libpod_reports))
    } else {
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "NetworksDeleted": deleted_names
            }),
        )
    }
}
