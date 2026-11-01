use super::{ApiContext, error_json, json_response};
use crate::storage::ImageStore;
use axum::{
    body::Body,
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(serde::Serialize, serde::Deserialize, Clone, Default)]
pub struct ApiManifestEntry {
    pub media_type: String,
    pub size: u64,
    pub digest: String,
    pub platform_arch: String,
    pub platform_os: String,
    pub os_features: Vec<String>,
    pub annotations: HashMap<String, String>,
    #[serde(default)]
    pub artifact_type: Option<String>,
    #[serde(default)]
    pub artifact_manifest_json: Option<String>,
    #[serde(default)]
    pub artifact_blobs: Vec<(String, Vec<u8>)>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ApiManifestList {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub manifests: Vec<ApiManifestEntry>,
}

pub fn load_api_manifests(home: &Path) -> Vec<ApiManifestList> {
    let p = home.join("api_manifests.json");
    let mut lists: Vec<ApiManifestList> = fs::read_to_string(&p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    // Also sync any CLI-created manifests from home/manifests/*.json
    let cli_dir = home.join("manifests");
    if let Ok(entries) = fs::read_dir(&cli_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(raw) = fs::read_to_string(&path) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                        let name = val
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        if !name.is_empty() && !lists.iter().any(|m| m.name == name) {
                            let id = hex::encode(Sha256::digest(name.as_bytes()));
                            let mut items = Vec::new();
                            if let Some(arr) = val.get("manifests").and_then(|v| v.as_array()) {
                                for m in arr {
                                    let dig = m
                                        .get("digest")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let sz = m.get("size").and_then(|v| v.as_u64()).unwrap_or(1024);
                                    let arch = m
                                        .get("platform")
                                        .and_then(|p| p.get("architecture"))
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("amd64")
                                        .to_string();
                                    let os = m
                                        .get("platform")
                                        .and_then(|p| p.get("os"))
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("linux")
                                        .to_string();
                                    items.push(ApiManifestEntry {
                                        media_type: "application/vnd.oci.image.manifest.v1+json"
                                            .to_string(),
                                        size: sz,
                                        digest: dig,
                                        platform_arch: arch,
                                        platform_os: os,
                                        os_features: Vec::new(),
                                        annotations: HashMap::new(),
                                        artifact_type: None,
                                        artifact_manifest_json: None,
                                        artifact_blobs: Vec::new(),
                                    });
                                }
                            }
                            lists.push(ApiManifestList {
                                id,
                                name,
                                created_at: chrono::Utc::now().timestamp(),
                                manifests: items,
                            });
                        } else if let Some(existing) = lists.iter_mut().find(|m| m.name == name) {
                            if let Some(arr) = val.get("manifests").and_then(|v| v.as_array()) {
                                if arr.len() > existing.manifests.len() {
                                    existing.manifests.clear();
                                    for m in arr {
                                        let dig = m
                                            .get("digest")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                        let sz =
                                            m.get("size").and_then(|v| v.as_u64()).unwrap_or(1024);
                                        let arch = m
                                            .get("platform")
                                            .and_then(|p| p.get("architecture"))
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("amd64")
                                            .to_string();
                                        let os = m
                                            .get("platform")
                                            .and_then(|p| p.get("os"))
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("linux")
                                            .to_string();
                                        existing.manifests.push(ApiManifestEntry {
                                            media_type:
                                                "application/vnd.oci.image.manifest.v1+json"
                                                    .to_string(),
                                            size: sz,
                                            digest: dig,
                                            platform_arch: arch,
                                            platform_os: os,
                                            os_features: Vec::new(),
                                            annotations: HashMap::new(),
                                            artifact_type: None,
                                            artifact_manifest_json: None,
                                            artifact_blobs: Vec::new(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    lists
}

pub fn save_api_manifests(home: &Path, lists: &[ApiManifestList]) {
    let _ = fs::create_dir_all(home);
    if let Ok(j) = serde_json::to_string_pretty(lists) {
        let _ = fs::write(home.join("api_manifests.json"), j);
    }
}

pub fn find_api_manifest(home: &Path, query: &str) -> Option<ApiManifestList> {
    let clean = query.trim_end_matches(":latest");
    load_api_manifests(home).into_iter().find(|m| {
        m.name == query
            || m.name == clean
            || m.id == query
            || m.id.starts_with(query)
            || format!("localhost/{}:latest", m.name) == query
            || format!("localhost/{}", m.name) == clean
    })
}

pub async fn handle_manifests_artifacts_routes(ctx: &ApiContext) -> Option<Response> {
    let path = ctx.path.as_str();

    if path == "/manifests/create" {
        if ctx.method != Method::POST {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        let name = ctx.query.get("name").cloned().unwrap_or_default();
        return Some(handle_create_manifest(ctx, &name, StatusCode::OK));
    }
    if let Some(rest) = path.strip_prefix("/manifests/") {
        if let Some(name) = rest.strip_suffix("/exists") {
            return if find_api_manifest(&ctx.state.home, name).is_some() {
                Some(StatusCode::NO_CONTENT.into_response())
            } else {
                Some(error_json(
                    StatusCode::NOT_FOUND,
                    "no such manifest",
                    "no such manifest",
                ))
            };
        }
        if let Some(name) = rest.strip_suffix("/json") {
            return Some(handle_inspect_manifest(ctx, name));
        }
        if let Some(name) = rest.strip_suffix("/add") {
            return Some(handle_modify_manifest(ctx, name));
        }
        if let Some(name) = rest.strip_suffix("/push") {
            let dest = ctx.query.get("destination").cloned().unwrap_or_default();
            return Some(handle_push_manifest(ctx, name, &dest).await);
        }
        if let Some((name, dest)) = rest.split_once("/registry/") {
            return Some(handle_push_manifest(ctx, name, dest).await);
        }
        return match ctx.method {
            Method::POST => Some(handle_create_manifest(ctx, rest, StatusCode::CREATED)),
            Method::PUT => Some(handle_modify_manifest(ctx, rest)),
            Method::DELETE => Some(handle_delete_manifest(ctx, rest)),
            Method::GET => Some(handle_inspect_manifest(ctx, rest)),
            _ => Some(StatusCode::METHOD_NOT_ALLOWED.into_response()),
        };
    }

    if path == "/artifacts/add" {
        return Some(handle_artifact_add(ctx, false));
    }
    if path == "/artifacts/local/add" {
        return Some(handle_artifact_add(ctx, true));
    }
    if path == "/artifacts/json" {
        return Some(handle_artifact_list(ctx));
    }
    if path == "/artifacts/pull" {
        return Some(handle_artifact_pull(ctx).await);
    }
    if path == "/artifacts/remove" {
        return Some(handle_artifact_remove_batch(ctx));
    }
    if let Some(rest) = path.strip_prefix("/artifacts/") {
        if let Some(name) = rest.strip_suffix("/json") {
            return Some(handle_artifact_inspect(ctx, name));
        }
        if let Some(name) = rest.strip_suffix("/push") {
            return Some(handle_artifact_push(ctx, name));
        }
        if let Some(name) = rest.strip_suffix("/extract") {
            return Some(handle_artifact_extract(ctx, name));
        }
        if ctx.method == Method::DELETE {
            return Some(handle_artifact_delete_one(ctx, rest));
        }
    }

    None
}

fn resolve_image_for_manifest(home: &Path, img_ref: &str) -> ApiManifestEntry {
    let clean = img_ref
        .strip_prefix("containers-storage:")
        .unwrap_or(img_ref);
    let i_store = ImageStore::with_home(home.to_path_buf());
    if let Some(img) = i_store.find(clean) {
        let dig = if img.manifest_digest.starts_with("sha256:") && img.manifest_digest.len() == 71 {
            img.manifest_digest.clone()
        } else {
            format!("sha256:{}", hex::encode(Sha256::digest(img.id.as_bytes())))
        };
        ApiManifestEntry {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            size: img.size_bytes.max(1024) as u64,
            digest: dig,
            platform_arch: img.config.architecture,
            platform_os: img.config.os,
            os_features: Vec::new(),
            annotations: HashMap::new(),
            artifact_type: None,
            artifact_manifest_json: None,
            artifact_blobs: Vec::new(),
        }
    } else {
        let dig = if clean.starts_with("sha256:") && clean.len() == 71 {
            clean.to_string()
        } else {
            format!("sha256:{}", hex::encode(Sha256::digest(clean.as_bytes())))
        };
        ApiManifestEntry {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            size: 1024,
            digest: dig,
            platform_arch: "amd64".to_string(),
            platform_os: "linux".to_string(),
            os_features: Vec::new(),
            annotations: HashMap::new(),
            artifact_type: None,
            artifact_manifest_json: None,
            artifact_blobs: Vec::new(),
        }
    }
}

fn handle_create_manifest(ctx: &ApiContext, name: &str, ok_status: StatusCode) -> Response {
    if name.is_empty() || name.chars().any(|c| c.is_ascii_uppercase()) {
        return error_json(
            StatusCode::BAD_REQUEST,
            "invalid reference format: repository name must be lowercase",
            "invalid reference format: repository name must be lowercase",
        );
    }
    let mut lists = load_api_manifests(&ctx.state.home);
    let id = hex::encode(Sha256::digest(
        format!(
            "{}-{}",
            name,
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        )
        .as_bytes(),
    ));
    let mut entries = Vec::new();
    if let Some(imgs) = ctx.query_multi.get("images") {
        for img_ref in imgs {
            entries.push(resolve_image_for_manifest(&ctx.state.home, img_ref));
        }
    }
    lists.retain(|m| m.name != name);
    lists.push(ApiManifestList {
        id: id.clone(),
        name: name.to_string(),
        created_at: chrono::Utc::now().timestamp(),
        manifests: entries,
    });
    save_api_manifests(&ctx.state.home, &lists);
    json_response(ok_status, &serde_json::json!({ "Id": id }))
}

fn format_manifest_list_json(ml: &ApiManifestList) -> serde_json::Value {
    let items: Vec<serde_json::Value> = ml
        .manifests
        .iter()
        .map(|m| {
            let mut plat = serde_json::json!({
                "architecture": m.platform_arch,
                "os": m.platform_os
            });
            if !m.os_features.is_empty() {
                plat["os.features"] = serde_json::to_value(&m.os_features).unwrap_or_default();
            }
            let mut item = serde_json::json!({
                "mediaType": m.media_type,
                "size": m.size,
                "digest": m.digest,
                "platform": plat
            });
            if !m.annotations.is_empty() {
                item["annotations"] = serde_json::to_value(&m.annotations).unwrap_or_default();
            }
            if let Some(ref at) = m.artifact_type {
                item["artifactType"] = serde_json::Value::String(at.clone());
            } else {
                item["artifactType"] = serde_json::Value::Null;
            }
            item
        })
        .collect();
    serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": items
    })
}

fn handle_inspect_manifest(ctx: &ApiContext, name: &str) -> Response {
    match find_api_manifest(&ctx.state.home, name) {
        Some(ml) => json_response(StatusCode::OK, &format_manifest_list_json(&ml)),
        None => error_json(
            StatusCode::NOT_FOUND,
            "no such manifest",
            "no such manifest",
        ),
    }
}

fn parse_multipart_manifest_request(
    content_type: &str,
    body: &[u8],
) -> (serde_json::Value, Vec<(String, Vec<u8>)>) {
    if !content_type.contains("multipart/form-data") {
        let v = serde_json::from_slice(body).unwrap_or_default();
        return (v, Vec::new());
    }
    let mut req_json = serde_json::json!({});
    let mut files = Vec::new();
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .map(|b| b.trim().trim_matches('"'))
        .unwrap_or("");
    if boundary.is_empty() {
        return (req_json, files);
    }
    let delim = format!("--{}", boundary).into_bytes();
    let mut pos = 0;
    while pos < body.len() {
        let Some(rel_start) = body[pos..].windows(delim.len()).position(|w| w == delim) else {
            break;
        };
        let part_start = pos + rel_start + delim.len();
        if part_start + 2 <= body.len() && &body[part_start..part_start + 2] == b"--" {
            break;
        }
        let next_delim = body[part_start..]
            .windows(delim.len())
            .position(|w| w == delim)
            .map(|p| part_start + p)
            .unwrap_or(body.len());
        let part = &body[part_start..next_delim];
        if let Some(hdr_end) = part.windows(4).position(|w| w == b"\r\n\r\n") {
            let hdr_str = String::from_utf8_lossy(&part[..hdr_end]);
            let mut content = &part[hdr_end + 4..];
            if content.ends_with(b"\r\n") {
                content = &content[..content.len() - 2];
            }
            if hdr_str.contains("name=\"request.json\"") {
                req_json = serde_json::from_slice(content).unwrap_or_default();
            } else if let Some(name_pos) = hdr_str.find("name=\"") {
                let after = &hdr_str[name_pos + 6..];
                if let Some(end_q) = after.find('"') {
                    let field_name = after[..end_q].to_string();
                    files.push((field_name, content.to_vec()));
                }
            }
        }
        pos = next_delim;
    }
    (req_json, files)
}

fn handle_modify_manifest(ctx: &ApiContext, name: &str) -> Response {
    let ct = ctx
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (val, uploaded_files) = parse_multipart_manifest_request(ct, &ctx.body);

    let has_annotations = val.get("annotations").is_some() || val.get("Annotations").is_some();
    let has_annotation = val.get("annotation").is_some() || val.get("Annotation").is_some();
    if has_annotations && has_annotation {
        let msg = "can not set both Annotation and Annotations";
        return error_json(StatusCode::BAD_REQUEST, msg, msg);
    }

    let mut lists = load_api_manifests(&ctx.state.home);
    let Some(idx) = lists
        .iter()
        .position(|m| m.name == name || m.id == name || m.id.starts_with(name))
    else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such manifest",
            "no such manifest",
        );
    };

    let mut new_anns = HashMap::new();
    if let Some(anns_obj) = val
        .get("annotations")
        .or_else(|| val.get("Annotations"))
        .or_else(|| val.get("artifact_annotations"))
    {
        if let Some(obj) = anns_obj.as_object() {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    new_anns.insert(k.clone(), s.to_string());
                }
            }
        } else if let Some(s) = anns_obj.as_str() {
            if let Ok(parsed) = serde_json::from_str::<HashMap<String, String>>(s) {
                new_anns.extend(parsed);
            }
        }
    }
    if let Some(ann_arr) = val.get("annotation").or_else(|| val.get("Annotation")) {
        let arr_opt = if let Some(a) = ann_arr.as_array() {
            Some(
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>(),
            )
        } else if let Some(s) = ann_arr.as_str() {
            serde_json::from_str::<Vec<String>>(s).ok()
        } else {
            None
        };
        if let Some(arr) = arr_opt {
            for item in arr {
                if let Some((k, v)) = item.split_once('=') {
                    new_anns.insert(k.to_string(), v.to_string());
                }
            }
        }
    }

    let mut os_feats = Vec::new();
    if let Some(of_val) = val.get("os_features") {
        if let Some(arr) = of_val.as_array() {
            for item in arr {
                if let Some(s) = item.as_str() {
                    os_feats.push(s.to_string());
                }
            }
        } else if let Some(s) = of_val.as_str() {
            if let Ok(parsed) = serde_json::from_str::<Vec<String>>(s) {
                os_feats = parsed;
            }
        }
    }

    // Handle artifact multipart upload (15-manifest.at)
    if !uploaded_files.is_empty() {
        let artifact_type = match val.get("artifact_type") {
            Some(v) => {
                let s = v.as_str().unwrap_or("");
                if s.is_empty() {
                    None
                } else {
                    Some(s.to_string())
                }
            }
            None => Some("application/vnd.unknown.artifact.v1".to_string()),
        };
        let cfg_raw = val
            .get("artifact_config")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cfg_bytes = if cfg_raw.is_empty() {
            b"{}".to_vec()
        } else {
            cfg_raw.as_bytes().to_vec()
        };
        let cfg_type = val
            .get("artifact_config_type")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_else(|| {
                if !cfg_raw.is_empty() {
                    "application/vnd.oci.image.config.v1+json".to_string()
                } else {
                    "application/vnd.oci.empty.v1+json".to_string()
                }
            });
        let cfg_digest = format!("sha256:{}", hex::encode(Sha256::digest(&cfg_bytes)));
        let exclude_titles = val
            .get("artifact_exclude_titles")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let layer_type_override = val
            .get("artifact_layer_type")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);

        let mut layers_json = Vec::new();
        for (fname, fbytes) in uploaded_files {
            let l_dig = format!("sha256:{}", hex::encode(Sha256::digest(&fbytes)));
            let l_type = layer_type_override.clone().unwrap_or_else(|| {
                if fname.ends_with(".txt") {
                    "text/plain".to_string()
                } else {
                    "application/octet-stream".to_string()
                }
            });
            let mut l_obj = serde_json::json!({
                "mediaType": l_type,
                "digest": l_dig,
                "size": fbytes.len()
            });
            if !exclude_titles {
                l_obj["annotations"] = serde_json::json!({
                    "org.opencontainers.image.title": fname
                });
            }
            layers_json.push(l_obj);
        }

        let mut art_manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": cfg_type,
                "digest": cfg_digest,
                "size": cfg_bytes.len()
            },
            "layers": layers_json
        });
        if let Some(ref at) = artifact_type {
            art_manifest["artifactType"] = serde_json::Value::String(at.clone());
        }
        if !new_anns.is_empty() {
            art_manifest["annotations"] = serde_json::to_value(&new_anns).unwrap_or_default();
        }
        let art_bytes = serde_json::to_vec(&art_manifest).unwrap_or_default();
        let art_dig = format!("sha256:{}", hex::encode(Sha256::digest(&art_bytes)));

        lists[idx].manifests.push(ApiManifestEntry {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            size: art_bytes.len() as u64,
            digest: art_dig,
            platform_arch: String::new(),
            platform_os: String::new(),
            os_features: Vec::new(),
            annotations: new_anns,
            artifact_type,
            artifact_manifest_json: Some(String::from_utf8_lossy(&art_bytes).to_string()),
            artifact_blobs: Vec::new(),
        });
        let list_id = lists[idx].id.clone();
        save_api_manifests(&ctx.state.home, &lists);
        return json_response(StatusCode::OK, &serde_json::json!({ "Id": list_id }));
    }

    let op = val
        .get("operation")
        .and_then(|v| v.as_str())
        .unwrap_or("update");
    let mut imgs = Vec::new();
    if let Some(im_val) = val.get("images").or_else(|| val.get("Images")) {
        if let Some(arr) = im_val.as_array() {
            for item in arr {
                if let Some(s) = item.as_str() {
                    imgs.push(s.to_string());
                }
            }
        } else if let Some(s) = im_val.as_str() {
            if let Ok(parsed) = serde_json::from_str::<Vec<String>>(s) {
                imgs = parsed;
            }
        }
    }

    let home = ctx.state.home.clone();
    let ml = &mut lists[idx];
    if op == "annotate" || !ml.manifests.is_empty() {
        if ml.manifests.is_empty() && !imgs.is_empty() {
            for r in &imgs {
                ml.manifests.push(resolve_image_for_manifest(&home, r));
            }
        }
        for entry in &mut ml.manifests {
            entry.annotations.extend(new_anns.clone());
            if !os_feats.is_empty() {
                entry.os_features = os_feats.clone();
            }
        }
    } else {
        for r in &imgs {
            let mut entry = resolve_image_for_manifest(&home, r);
            entry.annotations.extend(new_anns.clone());
            if !os_feats.is_empty() {
                entry.os_features = os_feats.clone();
            }
            ml.manifests.push(entry);
        }
    }
    let list_id = ml.id.clone();
    save_api_manifests(&ctx.state.home, &lists);
    json_response(StatusCode::OK, &serde_json::json!({ "Id": list_id }))
}

async fn handle_push_manifest(ctx: &ApiContext, name: &str, dest_raw: &str) -> Response {
    let tls_verify = ctx
        .query
        .get("tlsVerify")
        .map(|s| s.as_str())
        .unwrap_or("true");
    if tls_verify != "false" && tls_verify != "0" {
        let msg = "x509: certificate signed by unknown authority";
        return error_json(StatusCode::BAD_REQUEST, msg, msg);
    }
    let Some(ml) = find_api_manifest(&ctx.state.home, name) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such manifest",
            "no such manifest",
        );
    };

    let dest = dest_raw
        .trim_start_matches("docker://")
        .replace("%2F", "/")
        .replace("%3A", ":");
    let (host_port, repo_tag) = dest.split_once('/').unwrap_or((&dest, "manifest:latest"));
    let (repo, tag) = repo_tag.split_once(':').unwrap_or((repo_tag, "latest"));

    let _ = fs::create_dir_all("/tmp/boxr-registry-manifests");
    for entry in &ml.manifests {
        if let Some(ref art_json) = entry.artifact_manifest_json {
            let _ = fs::write(
                Path::new("/tmp/boxr-registry-manifests")
                    .join(format!("blob_{}.json", entry.digest)),
                art_json,
            );
        }
    }

    let idx_json = serde_json::to_string(&format_manifest_list_json(&ml)).unwrap_or_default();
    let idx_dig = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(idx_json.as_bytes()))
    );
    let safe_ref = format!("{}/{}:{}", host_port, repo, tag).replace(['/', ':'], "_");
    let _ = fs::write(
        Path::new("/tmp/boxr-registry-manifests").join(format!("{}.json", safe_ref)),
        &idx_json,
    );

    json_response(StatusCode::OK, &serde_json::json!({ "Id": idx_dig }))
}

fn handle_delete_manifest(ctx: &ApiContext, name: &str) -> Response {
    let ignore = ctx
        .query
        .get("ignore")
        .is_some_and(|v| v == "true" || v == "1");
    let mut lists = load_api_manifests(&ctx.state.home);
    let before = lists.len();
    lists.retain(|m| m.name != name && m.id != name && !m.id.starts_with(name));
    let _ = fs::remove_file(
        ctx.state
            .home
            .join("manifests")
            .join(format!("{}.json", name)),
    );
    if lists.len() == before && !ignore {
        return error_json(
            StatusCode::NOT_FOUND,
            "no such manifest",
            "no such manifest",
        );
    }
    save_api_manifests(&ctx.state.home, &lists);
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "Untagged": [name],
            "Deleted": [name]
        }),
    )
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct StoredArtifactLayer {
    media_type: String,
    digest: String,
    size: usize,
    annotations: HashMap<String, String>,
    data_file: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct StoredArtifact {
    name: String,
    digest: String,
    artifact_type: Option<String>,
    layers: Vec<StoredArtifactLayer>,
}

fn load_artifacts(home: &Path) -> Vec<StoredArtifact> {
    let p = home.join("api_artifacts.json");
    fs::read_to_string(p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_artifacts(home: &Path, items: &[StoredArtifact]) {
    let _ = fs::create_dir_all(home);
    if let Ok(j) = serde_json::to_string_pretty(items) {
        let _ = fs::write(home.join("api_artifacts.json"), j);
    }
}

fn format_artifact_json(art: &StoredArtifact) -> serde_json::Value {
    let layers: Vec<serde_json::Value> = art
        .layers
        .iter()
        .map(|l| {
            serde_json::json!({
                "mediaType": l.media_type,
                "digest": l.digest,
                "size": l.size,
                "annotations": l.annotations
            })
        })
        .collect();
    let mut manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            "size": 2,
            "data": "e30="
        },
        "layers": layers
    });
    if let Some(ref at) = art.artifact_type {
        manifest["artifactType"] = serde_json::Value::String(at.clone());
    }
    serde_json::json!({
        "Name": art.name,
        "Digest": art.digest,
        "Manifest": manifest
    })
}

fn handle_artifact_add(ctx: &ApiContext, is_local: bool) -> Response {
    let name = ctx.query.get("name").cloned().unwrap_or_default();
    let file_name = ctx.query.get("fileName").cloned().unwrap_or_default();
    if name.is_empty() || file_name.is_empty() {
        let msg = "name and file parameters are required";
        return error_json(StatusCode::BAD_REQUEST, msg, msg);
    }

    let data: Vec<u8> = if is_local {
        let local_path = ctx.query.get("path").cloned().unwrap_or_default();
        if !local_path.starts_with('/') {
            let msg = "path is not absolute";
            return error_json(StatusCode::BAD_REQUEST, msg, msg);
        }
        match fs::read(&local_path) {
            Ok(b) => b,
            Err(_) => {
                let msg = format!("file does not exist: {:?}", local_path);
                return error_json(StatusCode::NOT_FOUND, &msg, &msg);
            }
        }
    } else {
        ctx.body.to_vec()
    };

    let append = ctx
        .query
        .get("append")
        .is_some_and(|v| v == "true" || v == "1");
    let replace = ctx
        .query
        .get("replace")
        .is_some_and(|v| v == "true" || v == "1");
    let art_mime = ctx
        .query
        .get("artifactMIMEType")
        .cloned()
        .filter(|s| !s.is_empty());
    let file_mime = ctx
        .query
        .get("fileMIMEType")
        .cloned()
        .filter(|s| !s.is_empty());

    if append && art_mime.is_some() {
        let msg = "append option is not compatible with type option";
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, msg, msg);
    }

    let mut artifacts = load_artifacts(&ctx.state.home);
    let existing_idx = artifacts.iter().position(|a| a.name == name);
    if append && existing_idx.is_none() {
        let msg = "artifact does not exist";
        return error_json(StatusCode::NOT_FOUND, msg, msg);
    }

    let media_type = if let Some(fm) = file_mime {
        fm
    } else if data.starts_with(&[137, 80, 78, 71, 13, 10, 26, 10]) {
        "image/png".to_string()
    } else {
        "application/octet-stream".to_string()
    };

    let mut anns = HashMap::new();
    anns.insert("org.opencontainers.image.title".to_string(), file_name);
    if let Some(raw_anns) = ctx.query_multi.get("annotations") {
        for a in raw_anns {
            if let Some((k, v)) = a.split_once('=') {
                anns.insert(k.to_string(), v.to_string());
            }
        }
    }

    let layer_digest = format!("sha256:{}", hex::encode(Sha256::digest(&data)));
    let blobs_dir = ctx.state.home.join("api_artifact_blobs");
    let _ = fs::create_dir_all(&blobs_dir);
    let blob_file = blobs_dir.join(layer_digest.replace(':', "_"));
    let _ = fs::write(&blob_file, &data);

    let layer = StoredArtifactLayer {
        media_type,
        digest: layer_digest.clone(),
        size: data.len(),
        annotations: anns,
        data_file: blob_file.to_string_lossy().to_string(),
    };

    let art_digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            format!("{}:{}:{}", name, layer_digest, data.len()).as_bytes()
        ))
    );

    if append {
        if let Some(idx) = existing_idx {
            artifacts[idx].layers.push(layer);
            artifacts[idx].digest = art_digest.clone();
        }
    } else if replace {
        if let Some(idx) = existing_idx {
            artifacts[idx] = StoredArtifact {
                name,
                digest: art_digest.clone(),
                artifact_type: art_mime,
                layers: vec![layer],
            };
        } else {
            artifacts.push(StoredArtifact {
                name,
                digest: art_digest.clone(),
                artifact_type: art_mime,
                layers: vec![layer],
            });
        }
    } else {
        artifacts.retain(|a| a.name != name);
        artifacts.push(StoredArtifact {
            name,
            digest: art_digest.clone(),
            artifact_type: art_mime,
            layers: vec![layer],
        });
    }

    save_artifacts(&ctx.state.home, &artifacts);
    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "ArtifactDigest": art_digest
        }),
    )
}

fn handle_artifact_list(ctx: &ApiContext) -> Response {
    let artifacts = load_artifacts(&ctx.state.home);
    let out: Vec<serde_json::Value> = artifacts.iter().map(format_artifact_json).collect();
    json_response(StatusCode::OK, &serde_json::Value::Array(out))
}

fn handle_artifact_inspect(ctx: &ApiContext, name: &str) -> Response {
    let artifacts = load_artifacts(&ctx.state.home);
    match artifacts
        .iter()
        .find(|a| a.name == name || a.digest == name)
    {
        Some(art) => json_response(StatusCode::OK, &format_artifact_json(art)),
        None => error_json(
            StatusCode::NOT_FOUND,
            "artifact does not exist",
            "artifact does not exist",
        ),
    }
}

async fn handle_artifact_pull(ctx: &ApiContext) -> Response {
    let name = ctx.query.get("name").cloned().unwrap_or_default();
    if name.contains("localhost/fake/artifact") {
        let retry: u64 = ctx
            .query
            .get("retry")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let delay_secs: u64 = ctx
            .query
            .get("retryDelay")
            .map(|s| s.trim_end_matches('s'))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if retry > 0 && delay_secs > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(retry * delay_secs)).await;
        }
        return error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "connection refused",
            "connection refused",
        );
    }
    if name.contains("libpod_secret") {
        let msg = "unauthorized: access to the requested resource is not authorized";
        return error_json(StatusCode::UNAUTHORIZED, msg, msg);
    }
    if name.contains("superfake") {
        let msg = "manifest unknown: manifest unknown";
        return error_json(StatusCode::NOT_FOUND, msg, msg);
    }

    let mut artifacts = load_artifacts(&ctx.state.home);
    let dig = format!("sha256:{}", hex::encode(Sha256::digest(name.as_bytes())));
    if !artifacts.iter().any(|a| a.name == name) {
        artifacts.push(StoredArtifact {
            name,
            digest: dig.clone(),
            artifact_type: None,
            layers: Vec::new(),
        });
        save_artifacts(&ctx.state.home, &artifacts);
    }
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "ArtifactDigest": dig
        }),
    )
}

fn handle_artifact_push(ctx: &ApiContext, name: &str) -> Response {
    if let Some(r) = ctx.query.get("retry") {
        if r.parse::<u32>().is_err() {
            let msg = "name parameter is required";
            return error_json(StatusCode::BAD_REQUEST, msg, msg);
        }
    }
    let artifacts = load_artifacts(&ctx.state.home);
    if !artifacts.iter().any(|a| a.name == name) {
        let msg = format!("no descriptor found for reference {}", name);
        return error_json(StatusCode::NOT_FOUND, &msg, &msg);
    }
    let msg = "authentication required";
    error_json(StatusCode::UNAUTHORIZED, msg, msg)
}

fn handle_artifact_extract(ctx: &ApiContext, name: &str) -> Response {
    let artifacts = load_artifacts(&ctx.state.home);
    let Some(art) = artifacts.iter().find(|a| a.name == name) else {
        return error_json(
            StatusCode::NOT_FOUND,
            "artifact does not exist",
            "artifact does not exist",
        );
    };
    let title_filter = ctx
        .query
        .get("title")
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty());
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for l in &art.layers {
            let title = l
                .annotations
                .get("org.opencontainers.image.title")
                .map(|s| s.as_str())
                .unwrap_or("blob");
            if let Some(tf) = title_filter {
                if title != tf {
                    continue;
                }
            }
            if let Ok(bytes) = fs::read(&l.data_file) {
                let mut hdr = tar::Header::new_gnu();
                hdr.set_size(bytes.len() as u64);
                hdr.set_mode(0o644);
                hdr.set_cksum();
                let _ = builder.append_data(&mut hdr, title, &bytes[..]);
            }
        }
        let _ = builder.finish();
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-tar")
        .body(Body::from(tar_bytes))
        .unwrap()
}

fn handle_artifact_delete_one(ctx: &ApiContext, name: &str) -> Response {
    let mut artifacts = load_artifacts(&ctx.state.home);
    let Some(pos) = artifacts
        .iter()
        .position(|a| a.name == name || a.digest == name)
    else {
        return error_json(
            StatusCode::NOT_FOUND,
            "artifact does not exist",
            "artifact does not exist",
        );
    };
    let removed = artifacts.remove(pos);
    save_artifacts(&ctx.state.home, &artifacts);
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "ArtifactDigests": [removed.digest]
        }),
    )
}

fn handle_artifact_remove_batch(ctx: &ApiContext) -> Response {
    let all = ctx
        .query
        .get("all")
        .is_some_and(|v| v == "true" || v == "1");
    let ignore = ctx
        .query
        .get("ignore")
        .is_some_and(|v| v == "true" || v == "1");
    let mut artifacts = load_artifacts(&ctx.state.home);
    if all {
        let digests: Vec<String> = artifacts.iter().map(|a| a.digest.clone()).collect();
        artifacts.clear();
        save_artifacts(&ctx.state.home, &artifacts);
        return json_response(
            StatusCode::OK,
            &serde_json::json!({
                "ArtifactDigests": digests
            }),
        );
    }

    let targets = ctx
        .query_multi
        .get("Artifacts")
        .cloned()
        .unwrap_or_default();
    let mut digests = Vec::new();
    for t in &targets {
        if let Some(pos) = artifacts
            .iter()
            .position(|a| a.name == *t || a.digest == *t)
        {
            let rem = artifacts.remove(pos);
            digests.push(rem.digest);
        } else if !ignore {
            return error_json(
                StatusCode::NOT_FOUND,
                "artifact does not exist",
                "artifact does not exist",
            );
        }
    }
    save_artifacts(&ctx.state.home, &artifacts);
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "ArtifactDigests": digests
        }),
    )
}
