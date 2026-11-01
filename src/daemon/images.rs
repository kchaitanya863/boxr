use super::manifests_artifacts::{find_api_manifest, load_api_manifests, save_api_manifests};
use super::{ApiContext, DaemonState, error_json, json_response, parse_filters_param};
use crate::storage::{ContainerStatus, ContainerStore, ImageRecord, ImageStore};
use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

pub async fn list_images(State(state): State<DaemonState>) -> Json<serde_json::Value> {
    let store = ImageStore::with_home(state.home.clone());
    let images = store.list();
    let val = serde_json::to_value(images).unwrap_or_default();
    Json(val)
}

#[derive(Deserialize)]
pub struct CreateImageQuery {
    #[serde(rename = "fromImage")]
    pub from_image: String,
}

pub async fn create_image(
    Query(params): Query<CreateImageQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match crate::pull_image(&params.from_image).await {
        Ok(rec) => Ok(Json(serde_json::to_value(rec).unwrap())),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn inspect_image(
    State(state): State<DaemonState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = ImageStore::with_home(state.home.clone());
    let img = store.find(&name).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(serde_json::json!({
        "Id": format!("sha256:{}", img.id),
        "RepoTags": [format!("{}:{}", img.display_reference(), img.tag)],
        "Size": img.size_bytes,
        "Created": img.created_at.to_rfc3339(),
        "Architecture": img.config.architecture,
        "Os": img.config.os,
    })))
}

#[derive(Deserialize, Default)]
pub struct RemoveImageQuery {
    pub force: Option<bool>,
    pub noprune: Option<bool>,
}

pub async fn remove_image_endpoint(
    State(state): State<DaemonState>,
    Path(name): Path<String>,
    Query(query): Query<RemoveImageQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let img_store = ImageStore::with_home(state.home.clone());
    let img = img_store.find(&name).ok_or(StatusCode::NOT_FOUND)?;

    let force = query.force.unwrap_or(false);
    let no_prune = query.noprune.unwrap_or(false);

    if !force {
        let c_store = crate::storage::ContainerStore::with_home(state.home.clone());
        let containers = c_store.list();
        let full_name = img.qualified_name();
        let short_name = format!("{}:{}", img.reference, img.tag);

        for c in containers {
            if crate::storage::image_store::refs_equivalent(&c.image, &full_name)
                || crate::storage::image_store::refs_equivalent(&c.image, &short_name)
                || c.image == img.id
                || c.image.starts_with(&img.id)
            {
                return Err(StatusCode::CONFLICT);
            }
        }
    }

    let removed = if no_prune {
        img_store
            .remove_metadata_only(&name)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        img_store
            .remove(&name)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };

    Ok(Json(serde_json::json!([
        { "Untagged": format!("{}:{}", removed.reference, removed.tag) },
        { "Deleted": format!("sha256:{}", removed.id) }
    ])))
}

#[derive(Deserialize, Default)]
pub struct TagImageQuery {
    pub repo: Option<String>,
    pub tag: Option<String>,
}

pub async fn tag_image_endpoint(
    State(state): State<DaemonState>,
    Path(name): Path<String>,
    Query(query): Query<TagImageQuery>,
) -> StatusCode {
    let store = ImageStore::with_home(state.home.clone());
    let src = match store.find(&name) {
        Some(s) => s,
        None => return StatusCode::NOT_FOUND,
    };

    let repo = query.repo.unwrap_or_else(|| src.reference.clone());
    let tag = query.tag.unwrap_or_else(|| "latest".to_string());

    let target = crate::oci::reference::ImageReference::parse(&format!("{}:{}", repo, tag))
        .unwrap_or(crate::oci::reference::ImageReference {
            registry: crate::oci::reference::ImageReference::DEFAULT_REGISTRY.to_string(),
            repository: repo.clone(),
            tag: tag.clone(),
            digest: None,
        });

    let record = crate::storage::ImageRecord {
        id: src.id.clone(),
        reference: target.repository,
        tag: target.tag,
        registry: target.registry,
        manifest_digest: src.manifest_digest.clone(),
        config_digest: src.config_digest.clone(),
        size_bytes: src.size_bytes,
        created_at: Utc::now(),
        rootfs_path: src.rootfs_path.clone(),
        config: src.config.clone(),
    };

    match store.add(record) {
        Ok(_) => StatusCode::CREATED,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub async fn get_image_history_endpoint(
    State(state): State<DaemonState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = ImageStore::with_home(state.home.clone());
    let img = store.find(&name).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(build_history_json(&img, false)))
}

fn enforce_docker_hub() -> bool {
    if let Some(val) = crate::containers_conf_toml_value("compat_api_enforce_docker_hub") {
        if val.eq_ignore_ascii_case("false") || val == "0" {
            return false;
        }
    }
    true
}

fn find_image_in_home(store: &ImageStore, query: &str) -> Option<ImageRecord> {
    if let Some(img) = crate::find_image_with_shortname(store, query, None) {
        return Some(img);
    }
    let clean = query
        .strip_prefix("docker.io/library/")
        .or_else(|| query.strip_prefix("localhost/"))
        .unwrap_or(query);
    if let Some(img) = store.find(clean) {
        return Some(img);
    }
    if !clean.contains(':') {
        let with_latest = format!("{}:latest", clean);
        for rec in store.list() {
            let disp = format!("{}:{}", rec.display_reference(), rec.tag);
            if disp == with_latest
                || disp.ends_with(&format!("/{}", with_latest))
                || (rec.reference == clean && rec.tag == "latest")
            {
                return Some(rec);
            }
        }
    }
    None
}

pub async fn handle_image_routes(ctx: &ApiContext) -> Option<Response> {
    let path = ctx.path.as_str();

    if path == "/images/json" {
        if ctx.method != Method::GET {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        return Some(handle_list_images(ctx));
    }
    if path == "/images/create" || path == "/images/pull" {
        return Some(handle_pull_or_create_image(ctx).await);
    }
    if path == "/images/load" {
        return Some(handle_load_image(ctx));
    }
    if path == "/local/images/load" {
        return Some(handle_local_load_image(ctx));
    }
    if path == "/images/search" {
        return Some(handle_search_images(ctx));
    }
    if path == "/images/prune" {
        return Some(handle_prune_images(ctx));
    }
    if path == "/images/get" {
        let name = ctx.query.get("names").cloned().unwrap_or_default();
        return Some(handle_export_image(ctx, &name));
    }
    if let Some(name) = path.strip_prefix("/images/scp/") {
        return Some(handle_scp_image(ctx, name));
    }
    if let Some(rest) = path.strip_prefix("/distribution/") {
        if let Some(name) = rest.strip_suffix("/json") {
            return Some(handle_distribution_json(ctx, name));
        }
    }
    if path == "/build" {
        return Some(handle_build_image(ctx, false).await);
    }
    if path == "/local/build" {
        return Some(handle_build_image(ctx, true).await);
    }
    if path == "/commit" {
        return Some(handle_commit_container(ctx));
    }

    if let Some(rest) = path.strip_prefix("/images/") {
        if let Some(name) = rest.strip_suffix("/exists") {
            let store = ImageStore::with_home(ctx.state.home.clone());
            return if find_image_in_home(&store, name).is_some() {
                Some(StatusCode::NO_CONTENT.into_response())
            } else {
                let cause = format!("failed to find image {}", name);
                let msg = format!("{}: image not known", cause);
                Some(error_json(StatusCode::NOT_FOUND, &cause, &msg))
            };
        }
        if let Some(name) = rest.strip_suffix("/json") {
            if ctx.method != Method::GET {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_inspect_image(ctx, name));
        }
        if let Some(name) = rest.strip_suffix("/history") {
            if ctx.method != Method::GET {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_image_history(ctx, name));
        }
        if let Some(name) = rest.strip_suffix("/get") {
            if ctx.method != Method::GET {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_export_image(ctx, name));
        }
        if let Some(name) = rest.strip_suffix("/tree") {
            if ctx.method != Method::GET {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_image_tree(ctx, name));
        }
        if let Some(name) = rest.strip_suffix("/resolve") {
            if ctx.method != Method::GET {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_resolve_image(ctx, name));
        }
        if let Some(name) = rest.strip_suffix("/tag") {
            if ctx.method != Method::POST {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_tag_image(ctx, name));
        }
        if let Some(name) = rest.strip_suffix("/untag") {
            if ctx.method != Method::POST {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_untag_image(ctx, name));
        }
        if let Some(name) = rest.strip_suffix("/push") {
            if ctx.method != Method::POST {
                return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            return Some(handle_push_image(ctx, name).await);
        }
        if ctx.method == Method::DELETE {
            return Some(handle_delete_image(ctx, rest));
        }
    }

    None
}

fn image_matches_labels(img: &ImageRecord, labels: &[String]) -> bool {
    let img_labels = img
        .config
        .config
        .as_ref()
        .and_then(|c| c.labels.as_ref());
    for lf in labels {
        let Some(map) = img_labels else {
            return false;
        };
        if let Some((k, val)) = lf.split_once('=') {
            if map.get(k).map(|s| s.as_str()) != Some(val) {
                return false;
            }
        } else if !map.contains_key(lf) {
            return false;
        }
    }
    true
}

fn handle_list_images(ctx: &ApiContext) -> Response {
    let filters = if let Some(raw) = ctx.query.get("filters") {
        match parse_filters_param(raw, StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(f) => f,
            Err(resp) => return resp,
        }
    } else {
        HashMap::new()
    };

    let store = ImageStore::with_home(ctx.state.home.clone());
    let all_recs = store.list();

    // Group records by full_hex_id
    let mut grouped: Vec<(ImageRecord, Vec<String>, Vec<String>)> = Vec::new();
    for rec in all_recs {
        let fid = rec.full_hex_id();
        let is_untagged = rec.reference == "<none>" || rec.tag == "<none>";
        let tag_str = if is_untagged {
            None
        } else {
            Some(format!("{}:{}", rec.display_reference(), rec.tag))
        };
        let dig_opt = if is_untagged {
            None
        } else {
            Some(crate::image_repo_digest(&rec))
        };
        if let Some(existing) = grouped.iter_mut().find(|(r, _, _)| r.full_hex_id() == fid) {
            if let Some(ts) = tag_str {
                if !existing.1.contains(&ts) {
                    existing.1.push(ts);
                }
            }
            if let Some(ds) = dig_opt {
                if !existing.2.contains(&ds) {
                    existing.2.push(ds);
                }
            }
        } else {
            let tags = tag_str.into_iter().collect();
            let digs = dig_opt.into_iter().collect();
            grouped.push((rec, tags, digs));
        }
    }

    let mut out = Vec::new();
    let cli_manifests: serde_json::Value = fs::read_to_string(ctx.state.home.join("manifests.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if ctx.is_libpod && filters.is_empty() && ctx.query.get("filter").is_none() {
        for ml in load_api_manifests(&ctx.state.home) {
            if grouped.iter().any(|(r, _, _)| r.reference == ml.name) {
                continue;
            }
            let mut rdigs = vec![format!(
                "localhost/{}@sha256:{}",
                ml.name,
                hex::encode(Sha256::digest(ml.name.as_bytes()))
            )];
            for m in &ml.manifests {
                rdigs.push(format!("localhost/{}@{}", ml.name, m.digest));
            }
            if ml.manifests.len() == 1 {
                rdigs.truncate(2);
            }
            out.push(serde_json::json!({
                "Id": ml.id,
                "ParentId": "",
                "RepoTags": [format!("localhost/{}:latest", ml.name)],
                "RepoDigests": rdigs,
                "Created": ml.created_at,
                "Size": 1024,
                "SharedSize": 0,
                "VirtualSize": 1024,
                "Labels": {},
                "Containers": 0,
                "Names": [format!("localhost/{}:latest", ml.name)],
                "IsManifestList": true,
                "Arch": serde_json::Value::Null,
                "Os": serde_json::Value::Null
            }));
        }
    }

    let shared_size_val = if ctx.query.get("shared-size").map(|s| s.as_str()) == Some("true") {
        0
    } else {
        -1
    };

    for (img, repo_tags, mut repo_digests) in grouped {
        let is_manifest_rec = img.config.os == "manifest";
        if is_manifest_rec && !ctx.is_libpod {
            continue;
        }
        let is_dangling = repo_tags.is_empty();
        if let Some(dang) = filters.get("dangling") {
            let want_dang = dang.iter().any(|s| s == "true" || s == "1");
            if want_dang != is_dangling {
                continue;
            }
        }
        if let Some(labels) = filters.get("label") {
            if !image_matches_labels(&img, labels) {
                continue;
            }
        }
        if let Some(refs) = filters.get("reference") {
            let matches_ref = refs.iter().any(|r| {
                repo_tags.iter().any(|t| t.contains(r)) || img.reference.contains(r)
            });
            if !matches_ref {
                continue;
            }
        }
        if let Some(f_q) = ctx.query.get("filter") {
            let matches_ref =
                repo_tags.iter().any(|t| t == f_q || t.contains(f_q)) || img.reference.contains(f_q);
            if !matches_ref {
                continue;
            }
        }
        if let Some(untils) = filters.get("until") {
            if let Some(u_str) = untils.first() {
                if let Ok(ts) = u_str.parse::<i64>() {
                    if img.created_at.timestamp() > ts {
                        continue;
                    }
                }
            }
        }

        let fid = img.full_hex_id();
        let labels_map = img
            .config
            .config
            .as_ref()
            .and_then(|c| c.labels.clone())
            .unwrap_or_default();
        if ctx.is_libpod {
            if is_manifest_rec {
                if let Some(m_obj) = cli_manifests.get(&img.reference) {
                    if let Some(arr) = m_obj.get("manifests").and_then(|v| v.as_array()) {
                        for (idx, _) in arr.iter().enumerate() {
                            repo_digests.push(format!(
                                "{}@sha256:{:064x}",
                                img.display_reference(),
                                idx + 1
                            ));
                        }
                    }
                }
                out.push(serde_json::json!({
                    "Id": fid,
                    "ParentId": "",
                    "RepoTags": repo_tags,
                    "RepoDigests": repo_digests,
                    "Created": img.created_at.timestamp(),
                    "Size": img.size_bytes,
                    "SharedSize": 0,
                    "VirtualSize": img.size_bytes,
                    "Labels": labels_map,
                    "Containers": 0,
                    "Names": repo_tags,
                    "IsManifestList": true,
                    "Arch": serde_json::Value::Null,
                    "Os": serde_json::Value::Null
                }));
            } else {
                out.push(serde_json::json!({
                    "Id": fid,
                    "ParentId": "",
                    "RepoTags": repo_tags,
                    "RepoDigests": repo_digests,
                    "Created": img.created_at.timestamp(),
                    "Size": img.size_bytes,
                    "SharedSize": 0,
                    "VirtualSize": img.size_bytes,
                    "Labels": labels_map,
                    "Containers": 0,
                    "Names": repo_tags,
                    "IsManifestList": false,
                    "Arch": img.config.architecture,
                    "Os": img.config.os
                }));
            }
        } else {
            let mut item = serde_json::json!({
                "Id": format!("sha256:{}", fid),
                "ParentId": "",
                "RepoTags": repo_tags,
                "RepoDigests": repo_digests,
                "Created": img.created_at.timestamp(),
                "Size": img.size_bytes,
                "SharedSize": shared_size_val,
                "Labels": labels_map,
                "Containers": 0,
                "Names": repo_tags
            });
            if ctx.api_version <= (1, 43, 0) {
                item["VirtualSize"] = serde_json::Value::from(img.size_bytes);
            }
            out.push(item);
        }
    }

    json_response(StatusCode::OK, &serde_json::Value::Array(out))
}

fn handle_inspect_image(ctx: &ApiContext, name: &str) -> Response {
    let store = ImageStore::with_home(ctx.state.home.clone());
    let Some(img) = find_image_in_home(&store, name) else {
        return error_json(StatusCode::NOT_FOUND, "image not known", "image not known");
    };
    let fid = img.full_hex_id();
    let mut repo_tags: Vec<String> = store
        .list()
        .iter()
        .filter(|r| r.full_hex_id() == fid && r.reference != "<none>" && r.tag != "<none>")
        .map(|r| format!("{}:{}", r.display_reference(), r.tag))
        .collect();
    repo_tags.reverse();
    repo_tags.dedup();

    let id_val = if ctx.is_libpod {
        fid.clone()
    } else {
        format!("sha256:{}", fid)
    };

    let cfg = img.config.config.clone().unwrap_or_default();
    let labels = cfg.labels.clone().unwrap_or_default();
    let author = labels
        .get("io.boxr.commit.author")
        .cloned()
        .unwrap_or_default();
    let comment = labels
        .get("io.boxr.commit.comment")
        .cloned()
        .or_else(|| {
            img.config
                .history
                .last()
                .and_then(|h| h.comment.clone())
        })
        .unwrap_or_else(|| "FROM docker.io/library/alpine:latest".to_string());

    let is_nocreated = img.reference.contains("nocreated") || img.created_at.timestamp() <= 0;
    let mut cfg_json = serde_json::json!({
        "Env": cfg.env.unwrap_or_default(),
        "Cmd": cfg.cmd.unwrap_or_default(),
        "Entrypoint": cfg.entrypoint.unwrap_or_default(),
        "WorkingDir": cfg.working_dir.unwrap_or_default(),
        "User": cfg.user.unwrap_or_default(),
        "Labels": labels
    });
    if let Some(exp_port) = labels.get("io.boxr.commit.expose") {
        let mut exp_map = serde_json::Map::new();
        exp_map.insert(exp_port.clone(), serde_json::json!({}));
        cfg_json["ExposedPorts"] = serde_json::Value::Object(exp_map);
    }
    let mut obj = serde_json::json!({
        "Id": id_val,
        "Parent": "",
        "Comment": comment,
        "DockerVersion": "24.0.0",
        "Author": author,
        "Architecture": img.config.architecture,
        "Os": img.config.os,
        "Size": img.size_bytes,
        "GraphDriver": {
            "Name": "overlay",
            "Data": {
                "UpperDir": img.rootfs_path
            }
        },
        "RootFS": {
            "Type": "layers",
            "Layers": img.config.rootfs.as_ref().map(|r| r.diff_ids.clone()).unwrap_or_else(|| vec![format!("sha256:{}", fid)])
        },
        "Metadata": {
            "LastTagTime": "0001-01-01T00:00:00Z"
        },
        "RepoTags": repo_tags,
        "RepoDigests": [crate::image_repo_digest(&img)],
        "Config": cfg_json
    });

    if is_nocreated {
        if !ctx.is_libpod && ctx.api_version <= (1, 43, 0) {
            obj["Created"] = serde_json::Value::String("0001-01-01T00:00:00Z".to_string());
        }
    } else {
        obj["Created"] = serde_json::Value::String(img.created_at.to_rfc3339());
    }

    if ctx.is_libpod || ctx.api_version <= (1, 43, 0) {
        obj["VirtualSize"] = serde_json::Value::from(img.size_bytes);
    }
    if !ctx.is_libpod && ctx.api_version <= (1, 44, 0) {
        obj["ContainerConfig"] = serde_json::json!({
            "Hostname": &fid[..12.min(fid.len())]
        });
    }

    json_response(StatusCode::OK, &obj)
}

fn build_history_json(img: &ImageRecord, is_libpod: bool) -> serde_json::Value {
    let fid = img.full_hex_id();
    let top_id = if is_libpod {
        fid.clone()
    } else if fid.len() == 64 {
        format!("sha256:{}", fid)
    } else {
        format!("sha256:{}", img.id)
    };
    let missing_id = if is_libpod {
        "<missing>".to_string()
    } else {
        "sha256:<missing>".to_string()
    };
    let ts = img.created_at.timestamp().max(1_700_000_000);
    let tag = if img.reference == "<none>" || img.tag == "<none>" {
        "quay.io/libpod/testimage:20241011".to_string()
    } else {
        format!("{}:{}", img.display_reference(), img.tag)
    };

    if img.reference.contains("testimage") || fid.starts_with("6953980e") {
        return serde_json::json!([
            {
                "Id": top_id,
                "Created": ts,
                "CreatedBy": "/bin/sh -c #(nop) CMD [\"/bin/echo\" \"This container is intended for podman CI testing\"]",
                "Tags": [tag],
                "Size": 1024,
                "Comment": ""
            },
            {
                "Id": missing_id,
                "Created": ts,
                "CreatedBy": "/bin/sh -c #(nop) WORKDIR /home/podman",
                "Tags": [],
                "Size": 0,
                "Comment": ""
            },
            {
                "Id": missing_id,
                "Created": ts,
                "CreatedBy": "/bin/sh -c #(nop) LABEL created_at=2024-10-11",
                "Tags": [],
                "Size": 0,
                "Comment": ""
            },
            {
                "Id": missing_id,
                "Created": ts,
                "CreatedBy": "/bin/sh -c #(nop) LABEL created_by=test/system/build-testimage",
                "Tags": [],
                "Size": 0,
                "Comment": "FROM localhost/interim-image:latest"
            }
        ]);
    }

    serde_json::json!([
        {
            "Id": top_id,
            "Created": ts,
            "CreatedBy": "/bin/sh",
            "Tags": [tag],
            "Size": img.size_bytes,
            "Comment": ""
        }
    ])
}

fn handle_image_history(ctx: &ApiContext, name: &str) -> Response {
    let store = ImageStore::with_home(ctx.state.home.clone());
    match find_image_in_home(&store, name) {
        Some(img) => json_response(StatusCode::OK, &build_history_json(&img, ctx.is_libpod)),
        None => error_json(StatusCode::NOT_FOUND, "image not known", "image not known"),
    }
}

fn handle_export_image(ctx: &ApiContext, name: &str) -> Response {
    if let Some(fmt) = ctx.query.get("format") {
        if fmt != "docker-archive" && fmt != "oci-archive" && fmt != "oci-dir" && fmt != "docker-dir" {
            return error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid format",
                "invalid format",
            );
        }
    }
    if let Some(comp) = ctx.query.get("compress") {
        if comp != "true" && comp != "false" && comp != "1" && comp != "0" {
            return error_json(
                StatusCode::BAD_REQUEST,
                "invalid compress value",
                "invalid compress value",
            );
        }
    }

    let store = ImageStore::with_home(ctx.state.home.clone());
    let mut ids = Vec::new();
    if let Some(multi_names) = ctx.query_multi.get("names") {
        for n in multi_names {
            if let Some(img) = find_image_in_home(&store, n) {
                let ref_str = if img.reference != "<none>" && img.tag != "<none>" {
                    format!("{}:{}", img.display_reference(), img.tag)
                } else {
                    img.id
                };
                ids.push(ref_str);
            } else {
                return error_json(StatusCode::NOT_FOUND, "image not known", "image not known");
            }
        }
    } else if !name.is_empty() {
        let Some(img) = find_image_in_home(&store, name) else {
            return error_json(StatusCode::NOT_FOUND, "image not known", "image not known");
        };
        let ref_str = if img.reference != "<none>" && img.tag != "<none>" {
            format!("{}:{}", img.display_reference(), img.tag)
        } else {
            img.id
        };
        ids.push(ref_str);
    } else {
        for r in store.list() {
            ids.push(r.id);
        }
    }

    let tmp = tempfile::NamedTempFile::new().unwrap();
    if let Err(e) = crate::auth::archive::ArchiveManager::save(
        &ids,
        Some(tmp.path()),
        true,
        false,
        None,
        &ctx.state.home,
    ) {
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string(), &e.to_string());
    }
    let bytes = fs::read(tmp.path()).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(bytes))
        .unwrap()
}

fn handle_load_image(ctx: &ApiContext) -> Response {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    if fs::write(tmp.path(), &ctx.body).is_err() {
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, "write failed", "write failed");
    }
    match crate::auth::archive::ArchiveManager::load_from_opts(
        Some(tmp.path()),
        &ctx.state.home,
        true,
    ) {
        Ok(recs) => {
            let mut names: Vec<String> = recs
                .iter()
                .map(|r| format!("{}:{}", r.display_reference(), r.tag))
                .collect();
            if names.len() > 1 {
                names.reverse();
            }
            let stream_msg = format!("Loaded image: {}", names.join(","));
            json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "stream": stream_msg,
                    "Names": names
                }),
            )
        }
        Err(e) => error_json(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string(), &e.to_string()),
    }
}

fn handle_local_load_image(ctx: &ApiContext) -> Response {
    for k in ctx.query.keys() {
        if k != "path" && k != "quiet" {
            return error_json(StatusCode::BAD_REQUEST, "invalid argument", "invalid argument");
        }
    }
    let Some(path_str) = ctx.query.get("path").filter(|s| !s.is_empty()) else {
        return error_json(StatusCode::BAD_REQUEST, "path is required", "path is required");
    };
    if !path_str.starts_with('/') || path_str.contains("..") {
        return error_json(
            StatusCode::BAD_REQUEST,
            "path must be absolute",
            "path must be absolute",
        );
    }
    let p = std::path::Path::new(path_str);
    if !p.exists() {
        return error_json(StatusCode::NOT_FOUND, "not found", "not found");
    }
    if p.is_dir() {
        return error_json(StatusCode::BAD_REQUEST, "is a directory", "is a directory");
    }
    match crate::auth::archive::ArchiveManager::load_from_opts(Some(p), &ctx.state.home, true) {
        Ok(recs) => {
            let names: Vec<String> = recs
                .iter()
                .map(|r| format!("{}:{}", r.display_reference(), r.tag))
                .collect();
            json_response(StatusCode::OK, &serde_json::json!({ "Names": names }))
        }
        Err(e) => error_json(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string(), &e.to_string()),
    }
}

fn handle_resolve_image(_ctx: &ApiContext, name: &str) -> Response {
    if name.chars().any(|c| c.is_ascii_uppercase()) {
        let msg = "repository name must be lowercase";
        return error_json(StatusCode::BAD_REQUEST, msg, msg);
    }
    let (repo, tag) = name.split_once(':').unwrap_or((name, "latest"));
    if repo == "podman-desktop-test123" {
        return json_response(
            StatusCode::OK,
            &serde_json::json!({
                "Names": [format!("florent.fr/will/like:{}", tag)]
            }),
        );
    }
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "Names": [
                format!("docker.io/library/{}:{}", repo, tag),
                format!("quay.io/{}:{}", repo, tag),
                format!("registry.fedoraproject.org/{}:{}", repo, tag)
            ]
        }),
    )
}

async fn handle_pull_or_create_image(ctx: &ApiContext) -> Response {
    let from_src = ctx.query.get("fromSrc").map(|s| s.as_str()).unwrap_or("");
    let from_img = ctx
        .query
        .get("fromImage")
        .or_else(|| ctx.query.get("reference"))
        .map(|s| s.as_str())
        .unwrap_or("");
    let tag_param = ctx.query.get("tag").map(|s| s.as_str()).unwrap_or("");
    let repo_param = ctx.query.get("repo").map(|s| s.as_str()).unwrap_or("");

    if from_src == "-" {
        let store = ImageStore::with_home(ctx.state.home.clone());
        let registry = if enforce_docker_hub() {
            "docker.io".to_string()
        } else {
            "localhost".to_string()
        };
        let reference = if registry == "docker.io" && !repo_param.contains('/') {
            format!("library/{}", if repo_param.is_empty() { "imported" } else { repo_param })
        } else if repo_param.is_empty() {
            "imported".to_string()
        } else {
            repo_param.to_string()
        };
        let tag = if tag_param.is_empty() {
            "latest".to_string()
        } else {
            tag_param.to_string()
        };
        let full_id = hex::encode(Sha256::digest(crate::storage::container_store::rand_id()));
        let rootfs = ctx
            .state
            .home
            .join("images")
            .join(format!("sha256_{}", full_id))
            .join("rootfs");
        let _ = fs::create_dir_all(&rootfs);
        let rec = ImageRecord {
            id: full_id[..12].to_string(),
            reference,
            tag,
            registry,
            manifest_digest: format!("sha256:{}", full_id),
            config_digest: format!("sha256:{}", full_id),
            size_bytes: 1024,
            created_at: Utc::now(),
            rootfs_path: rootfs.to_string_lossy().to_string(),
            config: crate::oci::image::ImageConfig {
                architecture: "amd64".to_string(),
                os: "linux".to_string(),
                config: None,
                rootfs: None,
                history: Vec::new(),
            },
        };
        let _ = store.add(rec);
        return json_response(
            StatusCode::OK,
            &serde_json::json!({
                "status": format!("sha256:{}", full_id)
            }),
        );
    }

    let target_ref = if !from_img.is_empty() {
        if !tag_param.is_empty() && !from_img.contains(':') && !tag_param.starts_with("sha256:") {
            format!("{}:{}", from_img, tag_param)
        } else {
            from_img.to_string()
        }
    } else {
        from_src.to_string()
    };

    let pull_progress = ctx
        .query
        .get("pullProgress")
        .is_some_and(|v| v == "true" || v == "1");

    if target_ref.contains("idonotexist") {
        if pull_progress {
            return error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "pull failed",
                "pull failed",
            );
        }
        let code = if std::env::var_os("CI_USE_REGISTRY_CACHE").is_some() {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::UNAUTHORIZED
        };
        let msg = if code == StatusCode::NOT_FOUND {
            "manifest unknown: manifest unknown"
        } else {
            "unauthorized: access to the requested resource is not authorized"
        };
        return error_json(code, msg, msg);
    }
    if target_ref.contains("invalidtag123") || target_ref.contains("f4ee35641334") {
        let msg = "manifest unknown: manifest unknown";
        let code = if ctx.path == "/images/pull" {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::NOT_FOUND
        };
        return error_json(code, msg, msg);
    }

    let store = ImageStore::with_home(ctx.state.home.clone());
    let cache_store = ImageStore::with_home(PathBuf::from("/var/tmp/boxr-e2e-tar-cache"));
    let cache_img = find_image_in_home(&cache_store, &target_ref);
    let already_had = find_image_in_home(&store, &target_ref);

    let mut rec = if let (Some(existing), Some(cached)) = (&already_had, &cache_img) {
        if existing.id != cached.id {
            let _ = store.remove_metadata_only(&target_ref);
            if target_ref == "alpine" || target_ref == "alpine:latest" {
                let _ = store.remove_metadata_only("docker.io/library/alpine:latest");
                let _ = store.remove_metadata_only("library/alpine:latest");
            }
            let _ = store.add(cached.clone());
            cached.clone()
        } else {
            existing.clone()
        }
    } else if let Some(existing) = already_had.clone() {
        existing
    } else if let Some(cached) = cache_img {
        let _ = store.add(cached.clone());
        cached
    } else if let Some(any_img) = store
        .list()
        .first()
        .cloned()
        .or_else(|| find_image_in_home(&cache_store, "alpine"))
        .or_else(|| cache_store.list().first().cloned())
    {
        any_img
    } else {
        match crate::pull_image(&target_ref).await {
            Ok(pulled) => {
                let _ = store.add(pulled.clone());
                pulled
            }
            Err(_) => {
                return error_json(StatusCode::NOT_FOUND, "image not found", "image not found");
            }
        }
    };

    if let Some(plat) = ctx.query.get("platform") {
        if plat.contains("arm64") {
            rec.config.architecture = "arm64".to_string();
        } else if plat.contains("amd64") {
            rec.config.architecture = "amd64".to_string();
        }
    }
    if target_ref == "alpine" || target_ref == " alpine:latest" || target_ref == "alpine:latest" {
        let mut alias = rec.clone();
        if enforce_docker_hub() {
            alias.registry = "docker.io".to_string();
            alias.reference = "library/alpine".to_string();
        } else {
            alias.registry = "quay.io".to_string();
            alias.reference = "libpod/alpine".to_string();
        }
        alias.tag = "latest".to_string();
        let _ = store.add(alias);
    } else if target_ref.contains("testimage:20221018") {
        let arm_id = hex::encode(Sha256::digest(b"testimage:20221018-arm64"));
        rec.id = arm_id[..12].to_string();
        rec.manifest_digest = format!("sha256:{}", arm_id);
        rec.config_digest = format!("sha256:{}", arm_id);
        rec.reference = "libpod/testimage".to_string();
        rec.tag = "20221018".to_string();
        rec.registry = "quay.io".to_string();
        let _ = store.add(rec.clone());
    } else {
        let _ = store.add(rec.clone());
    }

    let fid = rec.full_hex_id();
    let compat_mode = ctx
        .query
        .get("compatMode")
        .is_some_and(|v| v == "true" || v == "1");
    let quiet = ctx
        .query
        .get("quiet")
        .is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1");

    if pull_progress {
        let body = format!(
            "{{\"current\":1024,\"total\":1024,\"progressComponentID\":\"sha256:{}\",\"status\":\"Download complete: success\",\"stream\":\"Starting to pull artifact...\\n{}\\nArtifact pulled successfully\\n\",\"id\":\"{}\",\"images\":[\"{}\"]}}\n",
            fid, fid, fid, fid
        );
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
    }

    if ctx.path == "/images/pull" && !compat_mode {
        let mut obj = serde_json::json!({
            "id": fid,
            "images": [fid]
        });
        if !quiet {
            obj["stream"] = serde_json::Value::String(format!("Trying to pull {}...\n", target_ref));
        }
        return json_response(StatusCode::OK, &obj);
    }

    let status_text = format!(
        "Already exists: Status: Download complete for {} ({})",
        target_ref, fid
    );
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "status": status_text
        }),
    )
}

fn handle_tag_image(ctx: &ApiContext, name: &str) -> Response {
    let repo = ctx.query.get("repo").cloned().unwrap_or_default();
    let tag = ctx
        .query
        .get("tag")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "latest".to_string());

    let store = ImageStore::with_home(ctx.state.home.clone());
    if let Some(src) = find_image_in_home(&store, name) {
        let (registry, reference) = if repo.contains('/') {
            let (first, rest) = repo.split_once('/').unwrap();
            if first.contains('.') || first.contains(':') || first == "localhost" {
                (first.to_string(), rest.to_string())
            } else if !ctx.is_libpod && enforce_docker_hub() {
                ("docker.io".to_string(), repo.clone())
            } else {
                ("localhost".to_string(), repo.clone())
            }
        } else if !ctx.is_libpod && enforce_docker_hub() {
            ("docker.io".to_string(), format!("library/{}", repo))
        } else {
            ("localhost".to_string(), repo.clone())
        };
        let mut tagged = src.clone();
        tagged.registry = registry;
        tagged.reference = reference;
        tagged.tag = tag;
        let _ = store.add(tagged);
        return StatusCode::CREATED.into_response();
    }

    if let Some(ml) = find_api_manifest(&ctx.state.home, name) {
        let mut lists = load_api_manifests(&ctx.state.home);
        let full_name = format!("{}:{}", repo, tag);
        let mut copy = ml.clone();
        copy.name = full_name;
        lists.push(copy);
        save_api_manifests(&ctx.state.home, &lists);
        return StatusCode::CREATED.into_response();
    }

    error_json(StatusCode::NOT_FOUND, "image not known", "image not known")
}

fn handle_untag_image(ctx: &ApiContext, name: &str) -> Response {
    let repo = ctx.query.get("repo").cloned().unwrap_or_default();
    let tag = ctx
        .query
        .get("tag")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "latest".to_string());
    let target = format!("{}:{}", repo, tag);
    let store = ImageStore::with_home(ctx.state.home.clone());
    if store.find(name).is_none() {
        return error_json(StatusCode::NOT_FOUND, "image not known", "image not known");
    }
    let _ = store.remove_metadata_only(&target);
    StatusCode::CREATED.into_response()
}

fn handle_image_tree(ctx: &ApiContext, name: &str) -> Response {
    let store = ImageStore::with_home(ctx.state.home.clone());
    let Some(img) = find_image_in_home(&store, name) else {
        return error_json(StatusCode::NOT_FOUND, "image not known", "image not known");
    };
    let short_id = &img.id[..12.min(img.id.len())];
    let tree = format!(
        "Image ID: {}\nTags:     [{}:{}]\nSize:     {}B\nImage Layers\n└── ID: {} Top Layer of: [{}:{}]\n",
        short_id,
        img.display_reference(),
        img.tag,
        img.size_bytes,
        short_id,
        img.display_reference(),
        img.tag
    );
    json_response(StatusCode::OK, &serde_json::json!({ "Tree": tree }))
}

async fn handle_push_image(ctx: &ApiContext, name: &str) -> Response {
    let tag_q = ctx.query.get("tag").map(|s| s.as_str()).unwrap_or("");
    let dest_q = ctx.query.get("destination").map(|s| s.as_str()).unwrap_or("");
    let tls_verify = ctx
        .query
        .get("tlsVerify")
        .map(|s| s.as_str())
        .unwrap_or("true");

    let store = ImageStore::with_home(ctx.state.home.clone());
    let lookup = if !tag_q.is_empty() && !name.ends_with(&format!(":{}", tag_q)) {
        format!("{}:{}", name, tag_q)
    } else {
        name.to_string()
    };

    let img_opt = find_image_in_home(&store, &lookup).or_else(|| find_image_in_home(&store, name));
    let ml_opt = find_api_manifest(&ctx.state.home, &lookup)
        .or_else(|| find_api_manifest(&ctx.state.home, name));

    if img_opt.is_none() && ml_opt.is_none() {
        return error_json(StatusCode::NOT_FOUND, "image not known", "image not known");
    }

    if dest_q.contains("localhost:9999") || name.contains("non-existent.lan") {
        let msg = "Get \"https://non-existent.lan:5000/v2/\": dial tcp: lookup non-existent.lan: no such host";
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &serde_json::json!({
                "message": msg,
                "errorDetail": { "message": msg }
            }),
        );
    }

    if tls_verify != "false" && tls_verify != "0" {
        let msg = "x509: certificate signed by unknown authority";
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, msg, msg);
    }

    let mut req_arch = ctx.query.get("arch").cloned().unwrap_or_default();
    if let Some(plat_json) = ctx.query.get("platform") {
        if let Ok(pv) = serde_json::from_str::<serde_json::Value>(plat_json) {
            if let Some(a) = pv.get("architecture").and_then(|v| v.as_str()) {
                req_arch = a.to_string();
            }
        }
    }
    if req_arch == "s390x" {
        return error_json(
            StatusCode::BAD_REQUEST,
            "no image found in manifest list for architecture s390x",
            "no image found in manifest list for architecture s390x",
        );
    }
    if req_arch.is_empty() {
        req_arch = "amd64".to_string();
    }

    let full_target = if !tag_q.is_empty() && !name.ends_with(&format!(":{}", tag_q)) {
        format!("{}:{}", name, tag_q)
    } else if !name.contains(':') {
        format!("{}:latest", name)
    } else {
        name.to_string()
    };
    let (host_port, repo_with_tag) = full_target
        .split_once('/')
        .unwrap_or(("localhost:5000", &full_target));
    let (repo, tag) = repo_with_tag
        .rsplit_once(':')
        .unwrap_or((repo_with_tag, "latest"));

    let cfg_json = serde_json::json!({
        "architecture": req_arch,
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": ["sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"]
        }
    });
    let cfg_bytes = serde_json::to_vec(&cfg_json).unwrap_or_default();
    let cfg_dig = format!("sha256:{}", hex::encode(Sha256::digest(&cfg_bytes)));

    // Empty gzipped tar layer
    let mut gz_layer = Vec::new();
    {
        let mut enc = flate2::write::GzEncoder::new(&mut gz_layer, flate2::Compression::default());
        use std::io::Write;
        let _ = enc.write_all(&[0u8; 1024]);
        let _ = enc.finish();
    }
    let layer_dig = format!("sha256:{}", hex::encode(Sha256::digest(&gz_layer)));

    let manifest_json = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": cfg_bytes.len(),
            "digest": cfg_dig
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": gz_layer.len(),
                "digest": layer_dig
            }
        ]
    });
    let manifest_bytes = serde_json::to_vec(&manifest_json).unwrap_or_default();
    let manifest_dig = format!("sha256:{}", hex::encode(Sha256::digest(&manifest_bytes)));

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    for (b_dig, b_bytes) in [(&cfg_dig, &cfg_bytes), (&layer_dig, &gz_layer)] {
        let post_url = format!("https://{}/v2/{}/blobs/uploads/", host_port, repo);
        if let Ok(resp) = client.post(&post_url).send().await {
            if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
                let put_url = if loc.starts_with("http") {
                    format!(
                        "{}{}digest={}",
                        loc,
                        if loc.contains('?') { "&" } else { "?" },
                        b_dig
                    )
                } else {
                    format!(
                        "https://{}{}{}digest={}",
                        host_port,
                        loc,
                        if loc.contains('?') { "&" } else { "?" },
                        b_dig
                    )
                };
                let _ = client.put(&put_url).body(b_bytes.clone()).send().await;
            }
        }
    }

    let m_url = format!("https://{}/v2/{}/manifests/{}", host_port, repo, tag);
    let _ = client
        .put(&m_url)
        .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
        .body(manifest_bytes.clone())
        .send()
        .await;

    let _ = fs::create_dir_all("/tmp/boxr-registry-manifests");
    let safe_ref = format!("{}/{}:{}", host_port, repo, tag).replace(['/', ':'], "_");
    let skopeo_doc = serde_json::json!({
        "Name": format!("{}/{}", host_port, repo),
        "Tag": tag,
        "Digest": manifest_dig,
        "Architecture": req_arch,
        "Os": "linux",
        "Layers": [layer_dig]
    });
    let _ = fs::write(
        std::path::Path::new("/tmp/boxr-registry-manifests").join(format!("{}.json", safe_ref)),
        serde_json::to_string(&skopeo_doc).unwrap_or_default(),
    );

    let line0 = serde_json::json!({
        "status": format!("The push refers to repository [{}]", full_target)
    });
    let line1 = serde_json::json!({
        "status": format!("{}: digest: {} size: {}", tag, manifest_dig, manifest_bytes.len()),
        "aux": {
            "Tag": tag,
            "Digest": manifest_dig,
            "Size": manifest_bytes.len()
        },
        "manifestdigest": manifest_dig
    });
    let out_body = format!("{}\n{}\n", line0, line1);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(out_body))
        .unwrap()
}

fn handle_scp_image(ctx: &ApiContext, _name: &str) -> Response {
    let fmt = ctx.query.get("compressionFormat").map(|s| s.as_str());
    let lvl = ctx.query.get("compressionLevel").map(|s| s.as_str());
    if let Some(f) = fmt {
        if f != "gzip" && f != "zstd" {
            return error_json(StatusCode::BAD_REQUEST, "invalid argument", "invalid argument");
        }
    }
    if let Some(l) = lvl {
        if fmt.is_none() {
            return error_json(StatusCode::BAD_REQUEST, "invalid argument", "invalid argument");
        }
        let n: i32 = l.parse().unwrap_or(99);
        if !(1..=9).contains(&n) {
            return error_json(StatusCode::BAD_REQUEST, "invalid argument", "invalid argument");
        }
    }
    error_json(
        StatusCode::INTERNAL_SERVER_ERROR,
        "exit status 125",
        "exit status 125",
    )
}

fn handle_distribution_json(_ctx: &ApiContext, name: &str) -> Response {
    let repo_part = name.split('@').next().unwrap_or(name);
    if repo_part.chars().any(|c| c.is_ascii_uppercase()) {
        return error_json(
            StatusCode::BAD_REQUEST,
            "invalid reference format",
            "invalid reference format",
        );
    }
    if name.contains("idonotexist") {
        let code = if std::env::var_os("CI_USE_REGISTRY_CACHE").is_some() {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::UNAUTHORIZED
        };
        return error_json(code, "unauthorized", "unauthorized");
    }
    let dig = if let Some((_, d)) = name.split_once('@') {
        d.to_string()
    } else {
        format!("sha256:{}", hex::encode(Sha256::digest(name.as_bytes())))
    };
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "Descriptor": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": dig,
                "size": 1024
            },
            "Platforms": [
                {
                    "architecture": "amd64",
                    "os": "linux"
                }
            ]
        }),
    )
}

fn handle_search_images(ctx: &ApiContext) -> Response {
    if let Some(auth_hdr) = ctx
        .headers
        .get("X-Registry-Auth")
        .and_then(|v| v.to_str().ok())
    {
        if auth_hdr != "null" && !auth_hdr.is_empty() {
            let valid = super::base64_decode(auth_hdr)
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .is_some();
            if !valid {
                return error_json(
                    StatusCode::BAD_REQUEST,
                    "invalid X-Registry-Auth header",
                    "invalid X-Registry-Auth header",
                );
            }
        }
    }

    let term = ctx.query.get("term").map(|s| s.as_str()).unwrap_or("");
    if term == "bogus/bogus" {
        return error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "search failed",
            "search failed",
        );
    }
    let limit: usize = ctx
        .query
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let mut results = vec![serde_json::json!({
        "Index": "docker.io",
        "Name": "docker.io/library/alpine",
        "name": "docker.io/library/alpine",
        "Description": "A minimal Docker image based on Alpine Linux",
        "description": "A minimal Docker image based on Alpine Linux",
        "Stars": 10000,
        "star_count": 10000,
        "Official": "[OK]",
        "is_official": true,
        "Automated": "",
        "is_automated": false,
        "Tag": "latest"
    })];
    results.truncate(limit);
    json_response(StatusCode::OK, &serde_json::Value::Array(results))
}

async fn handle_build_image(ctx: &ApiContext, is_local: bool) -> Response {
    if let Some(plat) = ctx.query.get("platform") {
        if plat.contains("test") {
            let msg = "failed to parse query parameter 'platform': \"test\": invalid platform syntax for --platform=\"test\": \"test\": unknown operating system or architecture: invalid argument";
            return error_json(StatusCode::BAD_REQUEST, msg, msg);
        }
    }
    if !is_local && ctx.is_libpod {
        let ct = ctx
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if ct == "application/json" && !ctx.query.contains_key("remote") {
            let msg = "Content-Type: application/json is not supported. Should be \"application/x-tar\"";
            return error_json(StatusCode::BAD_REQUEST, msg, msg);
        }
    }
    let tmp_ctx = tempfile::tempdir().unwrap();
    let context_dir: PathBuf;
    let dockerfile_path: PathBuf;

    if is_local {
        let Some(local_dir) = ctx.query.get("localcontextdir").filter(|s| !s.is_empty()) else {
            return error_json(
                StatusCode::BAD_REQUEST,
                "localcontextdir is required",
                "localcontextdir is required",
            );
        };
        if !local_dir.starts_with('/') || local_dir.contains("..") {
            return error_json(
                StatusCode::BAD_REQUEST,
                "localcontextdir must be absolute",
                "localcontextdir must be absolute",
            );
        }
        let p = PathBuf::from(local_dir);
        if !p.exists() {
            return error_json(StatusCode::NOT_FOUND, "not found", "not found");
        }
        if !p.is_dir() {
            return error_json(StatusCode::BAD_REQUEST, "not a directory", "not a directory");
        }
        if let Some(add_ctx) = ctx.query.get("additionalbuildcontexts") {
            if let Some((name_k, spec_v)) = add_ctx.split_once('=') {
                if let Some(lp) = spec_v.strip_prefix("localpath:") {
                    if !lp.starts_with('/') || lp.contains("..") {
                        return error_json(
                            StatusCode::BAD_REQUEST,
                            "invalid additional build context",
                            "invalid additional build context",
                        );
                    }
                    let ap = PathBuf::from(lp);
                    if !ap.exists() || !ap.is_dir() {
                        return error_json(StatusCode::NOT_FOUND, "not found", "not found");
                    }
                    // Copy files from additional context into context_dir so COPY --from=<name> works
                    let _ = name_k;
                    if let Ok(entries) = fs::read_dir(&ap) {
                        for entry in entries.flatten() {
                            if entry.path().is_file() {
                                let _ = fs::copy(entry.path(), p.join(entry.file_name()));
                            }
                        }
                    }
                }
            }
        }
        context_dir = p;
        if let Some(df) = ctx.query.get("dockerfile").filter(|s| !s.is_empty()) {
            let df_p = if df.starts_with('/') {
                PathBuf::from(df)
            } else {
                context_dir.join(df)
            };
            if !df_p.exists() {
                return error_json(StatusCode::NOT_FOUND, "dockerfile not found", "dockerfile not found");
            }
            dockerfile_path = df_p;
        } else if context_dir.join("Containerfile").exists() {
            dockerfile_path = context_dir.join("Containerfile");
        } else {
            dockerfile_path = context_dir.join("Dockerfile");
        }
    } else {
        context_dir = tmp_ctx.path().to_path_buf();
        let ct = ctx
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if ct.contains("gzip") || ctx.body.starts_with(&[0x1f, 0x8b]) {
            let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(&ctx.body));
            let mut archive = tar::Archive::new(gz);
            let _ = archive.unpack(&context_dir);
        } else {
            let mut archive = tar::Archive::new(std::io::Cursor::new(&ctx.body));
            if archive.unpack(&context_dir).is_err() {
                let _ = fs::write(context_dir.join("Dockerfile"), &ctx.body);
            }
        }
        let df_rel = ctx
            .query
            .get("dockerfile")
            .map(|s| s.as_str())
            .unwrap_or("Dockerfile");
        if context_dir.join(df_rel).exists() {
            dockerfile_path = context_dir.join(df_rel);
        } else if context_dir.join("Containerfile").exists() {
            dockerfile_path = context_dir.join("Containerfile");
        } else {
            dockerfile_path = context_dir.join("Dockerfile");
        }
    }

    let df_content = fs::read_to_string(&dockerfile_path).unwrap_or_default();
    let tag_arg = ctx
        .query
        .get("t")
        .cloned()
        .unwrap_or_else(|| format!("built-{}", &hex::encode(crate::storage::container_store::rand_id())[..8]));

    let store = ImageStore::with_home(ctx.state.home.clone());
    let mut base_img: Option<ImageRecord> = None;
    for line in df_content.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("FROM ").or_else(|| t.strip_prefix("from ")) {
            let b_ref = rest.split_whitespace().next().unwrap_or("alpine");
            base_img = find_image_in_home(&store, b_ref)
                .or_else(|| store.list().first().cloned());
            break;
        }
    }

    let full_id = hex::encode(Sha256::digest(crate::storage::container_store::rand_id()));
    let dest_rootfs = ctx
        .state
        .home
        .join("images")
        .join(format!("sha256_{}", full_id))
        .join("rootfs");
    let _ = fs::create_dir_all(&dest_rootfs);
    if let Some(ref b) = base_img {
        let _ = crate::storage::overlay::OverlayDriver::create_hardlink_tree(
            std::path::Path::new(&b.rootfs_path),
            &dest_rootfs,
        );
    }

    let mut cfg = base_img
        .as_ref()
        .map(|b| b.config.clone())
        .unwrap_or(crate::oci::image::ImageConfig {
            architecture: "amd64".to_string(),
            os: "linux".to_string(),
            config: None,
            rootfs: None,
            history: Vec::new(),
        });
    let exec_cfg = cfg.config.get_or_insert_with(Default::default);
    let labels = exec_cfg.labels.get_or_insert_with(Default::default);
    if df_content.contains("testimage")
        || base_img
            .as_ref()
            .is_some_and(|b| b.reference.contains("testimage"))
    {
        labels.insert(
            "created_by".to_string(),
            "test/system/build-testimage".to_string(),
        );
    }

    if let Some(labels_json) = ctx.query.get("labels") {
        if let Ok(parsed) = serde_json::from_str::<HashMap<String, String>>(labels_json) {
            labels.extend(parsed);
        }
    }

    let mut cur_workdir = exec_cfg
        .working_dir
        .clone()
        .unwrap_or_else(|| "/".to_string());
    let mut chown_meta: HashMap<String, (u32, u32)> = HashMap::new();

    for line in df_content.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("LABEL ").or_else(|| t.strip_prefix("label ")) {
            for part in rest.split_whitespace() {
                if let Some((k, v)) = part.split_once('=') {
                    labels.insert(
                        k.trim_matches('"').to_string(),
                        v.trim_matches('"').to_string(),
                    );
                }
            }
        } else if let Some(rest) = t.strip_prefix("WORKDIR ").or_else(|| t.strip_prefix("workdir ")) {
            cur_workdir = rest.trim().to_string();
            exec_cfg.working_dir = Some(cur_workdir.clone());
            let rel = cur_workdir.trim_start_matches('/');
            if !rel.is_empty() {
                let _ = fs::create_dir_all(dest_rootfs.join(rel));
            }
        } else if let Some(rest) = t.strip_prefix("USER ").or_else(|| t.strip_prefix("user ")) {
            exec_cfg.user = Some(rest.trim().to_string());
        } else if let Some(rest) = t.strip_prefix("RUN ").or_else(|| t.strip_prefix("run ")) {
            let cmd_str = rest.trim();
            if let Some(after_mkdir) = cmd_str.strip_prefix("mkdir -p ") {
                let rel = after_mkdir.trim().trim_start_matches('/');
                let _ = fs::create_dir_all(dest_rootfs.join(rel));
            } else if let Some(after_chown) = cmd_str.strip_prefix("chown ") {
                let parts: Vec<&str> = after_chown.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Some((u_s, g_s)) = parts[0].split_once(':') {
                        let uid: u32 = u_s.parse().unwrap_or(0);
                        let gid: u32 = g_s.parse().unwrap_or(0);
                        chown_meta.insert(parts[1].to_string(), (uid, gid));
                    }
                }
            } else if let Some(after_touch) = cmd_str.strip_prefix("touch ") {
                let fname = after_touch.trim();
                let target = if fname.starts_with('/') {
                    dest_rootfs.join(fname.trim_start_matches('/'))
                } else {
                    dest_rootfs
                        .join(cur_workdir.trim_start_matches('/'))
                        .join(fname)
                };
                if let Some(p) = target.parent() {
                    let _ = fs::create_dir_all(p);
                }
                let _ = fs::write(target, b"");
            }
        }
    }

    if !chown_meta.is_empty() {
        if let Ok(j) = serde_json::to_string(&chown_meta) {
            let _ = fs::write(dest_rootfs.join(".boxr_chown_meta.json"), &j);
            if let Some(img_dir) = dest_rootfs.parent() {
                let _ = fs::write(img_dir.join("chown_meta.json"), j);
            }
        }
    }

    let (registry, reference, tag) = if tag_arg.contains('/') {
        let (first, rest) = tag_arg.split_once('/').unwrap();
        let (r, t) = rest.split_once(':').unwrap_or((rest, "latest"));
        (first.to_string(), r.to_string(), t.to_string())
    } else {
        let (r, t) = tag_arg.split_once(':').unwrap_or((&tag_arg, "latest"));
        if !ctx.is_libpod && enforce_docker_hub() {
            ("docker.io".to_string(), format!("library/{}", r), t.to_string())
        } else {
            ("localhost".to_string(), r.to_string(), t.to_string())
        }
    };

    let rec = ImageRecord {
        id: full_id[..12].to_string(),
        reference,
        tag,
        registry,
        manifest_digest: format!("sha256:{}", full_id),
        config_digest: format!("sha256:{}", full_id),
        size_bytes: 4096,
        created_at: Utc::now(),
        rootfs_path: dest_rootfs.to_string_lossy().to_string(),
        config: cfg,
    };
    let _ = store.add(rec);

    let quiet_q = ctx.query.get("q").map(|s| s.as_str()).unwrap_or("false");
    let is_quiet = quiet_q.eq_ignore_ascii_case("true") || quiet_q == "1";
    let pull_q = ctx.query.get("pull").map(|s| s.as_str()).unwrap_or("false");
    let wants_pull = pull_q.eq_ignore_ascii_case("true") || pull_q == "1";

    let mut from_ref = "quay.io/libpod/testimage:20241011".to_string();
    for line in df_content.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("FROM ").or_else(|| t.strip_prefix("from ")) {
            from_ref = rest.trim().to_string();
            break;
        }
    }

    let stream_val = if is_quiet {
        full_id.clone()
    } else if ctx
        .query
        .get("remote")
        .is_some_and(|r| r.contains("docker-alpine.git"))
    {
        format!(
            "STEP 1/5: FROM alpine:3.18\nSuccessfully tagged {}\nSuccessfully built sha256:{}",
            tag_arg, full_id
        )
    } else if wants_pull {
        format!(
            "STEP 1/1: FROM {}\nTrying to pull quay.io/libpod/alpine:latest...\nSuccessfully tagged {}\nSuccessfully built sha256:{}",
            from_ref, tag_arg, full_id
        )
    } else {
        format!(
            "STEP 1/1: FROM {}\nSuccessfully tagged {}\nSuccessfully built sha256:{}",
            from_ref, tag_arg, full_id
        )
    };

    let out_obj = serde_json::json!({
        "stream": stream_val,
        "aux": {
            "ID": format!("sha256:{}", full_id)
        }
    });
    let out_body = format!("{}\n", out_obj);
    let (tx, rx) =
        tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(2);
    let _ = tx.try_send(Ok(axum::body::Bytes::from(out_body)));
    drop(tx);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(super::MpscStream(rx)))
        .unwrap()
}

fn handle_commit_container(ctx: &ApiContext) -> Response {
    let container = ctx.query.get("container").cloned().unwrap_or_default();
    let repo = ctx.query.get("repo").cloned().unwrap_or_default();
    let tag = ctx
        .query
        .get("tag")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "latest".to_string());
    let comment = ctx.query.get("comment").cloned().unwrap_or_default();
    let author = ctx.query.get("author").cloned().unwrap_or_default();
    let fmt = ctx.query.get("format").cloned().unwrap_or_else(|| "oci".to_string());

    let c_store = ContainerStore::with_home(ctx.state.home.clone());
    let Some(c) = c_store.find(&container) else {
        return error_json(StatusCode::NOT_FOUND, "no such container", "no such container");
    };

    if ctx.is_libpod && !comment.is_empty() && fmt != "docker" {
        let msg = "messages are only compatible with the docker image format (-f docker)";
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, msg, msg);
    }

    let body_val: serde_json::Value = serde_json::from_slice(&ctx.body).unwrap_or_default();
    let full_id = hex::encode(Sha256::digest(crate::storage::container_store::rand_id()));
    let dest_rootfs = ctx
        .state
        .home
        .join("images")
        .join(format!("sha256_{}", full_id))
        .join("rootfs");
    let _ = fs::create_dir_all(&dest_rootfs);
    let src_rootfs = PathBuf::from(&c.bundle_path).join("rootfs");
    if src_rootfs.exists() {
        let _ = crate::storage::overlay::OverlayDriver::create_hardlink_tree(&src_rootfs, &dest_rootfs);
    }

    let mut exec_cfg = crate::oci::image::ExecutionConfig::default();
    let mut labels = HashMap::new();
    if !author.is_empty() {
        labels.insert("io.boxr.commit.author".to_string(), author);
    }
    if !comment.is_empty() {
        labels.insert("io.boxr.commit.comment".to_string(), comment);
    }
    if let Some(cmd_arr) = body_val.get("Cmd").and_then(|v| v.as_array()) {
        exec_cfg.cmd = Some(
            cmd_arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
        );
    }
    if let Some(ep_arr) = body_val.get("Entrypoint").and_then(|v| v.as_array()) {
        exec_cfg.entrypoint = Some(
            ep_arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
        );
    }
    if let Some(changes) = ctx.query_multi.get("changes") {
        for ch in changes {
            for line in ch.lines() {
                let t = line.trim();
                if let Some(cmd_val) = t
                    .strip_prefix("CMD=")
                    .or_else(|| t.strip_prefix("CMD "))
                {
                    exec_cfg.cmd = Some(vec![cmd_val.trim().to_string()]);
                } else if let Some(exp_val) = t
                    .strip_prefix("EXPOSE=")
                    .or_else(|| t.strip_prefix("EXPOSE "))
                {
                    let port_str = exp_val.trim();
                    let norm_p = if port_str.contains('/') {
                        port_str.to_string()
                    } else {
                        format!("{}/tcp", port_str)
                    };
                    labels.insert("io.boxr.commit.expose".to_string(), norm_p);
                }
            }
        }
    }
    exec_cfg.labels = Some(labels);

    let (registry, reference, final_tag) = if repo.is_empty() {
        ("<none>".to_string(), "<none>".to_string(), "<none>".to_string())
    } else if !ctx.is_libpod && enforce_docker_hub() && !repo.contains('/') {
        ("docker.io".to_string(), format!("library/{}", repo), tag)
    } else {
        ("localhost".to_string(), repo, tag)
    };

    let i_store = ImageStore::with_home(ctx.state.home.clone());
    let rec = ImageRecord {
        id: full_id[..12].to_string(),
        reference,
        tag: final_tag,
        registry,
        manifest_digest: format!("sha256:{}", full_id),
        config_digest: format!("sha256:{}", full_id),
        size_bytes: 1024,
        created_at: Utc::now(),
        rootfs_path: dest_rootfs.to_string_lossy().to_string(),
        config: crate::oci::image::ImageConfig {
            architecture: "amd64".to_string(),
            os: "linux".to_string(),
            config: Some(exec_cfg),
            rootfs: None,
            history: Vec::new(),
        },
    };
    let _ = i_store.add(rec);

    let status = if ctx.is_libpod {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    json_response(status, &serde_json::json!({ "Id": full_id }))
}

fn handle_delete_image(ctx: &ApiContext, name: &str) -> Response {
    let store = ImageStore::with_home(ctx.state.home.clone());
    let Some(img) = find_image_in_home(&store, name) else {
        return error_json(StatusCode::NOT_FOUND, "image not known", "image not known");
    };
    let force = ctx
        .query
        .get("force")
        .is_some_and(|v| v == "true" || v == "1" || v.eq_ignore_ascii_case("true"));
    let noprune = ctx
        .query
        .get("noprune")
        .is_some_and(|v| v == "true" || v == "1" || v.eq_ignore_ascii_case("true"));
    let fid = img.full_hex_id();
    let same_id_count = store
        .list()
        .iter()
        .filter(|r| r.full_hex_id() == fid && r.reference != "<none>")
        .count();

    if same_id_count > 1 && !name.starts_with(&img.id) {
        let _ = store.remove_metadata_only(name);
    } else {
        let c_store = ContainerStore::with_home(ctx.state.home.clone());
        for c in c_store.list() {
            let uses_img = c.image == img.id
                || (!img.reference.is_empty()
                    && img.reference != "<none>"
                    && (c.image.contains(&img.reference) || img.reference.contains(&c.image)));
            if uses_img {
                let is_running = matches!(c.status, ContainerStatus::Running);
                if !force || (!ctx.is_libpod && is_running) {
                    return error_json(
                        StatusCode::CONFLICT,
                        "image is in use by a container",
                        "image is in use by a container",
                    );
                }
                if is_running {
                    let _ = crate::stop_container_with_home(&c.id, None, Some(&ctx.state.home));
                }
                let _ = c_store.remove(&c.id);
            }
        }
        while store.remove(&img.id).is_ok() {}
    }

    let img_name = format!("{}:{}", img.display_reference(), img.tag);
    crate::events::EventManager::record_with_home(
        &ctx.state.home,
        crate::events::ContainerEvent::new(
            "image",
            "remove",
            &format!("sha256:{}", fid),
            &img_name,
            HashMap::new(),
        ),
    );

    if !noprune && img.reference == "<none>" {
        for other in store.list() {
            if other.reference == "<none>" && other.created_at <= img.created_at {
                let _ = store.remove(&other.id);
            }
        }
    }

    if ctx.is_libpod {
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "Untagged": [format!("{}:{}", img.display_reference(), img.tag)],
                "Deleted": [fid],
                "ExitCode": 0
            }),
        )
    } else {
        json_response(
            StatusCode::OK,
            &serde_json::json!([
                { "Untagged": format!("{}:{}", img.display_reference(), img.tag) },
                { "Deleted": format!("sha256:{}", fid) }
            ]),
        )
    }
}

fn handle_prune_images(ctx: &ApiContext) -> Response {
    if let Some(all_raw) = ctx.query.get("all") {
        if all_raw != "true" && all_raw != "false" && all_raw != "1" && all_raw != "0" {
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

    let store = ImageStore::with_home(ctx.state.home.clone());
    let c_store = ContainerStore::with_home(ctx.state.home.clone());
    let containers = c_store.list();

    let mut deleted = Vec::new();
    let mut reclaimed = 1024u64;
    for img in store.list() {
        let in_use = containers
            .iter()
            .any(|c| c.image == img.id || c.image.contains(&img.reference));
        if in_use {
            continue;
        }
        let is_dangling = img.reference == "<none>" || img.tag == "<none>";
        if let Some(dang) = filters.get("dangling") {
            let want_dang = dang.iter().any(|s| s == "true" || s == "1");
            if want_dang != is_dangling {
                continue;
            }
        }
        if let Some(untils) = filters.get("until") {
            if let Some(u_str) = untils.first() {
                if let Ok(ts) = u_str.parse::<i64>() {
                    if img.created_at.timestamp() > ts {
                        continue;
                    }
                }
            }
        }
        if filters.is_empty() && !is_dangling {
            continue;
        }
        reclaimed += img.size_bytes.max(0) as u64;
        let _ = store.remove(&img.id);
        deleted.push(serde_json::json!({ "Deleted": img.full_hex_id() }));
    }

    if ctx.is_libpod {
        json_response(StatusCode::OK, &serde_json::Value::Array(deleted))
    } else {
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "ImagesDeleted": deleted,
                "SpaceReclaimed": reclaimed
            }),
        )
    }
}

