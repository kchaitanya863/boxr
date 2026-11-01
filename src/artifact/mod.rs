//! OCI Artifact store management (Podman `artifact` parity).

use crate::oci::distribution::RegistryClient;
use crate::oci::reference::ImageReference;
use crate::storage::boxr_home;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub fn normalize_artifact_name(raw: &str) -> (String, String, String) {
    let clean = raw
        .trim()
        .strip_prefix("docker://")
        .unwrap_or_else(|| raw.trim());
    let last_seg = clean.rsplit('/').next().unwrap_or(clean);
    let (repo_raw, tag_raw) = if last_seg.contains(':') {
        clean.rsplit_once(':').unwrap_or((clean, "latest"))
    } else {
        (clean, "latest")
    };
    let repo = if !repo_raw.contains('/') {
        format!("localhost/{}", repo_raw)
    } else {
        repo_raw.to_string()
    };
    let tag = if tag_raw.is_empty() {
        "latest".to_string()
    } else {
        tag_raw.to_string()
    };
    let canonical = format!("{}:{}", repo, tag);
    (canonical, repo, tag)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactLayer {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    #[serde(default)]
    pub file_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub name: String,
    pub digest: String,
    pub media_type: String,
    #[serde(default)]
    pub artifact_type: String,
    pub size_bytes: u64,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub created_rfc3339: String,
    pub file_path: String,
    #[serde(default)]
    pub layers: Vec<ArtifactLayer>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ArtifactIndex {
    artifacts: Vec<ArtifactRecord>,
}

pub struct ArtifactStore {
    index_file: PathBuf,
    artifacts_dir: PathBuf,
}

impl ArtifactStore {
    pub fn new() -> Self {
        Self::with_home(boxr_home())
    }

    pub fn with_home(home: PathBuf) -> Self {
        let artifacts_dir = home.join("artifacts");
        let _ = fs::create_dir_all(&artifacts_dir);
        Self {
            index_file: home.join("artifacts.json"),
            artifacts_dir,
        }
    }

    fn load(&self) -> ArtifactIndex {
        if let Ok(content) = fs::read_to_string(&self.index_file) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            ArtifactIndex::default()
        }
    }

    fn save(&self, data: &ArtifactIndex) -> Result<()> {
        let content = serde_json::to_string_pretty(data)?;
        let rand_suffix = hex::encode(crate::storage::container_store::rand_id());
        let temp_file = self
            .index_file
            .with_extension(format!("tmp.{}", rand_suffix));
        fs::write(&temp_file, content)?;
        fs::rename(&temp_file, &self.index_file)?;
        Ok(())
    }

    pub fn list(&self) -> Vec<ArtifactRecord> {
        self.load().artifacts
    }

    pub fn find(&self, query: &str) -> Option<ArtifactRecord> {
        let q = query.trim();
        if q.is_empty() {
            return None;
        }
        let (q_canon, q_repo, _) = normalize_artifact_name(q);
        self.load().artifacts.into_iter().find(|a| {
            if a.name == q || a.name == q_canon || a.name == q_repo {
                return true;
            }
            let (a_canon, _, _) = normalize_artifact_name(&a.name);
            if a_canon == q_canon {
                return true;
            }
            if a.digest == q || a.digest.starts_with(q) {
                return true;
            }
            let hex = a.digest.strip_prefix("sha256:").unwrap_or(&a.digest);
            hex == q || (q.len() >= 4 && hex.starts_with(q))
        })
    }

    pub fn add(&self, name: &str, file: &Path, media_type: &str) -> Result<ArtifactRecord> {
        self.add_with_options(name, file, media_type, false, true)
    }

    pub fn add_with_options(
        &self,
        name: &str,
        file: &Path,
        media_type: &str,
        append: bool,
        replace: bool,
    ) -> Result<ArtifactRecord> {
        if append && replace {
            crate::cli::usage_errors::exit_usage_error(
                "--append and --replace options cannot be used together",
            );
        }
        if !file.exists() {
            return Err(anyhow!(
                "Artifact source file '{}' not found",
                file.display()
            ));
        }

        let content = fs::read(file)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let layer_digest = format!("sha256:{}", hex::encode(hasher.finalize()));

        let target_file = self.artifacts_dir.join(&layer_digest.replace(':', "_"));
        fs::write(&target_file, &content)?;

        let mut layer_annotations = BTreeMap::new();
        if let Some(fname) = file.file_name().map(|n| n.to_string_lossy().to_string()) {
            if !fname.is_empty() {
                layer_annotations.insert("org.opencontainers.image.title".to_string(), fname);
            }
        }

        let new_layer = ArtifactLayer {
            media_type: media_type.to_string(),
            digest: layer_digest.clone(),
            size: content.len() as u64,
            annotations: layer_annotations,
            file_path: target_file.to_string_lossy().to_string(),
        };

        let mut data = self.load();
        let existing = data.artifacts.iter().find(|a| a.name == name).cloned();

        if let Some(ref ex) = existing {
            if !append && !replace {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "{}: artifact already exists",
                    name
                ));
            }
            if append {
                let mut updated = ex.clone();
                if updated.layers.is_empty() {
                    updated.layers.push(ArtifactLayer {
                        media_type: updated.media_type.clone(),
                        digest: updated.digest.clone(),
                        size: updated.size_bytes,
                        annotations: BTreeMap::new(),
                        file_path: updated.file_path.clone(),
                    });
                }
                updated.layers.push(new_layer);
                updated.size_bytes += content.len() as u64;
                let mut m_hasher = Sha256::new();
                for l in &updated.layers {
                    m_hasher.update(l.digest.as_bytes());
                }
                updated.digest = format!("sha256:{}", hex::encode(m_hasher.finalize()));
                data.artifacts.retain(|a| a.name != name);
                data.artifacts.push(updated.clone());
                self.save(&data)?;
                return Ok(updated);
            }
        }

        data.artifacts.retain(|a| a.name != name);
        let now = Utc::now();
        let created_rfc3339 = now.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);

        let record = ArtifactRecord {
            name: name.to_string(),
            digest: layer_digest,
            media_type: media_type.to_string(),
            artifact_type: String::new(),
            size_bytes: content.len() as u64,
            created_at: now,
            created_rfc3339,
            file_path: target_file.to_string_lossy().to_string(),
            layers: vec![new_layer],
        };

        data.artifacts.push(record.clone());
        self.save(&data)?;
        Ok(record)
    }

    pub fn add_cli(
        &self,
        raw_name: &str,
        files: &[PathBuf],
        artifact_type: Option<&str>,
        file_type: Option<&str>,
        annotations: &[String],
        append: bool,
        replace: bool,
    ) -> Result<ArtifactRecord> {
        if append && replace {
            crate::cli::usage_errors::exit_usage_error(
                "--append and --replace options cannot be used together",
            );
        }
        if append && artifact_type.is_some() {
            crate::cli::usage_errors::exit_usage_error(
                "append option is not compatible with type option",
            );
        }

        let mut base_annotations = BTreeMap::new();
        for ann in annotations {
            if let Some((k, v)) = ann.split_once('=') {
                base_annotations.insert(k.to_string(), v.to_string());
            } else {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "invalid annotation {:?}: must be in key=value format",
                    ann
                ));
            }
        }
        let has_explicit_title = base_annotations.contains_key("org.opencontainers.image.title");
        if has_explicit_title && files.len() > 1 {
            crate::cli::usage_errors::exit_usage_error(
                "duplicate layers org.opencontainers.image.title labels within an artifact not allowed",
            );
        }

        let (canon_name, _, _) = normalize_artifact_name(raw_name);
        let mut data = self.load();
        let existing = data
            .artifacts
            .iter()
            .find(|a| normalize_artifact_name(&a.name).0 == canon_name)
            .cloned();

        if existing.is_some() && !append && !replace {
            crate::cli::usage_errors::exit_usage_error(format!(
                "{}: artifact already exists",
                canon_name
            ));
        }

        let mut layers_so_far: Vec<ArtifactLayer> = if append {
            if let Some(ref ex) = existing {
                if ex.layers.is_empty() {
                    vec![ArtifactLayer {
                        media_type: ex.media_type.clone(),
                        digest: ex.digest.clone(),
                        size: ex.size_bytes,
                        annotations: BTreeMap::new(),
                        file_path: ex.file_path.clone(),
                    }]
                } else {
                    ex.layers.clone()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let layer_media_type = file_type.unwrap_or("application/octet-stream").to_string();

        for file in files {
            if !file.exists() {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "open {}: no such file or directory",
                    file.display()
                ));
            }
            let mut layer_annotations = base_annotations.clone();
            let file_basename = file
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if !has_explicit_title && !file_basename.is_empty() {
                layer_annotations.insert(
                    "org.opencontainers.image.title".to_string(),
                    file_basename.clone(),
                );
            }

            if let Some(title_val) = layer_annotations.get("org.opencontainers.image.title") {
                if layers_so_far
                    .iter()
                    .any(|l| l.annotations.get("org.opencontainers.image.title") == Some(title_val))
                {
                    if has_explicit_title {
                        crate::cli::usage_errors::exit_usage_error(
                            "duplicate layers org.opencontainers.image.title labels within an artifact not allowed",
                        );
                    } else {
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "{}: file already exists in artifact",
                            title_val
                        ));
                    }
                }
            }

            let content = fs::read(file)?;
            let layer_digest = format!("sha256:{}", hex::encode(Sha256::digest(&content)));
            let target_file = self.artifacts_dir.join(layer_digest.replace(':', "_"));
            fs::write(&target_file, &content)?;

            layers_so_far.push(ArtifactLayer {
                media_type: layer_media_type.clone(),
                digest: layer_digest,
                size: content.len() as u64,
                annotations: layer_annotations,
                file_path: target_file.to_string_lossy().to_string(),
            });
        }

        let total_size: u64 = layers_so_far.iter().map(|l| l.size).sum();
        let (created_at, created_rfc3339, final_artifact_type) = if append {
            if let Some(ref ex) = existing {
                (
                    ex.created_at,
                    ex.created_rfc3339.clone(),
                    ex.artifact_type.clone(),
                )
            } else {
                let now = Utc::now();
                (
                    now,
                    now.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                    artifact_type.unwrap_or("").to_string(),
                )
            }
        } else {
            let now = Utc::now();
            (
                now,
                now.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                artifact_type.unwrap_or("").to_string(),
            )
        };

        let mut m_hasher = Sha256::new();
        for l in &layers_so_far {
            m_hasher.update(l.digest.as_bytes());
            for (k, v) in &l.annotations {
                m_hasher.update(k.as_bytes());
                m_hasher.update(v.as_bytes());
            }
        }
        m_hasher.update(final_artifact_type.as_bytes());
        m_hasher.update(created_rfc3339.as_bytes());
        let manifest_digest = format!("sha256:{}", hex::encode(m_hasher.finalize()));

        let first_file_path = layers_so_far
            .first()
            .map(|l| l.file_path.clone())
            .unwrap_or_default();

        let record = ArtifactRecord {
            name: canon_name.clone(),
            digest: manifest_digest,
            media_type: layer_media_type,
            artifact_type: final_artifact_type,
            size_bytes: total_size,
            created_at,
            created_rfc3339,
            file_path: first_file_path,
            layers: layers_so_far,
        };

        data.artifacts
            .retain(|a| normalize_artifact_name(&a.name).0 != canon_name);
        data.artifacts.push(record.clone());
        self.save(&data)?;
        Ok(record)
    }

    pub fn remove_all(&self) -> Result<()> {
        let data = self.load();
        for a in &data.artifacts {
            let _ = fs::remove_file(&a.file_path);
        }
        self.save(&ArtifactIndex::default())?;
        Ok(())
    }

    pub fn extract(&self, query: &str, dest: &Path) -> Result<PathBuf> {
        let artifact = self
            .find(query)
            .ok_or_else(|| anyhow!("Artifact '{}' not found", query))?;

        let src = PathBuf::from(&artifact.file_path);
        if !src.exists() {
            return Err(anyhow!("Artifact file data missing on disk"));
        }

        fs::create_dir_all(dest)?;
        let target = dest.join(&artifact.name);
        fs::copy(&src, &target)?;
        Ok(target)
    }

    pub fn extract_cli(
        &self,
        query: &str,
        dest: &Path,
        filter_digest: Option<&str>,
        filter_title: Option<&str>,
    ) -> Result<()> {
        let Some(artifact) = self.find(query) else {
            crate::cli::usage_errors::exit_usage_error(format!(
                "{}: artifact does not exist",
                query
            ));
        };

        let all_layers = if artifact.layers.is_empty() {
            vec![ArtifactLayer {
                media_type: artifact.media_type.clone(),
                digest: artifact.digest.clone(),
                size: artifact.size_bytes,
                annotations: BTreeMap::new(),
                file_path: artifact.file_path.clone(),
            }]
        } else {
            artifact.layers.clone()
        };

        let selected: Vec<ArtifactLayer> = if let Some(d) = filter_digest {
            let v: Vec<_> = all_layers
                .into_iter()
                .filter(|l| l.digest == d || l.digest.strip_prefix("sha256:") == Some(d))
                .collect();
            if v.is_empty() {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "no blob with the digest {:?}",
                    d
                ));
            }
            v
        } else if let Some(t) = filter_title {
            let v: Vec<_> = all_layers
                .into_iter()
                .filter(|l| {
                    l.annotations
                        .get("org.opencontainers.image.title")
                        .map(String::as_str)
                        == Some(t)
                })
                .collect();
            if v.is_empty() {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "no blob with the title {:?}",
                    t
                ));
            }
            v
        } else {
            all_layers
        };

        if dest.is_dir() {
            for l in &selected {
                let filename = if filter_digest.is_some() {
                    l.digest.replace(':', "-")
                } else if let Some(t) = l
                    .annotations
                    .get("org.opencontainers.image.title")
                    .filter(|s| !s.is_empty())
                {
                    if t.contains('/') {
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "invalid name: {:?} cannot contain /",
                            t
                        ));
                    }
                    t.clone()
                } else {
                    l.digest.replace(':', "-")
                };
                let src_path = self.layer_blob_path(l);
                fs::copy(&src_path, dest.join(filename))?;
            }
        } else if selected.len() == 1 {
            if let Some(parent) = dest.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = fs::create_dir_all(parent);
                }
            }
            let src_path = self.layer_blob_path(&selected[0]);
            fs::copy(&src_path, dest)?;
        } else {
            fs::create_dir_all(dest)?;
            for l in &selected {
                let filename = if filter_digest.is_some() {
                    l.digest.replace(':', "-")
                } else if let Some(t) = l
                    .annotations
                    .get("org.opencontainers.image.title")
                    .filter(|s| !s.is_empty())
                {
                    if t.contains('/') {
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "invalid name: {:?} cannot contain /",
                            t
                        ));
                    }
                    t.clone()
                } else {
                    l.digest.replace(':', "-")
                };
                let src_path = self.layer_blob_path(l);
                fs::copy(&src_path, dest.join(filename))?;
            }
        }
        Ok(())
    }

    pub fn layer_blob_path(&self, layer: &ArtifactLayer) -> PathBuf {
        let p = PathBuf::from(&layer.file_path);
        if p.exists() {
            return p;
        }
        self.artifacts_dir.join(layer.digest.replace(':', "_"))
    }

    pub fn remove(&self, query: &str) -> Result<ArtifactRecord> {
        let mut data = self.load();
        let q = query.trim();
        let (q_canon, q_repo, _) = normalize_artifact_name(q);
        let pos = data
            .artifacts
            .iter()
            .position(|a| {
                if a.name == q || a.name == q_canon || a.name == q_repo {
                    return true;
                }
                let (a_canon, _, _) = normalize_artifact_name(&a.name);
                if a_canon == q_canon {
                    return true;
                }
                if a.digest == q || a.digest.starts_with(q) {
                    return true;
                }
                let hex = a.digest.strip_prefix("sha256:").unwrap_or(&a.digest);
                hex == q || (q.len() >= 4 && hex.starts_with(q))
            })
            .ok_or_else(|| anyhow!("{}: artifact does not exist", query))?;

        let removed = data.artifacts.remove(pos);
        self.save(&data)?;
        Ok(removed)
    }

    pub async fn push_cli(&self, query: &str, dest: Option<&str>) -> Result<()> {
        let Some(art) = self.find(query) else {
            crate::cli::usage_errors::exit_usage_error(format!(
                "{}: artifact does not exist",
                query
            ));
        };
        let target_str = dest.unwrap_or(&art.name);
        let reference = ImageReference::parse(target_str)?;

        let empty_cfg = b"{}";
        let empty_cfg_digest = format!("sha256:{}", hex::encode(Sha256::digest(empty_cfg)));

        let mut client = RegistryClient::for_registry(&reference.registry);
        if let Err(e) = client.authenticate_push(&reference).await {
            crate::cli::usage_errors::exit_usage_error(format!("{}", e));
        }
        if let Err(e) = client
            .upload_blob(&reference, &empty_cfg_digest, empty_cfg)
            .await
        {
            crate::cli::usage_errors::exit_usage_error(format!("{}", e));
        }

        let mut manifest_layers = Vec::new();
        for l in &art.layers {
            let blob_path = self.layer_blob_path(l);
            let bytes = fs::read(&blob_path)?;
            if let Err(e) = client.upload_blob(&reference, &l.digest, &bytes).await {
                crate::cli::usage_errors::exit_usage_error(format!("{}", e));
            }
            let mut l_obj = serde_json::json!({
                "mediaType": l.media_type,
                "digest": l.digest,
                "size": l.size,
            });
            if !l.annotations.is_empty() {
                l_obj["annotations"] = serde_json::to_value(&l.annotations)?;
            }
            manifest_layers.push(l_obj);
        }

        let created_str = if !art.created_rfc3339.is_empty() {
            art.created_rfc3339.clone()
        } else {
            art.created_at
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
        };
        let mut manifest_doc = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": empty_cfg_digest,
                "size": 2
            },
            "layers": manifest_layers,
            "annotations": {
                "org.opencontainers.image.created": created_str
            }
        });
        if !art.artifact_type.is_empty() {
            manifest_doc["artifactType"] = serde_json::Value::String(art.artifact_type.clone());
        }
        let manifest_bytes = serde_json::to_vec_pretty(&manifest_doc)?;
        if let Err(e) = client
            .put_raw_manifest(
                &reference,
                "application/vnd.oci.image.manifest.v1+json",
                manifest_bytes,
            )
            .await
        {
            crate::cli::usage_errors::exit_usage_error(format!("{}", e));
        }
        Ok(())
    }

    pub async fn pull_cli(
        &self,
        raw_ref: &str,
        retry: u32,
        retry_delay: &str,
    ) -> Result<ArtifactRecord> {
        let (canon_name, _, _) = normalize_artifact_name(raw_ref);
        let reference = ImageReference::parse(raw_ref)?;

        let delay_dur = parse_retry_delay_duration(retry_delay);
        let max_attempts = retry.max(1);
        let mut last_err = String::new();

        for attempt in 1..=max_attempts {
            let mut client = RegistryClient::for_registry(&reference.registry);
            match client.fetch_raw_manifest(&reference).await {
                Ok((manifest_doc, manifest_digest, _)) => {
                    let mut layers = Vec::new();
                    let mut total_size = 0u64;
                    if let Some(arr) = manifest_doc.get("layers").and_then(|v| v.as_array()) {
                        for item in arr {
                            let media_type = item
                                .get("mediaType")
                                .and_then(|v| v.as_str())
                                .unwrap_or("application/octet-stream")
                                .to_string();
                            let digest = item
                                .get("digest")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let blob_bytes = client.download_raw_blob(&reference, &digest).await?;
                            let target_file = self.artifacts_dir.join(digest.replace(':', "_"));
                            fs::write(&target_file, &blob_bytes)?;
                            let size = blob_bytes.len() as u64;
                            total_size += size;
                            let mut annotations = BTreeMap::new();
                            if let Some(ann_obj) =
                                item.get("annotations").and_then(|v| v.as_object())
                            {
                                for (k, v) in ann_obj {
                                    if let Some(vs) = v.as_str() {
                                        annotations.insert(k.clone(), vs.to_string());
                                    }
                                }
                            }
                            layers.push(ArtifactLayer {
                                media_type,
                                digest,
                                size,
                                annotations,
                                file_path: target_file.to_string_lossy().to_string(),
                            });
                        }
                    }
                    let artifact_type = manifest_doc
                        .get("artifactType")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let created_rfc3339 = manifest_doc
                        .get("annotations")
                        .and_then(|a| a.get("org.opencontainers.image.created"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| {
                            Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
                        });
                    let first_path = layers
                        .first()
                        .map(|l| l.file_path.clone())
                        .unwrap_or_default();
                    let first_media = layers
                        .first()
                        .map(|l| l.media_type.clone())
                        .unwrap_or_else(|| "application/octet-stream".to_string());

                    let record = ArtifactRecord {
                        name: canon_name.clone(),
                        digest: manifest_digest,
                        media_type: first_media,
                        artifact_type,
                        size_bytes: total_size,
                        created_at: Utc::now(),
                        created_rfc3339,
                        file_path: first_path,
                        layers,
                    };
                    let mut data = self.load();
                    data.artifacts
                        .retain(|a| normalize_artifact_name(&a.name).0 != canon_name);
                    data.artifacts.push(record.clone());
                    self.save(&data)?;
                    return Ok(record);
                }
                Err(e) => {
                    last_err = format!("{}", e);
                    if retry > 0 {
                        eprintln!(
                            "Failed, retrying in {} ... ({}/{})",
                            retry_delay, attempt, max_attempts
                        );
                        tokio::time::sleep(delay_dur).await;
                    }
                }
            }
        }

        if last_err.to_lowercase().contains("connection refused")
            || last_err.contains("tcp connect error")
        {
            crate::cli::usage_errors::exit_usage_error(format!(
                "initializing source docker://{}: connect: connection refused",
                canon_name
            ));
        }
        crate::cli::usage_errors::exit_usage_error(last_err);
    }

    pub fn mount_artifact_to_rootfs(
        &self,
        spec: &str,
        rootfs_dir: &Path,
        validate_only: bool,
    ) -> Result<()> {
        let mut src = String::new();
        let mut dst = String::new();
        let mut filter_title: Option<String> = None;
        let mut filter_digest: Option<String> = None;
        let mut custom_name: Option<String> = None;

        for part in spec.split(',') {
            let part = part.trim();
            if let Some((k, v)) = part.split_once('=') {
                match k.trim() {
                    "type" => {}
                    "src" | "source" => src = v.trim().to_string(),
                    "dst" | "destination" | "target" => dst = v.trim().to_string(),
                    "title" => filter_title = Some(v.trim().to_string()),
                    "digest" => filter_digest = Some(v.trim().to_string()),
                    "name" => custom_name = Some(v.trim().to_string()),
                    _ => {}
                }
            }
        }

        let Some(art) = self.find(&src) else {
            let (canon, _, _) = normalize_artifact_name(&src);
            crate::cli::usage_errors::exit_usage_error(format!(
                "{}: artifact does not exist",
                canon
            ));
        };

        if validate_only {
            return Ok(());
        }

        let all_layers = if art.layers.is_empty() {
            vec![ArtifactLayer {
                media_type: art.media_type.clone(),
                digest: art.digest.clone(),
                size: art.size_bytes,
                annotations: BTreeMap::new(),
                file_path: art.file_path.clone(),
            }]
        } else {
            art.layers.clone()
        };

        let is_multi_artifact = all_layers.len() > 1;
        let selected: Vec<ArtifactLayer> = if let Some(ref d) = filter_digest {
            all_layers
                .into_iter()
                .filter(|l| &l.digest == d || l.digest.strip_prefix("sha256:") == Some(d.as_str()))
                .collect()
        } else if let Some(ref t) = filter_title {
            if is_multi_artifact {
                all_layers
                    .into_iter()
                    .filter(|l| {
                        l.annotations
                            .get("org.opencontainers.image.title")
                            .map(String::as_str)
                            == Some(t.as_str())
                    })
                    .collect()
            } else {
                all_layers
            }
        } else {
            all_layers
        };

        let rel_dst = dst.trim_start_matches('/');
        let rootfs_dst = rootfs_dir.join(rel_dst);

        if selected.len() > 1 {
            fs::create_dir_all(&rootfs_dst)?;
            for (i, l) in selected.iter().enumerate() {
                let filename = if let Some(ref cname) = custom_name {
                    format!("{}-{}", cname, i)
                } else if let Some(t) = l
                    .annotations
                    .get("org.opencontainers.image.title")
                    .filter(|s| !s.is_empty())
                {
                    t.clone()
                } else {
                    l.digest.replace(':', "-")
                };
                let blob_path = self.layer_blob_path(l);
                fs::copy(&blob_path, rootfs_dst.join(filename))?;
            }
        } else if let Some(l) = selected.first() {
            let blob_path = self.layer_blob_path(l);
            if rootfs_dst.is_dir() {
                let filename = if let Some(ref cname) = custom_name {
                    cname.clone()
                } else if is_multi_artifact && filter_digest.is_some() {
                    l.digest.replace(':', "-")
                } else if let Some(ref ftitle) = filter_title {
                    ftitle.clone()
                } else if let Some(t) = l
                    .annotations
                    .get("org.opencontainers.image.title")
                    .filter(|s| !s.is_empty())
                {
                    t.clone()
                } else {
                    l.digest.replace(':', "-")
                };
                fs::copy(&blob_path, rootfs_dst.join(filename))?;
            } else {
                if let Some(parent) = rootfs_dst.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if rootfs_dst.exists() {
                    let _ = fs::remove_file(&rootfs_dst);
                }
                fs::copy(&blob_path, &rootfs_dst)?;
            }
        }
        Ok(())
    }
}

fn parse_retry_delay_duration(s: &str) -> std::time::Duration {
    let trimmed = s.trim();
    if let Some(ms) = trimmed.strip_suffix("ms") {
        if let Ok(v) = ms.trim().parse::<u64>() {
            return std::time::Duration::from_millis(v);
        }
    }
    if let Some(sec) = trimmed.strip_suffix('s') {
        if let Ok(v) = sec.trim().parse::<u64>() {
            return std::time::Duration::from_secs(v);
        }
    }
    std::time::Duration::from_millis(100)
}
