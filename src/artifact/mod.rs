//! OCI Artifact store management (Podman `artifact` parity).

use crate::storage::boxr_home;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactLayer {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    pub file_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub name: String,
    pub digest: String,
    pub media_type: String,
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
        self.load()
            .artifacts
            .into_iter()
            .find(|a| a.name == q || a.digest == q || a.digest.starts_with(q))
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

        let new_layer = ArtifactLayer {
            media_type: media_type.to_string(),
            digest: layer_digest.clone(),
            size: content.len() as u64,
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

    pub fn remove(&self, query: &str) -> Result<ArtifactRecord> {
        let mut data = self.load();
        let pos = data
            .artifacts
            .iter()
            .position(|a| a.name == query || a.digest == query || a.digest.starts_with(query))
            .ok_or_else(|| anyhow!("Artifact '{}' not found", query))?;

        let removed = data.artifacts.remove(pos);
        let _ = fs::remove_file(&removed.file_path);
        self.save(&data)?;
        Ok(removed)
    }
}
