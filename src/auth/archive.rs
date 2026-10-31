use crate::oci::reference::ImageReference;
use crate::storage::{ImageRecord, ImageStore};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tar::{Archive, Builder, Header};

#[derive(Debug, Serialize, Deserialize)]
pub struct TarManifestItem {
    #[serde(rename = "Config")]
    pub config: String,
    #[serde(rename = "RepoTags")]
    #[serde(default)]
    pub repo_tags: Vec<String>,
    #[serde(rename = "Layers")]
    pub layers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BoxrImageMeta {
    pub id: String,
    pub reference: String,
    pub tag: String,
    pub registry: String,
    pub manifest_digest: String,
    pub config_digest: String,
    pub size_bytes: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OciLayout {
    #[serde(rename = "imageLayoutVersion")]
    pub image_layout_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OciIndexDescriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default)]
    pub annotations: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OciIndex {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub manifests: Vec<OciIndexDescriptor>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OciManifestConfig {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OciManifestLayer {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OciManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "mediaType", default)]
    pub media_type: String,
    pub config: OciManifestConfig,
    pub layers: Vec<OciManifestLayer>,
}

pub struct ArchiveManager;

impl ArchiveManager {
    pub fn append_dir_resilient(
        builder: &mut Builder<File>,
        base: &Path,
        rel: &Path,
    ) -> Result<()> {
        let current = if rel.as_os_str().is_empty() {
            base.to_path_buf()
        } else {
            base.join(rel)
        };
        let entries = match fs::read_dir(&current) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = entry.file_name();
            let entry_rel = if rel.as_os_str().is_empty() {
                PathBuf::from(file_name)
            } else {
                rel.join(file_name)
            };
            let ft = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_dir() {
                let _ = builder.append_dir(&entry_rel, &path);
                let _ = Self::append_dir_resilient(builder, base, &entry_rel);
            } else if ft.is_symlink() {
                if let Ok(target) = fs::read_link(&path) {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(tar::EntryType::Symlink);
                    header.set_size(0);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        if let Ok(meta) = fs::symlink_metadata(&path) {
                            header.set_mode(meta.mode());
                            header.set_uid(meta.uid() as u64);
                            header.set_gid(meta.gid() as u64);
                            header.set_mtime(meta.mtime() as u64);
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        header.set_mode(0o777);
                    }
                    header.set_cksum();
                    let _ = builder.append_link(&mut header, &entry_rel, &target);
                }
            } else {
                let _ = builder.append_path_with_name(&path, &entry_rel);
            }
        }
        Ok(())
    }

    pub fn save(
        images: &[String],
        output_path: Option<&Path>,
        quiet: bool,
        _uncompressed: bool,
        format: Option<&str>,
        home: &Path,
    ) -> Result<()> {
        let store = ImageStore::with_home(home.to_path_buf());
        let mut records = Vec::new();
        let mut by_id = Vec::new();

        for q in images {
            let img = store
                .find(q)
                .ok_or_else(|| anyhow!("Image '{}' not found locally", q))?;
            let is_id = !q.contains(':') && (q == &img.id || img.id.starts_with(q));
            by_id.push(is_id);
            records.push(img);
        }

        let is_oci = format == Some("oci-archive");

        if let Some(path) = output_path {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let file = File::create(path)?;
            let mut builder = Builder::new(file);
            if is_oci {
                Self::pack_oci_archive(&records, &mut builder)?;
            } else {
                Self::pack_docker_archive(&records, &by_id, &mut builder)?;
            }
            if let Some(first) = records.first() {
                crate::events::EventManager::record(crate::events::ContainerEvent::new(
                    "image",
                    "save",
                    &format!("sha256:{}", first.id),
                    &path.to_string_lossy(),
                    std::collections::HashMap::new(),
                ));
            }
            if !quiet {
                for rec in &records {
                    println!("Exported image {} to {:?}", rec.display_reference(), path);
                }
            }
        } else {
            let stdout = std::io::stdout();
            let mut builder = Builder::new(stdout.lock());
            if is_oci {
                Self::pack_oci_archive(&records, &mut builder)?;
            } else {
                Self::pack_docker_archive(&records, &by_id, &mut builder)?;
            }
        }
        Ok(())
    }

    fn pack_docker_archive<W: Write>(
        records: &[ImageRecord],
        by_id: &[bool],
        builder: &mut Builder<W>,
    ) -> Result<()> {
        let mut manifest_items = Vec::new();

        for (idx, image) in records.iter().enumerate() {
            let saved_by_id = by_id.get(idx).copied().unwrap_or(false);
            let config_filename = format!("{}.json", &image.config_digest.replace(':', "_"));
            let config_bytes = serde_json::to_vec_pretty(&image.config)?;

            let mut config_header = Header::new_gnu();
            config_header.set_size(config_bytes.len() as u64);
            config_header.set_mode(0o644);
            config_header.set_cksum();
            builder.append_data(&mut config_header, &config_filename, &config_bytes[..])?;

            let layer_filename = format!("{}_layer.tar", idx);
            let temp_layer = tempfile::NamedTempFile::new()?;
            {
                let mut layer_builder = Builder::new(File::create(temp_layer.path())?);
                let rootfs_dir = Path::new(&image.rootfs_path);
                if rootfs_dir.exists() {
                    Self::append_dir_resilient(&mut layer_builder, rootfs_dir, Path::new(""))?;
                }
                layer_builder.finish()?;
            }

            let mut layer_file = File::open(temp_layer.path())?;
            let layer_size = layer_file.metadata()?.len();

            let mut layer_header = Header::new_gnu();
            layer_header.set_size(layer_size);
            layer_header.set_mode(0o644);
            layer_header.set_cksum();
            builder.append_data(&mut layer_header, &layer_filename, &mut layer_file)?;

            let repo_tags = if saved_by_id {
                Vec::new()
            } else {
                vec![format!("{}:{}", image.display_reference(), image.tag)]
            };

            manifest_items.push(TarManifestItem {
                config: config_filename,
                repo_tags,
                layers: vec![layer_filename],
            });

            let meta = BoxrImageMeta {
                id: image.id.clone(),
                reference: if saved_by_id {
                    "<none>".to_string()
                } else {
                    image.reference.clone()
                },
                tag: if saved_by_id {
                    "<none>".to_string()
                } else {
                    image.tag.clone()
                },
                registry: image.registry.clone(),
                manifest_digest: image.manifest_digest.clone(),
                config_digest: image.config_digest.clone(),
                size_bytes: image.size_bytes,
            };
            let meta_bytes = serde_json::to_vec_pretty(&meta)?;
            let mut meta_header = Header::new_gnu();
            let meta_filename = if records.len() == 1 {
                "boxr-meta.json".to_string()
            } else {
                format!("boxr-meta-{}.json", idx)
            };
            meta_header.set_size(meta_bytes.len() as u64);
            meta_header.set_mode(0o644);
            meta_header.set_cksum();
            builder.append_data(&mut meta_header, meta_filename, &meta_bytes[..])?;
        }

        let manifest_bytes = serde_json::to_vec_pretty(&manifest_items)?;
        let mut manifest_header = Header::new_gnu();
        manifest_header.set_size(manifest_bytes.len() as u64);
        manifest_header.set_mode(0o644);
        manifest_header.set_cksum();
        builder.append_data(&mut manifest_header, "manifest.json", &manifest_bytes[..])?;

        builder.finish()?;
        Ok(())
    }

    fn pack_oci_archive<W: Write>(
        records: &[ImageRecord],
        builder: &mut Builder<W>,
    ) -> Result<()> {
        let layout_bytes = serde_json::to_vec_pretty(&OciLayout {
            image_layout_version: "1.0.0".to_string(),
        })?;
        let mut layout_header = Header::new_gnu();
        layout_header.set_size(layout_bytes.len() as u64);
        layout_header.set_mode(0o644);
        layout_header.set_cksum();
        builder.append_data(&mut layout_header, "oci-layout", &layout_bytes[..])?;

        let mut index_manifests = Vec::new();

        for image in records {
            let temp_layer = tempfile::NamedTempFile::new()?;
            let layer_hash = {
                let mut layer_builder = Builder::new(File::create(temp_layer.path())?);
                let rootfs_dir = Path::new(&image.rootfs_path);
                if rootfs_dir.exists() {
                    Self::append_dir_resilient(&mut layer_builder, rootfs_dir, Path::new(""))?;
                }
                layer_builder.finish()?;
                let mut f = File::open(temp_layer.path())?;
                let mut hasher = Sha256::new();
                std::io::copy(&mut f, &mut hasher)?;
                hex::encode(hasher.finalize())
            };

            let mut layer_file = File::open(temp_layer.path())?;
            let layer_size = layer_file.metadata()?.len();

            let layer_blob_path = format!("blobs/sha256/{}", layer_hash);
            let mut layer_header = Header::new_gnu();
            layer_header.set_size(layer_size);
            layer_header.set_mode(0o644);
            layer_header.set_cksum();
            builder.append_data(&mut layer_header, &layer_blob_path, &mut layer_file)?;

            let config_bytes = serde_json::to_vec_pretty(&image.config)?;
            let config_hash = hex::encode(Sha256::digest(&config_bytes));
            let config_blob_path = format!("blobs/sha256/{}", config_hash);
            let mut config_header = Header::new_gnu();
            config_header.set_size(config_bytes.len() as u64);
            config_header.set_mode(0o644);
            config_header.set_cksum();
            builder.append_data(&mut config_header, &config_blob_path, &config_bytes[..])?;

            let manifest = OciManifest {
                schema_version: 2,
                media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                config: OciManifestConfig {
                    media_type: "application/vnd.oci.image.config.v1+json".to_string(),
                    digest: format!("sha256:{}", config_hash),
                    size: config_bytes.len() as u64,
                },
                layers: vec![OciManifestLayer {
                    media_type: "application/vnd.oci.image.layer.v1.tar".to_string(),
                    digest: format!("sha256:{}", layer_hash),
                    size: layer_size,
                }],
            };

            let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
            let manifest_hash = hex::encode(Sha256::digest(&manifest_bytes));
            let manifest_blob_path = format!("blobs/sha256/{}", manifest_hash);
            let mut manifest_header = Header::new_gnu();
            manifest_header.set_size(manifest_bytes.len() as u64);
            manifest_header.set_mode(0o644);
            manifest_header.set_cksum();
            builder.append_data(&mut manifest_header, &manifest_blob_path, &manifest_bytes[..])?;

            let mut annotations = std::collections::HashMap::new();
            let ref_name = format!("{}:{}", image.display_reference(), image.tag);
            annotations.insert("org.opencontainers.image.ref.name".to_string(), ref_name);

            index_manifests.push(OciIndexDescriptor {
                media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                digest: format!("sha256:{}", manifest_hash),
                size: manifest_bytes.len() as u64,
                annotations,
            });
        }

        let index = OciIndex {
            schema_version: 2,
            manifests: index_manifests,
        };
        let index_bytes = serde_json::to_vec_pretty(&index)?;
        let mut index_header = Header::new_gnu();
        index_header.set_size(index_bytes.len() as u64);
        index_header.set_mode(0o644);
        index_header.set_cksum();
        builder.append_data(&mut index_header, "index.json", &index_bytes[..])?;

        builder.finish()?;
        Ok(())
    }

    pub fn load_from(src_path: Option<&Path>, home: &Path) -> Result<Vec<ImageRecord>> {
        Self::load_from_opts(src_path, home, false)
    }

    pub fn load_from_opts(src_path: Option<&Path>, home: &Path, quiet: bool) -> Result<Vec<ImageRecord>> {
        let temp_dir = tempfile::tempdir()?;
        if let Some(path) = src_path {
            let path_str = path.to_string_lossy();
            if path_str.starts_with("http://") || path_str.starts_with("https://") {
                let bytes = if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    tokio::task::block_in_place(|| {
                        handle.block_on(async {
                            let client = reqwest::Client::new();
                            let res = client.get(path_str.as_ref()).send().await?;
                            res.bytes().await
                        })
                    })?
                } else {
                    let rt = tokio::runtime::Runtime::new()?;
                    rt.block_on(async {
                        let client = reqwest::Client::new();
                        let res = client.get(path_str.as_ref()).send().await?;
                        res.bytes().await
                    })?
                };
                let mut archive = Archive::new(std::io::Cursor::new(bytes));
                crate::oci::image::unpack_archive_safely(&mut archive, temp_dir.path())?;
            } else {
                let file = File::open(path)
                    .with_context(|| format!("Failed to open image archive at {:?}", path))?;
                let mut archive = Archive::new(file);
                crate::oci::image::unpack_archive_safely(&mut archive, temp_dir.path())?;
            }
        } else {
            let stdin = std::io::stdin();
            let mut archive = Archive::new(stdin.lock());
            crate::oci::image::unpack_archive_safely(&mut archive, temp_dir.path())?;
        }

        // Check for OCI layout
        if temp_dir.path().join("index.json").exists() {
            return Self::load_oci_archive(temp_dir.path(), home, quiet);
        }

        let manifest_path = temp_dir.path().join("manifest.json");
        if !manifest_path.exists() {
            return Err(anyhow!("Invalid image archive: missing manifest.json"));
        }

        let manifest_content = fs::read_to_string(&manifest_path)?;
        let manifest_items: Vec<TarManifestItem> = serde_json::from_str(&manifest_content)?;

        let store = ImageStore::with_home(home.to_path_buf());
        let mut loaded = Vec::new();

        for (idx, item) in manifest_items.iter().enumerate() {
            let config_path = temp_dir.path().join(&item.config);
            let config: crate::oci::image::ImageConfig = if config_path.exists() {
                let content = fs::read_to_string(&config_path)?;
                serde_json::from_str(&content)?
            } else {
                crate::oci::image::ImageConfig {
                    architecture: std::env::consts::ARCH.to_string(),
                    os: "linux".to_string(),
                    config: None,
                    rootfs: None,
                    history: Vec::new(),
                }
            };

            let meta_name = if manifest_items.len() == 1 {
                "boxr-meta.json".to_string()
            } else {
                format!("boxr-meta-{}.json", idx)
            };
            let meta_path = temp_dir.path().join(meta_name);
            let boxr_meta: Option<BoxrImageMeta> = if meta_path.exists() {
                fs::read_to_string(&meta_path)
                    .ok()
                    .and_then(|c| serde_json::from_str(&c).ok())
            } else {
                None
            };

            let (short_id, manifest_digest, config_digest, size_bytes) = match boxr_meta {
                Some(ref m) => (
                    m.id.clone(),
                    m.manifest_digest.clone(),
                    m.config_digest.clone(),
                    m.size_bytes,
                ),
                None => {
                    let config_id = item.config.strip_suffix(".json").unwrap_or(&item.config);
                    let clean_id = config_id.strip_prefix("sha256:").unwrap_or(config_id);
                    let sid = clean_id[..12.min(clean_id.len())].to_string();
                    let fid = format!("sha256:{}", clean_id);
                    (sid, fid.clone(), fid, 1024 * 1024)
                }
            };

            let image_id = manifest_digest.clone();
            let dest_rootfs = home
                .join("images")
                .join(image_id.replace(':', "_"))
                .join("rootfs");
            fs::create_dir_all(&dest_rootfs)?;

            for layer in &item.layers {
                let layer_path = temp_dir.path().join(layer);
                if layer_path.exists() {
                    let mut layer_archive = Archive::new(File::open(layer_path)?);
                    crate::oci::image::unpack_archive_safely(&mut layer_archive, &dest_rootfs)?;
                }
            }

            let tags = if item.repo_tags.is_empty() {
                vec!["<none>:<none>".to_string()]
            } else {
                item.repo_tags.clone()
            };

            for repo_tag in tags {
                let (reference, tag, registry) = if repo_tag == "<none>:<none>" {
                    ("<none>".to_string(), "<none>".to_string(), "".to_string())
                } else if let Ok(parsed) = ImageReference::parse(&repo_tag) {
                    (parsed.repository, parsed.tag, parsed.registry)
                } else {
                    (repo_tag.clone(), "<none>".to_string(), "".to_string())
                };

                let record = ImageRecord {
                    id: short_id.clone(),
                    reference,
                    tag,
                    registry,
                    manifest_digest: manifest_digest.clone(),
                    config_digest: config_digest.clone(),
                    size_bytes,
                    created_at: chrono::Utc::now(),
                    rootfs_path: dest_rootfs.to_string_lossy().to_string(),
                    config: config.clone(),
                };

                store.add(record.clone())?;
                if !quiet {
                    if record.reference == "<none>" && record.tag == "<none>" {
                        println!("Loaded image: <none>:<none>");
                    } else {
                        println!("Loaded image: {}:{}", record.reference, record.tag);
                    }
                }
                loaded.push(record);
            }
        }

        Ok(loaded)
    }

    fn load_oci_archive(dir: &Path, home: &Path, quiet: bool) -> Result<Vec<ImageRecord>> {
        let index_content = fs::read_to_string(dir.join("index.json"))?;
        let index: OciIndex = serde_json::from_str(&index_content)?;
        let store = ImageStore::with_home(home.to_path_buf());
        let mut loaded = Vec::new();

        for descriptor in index.manifests {
            let manifest_hash = descriptor
                .digest
                .strip_prefix("sha256:")
                .unwrap_or(&descriptor.digest);
            let manifest_path = dir.join("blobs/sha256").join(manifest_hash);
            if !manifest_path.exists() {
                continue;
            }
            let manifest_content = fs::read_to_string(&manifest_path)?;
            let manifest: OciManifest = serde_json::from_str(&manifest_content)?;

            let config_hash = manifest
                .config
                .digest
                .strip_prefix("sha256:")
                .unwrap_or(&manifest.config.digest);
            let config_path = dir.join("blobs/sha256").join(config_hash);
            let config: crate::oci::image::ImageConfig = if config_path.exists() {
                let content = fs::read_to_string(&config_path)?;
                serde_json::from_str(&content).unwrap_or_else(|_| crate::oci::image::ImageConfig {
                    architecture: std::env::consts::ARCH.to_string(),
                    os: "linux".to_string(),
                    config: None,
                    rootfs: None,
                    history: Vec::new(),
                })
            } else {
                crate::oci::image::ImageConfig {
                    architecture: std::env::consts::ARCH.to_string(),
                    os: "linux".to_string(),
                    config: None,
                    rootfs: None,
                    history: Vec::new(),
                }
            };

            let short_id = config_hash[..12.min(config_hash.len())].to_string();
            let dest_rootfs = home
                .join("images")
                .join(format!("sha256_{}", manifest_hash))
                .join("rootfs");
            fs::create_dir_all(&dest_rootfs)?;

            for layer in &manifest.layers {
                let layer_hash = layer
                    .digest
                    .strip_prefix("sha256:")
                    .unwrap_or(&layer.digest);
                let layer_path = dir.join("blobs/sha256").join(layer_hash);
                if layer_path.exists() {
                    let mut layer_archive = Archive::new(File::open(layer_path)?);
                    crate::oci::image::unpack_archive_safely(&mut layer_archive, &dest_rootfs)?;
                }
            }

            let ref_name = descriptor
                .annotations
                .get("org.opencontainers.image.ref.name")
                .cloned()
                .unwrap_or_else(|| "<none>:<none>".to_string());

            let parsed = ImageReference::parse(&ref_name).unwrap_or(ImageReference {
                registry: ImageReference::DEFAULT_REGISTRY.to_string(),
                repository: ref_name.clone(),
                tag: ImageReference::DEFAULT_TAG.to_string(),
                digest: None,
            });

            let record = ImageRecord {
                id: short_id,
                reference: parsed.repository,
                tag: parsed.tag,
                registry: parsed.registry,
                manifest_digest: format!("sha256:{}:oci", manifest_hash),
                config_digest: format!("sha256:{}", config_hash),
                size_bytes: descriptor.size as i64,
                created_at: chrono::Utc::now(),
                rootfs_path: dest_rootfs.to_string_lossy().to_string(),
                config,
            };

            store.add(record.clone())?;
            if !quiet {
                if record.reference == "<none>" && record.tag == "<none>" {
                    println!("Loaded image: <none>:<none>");
                } else {
                    println!("Loaded image: {}:{}", record.reference, record.tag);
                }
            }
            loaded.push(record);
        }

        Ok(loaded)
    }
}
