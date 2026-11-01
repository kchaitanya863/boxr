use crate::oci::image::ImageConfig;
use crate::oci::reference::ImageReference;
use crate::storage::boxr_home;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

fn default_image_registry() -> String {
    ImageReference::DEFAULT_REGISTRY.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageRecord {
    pub id: String, // Short 12-char ID or full sha256
    pub reference: String,
    pub tag: String,
    /// Normalized registry host (e.g. "registry-1.docker.io").
    /// Defaults to Docker Hub for records written before this field existed.
    #[serde(default = "default_image_registry")]
    pub registry: String,
    pub manifest_digest: String,
    pub config_digest: String,
    pub size_bytes: i64,
    pub created_at: DateTime<Utc>,
    pub rootfs_path: String,
    pub config: ImageConfig,
}

impl ImageRecord {
    /// Repository name for display and filters: qualified with the registry
    /// unless it is the default Docker Hub registry, e.g. "library/alpine"
    /// for Docker Hub but "ghcr.io/org/repo" elsewhere.
    pub fn display_reference(&self) -> String {
        if self.reference == "<none>" || self.registry.is_empty() {
            self.reference.clone()
        } else if self.registry == ImageReference::DEFAULT_REGISTRY {
            self.reference.clone()
        } else {
            format!("{}/{}", self.registry, self.reference)
        }
    }

    /// Fully qualified "registry/repository:tag" string, usable as a query.
    pub fn qualified_name(&self) -> String {
        if self.reference == "<none>" || self.registry.is_empty() {
            format!("{}:{}", self.reference, self.tag)
        } else {
            format!("{}/{}:{}", self.registry, self.reference, self.tag)
        }
    }

    /// 64-character lowercase hex image ID (without `sha256:` prefix).
    pub fn full_hex_id(&self) -> String {
        let raw = self.id.strip_prefix("sha256:").unwrap_or(&self.id);
        if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
            return raw.to_string();
        }
        let c = self
            .config_digest
            .strip_prefix("sha256:")
            .unwrap_or(&self.config_digest);
        if c.len() == 64 && c.chars().all(|c| c.is_ascii_hexdigit()) && c.starts_with(raw) {
            return c.to_string();
        }
        let m = self
            .manifest_digest
            .strip_prefix("sha256:")
            .unwrap_or(&self.manifest_digest);
        if m.len() == 64 && m.chars().all(|c| c.is_ascii_hexdigit()) && m.starts_with(raw) {
            return m.to_string();
        }
        if c.len() == 64 && c.chars().all(|c| c.is_ascii_hexdigit()) {
            return c.to_string();
        }
        if m.len() == 64 && m.chars().all(|c| c.is_ascii_hexdigit()) {
            return m.to_string();
        }
        format!("{:0<64}", raw)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ImageStoreData {
    images: Vec<ImageRecord>,
}

/// True when `query` identifies `img`: by image id prefix, by manifest
/// digest, or by normalized (registry, repository, tag) reference.
///
/// The reference is parsed with `ImageReference::parse`, which normalizes
/// Docker Hub aliases (`docker.io`, `index.docker.io`,
/// `registry-1.docker.io`), adds the `library/` prefix for official images,
/// applies the default `latest` tag, and handles registry ports. Equivalent
/// spellings of the same image (e.g. `alpine`,
/// `docker.io/library/alpine:latest`) therefore match the same record.
pub fn query_matches_image(img: &ImageRecord, query: &str) -> bool {
    let query = query
        .trim()
        .strip_prefix("containers-storage:")
        .or_else(|| query.trim().strip_prefix("docker://"))
        .unwrap_or_else(|| query.trim());
    if query.is_empty() {
        return false;
    }
    if img.id.starts_with(query) || img.full_hex_id().starts_with(query) {
        return true;
    }
    let cfg_hex = img
        .config_digest
        .strip_prefix("sha256:")
        .unwrap_or(&img.config_digest);
    if !cfg_hex.is_empty() && (cfg_hex.starts_with(query) || img.config_digest == query) {
        return true;
    }
    if let Some(hex) = query.strip_prefix("sha256:") {
        return img.manifest_digest == query
            || img.id.starts_with(hex)
            || img.full_hex_id().starts_with(hex)
            || img.config_digest == query
            || (!cfg_hex.is_empty() && cfg_hex.starts_with(hex));
    }
    if query == "<none>:<none>" || query == "/<none>:<none>" || query == "<none>" {
        return img.reference == "<none>";
    }
    if query == &img.qualified_name()
        || (query == &img.display_reference() && img.tag == ImageReference::DEFAULT_TAG)
    {
        return true;
    }
    if img.registry == "localhost" {
        if query == format!("{}:{}", img.reference, img.tag)
            || (query == img.reference && img.tag == ImageReference::DEFAULT_TAG)
        {
            return true;
        }
    }
    match ImageReference::parse(query) {
        Ok(r) => {
            if let Some(digest) = r.digest {
                return img.manifest_digest == digest;
            }
            let (reg, repo, tag) = record_identity(img);
            reg == r.registry && repo == r.repository && tag == r.tag
        }
        Err(_) => {
            // Fall back to the historical raw comparison for unparseable queries.
            img.reference == query
        }
    }
}

/// Canonical (registry, repository, tag) identity for a stored record. The
/// record's reference is parsed exactly like a query so that legacy records
/// written with un-normalized references (e.g. "test101" instead of
/// "library/test101") still match normalized queries.
fn record_identity(img: &ImageRecord) -> (String, String, String) {
    let probe = format!("{}/{}:{}", img.registry, img.reference, img.tag);
    match ImageReference::parse(&probe) {
        Ok(r) => (r.registry, r.repository, r.tag),
        Err(_) => (img.registry.clone(), img.reference.clone(), img.tag.clone()),
    }
}

/// True when two image query strings name the same image, normalizing
/// registry aliases, `library/` prefixes, default tags, and digests.
/// Used where exact string comparison would miss equivalent spellings
/// (e.g. checking whether a container uses the image being removed).
pub fn refs_equivalent(a: &str, b: &str) -> bool {
    match (ImageReference::parse(a), ImageReference::parse(b)) {
        (Ok(ra), Ok(rb)) => {
            match (ra.digest.as_deref(), rb.digest.as_deref()) {
                // A digest pins an exact image: both sides must carry the
                // same digest. A digest on only one side is never equivalent
                // to a tag on the other.
                (Some(da), Some(db)) => da == db,
                (Some(_), None) | (None, Some(_)) => false,
                (None, None) => {
                    ra.registry == rb.registry && ra.repository == rb.repository && ra.tag == rb.tag
                }
            }
        }
        _ => a.trim() == b.trim(),
    }
}

pub struct ImageStore {
    index_file: PathBuf,
}

impl ImageStore {
    pub fn new() -> Self {
        Self::with_home(boxr_home())
    }

    pub fn with_home(home: PathBuf) -> Self {
        Self {
            index_file: home.join("images.json"),
        }
    }

    fn load_unlocked(&self) -> ImageStoreData {
        let mut data: ImageStoreData = if let Ok(content) = fs::read_to_string(&self.index_file) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            ImageStoreData::default()
        };

        let globals = crate::cli::podman_globals::podman_global_options();
        for opt in &globals.storage_opts {
            if let Some((k, v)) = opt.split_once('=') {
                if k.ends_with(".imagestore") {
                    let alt_file = PathBuf::from(v).join("images.json");
                    if alt_file.exists() && alt_file != self.index_file {
                        if let Ok(content) = fs::read_to_string(&alt_file) {
                            if let Ok(alt_data) = serde_json::from_str::<ImageStoreData>(&content) {
                                for alt_img in alt_data.images {
                                    if !data.images.iter().any(|i| i.id == alt_img.id) {
                                        data.images.push(alt_img);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        data
    }

    fn save_unlocked(&self, data: &ImageStoreData) -> Result<()> {
        let content = serde_json::to_string_pretty(data)?;
        let rand_suffix = hex::encode(crate::storage::container_store::rand_id());
        let temp_file = self
            .index_file
            .with_extension(format!("tmp.{}", rand_suffix));
        fs::write(&temp_file, content)?;
        fs::rename(&temp_file, &self.index_file)?;
        Ok(())
    }

    pub fn list(&self) -> Vec<ImageRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            Ok(self.load_unlocked().images)
        })
        .unwrap_or_default()
    }

    pub fn find(&self, query: &str) -> Option<ImageRecord> {
        self.find_with_platform(query, None)
    }

    pub fn find_with_platform(&self, query: &str, platform: Option<&str>) -> Option<ImageRecord> {
        let query_trimmed = query.trim();
        if query_trimmed.is_empty() {
            return None;
        }
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let data = self.load_unlocked();
            let matching: Vec<ImageRecord> = data
                .images
                .into_iter()
                .filter(|img| query_matches_image(img, query_trimmed))
                .collect();
            if matching.is_empty() {
                return Ok(None);
            }
            if let Some(target_plat) = platform {
                let (target_os, norm_arch) = {
                    let (os, arch) = if let Some((os, arch)) = target_plat.split_once('/') {
                        (Some(os), arch)
                    } else {
                        (None, target_plat)
                    };
                    let norm = match arch {
                        "x86_64" => "amd64",
                        "aarch64" => "arm64",
                        other => other,
                    };
                    (os, norm)
                };
                return Ok(matching.into_iter().find(|img| {
                    let img_arch = match img.config.architecture.as_str() {
                        "x86_64" => "amd64",
                        "aarch64" => "arm64",
                        other => other,
                    };
                    let arch_matches = img_arch == norm_arch;
                    let os_matches = if let Some(tos) = target_os {
                        img.config.os.eq_ignore_ascii_case(tos)
                    } else {
                        true
                    };
                    arch_matches && os_matches
                }));
            }

            // When no specific platform requested: prefer matching host arch & os,
            // but if none match, fall back to the first matching image in the store.
            let host_arch = match std::env::consts::ARCH {
                "x86_64" => "amd64",
                "aarch64" => "arm64",
                other => other,
            };
            let default_os = if cfg!(target_os = "windows") {
                "windows"
            } else {
                "linux"
            };
            if let Some(preferred) = matching.iter().find(|img| {
                let img_arch = match img.config.architecture.as_str() {
                    "x86_64" => "amd64",
                    "aarch64" => "arm64",
                    other => other,
                };
                img_arch == host_arch && img.config.os.eq_ignore_ascii_case(default_os)
            }) {
                return Ok(Some(preferred.clone()));
            }

            Ok(matching.into_iter().next())
        })
        .ok()
        .flatten()
    }

    pub fn add(&self, record: ImageRecord) -> Result<()> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            // Remove previous entry with same registry, reference, tag, architecture, and os if present
            fn norm_arch(a: &str) -> &str {
                match a {
                    "x86_64" => "amd64",
                    "aarch64" => "arm64",
                    other => other,
                }
            }
            data.images.retain(|img| {
                !(img.registry == record.registry
                    && img.reference == record.reference
                    && img.tag == record.tag
                    && norm_arch(&img.config.architecture)
                        == norm_arch(&record.config.architecture)
                    && img.config.os.eq_ignore_ascii_case(&record.config.os))
            });
            data.images.push(record);
            self.save_unlocked(&data)?;
            Ok(())
        })
    }

    pub fn remove(&self, query: &str) -> Result<ImageRecord> {
        let query_trimmed = query.trim();
        if query_trimmed.is_empty() {
            return Err(anyhow!("Image not found: ''"));
        }
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();

            let pos = data
                .images
                .iter()
                .position(|img| img.qualified_name() == query_trimmed)
                .or_else(|| {
                    data.images
                        .iter()
                        .position(|img| query_matches_image(img, query_trimmed))
                });

            if let Some(index) = pos {
                let removed = data.images.remove(index);
                self.save_unlocked(&data)?;
                record_untagged_image_history(&self.index_file, &removed);

                // Only clean up rootfs directory if NO OTHER image shares this rootfs_path
                // and the rootfs resides within this store's root directory.
                let is_shared = data.images.iter().any(|img| {
                    img.rootfs_path == removed.rootfs_path
                        || img.manifest_digest == removed.manifest_digest
                });
                let rootfs = PathBuf::from(&removed.rootfs_path);
                let store_root = self.index_file.parent().unwrap_or(Path::new("."));
                let is_local_to_store = rootfs.starts_with(store_root)
                    && !removed
                        .rootfs_path
                        .starts_with("/var/tmp/boxr-e2e-tar-cache");
                if !is_shared && is_local_to_store {
                    if rootfs.exists() {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = fs::set_permissions(&rootfs, fs::Permissions::from_mode(0o755));
                        }
                        if fs::remove_dir_all(&rootfs).is_err() {
                            crate::storage::container_store::make_tree_writable(&rootfs);
                            let _ = fs::remove_dir_all(&rootfs);
                        }
                    }
                    if let Some(parent) = rootfs.parent() {
                        let root_dir = self.index_file.parent().unwrap_or(Path::new("."));
                        if parent.exists() && parent != root_dir && parent != Path::new("/") {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let _ =
                                    fs::set_permissions(parent, fs::Permissions::from_mode(0o755));
                            }
                            if fs::remove_dir_all(parent).is_err() {
                                crate::storage::container_store::make_tree_writable(parent);
                                let _ = fs::remove_dir_all(parent);
                            }
                        }
                    }
                }

                Ok(removed)
            } else {
                Err(anyhow!("Image not found: {}", query))
            }
        })
    }

    pub fn remove_metadata_only(&self, query: &str) -> Result<ImageRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let query_trimmed = query.trim();

            let pos = data
                .images
                .iter()
                .position(|img| img.qualified_name() == query_trimmed)
                .or_else(|| {
                    data.images
                        .iter()
                        .position(|img| query_matches_image(img, query_trimmed))
                });

            if let Some(index) = pos {
                let removed = data.images.remove(index);
                self.save_unlocked(&data)?;
                record_untagged_image_history(&self.index_file, &removed);
                Ok(removed)
            } else {
                Err(anyhow!("Image not found: {}", query))
            }
        })
    }

    /// Commit a container's current filesystem snapshot into a new image
    pub fn commit_container(
        &self,
        container: &crate::storage::ContainerRecord,
        repo_tag: Option<&str>,
        message: Option<&str>,
        author: Option<&str>,
    ) -> Result<ImageRecord> {
        self.commit_container_with_changes(container, repo_tag, message, author, &[])
    }

    pub fn commit_container_with_changes(
        &self,
        container: &crate::storage::ContainerRecord,
        repo_tag: Option<&str>,
        message: Option<&str>,
        author: Option<&str>,
        changes: &[String],
    ) -> Result<ImageRecord> {
        let home = boxr_home();
        use sha2::{Digest, Sha256};
        let random_id = hex::encode(Sha256::digest(crate::storage::container_store::rand_id()));
        let image_id = format!("sha256:{}", random_id);
        let safe_id = image_id.replace(':', "_");

        let dest_image_dir = home.join("images").join(&safe_id);
        let dest_rootfs = dest_image_dir.join("rootfs");
        fs::create_dir_all(&dest_rootfs)?;

        let container_rootfs = PathBuf::from(&container.bundle_path).join("rootfs");
        crate::storage::overlay::OverlayDriver::create_hardlink_tree(
            &container_rootfs,
            &dest_rootfs,
        )?;
        if let Some(base_img) = self.find(&container.image) {
            let _ = fs::write(
                dest_image_dir.join("parent_rootfs.txt"),
                &base_img.rootfs_path,
            );
        }

        let _ = fs::remove_file(dest_rootfs.join("boxr-run.sh"));
        let _ = fs::remove_file(dest_rootfs.join("boxr-exitcode"));
        let _ = fs::remove_file(dest_rootfs.join("logs.txt"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dest_rootfs, fs::Permissions::from_mode(0o755));
        }

        let (repo, tag, reg) = if let Some(full_tag) = repo_tag {
            let parsed_ref = ImageReference::parse(full_tag).unwrap_or(ImageReference {
                registry: ImageReference::DEFAULT_REGISTRY.to_string(),
                repository: full_tag.to_string(),
                tag: ImageReference::DEFAULT_TAG.to_string(),
                digest: None,
            });
            let name_only = full_tag
                .split('@')
                .next()
                .unwrap_or(full_tag)
                .split(':')
                .next()
                .unwrap_or(full_tag);
            if !full_tag.contains('/') {
                (
                    name_only.to_string(),
                    parsed_ref.tag.clone(),
                    "localhost".to_string(),
                )
            } else {
                (
                    parsed_ref.repository.clone(),
                    parsed_ref.tag.clone(),
                    parsed_ref.registry.clone(),
                )
            }
        } else {
            (
                "<none>".to_string(),
                "<none>".to_string(),
                ImageReference::DEFAULT_REGISTRY.to_string(),
            )
        };

        let mut base_config = self
            .find(&container.image)
            .map(|i| i.config)
            .unwrap_or_else(|| crate::oci::image::ImageConfig {
                architecture: std::env::consts::ARCH.to_string(),
                os: "linux".to_string(),
                config: Some(crate::oci::image::ExecutionConfig {
                    cmd: Some(container.command.clone()),
                    ..Default::default()
                }),
                rootfs: None,
                history: Vec::new(),
            });

        let bundle_config = PathBuf::from(&container.bundle_path).join("config.json");
        if let Ok(content) = fs::read_to_string(&bundle_config) {
            if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&content) {
                let run_args = spec.process.args;
                if !run_args.is_empty() {
                    let exec = base_config
                        .config
                        .get_or_insert_with(crate::oci::image::ExecutionConfig::default);
                    exec.entrypoint = Some(run_args);
                    exec.cmd = None;
                }
            }
        }

        for ch in changes {
            let ch = ch.trim();
            let (key, val) = if let Some((k, v)) = ch.split_once('=') {
                (k.trim(), v.trim())
            } else if let Some((k, v)) = ch.split_once(' ') {
                (k.trim(), v.trim())
            } else {
                (ch, "")
            };
            let exec = base_config
                .config
                .get_or_insert_with(crate::oci::image::ExecutionConfig::default);
            if key.eq_ignore_ascii_case("CMD") {
                if val.starts_with('[') && val.ends_with(']') {
                    if let Ok(arr) = serde_json::from_str::<Vec<String>>(val) {
                        exec.cmd = Some(arr);
                        exec.entrypoint = None;
                        continue;
                    }
                }
                exec.cmd = Some(vec![val.to_string()]);
                exec.entrypoint = None;
            } else if key.eq_ignore_ascii_case("ENTRYPOINT") {
                if val.starts_with('[') && val.ends_with(']') {
                    if let Ok(arr) = serde_json::from_str::<Vec<String>>(val) {
                        exec.entrypoint = Some(arr);
                        continue;
                    }
                }
                exec.entrypoint = Some(vec![val.to_string()]);
            }
        }

        if let Some(auth) = author {
            if let Some(cfg) = &mut base_config.config {
                let mut labels = cfg.labels.take().unwrap_or_default();
                labels.insert("author".to_string(), auth.to_string());
                cfg.labels = Some(labels);
            }
        }
        if let Some(msg) = message {
            if let Some(cfg) = &mut base_config.config {
                let mut labels = cfg.labels.take().unwrap_or_default();
                labels.insert("commit_message".to_string(), msg.to_string());
                cfg.labels = Some(labels);
            }
        }

        let base_max = self
            .list()
            .iter()
            .map(|i| i.size_bytes.max(0) as u64)
            .max()
            .unwrap_or(0);
        let total_size = crate::system::dir_size(&dest_rootfs).max(base_max);

        let record = ImageRecord {
            id: random_id[..12].to_string(),
            reference: repo,
            tag,
            registry: reg,
            manifest_digest: image_id.clone(),
            config_digest: image_id.clone(),
            size_bytes: if total_size > 0 {
                total_size as i64
            } else {
                1024 * 1024
            },
            created_at: Utc::now(),
            rootfs_path: dest_rootfs.to_string_lossy().to_string(),
            config: base_config,
        };

        self.add(record.clone())?;
        Ok(record)
    }
}

fn record_untagged_image_history(index_file: &Path, removed: &ImageRecord) {
    if removed.reference == "<none>" || removed.tag == "<none>" || removed.tag.contains("@sha256:")
    {
        return;
    }
    let Some(home) = index_file.parent() else {
        return;
    };
    let hist_file = home.join("image_history.json");
    let mut map: std::collections::HashMap<String, Vec<String>> = fs::read_to_string(&hist_file)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let tag_name = format!("{}:{}", removed.display_reference(), removed.tag);
    let list = map.entry(removed.id.clone()).or_default();
    list.retain(|x| x != &tag_name);
    list.insert(0, tag_name);
    if let Ok(json) = serde_json::to_string_pretty(&map) {
        let _ = fs::write(&hist_file, json);
    }
}

pub fn load_untagged_image_history(home: &Path) -> std::collections::HashMap<String, Vec<String>> {
    let hist_file = home.join("image_history.json");
    fs::read_to_string(&hist_file)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn additional_image_store_roots_from_env() -> Vec<PathBuf> {
    let Ok(conf_path) = std::env::var("CONTAINERS_STORAGE_CONF") else {
        return Vec::new();
    };
    let Ok(content) = fs::read_to_string(&conf_path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut in_list = false;
    let mut buf = String::new();
    for line in content.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if !in_list {
            if let Some(rest) = trimmed.strip_prefix("additionalimagestores") {
                let rest = rest.trim_start().strip_prefix('=').unwrap_or(rest).trim();
                buf.push_str(rest);
                if buf.contains(']') {
                    break;
                }
                in_list = true;
            }
        } else {
            buf.push(' ');
            buf.push_str(trimmed);
            if buf.contains(']') {
                break;
            }
        }
    }
    if let Some(start) = buf.find('[') {
        let end = buf.rfind(']').unwrap_or(buf.len());
        let inner = &buf[start + 1..end];
        for item in inner.split(',') {
            let clean = item.trim().trim_matches('"').trim_matches('\'').trim();
            if !clean.is_empty() {
                out.push(PathBuf::from(clean));
            }
        }
    }
    out
}

impl super::traits::ImageReader for ImageStore {
    fn find(&self, reference: &str) -> Option<ImageRecord> {
        self.find(reference)
    }

    fn find_with_platform(&self, reference: &str, platform: Option<&str>) -> Option<ImageRecord> {
        self.find_with_platform(reference, platform)
    }

    fn list(&self) -> Vec<ImageRecord> {
        self.list()
    }
}

impl super::traits::ImageWriter for ImageStore {
    fn add(&self, record: ImageRecord) -> Result<()> {
        self.add(record)
    }

    fn remove(&self, reference: &str) -> Result<()> {
        self.remove(reference).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::image::{ExecutionConfig, ImageConfig};
    use tempfile::tempdir;

    #[test]
    fn test_image_store_lifecycle() {
        let temp = tempdir().unwrap();
        let store = ImageStore {
            index_file: temp.path().join("images.json"),
        };

        let img_dir = temp.path().join("img_1234");
        let rootfs = img_dir.join("rootfs");
        fs::create_dir_all(&rootfs).unwrap();
        fs::write(rootfs.join("layer.txt"), b"test").unwrap();

        let rec = ImageRecord {
            id: "1234567890ab".to_string(),
            reference: "library/test".to_string(),
            tag: "latest".to_string(),
            registry: ImageReference::DEFAULT_REGISTRY.to_string(),
            manifest_digest: "sha256:1234".to_string(),
            config_digest: "sha256:5678".to_string(),
            size_bytes: 1024,
            created_at: Utc::now(),
            rootfs_path: rootfs.to_string_lossy().to_string(),
            config: ImageConfig {
                architecture: match std::env::consts::ARCH {
                    "x86_64" => "amd64".to_string(),
                    "aarch64" => "arm64".to_string(),
                    other => other.to_string(),
                },
                os: "linux".to_string(),
                config: Some(ExecutionConfig::default()),
                rootfs: None,
                history: Vec::new(),
            },
        };

        store.add(rec).unwrap();
        assert_eq!(store.list().len(), 1);

        assert!(store.find("test").is_some());
        assert!(store.find("library/test:latest").is_some());
        assert!(store.find("123456").is_some());

        store.remove("test").unwrap();
        assert_eq!(store.list().len(), 0);
        assert!(!rootfs.exists(), "Image rootfs must be deleted on remove");
    }

    fn test_record(reference: &str, tag: &str, registry: &str) -> ImageRecord {
        ImageRecord {
            id: "1234567890ab".to_string(),
            reference: reference.to_string(),
            tag: tag.to_string(),
            registry: registry.to_string(),
            manifest_digest: "sha256:abcdef123456".to_string(),
            config_digest: "sha256:fedcba654321".to_string(),
            size_bytes: 1024,
            created_at: Utc::now(),
            rootfs_path: "/nonexistent".to_string(),
            config: ImageConfig {
                architecture: match std::env::consts::ARCH {
                    "x86_64" => "amd64".to_string(),
                    "aarch64" => "arm64".to_string(),
                    other => other.to_string(),
                },
                os: "linux".to_string(),
                config: Some(ExecutionConfig::default()),
                rootfs: None,
                history: Vec::new(),
            },
        }
    }

    // Issue #398: fully-qualified docker.io spellings must resolve to the
    // same cached image as the short spelling.
    #[test]
    fn test_issue_398_qualified_refs_hit_cache() {
        let temp = tempdir().unwrap();
        let store = ImageStore {
            index_file: temp.path().join("images.json"),
        };
        store
            .add(test_record(
                "library/alpine",
                "latest",
                ImageReference::DEFAULT_REGISTRY,
            ))
            .unwrap();

        for query in [
            "alpine",
            "alpine:latest",
            "library/alpine",
            "library/alpine:latest",
            "docker.io/library/alpine",
            "docker.io/library/alpine:latest",
            "docker.io/alpine:latest",
            "index.docker.io/library/alpine:latest",
            "registry-1.docker.io/library/alpine:latest",
        ] {
            assert!(
                store.find(query).is_some(),
                "query '{}' should hit the cached image",
                query
            );
        }

        // A different tag must not match.
        assert!(store.find("alpine:3.19").is_none());
        // A different repository must not match.
        assert!(store.find("docker.io/library/busybox:latest").is_none());
        // Digest query matches by manifest digest.
        assert!(store.find("alpine@sha256:abcdef123456").is_some());
        assert!(store.find("sha256:abcdef123456").is_some());

        // Removal works with a qualified spelling too.
        store.remove("docker.io/library/alpine:latest").unwrap();
        assert_eq!(store.list().len(), 0);
    }

    // Equivalent spellings of a non-Docker-Hub image must hit the cache,
    // and must not collide with a Docker Hub image of the same repo path.
    #[test]
    fn test_issue_398_custom_registry_refs() {
        let temp = tempdir().unwrap();
        let store = ImageStore {
            index_file: temp.path().join("images.json"),
        };
        store.add(test_record("org/repo", "v1", "ghcr.io")).unwrap();

        assert!(store.find("ghcr.io/org/repo:v1").is_some());
        assert!(store.find("ghcr.io/org/repo").is_none()); // default tag is latest
        assert!(store.find("org/repo:v1").is_none()); // unqualified means Docker Hub
        assert!(store.find("quay.io/org/repo:v1").is_none()); // wrong registry

        // Registry with a port.
        let temp2 = tempdir().unwrap();
        let store2 = ImageStore {
            index_file: temp2.path().join("images.json"),
        };
        store2
            .add(test_record("myrepo", "latest", "localhost:5000"))
            .unwrap();
        assert!(store2.find("localhost:5000/myrepo:v2").is_none());
        assert!(store2.find("localhost:5000/myrepo:latest").is_some());
        assert!(store2.find("localhost:5000/myrepo").is_some());
    }

    // Records written before the `registry` field existed must still load,
    // defaulting to Docker Hub.
    #[test]
    fn test_issue_398_registry_field_backward_compatible() {
        let json = r#"{"images": [{"id": "abc123def456", "reference": "library/alpine",
            "tag": "latest", "manifest_digest": "sha256:aaa",
            "config_digest": "sha256:bbb", "size_bytes": 1,
            "created_at": "2026-01-01T00:00:00Z", "rootfs_path": "/x",
            "config": {"architecture": "amd64", "os": "linux"}}]}"#;
        let data: ImageStoreData = serde_json::from_str(json).unwrap();
        assert_eq!(data.images.len(), 1);
        assert_eq!(data.images[0].registry, ImageReference::DEFAULT_REGISTRY);
    }

    // Records stored with an un-normalized reference (e.g. "test101" instead
    // of "library/test101", as older code paths wrote) must still match
    // normalized queries for lookup and removal.
    #[test]
    fn test_issue_398_legacy_unnormalized_record_matches() {
        let temp = tempdir().unwrap();
        let store = ImageStore {
            index_file: temp.path().join("images.json"),
        };
        store
            .add(test_record(
                "test101",
                "latest",
                ImageReference::DEFAULT_REGISTRY,
            ))
            .unwrap();

        for query in [
            "test101",
            "test101:latest",
            "library/test101:latest",
            "docker.io/test101:latest",
            "docker.io/library/test101:latest",
        ] {
            assert!(
                store.find(query).is_some(),
                "query '{}' should match the legacy record",
                query
            );
        }
        assert!(store.find("test101:other").is_none());
        assert!(store.find("other:latest").is_none());

        store.remove("docker.io/library/test101:latest").unwrap();
        assert_eq!(store.list().len(), 0);
    }

    #[test]
    fn test_refs_equivalent() {
        assert!(refs_equivalent("alpine", "docker.io/library/alpine:latest"));
        assert!(refs_equivalent(
            "docker.io/library/alpine:3.19",
            "registry-1.docker.io/library/alpine:3.19"
        ));
        assert!(!refs_equivalent("alpine:3.19", "alpine:latest"));
        assert!(!refs_equivalent("ghcr.io/org/repo:v1", "org/repo:v1"));
        assert!(refs_equivalent(
            "alpine@sha256:aaa",
            "docker.io/library/alpine@sha256:aaa"
        ));
        // A digest on only one side is never equivalent to a tag.
        assert!(!refs_equivalent("alpine@sha256:aaa", "alpine:latest"));
        assert!(!refs_equivalent("alpine:latest", "alpine@sha256:aaa"));
    }
}
