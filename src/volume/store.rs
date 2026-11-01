use super::filter::*;
use super::mount::*;
use crate::storage::boxr_home;
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

fn default_volume_needs_flags() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeRecord {
    pub name: String,
    pub driver: String,
    pub mountpoint: String,
    pub created_at: DateTime<Utc>,
    pub labels: HashMap<String, String>,
    pub scope: String,
    #[serde(default)]
    pub options: HashMap<String, String>,
    /// True when created without an explicit user-provided name (`podman volume create`).
    #[serde(default)]
    pub anonymous: bool,
    #[serde(default = "default_volume_needs_flags")]
    pub needs_copy_up: bool,
    #[serde(default = "default_volume_needs_flags")]
    pub needs_chown: bool,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u32>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct VolumeStoreData {
    volumes: Vec<VolumeRecord>,
}

pub struct VolumeStore {
    pub(crate) index_file: PathBuf,
    pub(crate) volumes_dir: PathBuf,
}

/// Interface Segregation: Volume reading abstraction
pub trait VolumeReader: Send + Sync {
    fn find(&self, name: &str) -> Option<VolumeRecord>;
    fn list(&self) -> Vec<VolumeRecord>;
}

/// Interface Segregation: Volume mutation abstraction
pub trait VolumeWriter: Send + Sync {
    fn create_with_options(
        &self,
        name: Option<&str>,
        driver: &str,
        labels: Option<HashMap<String, String>>,
        scope: &str,
        options: Option<HashMap<String, String>>,
    ) -> Result<VolumeRecord>;
    fn remove(&self, name: &str) -> Result<VolumeRecord>;
    fn prune(&self) -> Result<Vec<String>>;
}

/// Combined volume operations contract (LSP compliant)
pub trait VolumeStoreOps: VolumeReader + VolumeWriter {}
impl<T: VolumeReader + VolumeWriter> VolumeStoreOps for T {}

impl VolumeStore {
    pub fn new() -> Self {
        Self::with_home(boxr_home())
    }

    pub fn with_home(home: PathBuf) -> Self {
        let volumes_dir = crate::storage::db_config::effective_volume_path();
        let _ = fs::create_dir_all(&volumes_dir);
        crate::storage::db_config::ensure_sqlite_db(&home);
        Self {
            index_file: home.join("volumes.json"),
            volumes_dir,
        }
    }

    fn load_unlocked(&self) -> VolumeStoreData {
        if let Ok(content) = fs::read_to_string(&self.index_file) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            VolumeStoreData::default()
        }
    }

    fn save_unlocked(&self, data: &VolumeStoreData) -> Result<()> {
        let content = serde_json::to_string_pretty(data)?;
        let rand_suffix = hex::encode(crate::storage::container_store::rand_id());
        let temp_file = self
            .index_file
            .with_extension(format!("tmp.{}", rand_suffix));
        fs::write(&temp_file, content)?;
        fs::rename(&temp_file, &self.index_file)?;
        Ok(())
    }

    pub fn list(&self) -> Vec<VolumeRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            Ok(self.load_unlocked().volumes)
        })
        .unwrap_or_default()
    }

    pub fn find(&self, name: &str) -> Option<VolumeRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            Ok(self
                .load_unlocked()
                .volumes
                .into_iter()
                .find(|v| v.name == name))
        })
        .ok()
        .flatten()
    }

    pub fn create(
        &self,
        name: Option<&str>,
        labels: Option<HashMap<String, String>>,
    ) -> Result<VolumeRecord> {
        self.create_with_options(name, "local", labels, "local", None)
    }

    pub fn create_with_options(
        &self,
        name: Option<&str>,
        driver: &str,
        labels: Option<HashMap<String, String>>,
        scope: &str,
        options: Option<HashMap<String, String>>,
    ) -> Result<VolumeRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let user_provided_name = matches!(name, Some(n) if !n.trim().is_empty());
            let vol_name = match name {
                Some(n) if !n.trim().is_empty() => n.trim().to_string(),
                _ => crate::new_container_id(),
            };

            if vol_name == "." || vol_name == ".." {
                return Err(anyhow!(
                    "Invalid volume name '{}': '.' and '..' are reserved",
                    vol_name
                ));
            }

            if vol_name.contains('/') || vol_name.contains('\\') || vol_name.contains("..") {
                return Err(anyhow!(
                    "Invalid volume name '{}': cannot contain path separators or '..'",
                    vol_name
                ));
            }

            if !vol_name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
            {
                return Err(anyhow!(
                    "Invalid volume name '{}': must contain only alphanumeric, '_', '-', or '.' characters",
                    vol_name
                ));
            }

            if data.volumes.iter().any(|v| v.name == vol_name) {
                return Err(anyhow!(
                    "volume with name {} already exists: volume already exists",
                    vol_name
                ));
            }

            let mut opts = options.clone().unwrap_or_default();
            let mut explicit_uid = opts
                .remove("__boxr_uid")
                .and_then(|s| s.parse::<u32>().ok());
            let mut explicit_gid = opts
                .remove("__boxr_gid")
                .and_then(|s| s.parse::<u32>().ok());

            if driver == "local" {
                for k in opts.keys() {
                    if !matches!(
                        k.as_str(),
                        "type"
                            | "device"
                            | "o"
                            | "copy"
                            | "nocopy"
                            | "uid"
                            | "gid"
                            | "size"
                            | "inodes"
                            | "noquota"
                            | "timeout"
                    ) {
                        return Err(anyhow!(
                            "invalid mount option {} for driver 'local': invalid argument",
                            k
                        ));
                    }
                }
            }
            if let Some(o_val) = opts.get("o").cloned() {
                for part in o_val.split(',') {
                    if let Some(u_str) = part.trim().strip_prefix("uid=") {
                        if let Ok(u) = u_str.parse::<u32>() {
                            explicit_uid = Some(u);
                            opts.insert("UID".to_string(), u_str.to_string());
                        }
                    } else if let Some(g_str) = part.trim().strip_prefix("gid=") {
                        if let Ok(g) = g_str.parse::<u32>() {
                            explicit_gid = Some(g);
                            opts.insert("GID".to_string(), g_str.to_string());
                        }
                    }
                }
            }

            let mountpoint = if driver == "image" {
                let img_ref = opts
                    .get("image")
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow!("image volume requires image option"))?;
                let img_store = crate::storage::ImageStore::new();
                let img_rec = crate::find_image_with_shortname(&img_store, img_ref, None)
                    .ok_or_else(|| anyhow!("{}: image not known", img_ref))?;
                PathBuf::from(&img_rec.rootfs_path)
            } else if opts.get("type").map(|t| t.as_str()) == Some("bind") {
                let device = opts
                    .get("device")
                    .filter(|d| !d.is_empty())
                    .ok_or_else(|| anyhow!("bind volume requires device option"))?;
                let device_path = PathBuf::from(device);
                if !device_path.exists() {
                    crate::cli::usage_errors::exit_usage_error(format!(
                        "invalid volume option device for driver 'local': faccessat {}: no such file or directory",
                        device
                    ));
                }
                device_path
            } else {
                let mp = self.volumes_dir.join(&vol_name).join("_data");
                fs::create_dir_all(&mp)?;
                if let (Ok(canon_vols), Ok(canon_mount)) =
                    (self.volumes_dir.canonicalize(), mp.canonicalize())
                {
                    if !canon_mount.starts_with(&canon_vols) {
                        return Err(anyhow!(
                            "Volume mountpoint escapes volumes directory: '{}'",
                            vol_name
                        ));
                    }
                }
                mp
            };
            if driver != "image" && opts.get("type").map(|t| t.as_str()) != Some("bind") {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o777));
                }
            }

            let record = VolumeRecord {
                name: vol_name,
                driver: driver.to_string(),
                mountpoint: mountpoint.to_string_lossy().to_string(),
                created_at: Utc::now(),
                labels: labels.unwrap_or_default(),
                scope: scope.to_string(),
                options: opts,
                anonymous: !user_provided_name,
                needs_copy_up: true,
                needs_chown: true,
                uid: explicit_uid,
                gid: explicit_gid,
            };

            data.volumes.push(record.clone());
            self.save_unlocked(&data)?;
            Ok(record)
        })
    }

    pub fn remove(&self, name: &str) -> Result<VolumeRecord> {
        self.remove_with_force(name, false)
    }

    pub fn delete_volume_record(&self, name: &str) -> Result<VolumeRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let pos = if let Some(p) = data.volumes.iter().position(|v| v.name == name) {
                p
            } else {
                let prefix_matches: Vec<usize> = data
                    .volumes
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| v.name.starts_with(name))
                    .map(|(i, _)| i)
                    .collect();
                if prefix_matches.len() == 1 {
                    prefix_matches[0]
                } else if prefix_matches.len() > 1 {
                    return Err(anyhow!(
                        "more than one result for volume name {}: volume already exists",
                        name
                    ));
                } else {
                    return Err(anyhow!("Volume '{}' not found", name));
                }
            };
            let removed = data.volumes.remove(pos);
            self.save_unlocked(&data)?;

            let vol_dir = self.volumes_dir.join(&removed.name);
            if removed.driver != "image" && vol_dir.exists() {
                if fs::remove_dir_all(&vol_dir).is_err() {
                    #[cfg(target_os = "linux")]
                    {
                        let _ = crate::runtime::linux::chown_path_rootless(&vol_dir, 0, 0, true);
                    }
                    crate::storage::container_store::make_tree_writable(&vol_dir);
                    let _ = fs::remove_dir_all(&vol_dir);
                }
            }
            Ok(removed)
        })
    }

    /// Podman `volume rename` (updates index, data dir, and container mount references).
    pub fn rename(&self, old_name: &str, new_name: &str) -> Result<VolumeRecord> {
        if old_name == new_name {
            return self
                .find(old_name)
                .ok_or_else(|| anyhow!("no such volume \"{}\"", old_name));
        }
        validate_volume_rename_name(new_name)?;

        let home = self
            .index_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let c_store = crate::storage::ContainerStore::with_home(home.clone());

        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let pos = data
                .volumes
                .iter()
                .position(|v| v.name == old_name)
                .ok_or_else(|| anyhow!("no such volume \"{}\"", old_name))?;
            if data.volumes.iter().any(|v| v.name == new_name) {
                return Err(anyhow!("volume already exists"));
            }
            let mut vol = data.volumes[pos].clone();
            if vol.driver == "image" {
                return Err(anyhow!(
                    "rename is not supported for volumes using driver \"image\""
                ));
            }

            for c in c_store.list() {
                if volume_used_by_container(&c.bundle_path, old_name) {
                    return Err(anyhow!(
                        "volume {} is being used by the following container(s): {}: volume is being used",
                        old_name,
                        c.id
                    ));
                }
            }

            let old_dir = PathBuf::from(&vol.mountpoint);
            let new_mp = self.volumes_dir.join(new_name).join("_data");
            if let Some(parent) = new_mp.parent() {
                fs::create_dir_all(parent)?;
            }
            if old_dir.exists() {
                if new_mp.exists() {
                    return Err(anyhow!("volume already exists"));
                }
                fs::rename(&old_dir, &new_mp)?;
                if let Some(old_parent) = old_dir.parent() {
                    let _ = fs::remove_dir(old_parent);
                }
            } else {
                fs::create_dir_all(&new_mp)?;
            }

            vol.name = new_name.to_string();
            vol.mountpoint = new_mp.to_string_lossy().to_string();
            vol.anonymous = false;
            data.volumes[pos] = vol.clone();
            self.save_unlocked(&data)?;

            for c in c_store.list() {
                rewrite_volume_name_in_container(&c.bundle_path, old_name, new_name);
            }

            Ok(vol)
        })
    }

    pub fn remove_with_force(&self, name: &str, force: bool) -> Result<VolumeRecord> {
        let home = self
            .index_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let c_store = crate::storage::ContainerStore::with_home(home);
        let containers = c_store.list();

        if !force {
            for c in containers {
                if volume_used_by_container(&c.bundle_path, name) {
                    return Err(anyhow!(
                        "volume {} is being used by the following container(s): {}: volume is being used",
                        name,
                        c.id
                    ));
                }
            }
        } else {
            for c in &containers {
                if volume_used_by_container(&c.bundle_path, name) {
                    if matches!(
                        c.status,
                        crate::storage::ContainerStatus::Running
                            | crate::storage::ContainerStatus::Paused
                    ) {
                        let _ = c_store
                            .update_status(&c.id, crate::storage::ContainerStatus::Exited(0));
                    }
                    let _ = crate::remove_container_quiet(&c.id, true, false);
                }
            }
        }

        self.delete_volume_record(name)
    }

    pub fn list_filtered(&self, filters: &[String]) -> Vec<VolumeRecord> {
        let all_vols = self.list();
        let used = if filters.iter().any(|f| f.starts_with("dangling=")) {
            self.collect_used_volume_names()
        } else {
            std::collections::HashSet::new()
        };
        all_vols
            .iter()
            .filter(|v| Self::matches_filters_with_context(v, filters, &all_vols, &used))
            .cloned()
            .collect()
    }

    pub fn matches_filters(vol: &VolumeRecord, filters: &[String]) -> bool {
        if filters.is_empty() {
            return true;
        }
        let used = std::collections::HashSet::new();
        Self::matches_filters_with_context(vol, filters, &[], &used)
    }

    pub fn matches_filters_with_context(
        vol: &VolumeRecord,
        filters: &[String],
        all_vols: &[VolumeRecord],
        used_volume_names: &std::collections::HashSet<String>,
    ) -> bool {
        if filters.is_empty() {
            return true;
        }
        filters
            .iter()
            .all(|f| Self::matches_filter_with_context(vol, f, all_vols, used_volume_names))
    }

    pub fn matches_filter(vol: &VolumeRecord, filter: &str) -> bool {
        Self::matches_filter_with_context(vol, filter, &[], &std::collections::HashSet::new())
    }

    fn label_filter_matches(labels: &HashMap<String, String>, expr: &str) -> bool {
        if let Some((lk, lv)) = expr.split_once('=') {
            labels.get(lk).map(|v| v == lv).unwrap_or(false)
        } else if expr.contains('*') || expr.contains('?') {
            let re_str = format!(
                "^{}$",
                regex::escape(expr).replace(r"\*", ".*").replace(r"\?", ".")
            );
            if let Ok(re) = regex::Regex::new(&re_str) {
                labels.keys().any(|k| re.is_match(k))
            } else {
                labels.contains_key(expr)
            }
        } else {
            labels.contains_key(expr)
        }
    }

    pub fn matches_filter_with_context(
        vol: &VolumeRecord,
        filter: &str,
        all_vols: &[VolumeRecord],
        used_volume_names: &std::collections::HashSet<String>,
    ) -> bool {
        if let Some(neg_expr) = filter.strip_prefix("label!=") {
            return !Self::label_filter_matches(&vol.labels, neg_expr);
        }
        if let Some((key, value)) = filter.split_once('=') {
            match key {
                "name" => volume_name_filter_matches(&vol.name, value),
                "driver" => vol.driver == value,
                "scope" => vol.scope == value,
                "opt" => {
                    if let Some((ok, ov)) = value.split_once('=') {
                        vol.options.get(ok).map(|v| v == ov).unwrap_or(false)
                    } else {
                        vol.options.contains_key(value)
                    }
                }
                "label" => Self::label_filter_matches(&vol.labels, value),
                "dangling" => {
                    let is_dangling = !used_volume_names.contains(&vol.name);
                    if value == "true" || value == "1" {
                        is_dangling
                    } else if value == "false" || value == "0" {
                        !is_dangling
                    } else {
                        false
                    }
                }
                "until" => {
                    if let Ok(ts) = value.trim().parse::<i64>() {
                        vol.created_at.timestamp() < ts
                    } else if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(value.trim()) {
                        vol.created_at < dt.with_timezone(&Utc)
                    } else {
                        true
                    }
                }
                "since" | "after" => {
                    if let Some(target_pos) = all_vols.iter().position(|v| v.name == value) {
                        if let Some(self_pos) = all_vols.iter().position(|v| v.name == vol.name) {
                            return self_pos > target_pos;
                        }
                    }
                    if let Some(target) = all_vols.iter().find(|v| v.name == value) {
                        vol.created_at > target.created_at && vol.name != target.name
                    } else {
                        false
                    }
                }
                "all" => true,
                _ => true,
            }
        } else {
            true
        }
    }

    fn collect_used_volume_names(&self) -> std::collections::HashSet<String> {
        let home = self
            .index_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let c_store = crate::storage::ContainerStore::with_home(home);
        let mut used_volume_names = std::collections::HashSet::new();
        let volumes = self.list();
        for c in c_store.list() {
            let bundle_path = PathBuf::from(&c.bundle_path);
            let mounts_json = bundle_path.join("mounts.json");
            if mounts_json.exists() {
                if let Ok(content) = fs::read_to_string(&mounts_json) {
                    if let Ok(mounts) = serde_json::from_str::<Vec<MountSpec>>(&content) {
                        for m in mounts {
                            if !m.is_volume {
                                continue;
                            }
                            if let Some(vn) = &m.volume_name {
                                used_volume_names.insert(vn.clone());
                            }
                            let src = m.source.to_string_lossy();
                            for v in &volumes {
                                if src.contains(&format!("volumes/{}/_data", v.name))
                                    || src.contains(&format!("/volumes/{}/", v.name))
                                {
                                    used_volume_names.insert(v.name.clone());
                                }
                            }
                        }
                    }
                }
            }
            let config_file = bundle_path.join("config.json");
            if let Ok(content) = fs::read_to_string(&config_file) {
                if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&content) {
                    for m in spec.mounts {
                        let m_src = m.source;
                        for v in &volumes {
                            if m_src.contains(&format!("volumes/{}/_data", v.name))
                                || m_src.contains(&format!("volumes/{}", v.name))
                                || m_src.ends_with(&v.name)
                            {
                                used_volume_names.insert(v.name.clone());
                            }
                        }
                    }
                }
            }
        }
        used_volume_names
    }

    pub fn prune_candidates(&self, all: bool, filters: &[String]) -> Vec<String> {
        let used_volume_names = self.collect_used_volume_names();
        let all_vols = self.list();
        let filter_all = filters.iter().any(|f| f == "all=true" || f == "all=1");
        let has_non_all_filter = filters.iter().any(|f| !f.starts_with("all="));
        let include_named = all || filter_all || has_non_all_filter;

        all_vols
            .iter()
            .filter(|v| {
                let unused = !used_volume_names.contains(&v.name);
                let matches =
                    Self::matches_filters_with_context(v, filters, &all_vols, &used_volume_names);
                if include_named {
                    unused && matches
                } else {
                    unused && matches && v.anonymous
                }
            })
            .map(|v| v.name.clone())
            .collect()
    }

    pub fn prune_with_options(&self, all: bool, filters: &[String]) -> Result<Vec<String>> {
        let used_volume_names = self.collect_used_volume_names();
        let filter_all = filters.iter().any(|f| f == "all=true" || f == "all=1");
        let has_non_all_filter = filters.iter().any(|f| !f.starts_with("all="));
        let include_named = all || filter_all || has_non_all_filter;

        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let snapshot = data.volumes.clone();
            let mut pruned = Vec::new();
            data.volumes.retain(|v| {
                let unused = !used_volume_names.contains(&v.name);
                let matches =
                    Self::matches_filters_with_context(v, filters, &snapshot, &used_volume_names);
                let eligible = if include_named {
                    unused && matches
                } else {
                    unused && matches && v.anonymous
                };
                if eligible {
                    if v.driver != "image"
                        && v.options.get("type").map(|t| t.as_str()) != Some("bind")
                    {
                        let vol_dir = self.volumes_dir.join(&v.name);
                        if vol_dir.exists() {
                            if fs::remove_dir_all(&vol_dir).is_err() {
                                #[cfg(target_os = "linux")]
                                {
                                    let _ = crate::runtime::linux::chown_path_rootless(
                                        &vol_dir, 0, 0, true,
                                    );
                                }
                                crate::storage::container_store::make_tree_writable(&vol_dir);
                                let _ = fs::remove_dir_all(&vol_dir);
                            }
                        }
                    }
                    pruned.push(v.name.clone());
                    false
                } else {
                    true
                }
            });
            self.save_unlocked(&data)?;
            Ok(pruned)
        })
    }

    pub fn prune(&self) -> Result<Vec<String>> {
        self.prune_with_options(false, &[])
    }

    /// Parse a volume flag string:
    /// e.g. "my-vol:/data:ro", "/host/path:/container/path", "my-vol:/data"
    pub fn resolve_mount(&self, spec_str: &str) -> Result<MountSpec> {
        let trimmed = spec_str.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("Volume specification cannot be empty"));
        }

        let (source_str, dest_str, read_only, noexec, chown_u) =
            if let Some(idx) = trimmed.find(':') {
                let source_str = trimmed[..idx].to_string();
                let (dest_str, read_only, noexec, chown_u) =
                    parse_volume_dest_and_options(&trimmed[idx + 1..]);
                (source_str, dest_str, read_only, noexec, chown_u)
            } else if trimmed.starts_with('/') {
                // Podman/Docker: `-v /container/path` creates an anonymous volume at that path.
                let vol = self.create(None, None)?;
                return Ok(MountSpec {
                    source: PathBuf::from(vol.mountpoint),
                    destination: trimmed.to_string(),
                    is_volume: true,
                    volume_name: Some(vol.name),
                    ..Default::default()
                });
            } else {
                (String::new(), trimmed.to_string(), false, false, false)
            };

        if dest_str.trim().is_empty() {
            return Err(anyhow!("Volume destination path cannot be empty"));
        }

        if !dest_str.starts_with('/') || dest_str.contains("..") {
            return Err(anyhow!(
                "Invalid volume destination '{}': must be an absolute path and cannot contain '..'",
                dest_str
            ));
        }

        if source_str.is_empty() {
            // Create anonymous volume
            let vol = self.create(None, None)?;
            return Ok(MountSpec {
                source: PathBuf::from(vol.mountpoint),
                destination: dest_str.to_string(),
                read_only,
                noexec,
                is_volume: true,
                volume_name: Some(vol.name),
                ..Default::default()
            });
        }

        let is_host_path = source_str.starts_with('/')
            || source_str.starts_with('.')
            || source_str.starts_with('~');

        if is_host_path {
            if source_str.contains("..") {
                return Err(anyhow!(
                    "Path traversal rejected in volume mount: '{}'",
                    source_str
                ));
            }

            let host_path = if source_str.starts_with('~') {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                PathBuf::from(source_str.replacen('~', &home, 1))
            } else {
                PathBuf::from(&source_str)
            };

            let canonical_source = if host_path.exists() {
                host_path.canonicalize()?
            } else if fs::create_dir_all(&host_path).is_ok() {
                host_path.canonicalize().unwrap_or(host_path)
            } else {
                // Rootless Podman: missing bind sources get an empty stub dir under boxr home.
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(source_str.as_str().as_bytes());
                let stub = crate::storage::boxr_home()
                    .join("bind-stubs")
                    .join(hex::encode(hasher.finalize()));
                fs::create_dir_all(&stub)?;
                stub
            };

            Ok(MountSpec {
                source: canonical_source,
                destination: dest_str.to_string(),
                read_only,
                noexec,
                chown_u,
                is_volume: false,
                ..Default::default()
            })
        } else {
            // Named volume
            let record = match self.find(&source_str) {
                Some(v) => v,
                None => self.create(Some(&source_str), None)?,
            };
            let tmpfs_mount_data = tmpfs_mount_data_from_volume_options(&record.options);
            Ok(MountSpec {
                source: PathBuf::from(record.mountpoint),
                destination: dest_str.to_string(),
                read_only,
                noexec,
                chown_u,
                tmpfs_mount_data,
                volume_name: Some(record.name.clone()),
                subpath: None,
                propagation: None,
                is_volume: true,
            })
        }
    }

    pub fn set_volume_copy_flags(
        &self,
        name: &str,
        needs_copy_up: bool,
        needs_chown: bool,
    ) -> Result<()> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            if let Some(v) = data.volumes.iter_mut().find(|v| v.name == name) {
                v.needs_copy_up = needs_copy_up;
                v.needs_chown = needs_chown;
                self.save_unlocked(&data)?;
                Ok(())
            } else {
                Err(anyhow!("Volume '{}' not found", name))
            }
        })
    }

    pub fn set_volume_uid_gid(&self, name: &str, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            if let Some(v) = data.volumes.iter_mut().find(|v| v.name == name) {
                if uid.is_some() {
                    v.uid = uid;
                }
                if gid.is_some() {
                    v.gid = gid;
                }
                self.save_unlocked(&data)?;
                Ok(())
            } else {
                Err(anyhow!("Volume '{}' not found", name))
            }
        })
    }
}

impl VolumeReader for VolumeStore {
    fn find(&self, name: &str) -> Option<VolumeRecord> {
        self.find(name)
    }

    fn list(&self) -> Vec<VolumeRecord> {
        self.list()
    }
}

impl VolumeWriter for VolumeStore {
    fn create_with_options(
        &self,
        name: Option<&str>,
        driver: &str,
        labels: Option<HashMap<String, String>>,
        scope: &str,
        options: Option<HashMap<String, String>>,
    ) -> Result<VolumeRecord> {
        self.create_with_options(name, driver, labels, scope, options)
    }

    fn remove(&self, name: &str) -> Result<VolumeRecord> {
        self.remove(name)
    }

    fn prune(&self) -> Result<Vec<String>> {
        self.prune()
    }
}
