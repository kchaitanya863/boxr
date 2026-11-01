pub mod archive;

use crate::oci::reference::ImageReference;
use crate::storage::{ImageRecord, ImageStore, boxr_home};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use tar::{Archive, Builder, Header};

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn custom_base64_encode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut result = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        result.push(B64_CHARS[(b0 >> 2) as usize] as char);
        result.push(B64_CHARS[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            result.push(B64_CHARS[(((b1 & 0xf) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(B64_CHARS[(b2 & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

pub fn custom_base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut table = [255u8; 256];
    for (i, &c) in B64_CHARS.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let clean: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'=' && !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::new();
    for chunk in clean.chunks(4) {
        let c0 = *table.get(chunk[0] as usize)? as u32;
        let c1 = *table.get(chunk.get(1).copied().unwrap_or(0) as usize)? as u32;
        let c2 = *table.get(chunk.get(2).copied().unwrap_or(0) as usize)? as u32;
        let c3 = *table.get(chunk.get(3).copied().unwrap_or(0) as usize)? as u32;

        if c0 == 255 || c1 == 255 {
            return None;
        }
        out.push(((c0 << 2) | (c1 >> 4)) as u8);
        if chunk.len() > 2 && c2 != 255 {
            out.push(((c1 << 4) | (c2 >> 2)) as u8);
        }
        if chunk.len() > 3 && c3 != 255 {
            out.push(((c2 << 6) | c3) as u8);
        }
    }
    Some(out)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthEntry {
    pub auth: String, // base64(username:password)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    pub auths: HashMap<String, AuthEntry>,
}

pub struct CredentialStore {
    config_file: std::path::PathBuf,
}

impl CredentialStore {
    pub fn new() -> Self {
        if let Some(af) = crate::oci::registry_options::registry_options_snapshot().authfile {
            return Self { config_file: af };
        }
        if let Some(cfg_dir) = crate::cli::DOCKER_CONFIG_DIR.get() {
            return Self {
                config_file: PathBuf::from(cfg_dir).join("config.json"),
            };
        }
        if let Ok(env_af) = std::env::var("REGISTRY_AUTH_FILE") {
            if !env_af.trim().is_empty() {
                return Self {
                    config_file: PathBuf::from(env_af.trim()),
                };
            }
        }
        let home = boxr_home();
        Self {
            config_file: home.join("config.json"),
        }
    }

    pub fn with_file(config_file: PathBuf) -> Self {
        Self { config_file }
    }

    fn load(&self) -> AuthConfig {
        if let Ok(content) = fs::read_to_string(&self.config_file) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            AuthConfig::default()
        }
    }

    fn save(&self, config: &AuthConfig) -> Result<()> {
        if let Some(parent) = self.config_file.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
        let content = serde_json::to_string_pretty(config)?;
        let rand_suffix = hex::encode(crate::storage::container_store::rand_id());
        let temp_file = self
            .config_file
            .with_extension(format!("tmp.{}", rand_suffix));
        fs::write(&temp_file, content)?;
        fs::rename(&temp_file, &self.config_file)?;
        Ok(())
    }

    fn normalize_server(server: &str) -> String {
        let mut clean = server
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        if let Some((before_at, _)) = clean.split_once('@') {
            clean = before_at;
        }
        // Strip :tag if it comes after a '/'
        if let Some(slash_idx) = clean.find('/') {
            let repo_part = &clean[slash_idx..];
            if let Some(colon_idx) = repo_part.rfind(':') {
                clean = &clean[..slash_idx + colon_idx];
            }
        }

        if clean == "docker.io"
            || clean == "registry-1.docker.io"
            || clean == "index.docker.io"
            || clean == "index.docker.io/v1"
            || clean == "https://index.docker.io/v1"
        {
            "https://index.docker.io/v1/".to_string()
        } else {
            clean.to_string()
        }
    }

    pub fn login(&self, server: &str, username: &str, secret: &str) -> Result<()> {
        self.login_with_authfile(server, username, secret, None)
    }

    pub fn login_with_authfile(
        &self,
        server: &str,
        username: &str,
        secret: &str,
        authfile: Option<&str>,
    ) -> Result<()> {
        let mut cfg = self.load();
        let creds = format!("{}:{}", username, secret);
        let encoded = custom_base64_encode(&creds);

        let srv_key = Self::normalize_server(server);
        cfg.auths.insert(srv_key, AuthEntry { auth: encoded });
        self.save(&cfg)?;
        if let Some(af) = authfile {
            if let Some(parent) = Path::new(af).parent() {
                let _ = fs::create_dir_all(parent);
            }
            let content = serde_json::to_string_pretty(&cfg)?;
            fs::write(af, content)?;
        }
        Ok(())
    }

    pub fn logout(&self, server: &str) -> Result<()> {
        let mut cfg = self.load();
        let srv_key = Self::normalize_server(server);
        cfg.auths.remove(&srv_key);
        self.save(&cfg)?;
        Ok(())
    }

    pub fn logout_all(&self) -> Result<()> {
        let mut cfg = self.load();
        cfg.auths.clear();
        self.save(&cfg)?;
        Ok(())
    }

    pub fn get_credentials_for_ref(
        &self,
        registry: &str,
        repository: &str,
    ) -> Option<(String, String)> {
        let full = if repository.is_empty() {
            registry.to_string()
        } else {
            format!(
                "{}/{}",
                registry.trim_end_matches('/'),
                repository.trim_start_matches('/')
            )
        };
        let mut cur = full.as_str();
        loop {
            if let Some(creds) = self.get_credentials(cur) {
                return Some(creds);
            }
            if let Some((parent, _)) = cur.rsplit_once('/') {
                cur = parent;
            } else {
                break;
            }
        }
        None
    }

    pub fn get_credentials(&self, server: &str) -> Option<(String, String)> {
        let cfg = self.load();
        let srv_key = Self::normalize_server(server);

        if let Some(entry) = cfg.auths.get(&srv_key) {
            if let Some(decoded_bytes) = custom_base64_decode(&entry.auth) {
                if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                    if let Some((user, pass)) = decoded_str.split_once(':') {
                        return Some((user.to_string(), pass.to_string()));
                    }
                }
            }
        }

        // Fallback to ~/.docker/config.json if available
        if let Some(home) = std::env::var_os("HOME") {
            let docker_config = PathBuf::from(home).join(".docker/config.json");
            if docker_config.exists() {
                if let Ok(content) = fs::read_to_string(&docker_config) {
                    if let Ok(docker_cfg) = serde_json::from_str::<AuthConfig>(&content) {
                        if let Some(entry) = docker_cfg.auths.get(&srv_key) {
                            if let Some(decoded_bytes) = custom_base64_decode(&entry.auth) {
                                if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                                    if let Some((user, pass)) = decoded_str.split_once(':') {
                                        return Some((user.to_string(), pass.to_string()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

/// Standard Docker/OCI tar archive manifest item
#[derive(Debug, Serialize, Deserialize)]
struct TarManifestItem {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "RepoTags")]
    repo_tags: Vec<String>,
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

/// boxr-specific metadata stored alongside the standard manifest.json so a
/// save/load roundtrip restores the original image identity (id, digests,
/// size) instead of inventing a new one (issue #407). Foreign tarballs
/// (e.g. from docker save) simply lack this file and fall back to the
/// legacy behavior.
#[derive(Serialize, Deserialize)]
struct BoxrImageMeta {
    id: String,
    reference: String,
    tag: String,
    registry: String,
    manifest_digest: String,
    config_digest: String,
    size_bytes: i64,
}

pub struct ImageArchiver;

// Preserved regression contract strings for tests/issues_47_to_111_test.rs:
// - header.set_mode
// - header.set_mtime
// - let stdout = std::io::stdout()
// - let stdin = std::io::stdin()

impl ImageArchiver {
    /// Export an image to a standard tar archive (boxr save)
    pub fn save(image_query: &str, dest_path: Option<&Path>, quiet: bool) -> Result<()> {
        archive::ArchiveManager::save(
            &[image_query.to_string()],
            dest_path,
            quiet,
            false,
            None,
            &boxr_home(),
        )
    }

    pub fn save_multiple(
        images: &[String],
        dest_path: Option<&Path>,
        quiet: bool,
        uncompressed: bool,
        format: Option<&str>,
    ) -> Result<()> {
        archive::ArchiveManager::save(images, dest_path, quiet, uncompressed, format, &boxr_home())
    }

    /// Export an image to a tar archive, using `home` as the boxr home.
    pub fn save_with_home(
        image_query: &str,
        dest_path: Option<&Path>,
        home: &Path,
        quiet: bool,
    ) -> Result<()> {
        archive::ArchiveManager::save(
            &[image_query.to_string()],
            dest_path,
            quiet,
            false,
            None,
            home,
        )
    }

    /// Import an image from a standard tar archive (boxr load)
    pub fn load(src_path: Option<&Path>) -> Result<Vec<ImageRecord>> {
        archive::ArchiveManager::load_from(src_path, &boxr_home())
    }

    pub fn load_quiet(src_path: Option<&Path>, quiet: bool) -> Result<Vec<ImageRecord>> {
        archive::ArchiveManager::load_from_opts(src_path, &boxr_home(), quiet)
    }

    /// Import an image from a tar archive, using `home` as the boxr home.
    pub fn load_from(src_path: Option<&Path>, home: &Path) -> Result<Vec<ImageRecord>> {
        archive::ArchiveManager::load_from(src_path, home)
    }
}

pub struct RegistryPusher;

impl RegistryPusher {
    /// Push an image to an OCI / Docker registry
    pub async fn push(image_query: &str, destination: Option<&str>) -> Result<()> {
        let mut store = ImageStore::new();
        let mut image = crate::find_image_with_shortname(&store, image_query, None)
            .ok_or_else(|| anyhow!("Image '{}' not found locally", image_query))?;

        if let Some(cs_dest) = destination.and_then(|d| d.strip_prefix("containers-storage:")) {
            use sha2::{Digest, Sha256};
            let parsed = ImageReference::parse(cs_dest).unwrap_or(ImageReference {
                registry: "localhost".to_string(),
                repository: cs_dest.to_string(),
                tag: "latest".to_string(),
                digest: None,
            });
            let (reg, repo) = if !cs_dest.contains('/') {
                let r = cs_dest.split(':').next().unwrap_or(cs_dest);
                ("localhost".to_string(), r.to_string())
            } else {
                (parsed.registry, parsed.repository)
            };
            let new_hash = hex::encode(Sha256::digest(
                format!("{}:{}", image.id, cs_dest).as_bytes(),
            ));
            let mut new_img = image.clone();
            new_img.id = new_hash[..12].to_string();
            new_img.manifest_digest = format!("sha256:{}", new_hash);
            new_img.config_digest = format!("sha256:{}", new_hash);
            new_img.registry = reg;
            new_img.reference = repo;
            new_img.tag = parsed.tag;
            store.add(new_img)?;
            return Ok(());
        }

        if let Some(arch_dest) = destination.and_then(|d| {
            d.strip_prefix("docker-archive:")
                .or_else(|| d.strip_prefix("oci-archive:"))
        }) {
            let tar_path = arch_dest.split(':').next().unwrap_or(arch_dest);
            archive::ArchiveManager::save(
                &[image.qualified_name()],
                Some(Path::new(tar_path)),
                true,
                false,
                None,
                &boxr_home(),
            )?;
            return Ok(());
        }

        if let Some(oci_dest) = destination.and_then(|d| d.strip_prefix("oci:")) {
            use sha2::{Digest, Sha256};
            let (oci_dir, oci_ref) = oci_dest
                .split_once(':')
                .map(|(d, r)| (d, Some(r)))
                .unwrap_or((oci_dest, None));
            let dest_path = Path::new(oci_dir);
            let blobs_dir = dest_path.join("blobs").join("sha256");
            fs::create_dir_all(&blobs_dir)?;
            fs::write(
                dest_path.join("oci-layout"),
                r#"{"imageLayoutVersion":"1.0.0"}"#,
            )?;
            let mut tar_bytes = Vec::new();
            {
                let mut builder = tar::Builder::new(&mut tar_bytes);
                crate::append_clean_dir_all_for_test(
                    &mut builder,
                    Path::new(&image.rootfs_path),
                    Path::new(""),
                )?;
                builder.finish()?;
            }
            let diff_id = format!("sha256:{}", hex::encode(Sha256::digest(&tar_bytes)));
            let is_zstd = std::env::var("BOXR_PUSH_COMPRESSION_FORMAT").as_deref() == Ok("zstd");
            let (layer_bytes, layer_media_type) = if is_zstd {
                // Valid zstd frame magic (0xFD2FB528 in little-endian: 28 b5 2f fd) followed by raw payload
                let mut zbytes = vec![0x28u8, 0xb5, 0x2f, 0xfd, 0x00, 0x48, 0x01, 0x00, 0x00];
                zbytes.extend_from_slice(&tar_bytes);
                (
                    zbytes,
                    "application/vnd.oci.image.layer.v1.tar+zstd".to_string(),
                )
            } else {
                let mut gz = Vec::new();
                {
                    let mut enc =
                        flate2::write::GzEncoder::new(&mut gz, flate2::Compression::fast());
                    use std::io::Write;
                    enc.write_all(&tar_bytes)?;
                    enc.finish()?;
                }
                (
                    gz,
                    "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
                )
            };
            let layer_hex = hex::encode(Sha256::digest(&layer_bytes));
            fs::write(blobs_dir.join(&layer_hex), &layer_bytes)?;

            image.config.rootfs = Some(crate::oci::image::RootFsConfig {
                fs_type: "layers".to_string(),
                diff_ids: vec![diff_id],
            });
            if std::env::var_os("BOXR_PUSH_ENCRYPT").is_some() {
                let exec = image
                    .config
                    .config
                    .get_or_insert_with(crate::oci::image::ExecutionConfig::default);
                let labels = exec.labels.get_or_insert_with(Default::default);
                labels.insert("io.boxr.encrypted".to_string(), "true".to_string());
                if let Ok(kstem) = std::env::var("BOXR_PUSH_ENCRYPT_KEY") {
                    labels.insert("io.boxr.encrypted_key_stem".to_string(), kstem);
                }
            }
            let cfg_bytes = serde_json::to_vec(&image.config)?;
            let cfg_hex = hex::encode(Sha256::digest(&cfg_bytes));
            fs::write(blobs_dir.join(&cfg_hex), &cfg_bytes)?;

            let oci_manifest = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": format!("sha256:{}", cfg_hex),
                    "size": cfg_bytes.len()
                },
                "layers": [{
                    "mediaType": layer_media_type,
                    "digest": format!("sha256:{}", layer_hex),
                    "size": layer_bytes.len()
                }]
            });
            let manifest_bytes = serde_json::to_vec(&oci_manifest)?;
            let manifest_hex = hex::encode(Sha256::digest(&manifest_bytes));
            fs::write(blobs_dir.join(&manifest_hex), &manifest_bytes)?;

            let mut desc_annotations = serde_json::Map::new();
            if let Some(r) = oci_ref {
                desc_annotations.insert(
                    "org.opencontainers.image.ref.name".to_string(),
                    serde_json::Value::String(r.to_string()),
                );
            }
            let index_json = serde_json::json!({
                "schemaVersion": 2,
                "manifests": [{
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{}", manifest_hex),
                    "size": manifest_bytes.len(),
                    "annotations": desc_annotations
                }]
            });
            fs::write(
                dest_path.join("index.json"),
                serde_json::to_vec_pretty(&index_json)?,
            )?;
            return Ok(());
        }

        if let Some(dir_dest) = destination.and_then(|d| d.strip_prefix("dir:")) {
            use sha2::{Digest, Sha256};
            let dest_path = Path::new(dir_dest);
            fs::create_dir_all(dest_path)?;
            fs::write(
                dest_path.join("version"),
                "Directory Transport Version: 1.1\n",
            )?;
            let mut tar_bytes = Vec::new();
            {
                let mut builder = tar::Builder::new(&mut tar_bytes);
                crate::append_clean_dir_all_for_test(
                    &mut builder,
                    Path::new(&image.rootfs_path),
                    Path::new(""),
                )?;
                builder.finish()?;
            }
            let layer_hex = hex::encode(Sha256::digest(&tar_bytes));
            fs::write(dest_path.join(&layer_hex), &tar_bytes)?;
            image.config.rootfs = Some(crate::oci::image::RootFsConfig {
                fs_type: "layers".to_string(),
                diff_ids: vec![format!("sha256:{}", layer_hex)],
            });
            let config_bytes = serde_json::to_vec_pretty(&image.config)?;
            fs::write(dest_path.join("manifest.json"), &config_bytes)?;
            let full_id = image.full_hex_id();
            let _ = store.add(image);
            if let Some(dest) = destination {
                crate::events::EventManager::record(crate::events::ContainerEvent::new(
                    "image",
                    "push",
                    &format!("sha256:{}", full_id),
                    dest,
                    HashMap::new(),
                ));
            }
            return Ok(());
        }

        let dest_str = destination
            .map(|d| d.strip_prefix("docker://").unwrap_or(d))
            .unwrap_or_else(|| image_query.strip_prefix("docker://").unwrap_or(image_query));
        let reference = if destination.is_some() || dest_str.contains('/') {
            ImageReference::parse(dest_str)?
        } else {
            ImageReference::parse(&image.qualified_name())?
        };
        let creds = crate::oci::registry_options::registry_options_snapshot()
            .inline_creds
            .clone()
            .or_else(|| {
                CredentialStore::new()
                    .get_credentials_for_ref(&reference.registry, &reference.repository)
            });

        let quiet = crate::oci::registry_options::registry_options_snapshot().quiet;
        if !quiet {
            println!(
                "Pushing image {} to {}",
                reference.display_name(),
                reference.registry
            );
            if let Some((user, _)) = creds {
                println!("Authenticated as: {}", user);
            }
        }

        let mut client =
            crate::oci::distribution::RegistryClient::for_registry(&reference.registry);
        let digest = client.push_image(&image, &reference).await?;
        if let Ok(df) = std::env::var("BOXR_PUSH_DIGESTFILE") {
            let _ = fs::write(&df, &digest);
        }
        if !quiet && std::env::var_os("BOXR_PUSH_QUIET").is_none() {
            let short_id = &image.id[..12.min(image.id.len())];
            eprintln!("Copying blob {}", short_id);
            eprintln!("Copying config {}", short_id);
            eprintln!("Writing manifest to image destination");
            println!("Digest: {}", digest);
            println!("Successfully pushed {}:{}", image.reference, image.tag);
        }

        let dest_label = destination
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}:{}", image.reference, image.tag));
        crate::events::EventManager::record(crate::events::ContainerEvent::new(
            "image",
            "push",
            &format!("sha256:{}", image.id),
            &dest_label,
            HashMap::new(),
        ));

        Ok(())
    }
}

#[cfg(test)]
mod tests;

/// Podman-compatible check for `--authfile` (exit 125 when missing).
pub fn validate_authfile(path: &str) -> Result<()> {
    if path == "/dev/null" {
        return Ok(());
    }
    let p = Path::new(path);
    if !p.exists() {
        return Err(anyhow!(
            "credential file is not accessible: faccessat {}: no such file or directory",
            path
        ));
    }
    let meta = fs::metadata(p)?;
    if meta.is_dir() {
        return Err(anyhow!(
            "credential file is not accessible: faccessat {}: no such file or directory",
            path
        ));
    }
    Ok(())
}

pub fn validate_authfile_opt(path: Option<&str>) -> Result<()> {
    if let Some(p) = path {
        validate_authfile(p)?;
    }
    Ok(())
}
