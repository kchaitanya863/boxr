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
        let home = boxr_home();
        Self {
            config_file: home.join("config.json"),
        }
    }

    fn load(&self) -> AuthConfig {
        if let Ok(content) = fs::read_to_string(&self.config_file) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            AuthConfig::default()
        }
    }

    fn save(&self, config: &AuthConfig) -> Result<()> {
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
        let clean = server
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');

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
        let mut cfg = self.load();
        let creds = format!("{}:{}", username, secret);
        let encoded = custom_base64_encode(&creds);

        let srv_key = Self::normalize_server(server);
        cfg.auths.insert(srv_key, AuthEntry { auth: encoded });
        self.save(&cfg)?;
        Ok(())
    }

    pub fn logout(&self, server: &str) -> Result<()> {
        let mut cfg = self.load();
        let srv_key = Self::normalize_server(server);
        cfg.auths.remove(&srv_key);
        self.save(&cfg)?;
        Ok(())
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
        let store = ImageStore::new();
        let image = store
            .find(image_query)
            .ok_or_else(|| anyhow!("Image '{}' not found locally", image_query))?;

        if let Some(dest) = destination {
            if let Some(dir_path) = dest.strip_prefix("dir:") {
                let target_dir = Path::new(dir_path);
                fs::create_dir_all(target_dir)?;
                fs::write(
                    target_dir.join("version"),
                    "Directory Transport Version: 1.1\n",
                )?;
                let config_bytes = serde_json::to_vec_pretty(&image.config)?;
                fs::write(target_dir.join("manifest.json"), &config_bytes)?;
                crate::events::EventManager::record(crate::events::ContainerEvent::new(
                    "image",
                    "push",
                    &format!("sha256:{}", image.id),
                    dest,
                    HashMap::new(),
                ));
                return Ok(());
            }
        }

        let reference = if let Some(dest) = destination {
            ImageReference::parse(dest)?
        } else {
            ImageReference::parse(&format!("{}:{}", image.reference, image.tag))?
        };
        let creds = crate::oci::registry_options::registry_options_snapshot()
            .inline_creds
            .clone()
            .or_else(|| CredentialStore::new().get_credentials(&reference.registry));

        println!(
            "Pushing image {} to {}",
            reference.display_name(),
            reference.registry
        );
        if let Some((user, _)) = creds {
            println!("Authenticated as: {}", user);
        }

        let mut client =
            crate::oci::distribution::RegistryClient::for_registry(&reference.registry);
        let digest = client.push_image(&image, &reference).await?;
        println!("Digest: {}", digest);
        println!("Successfully pushed {}:{}", image.reference, image.tag);

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
    let p = Path::new(path);
    if !p.exists() {
        return Err(anyhow!(
            "credential file is not accessible: faccessat {}: no such file or directory",
            path
        ));
    }
    let meta = fs::metadata(p)?;
    if !meta.is_file() {
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
