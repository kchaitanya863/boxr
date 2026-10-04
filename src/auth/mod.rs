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

impl ImageArchiver {
    /// Export an image to a standard tar archive (boxr save)
    pub fn save(image_query: &str, dest_path: Option<&Path>) -> Result<()> {
        Self::save_with_home(image_query, dest_path, &boxr_home())
    }

    /// Export an image to a tar archive, using `home` as the boxr home.
    pub fn save_with_home(image_query: &str, dest_path: Option<&Path>, home: &Path) -> Result<()> {
        let store = ImageStore::with_home(home.to_path_buf());
        let image = store
            .find(image_query)
            .ok_or_else(|| anyhow!("Image '{}' not found", image_query))?;

        if let Some(path) = dest_path {
            let file = File::create(path)
                .with_context(|| format!("Failed to create archive at {:?}", path))?;
            let mut builder = Builder::new(file);
            Self::pack_image_tar(&image, &mut builder)?;
            println!("Exported image {} to {:?}", image.reference, path);
        } else {
            let stdout = std::io::stdout();
            let mut builder = Builder::new(stdout.lock());
            Self::pack_image_tar(&image, &mut builder)?;
        }
        Ok(())
    }

    fn pack_image_tar<W: std::io::Write>(
        image: &ImageRecord,
        builder: &mut Builder<W>,
    ) -> Result<()> {
        // 1. Pack config JSON
        let config_filename = format!("{}.json", &image.config_digest.replace(':', "_"));
        let config_bytes = serde_json::to_vec_pretty(&image.config)?;

        let mut config_header = Header::new_gnu();
        config_header.set_size(config_bytes.len() as u64);
        config_header.set_mode(0o644);
        config_header.set_cksum();
        builder.append_data(&mut config_header, &config_filename, &config_bytes[..])?;

        // 2. Pack rootfs as a layer tar
        let layer_filename = "layer.tar";
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
        builder.append_data(&mut layer_header, layer_filename, &mut layer_file)?;

        // 3. Pack manifest.json
        let tag = format!("{}:{}", image.display_reference(), image.tag);
        let manifest_item = TarManifestItem {
            config: config_filename,
            repo_tags: vec![tag],
            layers: vec![layer_filename.to_string()],
        };
        let manifest_bytes = serde_json::to_vec_pretty(&vec![manifest_item])?;

        let mut manifest_header = Header::new_gnu();
        manifest_header.set_size(manifest_bytes.len() as u64);
        manifest_header.set_mode(0o644);
        manifest_header.set_cksum();
        builder.append_data(&mut manifest_header, "manifest.json", &manifest_bytes[..])?;

        // 4. Pack boxr metadata so load can restore the original identity.
        let meta = BoxrImageMeta {
            id: image.id.clone(),
            reference: image.reference.clone(),
            tag: image.tag.clone(),
            registry: image.registry.clone(),
            manifest_digest: image.manifest_digest.clone(),
            config_digest: image.config_digest.clone(),
            size_bytes: image.size_bytes,
        };
        let meta_bytes = serde_json::to_vec_pretty(&meta)?;

        let mut meta_header = Header::new_gnu();
        meta_header.set_size(meta_bytes.len() as u64);
        meta_header.set_mode(0o644);
        meta_header.set_cksum();
        builder.append_data(&mut meta_header, "boxr-meta.json", &meta_bytes[..])?;

        builder.finish()?;
        Ok(())
    }

    /// Import an image from a standard tar archive (boxr load)
    pub fn load(src_path: Option<&Path>) -> Result<Vec<ImageRecord>> {
        Self::load_from(src_path, &boxr_home())
    }

    /// Import an image from a tar archive, using `home` as the boxr home.
    pub fn load_from(src_path: Option<&Path>, home: &Path) -> Result<Vec<ImageRecord>> {
        let temp_dir = tempfile::tempdir()?;
        if let Some(path) = src_path {
            let file = File::open(path)
                .with_context(|| format!("Failed to open image archive at {:?}", path))?;
            let mut archive = Archive::new(file);
            crate::oci::image::unpack_archive_safely(&mut archive, temp_dir.path())?;
        } else {
            let stdin = std::io::stdin();
            let mut archive = Archive::new(stdin.lock());
            crate::oci::image::unpack_archive_safely(&mut archive, temp_dir.path())?;
        }

        let manifest_path = temp_dir.path().join("manifest.json");
        if !manifest_path.exists() {
            return Err(anyhow!("Invalid image archive: missing manifest.json"));
        }

        let manifest_content = fs::read_to_string(&manifest_path)?;
        let manifest_items: Vec<TarManifestItem> = serde_json::from_str(&manifest_content)?;

        // Tarballs written by boxr save carry the original image identity in
        // boxr-meta.json; foreign tarballs fall back to minting an identity.
        let boxr_meta: Option<BoxrImageMeta> = {
            let meta_path = temp_dir.path().join("boxr-meta.json");
            if meta_path.exists() {
                fs::read_to_string(&meta_path)
                    .ok()
                    .and_then(|content| serde_json::from_str(&content).ok())
            } else {
                None
            }
        };

        let store = ImageStore::with_home(home.to_path_buf());
        let mut loaded = Vec::new();

        for item in manifest_items {
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

            // Restore the original image identity when the tarball carries
            // boxr metadata; otherwise mint a fresh one (issue #407).
            let (short_id, manifest_digest, config_digest, size_bytes) = match &boxr_meta {
                Some(m) => (
                    m.id.clone(),
                    m.manifest_digest.clone(),
                    m.config_digest.clone(),
                    m.size_bytes,
                ),
                None => {
                    let random_id = hex::encode(crate::storage::container_store::rand_id());
                    let full_id = format!("sha256:{}", random_id);
                    (
                        random_id[..12].to_string(),
                        full_id.clone(),
                        full_id,
                        1024 * 1024,
                    )
                }
            };
            let image_id = manifest_digest.clone();
            let dest_rootfs = home
                .join("images")
                .join(image_id.replace(':', "_"))
                .join("rootfs");
            fs::create_dir_all(&dest_rootfs)?;

            // Unpack layers safely
            for layer in &item.layers {
                let layer_path = temp_dir.path().join(layer);
                if layer_path.exists() {
                    let mut layer_archive = Archive::new(File::open(layer_path)?);
                    crate::oci::image::unpack_archive_safely(&mut layer_archive, &dest_rootfs)?;
                }
            }

            for repo_tag in item.repo_tags {
                // Normalize so loaded tags store canonical registry/repo/tag.
                let parsed = crate::oci::reference::ImageReference::parse(&repo_tag).unwrap_or(
                    crate::oci::reference::ImageReference {
                        registry: crate::oci::reference::ImageReference::DEFAULT_REGISTRY
                            .to_string(),
                        repository: repo_tag.clone(),
                        tag: crate::oci::reference::ImageReference::DEFAULT_TAG.to_string(),
                        digest: None,
                    },
                );

                let record = ImageRecord {
                    id: short_id.clone(),
                    reference: parsed.repository,
                    tag: parsed.tag,
                    registry: parsed.registry,
                    manifest_digest: manifest_digest.clone(),
                    config_digest: config_digest.clone(),
                    size_bytes,
                    created_at: chrono::Utc::now(),
                    rootfs_path: dest_rootfs.to_string_lossy().to_string(),
                    config: config.clone(),
                };

                store.add(record.clone())?;
                println!("Loaded image: {}:{}", record.reference, record.tag);
                loaded.push(record);
            }
        }

        Ok(loaded)
    }

    fn append_dir_resilient(builder: &mut Builder<File>, base: &Path, rel: &Path) -> Result<()> {
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
            } else if ft.is_file() {
                if let Ok(mut f) = fs::File::open(&path) {
                    if let Ok(meta) = f.metadata() {
                        let mut header = Header::new_gnu();
                        header.set_size(meta.len());
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt;
                            header.set_mode(meta.mode());
                            header.set_uid(meta.uid() as u64);
                            header.set_gid(meta.gid() as u64);
                            header.set_mtime(meta.mtime() as u64);
                        }
                        #[cfg(not(unix))]
                        {
                            header.set_mode(0o644);
                        }
                        header.set_cksum();
                        let _ = builder.append_data(&mut header, &entry_rel, &mut f);
                    }
                }
            } else if ft.is_symlink() {
                // Archive symlinks explicitly so the restored rootfs keeps
                // them (e.g. /bin/sh -> busybox). Without this, loaded images
                // silently lose executables and fail to run (issue #407).
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
}

pub struct RegistryPusher;

impl RegistryPusher {
    /// Push an image to an OCI / Docker registry
    pub async fn push(image_query: &str) -> Result<()> {
        let store = ImageStore::new();
        let image = store
            .find(image_query)
            .ok_or_else(|| anyhow!("Image '{}' not found locally", image_query))?;

        let reference = ImageReference::parse(&format!("{}:{}", image.reference, image.tag))?;
        let creds = CredentialStore::new().get_credentials(&reference.registry);

        println!(
            "Pushing image {} to {}",
            reference.display_name(),
            reference.registry
        );
        if let Some((user, _)) = creds {
            println!("Authenticated as: {}", user);
        }

        let mut client = crate::oci::distribution::RegistryClient::new();
        let digest = client.push_image(&image, &reference).await?;
        println!("Digest: {}", digest);
        println!("Successfully pushed {}:{}", image.reference, image.tag);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Points $HOME at a temp dir for the duration of a test, then restores it.
    /// Needed because `get_credentials` falls back to ~/.docker/config.json for
    /// Docker compatibility, which would otherwise leak whatever credentials
    /// happen to exist on the machine running the tests.
    struct HomeGuard {
        orig: Option<std::ffi::OsString>,
    }

    impl HomeGuard {
        fn isolate_to(path: &std::path::Path) -> Self {
            let orig = std::env::var_os("HOME");
            // SAFETY: the test suite runs single-threaded (--test-threads=1) and
            // no other test in this binary reads or writes HOME concurrently.
            unsafe { std::env::set_var("HOME", path) };
            Self { orig }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            // SAFETY: same as above; the guard restores the previous value.
            unsafe {
                match self.orig.take() {
                    Some(h) => std::env::set_var("HOME", h),
                    None => std::env::remove_var("HOME"),
                }
            }
        }
    }

    #[test]
    fn test_credential_store_login_logout() {
        let temp = tempdir().unwrap();
        let _home_guard = HomeGuard::isolate_to(temp.path());
        let store = CredentialStore {
            config_file: temp.path().join("config.json"),
        };

        store.login("docker.io", "testuser", "secret123").unwrap();
        let creds = store.get_credentials("docker.io").unwrap();
        assert_eq!(creds.0, "testuser");
        assert_eq!(creds.1, "secret123");

        store.logout("docker.io").unwrap();
        assert!(store.get_credentials("docker.io").is_none());

        // Test server normalization for https:// and index.docker.io
        store
            .login("https://index.docker.io/v1/", "hubuser", "token999")
            .unwrap();
        let creds2 = store.get_credentials("registry-1.docker.io").unwrap();
        assert_eq!(creds2.0, "hubuser");
        assert_eq!(creds2.1, "token999");
    }

    // Issue #407: save/load roundtrip must preserve the image identity and
    // produce a runnable rootfs (symlinks intact). Previously load minted a
    // random id, hardcoded size_bytes to 1MB, and save silently dropped
    // symlinks, leaving an unrunnable image.
    #[cfg(unix)]
    #[test]
    fn test_issue_407_save_load_roundtrip() {
        use crate::oci::image::ImageConfig;

        let home = tempdir().unwrap();

        // Build a fake image whose rootfs contains a file and a symlink,
        // mirroring the alpine layout that exposed this bug.
        let img_dir = home.path().join("images").join("sha256_aaa").join("rootfs");
        let bin_dir = img_dir.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(bin_dir.join("busybox"), b"fake-busybox").unwrap();
        std::os::unix::fs::symlink("busybox", bin_dir.join("sh")).unwrap();

        let store = ImageStore::with_home(home.path().to_path_buf());
        // Use the host architecture so ImageStore::find (which filters by
        // platform) matches on any CI runner (amd64 or arm64).
        let host_arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        let record = ImageRecord {
            id: "aaa111bbb222".to_string(),
            reference: "library/testimg".to_string(),
            tag: "latest".to_string(),
            registry: "registry-1.docker.io".to_string(),
            manifest_digest: "sha256:aaa".to_string(),
            config_digest: "sha256:cfg".to_string(),
            size_bytes: 4242,
            created_at: chrono::Utc::now(),
            rootfs_path: img_dir.to_string_lossy().to_string(),
            config: ImageConfig {
                architecture: host_arch.to_string(),
                os: "linux".to_string(),
                config: None,
                rootfs: None,
                history: Vec::new(),
            },
        };
        store.add(record).unwrap();

        // Save, wipe the original, then load.
        let tar_path = home.path().join("testimg.tar");
        ImageArchiver::save_with_home("testimg:latest", Some(&tar_path), home.path()).unwrap();
        store.remove("testimg:latest").unwrap();
        assert!(store.find("testimg:latest").is_none());

        let loaded = ImageArchiver::load_from(Some(&tar_path), home.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        let rec = &loaded[0];

        // Identity preserved.
        assert_eq!(rec.id, "aaa111bbb222");
        assert_eq!(rec.manifest_digest, "sha256:aaa");
        assert_eq!(rec.config_digest, "sha256:cfg");
        assert_eq!(rec.size_bytes, 4242);
        assert_eq!(rec.reference, "library/testimg");
        assert_eq!(rec.tag, "latest");

        // Rootfs restored with the symlink intact.
        let link_target =
            std::fs::read_link(Path::new(&rec.rootfs_path).join("bin").join("sh")).unwrap();
        assert_eq!(link_target, PathBuf::from("busybox"));
        assert!(
            Path::new(&rec.rootfs_path)
                .join("bin")
                .join("busybox")
                .exists()
        );
    }
}
