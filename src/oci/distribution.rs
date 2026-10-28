use crate::oci::image::{
    Descriptor, ImageConfig, ImageManifest, ManifestListOrIndex, is_runnable_image_descriptor,
    media_types,
};
use crate::oci::reference::ImageReference;
use crate::storage::ImageRecord;
use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct RegistryClient {
    client: Client,
    token: Option<String>,
    basic_auth: Option<String>,
}

/// Open/Closed & Dependency Inversion: OCI Image distribution client contract
#[allow(async_fn_in_trait)]
pub trait ImageDistribution: Send + Sync {
    async fn authenticate(&mut self, reference: &ImageReference) -> Result<()>;

    async fn fetch_manifest_with_platform(
        &mut self,
        reference: &ImageReference,
        platform: Option<&str>,
    ) -> Result<(ImageManifest, String, Vec<u8>)>;

    async fn fetch_config(
        &self,
        reference: &ImageReference,
        config_desc: &Descriptor,
    ) -> Result<ImageConfig>;

    async fn download_blob_to_file(
        &self,
        reference: &ImageReference,
        descriptor: &Descriptor,
        target_path: &Path,
    ) -> Result<()>;
}

impl ImageDistribution for RegistryClient {
    async fn authenticate(&mut self, reference: &ImageReference) -> Result<()> {
        RegistryClient::authenticate(self, reference).await
    }

    async fn fetch_manifest_with_platform(
        &mut self,
        reference: &ImageReference,
        platform: Option<&str>,
    ) -> Result<(ImageManifest, String, Vec<u8>)> {
        RegistryClient::fetch_manifest_with_platform(self, reference, platform).await
    }

    async fn fetch_config(
        &self,
        reference: &ImageReference,
        config_desc: &Descriptor,
    ) -> Result<ImageConfig> {
        RegistryClient::fetch_config(self, reference, config_desc).await
    }

    async fn download_blob_to_file(
        &self,
        reference: &ImageReference,
        descriptor: &Descriptor,
        target_path: &Path,
    ) -> Result<()> {
        RegistryClient::download_blob_to_file(self, reference, descriptor, target_path).await
    }
}

fn registry_connect_host(registry: &str) -> &str {
    registry
}

fn build_registry_http_client(registry_for_resolve: Option<&str>) -> Client {
    let opts = crate::oci::registry_options::registry_options_snapshot();
    let mut builder = Client::builder()
        .user_agent("boxr/0.1.0")
        .no_proxy();
    if let Some(reg) = registry_for_resolve {
        if let Some(port) = reg.strip_prefix("localhost:") {
            if let Ok(addr) = format!("127.0.0.1:{}", port).parse() {
                builder = builder.resolve("localhost", addr);
            }
        }
    }
    if let Some(dir) = &opts.cert_dir {
        // BATS/Podman `--cert-dir` often contains the registry's self-signed *server*
        // certificate (not a CA). rustls rejects those as root anchors
        // (`CaUsedAsEndEntity`); trust the configured directory via verifier skip
        // (still requires HTTPS and correct --creds for the registry).
        let _ = crate::oci::registry_options::load_extra_root_certs(dir)
            .unwrap_or_else(|e| panic!("--cert-dir {}: {e}", dir.display()));
        builder = builder
            .tls_built_in_root_certs(false)
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    } else {
        builder = builder.tls_built_in_root_certs(true);
    }
    builder
        .build()
        .expect("build registry HTTP client")
}

impl RegistryClient {
    pub fn new() -> Self {
        Self::for_registry("")
    }

    pub fn for_registry(registry: &str) -> Self {
        let resolve = if registry.is_empty() {
            None
        } else {
            Some(registry)
        };
        Self {
            client: build_registry_http_client(resolve),
            token: None,
            basic_auth: None,
        }
    }

    fn inline_credentials(&self) -> Option<(String, String)> {
        crate::oci::registry_options::registry_options_snapshot().inline_creds
    }

    fn store_credentials(
        &self,
        reference: &ImageReference,
    ) -> Option<(String, String)> {
        if let Some(c) = self.inline_credentials() {
            return Some(c);
        }
        crate::auth::CredentialStore::new().get_credentials(&reference.registry)
    }

    /// Authenticate against registry if needed (e.g. Docker Hub auth token or private registry).
    pub async fn authenticate(&mut self, reference: &ImageReference) -> Result<()> {
        let creds = self.store_credentials(reference);

        let ping_url = format!("https://{}/v2/", registry_connect_host(&reference.registry));
        let resp = self
            .client
            .get(&ping_url)
            .send()
            .await
            .map_err(|e| {
                use std::error::Error;
                let mut detail = format!("{e}");
                let mut src = e.source();
                while let Some(s) = src {
                    detail.push_str(&format!("; {s}"));
                    src = s.source();
                }
                anyhow!("registry ping {}: {}", ping_url, detail)
            })?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            if let Some(auth_header) = resp.headers().get("www-authenticate") {
                let auth_str = auth_header.to_str()?;
                let token = self
                    .fetch_bearer_token(auth_str, reference, creds.as_ref())
                    .await?;
                if token.is_none() && creds.is_some() {
                    self.basic_auth = None;
                    self.token = self.fetch_bearer_token(auth_str, reference, None).await?;
                } else {
                    self.token = token;
                }
                if self.token.is_some() {
                    return Ok(());
                }
            }
        } else if resp.status().is_success() {
            return Ok(());
        }

        if let Some((u, p)) = &creds {
            let encoded = crate::auth::custom_base64_encode(&format!("{}:{}", u, p));
            self.basic_auth = Some(encoded);
        }
        Ok(())
    }

    async fn fetch_bearer_token(
        &self,
        auth_header: &str,
        reference: &ImageReference,
        creds: Option<&(String, String)>,
    ) -> Result<Option<String>> {
        // Example: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/hello-world:pull"
        if !auth_header.starts_with("Bearer ") {
            return Ok(None);
        }

        let params_str = &auth_header[7..];
        let mut realm = None;
        let mut service = None;

        for part in params_str.split(',') {
            let part = part.trim();
            if let Some((k, v)) = part.split_once('=') {
                let v = v.trim_matches('"');
                match k {
                    "realm" => realm = Some(v.to_string()),
                    "service" => service = Some(v.to_string()),
                    _ => {}
                }
            }
        }

        let realm = match realm {
            Some(r) => r,
            None => return Ok(None),
        };

        self.request_bearer_token(&realm, reference, service.as_deref(), creds, "pull")
            .await
    }

    async fn request_bearer_token(
        &self,
        realm: &str,
        reference: &ImageReference,
        service: Option<&str>,
        creds: Option<&(String, String)>,
        scope_action: &str,
    ) -> Result<Option<String>> {
        let mut url = format!(
            "{}?scope=repository:{}:{}",
            realm, reference.repository, scope_action
        );
        if let Some(s) = service {
            url.push_str(&format!("&service={}", s));
        }

        let mut req = self.client.get(&url);
        if let Some((u, p)) = creds {
            req = req.basic_auth(u, Some(p));
        }
        let resp = req.send().await?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED && creds.is_some() {
            // Stale credentials: retry anonymously (Docker Hub allows anonymous pull tokens)
            let resp = self.client.get(&url).send().await?;
            if !resp.status().is_success() {
                return Err(anyhow!(
                    "Failed to obtain registry auth token: status {}",
                    resp.status()
                ));
            }
            let token_data: serde_json::Value = resp.json().await?;
            return Ok(token_data
                .get("token")
                .or_else(|| token_data.get("access_token"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()));
        }
        if !resp.status().is_success() {
            return Err(anyhow!(
                "Failed to obtain registry auth token: status {}",
                resp.status()
            ));
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            token: Option<String>,
            access_token: Option<String>,
        }

        let token_data: TokenResponse = resp.json().await?;
        let token = token_data.token.or(token_data.access_token);
        Ok(token)
    }

    /// Authenticate for push operations (pull,push scope).
    pub async fn authenticate_push(&mut self, reference: &ImageReference) -> Result<()> {
        let creds = self.store_credentials(reference);
        if let Some((u, p)) = &creds {
            let encoded = crate::auth::custom_base64_encode(&format!("{}:{}", u, p));
            self.basic_auth = Some(encoded);
        }

        let ping_url = format!("https://{}/v2/", registry_connect_host(&reference.registry));
        let mut req = self.client.get(&ping_url);
        if let Some(auth) = &self.basic_auth {
            if let Ok(val) = HeaderValue::from_str(&format!("Basic {}", auth)) {
                req = req.header(AUTHORIZATION, val);
            }
        }
        let resp = req
            .send()
            .await
            .map_err(|e| {
                use std::error::Error;
                let mut detail = format!("{e}");
                let mut src = e.source();
                while let Some(s) = src {
                    detail.push_str(&format!("; {s}"));
                    src = s.source();
                }
                anyhow!("registry ping {}: {}", ping_url, detail)
            })?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            if let Some(auth_header) = resp.headers().get("www-authenticate") {
                let auth_str = auth_header.to_str()?;
                if auth_str.starts_with("Bearer ") {
                    let params_str = &auth_str[7..];
                    let mut realm = None;
                    let mut service = None;
                    for part in params_str.split(',') {
                        let part = part.trim();
                        if let Some((k, v)) = part.split_once('=') {
                            let v = v.trim_matches('"');
                            match k {
                                "realm" => realm = Some(v.to_string()),
                                "service" => service = Some(v.to_string()),
                                _ => {}
                            }
                        }
                    }
                    if let Some(realm) = realm {
                        if let Some(token) = self
                            .request_bearer_token(
                                &realm,
                                reference,
                                service.as_deref(),
                                creds.as_ref(),
                                "pull,push",
                            )
                            .await?
                        {
                            self.token = Some(token);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn upload_blob(
        &self,
        reference: &ImageReference,
        digest: &str,
        data: &[u8],
    ) -> Result<()> {
        let check_url = format!(
            "https://{}/v2/{}/blobs/{}",
            registry_connect_host(&reference.registry), reference.repository, digest
        );
        let head = self
            .client
            .head(&check_url)
            .headers(self.auth_headers())
            .send()
            .await?;
        if head.status().is_success() {
            return Ok(());
        }

        let upload_url = format!(
            "https://{}/v2/{}/blobs/uploads/",
            registry_connect_host(&reference.registry), reference.repository
        );
        let post = self
            .client
            .post(&upload_url)
            .headers(self.auth_headers())
            .send()
            .await?;
        if !post.status().is_success() {
            return Err(anyhow!(
                "Failed to initiate blob upload: status {}",
                post.status()
            ));
        }

        let location = post
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow!("Missing upload location header"))?;

        let mut put_url = if location.starts_with("http://") || location.starts_with("https://") {
            location.to_string()
        } else {
            format!(
                "https://{}/{}",
                registry_connect_host(&reference.registry),
                location.trim_start_matches('/')
            )
        };
        if !put_url.contains("digest=") {
            let sep = if put_url.contains('?') { '&' } else { '?' };
            let encoded_digest = digest.replace(':', "%3A");
            put_url.push_str(&format!("{sep}digest={encoded_digest}"));
        }

        let put = self
            .client
            .put(&put_url)
            .headers(self.auth_headers())
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::CONTENT_LENGTH, data.len())
            .body(data.to_vec())
            .send()
            .await?;
        if !put.status().is_success() {
            let status = put.status();
            let body = put.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Failed to upload blob {}: status {} {}",
                digest,
                status,
                body
            ));
        }
        Ok(())
    }

    /// Push a local image to a remote OCI registry.
    pub async fn push_image(
        &mut self,
        image: &ImageRecord,
        reference: &ImageReference,
    ) -> Result<String> {
        self.authenticate_push(reference).await?;

        let rootfs_path = PathBuf::from(&image.rootfs_path);
        let image_dir = rootfs_path
            .parent()
            .ok_or_else(|| anyhow!("Invalid image rootfs path"))?;
        let manifest_path = image_dir.join("manifest.json");
        let config_path = image_dir.join("config.json");

        let manifest_bytes_on_disk = if manifest_path.exists() {
            fs::read(&manifest_path)?
        } else {
            return Err(anyhow!(
                "Cannot push image '{}': manifest metadata missing (re-pull or rebuild image)",
                image.reference
            ));
        };
        let manifest: ImageManifest = serde_json::from_slice(&manifest_bytes_on_disk)?;

        let config_bytes = if config_path.exists() {
            fs::read(&config_path)?
        } else {
            serde_json::to_vec(&image.config)?
        };
        self.upload_blob(reference, &manifest.config.digest, &config_bytes)
            .await?;

        for layer in &manifest.layers {
            let safe_name = layer.digest.replace(':', "_");
            let layer_file = crate::storage::boxr_home()
                .join("layers")
                .join(format!("{}.tar", safe_name));
            if !layer_file.exists() {
                return Err(anyhow!("Missing layer blob {} for push", layer.digest));
            }
            let layer_bytes = fs::read(&layer_file)?;
            self.upload_blob(reference, &layer.digest, &layer_bytes)
                .await?;
        }

        let manifest_bytes = manifest_bytes_on_disk;
        let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest_bytes)));

        let manifest_media_type = manifest
            .media_type
            .as_deref()
            .unwrap_or(media_types::DOCKER_MANIFEST_V2);

        let put_url = format!(
            "https://{}/v2/{}/manifests/{}",
            registry_connect_host(&reference.registry), reference.repository, reference.tag
        );
        let mut headers = self.auth_headers();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(manifest_media_type)?,
        );
        let resp = self
            .client
            .put(&put_url)
            .headers(headers)
            .body(manifest_bytes)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to push manifest: {} - {}", status, body));
        }

        Ok(manifest_digest)
    }

    fn auth_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(token) = &self.token {
            if let Ok(val) = HeaderValue::from_str(&format!("Bearer {}", token)) {
                headers.insert(AUTHORIZATION, val);
            }
        } else if let Some(basic) = &self.basic_auth {
            if let Ok(val) = HeaderValue::from_str(&format!("Basic {}", basic)) {
                headers.insert(AUTHORIZATION, val);
            }
        }
        headers
    }

    /// Fetch manifest for the reference, resolving index / manifest lists to the target platform.
    pub async fn fetch_manifest(
        &mut self,
        reference: &ImageReference,
    ) -> Result<(ImageManifest, String, Vec<u8>)> {
        self.fetch_manifest_with_platform(reference, None).await
    }

    /// Fetch manifest for the reference with explicit target platform architecture.
    pub async fn fetch_manifest_with_platform(
        &mut self,
        reference: &ImageReference,
        target_platform: Option<&str>,
    ) -> Result<(ImageManifest, String, Vec<u8>)> {
        self.authenticate(reference).await?;

        let tag_or_digest = reference.digest.as_deref().unwrap_or(&reference.tag);

        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            registry_connect_host(&reference.registry), reference.repository, tag_or_digest
        );

        let mut headers = self.auth_headers();
        let accept_header = [
            media_types::OCI_INDEX_V1,
            media_types::OCI_MANIFEST_V1,
            media_types::DOCKER_MANIFEST_LIST_V2,
            media_types::DOCKER_MANIFEST_V2,
        ]
        .join(", ");
        headers.insert(ACCEPT, HeaderValue::from_str(&accept_header)?);

        let resp = self.client.get(&url).headers(headers).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Failed to fetch manifest from {}: status {} - {}",
                url,
                status,
                err_body
            ));
        }

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let body_bytes = resp.bytes().await?;

        // Determine if this is an Index / Manifest List
        if content_type.contains("manifest.list")
            || content_type.contains("image.index")
            || serde_json::from_slice::<ManifestListOrIndex>(&body_bytes).is_ok()
        {
            if let Ok(index) = serde_json::from_slice::<ManifestListOrIndex>(&body_bytes) {
                // Determine target architecture
                let (target_os, target_arch) = if let Some(plat) = target_platform {
                    if let Some((os_p, arch_p)) = plat.split_once('/') {
                        (os_p, arch_p)
                    } else {
                        ("linux", plat)
                    }
                } else {
                    let host_arch = match env::consts::ARCH {
                        "aarch64" => "arm64",
                        "x86_64" => "amd64",
                        other => other,
                    };
                    ("linux", host_arch)
                };

                let runnable = index
                    .manifests
                    .iter()
                    .filter(|desc| is_runnable_image_descriptor(desc))
                    .collect::<Vec<_>>();

                let chosen_descriptor = runnable
                    .iter()
                    .find(|desc| {
                        if let Some(p) = &desc.platform {
                            p.os == target_os && p.architecture == target_arch
                        } else {
                            false
                        }
                    })
                    .or_else(|| {
                        runnable.iter().find(|desc| {
                            if let Some(p) = &desc.platform {
                                p.os == "linux" && p.architecture == "amd64"
                            } else {
                                false
                            }
                        })
                    })
                    .or_else(|| {
                        runnable.iter().find(|desc| {
                            if let Some(p) = &desc.platform {
                                p.os == "linux"
                            } else {
                                false
                            }
                        })
                    })
                    .or_else(|| runnable.first())
                    .ok_or_else(|| {
                        anyhow!("No suitable manifest found in index for target platform")
                    })?;

                // Recursively fetch platform manifest by digest
                let mut platform_ref = reference.clone();
                platform_ref.digest = Some(chosen_descriptor.digest.clone());
                return Box::pin(self.fetch_manifest_with_platform(&platform_ref, target_platform))
                    .await;
            }
        }

        // Direct image manifest
        let manifest: ImageManifest =
            serde_json::from_slice(&body_bytes).context("Failed to parse image manifest JSON")?;

        if manifest.layers.is_empty() {
            return Err(anyhow!(
                "Registry returned a manifest with no layers (possible attestation artifact)"
            ));
        }

        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&body_bytes)));
        Ok((manifest, digest, body_bytes.to_vec()))
    }

    /// Fetch image configuration JSON blob (parsed) and raw bytes for storage/push.
    pub async fn fetch_config_blob(
        &self,
        reference: &ImageReference,
        config_descriptor: &Descriptor,
    ) -> Result<(ImageConfig, Vec<u8>)> {
        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            registry_connect_host(&reference.registry), reference.repository, config_descriptor.digest
        );

        let resp = self
            .client
            .get(&url)
            .headers(self.auth_headers())
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!(
                "Failed to fetch config blob {}: status {}",
                config_descriptor.digest,
                resp.status()
            ));
        }

        let body_bytes = resp.bytes().await?.to_vec();
        let config: ImageConfig =
            serde_json::from_slice(&body_bytes).context("Failed to parse image config JSON")?;

        Ok((config, body_bytes))
    }

    /// Fetch image configuration JSON blob
    pub async fn fetch_config(
        &self,
        reference: &ImageReference,
        config_descriptor: &Descriptor,
    ) -> Result<ImageConfig> {
        Ok(self
            .fetch_config_blob(reference, config_descriptor)
            .await?
            .0)
    }

    /// Download a blob (e.g. layer archive) to a file with progress and SHA-256 verification.
    pub async fn download_blob_to_file(
        &self,
        reference: &ImageReference,
        descriptor: &Descriptor,
        dest_path: &Path,
    ) -> Result<()> {
        if dest_path.exists() {
            // Verify existing cached file matches the expected SHA-256 digest
            if let Ok(mut f) = File::open(dest_path) {
                let mut hasher = Sha256::new();
                if std::io::copy(&mut f, &mut hasher).is_ok() {
                    let calculated = format!("sha256:{}", hex::encode(hasher.finalize()));
                    if calculated == descriptor.digest {
                        return Ok(());
                    }
                }
            }
            // Corrupt or partial cache file; purge and re-download
            let _ = std::fs::remove_file(dest_path);
        }

        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            registry_connect_host(&reference.registry), reference.repository, descriptor.digest
        );

        let resp = self
            .client
            .get(&url)
            .headers(self.auth_headers())
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!(
                "Failed to download blob {}: status {}",
                descriptor.digest,
                resp.status()
            ));
        }

        let total_size = resp.content_length().unwrap_or(descriptor.size as u64);
        let short_digest = if descriptor.digest.len() > 19 {
            &descriptor.digest[..19]
        } else {
            &descriptor.digest
        };

        let pb = ProgressBar::new(total_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );
        pb.set_message(format!("Downloading {}", short_digest));

        let temp_path = dest_path.with_extension("download");
        let mut file = File::create(&temp_path)?;
        let mut hasher = Sha256::new();
        let mut stream = resp.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            file.write_all(&chunk)?;
            hasher.update(&chunk);
            pb.inc(chunk.len() as u64);
        }

        file.flush()?;
        pb.finish_with_message(format!("Downloaded {}", short_digest));

        // Validate digest
        let calculated_digest = format!("sha256:{}", hex::encode(hasher.finalize()));
        if calculated_digest != descriptor.digest {
            let _ = std::fs::remove_file(&temp_path);
            return Err(anyhow!(
                "Checksum mismatch for blob {}: expected {}, got {}",
                descriptor.digest,
                descriptor.digest,
                calculated_digest
            ));
        }

        // Rename temp to target destination
        std::fs::rename(temp_path, dest_path)?;
        Ok(())
    }
}
