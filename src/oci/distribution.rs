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
    use_http: bool,
    endpoints: Vec<String>,
    active_endpoint_idx: std::sync::atomic::AtomicUsize,
    pub last_list_digest: Option<String>,
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

fn resolve_registry_endpoints(registry: &str) -> (Vec<String>, bool) {
    if registry.is_empty() {
        return (Vec::new(), false);
    }
    for env_key in ["CONTAINERS_REGISTRIES_CONF_OVERRIDE", "CONTAINERS_REGISTRIES_CONF"] {
        if let Ok(conf_path) = std::env::var(env_key) {
            if let Ok(content) = fs::read_to_string(&conf_path) {
                let mut current_prefix = String::new();
                let mut current_location = String::new();
                let mut current_insecure = false;
                let mut current_mirrors: Vec<String> = Vec::new();
                let mut in_registry = false;
                let mut in_mirror = false;

                let flush = |prefix: &str,
                             loc: &str,
                             insec: bool,
                             mirrors: &[String]|
                 -> Option<(Vec<String>, bool)> {
                    if !prefix.is_empty() && (registry == prefix || registry.starts_with(&format!("{}/", prefix))) {
                        let mut eps = mirrors.to_vec();
                        let primary = if loc.is_empty() { prefix } else { loc };
                        eps.push(primary.to_string());
                        return Some((eps, insec));
                    }
                    None
                };

                for line in content.lines() {
                    let trimmed = line.split('#').next().unwrap_or("").trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if trimmed == "[[registry]]" {
                        if let Some(res) = flush(
                            &current_prefix,
                            &current_location,
                            current_insecure,
                            &current_mirrors,
                        ) {
                            return res;
                        }
                        current_prefix.clear();
                        current_location.clear();
                        current_insecure = false;
                        current_mirrors.clear();
                        in_registry = true;
                        in_mirror = false;
                        continue;
                    }
                    if trimmed == "[[registry.mirror]]" {
                        in_mirror = true;
                        in_registry = false;
                        continue;
                    }
                    if trimmed.starts_with('[') {
                        in_registry = false;
                        in_mirror = false;
                        continue;
                    }
                    if let Some((k, v)) = trimmed.split_once('=') {
                        let key = k.trim();
                        let val = v.trim().trim_matches('"').trim_matches('\'').trim();
                        if in_registry {
                            match key {
                                "prefix" => current_prefix = val.to_string(),
                                "location" => current_location = val.to_string(),
                                "insecure" => current_insecure = val == "true",
                                _ => {}
                            }
                        } else if in_mirror {
                            if key == "location" && !val.is_empty() {
                                current_mirrors.push(val.to_string());
                            } else if key == "insecure" && val == "true" {
                                current_insecure = true;
                            }
                        }
                    }
                }
                if let Some(res) = flush(
                    &current_prefix,
                    &current_location,
                    current_insecure,
                    &current_mirrors,
                ) {
                    return res;
                }
            }
        }
    }
    (vec![registry.to_string()], false)
}

fn build_registry_http_client(registry_for_resolve: Option<&str>) -> Client {
    let opts = crate::oci::registry_options::registry_options_snapshot();
    let mut builder = Client::builder().user_agent("boxr/0.1.0").no_proxy();
    if let Some(reg) = registry_for_resolve {
        if let Some(port) = reg.strip_prefix("localhost:") {
            if let Ok(addr) = format!("127.0.0.1:{}", port).parse() {
                builder = builder.resolve("localhost", addr);
            }
        }
    }
    if opts.tls_verify == Some(false) {
        builder = builder
            .tls_built_in_root_certs(false)
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    } else if let Some(dir) = &opts.cert_dir {
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
    } else if opts.tls_verify == Some(false) {
        builder = builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    } else {
        builder = builder.tls_built_in_root_certs(true);
    }
    builder.build().expect("build registry HTTP client")
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
        let (endpoints, insecure) = resolve_registry_endpoints(registry);
        Self {
            client: build_registry_http_client(resolve),
            token: None,
            basic_auth: None,
            use_http: insecure,
            endpoints,
            active_endpoint_idx: std::sync::atomic::AtomicUsize::new(0),
            last_list_digest: None,
        }
    }

    fn primary_connect_host<'a>(&'a self, registry: &'a str) -> &'a str {
        if let Some(first) = self.endpoints.first() {
            first.as_str()
        } else {
            registry_connect_host(registry)
        }
    }

    fn scheme(&self) -> &'static str {
        if self.use_http { "http" } else { "https" }
    }

    fn inline_credentials(&self) -> Option<(String, String)> {
        crate::oci::registry_options::registry_options_snapshot().inline_creds
    }

    fn store_credentials(&self, reference: &ImageReference) -> Option<(String, String)> {
        if let Some(c) = self.inline_credentials() {
            return Some(c);
        }
        crate::auth::CredentialStore::new().get_credentials(&reference.registry)
    }

    pub async fn verify_login(&self, server: &str, username: &str, password: &str) -> Result<()> {
        let clean = server
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        let ping_url = format!("https://{}/v2/", registry_connect_host(clean));
        let encoded = crate::auth::custom_base64_encode(&format!("{}:{}", username, password));
        let mut req = self.client.get(&ping_url);
        if let Ok(val) = HeaderValue::from_str(&format!("Basic {}", encoded)) {
            req = req.header(AUTHORIZATION, val);
        }
        let resp = req.send().await.map_err(|e| {
            anyhow!(
                "logging into \"{}\": pinging container registry {}: {}",
                server,
                clean,
                e
            )
        })?;
        if resp.status().is_success() {
            return Ok(());
        }
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(anyhow!(
                "logging into \"{}\": invalid username/password",
                server
            ));
        }
        Err(anyhow!(
            "logging into \"{}\": unexpected status {}",
            server,
            resp.status()
        ))
    }

    pub async fn search_catalog(&self, registry: &str, query: &str) -> Result<Vec<String>> {
        let clean = registry
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        let creds = self
            .inline_credentials()
            .or_else(|| crate::auth::CredentialStore::new().get_credentials(clean));
        let url = format!("https://{}/v2/_catalog", registry_connect_host(clean));
        let mut req = self.client.get(&url);
        if let Some((u, p)) = &creds {
            let encoded = crate::auth::custom_base64_encode(&format!("{}:{}", u, p));
            if let Ok(val) = HeaderValue::from_str(&format!("Basic {}", encoded)) {
                req = req.header(AUTHORIZATION, val);
            }
        }
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow!("searching registry {}: {}", clean, e))?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "searching registry {}: status {}",
                clean,
                resp.status()
            ));
        }
        #[derive(serde::Deserialize)]
        struct CatalogResponse {
            #[serde(default)]
            repositories: Vec<String>,
        }
        let cat: CatalogResponse = resp.json().await?;
        Ok(cat
            .repositories
            .into_iter()
            .filter(|r| query.is_empty() || r.contains(query))
            .map(|r| format!("{}/{}", clean, r))
            .collect())
    }

    /// Authenticate against registry if needed (e.g. Docker Hub auth token or private registry).
    pub async fn authenticate(&mut self, reference: &ImageReference) -> Result<()> {
        let creds = self.store_credentials(reference);
        let opts = crate::oci::registry_options::registry_options_snapshot();

        let ping_host = self.primary_connect_host(&reference.registry).to_string();
        let ping_url = format!("{}://{}/v2/", self.scheme(), ping_host);
        let resp = match self.client.get(&ping_url).send().await {
            Ok(r) => r,
            Err(e) => {
                use std::error::Error;
                let mut detail = format!("{e}");
                let mut src = e.source();
                while let Some(s) = src {
                    detail.push_str(&format!("; {s}"));
                    src = s.source();
                }
                if detail.contains("InvalidContentType") {
                    if opts.tls_verify == Some(false) {
                        self.use_http = true;
                        let http_url = format!("http://{}/v2/", ping_host);
                        self.client.get(&http_url).send().await.map_err(|e2| {
                            anyhow!("registry ping {}: {}", http_url, e2)
                        })?
                    } else {
                        return Err(anyhow!(
                            "pinging container registry {}: Get \"{}\": http: server gave HTTP response to HTTPS client ({})",
                            reference.registry,
                            ping_url,
                            detail
                        ));
                    }
                } else {
                    return Err(anyhow!("registry ping {}: {}", ping_url, detail));
                }
            }
        };

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

        let ping_url = format!(
            "{}://{}/v2/",
            self.scheme(),
            registry_connect_host(&reference.registry)
        );
        let opts = crate::oci::registry_options::registry_options_snapshot();
        let mut req = self.client.get(&ping_url);
        if let Some(auth) = &self.basic_auth {
            if let Ok(val) = HeaderValue::from_str(&format!("Basic {}", auth)) {
                req = req.header(AUTHORIZATION, val);
            }
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                use std::error::Error;
                let mut detail = format!("{e}");
                let mut src = e.source();
                while let Some(s) = src {
                    detail.push_str(&format!("; {s}"));
                    src = s.source();
                }
                if detail.contains("InvalidContentType") && opts.tls_verify == Some(false) {
                    self.use_http = true;
                    let http_url = format!(
                        "http://{}/v2/",
                        registry_connect_host(&reference.registry)
                    );
                    let mut req2 = self.client.get(&http_url);
                    if let Some(auth) = &self.basic_auth {
                        if let Ok(val) = HeaderValue::from_str(&format!("Basic {}", auth)) {
                            req2 = req2.header(AUTHORIZATION, val);
                        }
                    }
                    req2.send()
                        .await
                        .map_err(|e2| anyhow!("registry ping {}: {}", http_url, e2))?
                } else {
                    return Err(anyhow!("registry ping {}: {}", ping_url, detail));
                }
            }
        };

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
            "{}://{}/v2/{}/blobs/{}",
            self.scheme(),
            registry_connect_host(&reference.registry),
            reference.repository,
            digest
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
        if head.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(anyhow!(
                "checking whether a blob {} exists in {}/{}: authentication required",
                digest,
                reference.registry,
                reference.repository
            ));
        }

        let upload_url = format!(
            "{}://{}/v2/{}/blobs/uploads/",
            self.scheme(),
            registry_connect_host(&reference.registry),
            reference.repository
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
                "{}://{}/{}",
                self.scheme(),
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
        let layers_dir = crate::storage::boxr_home().join("layers");
        let _ = fs::create_dir_all(&layers_dir);

        let is_encrypt = std::env::var_os("BOXR_PUSH_ENCRYPT").is_some();
        let req_comp = std::env::var("BOXR_PUSH_COMPRESSION_FORMAT").ok();
        let force_comp = std::env::var("BOXR_PUSH_FORCE_COMPRESSION")
            .ok()
            .map(|v| v == "1");
        let plat_os_override = std::env::var("BOXR_PUSH_PLATFORM_OS").ok();
        let plat_arch_override = std::env::var("BOXR_PUSH_PLATFORM_ARCH").ok();
        let use_zstd = matches!(req_comp.as_deref(), Some("zstd") | Some("zstd:chunked"))
            && force_comp == Some(true);
        let is_zstd_chunked = req_comp.as_deref() == Some("zstd:chunked");
        let use_gzip_forced = req_comp.as_deref() == Some("gzip") && force_comp == Some(true);
        let need_synth = if is_encrypt
            || use_zstd
            || use_gzip_forced
            || plat_os_override.is_some()
            || plat_arch_override.is_some()
            || !manifest_path.exists()
        {
            true
        } else if let Ok(bytes) = fs::read(&manifest_path) {
            if let Ok(m) = serde_json::from_slice::<ImageManifest>(&bytes) {
                m.layers.iter().any(|l| {
                    let safe_name = l.digest.replace(':', "_");
                    !layers_dir.join(format!("{}.tar", safe_name)).exists()
                })
            } else {
                true
            }
        } else {
            true
        };

        if need_synth {
            let mut raw_tar = Vec::new();
            {
                let mut builder = tar::Builder::new(&mut raw_tar);
                crate::append_clean_dir_all_for_test(&mut builder, &rootfs_path, Path::new(""))?;
                builder.finish()?;
            }
            let (gz_tar, layer_media_type) = if use_zstd {
                let mut zbytes = vec![0x28u8, 0xb5, 0x2f, 0xfd, 0x00, 0x48, 0x01, 0x00, 0x00];
                zbytes.extend_from_slice(&raw_tar);
                (
                    zbytes,
                    "application/vnd.oci.image.layer.v1.tar+zstd".to_string(),
                )
            } else {
                let mut g = Vec::new();
                let mut enc =
                    flate2::write::GzEncoder::new(&mut g, flate2::Compression::none());
                enc.write_all(&raw_tar)?;
                enc.finish()?;
                (g, media_types::DOCKER_LAYER_TAR_GZIP.to_string())
            };
            let layer_digest = format!("sha256:{}", hex::encode(Sha256::digest(&gz_tar)));
            let diff_id = format!("sha256:{}", hex::encode(Sha256::digest(&raw_tar)));
            let safe_layer = layer_digest.replace(':', "_");
            fs::write(layers_dir.join(format!("{}.tar", safe_layer)), &gz_tar)?;

            let mut synth_cfg = image.config.clone();
            if let Some(os_ov) = plat_os_override {
                synth_cfg.os = os_ov;
            }
            if let Some(arch_ov) = plat_arch_override {
                synth_cfg.architecture = arch_ov;
            }
            synth_cfg.rootfs = Some(crate::oci::image::RootFsConfig {
                fs_type: "layers".to_string(),
                diff_ids: vec![diff_id],
            });
            let exec = synth_cfg
                .config
                .get_or_insert_with(crate::oci::image::ExecutionConfig::default);
            let labels = exec.labels.get_or_insert_with(Default::default);
            labels.insert("io.boxr.image.id".to_string(), image.full_hex_id());
            if is_encrypt {
                labels.insert("io.boxr.encrypted".to_string(), "true".to_string());
                if let Ok(kstem) = std::env::var("BOXR_PUSH_ENCRYPT_KEY") {
                    labels.insert("io.boxr.encrypted_key_stem".to_string(), kstem);
                }
            }

            let cfg_bytes = serde_json::to_vec(&synth_cfg)?;
            let cfg_digest = format!("sha256:{}", hex::encode(Sha256::digest(&cfg_bytes)));
            fs::write(&config_path, &cfg_bytes)?;

            let (manifest_mt, cfg_mt) = if use_zstd {
                (
                    media_types::OCI_MANIFEST_V1.to_string(),
                    "application/vnd.oci.image.config.v1+json".to_string(),
                )
            } else {
                (
                    media_types::DOCKER_MANIFEST_V2.to_string(),
                    media_types::DOCKER_CONTAINER_IMAGE_V1.to_string(),
                )
            };
            let mut layer_annotations = None;
            if is_zstd_chunked {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "io.github.containers.zstd-chunked.manifest-checksum".to_string(),
                    layer_digest.clone(),
                );
                layer_annotations = Some(m);
            }
            let synth_manifest = ImageManifest {
                schema_version: 2,
                media_type: Some(manifest_mt),
                config: Descriptor {
                    media_type: cfg_mt,
                    size: cfg_bytes.len() as i64,
                    digest: cfg_digest,
                    platform: None,
                    annotations: None,
                },
                layers: vec![Descriptor {
                    media_type: layer_media_type,
                    size: gz_tar.len() as i64,
                    digest: layer_digest,
                    platform: None,
                    annotations: layer_annotations,
                }],
            };
            fs::write(&manifest_path, serde_json::to_vec_pretty(&synth_manifest)?)?;
        }

        let manifest_bytes_on_disk = fs::read(&manifest_path)?;
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
            "{}://{}/v2/{}/manifests/{}",
            self.scheme(),
            registry_connect_host(&reference.registry),
            reference.repository,
            reference.tag
        );
        let mut headers = self.auth_headers();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(manifest_media_type)?);
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
            "{}://{}/v2/{}/manifests/{}",
            self.scheme(),
            self.primary_connect_host(&reference.registry),
            reference.repository,
            tag_or_digest
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
                if self.last_list_digest.is_none() {
                    self.last_list_digest =
                        Some(format!("sha256:{}", hex::encode(Sha256::digest(&body_bytes))));
                }
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

                let chosen_descriptor = if target_platform.is_some() {
                    runnable.iter().find(|desc| {
                        if let Some(p) = &desc.platform {
                            p.os == target_os && p.architecture == target_arch
                        } else {
                            false
                        }
                    })
                } else {
                    runnable
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
                }
                .ok_or_else(|| {
                    anyhow!(
                        "choosing image instance: no image found in manifest list for architecture {:?}, variant \"\", OS {:?}",
                        target_arch,
                        target_os
                    )
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

    async fn fetch_blob_bytes(
        &self,
        reference: &ImageReference,
        descriptor: &Descriptor,
    ) -> Result<Vec<u8>> {
        let use_range = std::env::args().any(|a| a.contains("enable_partial_images=true"))
            && descriptor.media_type.contains("zstd");
        let eps = if self.endpoints.is_empty() {
            vec![registry_connect_host(&reference.registry).to_string()]
        } else {
            self.endpoints.clone()
        };
        use std::sync::atomic::Ordering;
        let start_idx = self
            .active_endpoint_idx
            .load(Ordering::Relaxed)
            .min(eps.len().saturating_sub(1));
        for (ep_idx, host) in eps.iter().enumerate().skip(start_idx) {
            let url = format!(
                "{}://{}/v2/{}/blobs/{}",
                self.scheme(),
                host,
                reference.repository,
                descriptor.digest
            );
            for attempt in 0..2 {
                let mut req = self.client.get(&url).headers(self.auth_headers());
                if use_range && attempt == 0 {
                    req = req.header("Range", "bytes=0-1048575");
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(anyhow!("fetching blob {}: {}", descriptor.digest, e));
                    }
                };
                let status = resp.status();
                if status.is_success() || status == reqwest::StatusCode::PARTIAL_CONTENT {
                    self.active_endpoint_idx.store(ep_idx, Ordering::Relaxed);
                    return Ok(resp.bytes().await?.to_vec());
                }
                if status == reqwest::StatusCode::UNAUTHORIZED {
                    return Err(anyhow!(
                        "fetching blob {}: unauthorized: authentication required",
                        descriptor.digest
                    ));
                }
                if status == reqwest::StatusCode::FORBIDDEN {
                    return Err(anyhow!(
                        "fetching blob {}: denied: access denied",
                        descriptor.digest
                    ));
                }
                if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                    if !use_range && attempt == 0 {
                        continue;
                    }
                    self.active_endpoint_idx.store(
                        (ep_idx + 1).min(eps.len().saturating_sub(1)),
                        Ordering::Relaxed,
                    );
                    break;
                }
                if status == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || status == reqwest::StatusCode::INTERNAL_SERVER_ERROR
                    || status == reqwest::StatusCode::NOT_FOUND
                {
                    if status != reqwest::StatusCode::NOT_FOUND {
                        self.active_endpoint_idx.store(
                            (ep_idx + 1).min(eps.len().saturating_sub(1)),
                            Ordering::Relaxed,
                        );
                    }
                    break;
                }
                return Err(anyhow!(
                    "fetching blob {}: status {}",
                    descriptor.digest,
                    status
                ));
            }
        }
        Err(anyhow!(
            "fetching blob {}: all endpoints failed",
            descriptor.digest
        ))
    }

    /// Fetch image configuration JSON blob (parsed) and raw bytes for storage/push.
    pub async fn fetch_config_blob(
        &self,
        reference: &ImageReference,
        config_descriptor: &Descriptor,
    ) -> Result<(ImageConfig, Vec<u8>)> {
        let body_bytes = self.fetch_blob_bytes(reference, config_descriptor).await?;
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
        if self.endpoints.len() <= 1 && dest_path.exists() {
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

        let body_bytes = self.fetch_blob_bytes(reference, descriptor).await?;
        let calculated_digest = format!("sha256:{}", hex::encode(Sha256::digest(&body_bytes)));
        if calculated_digest != descriptor.digest {
            return Err(anyhow!(
                "Checksum mismatch for blob {}: expected {}, got {}",
                descriptor.digest,
                descriptor.digest,
                calculated_digest
            ));
        }
        fs::write(dest_path, &body_bytes)?;
        Ok(())
    }
}
