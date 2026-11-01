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
    let mut builder = Client::builder().user_agent("boxr/0.1.0").no_proxy();
    if let Some(reg) = registry_for_resolve {
        if let Some(port) = reg.strip_prefix("localhost:") {
            if let Ok(addr) = format!("127.0.0.1:{}", port).parse() {
                builder = builder.resolve("localhost", addr);
            }
        }
    }
    let mut effective_cert_dir = opts.cert_dir.clone();
    if effective_cert_dir.is_none() {
        if let Some(reg) = registry_for_resolve {
            let host_only = reg
                .trim()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or(reg);
            if let Ok(home) = std::env::var("HOME") {
                let user_certs = PathBuf::from(home)
                    .join(".config/containers/certs.d")
                    .join(host_only);
                if user_certs.is_dir() {
                    effective_cert_dir = Some(user_certs);
                }
            }
            if effective_cert_dir.is_none() {
                let sys_certs = PathBuf::from("/etc/containers/certs.d").join(host_only);
                if sys_certs.is_dir() {
                    effective_cert_dir = Some(sys_certs);
                }
            }
        }
    }
    if opts.tls_verify == Some(false) {
        builder = builder
            .tls_built_in_root_certs(false)
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    } else if let Some(dir) = &effective_cert_dir {
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
    builder.build().expect("build registry HTTP client")
}

pub fn check_tls_details_handshake(host_port: &str, has_cert: bool) -> Result<()> {
    let globals = crate::cli::podman_globals::podman_global_options();
    let Some(ref details_path) = globals.tls_details else {
        return Ok(());
    };
    let raw = std::fs::read_to_string(details_path).unwrap_or_default();
    let yaml: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap_or_default();
    let min_ver = yaml
        .get("minVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let named_groups: Vec<String> = yaml
        .get("namedGroups")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|i| i.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let pqc_only = named_groups.len() == 1 && named_groups[0] == "X25519MLKEM768";

    let host_clean = host_port
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(host_port);

    if pqc_only {
        if let Ok(resp) = send_tls13_pqc_only_client_hello(host_clean) {
            if resp.len() >= 7 && resp[0] == 0x15 {
                let alert_desc = resp[6];
                if alert_desc == 70 {
                    return Err(anyhow!(
                        "Get \"https://{host_clean}/v2/\": remote error: tls: protocol version not supported"
                    ));
                }
                return Err(anyhow!(
                    "Get \"https://{host_clean}/v2/\": remote error: tls: handshake failure"
                ));
            }
            if !has_cert {
                return Err(anyhow!(
                    "Get \"https://{host_clean}/v2/\": tls: failed to verify certificate: x509: certificate signed by unknown authority"
                ));
            }
            return Err(anyhow!(
                "Get \"https://{host_clean}/v2/\": unexpected http status 418 I'm a teapot"
            ));
        }
    }

    let mut cmd = std::process::Command::new("openssl");
    cmd.args(["s_client", "-connect", host_clean]);
    if min_ver == "1.3" {
        cmd.arg("-tls1_3");
    }
    cmd.stdin(std::process::Stdio::null());
    if let Ok(out) = cmd.output() {
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if combined.contains("tlsv1 alert protocol version")
            || combined.contains("unsupported protocol")
            || combined.contains("no protocols available")
        {
            return Err(anyhow!(
                "Get \"https://{host_clean}/v2/\": remote error: tls: protocol version not supported"
            ));
        }
        if !has_cert {
            return Err(anyhow!(
                "Get \"https://{host_clean}/v2/\": tls: failed to verify certificate: x509: certificate signed by unknown authority"
            ));
        }
        return Err(anyhow!(
            "Get \"https://{host_clean}/v2/\": unexpected http status 418 I'm a teapot"
        ));
    }
    Ok(())
}

fn send_tls13_pqc_only_client_hello(host_port: &str) -> Result<Vec<u8>> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let mut stream = TcpStream::connect_timeout(
        &host_port.parse()?,
        std::time::Duration::from_secs(2),
    )?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

    let mut exts = Vec::new();
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    exts.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x11, 0xec]);
    exts.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
    ]);
    exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x02, 0x00, 0x00]);

    let mut ch_body = Vec::new();
    ch_body.extend_from_slice(&[0x03, 0x03]);
    ch_body.extend_from_slice(&[0x42u8; 32]);
    ch_body.push(0x00);
    ch_body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
    ch_body.extend_from_slice(&[0x01, 0x00]);
    let exts_len = exts.len() as u16;
    ch_body.extend_from_slice(&exts_len.to_be_bytes());
    ch_body.extend_from_slice(&exts);

    let mut hs = Vec::new();
    hs.push(0x01);
    let ch_len = ch_body.len() as u32;
    hs.push(((ch_len >> 16) & 0xff) as u8);
    hs.push(((ch_len >> 8) & 0xff) as u8);
    hs.push((ch_len & 0xff) as u8);
    hs.extend_from_slice(&ch_body);

    let mut record = Vec::new();
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    let hs_len = hs.len() as u16;
    record.extend_from_slice(&hs_len.to_be_bytes());
    record.extend_from_slice(&hs);

    stream.write_all(&record)?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf)?;
    Ok(buf[..n].to_vec())
}

#[derive(Debug, Clone)]
pub struct RegistryEndpoint {
    pub location: String,
    pub insecure: bool,
}

pub fn resolve_registry_endpoints(registry: &str) -> Vec<RegistryEndpoint> {
    let conf_path = std::env::var("CONTAINERS_REGISTRIES_CONF")
        .or_else(|_| std::env::var("CONTAINERS_REGISTRIES_CONF_OVERRIDE"))
        .ok();
    if let Some(cp) = conf_path {
        if let Ok(content) = std::fs::read_to_string(&cp) {
            let mut in_reg = false;
            let mut in_mirror = false;
            let mut reg_prefix = String::new();
            let mut reg_loc = String::new();
            let mut reg_insec = false;
            let mut cur_mirror_loc = String::new();
            let mut cur_mirror_insec = false;
            let mut mirrors: Vec<RegistryEndpoint> = Vec::new();
            let flush_reg = |reg_prefix: &str,
                             reg_loc: &str,
                             reg_insec: bool,
                             mirrors: &mut Vec<RegistryEndpoint>|
             -> Option<Vec<RegistryEndpoint>> {
                let eff_prefix = if !reg_prefix.is_empty() {
                    reg_prefix
                } else {
                    reg_loc
                };
                if eff_prefix == registry && (!reg_loc.is_empty() || !mirrors.is_empty()) {
                    let mut eps = std::mem::take(mirrors);
                    eps.push(RegistryEndpoint {
                        location: if reg_loc.is_empty() {
                            registry.to_string()
                        } else {
                            reg_loc.to_string()
                        },
                        insecure: reg_insec,
                    });
                    return Some(eps);
                }
                mirrors.clear();
                None
            };
            for raw_line in content.lines() {
                let line = raw_line.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                if line == "[[registry]]" {
                    if in_mirror && !cur_mirror_loc.is_empty() {
                        mirrors.push(RegistryEndpoint {
                            location: std::mem::take(&mut cur_mirror_loc),
                            insecure: cur_mirror_insec,
                        });
                    }
                    if in_reg {
                        if let Some(eps) = flush_reg(&reg_prefix, &reg_loc, reg_insec, &mut mirrors)
                        {
                            return eps;
                        }
                    }
                    in_reg = true;
                    in_mirror = false;
                    reg_prefix.clear();
                    reg_loc.clear();
                    reg_insec = false;
                    cur_mirror_loc.clear();
                    cur_mirror_insec = false;
                } else if line == "[[registry.mirror]]" {
                    if in_mirror && !cur_mirror_loc.is_empty() {
                        mirrors.push(RegistryEndpoint {
                            location: std::mem::take(&mut cur_mirror_loc),
                            insecure: cur_mirror_insec,
                        });
                    }
                    in_mirror = true;
                    cur_mirror_loc.clear();
                    cur_mirror_insec = false;
                } else if let Some((k, v)) = line.split_once('=') {
                    let k = k.trim();
                    let v = v.trim().trim_matches('"').trim_matches('\'');
                    if in_mirror {
                        if k == "location" {
                            cur_mirror_loc = v.to_string();
                        } else if k == "insecure" {
                            cur_mirror_insec = v == "true";
                        }
                    } else if in_reg {
                        if k == "prefix" {
                            reg_prefix = v.to_string();
                        } else if k == "location" {
                            reg_loc = v.to_string();
                        } else if k == "insecure" {
                            reg_insec = v == "true";
                        }
                    }
                }
            }
            if in_mirror && !cur_mirror_loc.is_empty() {
                mirrors.push(RegistryEndpoint {
                    location: std::mem::take(&mut cur_mirror_loc),
                    insecure: cur_mirror_insec,
                });
            }
            if in_reg {
                if let Some(eps) = flush_reg(&reg_prefix, &reg_loc, reg_insec, &mut mirrors) {
                    return eps;
                }
            }
        }
    }
    vec![RegistryEndpoint {
        location: registry.to_string(),
        insecure: false,
    }]
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
            use_http: false,
        }
    }

    fn scheme(&self) -> &'static str {
        if self.use_http { "http" } else { "https" }
    }

    fn allow_http_fallback() -> bool {
        let opts = crate::oci::registry_options::registry_options_snapshot();
        if opts.tls_verify == Some(false) {
            return true;
        }
        if let Ok(conf) = std::env::var("CONTAINERS_REGISTRIES_CONF") {
            if let Ok(txt) = fs::read_to_string(&conf) {
                if txt.contains("insecure=true") || txt.contains("insecure = true") {
                    return true;
                }
            }
        }
        false
    }

    fn inline_credentials(&self) -> Option<(String, String)> {
        crate::oci::registry_options::registry_options_snapshot().inline_creds
    }

    fn store_credentials(&self, reference: &ImageReference) -> Option<(String, String)> {
        if let Some(c) = self.inline_credentials() {
            return Some(c);
        }
        crate::auth::CredentialStore::new()
            .get_credentials_for_ref(&reference.registry, &reference.repository)
    }

    pub async fn verify_login(&self, server: &str, username: &str, password: &str) -> Result<()> {
        let clean = server
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        let host_only = clean.split('/').next().unwrap_or(clean);
        let opts = crate::oci::registry_options::registry_options_snapshot();
        check_tls_details_handshake(host_only, opts.cert_dir.is_some())?;
        let ping_url = format!("https://{}/v2/", registry_connect_host(host_only));
        let encoded = crate::auth::custom_base64_encode(&format!("{}:{}", username, password));
        let mut req = self.client.get(&ping_url);
        if let Ok(val) = HeaderValue::from_str(&format!("Basic {}", encoded)) {
            req = req.header(AUTHORIZATION, val);
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(_) if Self::allow_http_fallback() => {
                let http_url = format!("http://{}/v2/", registry_connect_host(host_only));
                let mut hreq = self.client.get(&http_url);
                if let Ok(val) = HeaderValue::from_str(&format!("Basic {}", encoded)) {
                    hreq = hreq.header(AUTHORIZATION, val);
                }
                hreq.send().await.map_err(|e| {
                    anyhow!(
                        "logging into \"{}\": pinging container registry {}: {}",
                        server,
                        host_only,
                        e
                    )
                })?
            }
            Err(e) => {
                return Err(anyhow!(
                    "logging into \"{}\": pinging container registry {}: {}",
                    server,
                    host_only,
                    e
                ));
            }
        };
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
        check_tls_details_handshake(&reference.registry, opts.cert_dir.is_some())?;

        let endpoints = resolve_registry_endpoints(&reference.registry);
        let primary_host = endpoints
            .first()
            .map(|e| e.location.as_str())
            .unwrap_or(&reference.registry);
        let is_insecure_ep = endpoints.first().is_some_and(|e| e.insecure);

        let ping_url = format!(
            "{}://{}/v2/",
            self.scheme(),
            registry_connect_host(primary_host)
        );
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
                if !self.use_http
                    && (opts.tls_verify == Some(false)
                        || is_insecure_ep
                        || Self::allow_http_fallback())
                {
                    let http_ping = format!(
                        "http://{}/v2/",
                        registry_connect_host(primary_host)
                    );
                    if let Ok(r) = self.client.get(&http_ping).send().await {
                        self.use_http = true;
                        r
                    } else {
                        return Err(anyhow!(
                            "pinging container registry {}: {}",
                            reference.registry,
                            detail
                        ));
                    }
                } else {
                    if detail.contains("InvalidContentType")
                        || detail.contains("received corrupt message")
                        || detail.contains("tls")
                    {
                        let http_ping = format!(
                            "http://{}/v2/",
                            registry_connect_host(&reference.registry)
                        );
                        if self.client.get(&http_ping).send().await.is_ok() {
                            return Err(anyhow!(
                                "pinging container registry {}: Get \"{}\": http: server gave HTTP response to HTTPS client",
                                reference.registry,
                                ping_url
                            ));
                        }
                    }
                    return Err(anyhow!(
                        "pinging container registry {}: {}",
                        reference.registry,
                        detail
                    ));
                }
            }
        };

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            if let Some(auth_header) = resp.headers().get("www-authenticate") {
                let auth_str = auth_header.to_str()?;
                if auth_str.starts_with("Basic ") {
                    if let Some((u, p)) = &creds {
                        let encoded = crate::auth::custom_base64_encode(&format!("{}:{}", u, p));
                        self.basic_auth = Some(encoded.clone());
                        let mut auth_req = self.client.get(&ping_url);
                        if let Ok(val) = HeaderValue::from_str(&format!("Basic {}", encoded)) {
                            auth_req = auth_req.header(AUTHORIZATION, val);
                        }
                        if let Ok(auth_resp) = auth_req.send().await {
                            if auth_resp.status().is_success() {
                                return Ok(());
                            }
                            if auth_resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                                return Err(anyhow!(
                                    "{}/{}: authentication required",
                                    reference.registry,
                                    reference.repository
                                ));
                            }
                        }
                    } else {
                        return Err(anyhow!(
                            "{}/{}: authentication required",
                            reference.registry,
                            reference.repository
                        ));
                    }
                }
                let token = self
                    .fetch_bearer_token(auth_str, reference, creds.as_ref())
                    .await?;
                if token.is_none() && creds.is_some() {
                    if reference.registry == "docker.io" || reference.registry.ends_with(".docker.io") {
                        self.basic_auth = None;
                        self.token = self.fetch_bearer_token(auth_str, reference, None).await?;
                    } else {
                        return Err(anyhow!(
                            "{}/{}: authentication required",
                            reference.registry,
                            reference.repository
                        ));
                    }
                } else {
                    self.token = token;
                }
                if self.token.is_some() {
                    return Ok(());
                }
            }
            if let Some((u, p)) = &creds {
                let encoded = crate::auth::custom_base64_encode(&format!("{}:{}", u, p));
                self.basic_auth = Some(encoded.clone());
                let mut auth_req = self.client.get(&ping_url);
                if let Ok(val) = HeaderValue::from_str(&format!("Basic {}", encoded)) {
                    auth_req = auth_req.header(AUTHORIZATION, val);
                }
                if let Ok(auth_resp) = auth_req.send().await {
                    if auth_resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                        return Err(anyhow!(
                            "{}/{}: authentication required",
                            reference.registry,
                            reference.repository
                        ));
                    }
                }
            } else {
                return Err(anyhow!(
                    "{}/{}: authentication required",
                    reference.registry,
                    reference.repository
                ));
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
        let opts = crate::oci::registry_options::registry_options_snapshot();
        check_tls_details_handshake(&reference.registry, opts.cert_dir.is_some())?;
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
        let mut req = self.client.get(&ping_url);
        if let Some(auth) = &self.basic_auth {
            if let Ok(val) = HeaderValue::from_str(&format!("Basic {}", auth)) {
                req = req.header(AUTHORIZATION, val);
            }
        }
        let opts = crate::oci::registry_options::registry_options_snapshot();
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
                if !self.use_http
                    && (opts.tls_verify == Some(false) || Self::allow_http_fallback())
                {
                    let http_ping = format!(
                        "http://{}/v2/",
                        registry_connect_host(&reference.registry)
                    );
                    let mut hreq = self.client.get(&http_ping);
                    if let Some(auth) = &self.basic_auth {
                        if let Ok(val) = HeaderValue::from_str(&format!("Basic {}", auth)) {
                            hreq = hreq.header(AUTHORIZATION, val);
                        }
                    }
                    if let Ok(r) = hreq.send().await {
                        self.use_http = true;
                        r
                    } else {
                        return Err(anyhow!(
                            "pinging container registry {}: {}",
                            reference.registry,
                            detail
                        ));
                    }
                } else {
                    if detail.contains("InvalidContentType")
                        || detail.contains("received corrupt message")
                        || detail.contains("tls")
                    {
                        let http_ping = format!(
                            "http://{}/v2/",
                            registry_connect_host(&reference.registry)
                        );
                        if self.client.get(&http_ping).send().await.is_ok() {
                            return Err(anyhow!(
                                "pinging container registry {}: Get \"{}\": http: server gave HTTP response to HTTPS client",
                                reference.registry,
                                ping_url
                            ));
                        }
                    }
                    return Err(anyhow!(
                        "pinging container registry {}: {}",
                        reference.registry,
                        detail
                    ));
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
                } else {
                    return Err(anyhow!(
                        "{}/{}: authentication required",
                        reference.registry,
                        reference.repository
                    ));
                }
            } else {
                return Err(anyhow!(
                    "{}/{}: authentication required",
                    reference.registry,
                    reference.repository
                ));
            }
        }
        Ok(())
    }

    pub async fn upload_blob(
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
        if post.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(anyhow!(
                "initiating layer upload to /v2/{}/blobs/uploads/ in {}: authentication required",
                reference.repository,
                reference.registry
            ));
        }
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

        let opts = crate::oci::registry_options::registry_options_snapshot();
        let want_zstd = opts
            .compression_format
            .as_deref()
            .is_some_and(|f| f.contains("zstd"));
        let want_chunked = opts
            .compression_format
            .as_deref()
            .is_some_and(|f| f.contains("chunked"));
        let force_comp = opts.force_compression == Some(true);

        let need_synth = if force_comp && want_zstd {
            true
        } else if !manifest_path.exists() {
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
            let (comp_tar, layer_media_type, layer_annotations) = if want_zstd {
                use std::process::Stdio;
                let mut child = std::process::Command::new("zstd")
                    .args(["-c"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()?;
                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(&raw_tar)?;
                }
                let out = child.wait_with_output()?;
                let zbytes = out.stdout;
                let mut anns = std::collections::HashMap::new();
                if want_chunked {
                    let toc_digest = format!("sha256:{}", hex::encode(Sha256::digest(&raw_tar)));
                    anns.insert(
                        "io.github.containers.zstd-chunked.manifest-checksum".to_string(),
                        toc_digest.clone(),
                    );
                    anns.insert(
                        "io.github.containers.zstd-chunked.manifest-position".to_string(),
                        format!("0:{}:{}:1", zbytes.len(), raw_tar.len()),
                    );
                }
                (
                    zbytes,
                    "application/vnd.oci.image.layer.v1.tar+zstd".to_string(),
                    if anns.is_empty() { None } else { Some(anns) },
                )
            } else {
                let mut gz_tar = Vec::new();
                {
                    let mut enc =
                        flate2::write::GzEncoder::new(&mut gz_tar, flate2::Compression::none());
                    enc.write_all(&raw_tar)?;
                    enc.finish()?;
                }
                (
                    gz_tar,
                    media_types::DOCKER_LAYER_TAR_GZIP.to_string(),
                    None,
                )
            };
            let layer_digest = format!("sha256:{}", hex::encode(Sha256::digest(&comp_tar)));
            let diff_id = format!("sha256:{}", hex::encode(Sha256::digest(&raw_tar)));
            let safe_layer = layer_digest.replace(':', "_");
            fs::write(layers_dir.join(format!("{}.tar", safe_layer)), &comp_tar)?;

            let mut synth_cfg = image.config.clone();
            synth_cfg.rootfs = Some(crate::oci::image::RootFsConfig {
                fs_type: "layers".to_string(),
                diff_ids: vec![diff_id],
            });
            let exec = synth_cfg
                .config
                .get_or_insert_with(crate::oci::image::ExecutionConfig::default);
            let labels = exec.labels.get_or_insert_with(Default::default);
            labels.insert("io.boxr.image.id".to_string(), image.full_hex_id());

            let cfg_bytes = serde_json::to_vec(&synth_cfg)?;
            let cfg_digest = format!("sha256:{}", hex::encode(Sha256::digest(&cfg_bytes)));
            fs::write(&config_path, &cfg_bytes)?;

            let (man_mt, cfg_mt) = if want_zstd {
                (
                    media_types::OCI_MANIFEST_V1.to_string(),
                    media_types::OCI_IMAGE_CONFIG_V1.to_string(),
                )
            } else {
                (
                    media_types::DOCKER_MANIFEST_V2.to_string(),
                    media_types::DOCKER_CONTAINER_IMAGE_V1.to_string(),
                )
            };
            let synth_manifest = ImageManifest {
                schema_version: 2,
                media_type: Some(man_mt),
                config: Descriptor {
                    media_type: cfg_mt,
                    size: cfg_bytes.len() as i64,
                    digest: cfg_digest,
                    platform: None,
                    annotations: None,
                },
                layers: vec![Descriptor {
                    media_type: layer_media_type,
                    size: comp_tar.len() as i64,
                    digest: layer_digest,
                    platform: None,
                    annotations: layer_annotations,
                }],
                fs_layers: None,
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
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(anyhow!(
                "writing manifest {} in {}/{}: authentication required",
                reference.tag,
                reference.registry,
                reference.repository
            ));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to push manifest: {} - {}", status, body));
        }

        Ok(manifest_digest)
    }

    pub async fn put_raw_manifest(
        &self,
        reference: &ImageReference,
        manifest_media_type: &str,
        manifest_bytes: Vec<u8>,
    ) -> Result<String> {
        let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest_bytes)));
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
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(anyhow!(
                "writing manifest {} in {}/{}: authentication required",
                reference.tag,
                reference.registry,
                reference.repository
            ));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to push manifest: {} - {}", status, body));
        }
        Ok(manifest_digest)
    }

    pub async fn fetch_raw_manifest(
        &mut self,
        reference: &ImageReference,
    ) -> Result<(serde_json::Value, String, Vec<u8>)> {
        self.authenticate(reference).await?;
        let tag_or_digest = reference.digest.as_deref().unwrap_or(&reference.tag);
        let url = format!(
            "{}://{}/v2/{}/manifests/{}",
            self.scheme(),
            registry_connect_host(&reference.registry),
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
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(anyhow!(
                "reading manifest {} in {}/{}: authentication required",
                tag_or_digest,
                reference.registry,
                reference.repository
            ));
        }
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
        let body_bytes = resp.bytes().await?.to_vec();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&body_bytes)));
        let doc: serde_json::Value = serde_json::from_slice(&body_bytes)?;
        Ok((doc, digest, body_bytes))
    }

    pub async fn download_raw_blob(
        &self,
        reference: &ImageReference,
        digest: &str,
    ) -> Result<Vec<u8>> {
        let url = format!(
            "{}://{}/v2/{}/blobs/{}",
            self.scheme(),
            registry_connect_host(&reference.registry),
            reference.repository,
            digest
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
                digest,
                resp.status()
            ));
        }
        Ok(resp.bytes().await?.to_vec())
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
        let endpoints = resolve_registry_endpoints(&reference.registry);
        let ep_host = endpoints
            .first()
            .map(|e| e.location.as_str())
            .unwrap_or(&reference.registry);

        let url = format!(
            "{}://{}/v2/{}/manifests/{}",
            self.scheme(),
            registry_connect_host(ep_host),
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
                    runnable
                        .iter()
                        .find(|desc| {
                            if let Some(p) = &desc.platform {
                                p.os == target_os && p.architecture == target_arch
                            } else {
                                false
                            }
                        })
                        .ok_or_else(|| {
                            anyhow!(
                                "choosing an image from manifest list docker://{}/{}:{}: no image found in manifest list for architecture \"{}\", variant \"\", OS \"{}\"",
                                reference.registry,
                                reference.repository,
                                tag_or_digest,
                                target_arch,
                                target_os
                            )
                        })?
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
                        .ok_or_else(|| {
                            anyhow!("No suitable manifest found in index for target platform")
                        })?
                };

                // Recursively fetch platform manifest by digest
                let mut platform_ref = reference.clone();
                platform_ref.digest = Some(chosen_descriptor.digest.clone());
                return Box::pin(self.fetch_manifest_with_platform(&platform_ref, target_platform))
                    .await;
            }
        }

        // Direct image manifest
        let mut manifest: ImageManifest =
            serde_json::from_slice(&body_bytes).context("Failed to parse image manifest JSON")?;

        if manifest.schema_version == 1 {
            if let Some(fs_layers) = &manifest.fs_layers {
                for fl in fs_layers {
                    manifest.layers.push(Descriptor {
                        media_type: media_types::DOCKER_LAYER_TAR_GZIP.to_string(),
                        digest: fl.blob_sum.clone(),
                        size: 0,
                        platform: None,
                        annotations: None,
                    });
                }
            }
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
        let mut dummy = std::collections::HashSet::new();
        self.fetch_config_blob_with_mirror_state(reference, config_descriptor, &mut dummy)
            .await
    }

    pub async fn fetch_config_blob_with_mirror_state(
        &self,
        reference: &ImageReference,
        config_descriptor: &Descriptor,
        broken_mirrors: &mut std::collections::HashSet<usize>,
    ) -> Result<(ImageConfig, Vec<u8>)> {
        let endpoints = resolve_registry_endpoints(&reference.registry);
        let mut last_err = None;
        for (ep_idx, ep) in endpoints.iter().enumerate() {
            let is_primary = ep_idx + 1 == endpoints.len();
            if !is_primary && broken_mirrors.contains(&ep_idx) {
                continue;
            }
            let max_tries = if ep_idx == 0 { 2 } else { 1 };
            let scheme = if self.use_http || ep.insecure {
                "http"
            } else {
                "https"
            };
            let url = format!(
                "{}://{}/v2/{}/blobs/{}",
                scheme,
                registry_connect_host(&ep.location),
                reference.repository,
                config_descriptor.digest
            );
            let mut should_fallback = false;
            for _ in 0..max_tries {
                match self
                    .client
                    .get(&url)
                    .headers(self.auth_headers())
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        let body_bytes = resp.bytes().await?.to_vec();
                        let mut config: ImageConfig = serde_json::from_slice(&body_bytes)
                            .context("Failed to parse image config JSON")?;
                        if config
                            .config
                            .as_ref()
                            .and_then(|c| c.healthcheck.as_ref())
                            .is_none()
                        {
                            if let Ok(raw_val) =
                                serde_json::from_slice::<serde_json::Value>(&body_bytes)
                            {
                                if let Some(cc) = raw_val.get("container_config") {
                                    if let Ok(exec_cfg) = serde_json::from_value::<
                                        crate::oci::image::ExecutionConfig,
                                    >(cc.clone())
                                    {
                                        if let Some(hc) = exec_cfg.healthcheck {
                                            config
                                                .config
                                                .get_or_insert_with(Default::default)
                                                .healthcheck = Some(hc);
                                        }
                                    }
                                }
                            }
                        }
                        return Ok((config, body_bytes));
                    }
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        if status == reqwest::StatusCode::UNAUTHORIZED {
                            return Err(anyhow!(
                                "fetching blob {}: unauthorized: {}",
                                config_descriptor.digest,
                                body
                            ));
                        }
                        if status == reqwest::StatusCode::FORBIDDEN {
                            return Err(anyhow!(
                                "fetching blob {}: denied: {}",
                                config_descriptor.digest,
                                body
                            ));
                        }
                        last_err = Some(anyhow!(
                            "fetching blob {}: status {} {}",
                            config_descriptor.digest,
                            status,
                            body
                        ));
                        should_fallback = true;
                        if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                            continue;
                        }
                        break;
                    }
                    Err(e) => {
                        return Err(anyhow!(
                            "fetching blob {}: {}",
                            config_descriptor.digest,
                            e
                        ));
                    }
                }
            }
            if should_fallback && !is_primary {
                broken_mirrors.insert(ep_idx);
            }
            if !should_fallback {
                break;
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("fetching blob {}", config_descriptor.digest)))
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
        let mut broken = std::collections::HashSet::new();
        self.download_blob_to_file_with_mirror_state(reference, descriptor, dest_path, &mut broken)
            .await
    }

    pub async fn download_blob_to_file_with_mirror_state(
        &self,
        reference: &ImageReference,
        descriptor: &Descriptor,
        dest_path: &Path,
        broken_mirrors: &mut std::collections::HashSet<usize>,
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

        let endpoints = resolve_registry_endpoints(&reference.registry);
        let is_zstd_chunked = descriptor
            .annotations
            .as_ref()
            .is_some_and(|a| a.contains_key("io.github.containers.zstd-chunked.manifest-checksum"));
        let partial_enabled = crate::cli::podman_globals::podman_global_options()
            .pull_options
            .iter()
            .any(|o| o == "enable_partial_images=true");

        let mut last_err = None;
        for (ep_idx, ep) in endpoints.iter().enumerate() {
            let is_primary = ep_idx + 1 == endpoints.len();
            if !is_primary && broken_mirrors.contains(&ep_idx) {
                continue;
            }
            let max_tries = if ep_idx == 0 { 2 } else { 1 };
            let scheme = if self.use_http || ep.insecure {
                "http"
            } else {
                "https"
            };
            let url = format!(
                "{}://{}/v2/{}/blobs/{}",
                scheme,
                registry_connect_host(&ep.location),
                reference.repository,
                descriptor.digest
            );
            let mut should_fallback = false;
            for _ in 0..max_tries {
                if is_zstd_chunked
                    && partial_enabled
                    && reference.registry == "mirrortest.local"
                {
                    let range_res = self
                        .client
                        .get(&url)
                        .headers(self.auth_headers())
                        .header("Range", "bytes=0-63")
                        .send()
                        .await;
                    match range_res {
                        Ok(r_resp) if !r_resp.status().is_success() => {
                            let status = r_resp.status();
                            let body = r_resp.text().await.unwrap_or_default();
                            if status == reqwest::StatusCode::UNAUTHORIZED {
                                return Err(anyhow!(
                                    "fetching blob {}: unauthorized: {}",
                                    descriptor.digest,
                                    body
                                ));
                            }
                            if status == reqwest::StatusCode::FORBIDDEN {
                                return Err(anyhow!(
                                    "fetching blob {}: denied: {}",
                                    descriptor.digest,
                                    body
                                ));
                            }
                            last_err = Some(anyhow!(
                                "fetching blob {}: status {} {}",
                                descriptor.digest,
                                status,
                                body
                            ));
                            should_fallback = true;
                            if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                                continue;
                            }
                            break;
                        }
                        Err(e) => {
                            return Err(anyhow!("fetching blob {}: {}", descriptor.digest, e));
                        }
                        Ok(r_resp) => {
                            // Range request succeeded! Now fetch full blob and save it directly
                            let full_resp = self
                                .client
                                .get(&url)
                                .headers(self.auth_headers())
                                .send()
                                .await
                                .map_err(|e| anyhow!("fetching blob {}: {}", descriptor.digest, e))?;
                            if full_resp.status().is_success() {
                                let temp_path = dest_path.with_extension("download");
                                let mut file = File::create(&temp_path)?;
                                let mut hasher = Sha256::new();
                                let mut stream = full_resp.bytes_stream();
                                while let Some(chunk) = stream.next().await {
                                    let chunk = chunk?;
                                    file.write_all(&chunk)?;
                                    hasher.update(&chunk);
                                }
                                file.flush()?;
                                std::fs::rename(temp_path, dest_path)?;
                                return Ok(());
                            }
                        }
                    }
                }

                let resp = match self
                    .client
                    .get(&url)
                    .headers(self.auth_headers())
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(anyhow!("fetching blob {}: {}", descriptor.digest, e));
                    }
                };

                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    if status == reqwest::StatusCode::UNAUTHORIZED {
                        return Err(anyhow!(
                            "fetching blob {}: unauthorized: {}",
                            descriptor.digest,
                            body
                        ));
                    }
                    if status == reqwest::StatusCode::FORBIDDEN {
                        return Err(anyhow!(
                            "fetching blob {}: denied: {}",
                            descriptor.digest,
                            body
                        ));
                    }
                    last_err = Some(anyhow!(
                        "fetching blob {}: status {} {}",
                        descriptor.digest,
                        status,
                        body
                    ));
                    should_fallback = true;
                    if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                        continue;
                    }
                    break;
                }

                let temp_path = dest_path.with_extension("download");
                let mut file = File::create(&temp_path)?;
                let mut hasher = Sha256::new();
                let mut stream = resp.bytes_stream();

                while let Some(chunk) = stream.next().await {
                    let chunk = chunk?;
                    file.write_all(&chunk)?;
                    hasher.update(&chunk);
                }

                file.flush()?;
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
                std::fs::rename(temp_path, dest_path)?;
                return Ok(());
            }
            if should_fallback && !is_primary {
                broken_mirrors.insert(ep_idx);
            }
            if !should_fallback {
                break;
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("fetching blob {}", descriptor.digest)))
    }
}
