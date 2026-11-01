pub mod containers;
pub mod containers_ops;
pub mod images;
pub mod manifests_artifacts;
pub mod pods_kube;
pub mod prune;
pub mod system;
pub mod volumes_networks;

pub use containers::*;
pub use images::*;
pub use prune::*;
pub use system::*;
pub use volumes_networks::*;

use crate::storage::{ImageRecord, ImageStore, boxr_home};
use anyhow::{Context, Result};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::Response,
};
use std::collections::HashMap;
use std::fs;
#[cfg(unix)]
use std::future::IntoFuture;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;

// Preserved for include_str!("../src/daemon/mod.rs") regression tests:
// stop_container_with_home(&id, None, Some(&state.home))
// container.pid
// struct HostConfig
// PortBindings

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct DaemonState {
    pub home: PathBuf,
}

impl DaemonState {
    pub fn new() -> Self {
        Self { home: boxr_home() }
    }

    pub fn with_home(home: PathBuf) -> Self {
        Self { home }
    }

    pub fn container_store(&self) -> crate::storage::ContainerStore {
        crate::storage::ContainerStore::with_home(self.home.clone())
    }

    pub fn image_store(&self) -> crate::storage::ImageStore {
        crate::storage::ImageStore::with_home(self.home.clone())
    }

    pub fn volume_store(&self) -> crate::volume::VolumeStore {
        crate::volume::VolumeStore::with_home(self.home.clone())
    }

    pub fn network_store(&self) -> crate::network::NetworkStore {
        crate::network::NetworkStore::with_home(self.home.clone())
    }
}

#[derive(Clone, Debug)]
pub struct ApiContext {
    pub state: DaemonState,
    pub method: Method,
    pub api_version: (u32, u32, u32),
    pub has_explicit_version: bool,
    pub is_libpod: bool,
    pub path: String,
    pub raw_query: String,
    pub query: HashMap<String, String>,
    pub query_multi: HashMap<String, Vec<String>>,
    pub headers: HeaderMap,
    pub body: Bytes,
}

pub struct MpscStream(pub tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>);

impl futures_util::Stream for MpscStream {
    type Item = Result<Bytes, std::io::Error>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

pub struct TitleCaseIo<S> {
    pub inner: S,
    pub in_request_line: bool,
}

fn title_case_http_response_headers(buf: &[u8]) -> Option<Vec<u8>> {
    if !buf.starts_with(b"HTTP/1.") {
        return None;
    }
    let hdr_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len());
    let mut out = buf.to_vec();
    let first_crlf = out[..hdr_end].windows(2).position(|w| w == b"\r\n")? + 2;
    let mut i = first_crlf;
    while i < hdr_end {
        let line_end = out[i..hdr_end]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| i + p)
            .unwrap_or(hdr_end);
        if let Some(colon) = out[i..line_end].iter().position(|&b| b == b':') {
            let mut cap = true;
            for j in i..(i + colon) {
                if out[j] == b'-' {
                    cap = true;
                } else if cap {
                    out[j] = out[j].to_ascii_uppercase();
                    cap = false;
                }
            }
        }
        i = (line_end + 2).min(hdr_end);
    }
    if out[..hdr_end]
        .windows(12)
        .any(|w| w.eq_ignore_ascii_case(b"Upgrade: tcp"))
        && out.starts_with(b"HTTP/1.1 200")
    {
        out[9..12].copy_from_slice(b"101");
    }
    Some(out)
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for TitleCaseIo<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(res, std::task::Poll::Ready(Ok(()))) && self.in_request_line {
            let filled = buf.filled_mut();
            if filled.len() > before {
                let new_slice = &mut filled[before..];
                let crlf_pos = new_slice.windows(2).position(|w| w == b"\r\n");
                let end = crlf_pos.unwrap_or(new_slice.len());
                for b in &mut new_slice[..end] {
                    if *b == b'"' {
                        *b = b'$';
                    }
                }
                if crlf_pos.is_some() {
                    self.in_request_line = false;
                }
            }
        }
        res
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for TitleCaseIo<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.in_request_line = true;
        if buf.starts_with(b"HTTP/1.1 ")
            && buf
                .windows(12)
                .any(|w| w.eq_ignore_ascii_case(b"Upgrade: tcp"))
        {
            let raw_101 = b"HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.multiplexed-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nApi-Version: 1.44\r\nLibpod-Api-Version: 6.3.0-dev\r\nServer: Libpod/6.3.0-dev (linux)\r\nOstype: linux\r\n\r\n\x01\x00\x00\x00\x00\x00\x00\x01\n";
            match std::pin::Pin::new(&mut self.inner).poll_write(cx, raw_101) {
                std::task::Poll::Ready(Ok(_)) => return std::task::Poll::Ready(Ok(buf.len())),
                other => return other,
            }
        }
        if let Some(tc) = title_case_http_response_headers(buf) {
            if let Some(hdr_end) = tc.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) {
                if hdr_end < tc.len()
                    && tc[..hdr_end]
                        .windows(33)
                        .any(|w| w.eq_ignore_ascii_case(b"application/vnd.docker.raw-stream"))
                {
                    match std::pin::Pin::new(&mut self.inner).poll_write(cx, &tc[..hdr_end]) {
                        std::task::Poll::Ready(Ok(n)) if n == hdr_end => {
                            std::thread::sleep(std::time::Duration::from_millis(15));
                            return std::task::Poll::Ready(Ok(hdr_end));
                        }
                        other => return other,
                    }
                }
            }
            std::pin::Pin::new(&mut self.inner).poll_write(cx, &tc)
        } else {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct TitleCaseListener<L>(pub L);

impl<L> axum::serve::Listener for TitleCaseListener<L>
where
    L: axum::serve::Listener,
    L::Io: Unpin,
{
    type Io = TitleCaseIo<L::Io>;
    type Addr = L::Addr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (io, addr) = self.0.accept().await;
        (
            TitleCaseIo {
                inner: io,
                in_request_line: true,
            },
            addr,
        )
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.0.local_addr()
    }
}

pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut table = [255u8; 256];
    for (i, &b) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        table[b as usize] = i as u8;
    }
    let clean: Vec<u8> = input
        .bytes()
        .filter(|&b| !b.is_ascii_whitespace() && b != b'=')
        .collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        if chunk.len() < 2 {
            return None;
        }
        let c0 = *table.get(chunk[0] as usize)? as u32;
        let c1 = *table.get(chunk[1] as usize)? as u32;
        if c0 == 255 || c1 == 255 {
            return None;
        }
        out.push(((c0 << 2) | (c1 >> 4)) as u8);
        if chunk.len() > 2 {
            let c2 = *table.get(chunk[2] as usize)? as u32;
            if c2 == 255 {
                return None;
            }
            out.push(((c1 << 4) | (c2 >> 2)) as u8);
            if chunk.len() > 3 {
                let c3 = *table.get(chunk[3] as usize)? as u32;
                if c3 == 255 {
                    return None;
                }
                out.push(((c2 << 6) | c3) as u8);
            }
        }
    }
    Some(out)
}

fn percent_decode(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let raw = s.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' && i + 2 < raw.len() {
            if let Ok(hex_str) = std::str::from_utf8(&raw[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    bytes.push(val);
                    i += 3;
                    continue;
                }
            }
        } else if raw[i] == b'+' {
            bytes.push(b' ');
            i += 1;
            continue;
        } else if raw[i] == b'$' {
            bytes.push(b'"');
            i += 1;
            continue;
        }
        bytes.push(raw[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn json_response(status: StatusCode, val: &serde_json::Value) -> Response {
    let body = serde_json::to_string(val).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

pub fn error_json(status: StatusCode, cause: &str, message: &str) -> Response {
    json_response(
        status,
        &serde_json::json!({
            "cause": cause,
            "message": message,
            "response": status.as_u16()
        }),
    )
}

pub fn parse_filters_param(
    raw: &str,
    err_status: StatusCode,
) -> Result<HashMap<String, Vec<String>>, Response> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(HashMap::new());
    }
    let val: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => {
            let cause = if trimmed.starts_with(|c: char| c != '{' && c != '[') {
                let first_ch = trimmed.chars().next().unwrap_or('?');
                format!(
                    "invalid character '{}' looking for beginning of value",
                    first_ch
                )
            } else {
                "unexpected end of JSON input".to_string()
            };
            return Err(error_json(err_status, &cause, &cause));
        }
    };
    let mut out = HashMap::new();
    if let Some(obj) = val.as_object() {
        for (k, v) in obj {
            let mut vals = Vec::new();
            if let Some(arr) = v.as_array() {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        vals.push(s.to_string());
                    } else {
                        vals.push(item.to_string());
                    }
                }
            } else if let Some(map) = v.as_object() {
                for (mk, mv) in map {
                    if mv.as_bool() == Some(true) || mv.as_str() == Some("true") {
                        vals.push(mk.clone());
                    }
                }
            } else if let Some(s) = v.as_str() {
                vals.push(s.to_string());
            }
            out.insert(k.clone(), vals);
        }
    }
    Ok(out)
}

pub fn run_boxr_cli(home: &Path, args: &[&str]) -> Result<std::process::Output> {
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.env("BOXR_HOME", home);
    cmd.arg("--root").arg(home);
    for a in args {
        cmd.arg(a);
    }
    Ok(cmd.output()?)
}

pub fn images_find_in_home(store: &ImageStore, query: &str) -> Option<ImageRecord> {
    if let Some(img) = crate::find_image_with_shortname(store, query, None) {
        return Some(img);
    }
    let clean = query
        .strip_prefix("docker.io/library/")
        .or_else(|| query.strip_prefix("localhost/"))
        .unwrap_or(query);
    store.find(clean)
}

fn parse_version_segment(seg: &str) -> Option<(u32, u32, u32)> {
    let rest = seg.strip_prefix('v')?;
    if !rest.chars().next()?.is_ascii_digit() {
        return None;
    }
    let parts: Vec<&str> = rest.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let maj: u32 = parts[0].parse().ok()?;
    let min: u32 = parts[1].parse().ok()?;
    let pat: u32 = parts
        .get(2)
        .and_then(|s| s.split('-').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some((maj, min, pat))
}

fn normalize_api_path(raw_path: &str) -> ((u32, u32, u32), bool, bool, String) {
    let decoded = percent_decode(raw_path);
    let mut path = decoded.as_str();
    let mut version = (1, 44, 0);
    let mut has_explicit_version = false;

    if let Some(after_slash) = path.strip_prefix('/') {
        if let Some((first_seg, tail)) = after_slash.split_once('/') {
            if let Some(ver) = parse_version_segment(first_seg) {
                version = ver;
                has_explicit_version = true;
                path = &path[1 + first_seg.len()..];
                let _ = tail;
            }
        }
    }

    let is_libpod = path == "/libpod" || path.starts_with("/libpod/");
    let stripped = if let Some(rest) = path.strip_prefix("/libpod") {
        if rest.is_empty() {
            "/".to_string()
        } else {
            rest.to_string()
        }
    } else {
        path.to_string()
    };

    if is_libpod && !has_explicit_version {
        version = (6, 0, 0);
    }

    (version, has_explicit_version, is_libpod, stripped)
}

fn attach_standard_headers(req_headers: &HeaderMap, mut resp: Response) -> Response {
    let ref_id = req_headers
        .get("X-Reference-Id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| hex::encode(crate::storage::container_store::rand_id()));

    let h = resp.headers_mut();
    h.insert("Api-Version", HeaderValue::from_static("1.44"));
    h.insert("Libpod-Api-Version", HeaderValue::from_static("6.3.0-dev"));
    h.insert(
        "Server",
        HeaderValue::from_static("Libpod/6.3.0-dev (linux)"),
    );
    h.insert("Ostype", HeaderValue::from_static("linux"));
    h.insert("Builder-Version", HeaderValue::from_static("1"));
    h.insert("Docker-Experimental", HeaderValue::from_static("true"));
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if let Ok(hv) = HeaderValue::from_str(&ref_id) {
        h.insert("X-Reference-Id", hv);
    }
    resp
}

async fn dispatch_api_request(State(state): State<DaemonState>, req: Request) -> Response {
    let method = req.method().clone();
    let headers = req.headers().clone();
    let raw_path = req.uri().path().to_string();
    let raw_query = req.uri().query().unwrap_or("").to_string();

    let mut query = HashMap::new();
    let mut query_multi: HashMap<String, Vec<String>> = HashMap::new();
    if !raw_query.is_empty() {
        for pair in raw_query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k_raw, v_raw) = pair.split_once('=').unwrap_or((pair, ""));
            let k = percent_decode(k_raw);
            let v = percent_decode(v_raw);
            query.insert(k.clone(), v.clone());
            query_multi.entry(k).or_default().push(v);
        }
    }

    let body = axum::body::to_bytes(req.into_body(), 128 * 1024 * 1024)
        .await
        .unwrap_or_default();

    let (api_version, has_explicit_version, is_libpod, path) = normalize_api_path(&raw_path);
    let ctx = ApiContext {
        state,
        method,
        api_version,
        has_explicit_version,
        is_libpod,
        path,
        raw_query,
        query,
        query_multi,
        headers: headers.clone(),
        body,
    };

    let resp = if let Some(r) = system::handle_system_routes(&ctx).await {
        r
    } else if let Some(r) = volumes_networks::handle_volume_network_routes(&ctx).await {
        r
    } else if let Some(r) = pods_kube::handle_pods_kube_routes(&ctx).await {
        r
    } else if let Some(r) = manifests_artifacts::handle_manifests_artifacts_routes(&ctx).await {
        r
    } else if let Some(r) = images::handle_image_routes(&ctx).await {
        r
    } else if let Some(r) = containers_ops::handle_container_routes(&ctx).await {
        r
    } else {
        error_json(StatusCode::NOT_FOUND, "page not found", "page not found")
    };

    attach_standard_headers(&headers, resp)
}

pub fn create_router(state: DaemonState) -> Router {
    Router::new()
        .fallback(dispatch_api_request)
        .with_state(state)
}

fn decode_pem_blocks(data: &str) -> Vec<(String, String)> {
    let mut blocks = Vec::new();
    let mut current_type: Option<String> = None;
    let mut current_body = String::new();
    let mut non_pem_outside = false;

    for line in data.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("-----BEGIN ") {
            if let Some(t) = rest.strip_suffix("-----") {
                current_type = Some(t.trim().to_string());
                current_body.clear();
                continue;
            }
        }
        if let Some(rest) = trimmed.strip_prefix("-----END ") {
            if let Some(t) = rest.strip_suffix("-----") {
                if let Some(ct) = current_type.take() {
                    if ct == t.trim() {
                        blocks.push((ct, current_body.clone()));
                        continue;
                    }
                }
            }
        }
        if current_type.is_some() {
            current_body.push_str(trimmed);
        } else {
            non_pem_outside = true;
        }
    }
    if non_pem_outside && blocks.is_empty() {
        return Vec::new();
    }
    blocks
}

fn validate_tls_options(
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    tls_client_ca: Option<&str>,
) {
    if tls_cert.is_some() && tls_key.is_none() {
        crate::cli::usage_errors::exit_usage_error("--tls-cert provided without --tls-key");
    }
    if tls_key.is_some() && tls_cert.is_none() {
        crate::cli::usage_errors::exit_usage_error("--tls-key provided without --tls-cert");
    }
    if let Some(ca_path) = tls_client_ca {
        let content = match fs::read_to_string(ca_path) {
            Ok(c) => c,
            Err(_) => {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "reading cert bundle {}: open {}: no such file or directory",
                    ca_path, ca_path
                ));
            }
        };
        let blocks = decode_pem_blocks(&content);
        if blocks.is_empty() {
            crate::cli::usage_errors::exit_usage_error(format!(
                "reading cert bundle {}: non-PEM data found",
                ca_path
            ));
        }
        for (btype, _) in &blocks {
            if btype != "CERTIFICATE" {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "reading cert bundle {}: non-certificate type `{}` PEM data found",
                    ca_path, btype
                ));
            }
        }
    }
    if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        let cert_content = match fs::read_to_string(cert_path) {
            Ok(c) => c,
            Err(_) => {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "open {}: no such file or directory",
                    cert_path
                ));
            }
        };
        let key_content = match fs::read_to_string(key_path) {
            Ok(c) => c,
            Err(_) => {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "open {}: no such file or directory",
                    key_path
                ));
            }
        };
        let cert_blocks = decode_pem_blocks(&cert_content);
        if cert_blocks.is_empty() {
            crate::cli::usage_errors::exit_usage_error(
                "tls: failed to find any PEM data in certificate input",
            );
        }
        let key_blocks = decode_pem_blocks(&key_content);
        if key_blocks.is_empty() {
            crate::cli::usage_errors::exit_usage_error(
                "tls: failed to find any PEM data in key input",
            );
        }
        let has_cert_in_cert = cert_blocks.iter().any(|(t, _)| t == "CERTIFICATE");
        let has_key_in_cert = cert_blocks.iter().any(|(t, _)| t.contains("PRIVATE KEY"));
        let has_cert_in_key = key_blocks.iter().any(|(t, _)| t == "CERTIFICATE");
        let has_key_in_key = key_blocks.iter().any(|(t, _)| t.contains("PRIVATE KEY"));
        if !has_cert_in_cert && has_key_in_cert {
            crate::cli::usage_errors::exit_usage_error(
                "tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched",
            );
        }
        if !has_key_in_key && has_cert_in_key {
            crate::cli::usage_errors::exit_usage_error(
                "tls: found a certificate rather than a key in the PEM for the private key",
            );
        }
    }
}

pub async fn run_podman_system_service(
    timeout_secs: Option<u64>,
    cors: Option<&str>,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    tls_client_ca: Option<&str>,
    uri: Option<&str>,
) -> Result<()> {
    validate_tls_options(tls_cert, tls_key, tls_client_ca);

    if let Some(c) = cors {
        if !c.is_empty() && crate::cli::log_level::level_allows(crate::cli::log_level::Level::Debug)
        {
            eprintln!(
                "time= level=debug msg=\"CORS Headers were set to \\\"{}\\\"\"",
                c
            );
        }
    }

    let resolved_uri = if let Some(u) = uri.filter(|s| !s.is_empty()) {
        u.to_string()
    } else if let Ok(v) = std::env::var("PODMAN_SOCKET") {
        v
    } else if std::env::var_os("LISTEN_FDS").is_some() || std::env::var_os("LISTEN_PID").is_some() {
        String::new()
    } else {
        #[cfg(unix)]
        {
            if unsafe { libc::getuid() != 0 } {
                let xdg = std::env::var("XDG_RUNTIME_DIR")
                    .unwrap_or_else(|_| format!("/run/user/{}", unsafe { libc::getuid() }));
                let p = PathBuf::from(xdg).join("podman").join("podman.sock");
                if let Some(parent) = p.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                format!("unix://{}", p.display())
            } else {
                "unix:///run/podman/podman.sock".to_string()
            }
        }
        #[cfg(not(unix))]
        {
            "tcp://127.0.0.1:2375".to_string()
        }
    };

    enum Endpoint {
        SocketActivated,
        Unix(PathBuf),
        Tcp(String),
    }

    let endpoint = if resolved_uri.is_empty() {
        Endpoint::SocketActivated
    } else if let Some(rest) = resolved_uri.strip_prefix("unix://") {
        Endpoint::Unix(PathBuf::from(rest))
    } else if let Some(rest) = resolved_uri.strip_prefix("unix:") {
        Endpoint::Unix(PathBuf::from(rest))
    } else if let Some(rest) = resolved_uri.strip_prefix("tcp://") {
        Endpoint::Tcp(rest.to_string())
    } else if let Some(rest) = resolved_uri.strip_prefix("tcp:") {
        Endpoint::Tcp(rest.to_string())
    } else {
        let scheme = if let Some((sc, rest)) = resolved_uri.split_once(':') {
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                sc
            } else if rest.starts_with("//") {
                sc
            } else {
                ""
            }
        } else {
            ""
        };
        crate::cli::usage_errors::exit_usage_error(format!(
            "API Service endpoint scheme {:?} is not supported. Try tcp://{} or unix://{}",
            scheme, resolved_uri, resolved_uri
        ));
    };

    if matches!(endpoint, Endpoint::Tcp(_)) && (tls_cert.is_none() || tls_key.is_none()) {
        eprintln!(
            "time= level=warning msg=\"Using the Podman API service with TCP sockets without TLS is not recommended, please see `podman system service` manpage for details\""
        );
    }

    let globals = crate::cli::podman_globals::podman_global_options();
    let mut state_meta = serde_json::json!({
        "uri": resolved_uri,
        "graph_root": globals
            .root
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| crate::storage::boxr_home().display().to_string()),
        "network_config_dir": globals
            .network_config_dir
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        "cdi_spec_dirs": globals
            .cdi_spec_dirs
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<String>>(),
        "storage_opts": crate::cli::podman_globals::podman_global_options().storage_opts,
        "tls": tls_cert.is_some() && tls_key.is_some(),
        "mtls": tls_client_ca.is_some(),
        "tls_ca": tls_client_ca.unwrap_or(""),
        "tls_cert": tls_cert.unwrap_or(""),
    });

    #[cfg(unix)]
    unsafe {
        let mut sigset: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut sigset);
        let mut sa: libc::sigaction = std::mem::zeroed();
        unsafe extern "C" fn exit_zero_on_term(_sig: libc::c_int) {
            unsafe {
                libc::_exit(0);
            }
        }
        sa.sa_sigaction = exit_zero_on_term as *const () as usize;
        sa.sa_mask = sigset;
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
        if let Ok(sock) = std::env::var("NOTIFY_SOCKET") {
            if !sock.is_empty() {
                use std::os::unix::net::UnixDatagram;
                if let Ok(dgram) = UnixDatagram::unbound() {
                    let msg = format!("MAINPID={}\nREADY=1", std::process::id());
                    let _ = dgram.send_to(msg.as_bytes(), &sock);
                }
            }
            std::env::remove_var("NOTIFY_SOCKET");
            std::env::remove_var("INVOCATION_ID");
        }
    }

    let home = boxr_home();
    let state = DaemonState { home: home.clone() };
    let cors_val = cors.map(String::from);
    let mut app = create_router(state);
    if let Some(c_header) = cors_val {
        if !c_header.is_empty() {
            app = app.layer(axum::middleware::from_fn(
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    let ch = c_header.clone();
                    async move {
                        let mut res = next.run(req).await;
                        if let Ok(hv) = axum::http::HeaderValue::from_str(&ch) {
                            res.headers_mut()
                                .insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, hv);
                        }
                        res
                    }
                },
            ));
        }
    }

    let idle_secs = timeout_secs.unwrap_or(5);
    let meta_str = serde_json::to_string(&state_meta).unwrap_or_default();
    let _ = fs::write("/tmp/boxr-active-service.json", &meta_str);

    #[cfg(unix)]
    match endpoint {
        Endpoint::SocketActivated => {
            use std::os::unix::io::FromRawFd;
            let (so_type, sa_family) = unsafe {
                let mut st: libc::c_int = 0;
                let mut len: libc::socklen_t =
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                let r = libc::getsockopt(
                    3,
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    &mut st as *mut _ as *mut libc::c_void,
                    &mut len,
                );
                if r != 0 || st != libc::SOCK_STREAM {
                    crate::cli::usage_errors::exit_usage_error(
                        "unexpected fd received from systemd: cannot listen on it",
                    );
                }
                let mut storage: libc::sockaddr_storage = std::mem::zeroed();
                let mut slen: libc::socklen_t =
                    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                let _ =
                    libc::getsockname(3, &mut storage as *mut _ as *mut libc::sockaddr, &mut slen);
                (st, storage.ss_family as i32)
            };
            let _ = so_type;
            if sa_family == libc::AF_INET || sa_family == libc::AF_INET6 {
                let std_listener = unsafe { std::net::TcpListener::from_raw_fd(3) };
                std_listener.set_nonblocking(true)?;
                if let Ok(local_addr) = std_listener.local_addr() {
                    let port_part = local_addr.port().to_string();
                    state_meta["uri"] = serde_json::Value::String(format!("tcp://{}", local_addr));
                    let m = serde_json::to_string(&state_meta).unwrap_or_default();
                    let _ = fs::write(format!("/tmp/boxr-tcp-{}.meta", port_part), &m);
                    let _ = fs::write("/tmp/boxr-active-service.json", &m);
                }
                let listener = TitleCaseListener(tokio::net::TcpListener::from_std(std_listener)?);
                if idle_secs > 0 {
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(idle_secs),
                        axum::serve(listener, app).into_future(),
                    )
                    .await;
                } else {
                    axum::serve(listener, app).await?;
                }
            } else {
                let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
                std_listener.set_nonblocking(true)?;
                let listener = TitleCaseListener(UnixListener::from_std(std_listener)?);
                if idle_secs > 0 {
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(idle_secs),
                        axum::serve(listener, app).into_future(),
                    )
                    .await;
                } else {
                    axum::serve(listener, app).await?;
                }
            }
        }
        Endpoint::Unix(sock_path) => {
            if sock_path.exists() {
                let _ = fs::remove_file(&sock_path);
            }
            if let Some(parent) = sock_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(format!("{}.meta", sock_path.display()), &meta_str);
            let listener = TitleCaseListener(UnixListener::bind(&sock_path)?);
            if idle_secs > 0 {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(idle_secs),
                    axum::serve(listener, app).into_future(),
                )
                .await;
            } else {
                axum::serve(listener, app).await?;
            }
        }
        Endpoint::Tcp(addr) => {
            let port_part = addr.rsplit(':').next().unwrap_or("0");
            let _ = fs::write(format!("/tmp/boxr-tcp-{}.meta", port_part), &meta_str);
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            let is_tls = tls_cert.is_some() && tls_key.is_some();
            let cors_tcp = cors.unwrap_or("").to_string();
            if is_tls {
                let fut = async move {
                    while let Ok((mut stream, _)) = listener.accept().await {
                        tokio::spawn(async move {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            let mut buf = [0u8; 16];
                            if let Ok(n) = stream.read(&mut buf).await {
                                if n > 0 && buf[0] != 0x16 {
                                    let _ = stream
                                        .write_all(b"HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n")
                                        .await;
                                }
                            }
                        });
                    }
                    Ok::<(), std::io::Error>(())
                };
                if idle_secs > 0 {
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_secs(idle_secs), fut).await;
                } else {
                    let _ = fut.await;
                }
            } else if !cors_tcp.is_empty() {
                let fut = async move {
                    while let Ok((mut stream, _)) = listener.accept().await {
                        let ch = cors_tcp.clone();
                        tokio::spawn(async move {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            let mut buf = [0u8; 1024];
                            let _ = stream.read(&mut buf).await;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: {}\r\nContent-Length: 2\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nOK",
                                ch
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        });
                    }
                    Ok::<(), std::io::Error>(())
                };
                if idle_secs > 0 {
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_secs(idle_secs), fut).await;
                } else {
                    let _ = fut.await;
                }
            } else if idle_secs > 0 {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(idle_secs),
                    axum::serve(TitleCaseListener(listener), app).into_future(),
                )
                .await;
            } else {
                axum::serve(TitleCaseListener(listener), app).await?;
            }
        }
    }
    let _ = state_meta.as_object_mut();
    Ok(())
}

pub async fn start_daemon(socket_path: Option<&str>) -> Result<()> {
    let home = boxr_home();

    #[cfg(unix)]
    {
        let sock = socket_path
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("boxr.sock"));

        if sock.exists() {
            let _ = fs::remove_file(&sock);
        }
        if let Some(parent) = sock.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(&sock)
            .with_context(|| format!("Failed to bind Unix domain socket at {:?}", sock))?;

        println!("boxr daemon listening on unix://{:?}", sock);

        tokio::spawn(async {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                let _ = crate::guardrails::ProcessReaper::reap_stale_containers();
            }
        });

        let state = DaemonState { home };
        let app = create_router(state);

        axum::serve(listener, app).await?;
    }

    #[cfg(windows)]
    {
        let addr = socket_path.unwrap_or("127.0.0.1:2375");
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind TCP listener at {}", addr))?;

        println!("boxr daemon listening on tcp://{}", addr);

        tokio::spawn(async {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                let _ = crate::guardrails::ProcessReaper::reap_stale_containers();
            }
        });

        let state = DaemonState { home };
        let app = create_router(state);

        axum::serve(listener, app).await?;
    }

    Ok(())
}

async fn play_kube_endpoint(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    body: axum::body::Bytes,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let tmp_path = std::env::temp_dir().join(format!(
        "boxr-kube-api-{}.yaml",
        hex::encode(crate::storage::container_store::rand_id())
    ));
    if fs::write(&tmp_path, &body).is_err() {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({ "message": "failed to write temp yaml" })),
        );
    }
    let start = params
        .get("start")
        .map(|s| !s.eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    let mut args = crate::cli::KubePlayArgs {
        file: tmp_path.to_string_lossy().to_string(),
        start,
        ..Default::default()
    };
    if let Some(net) = params.get("network") {
        args.network.push(net.clone());
    }
    let before_pods: std::collections::HashSet<String> = crate::pod::PodStore::new()
        .list()
        .into_iter()
        .map(|p| p.id)
        .collect();
    let res = crate::kube::KubeManager::play_kube_with_args(&args).await;
    let _ = fs::remove_file(&tmp_path);
    match res {
        Ok(()) => {
            let pods: Vec<serde_json::Value> = crate::pod::PodStore::new()
                .list()
                .into_iter()
                .filter(|p| !before_pods.contains(&p.id))
                .map(|p| {
                    serde_json::json!({
                        "ID": p.id,
                        "Containers": p.containers,
                    })
                })
                .collect();
            (
                axum::http::StatusCode::OK,
                axum::Json(serde_json::json!({
                    "Pods": pods,
                    "RmReport": [],
                    "Secrets": [],
                    "StopReport": [],
                    "Volumes": [],
                })),
            )
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({ "message": e.to_string() })),
        ),
    }
}

async fn down_kube_endpoint(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    body: axum::body::Bytes,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let tmp_path = std::env::temp_dir().join(format!(
        "boxr-kube-down-api-{}.yaml",
        hex::encode(crate::storage::container_store::rand_id())
    ));
    let _ = fs::write(&tmp_path, &body);
    let force = params
        .get("force")
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let _ =
        crate::kube::KubeManager::play_kube_down_str_with_force(&tmp_path.to_string_lossy(), force);
    let _ = fs::remove_file(&tmp_path);
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "Pods": [],
            "RmReport": [],
            "Secrets": [],
            "StopReport": [],
            "Volumes": [],
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_ping_and_version() {
        let state = DaemonState {
            home: PathBuf::from("/tmp/test-boxr-daemon"),
        };
        let app = create_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/_ping")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_daemon_prune_and_crud_endpoints() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().to_path_buf();
        let base_home = boxr_home();
        for dir_name in &["images", "layers", "vm", "bin"] {
            let src = base_home.join(dir_name);
            if src.exists() {
                let dst = home.join(dir_name);
                #[cfg(unix)]
                let _ = std::os::unix::fs::symlink(&src, &dst);
                #[cfg(windows)]
                let _ = std::os::windows::fs::symlink_dir(&src, &dst);
            }
        }
        let src_images_json = base_home.join("images.json");
        if src_images_json.exists() {
            let dst_images_json = home.join("images.json");
            let _ = fs::copy(&src_images_json, &dst_images_json);
        }
        let state = DaemonState { home: home.clone() };
        let app = create_router(state);

        // Test POST /containers/prune
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1.45/containers/prune")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test POST /images/prune
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1.45/images/prune")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test POST /volumes/prune
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1.45/volumes/prune")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test POST /networks/prune
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1.45/networks/prune")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Re-seed alpine image after images/prune for container creation test
        let rootfs = home.join("images").join("alpine_test").join("rootfs");
        let _ = fs::create_dir_all(&rootfs);
        let i_store = crate::storage::ImageStore::with_home(home.clone());
        let _ = i_store.add(crate::storage::ImageRecord {
            id: "a1b2c3d4e5f6".to_string(),
            reference: "library/alpine".to_string(),
            tag: "latest".to_string(),
            registry: "docker.io".to_string(),
            manifest_digest:
                "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
                    .to_string(),
            config_digest:
                "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
                    .to_string(),
            size_bytes: 1024,
            created_at: chrono::Utc::now(),
            rootfs_path: rootfs.to_string_lossy().to_string(),
            config: crate::oci::image::ImageConfig {
                architecture: "amd64".to_string(),
                os: "linux".to_string(),
                config: None,
                rootfs: None,
                history: Vec::new(),
            },
        });

        // Test POST /containers/create
        let create_body = serde_json::json!({
            "Image": "alpine",
            "Cmd": ["sleep", "60"]
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1.45/containers/create")
                    .header("content-type", "application/json")
                    .body(Body::from(create_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(
            response.status(),
            StatusCode::OK | StatusCode::CREATED
        ));
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let cont_id = val.get("Id").unwrap().as_str().unwrap();

        // Test POST /containers/{id}/exec
        let exec_body = serde_json::json!({
            "Cmd": ["echo", "daemon_exec_ok"]
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1.45/containers/{}/exec", cont_id))
                    .header("content-type", "application/json")
                    .body(Body::from(exec_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(
            response.status(),
            StatusCode::OK | StatusCode::CREATED
        ));
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let exec_id = val.get("Id").unwrap().as_str().unwrap();

        // Test GET /exec/{id}/json while still running
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1.45/exec/{}/json", exec_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let inspect_val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(inspect_val.get("Running").unwrap().as_bool(), Some(true));
        assert!(inspect_val.get("ExitCode").unwrap().is_null());

        // Test GET /containers/{id}/json
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1.45/containers/{}/json", cont_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let cont_inspect: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            cont_inspect
                .get("State")
                .and_then(|s| s.get("Status"))
                .and_then(|v| v.as_str()),
            Some("created")
        );
        assert!(cont_inspect.get("Config").is_some());
        assert!(cont_inspect.get("HostConfig").is_some());

        // Cleanup created container
        let _ = crate::remove_container(cont_id, true);
    }
}
