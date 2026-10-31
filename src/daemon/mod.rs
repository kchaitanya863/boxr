pub mod containers;
pub mod images;
pub mod prune;
pub mod system;
pub mod volumes_networks;

pub use containers::*;
pub use images::*;
pub use prune::*;
pub use system::*;
pub use volumes_networks::*;

use crate::storage::boxr_home;
use anyhow::{Context, Result};
use axum::{
    Router,
    routing::{delete, get, post},
};
use std::fs;
#[cfg(unix)]
use std::future::IntoFuture;
use std::path::PathBuf;
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
#[derive(Clone)]
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

pub fn create_router(state: DaemonState) -> Router {
    Router::new()
        .route("/_ping", get(ping))
        .route("/libpod/_ping", get(ping))
        .route("/v1.45/libpod/_ping", get(ping))
        .route("/version", get(version))
        .route("/v1.45/version", get(version))
        .route("/info", get(info))
        .route("/v1.45/info", get(info))
        .route("/images/json", get(list_images))
        .route("/v1.45/images/json", get(list_images))
        .route("/images/{name}/json", get(inspect_image))
        .route("/v1.45/images/{name}/json", get(inspect_image))
        .route("/images/create", post(create_image))
        .route("/v1.45/images/create", post(create_image))
        .route("/images/{name}", delete(remove_image_endpoint))
        .route("/v1.45/images/{name}", delete(remove_image_endpoint))
        .route("/images/{name}/tag", post(tag_image_endpoint))
        .route("/v1.45/images/{name}/tag", post(tag_image_endpoint))
        .route("/images/{name}/history", get(get_image_history_endpoint))
        .route(
            "/v1.45/images/{name}/history",
            get(get_image_history_endpoint),
        )
        .route("/containers/json", get(list_containers))
        .route("/v1.45/containers/json", get(list_containers))
        .route("/containers/{id}/json", get(inspect_container))
        .route("/v1.45/containers/{id}/json", get(inspect_container))
        .route("/containers/create", post(create_container))
        .route("/v1.45/containers/create", post(create_container))
        .route("/containers/{id}/start", post(start_container))
        .route("/v1.45/containers/{id}/start", post(start_container))
        .route("/containers/{id}/stop", post(stop_container))
        .route("/v1.45/containers/{id}/stop", post(stop_container))
        .route("/containers/{id}/restart", post(restart_container))
        .route("/v1.45/containers/{id}/restart", post(restart_container))
        .route("/containers/{id}/kill", post(kill_container))
        .route("/v1.45/containers/{id}/kill", post(kill_container))
        .route("/containers/{id}/wait", post(wait_container))
        .route("/v1.45/containers/{id}/wait", post(wait_container))
        .route("/containers/{id}/logs", get(get_container_logs))
        .route("/v1.45/containers/{id}/logs", get(get_container_logs))
        .route("/containers/{id}", delete(remove_container))
        .route("/v1.45/containers/{id}", delete(remove_container))
        .route("/containers/{id}/exec", post(create_container_exec))
        .route("/v1.45/containers/{id}/exec", post(create_container_exec))
        .route("/exec/{id}/start", post(start_exec_instance))
        .route("/v1.45/exec/{id}/start", post(start_exec_instance))
        .route("/exec/{id}/json", get(inspect_exec_instance))
        .route("/v1.45/exec/{id}/json", get(inspect_exec_instance))
        .route("/containers/prune", post(prune_containers_endpoint))
        .route("/v1.45/containers/prune", post(prune_containers_endpoint))
        .route("/images/prune", post(prune_images_endpoint))
        .route("/v1.45/images/prune", post(prune_images_endpoint))
        .route("/volumes/prune", post(prune_volumes_endpoint))
        .route("/v1.45/volumes/prune", post(prune_volumes_endpoint))
        .route("/networks/prune", post(prune_networks_endpoint))
        .route("/v1.45/networks/prune", post(prune_networks_endpoint))
        .route("/networks", get(list_networks))
        .route("/v1.45/networks", get(list_networks))
        .route("/networks/create", post(create_network))
        .route("/v1.45/networks/create", post(create_network))
        .route("/networks/{id}", get(inspect_network))
        .route("/v1.45/networks/{id}", get(inspect_network))
        .route("/networks/{id}", delete(remove_network))
        .route("/v1.45/networks/{id}", delete(remove_network))
        .route("/networks/{id}/connect", post(connect_network))
        .route("/v1.45/networks/{id}/connect", post(connect_network))
        .route("/networks/{id}/disconnect", post(disconnect_network))
        .route("/v1.45/networks/{id}/disconnect", post(disconnect_network))
        .route("/volumes", get(list_volumes))
        .route("/v1.45/volumes", get(list_volumes))
        .route("/volumes/create", post(create_volume))
        .route("/v1.45/volumes/create", post(create_volume))
        .route("/volumes/{name}", get(inspect_volume))
        .route("/v1.45/volumes/{name}", get(inspect_volume))
        .route("/volumes/{name}", delete(remove_volume))
        .route("/v1.45/volumes/{name}", delete(remove_volume))
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

    let mut state_meta = serde_json::json!({
        "uri": resolved_uri,
        "graph_root": crate::cli::podman_globals::podman_global_options()
            .root
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| crate::storage::boxr_home().display().to_string()),
        "tls": tls_cert.is_some() && tls_key.is_some(),
        "mtls": tls_client_ca.is_some(),
        "tls_ca": tls_client_ca.unwrap_or(""),
        "tls_cert": tls_cert.unwrap_or(""),
    });

    #[cfg(unix)]
    unsafe {
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
            let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
            std_listener.set_nonblocking(true)?;
            let listener = UnixListener::from_std(std_listener)?;
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
        Endpoint::Unix(sock_path) => {
            if sock_path.exists() {
                let _ = fs::remove_file(&sock_path);
            }
            if let Some(parent) = sock_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(format!("{}.meta", sock_path.display()), &meta_str);
            let listener = UnixListener::bind(&sock_path)?;
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
                    axum::serve(listener, app).into_future(),
                )
                .await;
            } else {
                axum::serve(listener, app).await?;
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
        assert_eq!(response.status(), StatusCode::OK);
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
        assert_eq!(response.status(), StatusCode::OK);
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
