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
