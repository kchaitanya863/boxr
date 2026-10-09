use super::DaemonState;
use crate::network::NetworkStore;
use crate::volume::VolumeStore;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

pub async fn list_networks(State(state): State<DaemonState>) -> Json<serde_json::Value> {
    let store = NetworkStore::with_home(state.home.clone());
    Json(serde_json::to_value(store.list()).unwrap_or_default())
}

#[derive(Deserialize)]
pub struct CreateNetworkRequest {
    #[serde(rename = "Name")]
    pub name: String,
}

pub async fn create_network(
    State(state): State<DaemonState>,
    Json(payload): Json<CreateNetworkRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = NetworkStore::with_home(state.home.clone());
    match store.create(&payload.name, None, None) {
        Ok(net) => Ok(Json(serde_json::to_value(net).unwrap())),
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

pub async fn inspect_network(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = NetworkStore::with_home(state.home.clone());
    let net = store.find(&id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(
        serde_json::to_value(net).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    ))
}

pub async fn remove_network(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> StatusCode {
    let store = NetworkStore::with_home(state.home.clone());
    match store.remove(&id) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            if msg.contains("active endpoints") || msg.contains("default bridge") || msg.contains("in use") {
                StatusCode::CONFLICT
            } else {
                StatusCode::NOT_FOUND
            }
        }
    }
}

#[derive(Deserialize)]
pub struct ConnectNetworkRequest {
    #[serde(rename = "Container")]
    pub container: String,
}

pub async fn connect_network(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    Json(payload): Json<ConnectNetworkRequest>,
) -> Result<StatusCode, StatusCode> {
    let store = NetworkStore::with_home(state.home.clone());
    let c_store = crate::storage::ContainerStore::with_home(state.home.clone());
    let c = c_store.find(&payload.container).ok_or(StatusCode::NOT_FOUND)?;
    store.connect_container(&id, &c.id, &c.name).map_err(|e| {
        let msg = e.to_string().to_lowercase();
        if msg.contains("not found") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_REQUEST
        }
    })?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct DisconnectNetworkRequest {
    #[serde(rename = "Container")]
    pub container: String,
    #[serde(rename = "Force", default)]
    pub force: bool,
}

pub async fn disconnect_network(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    Json(payload): Json<DisconnectNetworkRequest>,
) -> Result<StatusCode, StatusCode> {
    let store = NetworkStore::with_home(state.home.clone());
    store.disconnect_container(&id, &payload.container).map_err(|e| {
        let msg = e.to_string().to_lowercase();
        if msg.contains("not found") || msg.contains("not connected") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_REQUEST
        }
    })?;
    Ok(StatusCode::OK)
}

pub async fn list_volumes(State(state): State<DaemonState>) -> Json<serde_json::Value> {
    let store = VolumeStore::with_home(state.home.clone());
    #[derive(Serialize)]
    struct VolResp {
        #[serde(rename = "Volumes")]
        volumes: Vec<crate::volume::VolumeRecord>,
    }
    Json(
        serde_json::to_value(VolResp {
            volumes: store.list(),
        })
        .unwrap_or_default(),
    )
}

#[derive(Deserialize)]
pub struct CreateVolumeRequest {
    #[serde(rename = "Name")]
    pub name: Option<String>,
}

pub async fn create_volume(
    State(state): State<DaemonState>,
    Json(payload): Json<CreateVolumeRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = VolumeStore::with_home(state.home.clone());
    match store.create(payload.name.as_deref(), None) {
        Ok(vol) => Ok(Json(serde_json::to_value(vol).unwrap())),
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

pub async fn inspect_volume(
    State(state): State<DaemonState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = VolumeStore::with_home(state.home.clone());
    let vol = store.find(&name).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(
        serde_json::to_value(vol).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    ))
}

pub async fn remove_volume(
    State(state): State<DaemonState>,
    Path(name): Path<String>,
) -> StatusCode {
    let store = VolumeStore::with_home(state.home.clone());
    if store.find(&name).is_none() {
        return StatusCode::NOT_FOUND;
    }
    match store.remove(&name) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            let err_msg = e.to_string().to_lowercase();
            if err_msg.contains("active")
                || err_msg.contains("in use")
                || err_msg.contains("conflict")
            {
                StatusCode::CONFLICT
            } else if err_msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            }
        }
    }
}
