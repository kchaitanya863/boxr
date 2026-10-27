use super::DaemonState;
use crate::storage::{ContainerStatus, ContainerStore};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize)]
pub struct ListContainersQuery {
    pub all: Option<serde_json::Value>,
}

pub async fn list_containers(
    State(state): State<DaemonState>,
    Query(params): Query<ListContainersQuery>,
) -> Json<serde_json::Value> {
    let store = ContainerStore::with_home(state.home.clone());
    let mut containers = store.list();
    let show_all = match &params.all {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => n.as_i64() == Some(1),
        Some(serde_json::Value::String(s)) => s == "1" || s.to_lowercase() == "true",
        _ => false,
    };
    if !show_all {
        containers.retain(|c| matches!(c.status, ContainerStatus::Running));
    }
    Json(serde_json::to_value(containers).unwrap_or_default())
}

#[derive(Deserialize, Default)]
pub struct CreateContainerQuery {
    pub name: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct RestartPolicyConfig {
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "MaximumRetryCount")]
    pub maximum_retry_count: Option<u32>,
}

#[derive(Deserialize, Default)]
pub struct PortBindingItem {
    #[serde(rename = "HostIp")]
    pub host_ip: Option<String>,
    #[serde(rename = "HostPort")]
    pub host_port: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct HostConfig {
    #[serde(rename = "Binds")]
    pub binds: Option<Vec<String>>,
    #[serde(rename = "PortBindings")]
    pub port_bindings: Option<HashMap<String, Vec<PortBindingItem>>>,
    #[serde(rename = "Memory")]
    pub memory: Option<i64>,
    #[serde(rename = "RestartPolicy")]
    pub restart_policy: Option<RestartPolicyConfig>,
}

#[derive(Deserialize)]
pub struct CreateContainerRequest {
    #[serde(rename = "Image")]
    pub image: String,
    #[serde(rename = "Cmd")]
    pub cmd: Option<Vec<String>>,
    #[serde(rename = "Env")]
    pub env: Option<Vec<String>>,
    #[serde(rename = "WorkingDir")]
    pub working_dir: Option<String>,
    #[serde(rename = "User")]
    pub user: Option<String>,
    #[serde(rename = "HostConfig")]
    pub host_config: Option<HostConfig>,
}

pub async fn create_container(
    State(state): State<DaemonState>,
    Query(query): Query<CreateContainerQuery>,
    Json(payload): Json<CreateContainerRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut ports = Vec::new();
    let mut volumes = Vec::new();
    let mut memory = None;
    let mut restart = "no".to_string();

    if let Some(hc) = &payload.host_config {
        if let Some(b) = &hc.binds {
            volumes = b.clone();
        }
        if let Some(pb) = &hc.port_bindings {
            for (cont_port_proto, host_items) in pb {
                for item in host_items {
                    let host_p = item.host_port.as_deref().unwrap_or("");
                    let host_ip = item.host_ip.as_deref().unwrap_or("");
                    if !host_ip.is_empty() {
                        ports.push(format!("{}:{}:{}", host_ip, host_p, cont_port_proto));
                    } else if !host_p.is_empty() {
                        ports.push(format!("{}:{}", host_p, cont_port_proto));
                    } else {
                        ports.push(cont_port_proto.clone());
                    }
                }
            }
        }
        if let Some(m) = hc.memory {
            if m > 0 {
                memory = Some(m.to_string());
            }
        }
        if let Some(rp) = &hc.restart_policy {
            if let Some(n) = &rp.name {
                restart = n.clone();
            }
        }
    }

    let run_args = crate::cli::RunArgs {
        registry_auth: Default::default(),
        interactive: false,
        tty: false,
        detach: true,
        rm: false,
        name: query.name,
        env: payload.env.unwrap_or_default(),
        ports,
        volumes,
        workdir: payload.working_dir,
        user: payload.user,
        hostname: None,
        add_host: Vec::new(),
        dns: Vec::new(),
        labels: Vec::new(),
        cidfile: None,
        memory,
        cpus: None,
        pids_limit: None,
        rootless: true,
        restart,
        health_cmd: None,
        platform: None,
        network: "auto".to_string(),
        disable_content_trust: false,
        privileged: false,
        gpus: None,
        entrypoint: None,
        env_file: None,
        shm_size: None,
        cap_add: Vec::new(),
        cap_drop: Vec::new(),
        read_only: false,
        init: false,
        tmpfs: Vec::new(),
        devices: Vec::new(),
        security_opt: Vec::new(),
        cpu_shares: None,
        cpuset_cpus: None,
        memory_swap: None,
        memory_reservation: None,
        dns_search: Vec::new(),
        dns_option: Vec::new(),
        expose: Vec::new(),
        sysctl: Vec::new(),
        stop_timeout: None,
        stop_signal: None,
        annotations: Vec::new(),
        ulimits: Vec::new(),
        ipc: None,
        pid: None,
        uts: None,
        userns: None,
        cgroupns: None,
        cgroup_parent: None,
        isolation: None,
        cpu_count: None,
        cpu_percent: None,
        io_maxbandwidth: None,
        io_maxiops: None,
        publish_all: false,
        ip: None,
        ip6: None,
        mac_address: None,
        link: Vec::new(),
        network_alias: Vec::new(),
        mount: Vec::new(),
        health_interval: None,
        health_timeout: None,
        health_retries: None,
        health_start_period: None,
        health_start_interval: None,
        no_healthcheck: false,
        attach: Vec::new(),
        pull: None,
        quiet: false,
        log_driver: None,
        log_opt: Vec::new(),
        oom_kill_disable: false,
        oom_score_adj: None,
        group_add: Vec::new(),
        label_file: None,
        umask: None,
        domainname: None,
        detach_keys: None,
        blkio_weight: None,
        blkio_weight_device: Vec::new(),
        cpu_period: None,
        cpu_quota: None,
        cpu_rt_period: None,
        cpu_rt_runtime: None,
        cpuset_mems: None,
        device_cgroup_rule: Vec::new(),
        device_read_bps: Vec::new(),
        device_read_iops: Vec::new(),
        device_write_bps: Vec::new(),
        device_write_iops: Vec::new(),
        link_local_ip: Vec::new(),
        memory_swappiness: None,
        runtime: None,
        sig_proxy: true,
        storage_opt: Vec::new(),
        use_api_socket: false,
        volume_driver: None,
        volumes_from: Vec::new(),
        pod: None,
        image: payload.image,
        command: payload.cmd.unwrap_or_default(),
    };

    match crate::create_only_container_with_home(run_args, Some(&state.home)).await {
        Ok(id) => Ok(Json(serde_json::json!({
            "Id": id,
            "Warnings": []
        }))),
        Err(e) => {
            eprintln!("Failed to create container via REST API: {:#}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn start_container(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> StatusCode {
    match crate::start_container_with_home(&id, Some(&state.home)).await {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::NOT_FOUND,
    }
}

#[derive(Deserialize, Default)]
pub struct StopContainerQuery {
    pub t: Option<u64>,
    pub signal: Option<String>,
}

pub async fn stop_container(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    Query(query): Query<StopContainerQuery>,
) -> StatusCode {
    match crate::stop_container_with_home_and_timeout(
        &id,
        query.signal.as_deref(),
        query.t,
        Some(&state.home),
        true,
        None,
    ) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::NOT_FOUND,
    }
}

pub async fn restart_container(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> StatusCode {
    let _ = crate::stop_container_with_home(&id, None, Some(&state.home));
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    match crate::start_container_with_home(&id, Some(&state.home)).await {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::NOT_FOUND,
    }
}

pub async fn kill_container(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> StatusCode {
    let store = ContainerStore::with_home(state.home.clone());
    if let Some(c) = store.find(&id) {
        let _ = crate::runtime::kill::ContainerKiller::kill(&c, None);
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

pub async fn wait_container(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = ContainerStore::with_home(state.home.clone());
    let c = store.find(&id).ok_or(StatusCode::NOT_FOUND)?;
    let bundle_path = PathBuf::from(&c.bundle_path);

    let is_test = cfg!(test);
    let mut check_count = 0;

    loop {
        if let Some(curr) = store.find(&id) {
            if let ContainerStatus::Exited(code) = curr.status {
                return Ok(Json(serde_json::json!({ "StatusCode": code })));
            }
        }

        let mut is_running = false;
        #[cfg(unix)]
        {
            let mut pids = Vec::new();
            if let Ok(pid_str) = fs::read_to_string(bundle_path.join("vm.pid")) {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    pids.push(pid);
                }
            }
            if let Ok(pid_str) = fs::read_to_string(bundle_path.join("container.pid")) {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    pids.push(pid);
                }
            }
            for pid in pids {
                if unsafe { libc::kill(pid, 0) == 0 } {
                    is_running = true;
                    break;
                }
            }
        }

        if !is_running {
            break;
        }

        check_count += 1;
        if is_test && check_count > 5 {
            break;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    let exit_code = if let Ok(code_str) = fs::read_to_string(bundle_path.join("boxr-exitcode")) {
        code_str.trim().parse::<i32>().unwrap_or(0)
    } else if let Some(curr) = store.find(&id) {
        match curr.status {
            ContainerStatus::Exited(code) => code,
            _ => 0,
        }
    } else {
        0
    };

    Ok(Json(serde_json::json!({ "StatusCode": exit_code })))
}

pub async fn get_container_logs(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> Result<String, StatusCode> {
    let store = ContainerStore::with_home(state.home.clone());
    let c = store.find(&id).ok_or(StatusCode::NOT_FOUND)?;
    let log_path = PathBuf::from(&c.bundle_path).join("logs.txt");
    if log_path.exists() {
        fs::read_to_string(&log_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        Ok(String::new())
    }
}

#[derive(Deserialize, Default)]
pub struct RemoveContainerQuery {
    pub force: Option<bool>,
    pub v: Option<bool>,
}

pub async fn remove_container(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    Query(query): Query<RemoveContainerQuery>,
) -> StatusCode {
    let store = ContainerStore::with_home(state.home.clone());
    let c = match store.find(&id) {
        Some(c) => c,
        None => return StatusCode::NOT_FOUND,
    };

    let force = query.force.unwrap_or(false);
    let is_active =
        matches!(c.status, ContainerStatus::Running) || matches!(c.status, ContainerStatus::Paused);

    if is_active && !force {
        return StatusCode::CONFLICT;
    }

    if is_active {
        let _ = crate::stop_container_with_home(&id, None, Some(&state.home));
    }

    match store.remove(&id) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::NOT_FOUND,
    }
}

pub async fn inspect_container(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = ContainerStore::with_home(state.home.clone());
    let c = store.find(&id).ok_or(StatusCode::NOT_FOUND)?;

    let status_str = match c.status {
        ContainerStatus::Running => "running",
        ContainerStatus::Paused => "paused",
        ContainerStatus::Created => "created",
        ContainerStatus::Exited(_) => "exited",
        ContainerStatus::Failed(_) => "dead",
    };

    let bundle_path = PathBuf::from(&c.bundle_path);
    let config_file = bundle_path.join("config.json");
    let (env, cmd, cwd, user) = if let Ok(content) = fs::read_to_string(&config_file) {
        if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&content) {
            (
                spec.process.env.clone(),
                spec.process.args.clone(),
                spec.process.cwd.clone(),
                spec.process
                    .user
                    .username
                    .clone()
                    .unwrap_or_else(|| spec.process.user.uid.to_string()),
            )
        } else {
            (vec![], c.command.clone(), "/".to_string(), "0".to_string())
        }
    } else {
        (vec![], c.command.clone(), "/".to_string(), "0".to_string())
    };

    Ok(Json(serde_json::json!({
        "Id": c.id,
        "Created": c.created_at.to_rfc3339(),
        "Path": c.command.first().cloned().unwrap_or_default(),
        "Args": if c.command.len() > 1 { c.command[1..].to_vec() } else { vec![] },
        "State": {
            "Status": status_str,
            "Running": matches!(c.status, ContainerStatus::Running),
            "Paused": matches!(c.status, ContainerStatus::Paused),
            "ExitCode": match c.status {
                ContainerStatus::Exited(code) => code,
                _ => 0,
            }
        },
        "Image": c.image,
        "Name": format!("/{}", c.name),
        "RestartPolicy": { "Name": c.restart_policy.to_string() },
        "Config": {
            "Image": c.image,
            "Cmd": cmd,
            "Env": env,
            "WorkingDir": cwd,
            "User": user,
            "Labels": {}
        },
        "HostConfig": {
            "NetworkMode": "default",
            "PortBindings": {},
            "RestartPolicy": { "Name": c.restart_policy.to_string() }
        },
        "NetworkSettings": {
            "Ports": c.ports
        }
    })))
}

#[derive(Deserialize)]
pub struct CreateExecRequest {
    #[serde(rename = "Cmd")]
    pub cmd: Option<Vec<String>>,
    #[serde(rename = "Env")]
    pub env: Option<Vec<String>>,
    #[serde(rename = "WorkingDir")]
    pub working_dir: Option<String>,
    #[serde(rename = "User")]
    pub user: Option<String>,
    #[serde(rename = "Detach")]
    pub detach: Option<bool>,
}

pub async fn create_container_exec(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    Json(payload): Json<CreateExecRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = ContainerStore::with_home(state.home.clone());
    let c = store.find(&id).ok_or(StatusCode::NOT_FOUND)?;
    let exec_id = hex::encode(crate::storage::container_store::rand_id());

    let bundle = PathBuf::from(&c.bundle_path);
    let exec_info = serde_json::json!({
        "container_id": c.id,
        "cmd": payload.cmd.unwrap_or_default(),
        "env": payload.env.unwrap_or_default(),
        "working_dir": payload.working_dir,
        "user": payload.user,
        "detach": payload.detach.unwrap_or(false)
    });
    let _ = fs::write(
        bundle.join(format!("exec-{}.json", exec_id)),
        serde_json::to_string(&exec_info).unwrap(),
    );

    Ok(Json(serde_json::json!({
        "Id": exec_id
    })))
}

pub async fn start_exec_instance(
    State(state): State<DaemonState>,
    Path(exec_id): Path<String>,
) -> Result<String, StatusCode> {
    let store = ContainerStore::with_home(state.home.clone());
    for c in store.list() {
        let bundle = PathBuf::from(&c.bundle_path);
        let exec_file = bundle.join(format!("exec-{}.json", exec_id));
        if exec_file.exists() {
            if let Ok(content) = fs::read_to_string(&exec_file) {
                if let Ok(info) = serde_json::from_str::<serde_json::Value>(&content) {
                    let cmd: Vec<String> = info
                        .get("cmd")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_default();
                    let env: Vec<String> = info
                        .get("env")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_default();
                    let wd = info.get("working_dir").and_then(|v| v.as_str());
                    let user = info.get("user").and_then(|v| v.as_str());
                    let detach = info
                        .get("detach")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    let log_path = bundle.join(format!("exec-{}.log", exec_id));
                    let code =
                        crate::runtime::exec_in_bundle(&bundle, &cmd, &env, wd, user, detach)
                            .unwrap_or(1);
                    let _ = fs::write(
                        bundle.join(format!("exec-{}.done", exec_id)),
                        code.to_string(),
                    );
                    let output = if log_path.exists() {
                        fs::read_to_string(&log_path).unwrap_or_default()
                    } else {
                        String::new()
                    };
                    return Ok(output);
                }
            }
        }
    }
    Err(StatusCode::NOT_FOUND)
}

pub async fn inspect_exec_instance(
    State(state): State<DaemonState>,
    Path(exec_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = ContainerStore::with_home(state.home.clone());
    for c in store.list() {
        let bundle = PathBuf::from(&c.bundle_path);
        let exec_file = bundle.join(format!("exec-{}.json", exec_id));
        if exec_file.exists() {
            let done_file = bundle.join(format!("exec-{}.done", exec_id));
            let (running, exit_code) = if done_file.exists() {
                let code = fs::read_to_string(&done_file)
                    .ok()
                    .and_then(|s| s.trim().parse::<i32>().ok())
                    .unwrap_or(0);
                (false, serde_json::json!(code))
            } else {
                (true, serde_json::Value::Null)
            };
            return Ok(Json(serde_json::json!({
                "ID": exec_id,
                "Running": running,
                "ExitCode": exit_code,
                "ContainerID": c.id
            })));
        }
    }
    Err(StatusCode::NOT_FOUND)
}
