use crate::cli::{KubeDownArgs, KubeGenerateArgs, KubePlayArgs, RunArgs};
use crate::pod::PodStore;
use crate::storage::ContainerStore;
use crate::volume::MountSpec;
use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubePodYaml {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: KubeMetadata,
    pub spec: KubePodSpec,
    #[serde(default)]
    pub status: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubeMetadata {
    pub name: String,
    #[serde(rename = "creationTimestamp", skip_serializing_if = "Option::is_none")]
    pub creation_timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubePodSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub containers: Vec<KubeContainerSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<serde_json::Value>>,
    #[serde(rename = "restartPolicy", default, skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<String>,
    #[serde(rename = "hostNetwork", default, skip_serializing_if = "Option::is_none")]
    pub host_network: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubeContainerSpec {
    pub name: String,
    pub image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<KubeContainerPort>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<KubeEnvVar>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<serde_json::Value>,
    #[serde(rename = "securityContext", default, skip_serializing_if = "Option::is_none")]
    pub security_context: Option<serde_json::Value>,
    #[serde(rename = "volumeMounts", default, skip_serializing_if = "Option::is_none")]
    pub volume_mounts: Option<Vec<serde_json::Value>>,
    #[serde(rename = "workingDir", default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubeContainerPort {
    #[serde(rename = "containerPort")]
    pub container_port: u16,
    #[serde(rename = "hostPort", skip_serializing_if = "Option::is_none")]
    pub host_port: Option<u16>,
    #[serde(rename = "hostIP", default, skip_serializing_if = "Option::is_none")]
    pub host_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubeEnvVar {
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
}

pub struct KubeManager;

impl KubeManager {
    /// Play a Kubernetes YAML file (Pod, Deployment, Service, Volume)
    pub async fn play_kube(yaml_path: &Path) -> Result<()> {
        let mut args = KubePlayArgs::default();
        args.file = yaml_path.to_string_lossy().to_string();
        args.start = true;
        Self::play_kube_with_args(&args).await
    }

    pub async fn play_kube_with_args(args: &KubePlayArgs) -> Result<()> {
        if args.down {
            let down_args = KubeDownArgs {
                file: args.file.clone(),
                force: false,
            };
            return Self::play_kube_down_with_args(&down_args);
        }
        let content = if args.file == "-" {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        } else {
            let yaml_path = Path::new(&args.file);
            fs::read_to_string(yaml_path)
                .with_context(|| format!("Failed to read Kubernetes YAML at {:?}", yaml_path))?
        };

        for doc in serde_yaml::Deserializer::from_str(&content) {
            let val = serde_yaml::Value::deserialize(doc)?;
            Self::play_kube_value(val).await?;
        }
        Ok(())
    }

    pub async fn play_kube_value(val: serde_yaml::Value) -> Result<()> {
        let kind = val.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        match kind {
            "Pod" => {
                let pod_yaml: KubePodYaml = serde_yaml::from_value(val)?;
                Self::play_pod(pod_yaml).await?;
            }
            "Deployment" => {
                let name = val["metadata"]["name"]
                    .as_str()
                    .unwrap_or("deployment")
                    .to_string();
                let replicas = val["spec"]["replicas"].as_u64().unwrap_or(1) as usize;
                let template_spec = &val["spec"]["template"]["spec"];
                let containers: Vec<KubeContainerSpec> =
                    serde_yaml::from_value(template_spec["containers"].clone())?;

                println!(
                    "Playing Kubernetes Deployment '{}' ({} replica(s))...",
                    name, replicas
                );
                for i in 0..replicas {
                    let pod_name = if replicas == 1 {
                        name.clone()
                    } else {
                        format!("{}-{}", name, i + 1)
                    };
                    let pod_yaml = KubePodYaml {
                        api_version: "v1".to_string(),
                        kind: "Pod".to_string(),
                        metadata: KubeMetadata {
                            name: pod_name,
                            creation_timestamp: None,
                            labels: HashMap::new(),
                            annotations: HashMap::new(),
                        },
                        spec: KubePodSpec {
                            hostname: None,
                            containers: containers.clone(),
                            volumes: None,
                            restart_policy: None,
                            host_network: None,
                        },
                        status: None,
                    };
                    Self::play_pod(pod_yaml).await?;
                }
            }
            "Service" => {
                let name = val["metadata"]["name"].as_str().unwrap_or("service");
                println!("Configured Kubernetes Service '{}'", name);
            }
            "PersistentVolumeClaim" | "Volume" => {
                let name = val["metadata"]["name"].as_str().unwrap_or("volume");
                let store = crate::volume::VolumeStore::new();
                if store.find(name).is_none() {
                    let _ = store.create(Some(name), None)?;
                }
                println!("Configured Kubernetes Volume '{}'", name);
            }
            other => {
                return Err(anyhow!("Unsupported Kubernetes kind '{}'", other));
            }
        }
        Ok(())
    }

    pub async fn play_pod(pod_yaml: KubePodYaml) -> Result<()> {
        println!("Playing Kubernetes Pod '{}'...", pod_yaml.metadata.name);

        let pod_store = PodStore::new();
        let mut pod_ports = Vec::new();
        for c_spec in &pod_yaml.spec.containers {
            if let Some(ports) = &c_spec.ports {
                for p in ports {
                    if let Some(host_p) = p.host_port {
                        pod_ports.push(crate::network::PortMapping {
                            host_ip: None,
                            host_port: host_p,
                            container_port: p.container_port,
                            protocol: "tcp".to_string(),
                        });
                    }
                }
            }
        }
        let mut cfg = crate::pod::PodConfig::default();
        cfg.name = Some(pod_yaml.metadata.name.clone());
        cfg.ports = pod_ports;
        cfg.exit_policy = "stop".to_string();
        let pod = pod_store.create_with_config(cfg)?;

        for c_spec in &pod_yaml.spec.containers {
            let container_name = format!("{}-{}", pod.name, c_spec.name);
            let mut ports_vec = Vec::new();

            if let Some(ports) = &c_spec.ports {
                for p in ports {
                    if let Some(host_p) = p.host_port {
                        ports_vec.push(format!("{}:{}", host_p, p.container_port));
                    }
                }
            }

            let mut env_vec = Vec::new();
            if let Some(envs) = &c_spec.env {
                for e in envs {
                    env_vec.push(format!("{}={}", e.name, e.value.clone().unwrap_or_default()));
                }
            }

            let mut security_opt = Vec::new();
            let mut cap_drop = Vec::new();
            let mut cap_add = Vec::new();
            let mut privileged = false;
            let mut read_only = false;
            if let Some(sc) = &c_spec.security_context {
                if sc.get("procMount").and_then(|v| v.as_str()) == Some("Unmasked") {
                    security_opt.push("unmask=all".to_string());
                }
                if sc.get("privileged").and_then(|v| v.as_bool()) == Some(true) {
                    privileged = true;
                }
                if sc.get("readOnlyRootFilesystem").and_then(|v| v.as_bool()) == Some(true) {
                    read_only = true;
                }
                if let Some(caps) = sc.get("capabilities") {
                    if let Some(drops) = caps.get("drop").and_then(|v| v.as_array()) {
                        for d in drops {
                            if let Some(s) = d.as_str() {
                                cap_drop.push(s.to_string());
                            }
                        }
                    }
                    if let Some(adds) = caps.get("add").and_then(|v| v.as_array()) {
                        for a in adds {
                            if let Some(s) = a.as_str() {
                                cap_add.push(s.to_string());
                            }
                        }
                    }
                }
            }

            println!("Creating pod container: {}", container_name);

            let run_args = RunArgs {
                registry_auth: Default::default(),
                interactive: false,
                tty: false,
                detach: true,
                rm: false,
                rmi: false,
                name: Some(container_name.clone()),
                replace: false,
                env: env_vec,
                unsetenv: Vec::new(),
                unsetenv_all: false,
                systemd: None,
                ports: ports_vec,
                volumes: Vec::new(),
                image_volume: None,
                memory: None,
                kernel_memory: None,
                labels: Vec::new(),
                dns: Vec::new(),
                cidfile: None,
                conmon_pidfile: None,
                cpus: None,
                pids_limit: None,
                rootless: true,
                restart: "no".to_string(),
                health_cmd: None,
                secret: Vec::new(),
                health_startup_cmd: None,
                health_startup_interval: None,
                health_startup_timeout: None,
                health_startup_retries: None,
                health_startup_success: None,
                health_max_log_count: None,
                health_max_log_size: None,
                health_log_destination: None,
                platform: None,
                privileged,
                network: "auto".to_string(),
                disable_content_trust: false,
                gpus: None,
                entrypoint: None,
                tz: Vec::new(),
                env_file: None,
                user: None,
                hostuser: Vec::new(),
                group_entry: Vec::new(),
                hostname: None,
                no_hostname: false,
                add_host: Vec::new(),
                shm_size: None,
                cap_add,
                cap_drop,
                read_only,
                http_proxy: false,
                read_only_tmpfs: None,
                init: false,
                tmpfs: Vec::new(),
                devices: Vec::new(),
                security_opt,
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
                hooks_dir: None,
                conmon_syslog: false,
                ipc: None,
                pid: None,
                uts: None,
                userns: Vec::new(),
                uidmap: Vec::new(),
                gidmap: Vec::new(),
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
                health_on_failure: None,
                health_start_interval: None,
                no_healthcheck: false,
                attach: Vec::new(),
                preserve_fds: None,
                preserve_fd: Vec::new(),
                pull: None,
                quiet: false,
                log_driver: vec![],
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
                workdir: None,
                pod: Some(pod.name.clone()),
                rootfs: None,
                default_mounts_file: None,
                timeout: None,
                image: c_spec.image.clone(),
                command: c_spec.command.clone().unwrap_or_default(),
            };

            let _ = crate::run_container(run_args).await?;
            let _ = pod_store.add_container_to_pod(&pod.name, &container_name);
        }

        println!(
            "Pod '{}' started successfully with {} container(s)",
            pod.name,
            pod_yaml.spec.containers.len()
        );
        Ok(())
    }

    /// Tear down resources played via `play kube`.
    pub fn play_kube_down(yaml_path: &Path) -> Result<()> {
        let down_args = KubeDownArgs {
            file: yaml_path.to_string_lossy().to_string(),
            force: false,
        };
        Self::play_kube_down_with_args(&down_args)
    }

    pub fn play_kube_down_with_args(args: &KubeDownArgs) -> Result<()> {
        let content = if args.file == "-" {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        } else {
            let yaml_path = Path::new(&args.file);
            fs::read_to_string(yaml_path)
                .with_context(|| format!("Failed to read Kubernetes YAML at {:?}", yaml_path))?
        };

        for doc in serde_yaml::Deserializer::from_str(&content) {
            if let Ok(val) = serde_yaml::Value::deserialize(doc) {
                let _ = Self::play_kube_down_value(val);
            }
        }
        Ok(())
    }

    pub fn play_kube_down_value(val: serde_yaml::Value) -> Result<()> {
        let kind = val.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        match kind {
            "Pod" => {
                if let Ok(pod_yaml) = serde_yaml::from_value::<KubePodYaml>(val) {
                    Self::play_pod_down(&pod_yaml.metadata.name, &pod_yaml.spec.containers)?;
                }
            }
            "Deployment" => {
                let name = val["metadata"]["name"].as_str().unwrap_or("deployment");
                let replicas = val["spec"]["replicas"].as_u64().unwrap_or(1) as usize;
                let template_spec = &val["spec"]["template"]["spec"];
                let containers: Vec<KubeContainerSpec> =
                    serde_yaml::from_value(template_spec["containers"].clone()).unwrap_or_default();
                for i in 0..replicas {
                    let pod_name = if replicas == 1 {
                        name.to_string()
                    } else {
                        format!("{}-{}", name, i + 1)
                    };
                    let _ = Self::play_pod_down(&pod_name, &containers);
                }
            }
            "PersistentVolumeClaim" | "Volume" => {
                let name = val["metadata"]["name"].as_str().unwrap_or("volume");
                let _ = crate::volume::VolumeStore::new().remove(name);
                println!("Volume '{}' removed", name);
            }
            "Service" => {
                let name = val["metadata"]["name"].as_str().unwrap_or("service");
                println!("Service '{}' removed", name);
            }
            _ => {}
        }
        Ok(())
    }

    fn play_pod_down(pod_name: &str, containers: &[KubeContainerSpec]) -> Result<()> {
        let pod_store = PodStore::new();
        if let Some(pod) = pod_store.find(pod_name) {
            println!("Tearing down pod '{}'...", pod.name);
            pod_store.remove_with_force(&pod.name, true)?;
            println!("Pod '{}' removed", pod.name);
        } else {
            let c_store = ContainerStore::new();
            for c_spec in containers {
                let container_name = format!("{}-{}", pod_name, c_spec.name);
                if c_store.find(&container_name).is_some() {
                    let _ = crate::stop_container(&container_name, None);
                    let _ = crate::remove_container(&container_name, true);
                }
            }
            println!("Pod '{}' resources removed", pod_name);
        }
        Ok(())
    }

    /// Generate a Kubernetes Pod YAML for an existing container or pod (boxr generate kube)
    pub fn generate_kube(target: &str) -> Result<String> {
        let args = KubeGenerateArgs {
            targets: vec![target.to_string()],
            ..Default::default()
        };
        Self::generate_kube_with_args(&args)
    }

    pub fn generate_kube_with_args(args: &KubeGenerateArgs) -> Result<String> {
        let target = args
            .targets
            .first()
            .map(String::as_str)
            .ok_or_else(|| anyhow!("must provide at least one container, pod, or volume name"))?;

        let c_store = ContainerStore::new();
        let p_store = PodStore::new();

        let (pod_name, app_label, containers, pod_ports) = if let Some(pod) = p_store.find(target) {
            let infra_name = p_store.infra_name(&pod);
            let mut conts = Vec::new();
            for cid in &pod.containers {
                if cid == &infra_name || cid == &pod.infra_container_id {
                    continue;
                }
                if let Some(c) = c_store.find(cid) {
                    if c.name == infra_name || c.id == pod.infra_container_id {
                        continue;
                    }
                    conts.push(c);
                }
            }
            if conts.is_empty() {
                // Also check if any containers have `boxr.pod` matching this pod
                for c in c_store.list() {
                    if c.name == infra_name || c.id == pod.infra_container_id {
                        continue;
                    }
                    let cfg_path = Path::new(&c.bundle_path).join("config.json");
                    if let Ok(raw) = fs::read_to_string(&cfg_path) {
                        if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&raw) {
                            if let Some(ann) = &spec.annotations {
                                if ann.get("boxr.pod").is_some_and(|p| p == &pod.id || p == &pod.name) {
                                    conts.push(c);
                                }
                            }
                        }
                    }
                }
            }
            if conts.is_empty() {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "pod {} only has an infra container",
                    pod.id
                ));
            }
            (pod.name.clone(), pod.name.clone(), conts, pod.ports.clone())
        } else if let Some(c) = c_store.find(target) {
            let pname = format!("{}-pod", c.name);
            (pname.clone(), pname, vec![c], Vec::new())
        } else {
            return Err(anyhow!("No such container or pod: '{}'", target));
        };

        let mut kube_containers = Vec::new();
        let mut kube_volumes: Vec<serde_json::Value> = Vec::new();
        let mut seen_vol_names = std::collections::HashSet::new();

        for (idx, c) in containers.iter().enumerate() {
            let mut ports = Vec::new();
            for p in &c.ports {
                ports.push(KubeContainerPort {
                    container_port: p.container_port,
                    host_port: if p.host_port > 0 { Some(p.host_port) } else { None },
                    host_ip: p.host_ip.clone(),
                    protocol: if p.protocol.eq_ignore_ascii_case("tcp") || p.protocol.is_empty() {
                        None
                    } else {
                        Some(p.protocol.to_uppercase())
                    },
                });
            }
            if idx == 0 && ports.is_empty() && !pod_ports.is_empty() {
                for p in &pod_ports {
                    ports.push(KubeContainerPort {
                        container_port: p.container_port,
                        host_port: if p.host_port > 0 { Some(p.host_port) } else { None },
                        host_ip: p.host_ip.clone(),
                        protocol: if p.protocol.eq_ignore_ascii_case("tcp") || p.protocol.is_empty() {
                            None
                        } else {
                            Some(p.protocol.to_uppercase())
                        },
                    });
                }
            }

            let bundle_path = Path::new(&c.bundle_path);
            let mut annotations: HashMap<String, String> = HashMap::new();
            if let Ok(raw_cfg) = fs::read_to_string(bundle_path.join("config.json")) {
                if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&raw_cfg) {
                    if let Some(ann) = spec.annotations {
                        annotations = ann;
                    }
                }
            }

            // Build securityContext from cap_drop / cap_add / security_opt / privileged
            let mut sec_ctx = serde_json::Map::new();
            let cap_drop: Vec<String> = annotations
                .get("boxr.cap_drop")
                .and_then(|v| serde_json::from_str(v).ok())
                .unwrap_or_default();
            let cap_add: Vec<String> = annotations
                .get("boxr.cap_add")
                .and_then(|v| serde_json::from_str(v).ok())
                .unwrap_or_default();
            if !cap_drop.is_empty() || !cap_add.is_empty() {
                let mut caps = serde_json::Map::new();
                if !cap_drop.is_empty() {
                    let norm_drops: Vec<serde_json::Value> = cap_drop
                        .iter()
                        .map(|d| {
                            let u = d.to_uppercase();
                            let s = if u.starts_with("CAP_") { u } else { format!("CAP_{}", u) };
                            serde_json::Value::String(s)
                        })
                        .collect();
                    caps.insert("drop".to_string(), serde_json::Value::Array(norm_drops));
                }
                if !cap_add.is_empty() {
                    let norm_adds: Vec<serde_json::Value> = cap_add
                        .iter()
                        .map(|a| {
                            let u = a.to_uppercase();
                            let s = if u.starts_with("CAP_") { u } else { format!("CAP_{}", u) };
                            serde_json::Value::String(s)
                        })
                        .collect();
                    caps.insert("add".to_string(), serde_json::Value::Array(norm_adds));
                }
                sec_ctx.insert("capabilities".to_string(), serde_json::Value::Object(caps));
            }

            let security_opt: Vec<String> = annotations
                .get("boxr.security_opt")
                .and_then(|v| serde_json::from_str(v).ok())
                .unwrap_or_default();
            if security_opt.iter().any(|s| s == "unmask=all") {
                sec_ctx.insert(
                    "procMount".to_string(),
                    serde_json::Value::String("Unmasked".to_string()),
                );
            }

            // Build volumeMounts and pod volumes from mounts.json
            let mut vol_mounts: Vec<serde_json::Value> = Vec::new();
            if let Ok(raw_mounts) = fs::read_to_string(bundle_path.join("mounts.json")) {
                if let Ok(mounts) = serde_json::from_str::<Vec<MountSpec>>(&raw_mounts) {
                    for m in mounts {
                        if let Some(vname) = &m.volume_name {
                            let pvc_name = format!(
                                "{}-pvc",
                                sanitize_k8s_volume_name(vname)
                            );
                            vol_mounts.push(serde_json::json!({
                                "mountPath": m.destination,
                                "name": pvc_name,
                            }));
                            if seen_vol_names.insert(pvc_name.clone()) {
                                kube_volumes.push(serde_json::json!({
                                    "name": pvc_name,
                                    "persistentVolumeClaim": {
                                        "claimName": vname,
                                    }
                                }));
                            }
                        } else {
                            let host_vol_name = format!(
                                "{}-host-{}",
                                sanitize_k8s_volume_name(&m.source.to_string_lossy()),
                                kube_volumes.len()
                            );
                            vol_mounts.push(serde_json::json!({
                                "mountPath": m.destination,
                                "name": host_vol_name,
                            }));
                            if seen_vol_names.insert(host_vol_name.clone()) {
                                kube_volumes.push(serde_json::json!({
                                    "name": host_vol_name,
                                    "hostPath": {
                                        "path": m.source,
                                        "type": "Directory",
                                    }
                                }));
                            }
                        }
                    }
                }
            }

            kube_containers.push(KubeContainerSpec {
                name: c.name.clone(),
                image: c.image.clone(),
                command: if c.command.is_empty() {
                    None
                } else {
                    Some(c.command.clone())
                },
                args: None,
                ports: if ports.is_empty() { None } else { Some(ports) },
                env: None,
                resources: None,
                security_context: if sec_ctx.is_empty() {
                    None
                } else {
                    Some(serde_json::Value::Object(sec_ctx))
                },
                volume_mounts: if vol_mounts.is_empty() {
                    None
                } else {
                    Some(vol_mounts)
                },
                working_dir: None,
            });
        }

        let mut labels = HashMap::new();
        labels.insert("app".to_string(), app_label.clone());
        let creation_ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let effective_type = args
            .kind_type
            .clone()
            .or_else(kube_generate_type_from_containers_conf)
            .unwrap_or_else(|| "pod".to_string())
            .to_lowercase();

        let pod_spec = KubePodSpec {
            hostname: None,
            containers: kube_containers,
            volumes: if kube_volumes.is_empty() {
                None
            } else {
                Some(kube_volumes)
            },
            restart_policy: None,
            host_network: None,
        };

        let mut yaml_str = match effective_type.as_str() {
            "deployment" => {
                let replicas = args.replicas.unwrap_or(1);
                let doc = serde_json::json!({
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {
                        "creationTimestamp": creation_ts,
                        "labels": labels,
                        "name": format!("{}-deployment", pod_name),
                    },
                    "spec": {
                        "replicas": replicas,
                        "selector": {
                            "matchLabels": {
                                "app": app_label,
                            }
                        },
                        "template": {
                            "metadata": {
                                "creationTimestamp": null,
                                "labels": {
                                    "app": app_label,
                                }
                            },
                            "spec": pod_spec,
                        }
                    },
                    "status": {}
                });
                serde_yaml::to_string(&doc)?
            }
            "job" => {
                let doc = serde_json::json!({
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "metadata": {
                        "creationTimestamp": creation_ts,
                        "labels": labels,
                        "name": format!("{}-job", pod_name),
                    },
                    "spec": {
                        "template": {
                            "metadata": {
                                "creationTimestamp": null,
                                "labels": {
                                    "app": app_label,
                                }
                            },
                            "spec": pod_spec,
                        }
                    },
                    "status": {}
                });
                serde_yaml::to_string(&doc)?
            }
            _ => {
                let pod_yaml = KubePodYaml {
                    api_version: "v1".to_string(),
                    kind: "Pod".to_string(),
                    metadata: KubeMetadata {
                        name: pod_name,
                        creation_timestamp: Some(creation_ts.clone()),
                        labels,
                        annotations: HashMap::new(),
                    },
                    spec: pod_spec,
                    status: None,
                };
                serde_yaml::to_string(&pod_yaml)?
            }
        };
        yaml_str = yaml_str.replace(
            &format!("creationTimestamp: {}", creation_ts),
            &format!("creationTimestamp: \"{}\"", creation_ts),
        );

        if let Some(out_file) = &args.filename {
            fs::write(out_file, &yaml_str)?;
        }
        Ok(yaml_str)
    }

    /// Run a command in a new user namespace (boxr unshare)
    pub fn unshare_command(command: &[String], suppress_stdout: bool) -> Result<i32> {
        let default_cmd = vec!["/bin/sh".to_string()];
        let cmd = if command.is_empty() {
            &default_cmd
        } else {
            command
        };

        #[cfg(target_os = "linux")]
        {
            crate::runtime::linux::run_unshare_cli(cmd, suppress_stdout)
        }
        #[cfg(not(target_os = "linux"))]
        {
            use std::process::Stdio;
            let mut child = std::process::Command::new(&cmd[0]);
            if cmd.len() > 1 {
                child.args(&cmd[1..]);
            }
            if suppress_stdout {
                child.stdout(Stdio::null());
            }
            let status = child.status()?;
            Ok(status.code().unwrap_or(0))
        }
    }
}

fn sanitize_k8s_volume_name(raw: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "vol".to_string()
    } else {
        out
    }
}

fn kube_generate_type_from_containers_conf() -> Option<String> {
    for var in ["CONTAINERS_CONF_OVERRIDE", "CONTAINERS_CONF"] {
        let Ok(path) = std::env::var(var) else {
            continue;
        };
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() || trimmed.starts_with('[') {
                continue;
            }
            if let Some((k, v)) = trimmed.split_once('=') {
                if k.trim() == "kube_generate_type" {
                    let val = v
                        .split('#')
                        .next()
                        .unwrap_or(v)
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'');
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_generate_kube_pod_yaml() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
    - name: web
      image: nginx:latest
      ports:
        - containerPort: 80
          hostPort: 8080
"#;

        let parsed: KubePodYaml = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(parsed.kind, "Pod");
        assert_eq!(parsed.metadata.name, "test-pod");
        assert_eq!(parsed.spec.containers.len(), 1);
        assert_eq!(parsed.spec.containers[0].name, "web");

        let generated = serde_yaml::to_string(&parsed).unwrap();
        assert!(generated.contains("kind: Pod"));
        assert!(generated.contains("name: test-pod"));
    }

    #[test]
    fn test_kube_port_mapping_requires_host_port() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-internal-port
spec:
  containers:
    - name: backend
      image: redis:alpine
      ports:
        - containerPort: 6379
"#;
        let parsed: KubePodYaml = serde_yaml::from_str(yaml).unwrap();
        let c_spec = &parsed.spec.containers[0];
        let mut ports_vec = Vec::new();
        if let Some(ports) = &c_spec.ports {
            for p in ports {
                if let Some(host_p) = p.host_port {
                    ports_vec.push(format!("{}:{}", host_p, p.container_port));
                }
            }
        }
        assert!(
            ports_vec.is_empty(),
            "containerPort without hostPort must not bind host port"
        );
    }
}
