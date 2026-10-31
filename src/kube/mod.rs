use crate::cli::kube::{KubeGenerateArgs, KubePlayArgs};
use crate::cli::RunArgs;
use crate::pod::{PodConfig, PodStore};
use crate::storage::{ContainerStatus, ContainerStore};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

static KUBE_WAIT_INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn kube_wait_sig_handler(_sig: libc::c_int) {
    KUBE_WAIT_INTERRUPTED.store(true, Ordering::SeqCst);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubePodYaml {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: KubeMetadata,
    pub spec: KubePodSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeMetadata {
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub labels: HashMap<String, String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub annotations: HashMap<String, String>,
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    T: Default + Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    let opt = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubePodSpec {
    #[serde(default)]
    pub containers: Vec<KubeContainerSpec>,
    #[serde(rename = "initContainers", default, skip_serializing_if = "Option::is_none")]
    pub init_containers: Option<Vec<KubeContainerSpec>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<KubeVolume>>,
}

fn deserialize_opt_string_vec<'de, D>(deserializer: D) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<Vec<serde_yaml::Value>>::deserialize(deserializer)?;
    Ok(opt.map(|vec| {
        vec.into_iter()
            .map(|v| match v {
                serde_yaml::Value::String(s) => s,
                serde_yaml::Value::Bool(b) => b.to_string(),
                serde_yaml::Value::Number(n) => n.to_string(),
                other => serde_yaml::to_string(&other).unwrap_or_default().trim().to_string(),
            })
            .collect()
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeContainerSpec {
    pub name: String,
    pub image: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_opt_string_vec"
    )]
    pub command: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_opt_string_vec"
    )]
    pub args: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<KubeContainerPort>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<KubeEnvVar>>,
    #[serde(rename = "workingDir", default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(rename = "securityContext", default, skip_serializing_if = "Option::is_none")]
    pub security_context: Option<KubeSecurityContext>,
    #[serde(rename = "volumeMounts", default, skip_serializing_if = "Option::is_none")]
    pub volume_mounts: Option<Vec<KubeVolumeMount>>,
    #[serde(rename = "livenessProbe", default, skip_serializing_if = "Option::is_none")]
    pub liveness_probe: Option<KubeProbe>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeSecurityContext {
    #[serde(rename = "readOnlyRootFilesystem", default, skip_serializing_if = "Option::is_none")]
    pub read_only_root_filesystem: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    #[serde(rename = "runAsUser", default, skip_serializing_if = "Option::is_none")]
    pub run_as_user: Option<u32>,
    #[serde(rename = "runAsGroup", default, skip_serializing_if = "Option::is_none")]
    pub run_as_group: Option<u32>,
    #[serde(rename = "seLinuxOptions", default, skip_serializing_if = "Option::is_none")]
    pub selinux_options: Option<KubeSeLinuxOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeSeLinuxOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filetype: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeVolumeMount {
    pub name: String,
    #[serde(rename = "mountPath")]
    pub mount_path: String,
    #[serde(rename = "readOnly", default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeVolume {
    pub name: String,
    #[serde(rename = "hostPath", default, skip_serializing_if = "Option::is_none")]
    pub host_path: Option<KubeHostPath>,
    #[serde(
        rename = "persistentVolumeClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub persistent_volume_claim: Option<KubePvcVolumeSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<KubeImageVolumeSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeHostPath {
    pub path: String,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub path_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubePvcVolumeSource {
    #[serde(rename = "claimName")]
    pub claim_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeImageVolumeSource {
    pub reference: String,
    #[serde(rename = "pullPolicy", default, skip_serializing_if = "Option::is_none")]
    pub pull_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeProbe {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<KubeExecAction>,
    #[serde(rename = "initialDelaySeconds", default, skip_serializing_if = "Option::is_none")]
    pub initial_delay_seconds: Option<u64>,
    #[serde(rename = "failureThreshold", default, skip_serializing_if = "Option::is_none")]
    pub failure_threshold: Option<u32>,
    #[serde(rename = "periodSeconds", default, skip_serializing_if = "Option::is_none")]
    pub period_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeExecAction {
    #[serde(default)]
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubeContainerPort {
    #[serde(rename = "containerPort", default = "default_container_port")]
    pub container_port: u16,
    #[serde(rename = "hostPort", default)]
    pub host_port: Option<u16>,
    #[serde(rename = "hostIP", default, skip_serializing_if = "Option::is_none")]
    pub host_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

fn default_container_port() -> u16 {
    0
}

fn decode_base64_simple(input: &str) -> Vec<u8> {
    let mut vals = Vec::new();
    for b in input.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        vals.push(v);
    }
    let mut out = Vec::new();
    for chunk in vals.chunks(4) {
        if chunk.len() >= 2 {
            out.push((chunk[0] << 2) | (chunk[1] >> 4));
        }
        if chunk.len() >= 3 {
            out.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if chunk.len() >= 4 {
            out.push((chunk[2] << 6) | chunk[3]);
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubeEnvVar {
    pub name: String,
    #[serde(default)]
    pub value: String,
    #[serde(rename = "valueFrom", default, skip_serializing_if = "Option::is_none")]
    pub value_from: Option<KubeEnvVarSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeEnvVarSource {
    #[serde(rename = "configMapKeyRef", default, skip_serializing_if = "Option::is_none")]
    pub config_map_key_ref: Option<KubeKeySelector>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeKeySelector {
    pub name: String,
    pub key: String,
}

pub struct KubeManager;

impl KubeManager {
    async fn read_yaml_source(source: &str) -> Result<String> {
        if source == "-" {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .context("Failed to read Kubernetes YAML from stdin")?;
            return Ok(s);
        }
        if source.starts_with("http://") || source.starts_with("https://") {
            let resp = reqwest::get(source)
                .await
                .with_context(|| format!("Failed to fetch Kubernetes YAML URL {}", source))?;
            if !resp.status().is_success() {
                return Err(anyhow!(
                    "Failed to fetch Kubernetes YAML URL {}: HTTP {}",
                    source,
                    resp.status()
                ));
            }
            return resp.text().await.context("Failed to read URL body");
        }
        fs::read_to_string(source)
            .with_context(|| format!("Failed to read Kubernetes YAML at {:?}", source))
    }

    fn read_yaml_source_blocking(source: &str) -> Result<String> {
        if source == "-" {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .context("Failed to read Kubernetes YAML from stdin")?;
            return Ok(s);
        }
        if source.starts_with("http://") || source.starts_with("https://") {
            let out = std::process::Command::new("curl")
                .args(["-fsSL", source])
                .output()
                .with_context(|| format!("Failed to fetch URL {}", source))?;
            if !out.status.success() {
                return Err(anyhow!("Failed to fetch URL {}", source));
            }
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        fs::read_to_string(source)
            .with_context(|| format!("Failed to read Kubernetes YAML at {:?}", source))
    }

    fn load_configmaps(paths: &[String]) -> Result<HashMap<(String, String), String>> {
        let mut map = HashMap::new();
        for raw_arg in paths {
            let candidates: Vec<&str> = if Path::new(raw_arg).exists() {
                vec![raw_arg.as_str()]
            } else {
                raw_arg.split(',').collect()
            };
            for p in candidates {
                let p = p.trim();
                if p.is_empty() {
                    continue;
                }
                let content = fs::read_to_string(p)
                    .with_context(|| format!("Failed to read ConfigMap YAML at {:?}", p))?;
                Self::extract_configmaps_from_str(&content, &mut map)?;
            }
        }
        Ok(map)
    }

    fn extract_configmaps_from_str(
        content: &str,
        map: &mut HashMap<(String, String), String>,
    ) -> Result<()> {
        for doc in serde_yaml::Deserializer::from_str(content) {
            let val = serde_yaml::Value::deserialize(doc)?;
            if val.is_null() {
                continue;
            }
            let kind = val.get("kind").and_then(|k| k.as_str()).unwrap_or("");
            if kind == "ConfigMap" {
                let cm_name = val["metadata"]["name"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                if let Some(data) = val.get("data").and_then(|d| d.as_mapping()) {
                    for (k, v) in data {
                        if let Some(k_str) = k.as_str() {
                            let v_str = match v {
                                serde_yaml::Value::String(s) => s.clone(),
                                serde_yaml::Value::Number(n) => n.to_string(),
                                serde_yaml::Value::Bool(b) => b.to_string(),
                                _ => String::new(),
                            };
                            map.insert((cm_name.clone(), k_str.to_string()), v_str);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Play a Kubernetes YAML file (Pod, Deployment, Service, Volume)
    pub async fn play_kube(yaml_path: &Path) -> Result<()> {
        let args = KubePlayArgs {
            file: yaml_path.to_string_lossy().to_string(),
            start: true,
            tls_verify: true,
            ..Default::default()
        };
        Self::play_kube_with_args(&args).await
    }

    pub async fn play_kube_with_opts(
        yaml_path: &Path,
        replace: bool,
        service_container: bool,
        exit_code_propagation: Option<&str>,
    ) -> Result<()> {
        let args = KubePlayArgs {
            file: yaml_path.to_string_lossy().to_string(),
            replace,
            service_container,
            service_exit_code_propagation: exit_code_propagation.map(String::from),
            start: true,
            tls_verify: true,
            ..Default::default()
        };
        Self::play_kube_with_args(&args).await
    }

    pub async fn play_kube_with_args(args: &KubePlayArgs) -> Result<()> {
        if args.down {
            return Self::play_kube_down_str(&args.file);
        }
        if let Some(auth) = &args.authfile {
            if !Path::new(auth).exists() {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "credential file is not accessible: faccessat {}: no such file or directory",
                    auth
                ));
            }
        }
        let _reg_guard = crate::oci::registry_options::RegistryOptionsGuard::install(
            crate::oci::registry_options::RegistryOptions {
                cert_dir: None,
                inline_creds: None,
                tls_verify: Some(args.tls_verify),
                authfile: args.authfile.as_ref().map(PathBuf::from),
            },
        );
        for ann in &args.annotations {
            if !ann.contains('=') {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "annotation {:?} must include an '=' sign",
                    ann
                ));
            }
        }
        for lbl in &args.labels {
            if let Some((k, v)) = lbl.split_once('=') {
                if v.contains(',') {
                    crate::cli::usage_errors::exit_usage_error(format!(
                        "invalid label value {:?} for key {:?}",
                        v, k
                    ));
                }
            }
        }

        let saved_notify_sock = std::env::var("NOTIFY_SOCKET").ok().filter(|s| !s.is_empty());
        if saved_notify_sock.is_some() && args.service_container {
            unsafe {
                std::env::remove_var("NOTIFY_SOCKET");
            }
        }

        let mut configmaps = Self::load_configmaps(&args.configmaps)?;
        let content = Self::read_yaml_source(&args.file).await?;
        Self::extract_configmaps_from_str(&content, &mut configmaps)?;

        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let yaml_sha = hex::encode(hasher.finalize());
        let service_ctr_name = if args.service_container {
            Some(format!("{}-service", &yaml_sha[..12]))
        } else {
            None
        };

        let mut docs = Vec::new();
        let mut pod_names = Vec::new();
        let mut first_image = None;
        for doc in serde_yaml::Deserializer::from_str(&content) {
            let val = serde_yaml::Value::deserialize(doc)?;
            if val.is_null() {
                continue;
            }
            if val.get("kind").and_then(|k| k.as_str()) == Some("Pod") {
                if let Some(pname) = val["metadata"]["name"].as_str() {
                    pod_names.push(pname.to_string());
                }
                if first_image.is_none() {
                    first_image = val["spec"]["containers"]
                        .as_sequence()
                        .and_then(|s| s.first())
                        .and_then(|c| c.get("image"))
                        .and_then(|i| i.as_str())
                        .map(String::from);
                }
            }
            docs.push(val);
        }

        if let Some(sc_name) = &service_ctr_name {
            let sc_image = first_image.unwrap_or_else(|| {
                crate::storage::ImageStore::new()
                    .list()
                    .first()
                    .map(|i| i.qualified_name())
                    .unwrap_or_else(|| "alpine:3.20".to_string())
            });
            if args.replace {
                let _ = crate::remove_container_quiet(sc_name, true, false);
            }
            let mut sc_annotations = vec![
                "boxr.is_service=true".to_string(),
                "boxr.kube_service_container=true".to_string(),
                format!("boxr.service_pods={}", pod_names.join(",")),
                "boxr.stop_timeout=10".to_string(),
            ];
            if let Some(prop) = &args.service_exit_code_propagation {
                sc_annotations.push(format!(
                    "io.podman.annotations.kube.play.exit-code-propagation={}",
                    prop
                ));
            }
            if let Some(ref sock) = saved_notify_sock {
                sc_annotations.push(format!("boxr.sdnotify_socket={}", sock));
                sc_annotations.push("boxr.sdnotify_mode=ignore".to_string());
            }
            let sc_run = RunArgs {
                name: Some(sc_name.clone()),
                replace: true,
                detach: true,
                restart: "no".to_string(),
                stop_timeout: Some(10),
                annotations: sc_annotations,
                image: sc_image,
                command: vec!["sleep".to_string(), "infinity".to_string()],
                network: "none".to_string(),
                rootless: true,
                sig_proxy: true,
                sdnotify: if saved_notify_sock.is_some() {
                    Some("ignore".to_string())
                } else {
                    None
                },
                ..Default::default()
            };
            let _ = crate::run_container_with_output(
                sc_run,
                crate::CliOutputPolicy {
                    noout: true,
                    out: None,
                },
            )
            .await;
        }

        for val in docs.clone() {
            if args.replace && saved_notify_sock.is_some() {
                let _ = Self::play_kube_down_value(val.clone());
            }
            if let Err(e) = Self::play_kube_value_with_args(
                val,
                args,
                &configmaps,
                service_ctr_name.as_deref(),
            )
            .await
            {
                if let Some(ref sc) = service_ctr_name {
                    let _ = crate::remove_container_quiet(sc, true, false);
                }
                return Err(e);
            }
        }

        #[cfg(unix)]
        if let (Some(sock), Some(sc)) = (saved_notify_sock.as_ref(), service_ctr_name.as_deref()) {
            let c_store = ContainerStore::new();
            if let Some(sc_rec) = c_store.find(sc) {
                let b = std::path::PathBuf::from(&sc_rec.bundle_path);
                if let Ok(pid_str) = fs::read_to_string(b.join("conmon.pid")) {
                    let pid_trim = pid_str.trim();
                    if !pid_trim.is_empty() {
                        std::thread::sleep(std::time::Duration::from_millis(250));
                        use std::os::unix::net::UnixDatagram;
                        if let Ok(dgram) = UnixDatagram::unbound() {
                            let msg = format!("MAINPID={}\nREADY=1", pid_trim);
                            let _ = dgram.send_to(msg.as_bytes(), sock);
                        }
                    }
                }
            }
        }

        if let Some(sc_name) = &service_ctr_name {
            if saved_notify_sock.is_none() {
                loop {
                    let c_store = ContainerStore::new();
                    let sc_running = c_store
                        .find(sc_name)
                        .map(|c| matches!(c.status, ContainerStatus::Running))
                        .unwrap_or(false);
                    if !sc_running {
                        break;
                    }
                    let mut any_pod_running = false;
                    let p_store = PodStore::new();
                    for pname in &pod_names {
                        if let Some(p) = p_store.find(pname) {
                            for cid in &p.containers {
                                if let Some(c) = c_store.find(cid) {
                                    if matches!(c.status, ContainerStatus::Running) {
                                        #[cfg(target_os = "linux")]
                                        {
                                            if crate::runtime::linux::is_bundle_container_alive(
                                                Path::new(&c.bundle_path),
                                            ) {
                                                any_pod_running = true;
                                            }
                                        }
                                        #[cfg(not(target_os = "linux"))]
                                        {
                                            any_pod_running = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !any_pod_running && !pod_names.is_empty() {
                        for pname in &pod_names {
                            let _ = p_store.update_status(pname, "Exited");
                        }
                        let _ = crate::stop_container_with_home_and_timeout(
                            sc_name,
                            None,
                            Some(0),
                            None,
                            true,
                            None,
                        );
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }

        if args.wait {
            KUBE_WAIT_INTERRUPTED.store(false, Ordering::SeqCst);
            #[cfg(unix)]
            unsafe {
                libc::signal(
                    libc::SIGINT,
                    kube_wait_sig_handler as *const () as libc::sighandler_t,
                );
                libc::signal(
                    libc::SIGTERM,
                    kube_wait_sig_handler as *const () as libc::sighandler_t,
                );
            }
            loop {
                if KUBE_WAIT_INTERRUPTED.load(Ordering::SeqCst) {
                    break;
                }
                let c_store = ContainerStore::new();
                let p_store = PodStore::new();
                let mut any_running = false;
                for pname in &pod_names {
                    if let Some(p) = p_store.find(pname) {
                        for cid in &p.containers {
                            if let Some(c) = c_store.find(cid) {
                                if matches!(c.status, ContainerStatus::Running) {
                                    #[cfg(target_os = "linux")]
                                    {
                                        if crate::runtime::linux::is_bundle_container_alive(
                                            Path::new(&c.bundle_path),
                                        ) {
                                            any_running = true;
                                        }
                                    }
                                    #[cfg(not(target_os = "linux"))]
                                    {
                                        any_running = true;
                                    }
                                }
                            }
                        }
                    }
                }
                if !any_running {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            println!("Cleaning up containers, pods, and volumes");
            for val in docs {
                let _ = Self::play_kube_down_value(val);
            }
        }

        Ok(())
    }

    pub async fn play_kube_value(val: serde_yaml::Value) -> Result<()> {
        let default_args = KubePlayArgs {
            start: true,
            tls_verify: true,
            ..Default::default()
        };
        Self::play_kube_value_with_args(val, &default_args, &HashMap::new(), None).await
    }

    pub async fn play_kube_value_with_args(
        val: serde_yaml::Value,
        args: &KubePlayArgs,
        configmaps: &HashMap<(String, String), String>,
        service_ctr_name: Option<&str>,
    ) -> Result<()> {
        let kind = val.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        let mut cli_labels = HashMap::new();
        for l in &args.labels {
            if let Some((k, v)) = l.split_once('=') {
                cli_labels.insert(k.to_string(), v.to_string());
            }
        }
        match kind {
            "Pod" => {
                let pod_yaml: KubePodYaml = serde_yaml::from_value(val)?;
                Self::play_pod_with_args(pod_yaml, args, configmaps, service_ctr_name).await?;
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
                            labels: HashMap::new(),
                            annotations: HashMap::new(),
                        },
                        spec: KubePodSpec {
                            containers: containers.clone(),
                            init_containers: None,
                            volumes: None,
                        },
                    };
                    Self::play_pod_with_args(pod_yaml, args, configmaps, service_ctr_name).await?;
                }
            }
            "Service" | "ConfigMap" => {}
            "PersistentVolumeClaim" | "Volume" => {
                let name = val["metadata"]["name"].as_str().unwrap_or("volume");
                let mut labels = cli_labels;
                if let Some(m) = val["metadata"]["labels"].as_mapping() {
                    for (k, v) in m {
                        if let (Some(ks), Some(vs)) = (k.as_str(), v.as_str()) {
                            labels.insert(ks.to_string(), vs.to_string());
                        }
                    }
                }
                let store = crate::volume::VolumeStore::new();
                if store.find(name).is_none() {
                    let _ = store.create(Some(name), Some(labels))?;
                }
                println!("Volume:\n{}", name);
            }
            "Secret" => {
                let name = val["metadata"]["name"].as_str().unwrap_or("secret");
                let mut labels = cli_labels;
                if let Some(m) = val["metadata"]["labels"].as_mapping() {
                    for (k, v) in m {
                        if let (Some(ks), Some(vs)) = (k.as_str(), v.as_str()) {
                            labels.insert(ks.to_string(), vs.to_string());
                        }
                    }
                }
                let mut secret_bytes = Vec::new();
                if let Some(data_map) = val.get("data").and_then(|d| d.as_mapping()) {
                    if let Some((_, first_val)) = data_map.iter().next() {
                        if let Some(b64) = first_val.as_str() {
                            secret_bytes = decode_base64_simple(b64.trim());
                        }
                    }
                }
                let s_store = crate::secret::SecretStore::new();
                let rec = s_store.create(Some(name), &secret_bytes, labels)?;
                println!("Secret:\n{}", rec.id);
            }
            other => {
                return Err(anyhow!("Unsupported Kubernetes kind '{}'", other));
            }
        }
        Ok(())
    }

    pub async fn play_pod(pod_yaml: KubePodYaml) -> Result<()> {
        let default_args = KubePlayArgs {
            start: true,
            tls_verify: true,
            ..Default::default()
        };
        Self::play_pod_with_args(pod_yaml, &default_args, &HashMap::new(), None).await
    }

    pub async fn play_pod_with_args(
        pod_yaml: KubePodYaml,
        args: &KubePlayArgs,
        configmaps: &HashMap<(String, String), String>,
        service_ctr_name: Option<&str>,
    ) -> Result<()> {
        let pod_store = PodStore::new();
        if pod_store.find(&pod_yaml.metadata.name).is_some() {
            if !args.replace {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "pod {} is in use: pod already exists",
                    pod_yaml.metadata.name
                ));
            }
            let _ = pod_store.remove_with_force(&pod_yaml.metadata.name, true);
        }
        if args.replace {
            for c_spec in &pod_yaml.spec.containers {
                let cname = format!("{}-{}", pod_yaml.metadata.name, c_spec.name);
                let _ = crate::remove_container(&cname, true);
                let _ = crate::storage::external::remove_storage_container(&cname);
                let _ = crate::storage::external::remove_external_name(&cname);
            }
        }

        let default_host_ip = crate::containers_conf_toml_value("default_host_ips")
            .and_then(|raw| {
                let cleaned = raw
                    .trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .trim()
                    .trim_matches('"')
                    .to_string();
                if cleaned.is_empty() {
                    None
                } else {
                    Some(cleaned)
                }
            });

        let mut pod_ports = Vec::new();
        for pub_str in &args.publish {
            if let Ok(mut pm) = crate::network::PortMapping::parse(pub_str) {
                if pm.host_ip.is_none() {
                    pm.host_ip = default_host_ip.clone();
                }
                pod_ports.push(pm);
            }
        }
        for c_spec in &pod_yaml.spec.containers {
            if let Some(ports) = &c_spec.ports {
                for p in ports {
                    if let Some(host_p) = p.host_port {
                        let c_port = if p.container_port == 0 {
                            host_p
                        } else {
                            p.container_port
                        };
                        pod_ports.push(crate::network::PortMapping {
                            host_ip: p.host_ip.clone().or_else(|| default_host_ip.clone()),
                            host_port: host_p,
                            container_port: c_port,
                            protocol: p
                                .protocol
                                .clone()
                                .unwrap_or_else(|| "tcp".to_string())
                                .to_lowercase(),
                        });
                    }
                }
            }
        }
        let mut pod_labels = pod_yaml.metadata.labels.clone();
        if let Ok(unit) = std::env::var("PODMAN_SYSTEMD_UNIT") {
            let trimmed = unit.trim();
            if !trimmed.is_empty() {
                pod_labels
                    .entry("PODMAN_SYSTEMD_UNIT".to_string())
                    .or_insert_with(|| trimmed.to_string());
            }
        }
        for l in &args.labels {
            if let Some((k, v)) = l.split_once('=') {
                pod_labels.insert(k.to_string(), v.to_string());
            }
        }
        if let Some(sc) = service_ctr_name {
            pod_labels.insert("boxr.service_container".to_string(), sc.to_string());
            let c_store = ContainerStore::new();
            if let Some(sc_rec) = c_store.find(sc) {
                let b = std::path::PathBuf::from(&sc_rec.bundle_path);
                let _ = fs::write(b.join("service_for_pod"), &pod_yaml.metadata.name);
            }
        }

        let mut pod_annotations = pod_yaml.metadata.annotations.clone();
        for a in &args.annotations {
            if let Some((k, v)) = a.split_once('=') {
                pod_annotations.insert(k.to_string(), v.to_string());
            }
        }

        let pod_network = args.network.last().cloned();
        let pod_userns = args
            .userns
            .clone()
            .or_else(|| pod_annotations.get("io.podman.annotations.userns").cloned());

        // Resolve Pod volumes (hostPath, PVC, image volume) before creating pod
        let mut volume_sources: HashMap<String, (String, bool)> = HashMap::new();
        if let Some(vols) = &pod_yaml.spec.volumes {
            for v in vols {
                if let Some(hp) = &v.host_path {
                    volume_sources.insert(v.name.clone(), (hp.path.clone(), false));
                } else if let Some(pvc) = &v.persistent_volume_claim {
                    let v_store = crate::volume::VolumeStore::new();
                    let vol = match v_store.find(&pvc.claim_name) {
                        Some(existing) => existing,
                        None => v_store.create(Some(&pvc.claim_name), None)?,
                    };
                    volume_sources.insert(v.name.clone(), (vol.mountpoint, false));
                } else if let Some(img_vol) = &v.image {
                    let policy = img_vol
                        .pull_policy
                        .as_deref()
                        .unwrap_or("IfNotPresent")
                        .trim();
                    let img_store = crate::storage::ImageStore::new();
                    let img_rec = match policy {
                        "Never" => match img_store.find(&img_vol.reference) {
                            Some(rec) => rec,
                            None => crate::cli::usage_errors::exit_usage_error(format!(
                                "{}: image not known",
                                img_vol.reference
                            )),
                        },
                        "Always" => match crate::pull_image(&img_vol.reference).await {
                            Ok(rec) => rec,
                            Err(e) => crate::cli::usage_errors::exit_usage_error(format!("{}", e)),
                        },
                        _ => match img_store.find(&img_vol.reference) {
                            Some(rec) => rec,
                            None => match crate::pull_image(&img_vol.reference).await {
                                Ok(rec) => rec,
                                Err(e) => {
                                    crate::cli::usage_errors::exit_usage_error(format!("{}", e))
                                }
                            },
                        },
                    };
                    volume_sources.insert(v.name.clone(), (img_rec.rootfs_path, true));
                }
            }
        }

        let pod = pod_store.create_with_config(PodConfig {
            name: Some(pod_yaml.metadata.name.clone()),
            ports: pod_ports,
            hostname: None,
            labels: pod_labels.clone(),
            dns: Vec::new(),
            memory: None,
            cpus: None,
            share_ipc: true,
            share_net: true,
            share_uts: true,
            share_pid: false,
            infra: true,
            network: pod_network.clone(),
            userns: pod_userns.clone(),
        })?;
        let _ = crate::ensure_pod_infra_container(&pod).await;

        // Run initContainers first if present
        if let Some(init_ctrs) = &pod_yaml.spec.init_containers {
            for ic in init_ctrs {
                let ic_name = format!("{}-{}", pod.name, ic.name);
                let mut cmd_vec = ic.command.clone().unwrap_or_default();
                if let Some(a) = &ic.args {
                    cmd_vec.extend(a.clone());
                }
                let ic_run = RunArgs {
                    name: Some(ic_name.clone()),
                    detach: false,
                    pod: Some(pod.name.clone()),
                    network: pod_network.clone().unwrap_or_else(|| "auto".to_string()),
                    userns: pod_userns.iter().cloned().collect(),
                    image: ic.image.clone(),
                    command: cmd_vec,
                    rootless: true,
                    sig_proxy: true,
                    restart: "no".to_string(),
                    ..Default::default()
                };
                let _ = crate::run_container_with_output(
                    ic_run,
                    crate::CliOutputPolicy {
                        noout: true,
                        out: None,
                    },
                )
                .await?;
            }
        }

        println!("Pod:");
        println!("{}", pod.id);

        let mut created_cids = Vec::new();
        for c_spec in &pod_yaml.spec.containers {
            if crate::cli::podman_globals::podman_global_options().debug {
                let policy =
                    if c_spec.image.ends_with(":latest") || !c_spec.image.contains(':') {
                        "newer"
                    } else {
                        "missing"
                    };
                eprintln!("Pulling image {} (policy: {})", c_spec.image, policy);
            }

            if args.build {
                let ctx_root = args.context_dir.as_deref().unwrap_or(".");
                let img_base = c_spec
                    .image
                    .rsplit('/')
                    .next()
                    .unwrap_or(&c_spec.image)
                    .split(':')
                    .next()
                    .unwrap_or(&c_spec.image);
                let build_dir = Path::new(ctx_root).join(img_base);
                let cf_path = if build_dir.join("Containerfile").exists() {
                    Some(("Containerfile".to_string(), build_dir))
                } else if build_dir.join("Dockerfile").exists() {
                    Some(("Dockerfile".to_string(), build_dir))
                } else {
                    None
                };
                if let Some((cf_name, bdir)) = cf_path {
                    let b_args = crate::cli::BuildArgs {
                        registry_auth: crate::cli::RegistryAuthArgs {
                            authfile: args.authfile.clone(),
                            ..Default::default()
                        },
                        tags: vec![c_spec.image.clone()],
                        file: cf_name,
                        no_cache: false,
                        build_args: Vec::new(),
                        target: None,
                        add_host: Vec::new(),
                        memory: None,
                        shm_size: None,
                        rm: true,
                        no_cache_filter: Vec::new(),
                        cpu_shares: None,
                        cpuset_cpus: None,
                        cpuset_mems: None,
                        cpu_period: None,
                        cpu_quota: None,
                        platform: None,
                        isolation: None,
                        labels: Vec::new(),
                        quiet: true,
                        squash: false,
                        squash_all: false,
                        layers: None,
                        cap_add: Vec::new(),
                        disable_content_trust: false,
                        output: None,
                        progress: None,
                        secret: Vec::new(),
                        ssh: Vec::new(),
                        unsetenv: Vec::new(),
                        path: bdir.to_string_lossy().to_string(),
                        ..Default::default()
                    };
                    if let Err(e) = crate::build_image(b_args).await {
                        crate::cli::usage_errors::exit_usage_error(format!("{}", e));
                    }
                } else if !c_spec.image.contains('/') {
                    crate::cli::usage_errors::exit_usage_error(format!(
                        "short-name resolution enforced but cannot prompt without a TTY: {}",
                        c_spec.image
                    ));
                } else {
                    crate::cli::usage_errors::exit_usage_error(format!(
                        "initializing source docker://{}:latest: reading manifest latest in {}: manifest unknown",
                        c_spec.image, c_spec.image
                    ));
                }
            }

            let container_name = format!("{}-{}", pod.name, c_spec.name);
            let mut ports_vec = Vec::new();
            if let Some(ports) = &c_spec.ports {
                for p in ports {
                    if let Some(host_p) = p.host_port {
                        let c_port = if p.container_port == 0 {
                            host_p
                        } else {
                            p.container_port
                        };
                        ports_vec.push(format!("{}:{}", host_p, c_port));
                    }
                }
            }

            let mut env_vec = Vec::new();
            if let Some(envs) = &c_spec.env {
                for e in envs {
                    if let Some(vf) = &e.value_from {
                        if let Some(cm_ref) = &vf.config_map_key_ref {
                            if let Some(val) =
                                configmaps.get(&(cm_ref.name.clone(), cm_ref.key.clone()))
                            {
                                env_vec.push(format!("{}={}", e.name, val));
                                continue;
                            }
                        }
                    }
                    env_vec.push(format!("{}={}", e.name, e.value));
                }
            }

            let mut volumes_vec = Vec::new();
            let automount_key = format!(
                "io.podman.annotations.kube.image.volumes.mount/{}",
                c_spec.name
            );
            if let Some(automount_val) = pod_annotations.get(&automount_key) {
                let mut dest_map: BTreeMap<String, String> = BTreeMap::new();
                for img_name in automount_val.split(';') {
                    let img_name = img_name.trim();
                    if img_name.is_empty() {
                        continue;
                    }
                    if let Some(img_rec) = crate::storage::ImageStore::new().find(img_name) {
                        if let Some(vols) = img_rec
                            .config
                            .config
                            .as_ref()
                            .and_then(|c| c.volumes.as_ref())
                        {
                            for vol_dest in vols.keys() {
                                let src = Path::new(&img_rec.rootfs_path)
                                    .join(vol_dest.trim_start_matches('/'));
                                dest_map.insert(
                                    vol_dest.clone(),
                                    format!("{}:{}:ro", src.display(), vol_dest),
                                );
                            }
                        }
                    }
                }
                for v in dest_map.into_values() {
                    volumes_vec.push(v);
                }
            }

            if let Some(vms) = &c_spec.volume_mounts {
                for vm in vms {
                    let clean_dest = vm
                        .mount_path
                        .split(':')
                        .next()
                        .unwrap_or(&vm.mount_path);
                    if let Some((src_path, force_ro)) = volume_sources.get(&vm.name) {
                        let is_ro = *force_ro || vm.read_only.unwrap_or(false);
                        if is_ro {
                            volumes_vec.push(format!("{}:{}:ro", src_path, clean_dest));
                        } else {
                            volumes_vec.push(format!("{}:{}", src_path, clean_dest));
                        }
                    }
                }
            }

            let mut labels_vec: Vec<String> = pod_labels
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            if let Some(au) = pod_annotations
                .get(&format!("io.containers.autoupdate/{}", c_spec.name))
                .or_else(|| pod_annotations.get("io.containers.autoupdate"))
            {
                labels_vec.push(format!("io.containers.autoupdate={}", au));
            }
            if let Ok(unit) = std::env::var("PODMAN_SYSTEMD_UNIT") {
                let trimmed = unit.trim();
                if !trimmed.is_empty() && !labels_vec.iter().any(|l| l.starts_with("PODMAN_SYSTEMD_UNIT=")) {
                    labels_vec.push(format!("PODMAN_SYSTEMD_UNIT={}", trimmed));
                }
            }
            labels_vec.sort();

            let mut annotations_vec: Vec<String> = pod_annotations
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            annotations_vec.sort();

            let mut health_cmd = None;
            let mut health_interval = None;
            let mut health_retries = None;
            let mut health_start_period = None;
            if let Some(lp) = &c_spec.liveness_probe {
                if let Some(exec) = &lp.exec {
                    if !exec.command.is_empty() {
                        health_cmd = Some(exec.command.join(" "));
                        health_interval = Some(format!("{}s", lp.period_seconds.unwrap_or(30)));
                        health_retries = lp.failure_threshold;
                        let delay = lp.initial_delay_seconds.unwrap_or(0);
                        let _ = &mut health_start_period;
                        annotations_vec.push(format!("boxr.health_initial_delay_secs={}", delay));
                        annotations_vec.push(format!(
                            "boxr.started_unix_ms={}",
                            chrono::Utc::now().timestamp_millis()
                        ));
                    }
                }
            }

            let mut security_opt = Vec::new();
            let mut read_only = false;
            let mut privileged = false;
            if let Some(sc) = &c_spec.security_context {
                read_only = sc.read_only_root_filesystem.unwrap_or(false);
                privileged = sc.privileged.unwrap_or(false);
                if let Some(sel) = &sc.selinux_options {
                    if let Some(lvl) = &sel.level {
                        security_opt.push(format!("label=level:{}", lvl));
                    }
                    if let Some(ft) = &sel.filetype {
                        security_opt.push(format!("label=filetype:{}", ft));
                    }
                }
            }

            let mut cmd_vec = c_spec.command.clone().unwrap_or_default();
            if let Some(extra_args) = &c_spec.args {
                cmd_vec.extend(extra_args.clone());
            }

            let _ = ports_vec;
            let mut tmpfs_vec = Vec::new();
            if !volumes_vec.iter().any(|v| v.contains(":/tmp:") || v.ends_with(":/tmp")) {
                tmpfs_vec.push("/tmp:rw,nosuid,nodev,mode=1777".to_string());
            }

            let run_args = RunArgs {
                registry_auth: crate::cli::RegistryAuthArgs {
                    authfile: args.authfile.clone(),
                    tls_verify: Some(args.tls_verify),
                    ..Default::default()
                },
                interactive: false,
                tty: false,
                detach: true,
                rm: false,
                rmi: false,
                name: Some(container_name.clone()),
                replace: args.replace,
                env: env_vec,
                ports: Vec::new(),
                volumes: volumes_vec,
                tmpfs: tmpfs_vec,
                labels: labels_vec,
                annotations: annotations_vec,
                rootless: true,
                restart: "no".to_string(),
                health_cmd,
                health_interval,
                health_retries,
                health_start_period,
                privileged,
                read_only,
                security_opt,
                network: pod_network.clone().unwrap_or_else(|| "auto".to_string()),
                userns: pod_userns.iter().cloned().collect(),
                log_driver: args.log_driver.iter().cloned().collect(),
                log_opt: args.log_opt.clone(),
                sig_proxy: true,
                workdir: c_spec.working_dir.clone(),
                pod: Some(pod.name.clone()),
                image: c_spec.image.clone(),
                command: cmd_vec,
                ..Default::default()
            };

            if args.start {
                let _ = crate::run_container_with_output(
                    run_args,
                    crate::CliOutputPolicy {
                        noout: true,
                        out: None,
                    },
                )
                .await?;
            } else {
                let _ = crate::create_only_container(run_args).await?;
            }
            if let Some(c_rec) = ContainerStore::new().find(&container_name) {
                created_cids.push(c_rec.id);
            }
        }

        if !created_cids.is_empty() {
            println!("Container:");
            for cid in created_cids {
                println!("{}", cid);
            }
        }
        Ok(())
    }

    /// Tear down resources played via `play kube`.
    pub fn play_kube_down(yaml_path: &Path) -> Result<()> {
        Self::play_kube_down_str(&yaml_path.to_string_lossy())
    }

    pub fn play_kube_down_str(source: &str) -> Result<()> {
        let content = Self::read_yaml_source_blocking(source)?;

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let hex_hash = hex::encode(hasher.finalize());
        let svc_name = format!("{}-service", &hex_hash[..12]);
        let _ = crate::remove_container_quiet(&svc_name, true, false);

        for doc in serde_yaml::Deserializer::from_str(&content) {
            if let Ok(val) = serde_yaml::Value::deserialize(doc) {
                if !val.is_null() {
                    let _ = Self::play_kube_down_value(val);
                }
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
            }
            "Service" => {}
            _ => {}
        }
        Ok(())
    }

    fn play_pod_down(pod_name: &str, containers: &[KubeContainerSpec]) -> Result<()> {
        let pod_store = PodStore::new();
        let c_store = ContainerStore::new();
        let mut sc_to_remove = None;
        if let Some(pod) = pod_store.find(pod_name) {
            sc_to_remove = pod.labels.get("boxr.service_container").cloned();
            pod_store.remove_with_force(&pod.name, true)?;
        }
        for c_spec in containers {
            let container_name = format!("{}-{}", pod_name, c_spec.name);
            if c_store.find(&container_name).is_some() {
                let _ = crate::stop_container_with_home_and_timeout(
                    &container_name,
                    None,
                    Some(0),
                    None,
                    true,
                    None,
                );
                let _ = crate::remove_container(&container_name, true);
            }
        }
        if let Some(sc) = sc_to_remove {
            if c_store.find(&sc).is_some() {
                let _ = crate::stop_container_with_home_and_timeout(
                    &sc,
                    None,
                    Some(0),
                    None,
                    true,
                    None,
                );
                let _ = crate::remove_container(&sc, true);
            }
        }
        Ok(())
    }

    /// Generate a Kubernetes Pod YAML for an existing container or pod (boxr generate kube)
    pub fn generate_kube(target: &str) -> Result<String> {
        let c_store = ContainerStore::new();
        let p_store = PodStore::new();

        let (pod_name, pod_opt, containers) = if let Some(pod) = p_store.find(target) {
            let mut conts = Vec::new();
            for cid in &pod.containers {
                if let Some(c) = c_store.find(cid) {
                    conts.push(c);
                }
            }
            (pod.name.clone(), Some(pod), conts)
        } else if let Some(c) = c_store.find(target) {
            (format!("{}-pod", c.name), None, vec![c])
        } else {
            return Err(anyhow!("No such container or pod: '{}'", target));
        };

        let mut kube_containers = Vec::new();
        let mut kube_volumes = Vec::new();
        for c in containers {
            let mut ports = Vec::new();
            for p in &c.ports {
                ports.push(KubeContainerPort {
                    container_port: p.container_port,
                    host_port: Some(p.host_port),
                    host_ip: p.host_ip.clone(),
                    protocol: Some(p.protocol.clone()),
                });
            }

            let bundle_path = PathBuf::from(&c.bundle_path);
            let spec: Option<crate::oci::runtime::Spec> =
                fs::read_to_string(bundle_path.join("config.json"))
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok());
            let mounts: Vec<crate::volume::MountSpec> =
                fs::read_to_string(bundle_path.join("mounts.json"))
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();

            let readonly = spec.as_ref().map(|s| s.root.readonly).unwrap_or(false);
            let annotations = spec
                .as_ref()
                .and_then(|s| s.annotations.clone())
                .unwrap_or_default();

            let mut selinux_opts = None;
            if let Some(sec_json) = annotations.get("boxr.security_opt") {
                if let Ok(sec_list) = serde_json::from_str::<Vec<String>>(sec_json) {
                    let mut level = None;
                    let mut filetype = None;
                    for item in sec_list {
                        if let Some(l) = item.strip_prefix("label=level:") {
                            level = Some(l.to_string());
                        } else if let Some(ft) = item.strip_prefix("label=filetype:") {
                            filetype = Some(ft.to_string());
                        }
                    }
                    if level.is_some() || filetype.is_some() {
                        selinux_opts = Some(KubeSeLinuxOptions { level, filetype });
                    }
                }
            }

            let mut vol_mounts = Vec::new();
            for m in mounts {
                if let Some(vname) = m.volume_name {
                    let pvc_name = format!("{}-pvc", vname);
                    vol_mounts.push(KubeVolumeMount {
                        name: pvc_name.clone(),
                        mount_path: m.destination,
                        read_only: if m.read_only { Some(true) } else { None },
                    });
                    if !kube_volumes.iter().any(|kv: &KubeVolume| kv.name == pvc_name) {
                        kube_volumes.push(KubeVolume {
                            name: pvc_name,
                            host_path: None,
                            persistent_volume_claim: Some(KubePvcVolumeSource {
                                claim_name: vname,
                            }),
                            image: None,
                        });
                    }
                }
            }

            let short_name = c
                .name
                .strip_prefix(&format!("{}-", pod_name))
                .unwrap_or(&c.name)
                .to_string();

            kube_containers.push(KubeContainerSpec {
                name: short_name,
                image: c.image.clone(),
                command: if c.command.is_empty() {
                    None
                } else {
                    Some(c.command.clone())
                },
                args: None,
                ports: if ports.is_empty() { None } else { Some(ports) },
                env: None,
                working_dir: None,
                security_context: Some(KubeSecurityContext {
                    read_only_root_filesystem: Some(readonly),
                    privileged: None,
                    run_as_user: None,
                    run_as_group: None,
                    selinux_options: selinux_opts,
                }),
                volume_mounts: if vol_mounts.is_empty() {
                    None
                } else {
                    Some(vol_mounts)
                },
                liveness_probe: None,
            });
        }

        let mut metadata_annotations = HashMap::new();
        if let Some(p) = &pod_opt {
            if let Some(u) = &p.userns {
                metadata_annotations.insert("io.podman.annotations.userns".to_string(), u.clone());
            }
        }

        let pod_yaml = KubePodYaml {
            api_version: "v1".to_string(),
            kind: "Pod".to_string(),
            metadata: KubeMetadata {
                name: pod_name,
                labels: HashMap::new(),
                annotations: metadata_annotations,
            },
            spec: KubePodSpec {
                containers: kube_containers,
                init_containers: None,
                volumes: if kube_volumes.is_empty() {
                    None
                } else {
                    Some(kube_volumes)
                },
            },
        };

        let yaml_str = serde_yaml::to_string(&pod_yaml)?;
        Ok(yaml_str)
    }

    pub fn generate_kube_with_args(args: &KubeGenerateArgs) -> Result<()> {
        let mut out = String::new();
        for (i, t) in args.targets.iter().enumerate() {
            if i > 0 {
                out.push_str("---\n");
            }
            out.push_str(&Self::generate_kube(t)?);
        }
        if let Some(path) = &args.filename {
            fs::write(path, &out)?;
        } else {
            print!("{}", out);
        }
        Ok(())
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
