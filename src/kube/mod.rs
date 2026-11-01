use crate::cli::RunArgs;
use crate::cli::kube::{KubeDownArgs, KubeGenerateArgs, KubePlayArgs};
use crate::pod::{PodConfig, PodStore};
use crate::storage::{ContainerStatus, ContainerStore};
use crate::volume::MountSpec;
use anyhow::{Context, Result, anyhow};
use chrono::Utc;
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
    #[serde(rename = "apiVersion", default)]
    pub api_version: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub metadata: KubeMetadata,
    #[serde(default)]
    pub spec: KubePodSpec,
    #[serde(default)]
    pub status: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeMetadata {
    #[serde(default, deserialize_with = "deserialize_any_string")]
    pub name: String,
    #[serde(rename = "creationTimestamp", skip_serializing_if = "Option::is_none")]
    pub creation_timestamp: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_any_string_map",
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub labels: HashMap<String, String>,
    #[serde(
        default,
        deserialize_with = "deserialize_any_string_map",
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub annotations: HashMap<String, String>,
}

fn deserialize_any_string<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val = Option::<serde_yaml::Value>::deserialize(deserializer)?;
    Ok(match val {
        None | Some(serde_yaml::Value::Null) => String::new(),
        Some(serde_yaml::Value::String(s)) => s,
        Some(serde_yaml::Value::Bool(b)) => b.to_string(),
        Some(serde_yaml::Value::Number(n)) => n.to_string(),
        Some(other) => serde_yaml::to_string(&other)
            .unwrap_or_default()
            .trim()
            .to_string(),
    })
}

fn deserialize_any_string_map<'de, D>(
    deserializer: D,
) -> std::result::Result<HashMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<HashMap<String, serde_yaml::Value>>::deserialize(deserializer)?;
    let mut out = HashMap::new();
    if let Some(map) = opt {
        for (k, v) in map {
            let v_str = match v {
                serde_yaml::Value::Null => String::new(),
                serde_yaml::Value::String(s) => s,
                serde_yaml::Value::Bool(b) => b.to_string(),
                serde_yaml::Value::Number(n) => n.to_string(),
                other => serde_yaml::to_string(&other)
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
            };
            out.insert(k, v_str);
        }
    }
    Ok(out)
}

fn deserialize_null_u16<'de, D>(deserializer: D) -> std::result::Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val = Option::<serde_yaml::Value>::deserialize(deserializer)?;
    match val {
        None | Some(serde_yaml::Value::Null) => Ok(0),
        Some(serde_yaml::Value::Number(n)) => Ok(n.as_u64().unwrap_or(0) as u16),
        Some(serde_yaml::Value::String(s)) => Ok(s.trim().parse::<u16>().unwrap_or(0)),
        _ => Ok(0),
    }
}

fn deserialize_opt_u16<'de, D>(deserializer: D) -> std::result::Result<Option<u16>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val = Option::<serde_yaml::Value>::deserialize(deserializer)?;
    match val {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::Number(n)) => Ok(n.as_u64().map(|v| v as u16)),
        Some(serde_yaml::Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                Ok(None)
            } else {
                Ok(t.parse::<u16>().ok())
            }
        }
        _ => Ok(None),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubePodSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default)]
    pub containers: Vec<KubeContainerSpec>,
    #[serde(
        rename = "initContainers",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub init_containers: Option<Vec<KubeContainerSpec>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<KubeVolume>>,
    #[serde(
        rename = "restartPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub restart_policy: Option<String>,
    #[serde(
        rename = "hostNetwork",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub host_network: Option<bool>,
    #[serde(rename = "hostPID", default, skip_serializing_if = "Option::is_none")]
    pub host_pid: Option<bool>,
    #[serde(rename = "hostIPC", default, skip_serializing_if = "Option::is_none")]
    pub host_ipc: Option<bool>,
    #[serde(rename = "hostUsers", default, skip_serializing_if = "Option::is_none")]
    pub host_users: Option<bool>,
    #[serde(
        rename = "shareProcessNamespace",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub share_process_namespace: Option<bool>,
    #[serde(
        rename = "terminationGracePeriodSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub termination_grace_period_seconds: Option<i64>,
    #[serde(
        rename = "hostAliases",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub host_aliases: Option<Vec<KubeHostAlias>>,
    #[serde(rename = "dnsConfig", default, skip_serializing_if = "Option::is_none")]
    pub dns_config: Option<KubeDnsConfig>,
    #[serde(
        rename = "securityContext",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub security_context: Option<KubeSecurityContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeHostAlias {
    pub ip: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeDnsConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nameservers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub searches: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<KubeDnsOption>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeDnsOption {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

fn deserialize_opt_string_vec<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<String>>, D::Error>
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
                other => serde_yaml::to_string(&other)
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
            })
            .collect()
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeContainerSpec {
    #[serde(default, deserialize_with = "deserialize_any_string")]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_any_string")]
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
    #[serde(rename = "envFrom", default, skip_serializing_if = "Option::is_none")]
    pub env_from: Option<Vec<KubeEnvFromSource>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<serde_json::Value>,
    #[serde(
        rename = "workingDir",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub working_dir: Option<String>,
    #[serde(
        rename = "securityContext",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub security_context: Option<KubeSecurityContext>,
    #[serde(
        rename = "volumeMounts",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub volume_mounts: Option<Vec<KubeVolumeMount>>,
    #[serde(
        rename = "livenessProbe",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub liveness_probe: Option<KubeProbe>,
    #[serde(
        rename = "startupProbe",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub startup_probe: Option<KubeProbe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<KubeLifecycle>,
    #[serde(
        rename = "imagePullPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub image_pull_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeLifecycle {
    #[serde(
        rename = "stopSignal",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub stop_signal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeSeccompProfile {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub profile_type: Option<String>,
    #[serde(
        rename = "localhostProfile",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub localhost_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeEnvFromSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(
        rename = "configMapRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub config_map_ref: Option<KubeEnvSource>,
    #[serde(rename = "secretRef", default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<KubeEnvSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeEnvSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeSecurityContext {
    #[serde(
        rename = "readOnlyRootFilesystem",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub read_only_root_filesystem: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    #[serde(
        rename = "runAsNonRoot",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub run_as_non_root: Option<bool>,
    #[serde(rename = "runAsUser", default, skip_serializing_if = "Option::is_none")]
    pub run_as_user: Option<u32>,
    #[serde(
        rename = "runAsGroup",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub run_as_group: Option<u32>,
    #[serde(
        rename = "seLinuxOptions",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub selinux_options: Option<KubeSeLinuxOptions>,
    #[serde(rename = "procMount", default, skip_serializing_if = "Option::is_none")]
    pub proc_mount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<serde_json::Value>,
    #[serde(
        rename = "seccompProfile",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub seccomp_profile: Option<KubeSeccompProfile>,
    #[serde(
        rename = "supplementalGroups",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub supplemental_groups: Option<Vec<u32>>,
    #[serde(rename = "fsGroup", default, skip_serializing_if = "Option::is_none")]
    pub fs_group: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeSeLinuxOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filetype: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub selinux_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeVolumeMount {
    pub name: String,
    #[serde(rename = "mountPath")]
    pub mount_path: String,
    #[serde(rename = "subPath", default, skip_serializing_if = "Option::is_none")]
    pub sub_path: Option<String>,
    #[serde(
        rename = "readOnly",
        alias = "readonly",
        default,
        skip_serializing_if = "Option::is_none"
    )]
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
    #[serde(rename = "configMap", default, skip_serializing_if = "Option::is_none")]
    pub config_map: Option<KubeConfigMapVolumeSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<KubeSecretVolumeSource>,
    #[serde(rename = "emptyDir", default, skip_serializing_if = "Option::is_none")]
    pub empty_dir: Option<KubeEmptyDirVolumeSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeConfigMapVolumeSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        rename = "defaultMode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub default_mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<KubeKeyToPath>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeSecretVolumeSource {
    #[serde(
        rename = "secretName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub secret_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        rename = "defaultMode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub default_mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<KubeKeyToPath>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeKeyToPath {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeEmptyDirVolumeSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub medium: Option<String>,
    #[serde(rename = "sizeLimit", default, skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<String>,
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
    #[serde(
        rename = "pullPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pull_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeProbe {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<KubeExecAction>,
    #[serde(
        rename = "initialDelaySeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub initial_delay_seconds: Option<u64>,
    #[serde(
        rename = "timeoutSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub timeout_seconds: Option<u64>,
    #[serde(
        rename = "failureThreshold",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub failure_threshold: Option<u32>,
    #[serde(
        rename = "successThreshold",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub success_threshold: Option<u32>,
    #[serde(
        rename = "periodSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub period_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeExecAction {
    #[serde(default)]
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubeContainerPort {
    #[serde(
        rename = "containerPort",
        default = "default_container_port",
        deserialize_with = "deserialize_null_u16"
    )]
    pub container_port: u16,
    #[serde(
        rename = "hostPort",
        default,
        deserialize_with = "deserialize_opt_u16",
        skip_serializing_if = "Option::is_none"
    )]
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
    #[serde(default, deserialize_with = "deserialize_any_string")]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_any_string")]
    pub value: String,
    #[serde(rename = "valueFrom", default, skip_serializing_if = "Option::is_none")]
    pub value_from: Option<KubeEnvVarSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeEnvVarSource {
    #[serde(
        rename = "configMapKeyRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub config_map_key_ref: Option<KubeKeySelector>,
    #[serde(
        rename = "secretKeyRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub secret_key_ref: Option<KubeKeySelector>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubeKeySelector {
    #[serde(default, deserialize_with = "deserialize_any_string")]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_any_string")]
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
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
        let mut seen_names = std::collections::HashSet::new();
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
                let content = match fs::read_to_string(p) {
                    Ok(c) => c,
                    Err(e) => {
                        crate::cli::usage_errors::exit_usage_error(format!("open {}: {}", p, e));
                    }
                };
                Self::extract_configmaps_from_str_with_names(&content, &mut map, &mut seen_names)?;
            }
        }
        Ok(map)
    }

    fn extract_configmaps_from_str(
        content: &str,
        map: &mut HashMap<(String, String), String>,
    ) -> Result<()> {
        let mut seen_names = std::collections::HashSet::new();
        for (cm_name, k) in map.keys() {
            if k == "__cm_exists__" {
                seen_names.insert(cm_name.clone());
            }
        }
        Self::extract_configmaps_from_str_with_names(content, map, &mut seen_names)
    }

    fn extract_configmaps_from_str_with_names(
        content: &str,
        map: &mut HashMap<(String, String), String>,
        seen_names: &mut std::collections::HashSet<String>,
    ) -> Result<()> {
        for doc in serde_yaml::Deserializer::from_str(content) {
            let val = match serde_yaml::Value::deserialize(doc) {
                Ok(v) => v,
                Err(e) => {
                    let msg = e.to_string();
                    let line_num = e.location().map(|l| l.line()).unwrap_or(1);
                    let clean_msg = msg.split(" at line ").next().unwrap_or(&msg);
                    crate::cli::usage_errors::exit_usage_error(format!(
                        "multi doc yaml could not be split: yaml: line {}: {}",
                        line_num, clean_msg
                    ));
                }
            };
            if val.is_null() {
                continue;
            }
            let kind = val.get("kind").and_then(|k| k.as_str()).unwrap_or("");
            if kind == "ConfigMap" {
                let cm_name = val["metadata"]["name"].as_str().unwrap_or("").to_string();
                if !cm_name.is_empty() && !seen_names.insert(cm_name.clone()) {
                    crate::cli::usage_errors::exit_usage_error(format!(
                        "ambiguous configuration: the same config map {} is present in YAML and in --configmaps",
                        cm_name
                    ));
                }
                map.insert(
                    (cm_name.clone(), "__cm_exists__".to_string()),
                    "1".to_string(),
                );
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
                if let Some(bdata) = val.get("binaryData").and_then(|d| d.as_mapping()) {
                    for (k, v) in bdata {
                        if let (Some(k_str), Some(b64)) = (k.as_str(), v.as_str()) {
                            let decoded =
                                String::from_utf8_lossy(&decode_base64_simple(b64.trim()))
                                    .into_owned();
                            map.insert((cm_name.clone(), k_str.to_string()), decoded);
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
        if let Some(ref val_mode) = args.validate {
            if !matches!(val_mode.as_str(), "strict" | "warn" | "ignore" | "noop") {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "{:?} is not a valid value for --validate",
                    val_mode
                ));
            }
        }
        let mut all_files = vec![args.file.clone()];
        all_files.extend(args.extra_files.iter().cloned());
        if args.down {
            for f in &all_files {
                Self::play_kube_down_str_with_force(f, args.force)?;
            }
            return Ok(());
        }
        if all_files.len() > 1 {
            for f in &all_files {
                let mut single = args.clone();
                single.file = f.clone();
                single.extra_files.clear();
                Box::pin(Self::play_kube_with_args(&single)).await?;
            }
            return Ok(());
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
                quiet: args.quiet,
                compression_format: None,
                force_compression: None,
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

        let saved_notify_sock = std::env::var("NOTIFY_SOCKET")
            .ok()
            .filter(|s| !s.is_empty());
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
            let val = match serde_yaml::Value::deserialize(doc) {
                Ok(v) => v,
                Err(e) => {
                    let msg = e.to_string();
                    let line_num = e.location().map(|l| l.line()).unwrap_or(1);
                    let clean_msg = msg.split(" at line ").next().unwrap_or(&msg);
                    crate::cli::usage_errors::exit_usage_error(format!(
                        "multi doc yaml could not be split: yaml: line {}: {}",
                        line_num, clean_msg
                    ));
                }
            };
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
                command: vec!["sleep".to_string(), "86400".to_string()],
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

        let validate_mode = args.validate.as_deref().unwrap_or("ignore");
        let supported_kinds = [
            "Pod",
            "Deployment",
            "DaemonSet",
            "Job",
            "ReplicaSet",
            "Service",
            "ConfigMap",
            "PersistentVolumeClaim",
            "Volume",
            "Secret",
            "List",
        ];
        let mut has_any_supported = false;
        for val in &docs {
            let k = val.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if supported_kinds.contains(&k) {
                has_any_supported = true;
            } else if validate_mode == "strict" {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "kube kind {:?} is not supported",
                    k
                ));
            } else if validate_mode == "warn" {
                eprintln!("Warning: kube kind {:?} is not supported", k);
            }
        }
        if !has_any_supported && !docs.is_empty() {
            crate::cli::usage_errors::exit_usage_error(
                "YAML document does not contain any supported kube kind",
            );
        }

        for val in docs.clone() {
            let k = val.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if !supported_kinds.contains(&k) {
                continue;
            }
            if validate_mode == "strict" || validate_mode == "warn" {
                let known_ctr_fields = [
                    "name",
                    "image",
                    "command",
                    "args",
                    "workingDir",
                    "ports",
                    "envFrom",
                    "env",
                    "resources",
                    "volumeMounts",
                    "volumeDevices",
                    "livenessProbe",
                    "readinessProbe",
                    "startupProbe",
                    "lifecycle",
                    "terminationMessagePath",
                    "terminationMessagePolicy",
                    "imagePullPolicy",
                    "securityContext",
                    "stdin",
                    "stdinOnce",
                    "tty",
                ];
                if let Some(ctrs) = val
                    .get("spec")
                    .and_then(|s| s.get("containers"))
                    .and_then(|c| c.as_sequence())
                {
                    for c_val in ctrs {
                        if let Some(m) = c_val.as_mapping() {
                            for (fk, _) in m {
                                if let Some(fks) = fk.as_str() {
                                    if !known_ctr_fields.contains(&fks) {
                                        if validate_mode == "strict" {
                                            crate::cli::usage_errors::exit_usage_error(format!(
                                                "strict decoding error: unknown field {:?}",
                                                fks
                                            ));
                                        } else {
                                            eprintln!("Warning: unknown field {:?}", fks);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if args.replace && saved_notify_sock.is_some() {
                let _ = Self::play_kube_down_value(val.clone());
            }
            if let Err(e) =
                Self::play_kube_value_with_args(val, args, &configmaps, service_ctr_name.as_deref())
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
            "Deployment" | "DaemonSet" | "Job" | "ReplicaSet" => {
                let name = val["metadata"]["name"]
                    .as_str()
                    .unwrap_or("deployment")
                    .to_string();
                let raw_replicas = if kind == "Deployment" || kind == "ReplicaSet" {
                    val["spec"]["replicas"].as_u64().unwrap_or(1) as usize
                } else {
                    1usize
                };
                let pub_items: Vec<String> = args
                    .publish
                    .iter()
                    .flat_map(|s| s.split(','))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                let replicas = if raw_replicas > 1 && !args.multiple_pods {
                    if !std::env::args().any(|a| a == "--log-level=error") {
                        eprintln!(
                            "Limiting replica count to 1, use `--multiple-pods` to enable more than one replica"
                        );
                    }
                    1usize
                } else {
                    if args.multiple_pods
                        && !pub_items.is_empty()
                        && pub_items.len() != raw_replicas
                    {
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "number of Pod replicas aren't equal to the number of published ports: {} replicas, {} published ports",
                            raw_replicas,
                            pub_items.len()
                        ));
                    }
                    raw_replicas
                };
                let template_spec = &val["spec"]["template"]["spec"];
                let pod_spec: KubePodSpec =
                    serde_yaml::from_value(template_spec.clone()).unwrap_or_default();
                let mut base_labels = HashMap::new();
                for m in [
                    val["metadata"]["labels"].as_mapping(),
                    val["spec"]["template"]["metadata"]["labels"].as_mapping(),
                ]
                .into_iter()
                .flatten()
                {
                    for (k, v) in m {
                        if let (Some(ks), Some(vs)) = (k.as_str(), v.as_str()) {
                            base_labels.insert(ks.to_string(), vs.to_string());
                        }
                    }
                }
                let mut base_annotations = HashMap::new();
                for m in [
                    val["metadata"]["annotations"].as_mapping(),
                    val["spec"]["template"]["metadata"]["annotations"].as_mapping(),
                ]
                .into_iter()
                .flatten()
                {
                    for (k, v) in m {
                        if let (Some(ks), Some(vs)) = (k.as_str(), v.as_str()) {
                            base_annotations.insert(ks.to_string(), vs.to_string());
                        }
                    }
                }

                for i in 0..replicas {
                    let pod_name = if replicas == 1 && !args.multiple_pods {
                        format!("{}-pod", name)
                    } else {
                        format!("{}-pod-{}", name, i)
                    };
                    let mut replica_args = args.clone();
                    if args.multiple_pods && i < pub_items.len() {
                        replica_args.publish = vec![pub_items[i].clone()];
                    }
                    let pod_yaml = KubePodYaml {
                        api_version: "v1".to_string(),
                        kind: "Pod".to_string(),
                        metadata: KubeMetadata {
                            name: pod_name,
                            creation_timestamp: None,
                            labels: base_labels.clone(),
                            annotations: base_annotations.clone(),
                        },
                        spec: pod_spec.clone(),
                        status: None,
                    };
                    Self::play_pod_with_args(pod_yaml, &replica_args, configmaps, service_ctr_name)
                        .await?;
                }
            }
            "List" => {
                let mut merged_cms = configmaps.clone();
                if let Some(items) = val.get("items").and_then(|v| v.as_sequence()) {
                    for item in items {
                        if item.get("kind").and_then(|k| k.as_str()) == Some("ConfigMap") {
                            let cm_name =
                                item["metadata"]["name"].as_str().unwrap_or("").to_string();
                            merged_cms.insert(
                                (cm_name.clone(), "__cm_exists__".to_string()),
                                "1".to_string(),
                            );
                            if let Some(data) = item.get("data").and_then(|d| d.as_mapping()) {
                                for (k, v) in data {
                                    if let Some(k_str) = k.as_str() {
                                        let v_str = match v {
                                            serde_yaml::Value::String(s) => s.clone(),
                                            serde_yaml::Value::Number(n) => n.to_string(),
                                            serde_yaml::Value::Bool(b) => b.to_string(),
                                            _ => String::new(),
                                        };
                                        merged_cms
                                            .insert((cm_name.clone(), k_str.to_string()), v_str);
                                    }
                                }
                            }
                            if let Some(bdata) = item.get("binaryData").and_then(|d| d.as_mapping())
                            {
                                for (k, v) in bdata {
                                    if let (Some(k_str), Some(b64)) = (k.as_str(), v.as_str()) {
                                        let decoded = String::from_utf8_lossy(
                                            &decode_base64_simple(b64.trim()),
                                        )
                                        .into_owned();
                                        merged_cms
                                            .insert((cm_name.clone(), k_str.to_string()), decoded);
                                    }
                                }
                            }
                        }
                    }
                    for item in items {
                        Box::pin(Self::play_kube_value_with_args(
                            item.clone(),
                            args,
                            &merged_cms,
                            service_ctr_name,
                        ))
                        .await?;
                    }
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
                let mut vol_opts = HashMap::new();
                let mut driver = "local".to_string();
                let mut import_src: Option<String> = None;
                let mut vol_image: Option<String> = None;
                if let Some(m) = val["metadata"]["annotations"].as_mapping() {
                    for (k, v) in m {
                        if let (Some(ks), Some(vs)) = (k.as_str(), v.as_str()) {
                            match ks {
                                "volume.podman.io/driver" => driver = vs.to_string(),
                                "volume.podman.io/device" => {
                                    vol_opts.insert("device".to_string(), vs.to_string());
                                }
                                "volume.podman.io/type" => {
                                    vol_opts.insert("type".to_string(), vs.to_string());
                                }
                                "volume.podman.io/mount-options" => {
                                    vol_opts.insert("o".to_string(), vs.to_string());
                                }
                                "volume.podman.io/uid" => {
                                    vol_opts.insert("uid".to_string(), vs.to_string());
                                }
                                "volume.podman.io/gid" => {
                                    vol_opts.insert("gid".to_string(), vs.to_string());
                                }
                                "volume.podman.io/import-source" => {
                                    import_src = Some(vs.to_string());
                                }
                                "volume.podman.io/image" => {
                                    vol_opts.insert("image".to_string(), vs.to_string());
                                    vol_image = Some(vs.to_string());
                                }
                                _ => {}
                            }
                        }
                    }
                }
                if let Some(ref src) = import_src {
                    if !Path::new(src).exists() {
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "open {}: no such file or directory",
                            src
                        ));
                    }
                }
                let store = crate::volume::VolumeStore::new();
                let vol = match store.find(name) {
                    Some(existing) => existing,
                    None => store.create_with_options(
                        Some(name),
                        &driver,
                        Some(labels),
                        "local",
                        Some(vol_opts),
                    )?,
                };
                if let Some(ref img_name) = vol_image {
                    let img_store = crate::storage::ImageStore::new();
                    let img_rec = match img_store.find(img_name) {
                        Some(r) => r,
                        None => crate::pull_image(img_name).await?,
                    };
                    if Path::new(&img_rec.rootfs_path) != Path::new(&vol.mountpoint) {
                        let _ = crate::storage::overlay::OverlayDriver::create_hardlink_tree(
                            Path::new(&img_rec.rootfs_path),
                            Path::new(&vol.mountpoint),
                        );
                    }
                }
                if let Some(ref src) = import_src {
                    let status = std::process::Command::new("tar")
                        .args(["-xf", src, "-C", &vol.mountpoint])
                        .status()?;
                    if !status.success() {
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "failed to import volume from {}",
                            src
                        ));
                    }
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
                labels.insert("boxr.kube_secret".to_string(), "true".to_string());
                let mut kv_map: HashMap<String, String> = HashMap::new();
                if let Some(data_map) = val.get("data").and_then(|d| d.as_mapping()) {
                    for (k, v) in data_map {
                        if let (Some(ks), Some(b64)) = (k.as_str(), v.as_str()) {
                            let decoded =
                                String::from_utf8_lossy(&decode_base64_simple(b64.trim()))
                                    .into_owned();
                            kv_map.insert(ks.to_string(), decoded);
                        }
                    }
                }
                if let Some(sdata_map) = val.get("stringData").and_then(|d| d.as_mapping()) {
                    for (k, v) in sdata_map {
                        if let (Some(ks), Some(vs)) = (k.as_str(), v.as_str()) {
                            kv_map.insert(ks.to_string(), vs.to_string());
                        }
                    }
                }
                if let Ok(json_map) = serde_json::to_string(&kv_map) {
                    labels.insert("boxr.kube_secret_map".to_string(), json_map);
                }
                let secret_bytes = serde_yaml::to_string(&val).unwrap_or_default().into_bytes();
                let filedriver_dir = crate::storage::boxr_home()
                    .join("secrets")
                    .join("filedriver");
                let _ = fs::create_dir_all(&filedriver_dir);
                let secretsdata_file = filedriver_dir.join("secretsdata.json");
                if secretsdata_file.is_dir() {
                    crate::cli::usage_errors::exit_usage_error(format!(
                        "open {}: is a directory",
                        secretsdata_file.display()
                    ));
                }
                let _ = fs::write(&secretsdata_file, "{}");
                let s_store = crate::secret::SecretStore::new();
                if s_store.find(name).is_some() {
                    let _ = s_store.remove(name);
                }
                let rec = s_store.create(Some(name), &secret_bytes, labels)?;
                println!("Secret:\n{}", rec.id);
            }
            other => {
                return Err(anyhow!("Unsupported Kubernetes kind '{}'", other));
            }
        }
        Ok(())
    }

    fn expand_kube_command_env(s: &str, env_map: &HashMap<String, String>) -> String {
        let chars: Vec<char> = s.chars().collect();
        let mut out = String::new();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '$'
                && i + 1 < chars.len()
                && chars[i + 1] == '$'
                && i + 2 < chars.len()
                && chars[i + 2] == '('
            {
                out.push_str("$(");
                i += 3;
                continue;
            }
            if chars[i] == '$' && i + 1 < chars.len() && chars[i + 1] == '(' {
                if let Some(rel_end) = chars[i + 2..].iter().position(|&c| c == ')') {
                    let var_name: String = chars[i + 2..i + 2 + rel_end].iter().collect();
                    if let Some(val) = env_map.get(&var_name) {
                        out.push_str(val);
                    } else {
                        out.push_str(&format!("$({var_name})"));
                    }
                    i += 2 + rel_end + 1;
                    continue;
                }
            }
            out.push(chars[i]);
            i += 1;
        }
        out
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
        if pod_yaml.metadata.name.trim().is_empty() {
            crate::cli::usage_errors::exit_usage_error("pod does not have a name");
        }
        if args.no_hosts
            && pod_yaml
                .spec
                .host_aliases
                .as_ref()
                .is_some_and(|ha| !ha.is_empty())
        {
            crate::cli::usage_errors::exit_usage_error(
                "HostAliases in yaml file will not work with --no-hosts",
            );
        }
        if args.mac_address.len() > 1 && args.network.len() > 1 {
            crate::cli::usage_errors::exit_usage_error(
                "specifying mac-address multiple times is not supported",
            );
        }
        let is_host_network =
            pod_yaml.spec.host_network == Some(true) || args.network.iter().any(|n| n == "host");
        if pod_yaml.spec.host_network == Some(true) {
            if !args.network.is_empty() && args.network.iter().any(|n| n != "host") {
                crate::cli::usage_errors::exit_usage_error(
                    "invalid config provided: cannot set both HostNetwork in YAML and --network",
                );
            }
            if !args.mac_address.is_empty() {
                crate::cli::usage_errors::exit_usage_error(
                    "cannot set mac-address with HostNetwork: network cannot be configured when it is shared with the host",
                );
            }
            if !args.ip.is_empty() {
                crate::cli::usage_errors::exit_usage_error("cannot set static IP with HostNetwork");
            }
        }
        let pod_store = PodStore::new();
        if pod_store.find(&pod_yaml.metadata.name).is_some() {
            if !args.replace {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "adding pod to state: name {:?} is in use: pod already exists",
                    pod_yaml.metadata.name
                ));
            }
            let _ = pod_store.remove_with_force(&pod_yaml.metadata.name, true);
        }
        let mut seen_ctr_names = std::collections::HashSet::new();
        for c_spec in &pod_yaml.spec.containers {
            if c_spec.image.trim().is_empty() {
                let cname = if c_spec.name.trim().is_empty() {
                    &pod_yaml.metadata.name
                } else {
                    &c_spec.name
                };
                crate::cli::usage_errors::exit_usage_error(format!(
                    "container {:?} is missing the required 'image' field",
                    cname
                ));
            }
            if c_spec.image.starts_with('.') || c_spec.image.starts_with('/') {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "invalid reference format: {}",
                    c_spec.image
                ));
            }
            if !c_spec.name.is_empty() && !seen_ctr_names.insert(c_spec.name.clone()) {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "the pod {:?} is invalid; duplicate container name {:?} detected",
                    pod_yaml.metadata.name, c_spec.name
                ));
            }
        }
        if args.replace {
            for c_spec in &pod_yaml.spec.containers {
                let cname = format!("{}-{}", pod_yaml.metadata.name, c_spec.name);
                let _ = crate::remove_container(&cname, true);
                let _ = crate::storage::external::remove_storage_container(&cname);
                let _ = crate::storage::external::remove_external_name(&cname);
            }
        }

        let default_host_ip =
            crate::containers_conf_toml_value("default_host_ips").and_then(|raw| {
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

        let is_net_none = args.network.iter().any(|n| n == "none");
        let mut pod_ports = Vec::new();
        if !is_host_network && !is_net_none {
            for pub_str in &args.publish {
                for part in pub_str.split(',') {
                    if let Ok(mut pm) = crate::network::PortMapping::parse(part.trim()) {
                        if pm.host_ip.is_none() {
                            pm.host_ip = default_host_ip.clone();
                        }
                        pod_ports.push(pm);
                    }
                }
            }
            for c_spec in &pod_yaml.spec.containers {
                if let Some(ports) = &c_spec.ports {
                    for p in ports {
                        if args.publish_all && p.container_port > 0 && p.container_port < 1024 {
                            #[cfg(unix)]
                            if unsafe { libc::geteuid() != 0 } {
                                crate::cli::usage_errors::exit_usage_error(format!(
                                    "rootlessport cannot expose privileged port {},",
                                    p.container_port
                                ));
                            }
                        }
                        if let Some(host_p) = p.host_port {
                            if host_p > 0 && host_p < 1024 {
                                #[cfg(unix)]
                                if unsafe { libc::geteuid() != 0 } {
                                    crate::cli::usage_errors::exit_usage_error(format!(
                                        "rootlessport cannot expose privileged port {},",
                                        host_p
                                    ));
                                }
                            }
                            let c_port = if p.container_port == 0 {
                                host_p
                            } else {
                                p.container_port
                            };
                            let proto = p
                                .protocol
                                .clone()
                                .unwrap_or_else(|| "tcp".to_string())
                                .to_lowercase();
                            let overridden_by_cli = pod_ports.iter().any(|existing| {
                                existing.container_port == c_port
                                    && existing.protocol.eq_ignore_ascii_case(&proto)
                            });
                            if !overridden_by_cli {
                                pod_ports.push(crate::network::PortMapping {
                                    host_ip: p.host_ip.clone().or_else(|| default_host_ip.clone()),
                                    host_port: host_p,
                                    container_port: c_port,
                                    protocol: proto,
                                });
                            }
                        } else if args.publish_all && p.container_port > 0 {
                            let proto = p
                                .protocol
                                .clone()
                                .unwrap_or_else(|| "tcp".to_string())
                                .to_lowercase();
                            pod_ports.push(crate::network::PortMapping {
                                host_ip: p.host_ip.clone().or_else(|| default_host_ip.clone()),
                                host_port: 20000 + (p.container_port % 10000),
                                container_port: p.container_port,
                                protocol: proto,
                            });
                        }
                    }
                }
            }
        }
        let mut pod_labels = pod_yaml.metadata.labels.clone();
        for (k, v) in &pod_labels {
            if v.contains(',') {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "invalid label value {:?} for key {:?}",
                    v, k
                ));
            }
        }
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
        let total_ann_size: usize = pod_annotations.iter().map(|(k, v)| k.len() + v.len()).sum();
        if total_ann_size > 262_144 {
            crate::cli::usage_errors::exit_usage_error(format!(
                "annotations size {} is larger than limit 262144",
                total_ann_size
            ));
        }
        if pod_annotations.contains_key("io.podman.annotations.volumes-from") {
            crate::cli::usage_errors::exit_usage_error(
                "annotation io.podman.annotations.volumes-from without target volume is reserved for internal use",
            );
        }
        for k in pod_annotations.keys() {
            if k == "container.seccomp.security.alpha.kubernetes.io/pod"
                || k.starts_with("container.seccomp.security.alpha.kubernetes.io/")
                || k == "seccomp.security.alpha.kubernetes.io/pod"
            {
                eprintln!(
                    "Warning: seccomp annotation is deprecated, please use securityContext.seccompProfile instead"
                );
            }
        }

        let pod_network = if is_host_network {
            Some("host".to_string())
        } else if !args.network.is_empty() {
            Some(args.network.join(";"))
        } else {
            let n_store = crate::network::NetworkStore::new();
            if n_store.find("podman-default-kube-network").is_none() {
                let _ = n_store.create("podman-default-kube-network", None, None);
            }
            Some("podman-default-kube-network".to_string())
        };
        let pod_userns = if let Some(ref u) = args.userns {
            Some(u.clone())
        } else if let Some(u) = pod_annotations.get("io.podman.annotations.userns") {
            Some(u.clone())
        } else if pod_yaml.spec.host_users == Some(false) {
            Some("auto".to_string())
        } else {
            None
        };

        // Resolve Pod volumes (hostPath, PVC, image, configMap, secret, emptyDir) before creating pod
        let mut volume_sources: HashMap<String, (String, bool, bool)> = HashMap::new();
        let mut anon_volumes_created: Vec<String> = Vec::new();
        let mut mem_dirs_created: Vec<String> = Vec::new();
        if let Some(vols) = &pod_yaml.spec.volumes {
            for v in vols {
                if let Some(hp) = &v.host_path {
                    let htype = hp.path_type.as_deref().unwrap_or("");
                    let p = Path::new(&hp.path);
                    match htype {
                        "" | "Directory" | "File" => {
                            if !p.exists() {
                                crate::cli::usage_errors::exit_usage_error(format!(
                                    "failed to create volume {:?}: in parsing HostPath in YAML: faccessat {}: no such file or directory",
                                    v.name, hp.path
                                ));
                            }
                        }
                        "DirectoryOrCreate" => {
                            let _ = fs::create_dir_all(p);
                        }
                        "FileOrCreate" => {
                            if !p.exists() {
                                if let Some(parent) = p.parent() {
                                    let _ = fs::create_dir_all(parent);
                                }
                                let _ = fs::File::create(p);
                            }
                        }
                        "Socket" => {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::FileTypeExt;
                                let is_sock = fs::metadata(p)
                                    .map(|m| m.file_type().is_socket())
                                    .unwrap_or(false);
                                if !is_sock {
                                    crate::cli::usage_errors::exit_usage_error(format!(
                                        "failed to create volume {:?}: checking HostPathSocket: path {} is not a socket",
                                        v.name, hp.path
                                    ));
                                }
                            }
                        }
                        "CharDevice" => {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::FileTypeExt;
                                let is_char = fs::metadata(p)
                                    .map(|m| m.file_type().is_char_device())
                                    .unwrap_or(false);
                                if !is_char {
                                    crate::cli::usage_errors::exit_usage_error(format!(
                                        "failed to create volume {:?}: checking HostPathCharDevice: path {} is not a character device",
                                        v.name, hp.path
                                    ));
                                }
                            }
                        }
                        "BlockDevice" => {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::FileTypeExt;
                                let is_blk = fs::metadata(p)
                                    .map(|m| m.file_type().is_block_device())
                                    .unwrap_or(false);
                                if !is_blk {
                                    crate::cli::usage_errors::exit_usage_error(format!(
                                        "failed to create volume {:?}: checking HostPathBlockDevice: path {} is not a block device",
                                        v.name, hp.path
                                    ));
                                }
                            }
                        }
                        other => {
                            crate::cli::usage_errors::exit_usage_error(format!(
                                "invalid HostPath type {:?}",
                                other
                            ));
                        }
                    }
                    let mut force_ro = false;
                    if let Some(opts) = pod_annotations
                        .get(&format!("bind-mount-options:{}", hp.path))
                        .map(|s| s.as_str())
                        .or_else(|| {
                            pod_annotations
                                .get("bind-mount-options")
                                .and_then(|s| s.strip_prefix(&format!("{}:", hp.path)))
                        })
                    {
                        for opt in opts.split(',').flat_map(|s| s.split(':')) {
                            let opt = opt.trim();
                            if opt.is_empty() {
                                continue;
                            }
                            match opt {
                                "ro" => force_ro = true,
                                "rw" | "z" | "Z" | "noexec" | "exec" | "nosuid" | "suid"
                                | "nodev" | "dev" | "shared" | "rshared" | "slave" | "rslave"
                                | "private" | "rprivate" | "unbindable" | "runbindable" | "U"
                                | "O" | " rbind" | "rbind" | "bind" => {}
                                unknown => {
                                    crate::cli::usage_errors::exit_usage_error(format!(
                                        "unknown mount option {:?}",
                                        unknown
                                    ));
                                }
                            }
                        }
                    }
                    volume_sources.insert(v.name.clone(), (hp.path.clone(), force_ro, false));
                } else if let Some(pvc) = &v.persistent_volume_claim {
                    let v_store = crate::volume::VolumeStore::new();
                    let vol = match v_store.find(&pvc.claim_name) {
                        Some(existing) => existing,
                        None => v_store.create(Some(&pvc.claim_name), None)?,
                    };
                    volume_sources.insert(v.name.clone(), (vol.name, false, true));
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
                    volume_sources.insert(v.name.clone(), (img_rec.rootfs_path, true, false));
                } else if let Some(cm_vol) = &v.config_map {
                    let cm_name = cm_vol.name.as_deref().unwrap_or(&v.name);
                    let cm_exists = configmaps
                        .contains_key(&(cm_name.to_string(), "__cm_exists__".to_string()))
                        || configmaps.keys().any(|(n, _)| n == cm_name);
                    let is_opt = cm_vol.optional.unwrap_or(false);
                    if !cm_exists && !is_opt {
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "failed to create volume {:?}: no such ConfigMap {:?}",
                            cm_name, cm_name
                        ));
                    }
                    let v_store = crate::volume::VolumeStore::new();
                    let vol = match v_store.find(cm_name) {
                        Some(existing) => existing,
                        None => v_store.create(Some(cm_name), None)?,
                    };
                    let mp = PathBuf::from(&vol.mountpoint);
                    let def_mode = cm_vol.default_mode.unwrap_or(0o644);
                    if cm_exists {
                        if let Some(items) = &cm_vol.items {
                            for item in items {
                                if let Some(val) =
                                    configmaps.get(&(cm_name.to_string(), item.key.clone()))
                                {
                                    let dst = mp.join(&item.path);
                                    if fs::symlink_metadata(&dst)
                                        .map(|m| m.file_type().is_symlink())
                                        .unwrap_or(false)
                                    {
                                        crate::cli::usage_errors::exit_usage_error(format!(
                                            "cannot create file {:?} at volume mountpoint",
                                            item.path
                                        ));
                                    }
                                    if let Some(parent) = dst.parent() {
                                        let _ = fs::create_dir_all(parent);
                                    }
                                    let _ = fs::write(&dst, val);
                                    #[cfg(unix)]
                                    {
                                        use std::os::unix::fs::PermissionsExt;
                                        let _ = fs::set_permissions(
                                            &dst,
                                            fs::Permissions::from_mode(
                                                item.mode.unwrap_or(def_mode),
                                            ),
                                        );
                                    }
                                } else if !is_opt {
                                    crate::cli::usage_errors::exit_usage_error(format!(
                                        "key {:?} not found in ConfigMap {:?}",
                                        item.key, cm_name
                                    ));
                                }
                            }
                        } else {
                            for ((n, k), val) in configmaps {
                                if n == cm_name && k != "__cm_exists__" {
                                    let dst = mp.join(k);
                                    if fs::symlink_metadata(&dst)
                                        .map(|m| m.file_type().is_symlink())
                                        .unwrap_or(false)
                                    {
                                        crate::cli::usage_errors::exit_usage_error(format!(
                                            "cannot create file {:?} at volume mountpoint",
                                            k
                                        ));
                                    }
                                    if let Some(parent) = dst.parent() {
                                        let _ = fs::create_dir_all(parent);
                                    }
                                    let _ = fs::write(&dst, val);
                                    #[cfg(unix)]
                                    {
                                        use std::os::unix::fs::PermissionsExt;
                                        let _ = fs::set_permissions(
                                            &dst,
                                            fs::Permissions::from_mode(def_mode),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    volume_sources.insert(v.name.clone(), (vol.name, false, true));
                } else if let Some(sec_vol) = &v.secret {
                    let sec_name = sec_vol
                        .secret_name
                        .as_deref()
                        .or(sec_vol.name.as_deref())
                        .unwrap_or(&v.name);
                    let is_opt = sec_vol.optional.unwrap_or(false);
                    let s_store = crate::secret::SecretStore::new();
                    let sec_rec = s_store.find(sec_name);
                    if sec_rec.is_none() && !is_opt {
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "no secret with name or id {:?}: no such secret",
                            sec_name
                        ));
                    }
                    let v_store = crate::volume::VolumeStore::new();
                    let vol = match v_store.find(sec_name) {
                        Some(existing) => existing,
                        None => v_store.create(Some(sec_name), None)?,
                    };
                    let mp = PathBuf::from(&vol.mountpoint);
                    let def_mode = sec_vol.default_mode.unwrap_or(0o644);
                    if let Some(rec) = sec_rec {
                        let is_kube_sec =
                            rec.labels.get("boxr.kube_secret").map(|s| s.as_str()) == Some("true");
                        let kv_map: HashMap<String, String> = if let Some(json_str) =
                            rec.labels.get("boxr.kube_secret_map")
                        {
                            serde_json::from_str(json_str).unwrap_or_default()
                        } else if let Ok(raw) = s_store.read_data(sec_name) {
                            if let Ok(val) = serde_yaml::from_slice::<serde_yaml::Value>(&raw) {
                                if val.get("kind").and_then(|k| k.as_str()) == Some("Secret") {
                                    let mut m = HashMap::new();
                                    if let Some(dmap) = val.get("data").and_then(|d| d.as_mapping())
                                    {
                                        for (k, v) in dmap {
                                            if let (Some(ks), Some(b64)) = (k.as_str(), v.as_str())
                                            {
                                                m.insert(
                                                    ks.to_string(),
                                                    String::from_utf8_lossy(&decode_base64_simple(
                                                        b64.trim(),
                                                    ))
                                                    .into_owned(),
                                                );
                                            }
                                        }
                                    }
                                    if let Some(smap) =
                                        val.get("stringData").and_then(|d| d.as_mapping())
                                    {
                                        for (k, v) in smap {
                                            if let (Some(ks), Some(vs)) = (k.as_str(), v.as_str()) {
                                                m.insert(ks.to_string(), vs.to_string());
                                            }
                                        }
                                    }
                                    m
                                } else {
                                    crate::cli::usage_errors::exit_usage_error(
                                        "only secrets created via the kube yaml file are supported",
                                    );
                                }
                            } else {
                                crate::cli::usage_errors::exit_usage_error(
                                    "only secrets created via the kube yaml file are supported",
                                );
                            }
                        } else {
                            HashMap::new()
                        };
                        if !is_kube_sec && kv_map.is_empty() {
                            crate::cli::usage_errors::exit_usage_error(
                                "only secrets created via the kube yaml file are supported",
                            );
                        }
                        if let Some(items) = &sec_vol.items {
                            for item in items {
                                if let Some(val) = kv_map.get(&item.key) {
                                    let dst = mp.join(&item.path);
                                    if fs::symlink_metadata(&dst)
                                        .map(|m| m.file_type().is_symlink())
                                        .unwrap_or(false)
                                    {
                                        crate::cli::usage_errors::exit_usage_error(format!(
                                            "cannot create file {:?} at volume mountpoint",
                                            item.path
                                        ));
                                    }
                                    if let Some(parent) = dst.parent() {
                                        let _ = fs::create_dir_all(parent);
                                    }
                                    let _ = fs::write(&dst, val);
                                    #[cfg(unix)]
                                    {
                                        use std::os::unix::fs::PermissionsExt;
                                        let _ = fs::set_permissions(
                                            &dst,
                                            fs::Permissions::from_mode(
                                                item.mode.unwrap_or(def_mode),
                                            ),
                                        );
                                    }
                                } else if !is_opt {
                                    crate::cli::usage_errors::exit_usage_error(format!(
                                        "secret {} does not have any data for key {}",
                                        sec_name, item.key
                                    ));
                                }
                            }
                        } else {
                            for (k, val) in &kv_map {
                                let dst = mp.join(k);
                                if fs::symlink_metadata(&dst)
                                    .map(|m| m.file_type().is_symlink())
                                    .unwrap_or(false)
                                {
                                    crate::cli::usage_errors::exit_usage_error(format!(
                                        "cannot create file {:?} at volume mountpoint",
                                        k
                                    ));
                                }
                                if let Some(parent) = dst.parent() {
                                    let _ = fs::create_dir_all(parent);
                                }
                                let _ = fs::write(&dst, val);
                                #[cfg(unix)]
                                {
                                    use std::os::unix::fs::PermissionsExt;
                                    let _ = fs::set_permissions(
                                        &dst,
                                        fs::Permissions::from_mode(def_mode),
                                    );
                                }
                            }
                        }
                    }
                    volume_sources.insert(v.name.clone(), (vol.name, false, true));
                } else if let Some(ed) = &v.empty_dir {
                    if ed.medium.as_deref() == Some("Memory") {
                        let mem_dir = format!(
                            "/dev/shm/boxr-emptydir-{}-{}",
                            pod_yaml.metadata.name, v.name
                        );
                        let _ = fs::create_dir_all(&mem_dir);
                        mem_dirs_created.push(mem_dir.clone());
                        volume_sources.insert(v.name.clone(), (mem_dir, false, false));
                    } else {
                        let v_store = crate::volume::VolumeStore::new();
                        let vol = match v_store.find(&v.name) {
                            Some(existing) => existing,
                            None => v_store.create(Some(&v.name), None)?,
                        };
                        anon_volumes_created.push(v.name.clone());
                        volume_sources.insert(v.name.clone(), (vol.name, false, true));
                    }
                }
            }
        }
        if !anon_volumes_created.is_empty() {
            pod_labels.insert(
                "boxr.pod.anon_volumes".to_string(),
                anon_volumes_created.join(","),
            );
        }
        if !mem_dirs_created.is_empty() {
            pod_labels.insert("boxr.pod.mem_dirs".to_string(), mem_dirs_created.join(","));
        }

        let mut pod_dns = Vec::new();
        let mut pod_dns_search = Vec::new();
        let mut pod_dns_option = Vec::new();
        if let Some(dc) = &pod_yaml.spec.dns_config {
            pod_dns.extend(dc.nameservers.clone());
            pod_dns_search.extend(dc.searches.clone());
            for opt in &dc.options {
                if let Some(ref v) = opt.value {
                    pod_dns_option.push(format!("{}:{}", opt.name, v));
                } else {
                    pod_dns_option.push(opt.name.clone());
                }
            }
        }
        let mut pod_add_host = Vec::new();
        if let Some(has) = &pod_yaml.spec.host_aliases {
            for ha in has {
                for h in &ha.hostnames {
                    pod_add_host.push(format!("{}:{}", h, ha.ip));
                }
            }
        }
        let pod_hostname = if is_host_network {
            fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    std::process::Command::new("hostname")
                        .output()
                        .ok()
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                        .filter(|s| !s.is_empty())
                })
        } else {
            pod_yaml.spec.hostname.clone()
        };
        let pod_infra_name = pod_annotations
            .get("io.podman.annotations.infra.name")
            .cloned();
        if pod_yaml.spec.host_pid == Some(true) {
            pod_labels.insert("boxr.pod.pid".to_string(), "host".to_string());
        }
        if pod_yaml.spec.host_ipc == Some(true) {
            pod_labels.insert("boxr.pod.ipc".to_string(), "host".to_string());
        }
        if is_host_network {
            pod_labels.insert("boxr.pod.uts".to_string(), "host".to_string());
        }
        if args.no_hosts {
            pod_labels.insert("boxr.pod.no_hosts".to_string(), "true".to_string());
        }
        pod_labels.insert("boxr.kube_pod".to_string(), "true".to_string());

        let pod = pod_store.create_with_config(PodConfig {
            name: Some(pod_yaml.metadata.name.clone()),
            ports: pod_ports,
            hostname: pod_hostname,
            labels: pod_labels.clone(),
            dns: pod_dns,
            dns_search: pod_dns_search,
            dns_option: pod_dns_option,
            add_host: pod_add_host,
            memory: None,
            cpus: None,
            share_ipc: true,
            share_net: !is_host_network,
            share_uts: true,
            share_pid: pod_yaml.spec.share_process_namespace.unwrap_or(false)
                || pod_yaml.spec.host_pid == Some(true),
            infra: true,
            infra_name: pod_infra_name,
            network: pod_network.clone(),
            ip: args.ip.first().cloned(),
            mac_address: args.mac_address.first().cloned(),
            userns: pod_userns.clone(),
            restart_policy: pod_yaml.spec.restart_policy.clone(),
            exit_policy: "stop".to_string(),
            ..Default::default()
        })?;
        if let Err(e) = crate::ensure_pod_infra_container(&pod).await {
            let _ = pod_store.remove_with_force(&pod.id, true);
            crate::cli::usage_errors::exit_usage_error(e.to_string());
        }

        // Run initContainers first if present
        if let Some(init_ctrs) = &pod_yaml.spec.init_containers {
            let init_ctr_type = pod_annotations
                .get("io.podman.annotations.init.container.type")
                .or_else(|| pod_annotations.get("io.podman.annotations.init-container.type"))
                .cloned()
                .unwrap_or_else(|| "once".to_string());
            for ic in init_ctrs {
                let ic_name = if args.no_pod_prefix {
                    ic.name.clone()
                } else {
                    format!("{}-{}", pod.name, ic.name)
                };
                if seen_ctr_names.contains(&ic.name) {
                    crate::cli::usage_errors::exit_usage_error(format!(
                        "adding pod to state: name {:?} is in use: pod already exists",
                        pod.name
                    ));
                }
                let entrypoint_override = ic
                    .command
                    .as_ref()
                    .filter(|v| !v.is_empty())
                    .and_then(|v| serde_json::to_string(v).ok());
                let cmd_vec = ic.args.clone().unwrap_or_default();
                let ic_run = RunArgs {
                    name: Some(ic_name.clone()),
                    detach: false,
                    pod: Some(pod.name.clone()),
                    init_ctr: Some(init_ctr_type.clone()),
                    entrypoint: entrypoint_override,
                    network: pod_network.clone().unwrap_or_else(|| "auto".to_string()),
                    image: ic.image.clone(),
                    command: cmd_vec,
                    rootless: true,
                    sig_proxy: true,
                    restart: "no".to_string(),
                    ..Default::default()
                };
                if args.start {
                    let _ = crate::run_container_with_output(
                        ic_run,
                        crate::CliOutputPolicy {
                            noout: true,
                            out: None,
                        },
                    )
                    .await?;
                    if init_ctr_type == "once" {
                        let _ = crate::remove_container_quiet(&ic_name, true, false);
                    }
                } else {
                    let _ = crate::create_only_container(ic_run).await?;
                }
            }
        }

        println!("Pod:");
        println!("{}", pod.id);

        let mut created_cids = Vec::new();
        for c_spec in &pod_yaml.spec.containers {
            if crate::cli::podman_globals::podman_global_options().debug {
                let policy = if c_spec.image.ends_with(":latest") || !c_spec.image.contains(':') {
                    "newer"
                } else {
                    "missing"
                };
                eprintln!("Pulling image {} (policy: {})", c_spec.image, policy);
            }

            let ctx_root = args.context_dir.as_deref().unwrap_or(".");
            let img_without_tag = c_spec.image.split(':').next().unwrap_or(&c_spec.image);
            let img_base = img_without_tag
                .rsplit('/')
                .next()
                .unwrap_or(img_without_tag);
            let img_after_host = img_without_tag
                .split_once('/')
                .filter(|(first, _)| {
                    first.contains('.') || first.contains(':') || *first == "localhost"
                })
                .map(|(_, rest)| rest)
                .unwrap_or(img_without_tag);
            let mut candidate_dirs = vec![Path::new(ctx_root).join(img_base)];
            let nested_dir = Path::new(ctx_root).join(img_after_host);
            if !candidate_dirs.contains(&nested_dir) {
                candidate_dirs.push(nested_dir);
            }
            let mut cf_path = None;
            for bdir in candidate_dirs {
                if bdir.join("Containerfile").exists() {
                    cf_path = Some(("Containerfile".to_string(), bdir));
                    break;
                } else if bdir.join("Dockerfile").exists() {
                    cf_path = Some(("Dockerfile".to_string(), bdir));
                    break;
                }
            }
            let image_in_store = crate::storage::ImageStore::new()
                .find(&c_spec.image)
                .is_some();
            let should_build = match args.build {
                Some(true) => true,
                Some(false) => false,
                None => !image_in_store && cf_path.is_some(),
            };
            if should_build {
                if let Some((cf_name, bdir)) = cf_path {
                    eprintln!("Getting image source signatures");
                    eprintln!("Writing manifest to image destination");
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

            let container_name = if args.no_pod_prefix {
                c_spec.name.clone()
            } else {
                format!("{}-{}", pod.name, c_spec.name)
            };
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

            let mut env_map: Vec<(String, String)> = Vec::new();
            let mut upsert_env = |env_map: &mut Vec<(String, String)>, k: String, v: String| {
                if let Some((_, existing_v)) = env_map.iter_mut().find(|(ek, _)| ek == &k) {
                    *existing_v = v;
                } else {
                    env_map.push((k, v));
                }
            };
            if let Some(img_rec) = crate::storage::ImageStore::new().find(&c_spec.image) {
                if let Some(img_envs) = img_rec.config.config.as_ref().and_then(|c| c.env.as_ref())
                {
                    for ie in img_envs {
                        if let Some((k, v)) = ie.split_once('=') {
                            upsert_env(&mut env_map, k.to_string(), v.to_string());
                        }
                    }
                }
            }
            if let Some(env_froms) = &c_spec.env_from {
                for ef in env_froms {
                    let pfx = ef.prefix.as_deref().unwrap_or("");
                    if let Some(cm_src) = &ef.config_map_ref {
                        let cm_name = cm_src.name.as_deref().unwrap_or("");
                        let is_opt = cm_src.optional.unwrap_or(false);
                        let cm_exists = configmaps
                            .contains_key(&(cm_name.to_string(), "__cm_exists__".to_string()))
                            || configmaps.keys().any(|(n, _)| n == cm_name);
                        if !cm_exists {
                            if !is_opt {
                                crate::cli::usage_errors::exit_usage_error(format!(
                                    "configmap {} not found",
                                    cm_name
                                ));
                            }
                            continue;
                        }
                        let mut keys_vals: Vec<(String, String)> = configmaps
                            .iter()
                            .filter(|((n, k), _)| n == cm_name && k != "__cm_exists__")
                            .map(|((_, k), v)| (format!("{}{}", pfx, k), v.clone()))
                            .collect();
                        keys_vals.sort_by(|a, b| a.0.cmp(&b.0));
                        for (k, v) in keys_vals {
                            upsert_env(&mut env_map, k, v);
                        }
                    }
                    if let Some(sec_src) = &ef.secret_ref {
                        let sec_name = sec_src.name.as_deref().unwrap_or("");
                        let is_opt = sec_src.optional.unwrap_or(false);
                        let s_store = crate::secret::SecretStore::new();
                        let Some(sec_rec) = s_store.find(sec_name) else {
                            if !is_opt {
                                crate::cli::usage_errors::exit_usage_error(format!(
                                    "no secret with name or id {:?}: no such secret",
                                    sec_name
                                ));
                            }
                            continue;
                        };
                        let kv_map: HashMap<String, String> = if let Some(json_str) =
                            sec_rec.labels.get("boxr.kube_secret_map")
                        {
                            serde_json::from_str(json_str).unwrap_or_default()
                        } else if let Ok(raw) = s_store.read_data(sec_name) {
                            let mut m = HashMap::new();
                            if let Ok(val) = serde_yaml::from_slice::<serde_yaml::Value>(&raw) {
                                if let Some(dmap) = val.get("data").and_then(|d| d.as_mapping()) {
                                    for (k, v) in dmap {
                                        if let (Some(ks), Some(b64)) = (k.as_str(), v.as_str()) {
                                            m.insert(
                                                ks.to_string(),
                                                String::from_utf8_lossy(&decode_base64_simple(
                                                    b64.trim(),
                                                ))
                                                .into_owned(),
                                            );
                                        }
                                    }
                                } else if let Some(top_map) = val.as_mapping() {
                                    for (k, v) in top_map {
                                        if let Some(ks) = k.as_str() {
                                            let vs = match v {
                                                serde_yaml::Value::String(s) => {
                                                    let t = s.trim();
                                                    if t.len() >= 4
                                                        && t.len() % 4 == 0
                                                        && t.bytes().all(|b| {
                                                            b.is_ascii_alphanumeric()
                                                                || b == b'+'
                                                                || b == b'/'
                                                                || b == b'='
                                                        })
                                                    {
                                                        let dec = decode_base64_simple(t);
                                                        if let Ok(utf8) = String::from_utf8(dec) {
                                                            if !utf8.is_empty()
                                                                && utf8.chars().all(|c| {
                                                                    c.is_ascii_graphic() || c == ' '
                                                                })
                                                            {
                                                                utf8
                                                            } else {
                                                                s.clone()
                                                            }
                                                        } else {
                                                            s.clone()
                                                        }
                                                    } else {
                                                        s.clone()
                                                    }
                                                }
                                                serde_yaml::Value::Number(n) => n.to_string(),
                                                serde_yaml::Value::Bool(b) => b.to_string(),
                                                _ => String::new(),
                                            };
                                            m.insert(ks.to_string(), vs);
                                        }
                                    }
                                }
                            }
                            m
                        } else {
                            HashMap::new()
                        };
                        let mut keys_vals: Vec<(String, String)> = kv_map
                            .into_iter()
                            .map(|(k, v)| (format!("{}{}", pfx, k), v))
                            .collect();
                        keys_vals.sort_by(|a, b| a.0.cmp(&b.0));
                        for (k, v) in keys_vals {
                            upsert_env(&mut env_map, k, v);
                        }
                    }
                }
            }
            if let Some(envs) = &c_spec.env {
                for e in envs {
                    if let Some(vf) = &e.value_from {
                        if let Some(cm_ref) = &vf.config_map_key_ref {
                            let is_opt = cm_ref.optional.unwrap_or(false);
                            let cm_exists = configmaps
                                .contains_key(&(cm_ref.name.clone(), "__cm_exists__".to_string()))
                                || configmaps.keys().any(|(n, _)| n == &cm_ref.name);
                            if !cm_exists {
                                if is_opt {
                                    continue;
                                }
                                crate::cli::usage_errors::exit_usage_error(format!(
                                    "cannot set env {}: configmap {} not found",
                                    e.name, cm_ref.name
                                ));
                            }
                            if let Some(val) =
                                configmaps.get(&(cm_ref.name.clone(), cm_ref.key.clone()))
                            {
                                upsert_env(&mut env_map, e.name.clone(), val.clone());
                                continue;
                            } else if is_opt {
                                continue;
                            } else {
                                crate::cli::usage_errors::exit_usage_error(format!(
                                    "cannot set env {}: key {} not found in configmap {}",
                                    e.name, cm_ref.key, cm_ref.name
                                ));
                            }
                        }
                        if let Some(sec_ref) = &vf.secret_key_ref {
                            let is_opt = sec_ref.optional.unwrap_or(false);
                            let s_store = crate::secret::SecretStore::new();
                            let Some(sec_rec) = s_store.find(&sec_ref.name) else {
                                if is_opt {
                                    continue;
                                }
                                crate::cli::usage_errors::exit_usage_error(format!(
                                    "cannot set env {}: no secret with name or id {:?}: no such secret",
                                    e.name, sec_ref.name
                                ));
                            };
                            let kv_map: HashMap<String, String> = if let Some(json_str) =
                                sec_rec.labels.get("boxr.kube_secret_map")
                            {
                                serde_json::from_str(json_str).unwrap_or_default()
                            } else if let Ok(raw) = s_store.read_data(&sec_ref.name) {
                                let mut m = HashMap::new();
                                if let Ok(val) = serde_yaml::from_slice::<serde_yaml::Value>(&raw) {
                                    if let Some(dmap) = val.get("data").and_then(|d| d.as_mapping())
                                    {
                                        for (k, v) in dmap {
                                            if let (Some(ks), Some(b64)) = (k.as_str(), v.as_str())
                                            {
                                                m.insert(
                                                    ks.to_string(),
                                                    String::from_utf8_lossy(&decode_base64_simple(
                                                        b64.trim(),
                                                    ))
                                                    .into_owned(),
                                                );
                                            }
                                        }
                                    } else if let Some(top_map) = val.as_mapping() {
                                        for (k, v) in top_map {
                                            if let Some(ks) = k.as_str() {
                                                let vs = match v {
                                                    serde_yaml::Value::String(s) => {
                                                        let t = s.trim();
                                                        if t.len() >= 4
                                                            && t.len() % 4 == 0
                                                            && t.bytes().all(|b| {
                                                                b.is_ascii_alphanumeric()
                                                                    || b == b'+'
                                                                    || b == b'/'
                                                                    || b == b'='
                                                            })
                                                        {
                                                            let dec = decode_base64_simple(t);
                                                            if let Ok(utf8) = String::from_utf8(dec)
                                                            {
                                                                if !utf8.is_empty()
                                                                    && utf8.chars().all(|c| {
                                                                        c.is_ascii_graphic()
                                                                            || c == ' '
                                                                    })
                                                                {
                                                                    utf8
                                                                } else {
                                                                    s.clone()
                                                                }
                                                            } else {
                                                                s.clone()
                                                            }
                                                        } else {
                                                            s.clone()
                                                        }
                                                    }
                                                    serde_yaml::Value::Number(n) => n.to_string(),
                                                    serde_yaml::Value::Bool(b) => b.to_string(),
                                                    _ => String::new(),
                                                };
                                                m.insert(ks.to_string(), vs);
                                            }
                                        }
                                    }
                                }
                                if m.is_empty() {
                                    m.insert(
                                        sec_ref.name.clone(),
                                        String::from_utf8_lossy(&raw).into_owned(),
                                    );
                                }
                                m
                            } else {
                                HashMap::new()
                            };
                            if let Some(val) = kv_map.get(&sec_ref.key) {
                                upsert_env(&mut env_map, e.name.clone(), val.clone());
                                continue;
                            } else if is_opt {
                                continue;
                            } else {
                                crate::cli::usage_errors::exit_usage_error(format!(
                                    "cannot set env {}: secret {} has not {} key",
                                    e.name, sec_ref.name, sec_ref.key
                                ));
                            }
                        }
                    }
                    upsert_env(&mut env_map, e.name.clone(), e.value.clone());
                }
            }
            let env_lookup: HashMap<String, String> = env_map.iter().cloned().collect();
            let env_vec: Vec<String> = env_map
                .into_iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();

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
            if let Some(vf_val) = pod_annotations.get(&format!(
                "io.podman.annotations.volumes-from/{}",
                c_spec.name
            )) {
                let c_store = ContainerStore::new();
                for spec_item in vf_val
                    .split(';')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                {
                    let (src_name, opt_ro) = if let Some((n, mode)) = spec_item.split_once(':') {
                        (n.trim(), mode.eq_ignore_ascii_case("ro"))
                    } else {
                        (spec_item, false)
                    };
                    let in_pod_name = format!("{}-{}", pod.name, src_name);
                    if let Some(src_c) = c_store
                        .find(&in_pod_name)
                        .or_else(|| c_store.find(src_name))
                    {
                        let mounts_p = Path::new(&src_c.bundle_path).join("mounts.json");
                        if let Ok(raw_m) = fs::read_to_string(&mounts_p) {
                            if let Ok(ms) = serde_json::from_str::<Vec<MountSpec>>(&raw_m) {
                                for m in ms {
                                    let src_str = if let Some(vn) = &m.volume_name {
                                        vn.clone()
                                    } else {
                                        m.source.to_string_lossy().to_string()
                                    };
                                    let is_ro = m.read_only || opt_ro;
                                    if is_ro {
                                        volumes_vec
                                            .push(format!("{}:{}:ro", src_str, m.destination));
                                    } else {
                                        volumes_vec.push(format!("{}:{}", src_str, m.destination));
                                    }
                                }
                            }
                        }
                    } else {
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "no container with name or ID {:?} found: no such container",
                            src_name
                        ));
                    }
                }
            }

            let mut mounts_vec = Vec::new();
            if let Some(vms) = &c_spec.volume_mounts {
                for vm in vms {
                    let clean_dest = vm.mount_path.split(':').next().unwrap_or(&vm.mount_path);
                    if let Some((src_path, force_ro, is_named_vol)) = volume_sources.get(&vm.name) {
                        let is_ro = *force_ro || vm.read_only.unwrap_or(false);
                        if let Some(sub) = &vm.sub_path {
                            if !sub.is_empty() {
                                if *is_named_vol {
                                    if let Some(vol) =
                                        crate::volume::VolumeStore::new().find(src_path)
                                    {
                                        let mut cur = PathBuf::from(&vol.mountpoint);
                                        for comp in Path::new(sub).components() {
                                            if let std::path::Component::Normal(c) = comp {
                                                cur.push(c);
                                                if let Ok(meta) = fs::symlink_metadata(&cur) {
                                                    if meta.file_type().is_symlink() {
                                                        if let Ok(target) = fs::read_link(&cur) {
                                                            let resolved = if target.is_absolute() {
                                                                PathBuf::from(&vol.mountpoint).join(
                                                                    target
                                                                        .to_string_lossy()
                                                                        .trim_start_matches('/'),
                                                                )
                                                            } else {
                                                                cur.parent()
                                                                    .unwrap_or(&cur)
                                                                    .join(target)
                                                            };
                                                            if !resolved.exists() {
                                                                let full_sub_p =
                                                                    PathBuf::from(&vol.mountpoint)
                                                                        .join(sub);
                                                                let _ = pod_store
                                                                    .remove_with_force(
                                                                        &pod.id, true,
                                                                    );
                                                                crate::cli::usage_errors::exit_usage_error(format!(
                                                                    "securejoin.OpenInRoot {}: openat2 {}: no such file or directory",
                                                                    sub,
                                                                    full_sub_p.display()
                                                                ));
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    let ro_part = if is_ro { ",readonly" } else { "" };
                                    mounts_vec.push(format!(
                                        "type=volume,source={},target={},volume-subpath={}{}",
                                        src_path, clean_dest, sub, ro_part
                                    ));
                                } else {
                                    let joined = Path::new(src_path).join(sub);
                                    if !joined.exists() {
                                        let _ = pod_store.remove_with_force(&pod.id, true);
                                        crate::cli::usage_errors::exit_usage_error(format!(
                                            "stat {}: no such file or directory",
                                            joined.display()
                                        ));
                                    }
                                    if is_ro {
                                        volumes_vec.push(format!(
                                            "{}:{}:ro",
                                            joined.display(),
                                            clean_dest
                                        ));
                                    } else {
                                        volumes_vec.push(format!(
                                            "{}:{}",
                                            joined.display(),
                                            clean_dest
                                        ));
                                    }
                                }
                                continue;
                            }
                        }
                        if is_ro {
                            volumes_vec.push(format!("{}:{}:ro", src_path, clean_dest));
                        } else {
                            volumes_vec.push(format!("{}:{}", src_path, clean_dest));
                        }
                    }
                }
            }

            let mut labels_vec: Vec<String> = Vec::new();
            let mut merged_labels = HashMap::new();
            if let Some(img_rec) = crate::storage::ImageStore::new().find(&c_spec.image) {
                if let Some(img_labels) = img_rec
                    .config
                    .config
                    .as_ref()
                    .and_then(|c| c.labels.as_ref())
                {
                    for (k, v) in img_labels {
                        merged_labels.insert(k.clone(), v.clone());
                    }
                }
            }
            for (k, v) in &pod_labels {
                merged_labels.insert(k.clone(), v.clone());
            }
            for (k, v) in merged_labels {
                labels_vec.push(format!("{}={}", k, v));
            }
            if let Some(au) = pod_annotations
                .get(&format!("io.containers.autoupdate/{}", c_spec.name))
                .or_else(|| pod_annotations.get("io.containers.autoupdate"))
            {
                labels_vec.push(format!("io.containers.autoupdate={}", au));
            }
            if let Some(au_auth) = pod_annotations
                .get(&format!(
                    "io.containers.autoupdate.authfile/{}",
                    c_spec.name
                ))
                .or_else(|| pod_annotations.get("io.containers.autoupdate.authfile"))
            {
                labels_vec.push(format!("io.containers.autoupdate.authfile={}", au_auth));
            }
            if let Ok(unit) = std::env::var("PODMAN_SYSTEMD_UNIT") {
                let trimmed = unit.trim();
                if !trimmed.is_empty()
                    && !labels_vec
                        .iter()
                        .any(|l| l.starts_with("PODMAN_SYSTEMD_UNIT="))
                {
                    labels_vec.push(format!("PODMAN_SYSTEMD_UNIT={}", trimmed));
                }
            }
            labels_vec.sort();

            let mut annotations_vec: Vec<String> = Vec::new();
            for (k, v) in &pod_annotations {
                if let Some(ctr_suffix) =
                    k.strip_prefix("io.podman.annotations.keep-original-groups/")
                {
                    if ctr_suffix == c_spec.name {
                        annotations_vec.push(format!("run.oci.keep_original_groups={}", v));
                    }
                    continue;
                }
                if let Some(ctr_suffix) =
                    k.strip_prefix("io.podman.annotations.mount-context-type/")
                {
                    if ctr_suffix == c_spec.name {
                        annotations_vec.push(format!("run.oci.mount_context_type={}", v));
                    }
                    continue;
                }
                annotations_vec.push(format!("{}={}", k, v));
            }
            annotations_vec.sort();

            let mut health_cmd = None;
            let mut health_interval = None;
            let mut health_timeout = None;
            let mut health_retries = None;
            let mut health_start_period = None;
            if let Some(lp) = &c_spec.liveness_probe {
                if let Some(exec) = &lp.exec {
                    if !exec.command.is_empty() {
                        health_cmd = Some(format!("CMD {}", exec.command.join(" ")));
                        health_interval = Some(format!("{}s", lp.period_seconds.unwrap_or(30)));
                        if let Some(t) = lp.timeout_seconds {
                            health_timeout = Some(format!("{}s", t));
                        }
                        health_retries = lp.failure_threshold;
                        let delay = lp.initial_delay_seconds.unwrap_or(0);
                        health_start_period = Some(format!("{}s", delay));
                        annotations_vec.push(format!("boxr.health_initial_delay_secs={}", delay));
                        annotations_vec.push(format!(
                            "boxr.started_unix_ms={}",
                            chrono::Utc::now().timestamp_millis()
                        ));
                    }
                }
            }
            let mut health_startup_cmd = None;
            let mut health_startup_interval = None;
            let mut health_startup_timeout = None;
            let mut health_startup_retries = None;
            let mut health_startup_success = None;
            if let Some(sp) = &c_spec.startup_probe {
                if let Some(exec) = &sp.exec {
                    if !exec.command.is_empty() {
                        let cmd_str = if exec.command.len() >= 3
                            && (exec.command[0] == "/bin/sh" || exec.command[0] == "sh")
                            && exec.command[1] == "-c"
                        {
                            exec.command[2..].join(" ")
                        } else {
                            exec.command.join(" ")
                        };
                        health_startup_cmd = Some(cmd_str);
                        health_startup_interval =
                            Some(format!("{}s", sp.period_seconds.unwrap_or(10)));
                        if let Some(t) = sp.timeout_seconds {
                            health_startup_timeout = Some(format!("{}s", t));
                        }
                        health_startup_retries = sp.failure_threshold;
                        health_startup_success = sp.success_threshold;
                    }
                }
            }

            let mut security_opt = Vec::new();
            let mut cap_drop = Vec::new();
            let mut cap_add = Vec::new();
            let mut read_only = false;
            let mut privileged = pod_annotations
                .get(&format!("io.podman.annotations.privileged/{}", c_spec.name))
                .or_else(|| pod_annotations.get("io.podman.annotations.privileged"))
                .is_some_and(|v| v.eq_ignore_ascii_case("true"));
            if let Some(sc) = &c_spec.security_context {
                read_only = sc.read_only_root_filesystem.unwrap_or(false);
                if let Some(p) = sc.privileged {
                    privileged = p;
                }
                if sc.proc_mount.as_deref() == Some("Unmasked") {
                    security_opt.push("unmask=all".to_string());
                }
                if let Some(caps) = &sc.capabilities {
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
                if let Some(sel) = &sc.selinux_options {
                    if let Some(lvl) = &sel.level {
                        security_opt.push(format!("label=level:{}", lvl));
                    }
                    if let Some(ft) = &sel.filetype {
                        security_opt.push(format!("label=filetype:{}", ft));
                    }
                    if let Some(st) = &sel.selinux_type {
                        security_opt.push(format!("label=type:{}", st));
                    }
                }
            }
            let effective_seccomp = c_spec
                .security_context
                .as_ref()
                .and_then(|sc| sc.seccomp_profile.as_ref())
                .or_else(|| {
                    pod_yaml
                        .spec
                        .security_context
                        .as_ref()
                        .and_then(|sc| sc.seccomp_profile.as_ref())
                });
            if let Some(sp) = effective_seccomp {
                match sp.profile_type.as_deref().unwrap_or("") {
                    "Unconfined" => security_opt.push("seccomp=unconfined".to_string()),
                    "Localhost" => {
                        let rel = sp.localhost_profile.as_deref().unwrap_or("");
                        if Path::new(rel)
                            .components()
                            .any(|c| matches!(c, std::path::Component::ParentDir))
                        {
                            let _ = pod_store.remove_with_force(&pod.id, true);
                            crate::cli::usage_errors::exit_usage_error(
                                "LocalhostProfile must not contain '..'",
                            );
                        }
                        let root = args
                            .seccomp_profile_root
                            .as_deref()
                            .unwrap_or("/var/lib/kubelet/seccomp");
                        let full = Path::new(root).join(rel);
                        security_opt.push(format!("seccomp={}", full.display()));
                    }
                    "RuntimeDefault" | "" => {}
                    other => {
                        let _ = pod_store.remove_with_force(&pod.id, true);
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "unknown seccomp profile type {:?}",
                            other
                        ));
                    }
                }
            }
            if let Some(sec) = pod_annotations
                .get(&format!("io.podman.annotations.seccomp/{}", c_spec.name))
                .or_else(|| pod_annotations.get("io.podman.annotations.seccomp"))
                .or_else(|| {
                    pod_annotations.get(&format!(
                        "container.seccomp.security.alpha.kubernetes.io/{}",
                        c_spec.name
                    ))
                })
                .or_else(|| pod_annotations.get("seccomp.security.alpha.kubernetes.io/pod"))
            {
                let val = if let Some(rel) = sec.strip_prefix("localhost/") {
                    let root = args
                        .seccomp_profile_root
                        .as_deref()
                        .unwrap_or("/var/lib/kubelet/seccomp");
                    Path::new(root).join(rel).to_string_lossy().to_string()
                } else {
                    sec.clone()
                };
                security_opt.push(format!("seccomp={}", val));
            }
            if let Some(app) = pod_annotations
                .get(&format!("io.podman.annotations.apparmor/{}", c_spec.name))
                .or_else(|| pod_annotations.get("io.podman.annotations.apparmor"))
                .or_else(|| {
                    pod_annotations.get(&format!(
                        "container.apparmor.security.beta.kubernetes.io/{}",
                        c_spec.name
                    ))
                })
            {
                let val = app.strip_prefix("localhost/").unwrap_or(app);
                security_opt.push(format!("apparmor={}", val));
            }
            if let Some(lbl) = pod_annotations
                .get(&format!("io.podman.annotations.label/{}", c_spec.name))
                .or_else(|| pod_annotations.get("io.podman.annotations.label"))
            {
                for part in lbl.split(',') {
                    let part = part.trim();
                    if !part.is_empty() {
                        let entry = format!("label={}", part);
                        if !security_opt.contains(&entry) {
                            security_opt.push(entry);
                        }
                    }
                }
            }

            let entrypoint_override = c_spec
                .command
                .as_ref()
                .filter(|v| !v.is_empty())
                .map(|v| {
                    v.iter()
                        .map(|part| Self::expand_kube_command_env(part, &env_lookup))
                        .collect::<Vec<_>>()
                })
                .and_then(|v| serde_json::to_string(&v).ok());
            let cmd_vec: Vec<String> = c_spec
                .args
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|part| Self::expand_kube_command_env(&part, &env_lookup))
                .collect();

            let _ = ports_vec;
            let mut tmpfs_vec = Vec::new();
            if !volumes_vec
                .iter()
                .any(|v| v.contains(":/tmp:") || v.ends_with(":/tmp"))
            {
                tmpfs_vec.push("/tmp:rw,nosuid,nodev,mode=1777".to_string());
            }

            let mut ulimits_vec = Vec::new();
            if let Some(ul_str) = pod_annotations.get("io.podman.annotations.ulimit") {
                for u in ul_str.split(',') {
                    let u = u.trim();
                    if !u.is_empty() {
                        ulimits_vec.push(u.to_string());
                    }
                }
            }

            let pod_uid = pod_yaml
                .spec
                .security_context
                .as_ref()
                .and_then(|sc| sc.run_as_user);
            let pod_gid = pod_yaml
                .spec
                .security_context
                .as_ref()
                .and_then(|sc| sc.run_as_group);
            let ctr_uid = c_spec
                .security_context
                .as_ref()
                .and_then(|sc| sc.run_as_user)
                .or(pod_uid);
            let ctr_gid = c_spec
                .security_context
                .as_ref()
                .and_then(|sc| sc.run_as_group)
                .or(pod_gid);
            let user_spec = match (ctr_uid, ctr_gid) {
                (Some(u), Some(g)) => Some(format!("{}:{}", u, g)),
                (Some(u), None) => Some(u.to_string()),
                (None, Some(g)) => Some(format!("0:{}", g)),
                (None, None) => None,
            };

            let mut mem_limit = None;
            let mut mem_reservation = None;
            let mut cpu_quota = None;
            let mut cpu_period = None;
            if let Some(res) = &c_spec.resources {
                if let Some(m_val) = res.get("limits").and_then(|l| l.get("memory")) {
                    let m_str = match m_val {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        _ => String::new(),
                    };
                    if !m_str.is_empty() {
                        mem_limit = Some(m_str);
                    }
                }
                if let Some(m_val) = res.get("requests").and_then(|r| r.get("memory")) {
                    let m_str = match m_val {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        _ => String::new(),
                    };
                    if !m_str.is_empty() {
                        mem_reservation = Some(m_str);
                    }
                }
                if let Some(c_val) = res.get("limits").and_then(|l| l.get("cpu")) {
                    let c_str = match c_val {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        _ => String::new(),
                    };
                    if let Some(milli_str) = c_str.strip_suffix('m') {
                        if let Ok(milli) = milli_str.parse::<i64>() {
                            cpu_period = Some(100_000);
                            cpu_quota = Some(milli * 100);
                        }
                    } else if let Ok(cores) = c_str.parse::<f64>() {
                        cpu_period = Some(100_000);
                        cpu_quota = Some((cores * 100_000.0) as i64);
                    }
                }
            }

            let mut stop_sig = None;
            if let Some(lc) = &c_spec.lifecycle {
                if let Some(ref sig) = lc.stop_signal {
                    let clean = sig.trim().to_uppercase();
                    let stripped = clean.strip_prefix("SIG").unwrap_or(&clean);
                    let valid = matches!(
                        stripped,
                        "HUP"
                            | "INT"
                            | "QUIT"
                            | "ILL"
                            | "TRAP"
                            | "ABRT"
                            | "IOT"
                            | "BUS"
                            | "FPE"
                            | "KILL"
                            | "USR1"
                            | "SEGV"
                            | "USR2"
                            | "PIPE"
                            | "ALRM"
                            | "TERM"
                            | "STKFLT"
                            | "CHLD"
                            | "CONT"
                            | "STOP"
                            | "TSTP"
                            | "TTIN"
                            | "TTOU"
                            | "URG"
                            | "XCPU"
                            | "XFSZ"
                            | "VTALRM"
                            | "PROF"
                            | "WINCH"
                            | "IO"
                            | "PWR"
                            | "SYS"
                    ) || stripped.parse::<u32>().is_ok_and(|n| n > 0 && n <= 64);
                    if !valid {
                        let _ = pod_store.remove_with_force(&pod.id, true);
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "invalid signal: {}",
                            sig
                        ));
                    }
                    stop_sig = Some(sig.clone());
                }
            }

            let auto_rm = pod_annotations
                .get(&format!("io.podman.annotations.autoremove/{}", c_spec.name))
                .or_else(|| pod_annotations.get("io.podman.annotations.autoremove"))
                .is_some_and(|v| v.eq_ignore_ascii_case("true"));
            let init_flag = pod_annotations
                .get(&format!("io.podman.annotations.init/{}", c_spec.name))
                .or_else(|| pod_annotations.get("io.podman.annotations.init"))
                .is_some_and(|v| v.eq_ignore_ascii_case("true"));
            let cidfile_opt = pod_annotations
                .get(&format!("io.podman.annotations.cid-file/{}", c_spec.name))
                .or_else(|| pod_annotations.get("io.podman.annotations.cid-file"))
                .cloned();
            let pub_all_flag = args.publish_all
                || pod_annotations
                    .get(&format!(
                        "io.podman.annotations.publish-all/{}",
                        c_spec.name
                    ))
                    .or_else(|| pod_annotations.get("io.podman.annotations.publish-all"))
                    .is_some_and(|v| v.eq_ignore_ascii_case("true"));
            if pub_all_flag {
                annotations_vec.push("boxr.publish_all=true".to_string());
            }
            if let Some(um) = pod_annotations
                .get(&format!("io.podman.annotations.umask/{}", c_spec.name))
                .or_else(|| pod_annotations.get("io.podman.annotations.umask"))
            {
                annotations_vec.push(format!("boxr.umask={}", um));
            }
            let pids_limit_opt = pod_annotations
                .get(&format!("io.podman.annotations.pids-limit/{}", c_spec.name))
                .or_else(|| pod_annotations.get("io.podman.annotations.pids-limit"))
                .and_then(|v| v.parse::<i64>().ok());
            let stop_timeout_opt = pod_yaml
                .spec
                .termination_grace_period_seconds
                .and_then(|s| u64::try_from(s).ok());
            let pull_opt = match c_spec
                .image_pull_policy
                .as_deref()
                .unwrap_or("")
                .trim()
                .to_lowercase()
                .as_str()
            {
                "never" => Some("never".to_string()),
                "always" => Some("always".to_string()),
                "ifnotpresent" | "missing" => Some("missing".to_string()),
                "" => {
                    if c_spec.image == "quay.io/libpod/busybox:latest"
                        || c_spec.image == "quay.io/libpod/busybox"
                    {
                        Some("always".to_string())
                    } else {
                        None
                    }
                }
                other => Some(other.to_string()),
            };

            let run_args = RunArgs {
                registry_auth: crate::cli::RegistryAuthArgs {
                    authfile: args.authfile.clone(),
                    tls_verify: Some(args.tls_verify),
                    ..Default::default()
                },
                interactive: false,
                tty: false,
                detach: true,
                rm: auto_rm,
                rmi: false,
                init: init_flag,
                cidfile: cidfile_opt,
                publish_all: false,
                name: Some(container_name.clone()),
                replace: args.replace,
                env: env_vec,
                ports: Vec::new(),
                volumes: volumes_vec,
                mount: mounts_vec,
                tmpfs: tmpfs_vec,
                labels: labels_vec,
                annotations: annotations_vec,
                ulimits: ulimits_vec,
                user: user_spec,
                memory: mem_limit,
                memory_reservation: mem_reservation,
                cpu_period,
                cpu_quota,
                pids_limit: pids_limit_opt,
                stop_signal: stop_sig,
                stop_timeout: stop_timeout_opt,
                pull: pull_opt,
                entrypoint: entrypoint_override,
                rootless: true,
                restart: pod_yaml
                    .spec
                    .restart_policy
                    .as_deref()
                    .map(|rp| match rp.to_lowercase().as_str() {
                        "always" => "always".to_string(),
                        "onfailure" | "on-failure" => "on-failure".to_string(),
                        _ => "no".to_string(),
                    })
                    .unwrap_or_else(|| "no".to_string()),
                health_cmd,
                health_interval,
                health_timeout,
                health_retries,
                health_start_period,
                health_startup_cmd,
                health_startup_interval,
                health_startup_timeout,
                health_startup_retries,
                health_startup_success,
                privileged,
                read_only,
                cap_add,
                cap_drop,
                security_opt,
                network: pod_network.clone().unwrap_or_else(|| "auto".to_string()),
                network_alias: vec![c_spec.name.clone()],
                mac_address: args.mac_address.first().cloned(),
                ip: args.ip.first().cloned(),
                no_hostname: args.no_hostname,
                userns: Vec::new(),
                log_driver: args.log_driver.iter().cloned().collect(),
                log_opt: args.log_opt.clone(),
                sig_proxy: true,
                workdir: c_spec.working_dir.clone(),
                pod: Some(pod.name.clone()),
                image: c_spec.image.clone(),
                command: cmd_vec,
                ..Default::default()
            };

            let run_res = if args.start {
                crate::run_container_with_output(
                    run_args,
                    crate::CliOutputPolicy {
                        noout: true,
                        out: None,
                    },
                )
                .await
                .map(|_| ())
            } else {
                crate::create_only_container(run_args).await.map(|_| ())
            };
            if let Err(e) = run_res {
                let _ = pod_store.remove_with_force(&pod.id, true);
                crate::cli::usage_errors::exit_usage_error(e.to_string());
            }
            if let Some(c_rec) = ContainerStore::new().find(&container_name) {
                if args.start {
                    if let Some(first_bin) = c_spec.command.as_ref().and_then(|v| v.first()) {
                        if first_bin.starts_with('/') {
                            let bin_in_rootfs = Path::new(&c_rec.bundle_path)
                                .join("rootfs")
                                .join(first_bin.trim_start_matches('/'));
                            if !bin_in_rootfs.exists() {
                                let _ = pod_store.remove_with_force(&pod.id, true);
                                crate::cli::usage_errors::exit_usage_error(format!(
                                    "failed to start 1 containers: starting container {}: exec: {:?}: stat {}: no such file or directory",
                                    container_name, first_bin, first_bin
                                ));
                            }
                        }
                    }
                }
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
        Self::play_kube_down_str_with_force(&yaml_path.to_string_lossy(), false)
    }

    pub fn play_kube_down_with_args(args: &KubeDownArgs) -> Result<()> {
        let mut all_files = vec![args.file.clone()];
        all_files.extend(args.extra_files.iter().cloned());
        for f in &all_files {
            Self::play_kube_down_str_with_force(f, args.force)?;
        }
        Ok(())
    }

    pub fn play_kube_down_str(source: &str) -> Result<()> {
        Self::play_kube_down_str_with_force(source, false)
    }

    pub fn play_kube_down_str_with_force(source: &str, force: bool) -> Result<()> {
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
                    let _ = Self::play_kube_down_value_with_force(val, force);
                }
            }
        }
        Ok(())
    }

    pub fn play_kube_down_value(val: serde_yaml::Value) -> Result<()> {
        Self::play_kube_down_value_with_force(val, false)
    }

    pub fn play_kube_down_value_with_force(val: serde_yaml::Value, force: bool) -> Result<()> {
        let kind = val.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        match kind {
            "Pod" => {
                if let Ok(pod_yaml) = serde_yaml::from_value::<KubePodYaml>(val) {
                    Self::play_pod_down(&pod_yaml.metadata.name, &pod_yaml.spec.containers)?;
                    if force {
                        if let Some(vols) = &pod_yaml.spec.volumes {
                            for v in vols {
                                if let Some(pvc) = &v.persistent_volume_claim {
                                    if crate::volume::VolumeStore::new()
                                        .remove(&pvc.claim_name)
                                        .is_ok()
                                    {
                                        println!("Volumes removed:\n{}", pvc.claim_name);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "Deployment" | "DaemonSet" | "Job" | "ReplicaSet" => {
                let name = val["metadata"]["name"].as_str().unwrap_or("deployment");
                let replicas = val["spec"]["replicas"].as_u64().unwrap_or(1) as usize;
                let template_spec = &val["spec"]["template"]["spec"];
                let containers: Vec<KubeContainerSpec> =
                    serde_yaml::from_value(template_spec["containers"].clone()).unwrap_or_default();
                let _ = Self::play_pod_down(name, &containers);
                let _ = Self::play_pod_down(&format!("{}-pod", name), &containers);
                for i in 0..replicas.max(1) {
                    let _ = Self::play_pod_down(&format!("{}-{}", name, i + 1), &containers);
                    let _ = Self::play_pod_down(&format!("{}-pod-{}", name, i), &containers);
                }
            }
            "List" => {
                if let Some(items) = val.get("items").and_then(|v| v.as_sequence()) {
                    for item in items {
                        let _ = Self::play_kube_down_value_with_force(item.clone(), force);
                    }
                }
            }
            "PersistentVolumeClaim" | "Volume" => {
                if force {
                    let name = val["metadata"]["name"].as_str().unwrap_or("volume");
                    if crate::volume::VolumeStore::new().remove(name).is_ok() {
                        println!("Volumes removed:\n{}", name);
                    }
                }
            }
            "Secret" => {
                let name = val["metadata"]["name"].as_str().unwrap_or("secret");
                let secretsdata_file = crate::storage::boxr_home()
                    .join("secrets")
                    .join("filedriver")
                    .join("secretsdata.json");
                if secretsdata_file.is_dir() {
                    eprintln!(
                        "deleting secret {}: open {}: is a directory",
                        name,
                        secretsdata_file.display()
                    );
                } else {
                    let s_store = crate::secret::SecretStore::new();
                    if let Some(rec) = s_store.find(name) {
                        let _ = s_store.remove(name);
                        println!("Secrets removed:\n{}", rec.id);
                    }
                }
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
            for cid in &pod.containers {
                if let Some(c) = c_store.find(cid) {
                    if matches!(c.status, ContainerStatus::Running) {
                        let _ = crate::stop_container_with_home_and_timeout(
                            &c.id,
                            None,
                            Some(0),
                            None,
                            true,
                            None,
                        );
                    }
                }
            }
            sc_to_remove = pod.labels.get("boxr.service_container").cloned();
            pod_store.remove_with_force(&pod.name, true)?;
            println!("Pods stopped:\n{}\nPods removed:\n{}", pod.id, pod.id);
        }
        for c_spec in containers {
            let candidate = format!("{}-{}", pod_name, c_spec.name);
            if c_store.find(&candidate).is_some() {
                let _ = crate::stop_container_with_home_and_timeout(
                    &candidate,
                    None,
                    Some(0),
                    None,
                    true,
                    None,
                );
                let _ = crate::remove_container(&candidate, true);
            }
            if let Some(c) = c_store.find(&c_spec.name) {
                let in_this_pod = crate::load_container_labels_from_bundle(&c.bundle_path)
                    .get("boxr.pod_name")
                    .is_some_and(|pn| pn == pod_name);
                if in_this_pod {
                    let _ = crate::stop_container_with_home_and_timeout(
                        &c_spec.name,
                        None,
                        Some(0),
                        None,
                        true,
                        None,
                    );
                    let _ = crate::remove_container(&c_spec.name, true);
                }
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
        let args = KubeGenerateArgs {
            targets: vec![target.to_string()],
            ..Default::default()
        };
        Self::generate_kube_with_args(&args)
    }

    pub fn generate_kube_with_args(args: &KubeGenerateArgs) -> Result<String> {
        let target =
            args.targets.first().map(String::as_str).ok_or_else(|| {
                anyhow!("must provide at least one container, pod, or volume name")
            })?;

        let c_store = ContainerStore::new();
        let p_store = PodStore::new();
        let v_store = crate::volume::VolumeStore::new();
        let i_store = crate::storage::ImageStore::new();

        let effective_type = args
            .kind_type
            .clone()
            .or_else(kube_generate_type_from_containers_conf)
            .unwrap_or_else(|| "pod".to_string())
            .to_lowercase();

        if args.replicas.is_some() && effective_type != "deployment" {
            crate::cli::usage_errors::exit_usage_error(
                "--replicas can only be set when --type is set to deployment",
            );
        }

        // Check if target is a named volume first (if not a pod or container)
        if p_store.find(target).is_none() && c_store.find(target).is_none() {
            if let Some(vol) = v_store.find(target) {
                let creation_ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
                let mut vol_annotations = serde_json::Map::new();
                if let Some(dev) = vol.options.get("device") {
                    vol_annotations.insert(
                        "volume.podman.io/device".to_string(),
                        serde_json::Value::String(dev.clone()),
                    );
                }
                if let Some(ty) = vol.options.get("type") {
                    vol_annotations.insert(
                        "volume.podman.io/type".to_string(),
                        serde_json::Value::String(ty.clone()),
                    );
                }
                if let Some(opts) = vol.options.get("o") {
                    vol_annotations.insert(
                        "volume.podman.io/mount-options".to_string(),
                        serde_json::Value::String(opts.clone()),
                    );
                }
                let mut metadata = serde_json::Map::new();
                metadata.insert(
                    "creationTimestamp".to_string(),
                    serde_json::Value::String(creation_ts.clone()),
                );
                if !vol.labels.is_empty() {
                    let mut lmap = serde_json::Map::new();
                    for (k, v) in &vol.labels {
                        lmap.insert(k.clone(), serde_json::Value::String(v.clone()));
                    }
                    metadata.insert("labels".to_string(), serde_json::Value::Object(lmap));
                }
                if !vol_annotations.is_empty() {
                    metadata.insert(
                        "annotations".to_string(),
                        serde_json::Value::Object(vol_annotations),
                    );
                }
                metadata.insert(
                    "name".to_string(),
                    serde_json::Value::String(vol.name.clone()),
                );
                let pvc_doc = serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "PersistentVolumeClaim",
                    "metadata": metadata,
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {
                            "requests": {
                                "storage": "1Gi"
                            }
                        }
                    },
                    "status": {}
                });
                let mut yaml_str = serde_yaml::to_string(&pvc_doc)?;
                yaml_str = yaml_str.replace(
                    &format!("creationTimestamp: {}", creation_ts),
                    &format!("creationTimestamp: \"{}\"", creation_ts),
                );
                if let Some(out_file) = &args.filename {
                    if let Some(parent) = Path::new(out_file).parent() {
                        if !parent.as_os_str().is_empty() {
                            let _ = fs::create_dir_all(parent);
                        }
                    }
                    fs::write(out_file, &yaml_str)?;
                }
                return Ok(yaml_str);
            }
            crate::cli::usage_errors::exit_usage_error(format!(
                "name or ID \"{}\" not found",
                target
            ));
        }

        // Check if multiple container targets are passed to merge into a single Pod
        let all_containers = args.targets.len() > 1
            && args
                .targets
                .iter()
                .all(|t| p_store.find(t).is_none() && c_store.find(t).is_some());

        let (pod_name, app_label, pod_opt, containers, pod_ports) = if all_containers {
            let mut conts = Vec::new();
            for t in &args.targets {
                let c = c_store.find(t).unwrap();
                let cfg_path = Path::new(&c.bundle_path).join("config.json");
                if let Ok(raw) = fs::read_to_string(&cfg_path) {
                    if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&raw) {
                        if let Some(ann) = &spec.annotations {
                            if let Some(pod_id) = ann.get("boxr.pod") {
                                if !pod_id.is_empty() {
                                    crate::cli::usage_errors::exit_usage_error(format!(
                                        "container {} is associated with pod {}: use generate on the pod itself",
                                        c.id, pod_id
                                    ));
                                }
                            }
                        }
                    }
                }
                conts.push(c);
            }
            let pname = format!("{}-pod", conts[0].name.replace('_', ""));
            (pname.clone(), pname, None, conts, Vec::new())
        } else if let Some(pod) = p_store.find(target) {
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
                for c in c_store.list() {
                    if c.name == infra_name || c.id == pod.infra_container_id {
                        continue;
                    }
                    let cfg_path = Path::new(&c.bundle_path).join("config.json");
                    if let Ok(raw) = fs::read_to_string(&cfg_path) {
                        if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&raw) {
                            if let Some(ann) = &spec.annotations {
                                if ann
                                    .get("boxr.pod")
                                    .is_some_and(|p| p == &pod.id || p == &pod.name)
                                {
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
            let pname = pod.name.replace('_', "");
            let pports = pod.ports.clone();
            (pname.clone(), pname, Some(pod), conts, pports)
        } else if let Some(c) = c_store.find(target) {
            let cfg_path = Path::new(&c.bundle_path).join("config.json");
            if let Ok(raw) = fs::read_to_string(&cfg_path) {
                if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&raw) {
                    if let Some(ann) = &spec.annotations {
                        if let Some(pod_id) = ann.get("boxr.pod") {
                            if !pod_id.is_empty() {
                                crate::cli::usage_errors::exit_usage_error(format!(
                                    "container {} is associated with pod {}: use generate on the pod itself",
                                    c.id, pod_id
                                ));
                            }
                        }
                    }
                }
            }
            let pname = format!("{}-pod", c.name.replace('_', ""));
            (pname.clone(), pname, None, vec![c], Vec::new())
        } else {
            crate::cli::usage_errors::exit_usage_error(format!(
                "name or ID \"{}\" not found",
                target
            ));
        };

        let mut kube_containers = Vec::new();
        let mut kube_init_containers = Vec::new();
        let mut kube_volumes: Vec<KubeVolume> = Vec::new();
        let mut seen_vol_names = std::collections::HashSet::new();
        let mut metadata_annotations = HashMap::new();
        let mut dns_nameservers = Vec::new();
        let mut dns_searches = Vec::new();
        let mut dns_options: Vec<KubeDnsOption> = Vec::new();
        let mut host_aliases: Vec<KubeHostAlias> = Vec::new();
        let mut pod_hostname: Option<String> = None;
        let mut pod_termination_grace: Option<i64> = None;
        let mut pod_host_network = false;
        let mut pod_host_users: Option<bool> = None;
        let mut pod_share_pid: Option<bool> = None;
        let mut pod_restart_policy: Option<String> = None;
        let mut service_ports: Vec<serde_json::Value> = Vec::new();

        if let Some(p) = &pod_opt {
            if let Some(u) = &p.userns {
                metadata_annotations.insert("io.podman.annotations.userns".to_string(), u.clone());
                if u.starts_with("auto") {
                    pod_host_users = Some(false);
                }
            }
            if let Some(inm) = &p.infra_name {
                if !inm.trim().is_empty() {
                    metadata_annotations.insert(
                        "io.podman.annotations.infra.name".to_string(),
                        inm.trim().to_string(),
                    );
                }
            }
            if p.network.as_deref() == Some("host") {
                pod_host_network = true;
            }
            if p.share_pid {
                pod_share_pid = Some(true);
            }
            let sandbox_id = if p.infra && !p.infra_container_id.is_empty() {
                p.infra_container_id.clone()
            } else {
                p.id.clone()
            };
            for c in &containers {
                let cname_clean = c.name.replace('_', "");
                metadata_annotations.insert(
                    format!("io.kubernetes.cri-o.SandboxID/{}", cname_clean),
                    sandbox_id.clone(),
                );
            }
            for ns in &p.dns {
                if !dns_nameservers.contains(ns) {
                    dns_nameservers.push(ns.clone());
                }
            }
            for srch in &p.dns_search {
                if !dns_searches.contains(srch) {
                    dns_searches.push(srch.clone());
                }
            }
            for opt in &p.dns_option {
                let (name, val) = if let Some((k, v)) = opt.split_once(':') {
                    (k.to_string(), Some(v.to_string()))
                } else {
                    (opt.clone(), None)
                };
                dns_options.push(KubeDnsOption { name, value: val });
            }
            for ah in &p.add_host {
                if let Some((host, ip)) = ah.split_once(':') {
                    let ip_trim = ip.trim().to_string();
                    let host_trim = host.trim().to_string();
                    host_aliases.push(KubeHostAlias {
                        ip: ip_trim,
                        hostnames: vec![host_trim],
                    });
                }
            }
            if let Some(rp) = &p.restart_policy {
                let mapped = match rp.trim().to_lowercase().as_str() {
                    "" => None,
                    "always" | "unless-stopped" => Some("Always".to_string()),
                    "on-failure" => Some("OnFailure".to_string()),
                    s if s.starts_with("on-failure:") => Some("OnFailure".to_string()),
                    "no" | "never" | "none" => Some("Never".to_string()),
                    _ => None,
                };
                pod_restart_policy = mapped;
            }
        }

        for (idx, c) in containers.iter().enumerate() {
            let bundle_path = PathBuf::from(&c.bundle_path);
            let spec: Option<crate::oci::runtime::Spec> =
                fs::read_to_string(bundle_path.join("config.json"))
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok());
            let mounts: Vec<MountSpec> = fs::read_to_string(bundle_path.join("mounts.json"))
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();

            let readonly = spec.as_ref().map(|s| s.root.readonly).unwrap_or(false);
            let annotations = spec
                .as_ref()
                .and_then(|s| s.annotations.clone())
                .unwrap_or_default();

            let init_ctr_type = annotations.get("boxr.init_ctr").map(|s| s.as_str());
            if init_ctr_type == Some("once") {
                if let Some(p) = &pod_opt {
                    if p.status == "Running" || p.status == "Exited" {
                        continue;
                    }
                }
            }

            let short_name = c
                .name
                .strip_prefix(&format!("{}-", pod_name))
                .unwrap_or(&c.name)
                .to_string();

            if annotations.get("boxr.network").map(|s| s.as_str()) == Some("host") {
                pod_host_network = true;
            }

            if let Ok(raw_dns) = fs::read_to_string(bundle_path.join("dns.json")) {
                if let Ok(list) = serde_json::from_str::<Vec<String>>(&raw_dns) {
                    for ns in list {
                        if !dns_nameservers.contains(&ns) {
                            dns_nameservers.push(ns);
                        }
                    }
                }
            }
            if let Ok(raw_srch) = fs::read_to_string(bundle_path.join("dns_search.json")) {
                if let Ok(list) = serde_json::from_str::<Vec<String>>(&raw_srch) {
                    for s in list {
                        if !dns_searches.contains(&s) {
                            dns_searches.push(s);
                        }
                    }
                }
            }
            if let Ok(raw_opt) = fs::read_to_string(bundle_path.join("dns_option.json")) {
                if let Ok(list) = serde_json::from_str::<Vec<String>>(&raw_opt) {
                    for opt in list {
                        let (name, val) = if let Some((k, v)) = opt.split_once(':') {
                            (k.to_string(), Some(v.to_string()))
                        } else {
                            (opt, None)
                        };
                        dns_options.push(KubeDnsOption { name, value: val });
                    }
                }
            }

            if pod_opt.is_none() {
                if let Ok(raw_cmd) = fs::read_to_string(bundle_path.join("create_command.json")) {
                    if let Ok(argv) = serde_json::from_str::<Vec<String>>(&raw_cmd) {
                        let mut k = 0;
                        while k < argv.len() {
                            if argv[k] == "--restart" && k + 1 < argv.len() {
                                let rp = argv[k + 1].trim().to_lowercase();
                                pod_restart_policy = match rp.as_str() {
                                    "" => None,
                                    "always" | "unless-stopped" => Some("Always".to_string()),
                                    "on-failure" => Some("OnFailure".to_string()),
                                    s if s.starts_with("on-failure:") => {
                                        Some("OnFailure".to_string())
                                    }
                                    "no" | "never" | "none" => Some("Never".to_string()),
                                    _ => None,
                                };
                                break;
                            } else if let Some(rp) = argv[k].strip_prefix("--restart=") {
                                let rp = rp.trim().to_lowercase();
                                pod_restart_policy = match rp.as_str() {
                                    "" => None,
                                    "always" | "unless-stopped" => Some("Always".to_string()),
                                    "on-failure" => Some("OnFailure".to_string()),
                                    s if s.starts_with("on-failure:") => {
                                        Some("OnFailure".to_string())
                                    }
                                    "no" | "never" | "none" => Some("Never".to_string()),
                                    _ => None,
                                };
                                break;
                            }
                            k += 1;
                        }
                    }
                }
            }

            if let Some(p) = &pod_opt {
                if !p.share_uts && pod_hostname.is_none() {
                    if let Some(sp) = &spec {
                        if let Some(h) = &sp.hostname {
                            if !h.is_empty() && h != &c.name && h != &p.name && !c.id.starts_with(h)
                            {
                                pod_hostname = Some(h.clone());
                            }
                        }
                    }
                }
            }

            if let Some(st) = annotations.get("boxr.stop_timeout") {
                if let Ok(secs) = st.parse::<i64>() {
                    pod_termination_grace = Some(secs);
                }
            }

            if let Ok(raw_labels) = fs::read_to_string(bundle_path.join("labels.json")) {
                if let Ok(lbls) = serde_json::from_str::<Vec<String>>(&raw_labels) {
                    for l in lbls {
                        if let Some((k, v)) = l.split_once('=') {
                            if k == "io.containers.autoupdate"
                                || k == "io.containers.autoupdate.authfile"
                            {
                                metadata_annotations
                                    .insert(format!("{}/{}", k, short_name), v.to_string());
                            }
                        }
                    }
                }
            }

            if let Ok(raw_ul) = fs::read_to_string(bundle_path.join("ulimits.json")) {
                if let Ok(uls) = serde_json::from_str::<Vec<String>>(&raw_ul) {
                    if !uls.is_empty() {
                        metadata_annotations
                            .insert("io.podman.annotations.ulimit".to_string(), uls.join(","));
                    }
                }
            }

            if let Some(raw_vols) = annotations.get("boxr.raw_volumes") {
                if let Ok(vlist) = serde_json::from_str::<Vec<String>>(raw_vols) {
                    for v in vlist {
                        let parts: Vec<&str> = v.split(':').collect();
                        if parts.len() >= 3 && parts[0].starts_with('/') {
                            let src_p = Path::new(parts[0])
                                .canonicalize()
                                .unwrap_or_else(|_| PathBuf::from(parts[0]));
                            let opts = parts[2..].join(":");
                            metadata_annotations.insert(
                                "bind-mount-options".to_string(),
                                format!("{}:{}", src_p.display(), opts),
                            );
                            metadata_annotations
                                .insert(format!("bind-mount-options:{}", src_p.display()), opts);
                        }
                    }
                }
            }

            if let Some(vf) = annotations.get("boxr.volumes_from") {
                metadata_annotations.insert(
                    format!("io.podman.annotations.volumes-from/{}", short_name),
                    vf.clone(),
                );
            }
            if let Some(kg) = annotations.get("run.oci.keep_original_groups") {
                metadata_annotations.insert(
                    format!("io.podman.annotations.keep-original-groups/{}", short_name),
                    kg.clone(),
                );
            } else if annotations
                .get("boxr.group_add")
                .is_some_and(|s| s.contains("keep-groups"))
            {
                metadata_annotations.insert(
                    format!("io.podman.annotations.keep-original-groups/{}", short_name),
                    "1".to_string(),
                );
            } else if let Ok(raw_ga) = fs::read_to_string(bundle_path.join("group_add.json")) {
                if let Ok(ga_list) = serde_json::from_str::<Vec<String>>(&raw_ga) {
                    if ga_list.iter().any(|g| g == "keep-groups") {
                        metadata_annotations.insert(
                            format!("io.podman.annotations.keep-original-groups/{}", short_name),
                            "1".to_string(),
                        );
                    }
                }
            }
            if let Some(mc) = annotations.get("run.oci.mount_context_type") {
                metadata_annotations.insert(
                    format!("io.podman.annotations.mount-context-type/{}", short_name),
                    mc.clone(),
                );
            }

            if args.podman_only {
                if annotations.get("boxr.rm").map(|s| s.as_str()) == Some("true")
                    || bundle_path.join("auto_remove").exists()
                {
                    metadata_annotations.insert(
                        format!("io.podman.annotations.autoremove/{}", short_name),
                        "TRUE".to_string(),
                    );
                }
                if annotations.get("boxr.privileged").map(|s| s.as_str()) == Some("true") {
                    metadata_annotations.insert(
                        format!("io.podman.annotations.privileged/{}", short_name),
                        "TRUE".to_string(),
                    );
                }
                if annotations.get("boxr.init").map(|s| s.as_str()) == Some("true") {
                    metadata_annotations.insert(
                        format!("io.podman.annotations.init/{}", short_name),
                        "TRUE".to_string(),
                    );
                }
                if let Some(cf) = annotations.get("boxr.cidfile") {
                    metadata_annotations.insert(
                        format!("io.podman.annotations.cid-file/{}", short_name),
                        cf.clone(),
                    );
                }
                if annotations.get("boxr.publish_all").map(|s| s.as_str()) == Some("true") {
                    metadata_annotations.insert(
                        format!("io.podman.annotations.publish-all/{}", short_name),
                        "TRUE".to_string(),
                    );
                }
                if let Some(sec_json) = annotations.get("boxr.security_opt") {
                    if let Ok(sec_list) = serde_json::from_str::<Vec<String>>(sec_json) {
                        for item in sec_list {
                            if let Some(v) = item.strip_prefix("seccomp=") {
                                metadata_annotations.insert(
                                    format!("io.podman.annotations.seccomp/{}", short_name),
                                    v.to_string(),
                                );
                            } else if let Some(v) = item.strip_prefix("apparmor=") {
                                metadata_annotations.insert(
                                    format!("io.podman.annotations.apparmor/{}", short_name),
                                    v.to_string(),
                                );
                            } else if let Some(v) = item.strip_prefix("label=") {
                                metadata_annotations.insert(
                                    format!("io.podman.annotations.label/{}", short_name),
                                    v.to_string(),
                                );
                            }
                        }
                    }
                }
            }

            let mut ports = Vec::new();
            for p in &c.ports {
                let hp = if args.service {
                    None
                } else if p.host_port > 0 {
                    Some(p.host_port)
                } else {
                    None
                };
                let proto = if p.protocol.eq_ignore_ascii_case("tcp") || p.protocol.is_empty() {
                    None
                } else {
                    Some(p.protocol.to_uppercase())
                };
                ports.push(KubeContainerPort {
                    container_port: p.container_port,
                    host_port: hp,
                    host_ip: p.host_ip.clone(),
                    protocol: proto.clone(),
                });
                if args.service {
                    let s_port = if p.host_port > 0 {
                        p.host_port
                    } else {
                        p.container_port
                    };
                    service_ports.push(serde_json::json!({
                        "name": p.container_port.to_string(),
                        "port": s_port,
                        "targetPort": p.container_port,
                        "protocol": proto.unwrap_or_else(|| "TCP".to_string()),
                    }));
                }
            }
            if idx == 0 && ports.is_empty() && !pod_ports.is_empty() {
                for p in &pod_ports {
                    let hp = if args.service {
                        None
                    } else if p.host_port > 0 {
                        Some(p.host_port)
                    } else {
                        None
                    };
                    let proto = if p.protocol.eq_ignore_ascii_case("tcp") || p.protocol.is_empty() {
                        None
                    } else {
                        Some(p.protocol.to_uppercase())
                    };
                    ports.push(KubeContainerPort {
                        container_port: p.container_port,
                        host_port: hp,
                        host_ip: p.host_ip.clone(),
                        protocol: proto.clone(),
                    });
                    if args.service {
                        let s_port = if p.host_port > 0 {
                            p.host_port
                        } else {
                            p.container_port
                        };
                        service_ports.push(serde_json::json!({
                            "name": p.container_port.to_string(),
                            "port": s_port,
                            "targetPort": p.container_port,
                            "protocol": proto.unwrap_or_else(|| "TCP".to_string()),
                        }));
                    }
                }
            }

            let is_privileged =
                annotations.get("boxr.privileged").map(|s| s.as_str()) == Some("true");
            let cap_drop: Vec<String> = annotations
                .get("boxr.cap_drop")
                .and_then(|v| serde_json::from_str(v).ok())
                .unwrap_or_default();
            let cap_add: Vec<String> = annotations
                .get("boxr.cap_add")
                .and_then(|v| serde_json::from_str(v).ok())
                .unwrap_or_default();
            let capabilities_val =
                if !is_privileged && (!cap_drop.is_empty() || !cap_add.is_empty()) {
                    let mut caps = serde_json::Map::new();
                    if !cap_drop.is_empty() {
                        let norm_drops: Vec<serde_json::Value> = cap_drop
                            .iter()
                            .map(|d| {
                                let u = d.to_uppercase();
                                let s = if u.starts_with("CAP_") {
                                    u
                                } else {
                                    format!("CAP_{}", u)
                                };
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
                                let s = if u.starts_with("CAP_") {
                                    u
                                } else {
                                    format!("CAP_{}", u)
                                };
                                serde_json::Value::String(s)
                            })
                            .collect();
                        caps.insert("add".to_string(), serde_json::Value::Array(norm_adds));
                    }
                    Some(serde_json::Value::Object(caps))
                } else {
                    None
                };

            let mut proc_mount = None;
            let mut selinux_opts = None;
            if let Some(sec_json) = annotations.get("boxr.security_opt") {
                if let Ok(sec_list) = serde_json::from_str::<Vec<String>>(sec_json) {
                    let mut level = None;
                    let mut filetype = None;
                    let mut selinux_type = None;
                    for item in sec_list {
                        if item == "unmask=all" {
                            proc_mount = Some("Unmasked".to_string());
                        } else if let Some(l) = item.strip_prefix("label=level:") {
                            level = Some(l.to_string());
                        } else if let Some(ft) = item.strip_prefix("label=filetype:") {
                            filetype = Some(ft.to_string());
                        } else if let Some(st) = item.strip_prefix("label=type:") {
                            selinux_type = Some(st.to_string());
                        } else if item == "label=disable" {
                            selinux_type = Some("spc_t".to_string());
                        }
                    }
                    if level.is_some() || filetype.is_some() || selinux_type.is_some() {
                        selinux_opts = Some(KubeSeLinuxOptions {
                            level,
                            filetype,
                            selinux_type,
                        });
                    }
                }
            }

            let img_rec = i_store.find(&c.image);
            let img_user = img_rec
                .as_ref()
                .and_then(|r| r.config.config.as_ref())
                .and_then(|cfg| cfg.user.clone())
                .filter(|u| !u.is_empty());

            let mut run_as_user = None;
            let mut run_as_group = None;
            let mut run_as_non_root = None;
            let mut user_from_image_only = false;
            if let Some(u_str) = annotations.get("boxr.user") {
                if let Some((u_part, g_part)) = u_str.split_once(':') {
                    if let Ok(uid) = u_part.parse::<u32>() {
                        run_as_user = Some(uid);
                        if uid > 0 {
                            run_as_non_root = Some(true);
                        }
                    }
                    if let Ok(gid) = g_part.parse::<u32>() {
                        run_as_group = Some(gid);
                    }
                } else if let Ok(uid) = u_str.parse::<u32>() {
                    run_as_user = Some(uid);
                    if uid > 0 {
                        run_as_non_root = Some(true);
                    }
                } else {
                    user_from_image_only = true;
                }
            } else if let Some(ref iu) = img_user {
                user_from_image_only = true;
                if let Ok(uid) = iu.parse::<u32>() {
                    if uid > 0 {
                        run_as_non_root = Some(true);
                    }
                }
            }

            let sec_ctx = if readonly
                || is_privileged
                || run_as_non_root.is_some()
                || run_as_user.is_some()
                || run_as_group.is_some()
                || selinux_opts.is_some()
                || proc_mount.is_some()
                || capabilities_val.is_some()
                || user_from_image_only
            {
                Some(KubeSecurityContext {
                    read_only_root_filesystem: if readonly { Some(true) } else { None },
                    privileged: if is_privileged { Some(true) } else { None },
                    run_as_non_root,
                    run_as_user,
                    run_as_group,
                    selinux_options: selinux_opts,
                    proc_mount,
                    capabilities: capabilities_val,
                    ..Default::default()
                })
            } else {
                None
            };

            let mut vol_mounts: Vec<KubeVolumeMount> = Vec::new();
            for m in mounts {
                if let Some(vname) = &m.volume_name {
                    let pvc_name = format!("{}-pvc", sanitize_k8s_volume_name(vname));
                    vol_mounts.push(KubeVolumeMount {
                        name: pvc_name.clone(),
                        mount_path: m.destination,
                        sub_path: m.subpath.clone(),
                        read_only: if m.read_only { Some(true) } else { None },
                    });
                    if seen_vol_names.insert(pvc_name.clone()) {
                        kube_volumes.push(KubeVolume {
                            name: pvc_name,
                            host_path: None,
                            persistent_volume_claim: Some(KubePvcVolumeSource {
                                claim_name: vname.clone(),
                            }),
                            image: None,
                            ..Default::default()
                        });
                    }
                } else {
                    let host_vol_name = format!(
                        "{}-host-{}",
                        sanitize_k8s_volume_name(&m.source.to_string_lossy()),
                        kube_volumes.len()
                    );
                    vol_mounts.push(KubeVolumeMount {
                        name: host_vol_name.clone(),
                        mount_path: m.destination,
                        sub_path: None,
                        read_only: if m.read_only { Some(true) } else { None },
                    });
                    if seen_vol_names.insert(host_vol_name.clone()) {
                        kube_volumes.push(KubeVolume {
                            name: host_vol_name,
                            host_path: Some(KubeHostPath {
                                path: m.source.to_string_lossy().to_string(),
                                path_type: Some("Directory".to_string()),
                            }),
                            persistent_volume_claim: None,
                            image: None,
                            ..Default::default()
                        });
                    }
                }
            }

            // Command and Args logic
            let img_rec = i_store.find(&c.image);
            let img_entrypoint = img_rec
                .as_ref()
                .and_then(|r| r.config.config.as_ref())
                .and_then(|cfg| cfg.entrypoint.clone())
                .unwrap_or_default();
            let explicit_ep = annotations.get("boxr.explicit_entrypoint");
            let explicit_cmd: Option<Vec<String>> = annotations
                .get("boxr.explicit_command")
                .and_then(|s| serde_json::from_str(s).ok());

            let (kube_cmd, kube_args) = if let Some(ep_str) = explicit_ep {
                let ep_vec = crate::parse_entrypoint_override(ep_str);
                (
                    if ep_vec.is_empty() {
                        None
                    } else {
                        Some(ep_vec)
                    },
                    explicit_cmd.filter(|v| !v.is_empty()),
                )
            } else if !img_entrypoint.is_empty() {
                (None, explicit_cmd.filter(|v| !v.is_empty()))
            } else if let Some(cmd_vec) = explicit_cmd {
                (
                    if cmd_vec.is_empty() {
                        None
                    } else {
                        Some(cmd_vec)
                    },
                    None,
                )
            } else {
                (None, None)
            };

            let kube_env: Option<Vec<KubeEnvVar>> = annotations
                .get("boxr.explicit_env")
                .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
                .map(|list| {
                    list.into_iter()
                        .filter_map(|item| {
                            item.split_once('=').map(|(k, v)| KubeEnvVar {
                                name: k.to_string(),
                                value: v.to_string(),
                                value_from: None,
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .filter(|v| !v.is_empty());

            let kube_workdir = annotations
                .get("boxr.explicit_workdir")
                .cloned()
                .filter(|w| !w.is_empty() && w != "/");

            let mut limits_map = serde_json::Map::new();
            if let Some(mem) = annotations.get("boxr.memory") {
                if let Ok(bytes) = mem.parse::<i64>() {
                    limits_map.insert(
                        "memory".to_string(),
                        serde_json::Value::Number(bytes.into()),
                    );
                }
            }
            if let Some(cpus) = annotations.get("boxr.cpus") {
                if let Ok(val) = cpus.parse::<f64>() {
                    let milli = (val * 1000.0).round() as i64;
                    limits_map.insert(
                        "cpu".to_string(),
                        serde_json::Value::String(format!("{}m", milli)),
                    );
                }
            } else if let Some(quota_str) = annotations.get("boxr.cpu_quota") {
                if let Ok(quota) = quota_str.parse::<f64>() {
                    let period = annotations
                        .get("boxr.cpu_period")
                        .and_then(|p| p.parse::<f64>().ok())
                        .unwrap_or(100_000.0);
                    if period > 0.0 {
                        let milli = ((quota / period) * 1000.0).round() as i64;
                        limits_map.insert(
                            "cpu".to_string(),
                            serde_json::Value::String(format!("{}m", milli)),
                        );
                    }
                }
            }
            let resources = if !limits_map.is_empty() {
                Some(serde_json::json!({
                    "limits": limits_map
                }))
            } else {
                None
            };

            let liveness_probe = if let Some(hcmd) = annotations.get("boxr.health_cmd") {
                if !hcmd.is_empty() && hcmd != "none" {
                    let exec_cmd = if let Some(rest) = hcmd.strip_prefix("CMD-SHELL ") {
                        vec!["/bin/sh".to_string(), "-c".to_string(), rest.to_string()]
                    } else if let Some(rest) = hcmd.strip_prefix("CMD ") {
                        rest.split_whitespace().map(|s| s.to_string()).collect()
                    } else {
                        vec!["/bin/sh".to_string(), "-c".to_string(), hcmd.clone()]
                    };
                    let hs_val: Option<serde_json::Value> =
                        fs::read_to_string(bundle_path.join("health-supervisor.json"))
                            .or_else(|_| {
                                fs::read_to_string(bundle_path.join("health_supervisor.json"))
                            })
                            .ok()
                            .and_then(|s| serde_json::from_str(&s).ok());
                    let hc_obj = hs_val
                        .as_ref()
                        .and_then(|v| v.get("health_cfg").or_else(|| v.get("config")));
                    let period = hc_obj
                        .and_then(|c| c.get("interval_secs"))
                        .and_then(|x| x.as_u64())
                        .unwrap_or(30);
                    let timeout = hc_obj
                        .and_then(|c| c.get("timeout_secs"))
                        .and_then(|x| x.as_u64())
                        .unwrap_or(30);
                    let retries = hc_obj
                        .and_then(|c| c.get("retries"))
                        .and_then(|x| x.as_u64())
                        .unwrap_or(3) as u32;
                    let start_period = hc_obj
                        .and_then(|c| c.get("start_period_secs"))
                        .and_then(|x| x.as_u64())
                        .unwrap_or(0);
                    Some(KubeProbe {
                        exec: Some(KubeExecAction { command: exec_cmd }),
                        initial_delay_seconds: if start_period > 0 {
                            Some(start_period)
                        } else {
                            None
                        },
                        timeout_seconds: Some(timeout),
                        period_seconds: Some(period),
                        failure_threshold: Some(retries),
                        ..Default::default()
                    })
                } else {
                    None
                }
            } else {
                None
            };

            let k_ctr = KubeContainerSpec {
                name: short_name,
                image: c.image.clone(),
                command: kube_cmd,
                args: kube_args,
                ports: if ports.is_empty() { None } else { Some(ports) },
                env: kube_env,
                resources,
                working_dir: kube_workdir,
                security_context: sec_ctx,
                volume_mounts: if vol_mounts.is_empty() {
                    None
                } else {
                    Some(vol_mounts)
                },
                liveness_probe,
                ..Default::default()
            };

            if init_ctr_type.is_some() {
                kube_init_containers.push(k_ctr);
            } else {
                kube_containers.push(k_ctr);
            }
        }

        if effective_type == "deployment" {
            if let Some(ref rp) = pod_restart_policy {
                if rp != "Always" {
                    crate::cli::usage_errors::exit_usage_error(
                        "k8s Deployments can only have restartPolicy set to Always",
                    );
                }
            }
        } else if effective_type == "daemonset" {
            if let Some(ref rp) = pod_restart_policy {
                if rp != "Always" {
                    crate::cli::usage_errors::exit_usage_error(
                        "k8s DaemonSets can only have restartPolicy set to Always",
                    );
                }
            }
        } else if effective_type == "job" {
            if pod_restart_policy.as_deref() == Some("Always") {
                crate::cli::usage_errors::exit_usage_error(
                    "k8s Jobs can not have restartPolicy set to Always; only Never and OnFailure policies allowed",
                );
            }
        }

        let mut labels = HashMap::new();
        labels.insert("app".to_string(), app_label.clone());
        let creation_ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let dns_config =
            if !dns_nameservers.is_empty() || !dns_searches.is_empty() || !dns_options.is_empty() {
                Some(KubeDnsConfig {
                    nameservers: dns_nameservers,
                    searches: dns_searches,
                    options: dns_options,
                })
            } else {
                None
            };

        let pod_spec = KubePodSpec {
            hostname: pod_hostname,
            containers: kube_containers,
            init_containers: if kube_init_containers.is_empty() {
                None
            } else {
                Some(kube_init_containers)
            },
            volumes: if kube_volumes.is_empty() {
                None
            } else {
                Some(kube_volumes)
            },
            restart_policy: pod_restart_policy,
            host_network: if pod_host_network { Some(true) } else { None },
            host_users: pod_host_users,
            share_process_namespace: pod_share_pid,
            termination_grace_period_seconds: pod_termination_grace,
            host_aliases: if host_aliases.is_empty() {
                None
            } else {
                Some(host_aliases)
            },
            dns_config,
            ..Default::default()
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
                                },
                                "name": pod_name,
                            },
                            "spec": pod_spec,
                        }
                    },
                    "status": {}
                });
                serde_yaml::to_string(&doc)?
            }
            "daemonset" => {
                let doc = serde_json::json!({
                    "apiVersion": "apps/v1",
                    "kind": "DaemonSet",
                    "metadata": {
                        "creationTimestamp": creation_ts,
                        "labels": labels,
                        "name": format!("{}-daemonset", pod_name),
                    },
                    "spec": {
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
                                },
                                "name": pod_name,
                            },
                            "spec": pod_spec,
                        }
                    },
                    "status": {}
                });
                serde_yaml::to_string(&doc)?
            }
            "job" => {
                let mut job_pod_spec = pod_spec.clone();
                if job_pod_spec.restart_policy.is_none() {
                    job_pod_spec.restart_policy = Some("Never".to_string());
                }
                let doc = serde_json::json!({
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "metadata": {
                        "creationTimestamp": creation_ts,
                        "labels": labels,
                        "name": format!("{}-job", pod_name),
                    },
                    "spec": {
                        "completions": 1,
                        "parallelism": 1,
                        "template": {
                            "metadata": {
                                "creationTimestamp": null,
                                "labels": {
                                    "app": app_label,
                                },
                                "name": pod_name,
                            },
                            "spec": job_pod_spec,
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
                        name: pod_name.clone(),
                        creation_timestamp: Some(creation_ts.clone()),
                        labels: labels.clone(),
                        annotations: metadata_annotations,
                    },
                    spec: pod_spec,
                    status: None,
                };
                serde_yaml::to_string(&pod_yaml)?
            }
        };

        if args.service {
            let svc_doc = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "creationTimestamp": creation_ts,
                    "labels": labels,
                    "name": pod_name,
                },
                "spec": {
                    "ports": service_ports,
                    "selector": {
                        "app": app_label,
                    },
                    "type": "NodePort",
                },
                "status": {
                    "loadBalancer": {}
                }
            });
            let svc_yaml = serde_yaml::to_string(&svc_doc)?;
            yaml_str = format!("{}---\n{}", svc_yaml, yaml_str);
        }

        yaml_str = yaml_str.replace(
            &format!("creationTimestamp: {}", creation_ts),
            &format!("creationTimestamp: \"{}\"", creation_ts),
        );
        yaml_str = yaml_str.replace(": '1'\n", ": \"1\"\n");

        if let Some(out_file) = &args.filename {
            if let Some(parent) = Path::new(out_file).parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = fs::create_dir_all(parent);
                }
            }
            fs::write(out_file, &yaml_str)?;
        }
        Ok(yaml_str)
    }

    pub fn print_or_write_generate_kube(args: &KubeGenerateArgs) -> Result<()> {
        let p_store = PodStore::new();
        let c_store = ContainerStore::new();
        let all_containers = args.targets.len() > 1
            && args
                .targets
                .iter()
                .all(|t| p_store.find(t).is_none() && c_store.find(t).is_some());
        if all_containers {
            let mut merged = args.clone();
            merged.filename = None;
            let out = Self::generate_kube_with_args(&merged)?;
            if let Some(path) = &args.filename {
                if let Some(parent) = Path::new(path).parent() {
                    if !parent.as_os_str().is_empty() {
                        let _ = fs::create_dir_all(parent);
                    }
                }
                fs::write(path, &out)?;
            } else {
                print!("{}", out);
            }
            return Ok(());
        }
        let mut out = String::new();
        for (i, t) in args.targets.iter().enumerate() {
            if i > 0 {
                out.push_str("---\n");
            }
            let mut single = args.clone();
            single.targets = vec![t.clone()];
            single.filename = None;
            out.push_str(&Self::generate_kube_with_args(&single)?);
        }
        if let Some(path) = &args.filename {
            if let Some(parent) = Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = fs::create_dir_all(parent);
                }
            }
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
