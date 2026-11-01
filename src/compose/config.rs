use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposeFile {
    #[serde(default)]
    pub version: Option<String>,
    pub services: HashMap<String, ServiceConfig>,
    #[serde(default)]
    pub volumes: HashMap<String, Option<ComposeVolumeConfig>>,
    #[serde(default)]
    pub networks: HashMap<String, Option<ComposeNetworkConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComposeVolumeConfig {
    pub driver: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComposeIpamPool {
    pub subnet: Option<String>,
    pub gateway: Option<String>,
    pub ip_range: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComposeIpamConfig {
    pub driver: Option<String>,
    #[serde(default)]
    pub config: Vec<ComposeIpamPool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComposeNetworkConfig {
    pub driver: Option<String>,
    pub driver_opts: Option<HashMap<String, serde_yaml::Value>>,
    pub ipam: Option<ComposeIpamConfig>,
    pub internal: Option<bool>,
    pub attachable: Option<bool>,
    pub enable_ipv6: Option<bool>,
    pub labels: Option<LabelsConfig>,
}

impl ComposeNetworkConfig {
    pub fn driver_opts_map(&self) -> HashMap<String, String> {
        let mut out = HashMap::new();
        if let Some(opts) = &self.driver_opts {
            for (k, v) in opts {
                let s = match v {
                    serde_yaml::Value::String(s) => s.clone(),
                    serde_yaml::Value::Number(n) => n.to_string(),
                    serde_yaml::Value::Bool(b) => b.to_string(),
                    other => serde_yaml::to_string(other)
                        .unwrap_or_default()
                        .trim()
                        .to_string(),
                };
                out.insert(k.clone(), s);
            }
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceNetworkEndpointConfig {
    #[serde(default)]
    pub aliases: Vec<String>,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub mac_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceNetworksConfig {
    List(Vec<String>),
    Map(HashMap<String, Option<ServiceNetworkEndpointConfig>>),
}

impl ServiceNetworksConfig {
    pub fn network_names(&self) -> Vec<String> {
        match self {
            Self::List(v) => v.clone(),
            Self::Map(m) => {
                let mut names: Vec<String> = m.keys().cloned().collect();
                names.sort();
                names
            }
        }
    }

    pub fn endpoint_config(&self, net_name: &str) -> Option<&ServiceNetworkEndpointConfig> {
        match self {
            Self::List(_) => None,
            Self::Map(m) => m.get(net_name).and_then(|v| v.as_ref()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LabelsConfig {
    List(Vec<String>),
    Map(HashMap<String, serde_yaml::Value>),
}

impl LabelsConfig {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::List(l) => l.clone(),
            Self::Map(m) => m
                .iter()
                .map(|(k, v)| {
                    let s = match v {
                        serde_yaml::Value::String(s) => s.clone(),
                        serde_yaml::Value::Number(n) => n.to_string(),
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        other => serde_yaml::to_string(other)
                            .unwrap_or_default()
                            .trim()
                            .to_string(),
                    };
                    format!("{}={}", k, s)
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComposeHealthcheck {
    pub test: Option<CommandOrList>,
    #[serde(default)]
    pub disable: bool,
    pub interval: Option<String>,
    pub timeout: Option<String>,
    pub retries: Option<u32>,
    pub start_period: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComposeDeviceReservation {
    pub driver: Option<String>,
    #[serde(default)]
    pub device_ids: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComposeResourceSpec {
    pub cpus: Option<serde_yaml::Value>,
    pub memory: Option<String>,
    pub devices: Option<Vec<ComposeDeviceReservation>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComposeDeployResources {
    pub reservations: Option<ComposeResourceSpec>,
    pub limits: Option<ComposeResourceSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComposeDeploy {
    pub resources: Option<ComposeDeployResources>,
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
                serde_yaml::Value::Number(n) => n.to_string(),
                serde_yaml::Value::Bool(b) => b.to_string(),
                other => serde_yaml::to_string(&other)
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
            })
            .collect()
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BuildConfig {
    Path(String),
    Spec(ServiceBuildSpec),
}

impl BuildConfig {
    pub fn context_path(&self) -> String {
        match self {
            BuildConfig::Path(p) => p.clone(),
            BuildConfig::Spec(s) => s.context.clone().unwrap_or_else(|| ".".to_string()),
        }
    }

    pub fn dockerfile_name(&self) -> String {
        match self {
            BuildConfig::Path(_) => "Dockerfile".to_string(),
            BuildConfig::Spec(s) => s
                .dockerfile
                .clone()
                .unwrap_or_else(|| "Dockerfile".to_string()),
        }
    }

    pub fn build_args(&self) -> HashMap<String, String> {
        match self {
            BuildConfig::Path(_) => HashMap::new(),
            BuildConfig::Spec(s) => s.args.clone().unwrap_or_default(),
        }
    }

    pub fn target(&self) -> Option<String> {
        match self {
            BuildConfig::Path(_) => None,
            BuildConfig::Spec(s) => s.target.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceBuildSpec {
    pub context: Option<String>,
    pub dockerfile: Option<String>,
    pub args: Option<HashMap<String, String>>,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DependsOnConfig {
    List(Vec<String>),
    Map(HashMap<String, serde_yaml::Value>),
}

impl DependsOnConfig {
    pub fn dependency_names(&self) -> Vec<String> {
        match self {
            DependsOnConfig::List(names) => names.clone(),
            DependsOnConfig::Map(map) => map.keys().cloned().collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceConfig {
    pub image: Option<String>,
    pub build: Option<BuildConfig>,
    pub container_name: Option<String>,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub tty: Option<bool>,
    pub stdin_open: Option<bool>,
    pub stop_signal: Option<String>,
    pub security_opt: Option<Vec<String>>,
    pub labels: Option<LabelsConfig>,
    pub network_mode: Option<String>,
    pub healthcheck: Option<ComposeHealthcheck>,
    pub deploy: Option<ComposeDeploy>,
    pub devices: Option<Vec<String>>,
    pub env_file: Option<CommandOrList>,
    pub command: Option<CommandOrList>,
    pub entrypoint: Option<CommandOrList>,
    pub environment: Option<EnvironmentConfig>,
    #[serde(default, deserialize_with = "deserialize_opt_string_vec")]
    pub ports: Option<Vec<String>>,
    pub volumes: Option<Vec<String>>,
    pub depends_on: Option<DependsOnConfig>,
    pub networks: Option<ServiceNetworksConfig>,
    pub restart: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CommandOrList {
    String(String),
    List(Vec<String>),
}

impl CommandOrList {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            CommandOrList::String(s) => s.split_whitespace().map(|w| w.to_string()).collect(),
            CommandOrList::List(l) => l.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EnvironmentConfig {
    List(Vec<String>),
    Map(HashMap<String, String>),
}

impl EnvironmentConfig {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            EnvironmentConfig::List(l) => l.clone(),
            EnvironmentConfig::Map(m) => m.iter().map(|(k, v)| format!("{}={}", k, v)).collect(),
        }
    }
}
