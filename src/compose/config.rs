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
pub struct ComposeNetworkConfig {
    pub driver: Option<String>,
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
    pub env_file: Option<CommandOrList>,
    pub command: Option<CommandOrList>,
    pub entrypoint: Option<CommandOrList>,
    pub environment: Option<EnvironmentConfig>,
    pub ports: Option<Vec<String>>,
    pub volumes: Option<Vec<String>>,
    pub depends_on: Option<DependsOnConfig>,
    pub networks: Option<Vec<String>>,
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
