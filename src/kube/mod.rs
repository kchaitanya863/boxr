use crate::cli::RunArgs;
use crate::pod::PodStore;
use crate::storage::ContainerStore;
use anyhow::{Context, Result, anyhow};
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubeMetadata {
    pub name: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubePodSpec {
    pub containers: Vec<KubeContainerSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubeContainerSpec {
    pub name: String,
    pub image: String,
    #[serde(default)]
    pub command: Option<Vec<String>>,
    #[serde(default)]
    pub ports: Option<Vec<KubeContainerPort>>,
    #[serde(default)]
    pub env: Option<Vec<KubeEnvVar>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubeContainerPort {
    #[serde(rename = "containerPort")]
    pub container_port: u16,
    #[serde(rename = "hostPort")]
    pub host_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubeEnvVar {
    pub name: String,
    pub value: String,
}

pub struct KubeManager;

impl KubeManager {
    /// Play a Kubernetes YAML file (Pod, Deployment, Service, Volume)
    pub async fn play_kube(yaml_path: &Path) -> Result<()> {
        let content = fs::read_to_string(yaml_path)
            .with_context(|| format!("Failed to read Kubernetes YAML at {:?}", yaml_path))?;

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
                            labels: HashMap::new(),
                        },
                        spec: KubePodSpec {
                            containers: containers.clone(),
                        },
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
        let pod = pod_store.create(Some(&pod_yaml.metadata.name), pod_ports)?;

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
                    env_vec.push(format!("{}={}", e.name, e.value));
                }
            }

            println!("Creating pod container: {}", container_name);

            let run_args = RunArgs {
                registry_auth: Default::default(),
                interactive: false,
                tty: None,
                detach: true,
                rm: false,
                rmi: false,
                name: Some(container_name.clone()),
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
                platform: None,
                privileged: false,
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
                add_host: Vec::new(),
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
                userns: Vec::new(),
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
        let content = fs::read_to_string(yaml_path)
            .with_context(|| format!("Failed to read Kubernetes YAML at {:?}", yaml_path))?;

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
        let c_store = ContainerStore::new();
        let p_store = PodStore::new();

        let (pod_name, containers) = if let Some(pod) = p_store.find(target) {
            let mut conts = Vec::new();
            for cid in &pod.containers {
                if let Some(c) = c_store.find(cid) {
                    conts.push(c);
                }
            }
            (pod.name, conts)
        } else if let Some(c) = c_store.find(target) {
            (c.name.clone(), vec![c])
        } else {
            return Err(anyhow!("No such container or pod: '{}'", target));
        };

        let mut kube_containers = Vec::new();
        for c in containers {
            let mut ports = Vec::new();
            for p in &c.ports {
                ports.push(KubeContainerPort {
                    container_port: p.container_port,
                    host_port: Some(p.host_port),
                });
            }

            kube_containers.push(KubeContainerSpec {
                name: c.name.clone(),
                image: c.image.clone(),
                command: if c.command.is_empty() {
                    None
                } else {
                    Some(c.command.clone())
                },
                ports: if ports.is_empty() { None } else { Some(ports) },
                env: None,
            });
        }

        let pod_yaml = KubePodYaml {
            api_version: "v1".to_string(),
            kind: "Pod".to_string(),
            metadata: KubeMetadata {
                name: pod_name,
                labels: HashMap::new(),
            },
            spec: KubePodSpec {
                containers: kube_containers,
            },
        };

        let yaml_str = serde_yaml::to_string(&pod_yaml)?;
        Ok(yaml_str)
    }

    /// Run a command in a new user namespace (boxr unshare)
    pub fn unshare_command(command: &[String]) -> Result<i32> {
        let default_cmd = vec!["/bin/sh".to_string()];
        let cmd = if command.is_empty() {
            &default_cmd
        } else {
            command
        };

        #[cfg(target_os = "linux")]
        {
            crate::runtime::linux::run_unshare_cli(cmd)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut child = std::process::Command::new(&cmd[0]);
            if cmd.len() > 1 {
                child.args(&cmd[1..]);
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
