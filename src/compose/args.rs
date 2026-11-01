use super::ComposeProject;
use super::config::*;
use crate::cli::RunArgs;
use crate::network::NetworkStore;
use anyhow::Result;
use std::fs;
use std::path::Path;

pub(crate) fn resolve_cdi_device_mounts(device_id: &str) -> Vec<String> {
    let mut mounts = Vec::new();
    let Some((kind, dev_name)) = device_id.split_once('=') else {
        return mounts;
    };
    for dir in crate::storage::effective_cdi_spec_dirs() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Ok(raw) = fs::read_to_string(&path) else {
                continue;
            };
            let val: serde_json::Value = if let Ok(v) = serde_json::from_str(&raw) {
                v
            } else if let Ok(v) = serde_yaml::from_str(&raw) {
                v
            } else {
                continue;
            };
            if val.get("kind").and_then(|k| k.as_str()) != Some(kind) {
                continue;
            }
            if let Some(devs) = val.get("devices").and_then(|d| d.as_array()) {
                for dev in devs {
                    if dev.get("name").and_then(|n| n.as_str()) == Some(dev_name) {
                        if let Some(m_arr) = dev
                            .get("containerEdits")
                            .and_then(|ce| ce.get("mounts"))
                            .and_then(|m| m.as_array())
                        {
                            for m in m_arr {
                                let hp = m.get("hostPath").and_then(|s| s.as_str()).unwrap_or("");
                                let cp =
                                    m.get("containerPath").and_then(|s| s.as_str()).unwrap_or("");
                                if !hp.is_empty() && !cp.is_empty() {
                                    mounts.push(format!("{}:{}", hp, cp));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    mounts
}

impl ComposeProject {
    pub fn build_service_run_args(
        &self,
        svc_name: &str,
        svc: &ServiceConfig,
        container_name: &str,
        image_name: &str,
        detach: bool,
    ) -> Result<RunArgs> {
        let root_dir = self.compose_file_path.parent().unwrap_or(Path::new("."));
        let mut env_vec = Vec::new();
        if let Some(ef) = &svc.env_file {
            for path_str in ef.to_vec() {
                let p = root_dir.join(&path_str);
                if let Ok(content) = fs::read_to_string(&p) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            env_vec.push(trimmed.to_string());
                        }
                    }
                }
            }
        }
        if let Some(env_entries) = &svc.environment {
            env_vec.extend(env_entries.to_vec());
        }
        let cmd_vec = svc.command.as_ref().map(|c| c.to_vec()).unwrap_or_default();
        let port_vec = svc.ports.clone().unwrap_or_default();
        let mut vol_vec = Vec::new();
        if let Some(vols) = &svc.volumes {
            for v in vols {
                if let Some((src, dest)) = v.split_once(':') {
                    if !src.starts_with('/') && !src.starts_with('.') && !src.starts_with('~') {
                        vol_vec.push(format!("{}_{}:{}", self.name, src, dest));
                    } else {
                        vol_vec.push(v.clone());
                    }
                } else {
                    vol_vec.push(v.clone());
                }
            }
        }
        if let Some(deploy) = &svc.deploy {
            if let Some(res) = &deploy.resources {
                if let Some(reservations) = &res.reservations {
                    if let Some(devs) = &reservations.devices {
                        for d in devs {
                            for id in &d.device_ids {
                                for m in resolve_cdi_device_mounts(id) {
                                    if !vol_vec.contains(&m) {
                                        vol_vec.push(m);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let net_store = NetworkStore::new();
        let net_names = svc
            .networks
            .as_ref()
            .map(|n| n.network_names())
            .unwrap_or_default();
        let svc_net = if let Some(ref nm) = svc.network_mode {
            nm.clone()
        } else if let Some(first) = net_names.first() {
            format!("{}_{}", self.name, first)
        } else {
            format!("{}_default", self.name)
        };

        let mut attached_nets = Vec::new();
        if svc.network_mode.is_none() {
            attached_nets.push(svc_net.clone());
            for net_name in &net_names {
                attached_nets.push(format!("{}_{}", self.name, net_name));
            }
            if net_names.is_empty() {
                let default_net = format!("{}_default", self.name);
                if !attached_nets.contains(&default_net) {
                    attached_nets.push(default_net);
                }
            }
            attached_nets.sort();
            attached_nets.dedup();
        }

        let mut add_host = Vec::new();
        for anet in &attached_nets {
            if let Some(net) = net_store.find(anet) {
                for (_, ep) in &net.containers {
                    if !ep.ipv4_address.is_empty() {
                        add_host.push(format!("{}:{}", ep.container_name, ep.ipv4_address));
                        if ep.container_id != ep.container_name {
                            add_host.push(format!("{}:{}", ep.container_id, ep.ipv4_address));
                        }
                        for alias in &ep.aliases {
                            add_host.push(format!("{}:{}", alias, ep.ipv4_address));
                        }
                    }
                }
            }
        }
        add_host.sort();
        add_host.dedup();

        let mut ip_override = None;
        let mut ip6_override = None;
        let mut mac_override = svc.mac_address.clone();
        let mut aliases = vec![svc_name.to_string()];
        if let Some(nets_cfg) = &svc.networks {
            for net_name in &net_names {
                if let Some(ep_cfg) = nets_cfg.endpoint_config(net_name) {
                    if ip_override.is_none() && ep_cfg.ipv4_address.is_some() {
                        ip_override = ep_cfg.ipv4_address.clone();
                    }
                    if ip6_override.is_none() && ep_cfg.ipv6_address.is_some() {
                        ip6_override = ep_cfg.ipv6_address.clone();
                    }
                    if mac_override.is_none() && ep_cfg.mac_address.is_some() {
                        mac_override = ep_cfg.mac_address.clone();
                    }
                    for a in &ep_cfg.aliases {
                        if !aliases.contains(a) {
                            aliases.push(a.clone());
                        }
                    }
                }
            }
        }

        let labels_vec = svc.labels.as_ref().map(|l| l.to_vec()).unwrap_or_default();
        let security_opt_vec = svc.security_opt.clone().unwrap_or_default();
        let no_healthcheck = svc.healthcheck.as_ref().is_some_and(|h| {
            h.disable
                || h.test
                    .as_ref()
                    .is_some_and(|t| t.to_vec().first().is_some_and(|s| s == "NONE"))
        });
        let health_cmd = if no_healthcheck {
            None
        } else {
            svc.healthcheck
                .as_ref()
                .and_then(|h| h.test.as_ref())
                .map(|t| {
                    let v = t.to_vec();
                    if v.first().is_some_and(|s| s == "CMD" || s == "CMD-SHELL") {
                        v[1..].join(" ")
                    } else {
                        v.join(" ")
                    }
                })
        };

        Ok(RunArgs {
            registry_auth: Default::default(),
            interactive: svc.stdin_open.unwrap_or(false),
            tty: svc.tty.unwrap_or(false),
            detach,
            rm: false,
            rmi: false,
            name: Some(container_name.to_string()),
            replace: false,
            env: env_vec,
            unsetenv: Vec::new(),
            unsetenv_all: false,
            env_merge: Vec::new(),
            systemd: None,
            ports: port_vec,
            volumes: vol_vec,
            image_volume: None,
            memory: None,
            kernel_memory: None,
            labels: labels_vec,
            dns: Vec::new(),
            cidfile: None,
            conmon_pidfile: None,
            cpus: None,
            pids_limit: None,
            rootless: true,
            restart: svc.restart.clone().unwrap_or_else(|| "no".to_string()),
            health_cmd,
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
            privileged: false,
            network: svc_net,
            disable_content_trust: false,
            gpus: None,
            entrypoint: svc
                .entrypoint
                .as_ref()
                .and_then(|e| e.to_vec().into_iter().next()),
            tz: Vec::new(),
            env_file: None,
            user: None,
            hostuser: Vec::new(),
            group_entry: Vec::new(),
            hostname: Some(
                svc.hostname
                    .clone()
                    .unwrap_or_else(|| svc_name.to_string()),
            ),
            no_hostname: false,
            add_host,
            shm_size: None,
            cap_add: Vec::new(),
            cap_drop: Vec::new(),
            read_only: false,
            http_proxy: false,
            read_only_tmpfs: None,
            init: false,
            tmpfs: Vec::new(),
            devices: svc.devices.clone().unwrap_or_default(),
            cdi_spec_dir: Vec::new(),
            security_opt: security_opt_vec,
            cpu_shares: None,
            cpuset_cpus: None,
            memory_swap: None,
            memory_reservation: None,
            dns_search: Vec::new(),
            dns_option: Vec::new(),
            expose: Vec::new(),
            sysctl: Vec::new(),
            stop_timeout: None,
            stop_signal: svc.stop_signal.clone(),
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
            ip: ip_override,
            ip6: ip6_override,
            mac_address: mac_override,
            link: Vec::new(),
            network_alias: aliases,
            mount: Vec::new(),
            health_interval: None,
            health_timeout: None,
            health_retries: None,
            health_start_period: None,
            health_on_failure: None,
            health_start_interval: None,
            no_healthcheck,
            attach: Vec::new(),
            preserve_fds: None,
            preserve_fd: Vec::new(),
            sdnotify: None,
            cgroups: None,
            pod_id_file: None,
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
            cgroup_conf: Vec::new(),
            runtime: None,
            sig_proxy: true,
            storage_opt: Vec::new(),
            use_api_socket: false,
            volume_driver: None,
            volumes_from: Vec::new(),
            workdir: None,
            pod: None,
            rootfs: None,
            default_mounts_file: None,
            init_ctr: None,
            timeout: None,
            image: image_name.to_string(),
            command: cmd_vec,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
