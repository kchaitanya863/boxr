use super::ComposeProject;
use super::config::*;
use crate::cli::RunArgs;
use crate::network::NetworkStore;
use anyhow::Result;
use std::fs;
use std::path::Path;

impl ComposeProject {
    pub fn build_service_run_args(
        &self,
        _svc_name: &str,
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
        let net_store = NetworkStore::new();
        let svc_net = svc
            .networks
            .as_ref()
            .and_then(|nets| nets.first())
            .map(|n| format!("{}_{}", self.name, n))
            .unwrap_or_else(|| format!("{}_default", self.name));

        let mut attached_nets = vec![svc_net.clone()];
        if let Some(nets) = &svc.networks {
            for net_name in nets {
                attached_nets.push(format!("{}_{}", self.name, net_name));
            }
        }
        let default_net = format!("{}_default", self.name);
        if !attached_nets.contains(&default_net) {
            attached_nets.push(default_net);
        }
        attached_nets.sort();
        attached_nets.dedup();

        let mut add_host = Vec::new();
        for anet in &attached_nets {
            if let Some(net) = net_store.find(anet) {
                for (_, ep) in &net.containers {
                    add_host.push(format!("{}:{}", ep.container_name, ep.ipv4_address));
                    if ep.container_id != ep.container_name {
                        add_host.push(format!("{}:{}", ep.container_id, ep.ipv4_address));
                    }
                }
            }
        }
        add_host.sort();
        add_host.dedup();

        Ok(RunArgs {
            registry_auth: Default::default(),
            interactive: false,
            tty: false,
            detach,
            rm: false,
            rmi: false,
            name: Some(container_name.to_string()),
            replace: false,
            env: env_vec,
            unsetenv: Vec::new(),
            unsetenv_all: false,
            systemd: None,
            ports: port_vec,
            volumes: vol_vec,
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
            restart: svc.restart.clone().unwrap_or_else(|| "no".to_string()),
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
            privileged: false,
            network: svc_net,
            disable_content_trust: false,
            gpus: None,
            entrypoint: None,
            tz: Vec::new(),
            env_file: None,
            user: None,
            hostuser: Vec::new(),
            group_entry: Vec::new(),
            hostname: Some(_svc_name.to_string()),
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
