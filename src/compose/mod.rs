pub mod args;
pub mod config;
mod interpolate;
pub mod provider;

#[cfg(test)]
mod tests;

pub use config::*;

use crate::builder::{BuildOptions, ImageBuilder};
use crate::network::NetworkStore;
use crate::storage::{ContainerRecord, ContainerStore};
use crate::volume::VolumeStore;
use anyhow::{Context, Result, anyhow};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub struct ComposeProject {
    pub name: String,
    pub compose_file_path: PathBuf,
    pub compose: ComposeFile,
}

impl ComposeProject {
    pub fn from_str(content: &str, project_name: &str) -> Result<Self> {
        let compose: ComposeFile =
            serde_yaml::from_str(content).context("Failed to parse YAML compose file")?;

        Ok(Self {
            name: project_name.to_string(),
            compose_file_path: PathBuf::from("docker-compose.yml"),
            compose,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let compose_path = if path.is_relative() {
            std::env::current_dir()
                .with_context(|| "Failed to determine current directory for compose file")?
                .join(path)
        } else {
            path.to_path_buf()
        };

        let content = fs::read_to_string(&compose_path)
            .with_context(|| format!("Failed to read compose file at {:?}", compose_path))?;

        let project_dir = compose_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let env = interpolate::project_env(project_dir);

        let mut root: serde_yaml::Value =
            serde_yaml::from_str(&content).context("Failed to parse YAML compose file")?;
        interpolate::interpolate_yaml(&mut root, &env)?;
        let compose: ComposeFile =
            serde_yaml::from_value(root).context("Failed to parse YAML compose file")?;

        let project_name = std::env::var("COMPOSE_PROJECT_NAME")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                project_dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "compose".to_string());

        Ok(Self {
            name: project_name,
            compose_file_path: compose_path,
            compose,
        })
    }

    /// Compute topological ordering of services based on depends_on
    pub fn dependency_order(&self) -> Result<Vec<String>> {
        let mut order = Vec::new();
        let mut visited = HashSet::new();
        let mut visiting = HashSet::new();

        for service in self.compose.services.keys() {
            if !visited.contains(service) {
                self.visit_service(service, &mut visited, &mut visiting, &mut order)?;
            }
        }

        Ok(order)
    }

    fn visit_service(
        &self,
        service: &str,
        visited: &mut HashSet<String>,
        visiting: &mut HashSet<String>,
        order: &mut Vec<String>,
    ) -> Result<()> {
        if visiting.contains(service) {
            return Err(anyhow!(
                "Cyclic dependency detected involving service '{}'",
                service
            ));
        }

        if !visited.contains(service) {
            visiting.insert(service.to_string());

            if let Some(cfg) = self.compose.services.get(service) {
                if let Some(deps) = &cfg.depends_on {
                    for dep in deps.dependency_names() {
                        if !self.compose.services.contains_key(&dep) {
                            return Err(anyhow!(
                                "Service '{}' depends on undefined service '{}'",
                                service,
                                dep
                            ));
                        }
                        self.visit_service(&dep, visited, visiting, order)?;
                    }
                }
            }

            visiting.remove(service);
            visited.insert(service.to_string());
            order.push(service.to_string());
        }

        Ok(())
    }

    /// Ensure project networks exist in NetworkStore (custom networks + default network)
    pub fn ensure_networks(&self) -> Result<Vec<String>> {
        let net_store = NetworkStore::new();
        let default_net_name = format!("{}_default", self.name);
        let mut created = Vec::new();

        let apply_net_cfg =
            |scoped_net: &str, cfg_opt: Option<&ComposeNetworkConfig>| -> Result<()> {
                let cfg = cfg_opt.cloned().unwrap_or_default();
                let driver = cfg.driver.as_deref().unwrap_or("bridge");
                let first_pool = cfg.ipam.as_ref().and_then(|i| i.config.first());
                let subnet = first_pool.and_then(|p| p.subnet.as_deref());
                let gateway = first_pool.and_then(|p| p.gateway.as_deref());
                let internal = cfg.internal.unwrap_or(false);
                let attachable = cfg.attachable.unwrap_or(false);
                let mut label_map = std::collections::HashMap::new();
                if let Some(lbls) = &cfg.labels {
                    for l in lbls.to_vec() {
                        if let Some((k, v)) = l.split_once('=') {
                            label_map.insert(k.to_string(), v.to_string());
                        }
                    }
                }
                if net_store.find(scoped_net).is_none() {
                    let _ = net_store.create_with_options(
                        scoped_net, driver, subnet, gateway, internal, attachable, label_map,
                    )?;
                }
                let raw_opts = cfg.driver_opts_map();
                let mut net_iface = None;
                let mut norm_opts = std::collections::HashMap::new();
                for (k, v) in raw_opts {
                    if k == "com.docker.network.bridge.name" {
                        net_iface = Some(v);
                    } else if k == "com.docker.network.driver.mtu" {
                        norm_opts.insert("mtu".to_string(), v);
                    } else if k == "parent" && (driver == "macvlan" || driver == "ipvlan") {
                        net_iface = Some(v);
                    } else {
                        norm_opts.insert(k, v);
                    }
                }
                if net_iface.is_some() || !norm_opts.is_empty() || cfg.enable_ipv6.is_some() {
                    let _ = net_store.configure_network_details(
                        scoped_net,
                        net_iface,
                        if norm_opts.is_empty() {
                            None
                        } else {
                            Some(norm_opts)
                        },
                        None,
                        None,
                        None,
                        cfg.enable_ipv6,
                    );
                }
                Ok(())
            };

        let def_cfg = self
            .compose
            .networks
            .get("default")
            .and_then(|o| o.as_ref());
        apply_net_cfg(&default_net_name, def_cfg)?;
        created.push(default_net_name);

        for (net_name, cfg_opt) in &self.compose.networks {
            if net_name == "default" {
                continue;
            }
            let scoped_net = format!("{}_{}", self.name, net_name);
            apply_net_cfg(&scoped_net, cfg_opt.as_ref())?;
            created.push(scoped_net);
        }
        Ok(created)
    }

    /// Resolve which services `compose up` should start (Docker parity: includes dependencies).
    pub fn services_for_up(&self, requested: &[String], no_deps: bool) -> Result<Vec<String>> {
        let order = self.dependency_order()?;
        if requested.is_empty() {
            return Ok(order);
        }
        for name in requested {
            if !self.compose.services.contains_key(name) {
                return Err(anyhow!("no such service: {}", name));
            }
        }
        if no_deps {
            let want: HashSet<_> = requested.iter().cloned().collect();
            return Ok(order.into_iter().filter(|s| want.contains(s)).collect());
        }

        let mut needed = HashSet::new();
        let mut stack = requested.to_vec();
        while let Some(svc) = stack.pop() {
            if !needed.insert(svc.clone()) {
                continue;
            }
            if let Some(cfg) = self.compose.services.get(&svc) {
                if let Some(deps) = &cfg.depends_on {
                    for dep in deps.dependency_names() {
                        stack.push(dep);
                    }
                }
            }
        }

        Ok(order.into_iter().filter(|s| needed.contains(s)).collect())
    }

    async fn resolve_service_image(
        &self,
        root_dir: &Path,
        svc_name: &str,
        svc: &ServiceConfig,
        build: bool,
        quiet: bool,
    ) -> Result<String> {
        if let Some(build_cfg) = &svc.build {
            if build || svc.image.is_none() {
                let context_path = root_dir.join(build_cfg.context_path());
                let dockerfile_path = context_path.join(build_cfg.dockerfile_name());
                let built_tag = format!("{}_{}:latest", self.name, svc_name);
                let record = ImageBuilder::new()
                    .build(BuildOptions {
                        context_dir: context_path,
                        dockerfile_path,
                        tag: Some(built_tag),
                        no_cache: false,
                        build_args: build_cfg.build_args(),
                        target: build_cfg.target(),
                        add_host: Vec::new(),
                        memory: None,
                        shm_size: None,
                        quiet,
                    })
                    .await?;
                return Ok(record.reference);
            }
        }
        if let Some(img) = &svc.image {
            return Ok(img.clone());
        }
        Err(anyhow!(
            "Service '{}' must specify either image or build",
            svc_name
        ))
    }

    pub async fn up(
        &self,
        detach: bool,
        build: bool,
        services: &[String],
        no_deps: bool,
    ) -> Result<()> {
        let order = self.services_for_up(services, no_deps)?;
        let c_store = ContainerStore::new();
        let is_reup = order.iter().any(|svc_name| {
            let svc = self.compose.services.get(svc_name).unwrap();
            let cname = svc
                .container_name
                .clone()
                .unwrap_or_else(|| format!("{}-{}-1", self.name, svc_name));
            c_store.find(&cname).is_some()
                || c_store
                    .find(&format!("{}_{}_1", self.name, svc_name))
                    .is_some()
        });

        if !is_reup {
            println!(
                "Starting compose project '{}' (service order: {:?})",
                self.name, order
            );
        }

        // Ensure project networks (custom networks declared in compose file, plus default network)
        let _ = self.ensure_networks()?;
        let net_store = NetworkStore::new();
        let default_net_name = format!("{}_default", self.name);

        // Helper to resolve the primary network name for a service
        let service_primary_network = |svc: &ServiceConfig| -> String {
            if let Some(nets) = &svc.networks {
                if let Some(first) = nets.network_names().first() {
                    return format!("{}_{}", self.name, first);
                }
            }
            default_net_name.clone()
        };

        // Pre-allocate IPAM endpoints for all services so service discovery knows all service IPs
        for svc_name in &order {
            let svc = self.compose.services.get(svc_name).unwrap();
            if svc.network_mode.is_some() {
                continue;
            }
            let container_name = svc
                .container_name
                .clone()
                .unwrap_or_else(|| format!("{}-{}-1", self.name, svc_name));
            let primary_net = service_primary_network(svc);
            let mut aliases = vec![svc_name.clone()];
            let mut ip_ov = None;
            let mut ip6_ov = None;
            let mut mac_ov = svc.mac_address.clone();
            if let Some(nets) = &svc.networks {
                for net_name in nets.network_names() {
                    let scoped_net = format!("{}_{}", self.name, net_name);
                    let mut net_aliases = vec![svc_name.clone()];
                    let mut net_ip = None;
                    let mut net_ip6 = None;
                    let mut net_mac = svc.mac_address.clone();
                    if let Some(ep_cfg) = nets.endpoint_config(&net_name) {
                        for a in &ep_cfg.aliases {
                            if !net_aliases.contains(a) {
                                net_aliases.push(a.clone());
                            }
                            if !aliases.contains(a) {
                                aliases.push(a.clone());
                            }
                        }
                        net_ip = ep_cfg.ipv4_address.clone();
                        net_ip6 = ep_cfg.ipv6_address.clone();
                        if ep_cfg.mac_address.is_some() {
                            net_mac = ep_cfg.mac_address.clone();
                        }
                        if ip_ov.is_none() {
                            ip_ov = net_ip.clone();
                        }
                        if ip6_ov.is_none() {
                            ip6_ov = net_ip6.clone();
                        }
                        if mac_ov.is_none() {
                            mac_ov = net_mac.clone();
                        }
                    }
                    let _ = net_store.connect_container_with_details(
                        &scoped_net,
                        &container_name,
                        &container_name,
                        net_ip.as_deref(),
                        net_ip6.as_deref(),
                        net_mac.as_deref(),
                        net_aliases,
                    );
                }
            } else {
                let _ = net_store.connect_container_with_details(
                    &primary_net,
                    &container_name,
                    &container_name,
                    ip_ov.as_deref(),
                    ip6_ov.as_deref(),
                    mac_ov.as_deref(),
                    aliases,
                );
            }
        }

        #[cfg(target_os = "macos")]
        let mesh_ports: std::collections::HashMap<String, u16> = order
            .iter()
            .enumerate()
            .map(|(idx, svc)| (svc.clone(), 28000 + idx as u16))
            .collect();

        // Ensure project volumes
        let vol_store = VolumeStore::new();
        for vol_name in self.compose.volumes.keys() {
            let scoped_vol = format!("{}_{}", self.name, vol_name);
            if vol_store.find(&scoped_vol).is_none() {
                let _ = vol_store.create(Some(&scoped_vol), None);
            }
        }

        // Launch services
        let root_dir = self.compose_file_path.parent().unwrap_or(Path::new("."));

        for svc_name in order {
            let svc = self.compose.services.get(&svc_name).unwrap();
            let container_name = svc
                .container_name
                .clone()
                .unwrap_or_else(|| format!("{}-{}-1", self.name, svc_name));

            let existing = ContainerStore::new()
                .find(&container_name)
                .or_else(|| ContainerStore::new().find(&format!("{}_{}_1", self.name, svc_name)));

            let image_name = self
                .resolve_service_image(root_dir, &svc_name, svc, build, is_reup)
                .await?;

            let mut run_args =
                self.build_service_run_args(&svc_name, svc, &container_name, &image_name, detach)?;

            if let Some(ex) = existing {
                let want_cmd = svc.command.as_ref().map(|c| c.to_vec()).unwrap_or_default();
                let same_cmd = want_cmd.is_empty() || ex.command == want_cmd;
                if same_cmd && matches!(ex.status, crate::storage::ContainerStatus::Running) {
                    println!(" Container {}  Running", container_name);
                    continue;
                }
                println!(" Container {}  Recreate", container_name);
                let _ = crate::stop_container_with_home_and_timeout(
                    &ex.id,
                    None,
                    Some(0),
                    None,
                    true,
                    None,
                );
                let _ = crate::remove_container_quiet(&ex.id, true, false);
                println!(" Container {}  Recreated", container_name);
                println!(" Container {}  Starting", container_name);
            } else if !is_reup {
                println!(
                    "Creating and starting service '{}' ({})",
                    svc_name, container_name
                );
            }

            let svc_net = service_primary_network(svc);

            #[cfg(target_os = "macos")]
            for (peer_svc, relay_port) in &mesh_ports {
                if *peer_svc != *svc_name {
                    run_args.env.push(format!(
                        "BOXR_MESH_{}={}:{}",
                        peer_svc.to_uppercase(),
                        "192.168.64.1",
                        relay_port
                    ));
                }
            }

            let run_res = if is_reup {
                crate::run_container_with_output(
                    run_args,
                    crate::CliOutputPolicy {
                        noout: true,
                        out: None,
                    },
                )
                .await
            } else {
                crate::run_container(run_args).await
            };

            match run_res {
                Ok(code) if code != 0 => {
                    return Err(anyhow!(
                        "Service '{}' in compose project '{}' exited with error code {}",
                        svc_name,
                        self.name,
                        code
                    ));
                }
                Err(err) => {
                    return Err(anyhow!(
                        "Failed to start service '{}' in compose project '{}': {:?}",
                        svc_name,
                        self.name,
                        err
                    ));
                }
                _ => {}
            }

            if svc.network_mode.is_none() {
                if let Some(created_c) = ContainerStore::new().find(&container_name) {
                    if let Some(nets) = &svc.networks {
                        for net_name in nets.network_names() {
                            let scoped_net = format!("{}_{}", self.name, net_name);
                            let mut net_aliases = vec![svc_name.clone()];
                            let mut net_ip = None;
                            let mut net_ip6 = None;
                            let mut net_mac = svc.mac_address.clone();
                            if let Some(ep_cfg) = nets.endpoint_config(&net_name) {
                                for a in &ep_cfg.aliases {
                                    if !net_aliases.contains(a) {
                                        net_aliases.push(a.clone());
                                    }
                                }
                                net_ip = ep_cfg.ipv4_address.clone();
                                net_ip6 = ep_cfg.ipv6_address.clone();
                                if ep_cfg.mac_address.is_some() {
                                    net_mac = ep_cfg.mac_address.clone();
                                }
                            }
                            if let Some(pre_ep) = net_store
                                .find(&scoped_net)
                                .and_then(|n| n.containers.get(&container_name).cloned())
                            {
                                if net_ip.is_none() && !pre_ep.ipv4_address.is_empty() {
                                    net_ip = Some(pre_ep.ipv4_address);
                                }
                                if net_mac.is_none() && !pre_ep.mac_address.is_empty() {
                                    net_mac = Some(pre_ep.mac_address);
                                }
                            }
                            let _ = net_store.disconnect_container(&scoped_net, &container_name);
                            let _ = net_store.connect_container_with_details(
                                &scoped_net,
                                &created_c.id,
                                &container_name,
                                net_ip.as_deref(),
                                net_ip6.as_deref(),
                                net_mac.as_deref(),
                                net_aliases,
                            );
                            let _ =
                                crate::network::refresh_bridge_hosts_for_network(&scoped_net, None);
                        }
                    } else {
                        let _ = net_store.disconnect_container(&svc_net, &container_name);
                        let _ = net_store.connect_container_with_details(
                            &svc_net,
                            &created_c.id,
                            &container_name,
                            None,
                            None,
                            svc.mac_address.as_deref(),
                            vec![svc_name.clone()],
                        );
                        let _ = crate::network::refresh_bridge_hosts_for_network(&svc_net, None);
                    }
                }
            }

            if is_reup {
                println!(" Container {}  Started", container_name);
            }
        }

        #[cfg(target_os = "macos")]
        if let Err(e) = crate::network::macos_compose::start_compose_mesh(&default_net_name).await {
            eprintln!(
                "Warning: compose inter-service mesh relays unavailable: {:?}",
                e
            );
        }

        if !is_reup {
            println!("Project '{}' started successfully.", self.name);
        }
        Ok(())
    }

    pub fn down(&self, remove_volumes: bool) -> Result<()> {
        println!("Stopping compose project '{}'...", self.name);
        let store = ContainerStore::new();
        let prefix_under = format!("{}_", self.name);
        let prefix_dash = format!("{}-", self.name);

        let mut custom_names = HashSet::new();
        for (svc_name, svc) in &self.compose.services {
            if let Some(cname) = &svc.container_name {
                custom_names.insert(cname.clone());
            }
            for num in 1..=20 {
                custom_names.insert(format!("{}_{}_{}", self.name, svc_name, num));
                custom_names.insert(format!("{}-{}-{}", self.name, svc_name, num));
            }
        }

        for c in store.list() {
            let matches_project = custom_names.contains(&c.name) || {
                if let Some(rest) = c.name.strip_prefix(&prefix_under) {
                    if let Some((svc, _num)) = rest.rsplit_once('_') {
                        self.compose.services.contains_key(svc)
                    } else {
                        false
                    }
                } else if let Some(rest) = c.name.strip_prefix(&prefix_dash) {
                    if let Some((svc, _num)) = rest.rsplit_once('-') {
                        self.compose.services.contains_key(svc)
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if matches_project {
                println!("Stopping container {}", c.name);
                let _ = crate::stop_container(&c.id, None);
                println!("Removing container {}", c.name);
                let _ = crate::remove_container(&c.id, true);
            }
        }

        if remove_volumes {
            let vol_store = VolumeStore::new();
            for vol_name in self.compose.volumes.keys() {
                let scoped_vol = format!("{}_{}", self.name, vol_name);
                let _ = vol_store.remove(&scoped_vol);
            }
        }

        let net_store = NetworkStore::new();
        let default_net_name = format!("{}_default", self.name);
        let mut all_project_nets = vec![default_net_name.clone()];
        for net_name in self.compose.networks.keys() {
            all_project_nets.push(format!("{}_{}", self.name, net_name));
        }

        for (svc_name, svc) in &self.compose.services {
            for container_name in [
                svc.container_name
                    .clone()
                    .unwrap_or_else(|| format!("{}-{}-1", self.name, svc_name)),
                format!("{}_{}_1", self.name, svc_name),
            ] {
                for pnet in &all_project_nets {
                    let _ = net_store.disconnect_container(pnet, &container_name);
                    let _ = net_store.disconnect_container(pnet, svc_name);
                }
                let _ = net_store.cleanup_container_endpoints(&container_name, svc_name);
            }
        }
        for pnet in all_project_nets {
            let _ = net_store.remove_with_force(&pnet, true);
        }

        println!("Project '{}' stopped and removed.", self.name);
        Ok(())
    }

    pub async fn build(&self, no_cache: bool, quiet: bool) -> Result<()> {
        let root_dir = self.compose_file_path.parent().unwrap_or(Path::new("."));
        for (svc_name, svc) in &self.compose.services {
            if let Some(build_cfg) = &svc.build {
                let ctx_path = root_dir.join(build_cfg.context_path());
                let dockerfile = ctx_path.join(build_cfg.dockerfile_name());
                if dockerfile.exists() {
                    let builder = ImageBuilder::new();
                    let tag = svc
                        .image
                        .clone()
                        .unwrap_or_else(|| format!("{}_{}:latest", self.name, svc_name));
                    let _ = builder
                        .build(BuildOptions {
                            context_dir: ctx_path,
                            dockerfile_path: dockerfile,
                            tag: Some(tag),
                            no_cache,
                            build_args: build_cfg.build_args(),
                            target: build_cfg.target(),
                            add_host: Vec::new(),
                            memory: None,
                            shm_size: None,
                            quiet,
                        })
                        .await?;
                }
            }
        }
        Ok(())
    }

    pub fn ps(&self) -> Result<Vec<ContainerRecord>> {
        let store = ContainerStore::new();
        let prefix_under = format!("{}_", self.name);
        let prefix_dash = format!("{}-", self.name);

        let mut custom_names = HashSet::new();
        for svc in self.compose.services.values() {
            if let Some(cname) = &svc.container_name {
                custom_names.insert(cname.clone());
            }
        }

        let containers: Vec<ContainerRecord> = store
            .list()
            .into_iter()
            .filter(|c| {
                c.name.starts_with(&prefix_under)
                    || c.name.starts_with(&prefix_dash)
                    || custom_names.contains(&c.name)
            })
            .collect();
        Ok(containers)
    }

    pub async fn pull_images(&self) -> Result<()> {
        for (svc_name, svc) in &self.compose.services {
            if let Some(img) = &svc.image {
                println!("Pulling service {} image {}...", svc_name, img);
                let _ = crate::pull_image(img).await?;
            }
        }
        Ok(())
    }

    pub async fn push_images(&self) -> Result<()> {
        for (svc_name, svc) in &self.compose.services {
            if let Some(img) = &svc.image {
                println!("Pushing service {} image {}...", svc_name, img);
                let _ = crate::push_image(img).await?;
            }
        }
        Ok(())
    }

    pub async fn create_containers(&self) -> Result<()> {
        let order = self.dependency_order()?;
        for svc_name in order {
            let svc = self.compose.services.get(&svc_name).unwrap();
            let container_name = svc
                .container_name
                .clone()
                .unwrap_or_else(|| format!("{}_{}_1", self.name, svc_name));
            if let Some(img) = &svc.image {
                let run_args =
                    self.build_service_run_args(&svc_name, svc, &container_name, img, false)?;
                let _ = crate::create_only_container(run_args).await?;
            }
        }
        Ok(())
    }

    pub async fn run_one_off(&self, service: &str, command: Vec<String>, rm: bool) -> Result<()> {
        let svc = self
            .compose
            .services
            .get(service)
            .ok_or_else(|| anyhow!("Service '{}' not found", service))?;
        let container_name = format!(
            "{}_{}_run_{}",
            self.name,
            service,
            hex::encode(crate::storage::container_store::rand_id())
        );
        let image_name = svc
            .image
            .clone()
            .ok_or_else(|| anyhow!("Service '{}' has no image", service))?;
        let mut run_args =
            self.build_service_run_args(service, svc, &container_name, &image_name, true)?;
        run_args.rm = rm;
        run_args.detach = false;
        run_args.interactive = true;
        run_args.tty = true;
        if !command.is_empty() {
            run_args.command = command;
        }
        let _ = crate::run_container(run_args).await?;
        Ok(())
    }
}
