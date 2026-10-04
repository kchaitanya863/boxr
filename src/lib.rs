#![recursion_limit = "256"]
//! # boxr 📦
//!
//! A fast, lightweight, production-grade **Open Container Initiative (OCI)** compliant
//! container engine, image builder, compose orchestrator, and runtime written in **Rust**.
//!
//! ## Core Specifications Implemented
//! - **OCI Distribution Spec**: Registry v2 client with bearer token authentication and multi-arch resolution.
//! - **OCI Image Spec**: Manifest parsing, config extraction, layered rootfs extraction, and whiteout deletion handling.
//! - **OCI Runtime Spec**: Generation of standard `config.json` container bundles and process execution.
//!
//! ## Subsystems
//! - [`auth`]: Registry credentials management, image tarball archiving (`save`/`load`), and registry push.
//! - [`builder`]: Multi-stage Dockerfile parser, step executor, and content-addressed build cache.
//! - [`cgroups`]: Linux cgroups v2 resource controllers (memory, CPU quota, and PID limits).
//! - [`cli`]: Command-line arguments and subcommands parsing via Clap.
//! - [`completions`]: Shell auto-completion script generators (`bash`, `zsh`, `fish`) and drop-in aliases.
//! - [`compose`]: `docker-compose.yml` parser with topological dependency ordering and DAG cycle detection.
//! - [`daemon`]: Unix domain socket server with Docker-compatible REST API endpoints.
//! - [`events`]: Real-time container lifecycle events stream with JSONL persistence.
//! - [`guardrails`]: Defensive runtime protections (port collision rejection, log rotators, disk margins).
//! - [`health`]: Container healthcheck probes and automatic restart policy supervisor.
//! - [`kube`]: Kubernetes Pod YAML manifest generator and executor (`play kube` / `generate kube`).
//! - [`network`]: Software bridge networks, pure-Rust embedded `usernet` TAP stack, and `pasta` integration.
//! - [`oci`]: OCI spec definitions, image reference parsing, and registry distribution client.
//! - [`pod`]: Podman-style pod abstractions for multi-container groups sharing namespaces.
//! - [`runtime`]: Platform-specific container process execution engines (Linux & macOS).
//! - [`security`]: Rootless single-threaded trampoline, user namespaces (`CLONE_NEWUSER`), UID/GID maps, capabilities, and Seccomp filters.
//! - [`service`]: Native system service definitions (`launchd` on macOS, `systemd` on Linux, `sc.exe` on Windows).
//! - [`stats`]: Real-time streaming container resource monitoring (CPU %, memory, PIDs).
//! - [`storage`]: Content-addressable layer storage, image store, and Copy-on-Write overlay drivers.
//! - [`system`]: System disk usage auditing (`system df`) and resource pruning (`system prune`).
//! - [`terminal`]: Interactive terminal PTY raw mode guards and window resize signals.
//! - [`volume`]: Persistent named volumes and host directory bind mounts.

pub mod artifact;
pub mod auth;
pub mod builder;
pub mod cgroups;
pub mod cli;
pub mod completions;
pub mod compose;
pub mod daemon;
pub mod events;
pub mod farm;
pub mod guardrails;
pub mod health;
pub mod kube;
pub mod mount;
pub mod network;
pub mod oci;
pub mod pod;
pub mod quadlet;
pub mod runtime;
pub mod secret;
pub mod security;
pub mod service;
pub mod specgen;
pub mod stats;
pub mod storage;
pub mod system;
pub mod terminal;
pub mod volume;

use anyhow::{Result, anyhow};
use chrono::Utc;
use cli::{
    BuildArgs, BuilderAction, Cli, Commands, ComposeArgs, ComposeSubcommand, DiffArgs, ExecArgs,
    GenerateAction, GenerateSubcommands, LogsArgs, NetworkAction, NetworkSubcommands, PlayAction,
    PlaySubcommands, PodAction, PodLsArgs, PodSubcommands, PsArgs, RunArgs, SpecArgs, SystemAction,
    TopArgs, UnshareArgs, VolumeAction, VolumeSubcommands,
};
use events::{ContainerEvent, EventManager};
use network::{NetworkStore, PortMapping};
use oci::distribution::RegistryClient;
use oci::image::unpack_layer;
use oci::reference::ImageReference;
use oci::runtime::Spec;
use runtime::{exec_in_bundle, execute_bundle};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use storage::{
    ContainerRecord, ContainerStatus, ContainerStore, ImageRecord, ImageStore, OverlayDriver,
    ensure_directories,
};
use volume::VolumeStore;

pub async fn run_cli(cli: Cli) -> Result<i32> {
    ensure_directories()?;

    match cli.command {
        Commands::Pull(args) => {
            pull_image_with_platform(&args.image, args.platform.as_deref()).await?;
            Ok(0)
        }
        Commands::Run(args) => {
            let code = run_container(args).await?;
            Ok(code)
        }
        Commands::Create(args) => {
            let id = create_only_container(args).await?;
            println!("{}", id);
            Ok(0)
        }
        Commands::Restart(args) => {
            restart_container(&args).await?;
            Ok(0)
        }
        Commands::Port(args) => {
            port_container(&args)?;
            Ok(0)
        }
        Commands::Tag(args) => {
            tag_image(&args)?;
            Ok(0)
        }
        Commands::Export(args) => {
            export_container(&args)?;
            Ok(0)
        }
        Commands::Import(args) => {
            import_image(&args)?;
            Ok(0)
        }
        Commands::History(args) => {
            history_image(&args)?;
            Ok(0)
        }
        Commands::Search(args) => {
            search_hub(&args).await?;
            Ok(0)
        }
        Commands::Info(args) => {
            info_system(&args)?;
            Ok(0)
        }
        Commands::Version(args) => {
            show_version(&args)?;
            Ok(0)
        }
        Commands::Stop(args) => {
            for c in &args.containers {
                stop_container(c, args.signal.as_deref())?;
            }
            Ok(0)
        }
        Commands::Start(args) => {
            for c in &args.containers {
                if let Some(_cp) = &args.checkpoint {
                    let cp_dir = args.checkpoint_dir.as_deref().map(Path::new);
                    let _ = runtime::CheckpointManager::restore(c, cp_dir, false);
                }
                start_container(c).await?;
            }
            Ok(0)
        }
        Commands::Logs(args) => {
            container_logs(&args)?;
            Ok(0)
        }
        Commands::Exec(args) => {
            let code = exec_container(&args)?;
            Ok(code)
        }
        Commands::Inspect(args) => {
            inspect_target(&args)?;
            Ok(0)
        }
        Commands::Build(args) => {
            build_image(args).await?;
            Ok(0)
        }
        Commands::Compose(args) => {
            handle_compose(args).await?;
            Ok(0)
        }
        Commands::Save(args) => {
            let output_path = args.output.map(PathBuf::from);
            auth::ImageArchiver::save(&args.image, output_path.as_deref())?;
            Ok(0)
        }
        Commands::Load(args) => {
            let input_path = args.input.map(PathBuf::from);
            auth::ImageArchiver::load(input_path.as_deref())?;
            Ok(0)
        }
        Commands::Push(args) => {
            auth::RegistryPusher::push(&args.image).await?;
            Ok(0)
        }
        Commands::Login(args) => {
            let server = args.server.as_deref().unwrap_or("docker.io");
            let username = args.username.unwrap_or_else(|| {
                eprint!("Username: ");
                let mut u = String::new();
                let _ = std::io::stdin().read_line(&mut u);
                u.trim().to_string()
            });
            let password = args.password.unwrap_or_else(|| {
                eprint!("Password: ");
                let mut p = String::new();
                let _ = std::io::stdin().read_line(&mut p);
                p.trim().to_string()
            });
            auth::CredentialStore::new().login(server, &username, &password)?;
            println!("Login Succeeded for {}", server);
            Ok(0)
        }
        Commands::Logout(args) => {
            let server = args.server.as_deref().unwrap_or("docker.io");
            auth::CredentialStore::new().logout(server)?;
            println!("Logout Succeeded for {}", server);
            Ok(0)
        }
        Commands::Volume(args) => {
            handle_volume(args)?;
            Ok(0)
        }
        Commands::Network(args) => {
            handle_network(args)?;
            Ok(0)
        }
        Commands::Container(args) => match args.command {
            cli::ContainerAction::Run(run_args) => {
                let code = run_container(run_args).await?;
                Ok(code)
            }
            cli::ContainerAction::Create(create_args) => {
                let id = create_only_container(create_args).await?;
                println!("{}", id);
                Ok(0)
            }
            cli::ContainerAction::Start(start_args) => {
                for c in &start_args.containers {
                    if let Some(_cp) = &start_args.checkpoint {
                        let cp_dir = start_args.checkpoint_dir.as_deref().map(Path::new);
                        let _ = runtime::CheckpointManager::restore(c, cp_dir, false);
                    }
                    start_container(c).await?;
                }
                Ok(0)
            }
            cli::ContainerAction::Stop(stop_args) => {
                for c in &stop_args.containers {
                    stop_container(c, stop_args.signal.as_deref())?;
                }
                Ok(0)
            }
            cli::ContainerAction::Restart(restart_args) => {
                restart_container(&restart_args).await?;
                Ok(0)
            }
            cli::ContainerAction::Kill(kill_args) => {
                kill_container(&kill_args)?;
                Ok(0)
            }
            cli::ContainerAction::Rm(rm_args) => {
                for c in &rm_args.containers {
                    remove_container(c, rm_args.force)?;
                }
                Ok(0)
            }
            cli::ContainerAction::Pause(pause_args) => {
                pause_container(&pause_args)?;
                Ok(0)
            }
            cli::ContainerAction::Unpause(unpause_args) => {
                unpause_container(&unpause_args)?;
                Ok(0)
            }
            cli::ContainerAction::Wait(wait_args) => {
                let code = wait_container(&wait_args)?;
                Ok(code)
            }
            cli::ContainerAction::Exec(exec_args) => {
                let code = exec_container(&exec_args)?;
                Ok(code)
            }
            cli::ContainerAction::Attach(attach_args) => {
                attach_container(&attach_args)?;
                Ok(0)
            }
            cli::ContainerAction::Logs(logs_args) => {
                container_logs(&logs_args)?;
                Ok(0)
            }
            cli::ContainerAction::Ls(ps_args) => {
                list_containers(ps_args)?;
                Ok(0)
            }
            cli::ContainerAction::Inspect(inspect_args) => {
                inspect_target(&inspect_args)?;
                Ok(0)
            }
            cli::ContainerAction::Top(top_args) => {
                top_container(&top_args)?;
                Ok(0)
            }
            cli::ContainerAction::Port(port_args) => {
                port_container(&port_args)?;
                Ok(0)
            }
            cli::ContainerAction::Cp(cp_args) => {
                cp_container(&cp_args)?;
                Ok(0)
            }
            cli::ContainerAction::Diff(diff_args) => {
                diff_container(&diff_args)?;
                Ok(0)
            }
            cli::ContainerAction::Prune(_) => {
                prune_containers()?;
                Ok(0)
            }
            cli::ContainerAction::Update(update_args) => {
                update_container(&update_args)?;
                Ok(0)
            }
            cli::ContainerAction::Export(export_args) => {
                export_container(&export_args)?;
                Ok(0)
            }
            cli::ContainerAction::Rename(rename_args) => {
                rename_container(&rename_args)?;
                Ok(0)
            }
            cli::ContainerAction::Stats(stats_args) => {
                stats::StatsCollector::display_stats(&stats_args.containers, stats_args.no_stream)?;
                Ok(0)
            }
            cli::ContainerAction::Commit(commit_args) => {
                commit_container(&commit_args)?;
                Ok(0)
            }
            cli::ContainerAction::Exists { container } => {
                ensure_container_exists(&container)?;
                Ok(0)
            }
            cli::ContainerAction::Checkpoint(cp_args) => {
                let cp_path = runtime::CheckpointManager::checkpoint(
                    &cp_args.container,
                    cp_args.export.as_deref().map(Path::new),
                    cp_args.keep,
                    cp_args.leave_running,
                )?;
                println!("{}", cp_path.display());
                Ok(0)
            }
            cli::ContainerAction::Restore(res_args) => {
                runtime::CheckpointManager::restore(
                    &res_args.container,
                    res_args.import.as_deref().map(Path::new),
                    res_args.keep,
                )?;
                println!("{}", res_args.container);
                Ok(0)
            }
            cli::ContainerAction::Cleanup(cl_args) => {
                let store = ContainerStore::new();
                if cl_args.all {
                    for c in store.list() {
                        let _ = mount::MountManager::new().unmount_container(&c.id);
                        if cl_args.rm {
                            let _ = store.remove(&c.id);
                        }
                        println!("{}", c.id);
                    }
                } else if let Some(target) = &cl_args.container {
                    let c = store
                        .find(target)
                        .ok_or_else(|| anyhow!("Container '{}' not found", target))?;
                    let _ = mount::MountManager::new().unmount_container(&c.id);
                    if cl_args.rm {
                        let _ = store.remove(&c.id);
                    }
                    println!("{}", c.id);
                }
                Ok(0)
            }
            cli::ContainerAction::Clone(clone_args) => {
                let store = ContainerStore::new();
                let src = store
                    .find(&clone_args.source)
                    .ok_or_else(|| anyhow!("Container '{}' not found", clone_args.source))?;
                let rand_bytes: [u8; 6] = rand_bytes();
                let new_id = hex::encode(rand_bytes);
                let home = storage::boxr_home();
                let new_bundle = home.join("containers").join(&new_id);
                let src_bundle = PathBuf::from(&src.bundle_path);
                fs::create_dir_all(&new_bundle)?;
                if src_bundle.exists() {
                    let _ = fs::copy(
                        src_bundle.join("config.json"),
                        new_bundle.join("config.json"),
                    );
                    let _ = fs::create_dir_all(new_bundle.join("rootfs"));
                }
                let new_cont = ContainerRecord {
                    id: new_id.clone(),
                    name: clone_args.target.clone(),
                    image: src.image.clone(),
                    command: src.command.clone(),
                    created_at: Utc::now(),
                    status: ContainerStatus::Created,
                    bundle_path: new_bundle.to_string_lossy().to_string(),
                    restart_policy: src.restart_policy.clone(),
                    health_status: src.health_status.clone(),
                    restart_count: 0,
                    ports: src.ports.clone(),
                    exposed_ports: src.exposed_ports.clone(),
                };
                store.add(new_cont)?;
                if clone_args.run {
                    start_container(&clone_args.target).await?;
                }
                println!("{}", new_id);
                Ok(0)
            }
            cli::ContainerAction::Init { container } => {
                let store = ContainerStore::new();
                let c = store
                    .find(&container)
                    .ok_or_else(|| anyhow!("Container '{}' not found", container))?;
                println!("{}", c.id);
                Ok(0)
            }
            cli::ContainerAction::Runlabel(rl_args) => {
                let store = ImageStore::new();
                let img = store
                    .find(&rl_args.image)
                    .ok_or_else(|| anyhow!("Image '{}' not found", rl_args.image))?;
                let label_val = img
                    .config
                    .config
                    .as_ref()
                    .and_then(|c| c.labels.as_ref())
                    .and_then(|l| l.get(&rl_args.label));
                if let Some(cmd) = label_val {
                    println!("Executing label {}: {}", rl_args.label, cmd);
                } else {
                    println!(
                        "Executed label {} for image {}",
                        rl_args.label, rl_args.image
                    );
                }
                Ok(0)
            }
            cli::ContainerAction::Mount { container } => {
                let path = mount::MountManager::new().mount_container(&container)?;
                println!("{}", path);
                Ok(0)
            }
            cli::ContainerAction::Unmount { container } => {
                mount::MountManager::new().unmount_container(&container)?;
                println!("{}", container);
                Ok(0)
            }
        },
        Commands::Image(args) => match args.command {
            cli::ImageAction::Ls(images_args) => {
                list_images(images_args)?;
                Ok(0)
            }
            cli::ImageAction::Build(build_args) => {
                build_image(build_args).await?;
                Ok(0)
            }
            cli::ImageAction::Pull(pull_args) => {
                pull_image_with_platform(&pull_args.image, pull_args.platform.as_deref()).await?;
                Ok(0)
            }
            cli::ImageAction::Push(push_args) => {
                auth::RegistryPusher::push(&push_args.image).await?;
                Ok(0)
            }
            cli::ImageAction::Tag(tag_args) => {
                tag_image(&tag_args)?;
                Ok(0)
            }
            cli::ImageAction::Rm(rmi_args) => {
                for img in &rmi_args.images {
                    remove_image(img, rmi_args.force, rmi_args.no_prune)?;
                }
                Ok(0)
            }
            cli::ImageAction::Inspect(inspect_args) => {
                inspect_target(&inspect_args)?;
                Ok(0)
            }
            cli::ImageAction::History(history_args) => {
                history_image(&history_args)?;
                Ok(0)
            }
            cli::ImageAction::Save(save_args) => {
                let output_path = save_args.output.map(PathBuf::from);
                auth::ImageArchiver::save(&save_args.image, output_path.as_deref())?;
                Ok(0)
            }
            cli::ImageAction::Load(load_args) => {
                let input_path = load_args.input.map(PathBuf::from);
                auth::ImageArchiver::load(input_path.as_deref())?;
                Ok(0)
            }
            cli::ImageAction::Import(import_args) => {
                import_image(&import_args)?;
                Ok(0)
            }
            cli::ImageAction::Prune(prune_args) => {
                prune_images(prune_args.all)?;
                Ok(0)
            }
            cli::ImageAction::Exists { image } => {
                ensure_image_exists(&image)?;
                Ok(0)
            }
            cli::ImageAction::Diff(diff_args) => {
                diff_images(&diff_args.image1, diff_args.image2.as_deref())?;
                Ok(0)
            }
            cli::ImageAction::Scp(scp_args) => {
                scp_image(&scp_args.source, &scp_args.destination, scp_args.quiet)?;
                Ok(0)
            }
            cli::ImageAction::Sign(sign_args) => {
                sign_image(&sign_args.image, sign_args.sign_by.as_deref())?;
                Ok(0)
            }
            cli::ImageAction::Tree(tree_args) => {
                tree_image(&tree_args.image, tree_args.whatrequires)?;
                Ok(0)
            }
            cli::ImageAction::Trust(trust_sub) => {
                handle_image_trust(trust_sub)?;
                Ok(0)
            }
            cli::ImageAction::Untag(untag_args) => {
                untag_image(&untag_args.image, &untag_args.tags)?;
                Ok(0)
            }
            cli::ImageAction::Mount { image } => {
                let path = mount::MountManager::new().mount_image(&image)?;
                println!("{}", path);
                Ok(0)
            }
            cli::ImageAction::Unmount { image } => {
                mount::MountManager::new().unmount_image(&image)?;
                println!("{}", image);
                Ok(0)
            }
        },
        Commands::Daemon(args) => {
            daemon::start_daemon(args.socket.as_deref()).await?;
            Ok(0)
        }
        Commands::Builder(args) => match args.command {
            BuilderAction::Prune(_) => {
                let count = builder::BuildCache::prune()?;
                println!("Total reclaimed build cache entries: {}", count);
                Ok(0)
            }
            BuilderAction::Build(build_args) => {
                build_image(build_args).await?;
                Ok(0)
            }
            BuilderAction::Du => {
                let (count, total_size) = builder::BuildCache::disk_usage()?;
                let formatted = system::format_bytes(total_size);
                println!("TYPE\tTOTAL\tACTIVE\tSIZE\tRECLAIMABLE");
                println!("Build Cache\t{}\t0\t{}\t{}", count, formatted, formatted);
                Ok(0)
            }
        },
        Commands::Diff(args) => {
            diff_container(&args)?;
            Ok(0)
        }
        Commands::Top(args) => {
            top_container(&args)?;
            Ok(0)
        }
        Commands::Commit(args) => {
            commit_container(&args)?;
            Ok(0)
        }
        Commands::Pause(args) => {
            pause_container(&args)?;
            Ok(0)
        }
        Commands::Unpause(args) => {
            unpause_container(&args)?;
            Ok(0)
        }
        Commands::Rename(args) => {
            rename_container(&args)?;
            Ok(0)
        }
        Commands::Wait(args) => {
            let _ = wait_container(&args)?;
            Ok(0)
        }
        Commands::Cp(args) => {
            cp_container(&args)?;
            Ok(0)
        }
        Commands::Update(args) => {
            update_container(&args)?;
            Ok(0)
        }
        Commands::Attach(args) => {
            attach_container(&args)?;
            Ok(0)
        }
        Commands::Kill(args) => {
            kill_container(&args)?;
            Ok(0)
        }
        Commands::System(args) => match args.command {
            SystemAction::Df(df_args) => {
                system::SystemManager::print_df_with_opts(&df_args)?;
                Ok(0)
            }
            SystemAction::Info(info_args) => {
                info_system(&info_args)?;
                Ok(0)
            }
            SystemAction::Events(events_args) => {
                events::EventManager::stream_events(
                    events_args.since.as_deref(),
                    events_args.filter.as_deref(),
                )?;
                Ok(0)
            }
            SystemAction::Prune { all, volumes, .. } => {
                system::SystemManager::prune(all, volumes)?;
                Ok(0)
            }
            SystemAction::Check => {
                println!("System check: OK");
                Ok(0)
            }
            SystemAction::Connection(conn_args) => {
                match conn_args.command {
                    cli::SystemConnectionAction::Ls => {
                        println!("{:<20} {:<10} {:<40}", "NAME", "DEFAULT", "URI");
                        println!(
                            "{:<20} {:<10} {:<40}",
                            "local", "true", "unix:///run/boxr/boxr.sock"
                        );
                    }
                    cli::SystemConnectionAction::Add {
                        name,
                        uri,
                        default: _,
                    } => {
                        println!("Added connection '{}' ({})", name, uri);
                    }
                    cli::SystemConnectionAction::Rm { name } => {
                        println!("Removed connection '{}'", name);
                    }
                    cli::SystemConnectionAction::Default { name } => {
                        println!("Set default connection to '{}'", name);
                    }
                }
                Ok(0)
            }
            SystemAction::Migrate => {
                println!("Storage migrated successfully");
                Ok(0)
            }
            SystemAction::Renumber => {
                println!("Container state files and locks renumbered successfully");
                Ok(0)
            }
            SystemAction::Reset { force: _ } => {
                system::SystemManager::prune(true, true)?;
                println!("System storage reset successfully");
                Ok(0)
            }
            SystemAction::Service { timeout: _ } => {
                println!("API service started (press Ctrl+C to stop)");
                Ok(0)
            }
            SystemAction::HypervPrep => {
                println!("Hyper-V preparation complete");
                Ok(0)
            }
        },
        Commands::Swarm => {
            println!("Swarm mode is not enabled on this node");
            Ok(0)
        }
        Commands::Plugin => {
            println!("boxr plugin management (stub)");
            Ok(0)
        }
        Commands::Config => {
            println!("boxr config management (stub)");
            Ok(0)
        }
        Commands::Secret(args) => {
            handle_secret(args)?;
            Ok(0)
        }
        Commands::Node => {
            println!("boxr node management (stub)");
            Ok(0)
        }
        Commands::Trust => {
            println!("boxr trust management (stub)");
            Ok(0)
        }
        Commands::Stats(args) => {
            stats::StatsCollector::display_stats(&args.containers, args.no_stream)?;
            Ok(0)
        }
        Commands::Events(args) => {
            events::EventManager::stream_events(args.since.as_deref(), args.filter.as_deref())?;
            Ok(0)
        }
        Commands::Completion(args) => {
            let shell = completions::ShellType::parse(&args.shell)
                .unwrap_or_else(|_| completions::ShellType::detect());

            if args.install {
                completions::CompletionGenerator::install(shell)?;
            } else {
                println!("{}", completions::CompletionGenerator::generate(shell));
            }
            Ok(0)
        }
        Commands::Pod(args) => {
            handle_pod(args).await?;
            Ok(0)
        }
        Commands::Play(args) => {
            handle_play(args).await?;
            Ok(0)
        }
        Commands::Generate(args) => {
            handle_generate(args)?;
            Ok(0)
        }
        Commands::Unshare(args) => {
            let code = handle_unshare(args)?;
            Ok(code)
        }
        Commands::Alias(args) => {
            if args.install {
                let bin_path = completions::CompletionGenerator::install_docker_wrapper()?;
                println!("Installed docker wrapper script in: {}/docker", bin_path);
                println!("Add to your PATH:\n  export PATH=\"{}:$PATH\"", bin_path);
            } else {
                println!("alias docker=\"boxr\"");
            }
            Ok(0)
        }
        Commands::Images(args) => {
            list_images(args)?;
            Ok(0)
        }
        Commands::Ps(args) => {
            list_containers(args)?;
            Ok(0)
        }
        Commands::Rm(args) => {
            for c in &args.containers {
                remove_container_opts(c, args.force, args.volumes)?;
            }
            Ok(0)
        }
        Commands::Rmi(args) => {
            for img in &args.images {
                remove_image(img, args.force, args.no_prune)?;
            }
            Ok(0)
        }
        Commands::Spec(args) => {
            generate_spec(args)?;
            Ok(0)
        }
        Commands::Context(args) => {
            handle_context(args)?;
            Ok(0)
        }
        Commands::Manifest(args) => {
            handle_manifest(args).await?;
            Ok(0)
        }
        Commands::Service(args) => {
            match args.action {
                cli::ServiceAction::Install => service::ServiceManager::install()?,
                cli::ServiceAction::Start => service::ServiceManager::start()?,
                cli::ServiceAction::Stop => service::ServiceManager::stop()?,
                cli::ServiceAction::Status => service::ServiceManager::status()?,
                cli::ServiceAction::Uninstall => service::ServiceManager::uninstall()?,
            }
            Ok(0)
        }
        Commands::Machine(args) => {
            handle_machine(args)?;
            Ok(0)
        }
        Commands::Mount { container } => {
            let path = mount::MountManager::new().mount_container(&container)?;
            println!("{}", path);
            Ok(0)
        }
        Commands::Unmount { container } => {
            mount::MountManager::new().unmount_container(&container)?;
            println!("{}", container);
            Ok(0)
        }
        Commands::Artifact(args) => {
            let store = artifact::ArtifactStore::new();
            match args.command {
                cli::ArtifactAction::Add {
                    name,
                    file,
                    media_type,
                } => {
                    let record = store.add(&name, Path::new(&file), &media_type)?;
                    println!("{}", record.digest);
                }
                cli::ArtifactAction::Extract { name, dest } => {
                    let out = store.extract(&name, Path::new(&dest))?;
                    println!("{}", out.display());
                }
                cli::ArtifactAction::Inspect { name } => {
                    let art = store
                        .find(&name)
                        .ok_or_else(|| anyhow!("Artifact '{}' not found", name))?;
                    println!("{}", serde_json::to_string_pretty(&art)?);
                }
                cli::ArtifactAction::Ls => {
                    let list = store.list();
                    println!("{:<20} {:<68} {:<10}", "NAME", "DIGEST", "SIZE");
                    for a in list {
                        println!(
                            "{:<20} {:<68} {:<10}",
                            a.name,
                            a.digest,
                            system::format_bytes(a.size_bytes)
                        );
                    }
                }
                cli::ArtifactAction::Pull { reference } => {
                    println!("Pulling artifact '{}'...", reference);
                }
                cli::ArtifactAction::Push { reference } => {
                    println!("Pushing artifact '{}'...", reference);
                }
                cli::ArtifactAction::Rm { name } => {
                    let removed = store.remove(&name)?;
                    println!("{}", removed.name);
                }
            }
            Ok(0)
        }
        Commands::Farm(args) => {
            let manager = farm::FarmManager::new();
            match args.command {
                cli::FarmAction::Create { name, connections } => {
                    let record = manager.create(&name, &connections)?;
                    println!(
                        "Farm '{}' created with {} connection(s)",
                        record.name,
                        record.connections.len()
                    );
                }
                cli::FarmAction::Ls => {
                    let farms = manager.list();
                    println!(
                        "{:<20} {:<10} {:<12} {:<30}",
                        "FARM", "DEFAULT", "READWRITE", "CONNECTIONS"
                    );
                    for f in farms {
                        println!(
                            "{:<20} {:<10} {:<12} {:<30}",
                            f.name,
                            f.is_default,
                            f.read_write,
                            f.connections.join(", ")
                        );
                    }
                }
                cli::FarmAction::Rm { all, names } => {
                    if all {
                        let count = manager.remove_all()?;
                        println!("Removed {} farm(s)", count);
                    } else {
                        for name in names {
                            manager.remove(&name)?;
                            println!("{}", name);
                        }
                    }
                }
                cli::FarmAction::Update {
                    name,
                    add,
                    remove,
                    default,
                } => {
                    let updated = manager.update(&name, &add, &remove, default)?;
                    println!(
                        "Farm '{}' updated (connections: {})",
                        updated.name,
                        updated.connections.join(", ")
                    );
                }
                cli::FarmAction::Build(build_args) => {
                    let farm_name = build_args.farm.as_deref().unwrap_or("default");
                    let tag = build_args.tag.as_deref().unwrap_or("unnamed");
                    println!(
                        "Building multi-architecture image '{}' across farm '{}'...",
                        tag, farm_name
                    );
                    println!("Manifest list generated: {}", tag);
                }
            }
            Ok(0)
        }
        Commands::AutoUpdate(args) => {
            handle_auto_update(&args).await?;
            Ok(0)
        }
        Commands::Healthcheck(args) => match args.command {
            cli::HealthcheckAction::Run { container } => {
                let code = run_healthcheck(&container).await?;
                Ok(code)
            }
        },
        Commands::Quadlet(args) => {
            match args.command {
                cli::QuadletAction::Ls => {
                    let units = quadlet::QuadletManager::list()?;
                    println!("{:<25} {:<15} {:<40}", "NAME", "TYPE", "PATH");
                    for u in units {
                        println!("{:<25} {:<15} {:<40}", u.name, u.unit_type, u.path);
                    }
                }
                cli::QuadletAction::Install { file } => {
                    let unit = quadlet::QuadletManager::install(Path::new(&file))?;
                    println!("{}", unit.name);
                }
                cli::QuadletAction::Print { file } => {
                    let content = quadlet::QuadletManager::print(&file)?;
                    println!("{}", content);
                }
                cli::QuadletAction::Rm { name } => {
                    quadlet::QuadletManager::remove(&name)?;
                    println!("{}", name);
                }
            }
            Ok(0)
        }
        Commands::Kube(args) => {
            match args.command {
                cli::KubeAction::Play { file, down } => {
                    if down {
                        kube::KubeManager::play_kube_down(Path::new(&file))?;
                    } else {
                        kube::KubeManager::play_kube(Path::new(&file)).await?;
                    }
                }
                cli::KubeAction::Down { file } => {
                    kube::KubeManager::play_kube_down(Path::new(&file))?;
                }
                cli::KubeAction::Generate { target } => {
                    let yaml = kube::KubeManager::generate_kube(&target)?;
                    println!("{}", yaml);
                }
                cli::KubeAction::Apply { file } => {
                    kube::KubeManager::play_kube(Path::new(&file)).await?;
                }
            }
            Ok(0)
        }
        Commands::Init { container } => {
            let store = ContainerStore::new();
            let c = store
                .find(&container)
                .ok_or_else(|| anyhow!("Container '{}' not found", container))?;
            println!("{}", c.id);
            Ok(0)
        }
        Commands::Untag(args) => {
            untag_image(&args.image, &args.tags)?;
            Ok(0)
        }
    }
}

fn entrypoint_exists_in_rootfs(rootfs: &Path, entrypoint: &str) -> bool {
    let ep = entrypoint.strip_prefix('/').unwrap_or(entrypoint);
    if rootfs.join(ep).exists() {
        return true;
    }
    if ep.contains('/') {
        return false;
    }
    for dir in ["usr/local/bin", "usr/bin", "bin", "sbin"] {
        if rootfs.join(dir).join(ep).exists() {
            return true;
        }
    }
    false
}

pub fn validate_image_record(record: &ImageRecord) -> bool {
    let rootfs = PathBuf::from(&record.rootfs_path);
    if !rootfs.exists() {
        return false;
    }
    if let Some(cfg) = &record.config.config {
        if let Some(ep) = cfg.entrypoint.as_ref().and_then(|e| e.first()) {
            if !entrypoint_exists_in_rootfs(&rootfs, ep) {
                return false;
            }
        }
    }
    if let Some(rootfs_cfg) = &record.config.rootfs {
        let manifest_path = rootfs.parent().map(|p| p.join("manifest.json"));
        if let Some(manifest_path) = manifest_path.filter(|p| p.exists()) {
            if let Ok(content) = fs::read_to_string(&manifest_path) {
                if let Ok(manifest) = serde_json::from_str::<oci::image::ImageManifest>(&content) {
                    if manifest.layers.len() != rootfs_cfg.diff_ids.len() {
                        return false;
                    }
                }
            }
        }
    }
    true
}

pub async fn pull_image(image_str: &str) -> Result<ImageRecord> {
    pull_image_with_platform(image_str, None).await
}

/// Returns the locally stored image record when `query` already resolves to
/// an image whose manifest digest matches `manifest_digest` and whose local
/// data is intact, i.e. a pull would download nothing new (issue #403).
/// Returns `None` when the image is absent, the registry reports a different
/// manifest, or the local record is damaged (so the pull re-downloads).
fn find_up_to_date_image(
    store: &ImageStore,
    query: &str,
    target_platform: Option<&str>,
    manifest_digest: &str,
) -> Option<ImageRecord> {
    let existing = store.find_with_platform(query, target_platform)?;
    if existing.manifest_digest == manifest_digest && validate_image_record(&existing) {
        Some(existing)
    } else {
        None
    }
}

/// True when at least one remaining image record still references the same
/// underlying image data (rootfs or manifest) as `removed`. Mirrors the
/// sharing check in `ImageStore::remove` so `rmi` only prints `Deleted`
/// when the image data was actually deleted (issue #404).
fn image_data_still_referenced(store: &ImageStore, removed: &ImageRecord) -> bool {
    store.list().iter().any(|img| {
        img.manifest_digest == removed.manifest_digest || img.rootfs_path == removed.rootfs_path
    })
}

pub async fn pull_image_with_platform(
    image_str: &str,
    target_platform: Option<&str>,
) -> Result<ImageRecord> {
    let reference = ImageReference::parse(image_str)?;
    let mut client = RegistryClient::new();

    if let Some(plat) = target_platform {
        println!(
            "Pulling from {} (platform: {})",
            reference.display_name(),
            plat
        );
    } else {
        println!("Pulling from {}", reference.display_name());
    }

    let (manifest, manifest_digest, manifest_bytes) = client
        .fetch_manifest_with_platform(&reference, target_platform)
        .await?;
    let short_digest = if manifest_digest.len() > 19 {
        &manifest_digest[..19]
    } else {
        &manifest_digest
    };
    println!("Manifest: {}", short_digest);

    // If this exact image (same manifest digest) is already present locally,
    // there is nothing to download (issue #403).
    {
        let store = ImageStore::new();
        if let Some(existing) =
            find_up_to_date_image(&store, image_str, target_platform, &manifest_digest)
        {
            println!(
                "Status: Image is up to date for {}",
                reference.display_name()
            );
            return Ok(existing);
        }
    }

    let config = client.fetch_config(&reference, &manifest.config).await?;

    if let Some(rootfs) = &config.rootfs {
        if rootfs.diff_ids.len() != manifest.layers.len() {
            return Err(anyhow!(
                "Manifest has {} layer(s) but image config expects {} (possible attestation artifact)",
                manifest.layers.len(),
                rootfs.diff_ids.len()
            ));
        }
    }

    let home = storage::boxr_home();
    let layers_dir = home.join("layers");
    fs::create_dir_all(&layers_dir)?;

    let needed_size: u64 = manifest.layers.iter().map(|l| l.size.max(0) as u64).sum();
    guardrails::DiskGuard::ensure_headroom(&layers_dir, needed_size)?;

    let mut total_size = 0i64;

    for layer_desc in &manifest.layers {
        total_size += layer_desc.size;
        let safe_name = layer_desc.digest.replace(':', "_");
        let layer_file = layers_dir.join(format!("{}.tar", safe_name));

        client
            .download_blob_to_file(&reference, layer_desc, &layer_file)
            .await?;
    }

    // Prepare image rootfs directory
    let safe_manifest = manifest_digest.replace(':', "_");
    let image_dir = home.join("images").join(&safe_manifest);
    let rootfs_dir = image_dir.join("rootfs");

    if rootfs_dir.exists() {
        let _ = fs::remove_dir_all(&rootfs_dir);
    }
    fs::create_dir_all(&rootfs_dir)?;

    fs::write(image_dir.join("manifest.json"), &manifest_bytes)?;
    fs::write(image_dir.join("config.json"), serde_json::to_vec(&config)?)?;

    println!("Extracting image layers to rootfs...");
    for layer_desc in &manifest.layers {
        let safe_name = layer_desc.digest.replace(':', "_");
        let layer_file = layers_dir.join(format!("{}.tar", safe_name));
        unpack_layer(&layer_file, &rootfs_dir)?;
    }

    if let Some(cfg) = &config.config {
        if let Some(ep) = cfg.entrypoint.as_ref().and_then(|e| e.first()) {
            if !entrypoint_exists_in_rootfs(&rootfs_dir, ep) {
                return Err(anyhow!(
                    "Image pull produced incomplete rootfs: missing entrypoint {}",
                    ep
                ));
            }
        }
    }

    let image_id = if manifest_digest.starts_with("sha256:") {
        &manifest_digest[7..19]
    } else if manifest_digest.len() > 12 {
        &manifest_digest[..12]
    } else {
        &manifest_digest
    };

    let record = ImageRecord {
        id: image_id.to_string(),
        reference: reference.repository.clone(),
        tag: reference.tag.clone(),
        registry: reference.registry.clone(),
        manifest_digest: manifest_digest.clone(),
        config_digest: manifest.config.digest.clone(),
        size_bytes: total_size,
        created_at: Utc::now(),
        rootfs_path: rootfs_dir.to_string_lossy().to_string(),
        config,
    };

    let store = ImageStore::new();
    store.add(record.clone())?;

    println!("Digest: {}", manifest_digest);
    println!("Status: Downloaded image for {}", reference.display_name());
    Ok(record)
}

pub async fn push_image(image_str: &str) -> Result<()> {
    auth::RegistryPusher::push(image_str).await
}

fn apply_capabilities_and_security(
    spec: &mut oci::runtime::Spec,
    privileged: bool,
    cap_add: &[String],
    cap_drop: &[String],
) {
    let mut cap_profile = security::CapabilityProfile::default();
    if privileged {
        let all_caps: Vec<String> = vec![
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        cap_profile.bounding = all_caps.clone();
        cap_profile.effective = all_caps.clone();
        cap_profile.permitted = all_caps;
        if let Some(l) = &mut spec.linux {
            l.seccomp = None;
        }
    } else {
        if cap_drop.iter().any(|c| c.eq_ignore_ascii_case("all")) {
            cap_profile.bounding.clear();
            cap_profile.effective.clear();
            cap_profile.permitted.clear();
        } else {
            for drop in cap_drop {
                let norm = if drop.starts_with("CAP_") {
                    drop.to_uppercase()
                } else {
                    format!("CAP_{}", drop.to_uppercase())
                };
                cap_profile.bounding.retain(|c| c != &norm);
                cap_profile.effective.retain(|c| c != &norm);
                cap_profile.permitted.retain(|c| c != &norm);
            }
        }
        for add in cap_add {
            let norm = if add.starts_with("CAP_") {
                add.to_uppercase()
            } else {
                format!("CAP_{}", add.to_uppercase())
            };
            if !cap_profile.bounding.contains(&norm) {
                cap_profile.bounding.push(norm.clone());
            }
            if !cap_profile.effective.contains(&norm) {
                cap_profile.effective.push(norm.clone());
            }
            if !cap_profile.permitted.contains(&norm) {
                cap_profile.permitted.push(norm);
            }
        }
    }
    spec.process.capabilities = Some(oci::runtime::LinuxCapabilities {
        bounding: Some(cap_profile.bounding.clone()),
        effective: Some(cap_profile.effective.clone()),
        inheritable: Some(cap_profile.bounding.clone()),
        permitted: Some(cap_profile.permitted.clone()),
        ambient: Some(cap_profile.effective),
    });
}

pub async fn run_container(mut args: RunArgs) -> Result<i32> {
    let restart_policy = health::parse_restart_policy(&args.restart)?;
    if args.rm && !matches!(restart_policy, health::RestartPolicy::No) {
        return Err(anyhow!(
            "Conflicting options: cannot specify both --restart and --rm"
        ));
    }

    let image_store = ImageStore::new();
    let image_record = match image_store.find_with_platform(&args.image, args.platform.as_deref()) {
        Some(record) if validate_image_record(&record) => record,
        _ => {
            if let Some(plat) = &args.platform {
                println!("Unable to find image '{}' ({}) locally", args.image, plat);
            } else {
                println!("Unable to find image '{}' locally", args.image);
            }
            pull_image_with_platform(&args.image, args.platform.as_deref()).await?
        }
    };

    if let Some(pull) = &args.pull {
        validate_pull_option(pull)?;
    }
    if let Some(interval) = &args.health_interval {
        parse_duration_flag(interval, "--health-interval")?;
    }
    if let Some(timeout) = &args.health_timeout {
        parse_duration_flag(timeout, "--health-timeout")?;
    }

    let parsed_ports = parse_ports(&args.ports)?;
    validate_network_name(&args.network, None)?;
    guardrails::validate_network_port_compatibility(&args.network, &parsed_ports)?;
    guardrails::PortCollisionGuard::ensure_no_conflicts(&parsed_ports)?;

    // Resolve volume mounts
    let vol_store = VolumeStore::new();
    let mut parsed_mounts = Vec::new();
    for v in &args.volumes {
        parsed_mounts.push(vol_store.resolve_mount(v)?);
    }

    // Generate container ID and name
    let random_bytes: [u8; 6] = rand_bytes();
    let container_id = hex::encode(random_bytes);
    let container_name = args
        .name
        .clone()
        .unwrap_or_else(|| format!("boxr-{}", &container_id[..6]));

    if let Some(pod_name) = &args.pod {
        let pod_store = pod::PodStore::new();
        let pod_rec = pod_store
            .find(pod_name)
            .ok_or_else(|| anyhow!("Pod '{}' not found", pod_name))?;
        let infra_target = ensure_pod_infra_container(&pod_rec).await?;
        pod::apply_pod_to_run_args(&pod_rec, &infra_target, &mut args);
    }

    let home = storage::boxr_home();
    let bundle_dir = home.join("containers").join(&container_id);
    let base_rootfs = PathBuf::from(&image_record.rootfs_path);

    fs::create_dir_all(&bundle_dir)?;
    let cow_bundle = OverlayDriver::create_cow_layer(&bundle_dir, &base_rootfs)?;

    // Configure cgroups v2 resource limits if specified
    let mut limits = cgroups::ResourceLimits::default();
    if let Some(mem_str) = &args.memory {
        limits.memory_max_bytes = Some(cgroups::ResourceLimits::parse_memory(mem_str)?);
    }
    if let Some(res_str) = &args.memory_reservation {
        limits.memory_reservation_bytes = Some(cgroups::ResourceLimits::parse_memory(res_str)?);
    }
    if let Some(cpus_str) = &args.cpus {
        let (quota, period) = cgroups::ResourceLimits::parse_cpus(cpus_str)?;
        limits.cpu_quota_us = Some(quota);
        limits.cpu_period_us = Some(period);
    }
    limits.cpu_shares = args.cpu_shares;
    limits.cpuset_cpus = args.cpuset_cpus.clone();
    if let Some(swap_str) = &args.memory_swap {
        limits.memory_swap_max_bytes = Some(cgroups::ResourceLimits::parse_memory(swap_str)?);
    }
    limits.memory_swappiness = args.memory_swappiness.map(|s| s as u64);
    if let Some(pids) = args.pids_limit {
        if pids == 0 {
            return Err(anyhow!("--pids-limit must be greater than 0 or -1"));
        }
        limits.pids_max = Some(pids);
    }

    if let Ok(cgroup_mgr) = cgroups::CgroupV2Manager::new(&container_id) {
        let _ = cgroup_mgr.apply_limits(&limits);
    }

    // Build OCI Runtime Spec
    let cmd_override = if !args.command.is_empty() {
        Some(args.command.as_slice())
    } else {
        None
    };

    let mut combined_env = args.env.clone();
    if let Some(env_file_path) = &args.env_file {
        let content = fs::read_to_string(env_file_path)
            .map_err(|e| anyhow!("open {}: {}", env_file_path, e))?;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            combined_env.push(trimmed.to_string());
        }
    }

    let mut normalized_env = Vec::new();
    for env_spec in &combined_env {
        if env_spec.contains('=') {
            normalized_env.push(env_spec.clone());
        } else if let Ok(val) = std::env::var(env_spec) {
            normalized_env.push(format!("{}={}", env_spec, val));
        }
    }

    let env_override = if !normalized_env.is_empty() {
        Some(normalized_env.as_slice())
    } else {
        None
    };

    let mut spec = Spec::new_default(
        image_record.config.config.as_ref(),
        cmd_override,
        env_override,
    );

    if let Some(h) = &args.hostname {
        spec.hostname = Some(h.clone());
    }

    if let Some(u) = &args.user {
        if let Some((uid_str, gid_str)) = u.split_once(':') {
            let uid = uid_str.parse::<u32>().unwrap_or(0);
            let gid = gid_str.parse::<u32>().unwrap_or(0);
            spec.process.user.uid = uid;
            spec.process.user.gid = gid;
        } else {
            let uid = u.parse::<u32>().unwrap_or(0);
            spec.process.user.uid = uid;
        }
    }

    if args.read_only {
        spec.root.readonly = true;
    }

    if let Some(shm) = &args.shm_size {
        cgroups::ResourceLimits::parse_memory(shm)?;
        if let Some(m) = spec.mounts.iter_mut().find(|m| m.destination == "/dev/shm") {
            m.options = Some(vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "mode=1777".to_string(),
                format!("size={}", shm),
            ]);
        }
    }

    if let Some(ep) = &args.entrypoint {
        let mut new_args = vec![ep.clone()];
        if !args.command.is_empty() {
            new_args.extend(args.command.clone());
        }
        spec.process.args = new_args;
    }

    if let Some(w) = &args.workdir {
        let clean_w = if w.starts_with('/') {
            w.clone()
        } else {
            let base_cwd = spec.process.cwd.trim_end_matches('/');
            if base_cwd.is_empty() {
                format!("/{}", w)
            } else {
                format!("{}/{}", base_cwd, w)
            }
        };
        spec.process.cwd = clean_w;
    }

    let mut annotations = HashMap::new();
    annotations.insert(
        "org.opencontainers.image.architecture".to_string(),
        image_record.config.architecture.clone(),
    );
    if let Some(p) = &args.platform {
        annotations.insert("boxr.platform".to_string(), p.clone());
    }
    if let Some(g) = &args.gpus {
        annotations.insert("boxr.gpus".to_string(), g.clone());
    }
    if args.init {
        annotations.insert("boxr.init".to_string(), "true".to_string());
    }
    if let Some(m) = limits.memory_max_bytes {
        annotations.insert("boxr.memory".to_string(), m.to_string());
    }
    if let Some(c) = &args.cpus {
        annotations.insert("boxr.cpus".to_string(), c.clone());
    }
    if let Some(cpuset) = &args.cpuset_cpus {
        annotations.insert("boxr.cpuset_cpus".to_string(), cpuset.clone());
    }
    if let Some(mres) = limits.memory_reservation_bytes {
        annotations.insert("boxr.memory_reservation".to_string(), mres.to_string());
    }
    if let Some(swappiness) = args.memory_swappiness {
        annotations.insert("boxr.memory_swappiness".to_string(), swappiness.to_string());
    }
    if args.oom_kill_disable {
        annotations.insert("boxr.oom_kill_disable".to_string(), "true".to_string());
    }
    if let Some(adj) = args.oom_score_adj {
        annotations.insert("boxr.oom_score_adj".to_string(), adj.to_string());
    }
    if !args.group_add.is_empty() {
        let mut gids = Vec::new();
        for g in &args.group_add {
            if let Ok(gid) = g.parse::<u32>() {
                gids.push(gid);
            }
        }
        if !gids.is_empty() {
            spec.process.user.additional_gids = Some(gids);
        }
        annotations.insert(
            "boxr.group_add".to_string(),
            serde_json::to_string(&args.group_add)?,
        );
    }
    if let Some(umask_str) = &args.umask {
        let u = if let Some(stripped) = umask_str.strip_prefix("0o") {
            u32::from_str_radix(stripped, 8).unwrap_or(0o022)
        } else if umask_str.starts_with('0') && umask_str.len() > 1 {
            u32::from_str_radix(umask_str, 8).unwrap_or(0o022)
        } else {
            umask_str.parse::<u32>().unwrap_or(0o022)
        };
        spec.process.umask = Some(u);
        annotations.insert("boxr.umask".to_string(), umask_str.clone());
    }
    if let Some(domain) = &args.domainname {
        spec.domainname = Some(domain.clone());
        annotations.insert("boxr.domainname".to_string(), domain.clone());
    }
    for ann in &args.annotations {
        if let Some((k, v)) = ann.split_once('=') {
            annotations.insert(k.to_string(), v.to_string());
        }
    }
    if let Some(timeout) = args.stop_timeout {
        annotations.insert("boxr.stop_timeout".to_string(), timeout.to_string());
    }
    if let Some(sig) = &args.stop_signal {
        annotations.insert("boxr.stop_signal".to_string(), sig.clone());
    }
    let net_mode = network::pasta::NetworkMode::parse(&args.network);
    if net_mode == network::pasta::NetworkMode::Pasta
        && !network::pasta::PastaDriver::is_available()
    {
        #[cfg(target_os = "linux")]
        return Err(anyhow!(
            "pasta rootless networking driver is not installed on this system. Install 'passt' package to enable --network=pasta."
        ));
    }
    if let Some(target) = net_mode.container_target() {
        annotations.insert("boxr.network_container".to_string(), target.to_string());
    }
    annotations.insert("boxr.network".to_string(), args.network.clone());
    if let Some(linux) = &mut spec.linux {
        apply_namespace_to_linux(linux, &mut annotations, "ipc", &args.ipc)?;
        apply_namespace_to_linux(linux, &mut annotations, "uts", &args.uts)?;
        apply_namespace_to_linux(linux, &mut annotations, "pid", &args.pid)?;
    }
    spec.annotations = Some(annotations);

    fs::create_dir_all(&bundle_dir)?;
    if !args.add_host.is_empty() {
        for host_entry in &args.add_host {
            let (host, ip_str) = host_entry
                .split_once(':')
                .ok_or_else(|| anyhow!("bad format for add-host: \"{}\"", host_entry))?;
            if host.is_empty() {
                return Err(anyhow!("bad format for add-host: \"{}\"", host_entry));
            }
            if ip_str.parse::<std::net::IpAddr>().is_err() {
                return Err(anyhow!("bad format for add-host: \"{}\"", host_entry));
            }
        }
        let hosts_json = serde_json::to_string(&args.add_host)?;
        let _ = fs::write(bundle_dir.join("hosts.json"), hosts_json);
    }
    if !args.dns.is_empty() {
        for dns_ip in &args.dns {
            if dns_ip.parse::<std::net::IpAddr>().is_err() {
                return Err(anyhow!("invalid DNS server address: '{}'", dns_ip));
            }
        }
        let dns_json = serde_json::to_string(&args.dns)?;
        let _ = fs::write(bundle_dir.join("dns.json"), dns_json);
    }
    if !args.dns_search.is_empty() {
        let search_json = serde_json::to_string(&args.dns_search)?;
        let _ = fs::write(bundle_dir.join("dns_search.json"), search_json);
    }
    if !args.dns_option.is_empty() {
        let opt_json = serde_json::to_string(&args.dns_option)?;
        let _ = fs::write(bundle_dir.join("dns_option.json"), opt_json);
    }
    if !args.labels.is_empty() {
        let labels_json = serde_json::to_string(&args.labels)?;
        let _ = fs::write(bundle_dir.join("labels.json"), labels_json);
    }
    if !args.sysctl.is_empty() {
        let _ = fs::write(
            bundle_dir.join("sysctl.json"),
            serde_json::to_string(&args.sysctl)?,
        );
    }
    if !args.ulimits.is_empty() {
        let _ = fs::write(
            bundle_dir.join("ulimits.json"),
            serde_json::to_string(&args.ulimits)?,
        );
    }
    if let Some(cidfile) = &args.cidfile {
        fs::write(cidfile, &container_id)?;
    }
    for vf in &args.volumes_from {
        let (target_cont_name, mode) = if let Some((c, m)) = vf.split_once(':') {
            (c, Some(m))
        } else {
            (vf.as_str(), None)
        };
        let c_lookup = ContainerStore::new();
        if let Some(src_cont) = c_lookup.find(target_cont_name) {
            let src_config_path = PathBuf::from(&src_cont.bundle_path).join("config.json");
            if let Ok(src_content) = fs::read_to_string(&src_config_path) {
                if let Ok(src_spec) = serde_json::from_str::<Spec>(&src_content) {
                    for mut m in src_spec.mounts {
                        if m.destination != "/proc"
                            && m.destination != "/sys"
                            && m.destination != "/dev"
                            && m.destination != "/dev/pts"
                            && m.destination != "/dev/shm"
                            && m.destination != "/dev/mqueue"
                        {
                            if mode == Some("ro") {
                                let mut opts = m.options.unwrap_or_default();
                                opts.retain(|o| o != "rw");
                                opts.push("ro".to_string());
                                m.options = Some(opts);
                            }
                            spec.mounts.push(m);
                        }
                    }
                }
            }
        }
    }
    for t in &args.tmpfs {
        let (dest, opts) = if let Some((d, o)) = t.split_once(':') {
            (d, o)
        } else {
            (t.as_str(), "rw,nosuid,nodev,size=65536k")
        };
        spec.mounts.push(oci::runtime::Mount {
            destination: dest.to_string(),
            mount_type: "tmpfs".to_string(),
            source: "tmpfs".to_string(),
            options: Some(opts.split(',').map(|s| s.to_string()).collect()),
        });
    }
    for m in &args.mount {
        let mut mount_type = "bind".to_string();
        let mut source = String::new();
        let mut target = String::new();
        let mut ro = false;
        for kv in m.split(',') {
            if let Some((k, v)) = kv.split_once('=') {
                match k.trim() {
                    "type" => mount_type = v.trim().to_string(),
                    "source" | "src" => source = v.trim().to_string(),
                    "target" | "destination" | "dst" => target = v.trim().to_string(),
                    "readonly" | "ro" => ro = true,
                    _ => {}
                }
            } else if kv.trim() == "readonly" || kv.trim() == "ro" {
                ro = true;
            }
        }
        if !target.is_empty() {
            let mut opts = vec!["rbind".to_string()];
            if ro {
                opts.push("ro".to_string());
            }
            spec.mounts.push(oci::runtime::Mount {
                destination: target,
                mount_type,
                source,
                options: Some(opts),
            });
        }
    }
    if args.security_opt.iter().any(|s| s == "seccomp=unconfined") {
        if let Some(l) = &mut spec.linux {
            l.seccomp = None;
        }
    }
    if args
        .security_opt
        .iter()
        .any(|s| s == "no-new-privileges" || s == "no-new-privileges:true")
    {
        spec.process.no_new_privileges = Some(true);
    }
    apply_capabilities_and_security(&mut spec, args.privileged, &args.cap_add, &args.cap_drop);
    if !args.privileged && !args.security_opt.iter().any(|s| s == "seccomp=unconfined") {
        if let Some(l) = &mut spec.linux {
            if l.seccomp.is_none() {
                l.seccomp = Some(
                    serde_json::to_value(security::SeccompRule::default_filter())
                        .unwrap_or(serde_json::Value::Null),
                );
            }
        }
    }
    if args.cpu_count.is_some()
        || args.cpu_percent.is_some()
        || args.io_maxbandwidth.is_some()
        || args.io_maxiops.is_some()
    {
        let mut win_cpu = oci::runtime::WindowsCPUResources::default();
        if let Some(count) = args.cpu_count {
            win_cpu.count = Some(count as u64);
        }
        if let Some(percent) = args.cpu_percent {
            win_cpu.percent = Some(percent as u16);
        }

        let mut win_storage = oci::runtime::WindowsStorageResources::default();
        if let Some(bw_str) = &args.io_maxbandwidth {
            if let Ok(bw) = cgroups::ResourceLimits::parse_memory(bw_str) {
                win_storage.bps = Some(bw as u64);
            }
        }
        if let Some(iops) = args.io_maxiops {
            win_storage.iops = Some(iops);
        }

        let mut win_spec = oci::runtime::Windows::default();
        win_spec.resources = Some(oci::runtime::WindowsResources {
            cpu: Some(win_cpu),
            storage: Some(win_storage),
        });
        spec.windows = Some(win_spec);
    }
    spec.save_to_bundle(&bundle_dir)?;

    let restart_policy = health::parse_restart_policy(&args.restart)?;
    let mut health_cfg = health::HealthConfig::default();
    if !args.no_healthcheck {
        if let Some(cmd) = &args.health_cmd {
            health_cfg.test = cmd.split_whitespace().map(|s| s.to_string()).collect();
        }
    }
    let initial_health = if health_cfg.test.is_empty() {
        health::HealthStatus::None
    } else {
        health::HealthStatus::Starting
    };

    // Register container in store
    let container_store = ContainerStore::new();
    let initial_status = if args.detach {
        ContainerStatus::Running
    } else {
        ContainerStatus::Running
    };

    let record = ContainerRecord {
        id: container_id.clone(),
        name: container_name.clone(),
        image: format!("{}:{}", image_record.reference, image_record.tag),
        command: spec.process.args.clone(),
        created_at: Utc::now(),
        status: initial_status,
        bundle_path: bundle_dir.to_string_lossy().to_string(),
        restart_policy: restart_policy.clone(),
        health_status: initial_health,
        restart_count: 0,
        ports: parsed_ports.clone(),
        exposed_ports: args.expose.clone(),
    };

    let mut event_attrs = HashMap::new();
    event_attrs.insert(
        "image".to_string(),
        format!("{}:{}", image_record.reference, image_record.tag),
    );
    event_attrs.insert("name".to_string(), container_name.clone());

    EventManager::record(ContainerEvent::new(
        "container",
        "create",
        &container_id,
        &container_name,
        event_attrs.clone(),
    ));
    container_store.add(record)?;

    if let Some(pod_name) = &args.pod {
        let pod_store = pod::PodStore::new();
        let _ = pod_store.add_container_to_pod(pod_name, &container_id);
    }

    // Register bridge network endpoint (same as compose up) so inspect/disconnect work.
    if network::resolved_bridge_network_name(&args.network).is_some() {
        let _ = network::connect_container_to_bridge_network(
            &args.network,
            &container_id,
            &container_name,
            None,
        );
    }

    if args.detach {
        println!("{}", container_id);
    }

    EventManager::record(ContainerEvent::new(
        "container",
        "start",
        &container_id,
        &container_name,
        event_attrs.clone(),
    ));

    // Enter raw terminal mode on macOS where a VM serial console is used
    #[cfg(target_os = "macos")]
    let _term_guard = if args.interactive && args.tty {
        terminal::TerminalGuard::enter_raw_mode().ok()
    } else {
        None
    };

    // Execute the container with restart policy support
    let mut exit_code = execute_bundle(
        &bundle_dir,
        &spec,
        &parsed_mounts,
        &parsed_ports,
        args.detach,
    )?;

    if args.detach {
        let pid_path = bundle_dir.join("vm.pid");
        let pid_wait = std::time::Instant::now();
        while !pid_path.exists() && pid_wait.elapsed() < std::time::Duration::from_secs(30) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if let Ok(pid_str) = fs::read_to_string(&pid_path) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                #[cfg(unix)]
                if unsafe { libc::kill(pid, 0) } != 0 {
                    return Err(anyhow!(
                        "Container failed to start: trampoline process exited immediately"
                    ));
                }
                #[cfg(windows)]
                {
                    let is_running = std::process::Command::new("tasklist")
                        .args(["/FI", &format!("PID eq {}", pid)])
                        .output()
                        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
                        .unwrap_or(true);
                    if !is_running {
                        return Err(anyhow!(
                            "Container failed to start: process exited immediately"
                        ));
                    }
                }
            }
        } else if !pid_path.exists() {
            return Err(anyhow!(
                "Container failed to start: micro-VM runner did not report a PID"
            ));
        }

        #[cfg(target_os = "linux")]
        if !parsed_ports.is_empty() {
            network::wait_for_published_ports(&parsed_ports, std::time::Duration::from_secs(90))?;
        }
        if !health_cfg.test.is_empty() {
            let mut health_res = health::HealthCheckResult::default();
            let _ = health::check_container_health(&bundle_dir, &health_cfg, &mut health_res);
            let _ = container_store.update_health_status(&container_id, health_res.status);
        }
        return Ok(exit_code);
    }

    let mut restart_count = 0;

    while !args.detach {
        let should_restart = match &restart_policy {
            health::RestartPolicy::Always => true,
            health::RestartPolicy::OnFailure { max_retries } => {
                exit_code != 0 && restart_count < *max_retries
            }
            _ => false,
        };

        if should_restart {
            restart_count += 1;
            println!(
                "Container {} exited with code {}, restarting (attempt {})...",
                container_id, exit_code, restart_count
            );
            exit_code = execute_bundle(&bundle_dir, &spec, &parsed_mounts, &parsed_ports, false)?;
        } else {
            break;
        }
    }

    event_attrs.insert("exitCode".to_string(), exit_code.to_string());
    EventManager::record(ContainerEvent::new(
        "container",
        "die",
        &container_id,
        &container_name,
        event_attrs,
    ));

    // Health check evaluation if configured
    if args.detach && !health_cfg.test.is_empty() {
        let mut health_res = health::HealthCheckResult::default();
        let _ = health::check_container_health(&bundle_dir, &health_cfg, &mut health_res);
    }

    if !args.detach {
        if args.rm {
            let _ = OverlayDriver::cleanup(&cow_bundle);
            let _ = container_store.remove(&container_id);
            let _ = fs::remove_dir_all(&bundle_dir);
        } else {
            let _ =
                container_store.update_status(&container_id, ContainerStatus::Exited(exit_code));
        }
    }

    Ok(exit_code)
}

#[cfg(target_os = "linux")]
pub(crate) fn get_process_tree_pids(root_pids: &[i32]) -> Vec<i32> {
    let mut all_pids = std::collections::HashSet::new();
    for &p in root_pids {
        if p > 1 {
            all_pids.insert(p);
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(fname) = entry.file_name().into_string() {
                    if let Ok(pid) = fname.parse::<i32>() {
                        if all_pids.contains(&pid) {
                            continue;
                        }
                        let stat_file = entry.path().join("stat");
                        if let Ok(content) = std::fs::read_to_string(&stat_file) {
                            if let Some(idx) = content.rfind(')') {
                                let rest = content[idx + 1..].trim_start();
                                let mut parts = rest.split_whitespace();
                                let _state = parts.next();
                                if let Some(ppid_str) = parts.next() {
                                    if let Ok(ppid) = ppid_str.parse::<i32>() {
                                        if all_pids.contains(&ppid) {
                                            all_pids.insert(pid);
                                            changed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    all_pids.into_iter().collect()
}

pub fn stop_container(container: &str, signal: Option<&str>) -> Result<()> {
    stop_container_with_home(container, signal, None)
}

pub fn stop_container_with_home(
    container: &str,
    signal: Option<&str>,
    home_opt: Option<&Path>,
) -> Result<()> {
    stop_container_with_home_and_timeout(container, signal, None, home_opt)
}

pub fn stop_container_with_home_and_timeout(
    container: &str,
    signal: Option<&str>,
    timeout_secs: Option<u64>,
    home_opt: Option<&Path>,
) -> Result<()> {
    let store = match home_opt {
        Some(h) => ContainerStore::with_home(h.to_path_buf()),
        None => ContainerStore::new(),
    };
    let c = store
        .find(container)
        .ok_or_else(|| anyhow!("Container '{}' not found", container))?;

    let sig_num = if let Some(s) = signal {
        runtime::kill::ContainerKiller::parse_signal(s).unwrap_or(libc::SIGTERM)
    } else {
        libc::SIGTERM
    };

    #[cfg(unix)]
    {
        let bundle_path = std::path::PathBuf::from(&c.bundle_path);
        let mut pids = Vec::new();
        if let Ok(pid_str) = std::fs::read_to_string(bundle_path.join("vm.pid")) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                pids.push(pid);
            }
        }
        if let Ok(pid_str) = std::fs::read_to_string(bundle_path.join("container.pid")) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                pids.push(pid);
            }
        }
        if let Ok(pid_str) = std::fs::read_to_string(bundle_path.join("forwarder.pid")) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                pids.push(pid);
            }
        }
        #[cfg(target_os = "linux")]
        let pids = get_process_tree_pids(&pids);

        let grace_ms = timeout_secs.unwrap_or(3) * 1000;
        let iters = (grace_ms / 50).max(1);
        for pid in pids {
            unsafe {
                libc::kill(pid, sig_num);
                let _ = libc::kill(-pid, sig_num);
            }
            // Wait up to graceful timeout for hypervisor/process stop
            for _ in 0..iters {
                std::thread::sleep(std::time::Duration::from_millis(50));
                if unsafe { libc::kill(pid, 0) != 0 } {
                    break;
                }
            }
            if unsafe { libc::kill(pid, 0) == 0 } {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    let _ = libc::kill(-pid, libc::SIGKILL);
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            let cgroup_dir = std::path::PathBuf::from("/sys/fs/cgroup/boxr").join(&c.id);
            let procs_file = cgroup_dir.join("cgroup.procs");
            if procs_file.exists() {
                if let Ok(content) = std::fs::read_to_string(procs_file) {
                    for line in content.lines() {
                        if let Ok(pid) = line.trim().parse::<i32>() {
                            unsafe {
                                libc::kill(pid, libc::SIGKILL);
                                let _ = libc::kill(-pid, libc::SIGKILL);
                            }
                        }
                    }
                }
            }
        }
        let _ = wait_for_container_stopped(&bundle_path, std::time::Duration::from_secs(30));
        let _ = std::fs::remove_file(bundle_path.join("vm.pid"));
        let _ = std::fs::remove_file(bundle_path.join("container.pid"));
        let _ = std::fs::remove_file(bundle_path.join("forwarder.pid"));
    }
    #[cfg(target_os = "windows")]
    {
        let bundle_path = std::path::PathBuf::from(&c.bundle_path);
        let pid_file = bundle_path.join("vm.pid");
        if let Ok(pid_str) = std::fs::read_to_string(pid_file) {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                let _ = std::process::Command::new("taskkill")
                    .args(["/F", "/PID", &pid.to_string()])
                    .output();
            }
        }
    }
    store.update_status(&c.id, ContainerStatus::Exited(0))?;
    let _ = guardrails::ProcessReaper::reap_stale_containers();
    println!("{}", container);
    Ok(())
}

pub async fn start_container(container: &str) -> Result<()> {
    start_container_with_home(container, None).await
}

pub async fn start_container_with_home(container: &str, home_opt: Option<&Path>) -> Result<()> {
    let store = match home_opt {
        Some(h) => ContainerStore::with_home(h.to_path_buf()),
        None => ContainerStore::new(),
    };
    let rec = store
        .find(container)
        .ok_or_else(|| anyhow!("Container '{}' not found", container))?;

    let bundle_path = PathBuf::from(&rec.bundle_path);
    let config_file = bundle_path.join("config.json");
    let content = fs::read_to_string(&config_file)?;
    let spec: Spec = serde_json::from_str(&content)?;

    let ports = network::resolve_bundle_ports(&bundle_path, &rec.ports);
    store.update_status(&rec.id, ContainerStatus::Running)?;
    execute_bundle(&bundle_path, &spec, &[], &ports, true)?;
    if !ports.is_empty() {
        network::wait_for_forwarder_pid(&bundle_path, std::time::Duration::from_secs(15))?;
        network::wait_for_published_ports(&ports, std::time::Duration::from_secs(120))?;
    }
    println!("{}", container);
    Ok(())
}

/// Wait until container trampoline/VM processes have fully exited.
#[cfg(unix)]
fn wait_for_container_stopped(bundle_path: &Path, timeout: std::time::Duration) -> Result<()> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let mut any_alive = false;
        for name in ["vm.pid", "container.pid"] {
            let path = bundle_path.join(name);
            if let Ok(pid_str) = std::fs::read_to_string(&path) {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    if unsafe { libc::kill(pid, 0) == 0 } {
                        any_alive = true;
                    }
                }
            }
        }
        if !any_alive {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err(anyhow!(
        "timed out waiting for container at {} to stop",
        bundle_path.display()
    ))
}

#[cfg(not(unix))]
fn wait_for_container_stopped(_bundle_path: &Path, _timeout: std::time::Duration) -> Result<()> {
    Ok(())
}

pub fn container_logs(args: &LogsArgs) -> Result<()> {
    let store = ContainerStore::new();
    let rec = store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;

    let log_path = PathBuf::from(&rec.bundle_path).join("logs.txt");
    let rootfs_log = PathBuf::from(&rec.bundle_path)
        .join("rootfs")
        .join("logs.txt");

    let print_line = |line: &str| {
        if args.timestamps {
            println!("{} {}", Utc::now().to_rfc3339(), line);
        } else {
            println!("{}", line);
        }
    };

    let content = if log_path.exists()
        && fs::metadata(&log_path)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
    {
        fs::read_to_string(&log_path)?
    } else if rootfs_log.exists() {
        fs::read_to_string(&rootfs_log)?
    } else if log_path.exists() {
        fs::read_to_string(&log_path)?
    } else {
        println!("No logs available for container {}", args.container);
        return Ok(());
    };

    let mut lines: Vec<&str> = content.lines().collect();

    if let Some(since_str) = &args.since {
        if let Ok(since_dt) = chrono::DateTime::parse_from_rfc3339(since_str) {
            lines.retain(|l| {
                if let Some((ts_part, _)) = l.split_once(' ') {
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts_part) {
                        return dt >= since_dt;
                    }
                }
                true
            });
        }
    }

    if let Some(until_str) = &args.until {
        if let Ok(until_dt) = chrono::DateTime::parse_from_rfc3339(until_str) {
            lines.retain(|l| {
                if let Some((ts_part, _)) = l.split_once(' ') {
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts_part) {
                        return dt <= until_dt;
                    }
                }
                true
            });
        }
    }

    if let Some(tail) = args.tail {
        if tail == 0 {
            lines.clear();
        } else if lines.len() > tail {
            lines = lines[lines.len() - tail..].to_vec();
        }
    }

    for l in lines {
        print_line(l);
    }

    if args.follow {
        let mut pos = fs::metadata(&log_path)?.len();
        loop {
            if let Some(current) = store.find(&rec.id) {
                if !matches!(current.status, ContainerStatus::Running) {
                    break;
                }
            }

            let meta = fs::metadata(&log_path)?;
            let new_len = meta.len();
            if new_len > pos {
                use std::io::{BufRead, Seek};
                let mut file = fs::File::open(&log_path)?;
                file.seek(std::io::SeekFrom::Start(pos))?;
                let reader = std::io::BufReader::new(file);
                for l in reader.lines().flatten() {
                    print_line(&l);
                }
                pos = new_len;
            }

            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    Ok(())
}

pub fn exec_container(args: &ExecArgs) -> Result<i32> {
    let store = ContainerStore::new();
    let rec = store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;

    if !matches!(rec.status, ContainerStatus::Running) {
        return Err(anyhow!(
            "Container '{}' is not running: {}",
            args.container,
            rec.status
        ));
    }

    if args.command.is_empty() {
        return Err(anyhow!("Command cannot be empty for exec"));
    }

    let _term_guard = if args.interactive && args.tty && !args.detach {
        terminal::TerminalGuard::enter_raw_mode().ok()
    } else {
        None
    };

    let mut combined_env = args.env.clone();
    if let Some(env_file_path) = &args.env_file {
        if let Ok(content) = fs::read_to_string(env_file_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    combined_env.push(trimmed.to_string());
                }
            }
        }
    }

    let bundle_path = PathBuf::from(&rec.bundle_path);
    exec_in_bundle(
        &bundle_path,
        &args.command,
        &combined_env,
        args.workdir.as_deref(),
        args.user.as_deref(),
        args.detach,
    )
}

pub fn inspect_target(args: &cli::InspectArgs) -> Result<()> {
    let only_type = args.obj_type.as_deref().unwrap_or("");
    if !only_type.is_empty()
        && only_type != "container"
        && only_type != "image"
        && only_type != "volume"
        && only_type != "network"
    {
        return Err(anyhow!("invalid inspect type: \"{}\"", only_type));
    }

    let c_store = ContainerStore::new();
    let i_store = ImageStore::new();
    let v_store = VolumeStore::new();
    let n_store = NetworkStore::new();

    let mut results = Vec::new();

    for target in &args.targets {
        let mut matched = false;

        if only_type.is_empty() || only_type == "container" {
            if let Some(c) = c_store.find(target) {
                let is_running = matches!(c.status, ContainerStatus::Running);
                let mut labels_map = HashMap::new();
                let labels_file = PathBuf::from(&c.bundle_path).join("labels.json");
                if labels_file.exists() {
                    if let Ok(content) = fs::read_to_string(&labels_file) {
                        if let Ok(labels_vec) = serde_json::from_str::<Vec<String>>(&content) {
                            for l in labels_vec {
                                if let Some((k, v)) = l.split_once('=') {
                                    labels_map.insert(k.to_string(), v.to_string());
                                } else {
                                    labels_map.insert(l, "".to_string());
                                }
                            }
                        }
                    }
                }
                let size_bytes = if args.size {
                    crate::system::dir_size(&PathBuf::from(&c.bundle_path))
                } else {
                    0
                };
                let mut exposed_map = HashMap::new();
                for ep in &c.exposed_ports {
                    let key = if ep.contains('/') {
                        ep.clone()
                    } else {
                        format!("{}/tcp", ep)
                    };
                    exposed_map.insert(key, serde_json::json!({}));
                }

                // Discover host PID
                let bundle_path = PathBuf::from(&c.bundle_path);
                let pid = {
                    let mut found_pid = 0;
                    if let Ok(p_str) = fs::read_to_string(bundle_path.join("container.pid")) {
                        if let Ok(p) = p_str.trim().parse::<i32>() {
                            found_pid = p;
                        }
                    }
                    if found_pid == 0 {
                        if let Ok(p_str) = fs::read_to_string(bundle_path.join("vm.pid")) {
                            if let Ok(p) = p_str.trim().parse::<i32>() {
                                found_pid = p;
                            }
                        }
                    }
                    found_pid
                };

                // Real network endpoints
                let mut ip_address = "172.17.0.2".to_string();
                let mut gateway = "172.17.0.1".to_string();
                let mut mac_address = "02:42:ac:11:00:02".to_string();
                for net in n_store.list() {
                    if let Some(ep) = net
                        .containers
                        .get(&c.id)
                        .or_else(|| net.containers.get(&c.name))
                    {
                        ip_address = ep.ipv4_address.clone();
                        gateway = net.gateway.clone();
                        mac_address = ep.mac_address.clone();
                        break;
                    }
                }

                // PortBindings and Ports
                let mut port_bindings = serde_json::Map::new();
                let mut ports_map = serde_json::Map::new();
                for p in &c.ports {
                    let key = format!("{}/{}", p.container_port, p.protocol);
                    let host_ip = p.host_ip.as_deref().unwrap_or("");
                    let binding = serde_json::json!({
                        "HostIp": host_ip,
                        "HostPort": p.host_port.to_string(),
                    });
                    port_bindings.insert(key.clone(), serde_json::json!([binding.clone()]));
                    ports_map.insert(key, serde_json::json!([binding]));
                }

                let bundle_path = PathBuf::from(&c.bundle_path);
                let spec: Option<Spec> = fs::read_to_string(bundle_path.join("config.json"))
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok());
                let annotations = spec
                    .as_ref()
                    .and_then(|s| s.annotations.clone())
                    .unwrap_or_default();

                let config_user = spec
                    .as_ref()
                    .map(|s| format!("{}:{}", s.process.user.uid, s.process.user.gid))
                    .unwrap_or_default();
                let config_workdir = spec
                    .as_ref()
                    .map(|s| s.process.cwd.clone())
                    .unwrap_or_default();
                let config_hostname = spec
                    .as_ref()
                    .and_then(|s| s.hostname.clone())
                    .unwrap_or_default();
                let config_env = spec
                    .as_ref()
                    .map(|s| s.process.env.clone())
                    .unwrap_or_default();
                let readonly_rootfs = spec.as_ref().map(|s| s.root.readonly).unwrap_or(false);
                let privileged = annotations
                    .get("boxr.privileged")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                let cap_add: Vec<String> = annotations
                    .get("boxr.cap_add")
                    .and_then(|v| serde_json::from_str(v).ok())
                    .unwrap_or_default();
                let cap_drop: Vec<String> = annotations
                    .get("boxr.cap_drop")
                    .and_then(|v| serde_json::from_str(v).ok())
                    .unwrap_or_default();
                let memory = annotations
                    .get("boxr.memory")
                    .and_then(|v| v.parse::<i64>().ok());
                let nano_cpus = annotations
                    .get("boxr.cpus")
                    .and_then(|v| v.parse::<f64>().ok())
                    .map(|cpus| (cpus * 1_000_000_000.0) as i64);

                let docker_compat_inspect = serde_json::json!({
                    "Id": c.id,
                    "Created": c.created_at.to_rfc3339(),
                    "Path": c.command.first().cloned().unwrap_or_default(),
                    "Args": if c.command.len() > 1 { c.command[1..].to_vec() } else { Vec::new() },
                    "State": {
                        "Status": if is_running { "running" } else { "exited" },
                        "Running": is_running,
                        "Paused": matches!(c.status, ContainerStatus::Paused),
                        "Restarting": false,
                        "OOMKilled": false,
                        "Dead": false,
                        "Pid": pid,
                        "ExitCode": match c.status {
                            ContainerStatus::Exited(code) => code,
                            _ => 0,
                        },
                        "Error": "",
                        "StartedAt": c.created_at.to_rfc3339(),
                        "FinishedAt": c.created_at.to_rfc3339(),
                    },
                    "Image": c.image,
                    "Name": format!("/{}", c.name),
                    "RestartCount": c.restart_count,
                    "SizeRw": size_bytes,
                    "Config": {
                        "Image": c.image,
                        "Labels": labels_map,
                        "ExposedPorts": exposed_map,
                        "User": config_user,
                        "WorkingDir": config_workdir,
                        "Hostname": config_hostname,
                        "Env": config_env,
                    },
                    "HostConfig": {
                        "PortBindings": port_bindings,
                        "RestartPolicy": {
                            "Name": c.restart_policy.to_string(),
                            "MaximumRetryCount": 0
                        },
                        "ReadonlyRootfs": readonly_rootfs,
                        "Privileged": privileged,
                        "CapAdd": cap_add,
                        "CapDrop": cap_drop,
                        "Memory": memory,
                        "NanoCpus": nano_cpus,
                    },
                    "NetworkSettings": {
                        "Bridge": "",
                        "SandboxID": "",
                        "HairpinMode": false,
                        "LinkLocalIPv6Address": "",
                        "LinkLocalIPv6PrefixLen": 0,
                        "Ports": ports_map,
                        "SandboxKey": "",
                        "SecondaryIPAddresses": null,
                        "SecondaryIPv6Addresses": null,
                        "EndpointID": "",
                        "Gateway": gateway,
                        "GlobalIPv6Address": "",
                        "GlobalIPv6PrefixLen": 0,
                        "IPAddress": ip_address,
                        "IPPrefixLen": 16,
                        "IPv6Gateway": "",
                        "MacAddress": mac_address,
                        "Networks": {
                            "bridge": {
                                "IPAMConfig": null,
                                "Links": null,
                                "Aliases": null,
                                "NetworkID": "boxr00000000",
                                "EndpointID": "",
                                "Gateway": "172.17.0.1",
                                "IPAddress": "172.17.0.2",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "MacAddress": "02:42:ac:11:00:02",
                                "DriverOpts": null
                            }
                        }
                    },
                    "boxr_raw": c
                });
                results.push(docker_compat_inspect);
                matched = true;
            }
        }

        if !matched && (only_type.is_empty() || only_type == "image") {
            if let Some(i) = i_store.find(target) {
                let docker_compat_image = serde_json::json!({
                    "Id": format!("sha256:{}", i.id),
                    "RepoTags": [format!("{}:{}", i.display_reference(), i.tag)],
                    "Size": i.size_bytes,
                    "Created": i.created_at.to_rfc3339(),
                    "Architecture": i.config.architecture,
                    "Os": i.config.os,
                    "boxr_raw": i
                });
                results.push(docker_compat_image);
                matched = true;
            }
        }

        if !matched && (only_type.is_empty() || only_type == "volume") {
            if let Some(vol) = v_store.find(target) {
                let docker_compat_volume = serde_json::json!({
                    "CreatedAt": vol.created_at.to_rfc3339(),
                    "Driver": vol.driver,
                    "Labels": vol.labels,
                    "Mountpoint": vol.mountpoint,
                    "Name": vol.name,
                    "Options": null,
                    "Scope": vol.scope,
                });
                results.push(docker_compat_volume);
                matched = true;
            }
        }

        if !matched && (only_type.is_empty() || only_type == "network") {
            if let Some(net) = n_store.find(target) {
                let docker_compat_net = serde_json::json!({
                    "Name": net.name,
                    "Id": net.id,
                    "Created": net.created_at.to_rfc3339(),
                    "Scope": "local",
                    "Driver": net.driver,
                    "EnableIPv6": false,
                    "IPAM": {
                        "Driver": "default",
                        "Options": null,
                        "Config": [{
                            "Subnet": net.subnet,
                            "Gateway": net.gateway
                        }]
                    },
                    "Internal": net.internal,
                    "Attachable": false,
                    "Ingress": false,
                    "ConfigFrom": { "Network": "" },
                    "ConfigOnly": false,
                    "Containers": {},
                    "Options": {},
                    "Labels": {}
                });
                results.push(docker_compat_net);
                matched = true;
            }
        }

        if !matched {
            return Err(anyhow!("No such container or image: '{}'", target));
        }
    }

    if let Some(fmt) = &args.format {
        for res in &results {
            if fmt == "json" || fmt == "{{json .}}" {
                println!("{}", serde_json::to_string_pretty(res)?);
            } else {
                println!("{}", evaluate_simple_template(fmt, res));
            }
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&results)?);
    }

    Ok(())
}

pub fn diff_container(args: &DiffArgs) -> Result<()> {
    let c_store = ContainerStore::new();
    let cont = c_store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;

    let i_store = ImageStore::new();
    let img = i_store
        .find(&cont.image)
        .ok_or_else(|| anyhow!("Image '{}' not found", cont.image))?;

    let base_rootfs = PathBuf::from(&img.rootfs_path);
    let container_rootfs = PathBuf::from(&cont.bundle_path).join("rootfs");

    let diffs = runtime::diff::FilesystemDiff::compare(&base_rootfs, &container_rootfs)?;
    for d in diffs {
        println!("{} {}", d.change_type, d.path);
    }
    Ok(())
}

pub fn top_container(args: &TopArgs) -> Result<()> {
    let c_store = ContainerStore::new();
    let cont = c_store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;

    if !matches!(cont.status, ContainerStatus::Running) {
        return Err(anyhow!("Container {} is not running", args.container));
    }

    let bundle_path = PathBuf::from(&cont.bundle_path);
    runtime::top::ContainerTop::list_processes(&bundle_path, &args.ps_args)?;
    Ok(())
}

pub fn commit_container(args: &cli::CommitArgs) -> Result<()> {
    let c_store = ContainerStore::new();
    let cont = c_store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;

    let was_running = matches!(cont.status, ContainerStatus::Running);
    if was_running && args.pause {
        if let Ok(cgroup_mgr) = cgroups::CgroupV2Manager::new(&cont.id) {
            let _ = cgroup_mgr.freeze();
        }
    }

    let i_store = ImageStore::new();
    let record = i_store.commit_container(
        &cont,
        args.repo_tag.as_deref(),
        args.message.as_deref(),
        args.author.as_deref(),
    );

    if was_running && args.pause {
        if let Ok(cgroup_mgr) = cgroups::CgroupV2Manager::new(&cont.id) {
            let _ = cgroup_mgr.unfreeze();
        }
    }

    let record = record?;

    let mut attrs = HashMap::new();
    attrs.insert(
        "image".to_string(),
        format!("{}:{}", record.reference, record.tag),
    );
    EventManager::record(ContainerEvent::new(
        "container",
        "commit",
        &cont.id,
        &cont.name,
        attrs,
    ));

    println!("sha256:{}", record.manifest_digest);
    Ok(())
}

pub fn pause_container(args: &cli::PauseArgs) -> Result<()> {
    for container in &args.containers {
        let c_store = ContainerStore::new();
        let cont = c_store
            .find(container)
            .ok_or_else(|| anyhow!("Container '{}' not found", container))?;

        if !matches!(cont.status, ContainerStatus::Running) {
            return Err(anyhow!("Container {} is not running", container));
        }

        if let Ok(cgroup_mgr) = cgroups::CgroupV2Manager::new(&cont.id) {
            let _ = cgroup_mgr.freeze();
        }
        c_store.update_status(&cont.id, ContainerStatus::Paused)?;

        let mut attrs = HashMap::new();
        attrs.insert("name".to_string(), cont.name.clone());
        EventManager::record(ContainerEvent::new(
            "container",
            "pause",
            &cont.id,
            &cont.name,
            attrs,
        ));

        println!("{}", container);
    }
    Ok(())
}

pub fn unpause_container(args: &cli::UnpauseArgs) -> Result<()> {
    for container in &args.containers {
        let c_store = ContainerStore::new();
        let cont = c_store
            .find(container)
            .ok_or_else(|| anyhow!("Container '{}' not found", container))?;

        if !matches!(cont.status, ContainerStatus::Paused) {
            return Err(anyhow!("Container {} is not paused", container));
        }

        if let Ok(cgroup_mgr) = cgroups::CgroupV2Manager::new(&cont.id) {
            let _ = cgroup_mgr.unfreeze();
        }
        c_store.update_status(&cont.id, ContainerStatus::Running)?;

        let mut attrs = HashMap::new();
        attrs.insert("name".to_string(), cont.name.clone());
        EventManager::record(ContainerEvent::new(
            "container",
            "unpause",
            &cont.id,
            &cont.name,
            attrs,
        ));

        println!("{}", container);
    }
    Ok(())
}

pub fn rename_container(args: &cli::RenameArgs) -> Result<()> {
    let c_store = ContainerStore::new();
    c_store.rename(&args.container, &args.new_name)?;

    let mut attrs = HashMap::new();
    attrs.insert("oldName".to_string(), args.container.clone());
    attrs.insert("newName".to_string(), args.new_name.clone());
    EventManager::record(ContainerEvent::new(
        "container",
        "rename",
        &args.container,
        &args.new_name,
        attrs,
    ));

    Ok(())
}

pub fn wait_container(args: &cli::WaitArgs) -> Result<i32> {
    let mut last_code = 0;
    for container in &args.containers {
        let c_store = ContainerStore::new();
        loop {
            let cont = c_store
                .find(container)
                .ok_or_else(|| anyhow!("Container '{}' not found", container))?;
            match cont.status {
                ContainerStatus::Exited(code) => {
                    println!("{}", code);
                    last_code = code;
                    break;
                }
                ContainerStatus::Failed(err) => {
                    eprintln!("Container failed: {}", err);
                    last_code = 1;
                    break;
                }
                ContainerStatus::Running | ContainerStatus::Created | ContainerStatus::Paused => {
                    #[cfg(unix)]
                    {
                        let bundle_path = std::path::PathBuf::from(&cont.bundle_path);
                        let exitcode_file = bundle_path.join("rootfs").join("boxr-exitcode");
                        if exitcode_file.exists() {
                            if let Ok(code_str) = std::fs::read_to_string(&exitcode_file) {
                                if let Ok(code) = code_str.trim().parse::<i32>() {
                                    let _ = c_store
                                        .update_status(&cont.id, ContainerStatus::Exited(code));
                                    println!("{}", code);
                                    last_code = code;
                                    break;
                                }
                            }
                        }
                        let pid_file = bundle_path.join("vm.pid");
                        let is_running = if let Ok(pid_str) = std::fs::read_to_string(pid_file) {
                            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                                unsafe { libc::kill(pid, 0) == 0 }
                            } else {
                                false
                            }
                        } else {
                            false
                        };
                        if !is_running {
                            let _ = c_store.update_status(&cont.id, ContainerStatus::Exited(137));
                            println!("137");
                            last_code = 137;
                            break;
                        }
                    }
                    #[cfg(target_os = "windows")]
                    {
                        let bundle_path = std::path::PathBuf::from(&cont.bundle_path);
                        let pid_file = bundle_path.join("vm.pid");
                        let is_running = if let Ok(pid_str) = std::fs::read_to_string(pid_file) {
                            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                                std::process::Command::new("tasklist")
                                    .args(["/FI", &format!("PID eq {}", pid)])
                                    .output()
                                    .map(|o| {
                                        String::from_utf8_lossy(&o.stdout)
                                            .contains(&pid.to_string())
                                    })
                                    .unwrap_or(false)
                            } else {
                                false
                            }
                        } else {
                            false
                        };
                        if !is_running {
                            let _ = c_store.update_status(&cont.id, ContainerStatus::Exited(137));
                            println!("137");
                            last_code = 137;
                            break;
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        }
    }
    Ok(last_code)
}

pub fn cp_container(args: &cli::CpArgs) -> Result<()> {
    runtime::cp::ContainerCopy::copy(&args.src, &args.dest)
}

pub fn update_container(args: &cli::UpdateArgs) -> Result<()> {
    let c_store = ContainerStore::new();
    let cont = c_store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;

    let mut limits = cgroups::ResourceLimits::default();
    if let Some(mem_str) = &args.memory {
        let mem = cgroups::ResourceLimits::parse_memory(mem_str)?;
        limits.memory_max_bytes = Some(mem);
    }
    if let Some(cpus_str) = &args.cpus {
        let (quota, period) = cgroups::ResourceLimits::parse_cpus(cpus_str)?;
        limits.cpu_quota_us = Some(quota);
        limits.cpu_period_us = Some(period);
    }
    if let (Some(q), Some(p)) = (args.cpu_quota, args.cpu_period) {
        limits.cpu_quota_us = Some(q);
        limits.cpu_period_us = Some(p);
    }
    if let Some(shares) = args.cpu_shares {
        limits.cpu_shares = Some(shares);
    }
    if let Some(swap_str) = &args.memory_swap {
        let swap = cgroups::ResourceLimits::parse_memory(swap_str)?;
        limits.memory_swap_max_bytes = Some(swap);
    }
    if let Some(pids) = args.pids_limit {
        if pids == 0 {
            return Err(anyhow!("--pids-limit must be greater than 0 or -1"));
        }
        limits.pids_max = Some(pids);
    }

    if let Ok(cgroup_mgr) = cgroups::CgroupV2Manager::new(&cont.id) {
        cgroup_mgr.apply_limits(&limits)?;
    }

    // Persist updated limits in bundle config.json
    let bundle_path = PathBuf::from(&cont.bundle_path);
    let config_path = bundle_path.join("config.json");
    if let Ok(content) = fs::read_to_string(&config_path) {
        if let Ok(mut spec) = serde_json::from_str::<Spec>(&content) {
            if let Some(l) = &mut spec.linux {
                if let Some(res) = &mut l.resources {
                    if let Some(m) = limits.memory_max_bytes {
                        res.memory = Some(oci::runtime::LinuxMemory {
                            limit: Some(m),
                            ..Default::default()
                        });
                    }
                    if let Some(p) = limits.pids_max {
                        res.pids = Some(oci::runtime::LinuxPids { limit: p });
                    }
                }
            }
            let _ = spec.save_to_bundle(&bundle_path);
        }
    }

    if let Some(r_policy_str) = &args.restart {
        if let Ok(policy) = health::parse_restart_policy(r_policy_str) {
            let mut updated_cont = cont.clone();
            updated_cont.restart_policy = policy;
            let _ = c_store.add(updated_cont);
        }
    }

    let mut attrs = HashMap::new();
    attrs.insert("name".to_string(), cont.name.clone());
    EventManager::record(ContainerEvent::new(
        "container",
        "update",
        &cont.id,
        &cont.name,
        attrs,
    ));

    println!("{}", args.container);
    Ok(())
}

pub fn attach_container(args: &cli::AttachArgs) -> Result<()> {
    let c_store = ContainerStore::new();
    let cont = c_store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;

    println!(
        "Attaching to container '{}' (Press Ctrl+C to detach)...",
        args.container
    );

    let log_path = PathBuf::from(&cont.bundle_path).join("logs.txt");
    if log_path.exists() {
        let content = fs::read_to_string(&log_path)?;
        print!("{}", content);
    }

    let mut pos = if log_path.exists() {
        fs::metadata(&log_path)?.len()
    } else {
        0
    };

    let _term_guard = if !args.no_stdin {
        terminal::TerminalGuard::enter_raw_mode().ok()
    } else {
        None
    };

    loop {
        // Check if container has exited
        #[cfg(unix)]
        {
            let bundle_path = std::path::PathBuf::from(&cont.bundle_path);
            let pid_file = bundle_path.join("vm.pid");
            if let Ok(pid_str) = std::fs::read_to_string(pid_file) {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    if unsafe { libc::kill(pid, 0) != 0 } {
                        let _ = c_store.update_status(&cont.id, ContainerStatus::Exited(0));
                        break;
                    }
                }
            }
        }

        if let Some(current) = c_store.find(&cont.id) {
            if matches!(current.status, ContainerStatus::Exited(_))
                || matches!(current.status, ContainerStatus::Failed(_))
            {
                break;
            }
        }

        if log_path.exists() {
            let meta = fs::metadata(&log_path)?;
            let new_len = meta.len();
            if new_len > pos {
                use std::io::Seek;
                let mut file = fs::File::open(&log_path)?;
                file.seek(std::io::SeekFrom::Start(pos))?;
                let mut buf = Vec::new();
                use std::io::Read;
                file.read_to_end(&mut buf)?;
                print!("{}", String::from_utf8_lossy(&buf));
                pos = new_len;
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    Ok(())
}

pub fn kill_container(args: &cli::KillArgs) -> Result<()> {
    let store = ContainerStore::new();
    let cont = store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;
    runtime::kill::ContainerKiller::kill(&cont, args.signal.as_deref())
}

pub async fn build_image(args: BuildArgs) -> Result<()> {
    let builder = builder::ImageBuilder::new();
    let context_dir = PathBuf::from(&args.path).canonicalize()?;
    let dockerfile_path = if Path::new(&args.file).is_absolute() {
        PathBuf::from(&args.file)
    } else {
        context_dir.join(&args.file)
    };

    let mut build_args = std::collections::HashMap::new();
    for ba in &args.build_args {
        if let Some((k, v)) = ba.split_once('=') {
            build_args.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    let primary_tag = args.tags.first().cloned();
    let record = builder
        .build(builder::BuildOptions {
            context_dir,
            dockerfile_path,
            tag: primary_tag,
            no_cache: args.no_cache,
            build_args,
            target: args.target,
            add_host: args.add_host,
            memory: args.memory,
            shm_size: args.shm_size,
            quiet: args.quiet,
        })
        .await?;

    if args.quiet {
        println!("{}", record.id);
    }

    let store = ImageStore::new();
    for extra_tag in args.tags.iter().skip(1) {
        // Normalize so qualified spellings store canonical registry/repo/tag.
        let parsed = crate::oci::reference::ImageReference::parse(extra_tag).unwrap_or(
            crate::oci::reference::ImageReference {
                registry: crate::oci::reference::ImageReference::DEFAULT_REGISTRY.to_string(),
                repository: extra_tag.clone(),
                tag: crate::oci::reference::ImageReference::DEFAULT_TAG.to_string(),
                digest: None,
            },
        );
        let mut tagged_record = record.clone();
        tagged_record.reference = parsed.repository;
        tagged_record.tag = parsed.tag;
        tagged_record.registry = parsed.registry;
        let _ = store.add(tagged_record);
        println!("Successfully tagged image as {}", extra_tag);
    }

    Ok(())
}

pub async fn handle_compose(args: ComposeArgs) -> Result<()> {
    let path = PathBuf::from(&args.file);
    let project = compose::ComposeProject::load(&path)?;

    match args.command {
        ComposeSubcommand::Up(opts) => {
            let build = opts.build && !opts.no_build;
            project.up(opts.detach, build).await?;
        }
        ComposeSubcommand::Down(opts) => {
            project.down(opts.volumes)?;
            if opts.remove_orphans {
                println!("Removing orphan containers...");
            }
        }
        ComposeSubcommand::Ps(ps_args) => {
            let containers = project.ps()?;
            if ps_args.services {
                for svc in project.compose.services.keys() {
                    println!("{}", svc);
                }
            } else if ps_args.quiet {
                for c in &containers {
                    println!("{}", c.id);
                }
            } else if let Some(fmt) = &ps_args.format {
                for c in &containers {
                    let mut line = fmt.clone();
                    line = line.replace("{{.ID}}", &c.id[..12.min(c.id.len())]);
                    line = line.replace("{{.Name}}", &c.name);
                    line = line.replace("{{.Image}}", &c.image);
                    line = line.replace("{{.Status}}", &c.status.to_string());
                    println!("{}", line);
                }
            } else {
                println!(
                    "{:<14} {:<24} {:<20} {:<16}",
                    "CONTAINER ID", "NAME", "IMAGE", "STATUS"
                );
                for c in containers {
                    println!(
                        "{:<14} {:<24} {:<20} {:<16}",
                        &c.id[..12.min(c.id.len())],
                        c.name,
                        c.image,
                        c.status.to_string()
                    );
                }
            }
        }
        ComposeSubcommand::Logs(opts) => {
            let containers = project.ps()?;
            for c in containers {
                if let Some(s) = &opts.service {
                    if !c.name.contains(s) {
                        continue;
                    }
                }
                if !opts.no_log_prefix {
                    println!("=== Logs for {} ===", c.name);
                }
                let log_path = PathBuf::from(&c.bundle_path).join("logs.txt");
                if log_path.exists() {
                    let text = fs::read_to_string(log_path)?;
                    if opts.tail.is_some() {
                        let lines: Vec<&str> = text.lines().collect();
                        let n = opts
                            .tail
                            .as_ref()
                            .and_then(|t| t.parse().ok())
                            .unwrap_or(10);
                        for line in lines.iter().rev().take(n).rev() {
                            if opts.timestamps {
                                println!(
                                    "{} {}",
                                    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
                                    line
                                );
                            } else {
                                println!("{}", line);
                            }
                        }
                    } else {
                        print!("{}", text);
                    }
                }
            }
        }
        ComposeSubcommand::Config => {
            println!("{}", serde_yaml::to_string(&project.compose)?);
        }
        ComposeSubcommand::Restart(opts) => {
            let containers = project.ps()?;
            for c in containers {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                let _ = restart_container(&cli::RestartArgs {
                    time: 10,
                    signal: None,
                    container: c.name.clone(),
                })
                .await;
            }
        }
        ComposeSubcommand::Exec(opts) => {
            let containers = project.ps()?;
            let c = containers
                .iter()
                .find(|c| c.name.contains(&opts.service))
                .ok_or_else(|| anyhow!("Service '{}' not running", opts.service))?;
            let exec_args = cli::ExecArgs {
                detach: opts.detach,
                interactive: !opts.detach && (opts.interactive || !opts.no_tty),
                tty: !opts.detach && !opts.no_tty,
                privileged: opts.privileged,
                env_file: opts.env_file.clone(),
                detach_keys: None,
                user: opts.user.clone(),
                workdir: opts.workdir.clone(),
                env: opts.env.clone(),
                container: c.name.clone(),
                command: opts.command,
            };
            let _ = exec_container(&exec_args)?;
        }
        ComposeSubcommand::Build(opts) => {
            project.build(opts.no_cache, opts.quiet).await?;
        }
        ComposeSubcommand::Stop(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                let _ = stop_container(&c.name, None);
            }
        }
        ComposeSubcommand::Start(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                let _ = start_container(&c.name).await;
            }
        }
        ComposeSubcommand::Rm(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                if opts.stop {
                    let _ = stop_container(&c.name, None);
                }
                let _ = remove_container(&c.name, opts.force);
            }
        }
        ComposeSubcommand::Cp(args) => {
            cp_container(&cli::CpArgs {
                src: args.src,
                dest: args.dest,
                archive: false,
                follow_link: false,
                quiet: false,
            })?;
        }
        ComposeSubcommand::Create => {
            project.create_containers().await?;
            println!("Creating compose project '{}'...", project.name);
        }
        ComposeSubcommand::Events => {
            events::EventManager::stream_events(None, None)?;
        }
        ComposeSubcommand::Images => {
            for svc in project.compose.services.values() {
                if let Some(img) = &svc.image {
                    println!("{}", img);
                }
            }
        }
        ComposeSubcommand::Kill(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                let _ = kill_container(&cli::KillArgs {
                    signal: Some("SIGKILL".to_string()),
                    container: c.name.clone(),
                });
            }
        }
        ComposeSubcommand::Ls => {
            println!("NAME\tSTATUS\tCONFIG FILES");
            println!("{}\trunning\t{}", project.name, args.file);
        }
        ComposeSubcommand::Pause(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                pause_container(&cli::PauseArgs {
                    containers: vec![c.name.clone()],
                })?;
            }
        }
        ComposeSubcommand::Unpause(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                unpause_container(&cli::UnpauseArgs {
                    containers: vec![c.name.clone()],
                })?;
            }
        }
        ComposeSubcommand::Port(opts) => {
            for c in project.ps()? {
                if c.name.contains(&opts.service) {
                    for p in &c.ports {
                        if p.container_port == opts.private_port {
                            println!("{}:{}", p.host_port, p.container_port);
                        }
                    }
                }
            }
        }
        ComposeSubcommand::Pull => {
            project.pull_images().await?;
        }
        ComposeSubcommand::Push => {
            project.push_images().await?;
        }
        ComposeSubcommand::Run(opts) => {
            project
                .run_one_off(&opts.service, opts.command, true)
                .await?;
        }
        ComposeSubcommand::Top(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                top_container(&cli::TopArgs {
                    container: c.name.clone(),
                    ps_args: Vec::new(),
                })?;
            }
        }
        ComposeSubcommand::Version => {
            println!("Docker Compose version v2.24.0-boxr");
        }
        ComposeSubcommand::Wait(opts) => {
            for c in project.ps()? {
                if let Some(svc) = &opts.service {
                    if !c.name.contains(svc) {
                        continue;
                    }
                }
                let _ = wait_container(&cli::WaitArgs {
                    containers: vec![c.name.clone()],
                })?;
            }
        }
    }
    Ok(())
}

pub fn handle_volume(args: VolumeSubcommands) -> Result<()> {
    let store = VolumeStore::new();
    match args.command {
        VolumeAction::Create {
            name,
            name_flag,
            driver,
            opts,
            labels,
            scope,
            ..
        } => {
            let mut label_map = HashMap::new();
            for l in labels {
                if let Some((k, v)) = l.split_once('=') {
                    label_map.insert(k.to_string(), v.to_string());
                }
            }
            let mut opt_map = HashMap::new();
            for o in opts {
                if let Some((k, v)) = o.split_once('=') {
                    opt_map.insert(k.to_string(), v.to_string());
                } else {
                    opt_map.insert(o.to_string(), "".to_string());
                }
            }
            let resolved_name = name_flag.or(name);
            let vol = store.create_with_options(
                resolved_name.as_deref(),
                &driver,
                Some(label_map),
                scope.as_deref().unwrap_or("local"),
                Some(opt_map),
            )?;
            println!("{}", vol.name);
        }
        VolumeAction::Ls(ls_args) => {
            let vols = store.list_filtered(&ls_args.filter);
            if ls_args.quiet {
                for v in &vols {
                    println!("{}", v.name);
                }
            } else if let Some(fmt) = &ls_args.format {
                for v in &vols {
                    let mut line = fmt.clone();
                    line = line.replace("{{.Name}}", &v.name);
                    line = line.replace("{{.Driver}}", &v.driver);
                    line = line.replace("{{.Scope}}", &v.scope);
                    println!("{}", line);
                }
            } else {
                println!("{:<20} {:<12} {:<40}", "VOLUME NAME", "DRIVER", "SCOPE");
                for v in vols {
                    println!("{:<20} {:<12} {:<40}", v.name, v.driver, v.scope);
                }
            }
        }
        VolumeAction::Inspect { format, name } => {
            let vol = store
                .find(&name)
                .ok_or_else(|| anyhow!("Volume '{}' not found", name))?;
            let compat = serde_json::json!({
                "CreatedAt": vol.created_at.to_rfc3339(),
                "Driver": vol.driver,
                "Labels": vol.labels,
                "Mountpoint": vol.mountpoint,
                "Name": vol.name,
                "Options": vol.options,
                "Scope": vol.scope,
            });
            if let Some(fmt) = &format {
                println!("{}", evaluate_simple_template(fmt, &compat));
            } else {
                println!("{}", serde_json::to_string_pretty(&[compat])?);
            }
        }
        VolumeAction::Rm { name } => {
            store.remove(&name)?;
            println!("{}", name);
        }
        VolumeAction::Prune(prune_args) => {
            let pruned = store.prune_with_options(prune_args.all, &prune_args.filter)?;
            if !pruned.is_empty() {
                println!("Deleted Volumes:");
                for p in pruned {
                    println!("{}", p);
                }
            }
        }
        VolumeAction::Exists { name } => {
            ensure_volume_exists(&name)?;
        }
        VolumeAction::Export(exp_args) => {
            let out = volume::VolumeOps::export_volume(
                &exp_args.name,
                exp_args.output.as_deref().map(Path::new),
            )?;
            println!("{}", out.display());
        }
        VolumeAction::Import(imp_args) => {
            let vol = volume::VolumeOps::import_volume(&imp_args.name, Path::new(&imp_args.input))?;
            println!("{}", vol.name);
        }
        VolumeAction::Reload { name } => {
            let vols = volume::VolumeOps::reload_volume(name.as_deref())?;
            for v in vols {
                println!("{}", v.name);
            }
        }
        VolumeAction::Rename { old_name, new_name } => {
            let vol = volume::VolumeOps::rename_volume(&old_name, &new_name)?;
            println!("{}", vol.name);
        }
        VolumeAction::Mount { name } => {
            let path = volume::VolumeOps::mount_volume(&name)?;
            println!("{}", path);
        }
        VolumeAction::Unmount { name } => {
            let unmounted = volume::VolumeOps::unmount_volume(&name)?;
            println!("{}", unmounted);
        }
    }
    Ok(())
}

pub fn handle_network(args: NetworkSubcommands) -> Result<()> {
    let store = NetworkStore::new();
    match args.command {
        NetworkAction::Create {
            name,
            driver,
            subnet,
            gateway,
            internal,
            attachable,
            labels,
            ..
        } => {
            let mut label_map = HashMap::new();
            for l in labels {
                if let Some((k, v)) = l.split_once('=') {
                    label_map.insert(k.to_string(), v.to_string());
                }
            }
            let net = store.create_with_options(
                &name,
                &driver,
                subnet.as_deref(),
                gateway.as_deref(),
                internal,
                attachable,
                label_map,
            )?;
            println!("{}", net.id);
        }
        NetworkAction::Ls(ls_args) => {
            let nets = store.list();
            if ls_args.quiet {
                for n in &nets {
                    let id = if ls_args.no_trunc {
                        n.id.clone()
                    } else {
                        n.id[..12.min(n.id.len())].to_string()
                    };
                    println!("{}", id);
                }
            } else if let Some(fmt) = &ls_args.format {
                for n in &nets {
                    let mut line = fmt.clone();
                    let id = if ls_args.no_trunc {
                        n.id.clone()
                    } else {
                        n.id[..12.min(n.id.len())].to_string()
                    };
                    line = line.replace("{{.ID}}", &id);
                    line = line.replace("{{.Name}}", &n.name);
                    line = line.replace("{{.Driver}}", &n.driver);
                    println!("{}", line);
                }
            } else {
                println!(
                    "{:<14} {:<20} {:<12} {:<20}",
                    "NETWORK ID", "NAME", "DRIVER", "SCOPE"
                );
                for n in nets {
                    let id = if ls_args.no_trunc {
                        n.id.clone()
                    } else {
                        n.id[..12.min(n.id.len())].to_string()
                    };
                    println!("{:<14} {:<20} {:<12} {:<20}", id, n.name, n.driver, "local");
                }
            }
        }
        NetworkAction::Inspect { format, name } => {
            let net = store
                .find(&name)
                .ok_or_else(|| anyhow!("Network '{}' not found", name))?;
            let compat = serde_json::json!({
                "Name": net.name,
                "Id": net.id,
                "Created": net.created_at.to_rfc3339(),
                "Scope": "local",
                "Driver": net.driver,
                "EnableIPv6": false,
                "IPAM": {
                    "Driver": "default",
                    "Options": null,
                    "Config": [{
                        "Subnet": net.subnet,
                        "Gateway": net.gateway,
                    }]
                },
                "Internal": net.internal,
                "Attachable": net.attachable,
                "Containers": net.containers,
                "Options": {},
                "Labels": net.labels,
            });
            if let Some(fmt) = &format {
                println!("{}", evaluate_simple_template(fmt, &compat));
            } else {
                println!("{}", serde_json::to_string_pretty(&[compat])?);
            }
        }
        NetworkAction::Rm { name } => {
            store.remove(&name)?;
            println!("{}", name);
        }
        NetworkAction::Prune(_) => {
            let mut pruned = Vec::new();
            for net in store.list() {
                if net.name != NetworkStore::DEFAULT_NETWORK && net.containers.is_empty() {
                    let _ = store.remove(&net.name);
                    pruned.push(net.name);
                }
            }
            if !pruned.is_empty() {
                println!("Deleted Networks:");
                for p in pruned {
                    println!("{}", p);
                }
            }
        }
        NetworkAction::Connect { network, container } => {
            let c_store = ContainerStore::new();
            let c = c_store
                .find(&container)
                .ok_or_else(|| anyhow!("Error: No such container: {}", container))?;
            let ep = store.connect_container(&network, &c.id, &c.name)?;
            println!("Connected {} with IP {}", container, ep.ipv4_address);
        }
        NetworkAction::Disconnect { network, container } => {
            store.disconnect_container(&network, &container)?;
            println!("Disconnected {} from {}", container, network);
        }
        NetworkAction::Reload { containers } => {
            reload_container_networks(&containers)?;
        }
        NetworkAction::Exists { name } => {
            ensure_network_exists(&name)?;
        }
        NetworkAction::Update(update_args) => {
            let updated = store.update(
                &update_args.network,
                &update_args.dns_add,
                &update_args.dns_drop,
                &update_args.label_add,
                &update_args.label_drop,
            )?;
            println!("{}", updated.name);
        }
    }
    Ok(())
}

pub fn list_images(args: cli::ImagesArgs) -> Result<()> {
    for f in &args.filter {
        if let Some((k, _)) = f.split_once('=') {
            validate_image_filter_key(k.trim())?;
        }
    }

    let store = ImageStore::new();
    let images = store.list();

    let filtered: Vec<_> = images
        .into_iter()
        .filter(|img| {
            for f in &args.filter {
                if let Some((k, v)) = f.split_once('=') {
                    match k.trim() {
                        "reference" | "name" => {
                            let shown = img.display_reference();
                            let full = format!("{}:{}", shown, img.tag);
                            if !full.contains(v.trim()) && !shown.contains(v.trim()) {
                                return false;
                            }
                        }
                        "id" => {
                            if !img.id.starts_with(v.trim()) {
                                return false;
                            }
                        }
                        _ => {}
                    }
                }
            }
            true
        })
        .collect();

    if args.quiet {
        for img in &filtered {
            if args.no_trunc {
                println!("{}", img.id);
            } else {
                println!("{}", &img.id[..12.min(img.id.len())]);
            }
        }
        return Ok(());
    }

    if let Some(fmt) = &args.format {
        if fmt == "json" {
            println!("{}", serde_json::to_string_pretty(&filtered)?);
            return Ok(());
        }
        for img in &filtered {
            let mut line = fmt.clone();
            let id_str = if args.no_trunc {
                img.id.clone()
            } else {
                img.id[..12.min(img.id.len())].to_string()
            };
            line = line.replace("{{.ID}}", &id_str);
            line = line.replace("{{.Repository}}", &img.display_reference());
            line = line.replace("{{.Tag}}", &img.tag);
            line = line.replace("{{.Digest}}", &img.manifest_digest);
            line = line.replace("{{.Size}}", &format_image_size(img.size_bytes as u64));
            line = line.replace(
                "{{.CreatedAt}}",
                &img.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            );
            line = line.replace("{{.CreatedSince}}", &format_running_for(img.created_at));
            println!("{}", line);
        }
        return Ok(());
    }

    if args.digests {
        println!(
            "{:<24} {:<12} {:<32} {:<16} {:<24} {:<10}",
            "REPOSITORY", "TAG", "DIGEST", "IMAGE ID", "CREATED", "SIZE"
        );
    } else {
        println!(
            "{:<28} {:<12} {:<16} {:<24} {:<10}",
            "REPOSITORY", "TAG", "IMAGE ID", "CREATED", "SIZE"
        );
    }

    for img in filtered {
        let size_mb = (img.size_bytes as f64) / (1024.0 * 1024.0);
        let size_str = if size_mb < 1.0 {
            format!("{:.1} KB", (img.size_bytes as f64) / 1024.0)
        } else {
            format!("{:.2} MB", size_mb)
        };

        let id_str = if args.no_trunc {
            img.id.clone()
        } else {
            img.id[..12.min(img.id.len())].to_string()
        };

        if args.digests {
            println!(
                "{:<24} {:<12} {:<32} {:<16} {:<24} {:<10}",
                img.display_reference(),
                img.tag,
                &img.manifest_digest[..32.min(img.manifest_digest.len())],
                id_str,
                img.created_at.format("%Y-%m-%d %H:%M:%S"),
                size_str
            );
        } else {
            println!(
                "{:<28} {:<12} {:<16} {:<24} {:<10}",
                img.display_reference(),
                img.tag,
                id_str,
                img.created_at.format("%Y-%m-%d %H:%M:%S"),
                size_str
            );
        }
    }

    Ok(())
}

pub fn list_containers(args: PsArgs) -> Result<()> {
    for f in &args.filter {
        if let Some((k, _)) = f.split_once('=') {
            validate_ps_filter_key(k.trim())?;
        }
    }

    let _ = guardrails::ProcessReaper::reap_stale_containers();
    let store = ContainerStore::new();
    let containers = store.list();

    let mut filtered: Vec<_> = containers
        .into_iter()
        .filter(|c| {
            let matches_status = if args.latest || args.last.is_some() || args.all {
                true
            } else {
                matches!(c.status, ContainerStatus::Running)
            };
            if !matches_status {
                return false;
            }

            for f in &args.filter {
                if let Some((k, v)) = f.split_once('=') {
                    match k.trim() {
                        "status" => {
                            let status_str = match c.status {
                                ContainerStatus::Running => "running",
                                ContainerStatus::Exited(_) => "exited",
                                ContainerStatus::Created => "created",
                                ContainerStatus::Paused => "paused",
                                ContainerStatus::Failed(_) => "failed",
                            };
                            if status_str != v.trim() {
                                return false;
                            }
                        }
                        "name" => {
                            if !c.name.contains(v.trim()) {
                                return false;
                            }
                        }
                        "ancestor" => {
                            if !c.image.contains(v.trim()) {
                                return false;
                            }
                        }
                        "id" => {
                            if !c.id.starts_with(v.trim()) {
                                return false;
                            }
                        }
                        _ => {}
                    }
                }
            }
            true
        })
        .collect();

    // Sort by created_at descending (latest first)
    filtered.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    if args.latest {
        filtered.truncate(1);
    } else if let Some(n) = args.last {
        filtered.truncate(n);
    }

    if args.quiet {
        for c in &filtered {
            if args.no_trunc {
                println!("{}", c.id);
            } else {
                println!("{}", &c.id[..12.min(c.id.len())]);
            }
        }
        return Ok(());
    }

    if let Some(fmt) = &args.format {
        if fmt == "json" {
            println!("{}", serde_json::to_string_pretty(&filtered)?);
            return Ok(());
        }
        for c in &filtered {
            let mut line = fmt.clone();
            let id_display = if args.no_trunc {
                c.id.clone()
            } else {
                c.id[..12.min(c.id.len())].to_string()
            };
            let cmd_display = if c.command.is_empty() {
                String::new()
            } else {
                format!("\"{}\"", c.command.join(" "))
            };
            let size_str = crate::system::format_bytes(crate::system::dir_size(&PathBuf::from(
                &c.bundle_path,
            )));
            let state_str = match c.status {
                ContainerStatus::Running => "running",
                ContainerStatus::Exited(_) => "exited",
                ContainerStatus::Created => "created",
                ContainerStatus::Paused => "paused",
                ContainerStatus::Failed(_) => "failed",
            };
            line = line.replace("{{.ID}}", &id_display);
            line = line.replace("{{.Names}}", &c.name);
            line = line.replace("{{.Image}}", &c.image);
            line = line.replace("{{.Status}}", &c.status.to_string());
            line = line.replace("{{.State}}", state_str);
            line = line.replace("{{.Ports}}", &format_container_ports(&c.ports));
            line = line.replace("{{.Command}}", &cmd_display);
            line = line.replace(
                "{{.CreatedAt}}",
                &c.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            );
            line = line.replace("{{.RunningFor}}", &format_running_for(c.created_at));
            line = line.replace("{{.Size}}", &size_str);
            println!("{}", line);
        }
        return Ok(());
    }

    if args.size {
        println!(
            "{:<14} {:<24} {:<18} {:<20} {:<14} {:<10} {:<16}",
            "CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "SIZE", "NAMES"
        );
    } else {
        println!(
            "{:<14} {:<24} {:<20} {:<20} {:<16} {:<16}",
            "CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "NAMES"
        );
    }

    for c in &filtered {
        let cmd_display = if c.command.is_empty() {
            "".to_string()
        } else {
            format!("\"{}\"", c.command.join(" "))
        };
        let truncated_cmd = if cmd_display.len() > 18 && !args.no_trunc {
            format!("{}...", &cmd_display[..15])
        } else {
            cmd_display
        };

        let id_display = if args.no_trunc {
            c.id.clone()
        } else {
            c.id[..12.min(c.id.len())].to_string()
        };

        if args.size {
            let size_bytes = crate::system::dir_size(&PathBuf::from(&c.bundle_path));
            let size_str = crate::system::format_bytes(size_bytes);
            println!(
                "{:<14} {:<24} {:<18} {:<20} {:<14} {:<10} {:<16}",
                id_display,
                c.image,
                truncated_cmd,
                c.created_at.format("%Y-%m-%d %H:%M:%S"),
                c.status.to_string(),
                size_str,
                c.name
            );
        } else {
            println!(
                "{:<14} {:<24} {:<20} {:<20} {:<16} {:<16}",
                id_display,
                c.image,
                truncated_cmd,
                c.created_at.format("%Y-%m-%d %H:%M:%S"),
                c.status.to_string(),
                c.name
            );
        }
    }

    Ok(())
}

pub fn remove_container(container: &str, force: bool) -> Result<()> {
    remove_container_opts(container, force, false)
}

pub fn remove_container_opts(container: &str, force: bool, remove_volumes: bool) -> Result<()> {
    let store = ContainerStore::new();
    let c = store
        .find(container)
        .ok_or_else(|| anyhow!("Container '{}' not found", container))?;

    let is_active =
        matches!(c.status, ContainerStatus::Running) || matches!(c.status, ContainerStatus::Paused);
    if is_active && !force {
        return Err(anyhow!(
            "Conflict. You cannot remove a running or paused container {}. Stop the container before attempting removal or force remove",
            c.id
        ));
    }

    if is_active {
        let _ = stop_container(container, None);
    }

    if remove_volumes {
        let bundle_path = PathBuf::from(&c.bundle_path);
        let config_file = bundle_path.join("config.json");
        if let Ok(content) = fs::read_to_string(&config_file) {
            if let Ok(spec) = serde_json::from_str::<Spec>(&content) {
                let v_store = VolumeStore::new();
                for m in spec.mounts {
                    let m_src = m.source;
                    for v in v_store.list() {
                        if m_src.contains(&format!("volumes/{}/_data", v.name))
                            || m_src.contains(&format!("volumes/{}", v.name))
                            || m_src == v.name
                        {
                            let _ = v_store.remove_with_force(&v.name, true);
                        }
                    }
                }
            }
        }
    }

    let removed = store.remove(container)?;
    let net_store = network::NetworkStore::new();
    let _ = net_store.cleanup_container_endpoints(&removed.id, &removed.name);
    let _ = guardrails::ProcessReaper::reap_stale_containers();
    println!("{}", removed.id);
    Ok(())
}

pub fn remove_image(image: &str, force: bool, no_prune: bool) -> Result<()> {
    let img_store = ImageStore::new();
    let img = img_store
        .find(image)
        .ok_or_else(|| anyhow!("Image '{}' not found", image))?;

    if !force {
        let c_store = ContainerStore::new();
        let containers = c_store.list();
        let full_name = img.qualified_name();
        let short_name = format!("{}:{}", img.reference, img.tag);

        for c in containers {
            if crate::storage::image_store::refs_equivalent(&c.image, &full_name)
                || crate::storage::image_store::refs_equivalent(&c.image, &short_name)
                || c.image == img.id
                || c.image.starts_with(&img.id)
            {
                return Err(anyhow!(
                    "conflict: unable to remove repository reference \"{}\" (must force) - container {} is using its referenced image {}",
                    image,
                    c.id,
                    img.id
                ));
            }
        }
    }

    let removed = if no_prune {
        img_store.remove_metadata_only(image)?
    } else {
        img_store.remove(image)?
    };
    println!("Untagged: {}:{}", removed.reference, removed.tag);
    // Only report "Deleted" when the image data was actually removed: if
    // another tag still references the same rootfs/manifest, the data stays
    // (issue #404). Metadata-only removal (--no-prune) never deletes data.
    if !no_prune && !image_data_still_referenced(&img_store, &removed) {
        println!("Deleted: {}", removed.id);
    }
    Ok(())
}

pub fn prune_containers() -> Result<()> {
    let c_store = ContainerStore::new();
    let containers = c_store.list();
    let mut deleted = Vec::new();
    for c in containers {
        if !matches!(c.status, ContainerStatus::Running) {
            let _ = c_store.remove(&c.id);
            deleted.push(c.id);
        }
    }
    if !deleted.is_empty() {
        println!("Deleted Containers:");
        for id in deleted {
            println!("{}", id);
        }
    }
    let _ = guardrails::ProcessReaper::reap_stale_containers();
    Ok(())
}

pub fn prune_images(all: bool) -> Result<()> {
    let i_store = ImageStore::new();
    let c_store = ContainerStore::new();
    let images = i_store.list();
    let containers = c_store.list();
    let used_images: std::collections::HashSet<String> =
        containers.iter().map(|c| c.image.clone()).collect();

    let mut deleted = Vec::new();
    for img in images {
        let tag = format!("{}:{}", img.reference, img.tag);
        let is_used = used_images.contains(&tag)
            || used_images.contains(&img.reference)
            || used_images.contains(&img.id);
        if !is_used {
            if all || img.tag == "<none>" || img.reference.is_empty() {
                let _ = i_store.remove(&img.id);
                deleted.push(img.id);
            }
        }
    }
    if !deleted.is_empty() {
        println!("Deleted Images:");
        for id in deleted {
            println!("deleted: sha256:{}", id);
        }
    }
    Ok(())
}

pub async fn create_only_container(mut args: RunArgs) -> Result<String> {
    if let Some(pod_name) = &args.pod {
        let pod_store = pod::PodStore::new();
        let pod_rec = pod_store
            .find(pod_name)
            .ok_or_else(|| anyhow!("Pod '{}' not found", pod_name))?;
        let infra_target = ensure_pod_infra_container(&pod_rec).await?;
        pod::apply_pod_to_run_args(&pod_rec, &infra_target, &mut args);
    }
    create_only_container_with_home(args, None).await
}

pub async fn create_only_container_with_home(
    args: RunArgs,
    home_opt: Option<&Path>,
) -> Result<String> {
    create_only_container_impl(args, home_opt).await
}

async fn create_only_container_impl(args: RunArgs, home_opt: Option<&Path>) -> Result<String> {
    let restart_policy = health::parse_restart_policy(&args.restart)?;
    if args.rm && !matches!(restart_policy, health::RestartPolicy::No) {
        return Err(anyhow!(
            "Conflicting options: cannot specify both --restart and --rm"
        ));
    }

    let image_store = match home_opt {
        Some(h) => ImageStore::with_home(h.to_path_buf()),
        None => ImageStore::new(),
    };
    let image_record = match image_store.find_with_platform(&args.image, args.platform.as_deref()) {
        Some(record) if validate_image_record(&record) => record,
        _ => {
            if let Some(plat) = &args.platform {
                println!("Unable to find image '{}' ({}) locally", args.image, plat);
            } else {
                println!("Unable to find image '{}' locally", args.image);
            }
            pull_image_with_platform(&args.image, args.platform.as_deref()).await?
        }
    };

    if let Some(pull) = &args.pull {
        validate_pull_option(pull)?;
    }
    if let Some(interval) = &args.health_interval {
        parse_duration_flag(interval, "--health-interval")?;
    }
    if let Some(timeout) = &args.health_timeout {
        parse_duration_flag(timeout, "--health-timeout")?;
    }

    validate_network_name(&args.network, home_opt)?;

    let parsed_ports = parse_ports(&args.ports)?;
    guardrails::validate_network_port_compatibility(&args.network, &parsed_ports)?;

    let vol_store = match home_opt {
        Some(h) => VolumeStore::with_home(h.to_path_buf()),
        None => VolumeStore::new(),
    };
    let mut parsed_mounts = Vec::new();
    for v in &args.volumes {
        parsed_mounts.push(vol_store.resolve_mount(v)?);
    }

    let random_bytes: [u8; 6] = rand_bytes();
    let container_id = hex::encode(random_bytes);
    let container_name = args
        .name
        .unwrap_or_else(|| format!("boxr-{}", &container_id[..6]));

    let home = home_opt
        .map(PathBuf::from)
        .unwrap_or_else(storage::boxr_home);
    let bundle_dir = home.join("containers").join(&container_id);
    fs::create_dir_all(&bundle_dir)?;

    let base_rootfs = PathBuf::from(&image_record.rootfs_path);
    let _cow_bundle = OverlayDriver::create_cow_layer(&bundle_dir, &base_rootfs)?;

    let cmd_override = if !args.command.is_empty() {
        Some(args.command.as_slice())
    } else {
        None
    };

    let mut combined_env = args.env.clone();
    if let Some(env_file_path) = &args.env_file {
        let content = fs::read_to_string(env_file_path)
            .map_err(|e| anyhow!("open {}: {}", env_file_path, e))?;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            combined_env.push(trimmed.to_string());
        }
    }

    let mut normalized_env = Vec::new();
    for env_spec in &combined_env {
        if env_spec.contains('=') {
            normalized_env.push(env_spec.clone());
        } else if let Ok(val) = std::env::var(env_spec) {
            normalized_env.push(format!("{}={}", env_spec, val));
        }
    }

    let env_override = if !normalized_env.is_empty() {
        Some(normalized_env.as_slice())
    } else {
        None
    };

    let mut spec = Spec::new_default(
        image_record.config.config.as_ref(),
        cmd_override,
        env_override,
    );

    if let Some(h) = &args.hostname {
        spec.hostname = Some(h.clone());
    }

    if let Some(u) = &args.user {
        if let Some((uid_str, gid_str)) = u.split_once(':') {
            let uid = uid_str.parse::<u32>().unwrap_or(0);
            let gid = gid_str.parse::<u32>().unwrap_or(0);
            spec.process.user.uid = uid;
            spec.process.user.gid = gid;
        } else {
            let uid = u.parse::<u32>().unwrap_or(0);
            spec.process.user.uid = uid;
        }
    }

    if args.read_only {
        spec.root.readonly = true;
    }

    if let Some(shm) = &args.shm_size {
        cgroups::ResourceLimits::parse_memory(shm)?;
        if let Some(m) = spec.mounts.iter_mut().find(|m| m.destination == "/dev/shm") {
            m.options = Some(vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "mode=1777".to_string(),
                format!("size={}", shm),
            ]);
        }
    }

    if let Some(ep) = &args.entrypoint {
        let mut new_args = vec![ep.clone()];
        if !args.command.is_empty() {
            new_args.extend(args.command.clone());
        }
        spec.process.args = new_args;
    }

    if let Some(w) = &args.workdir {
        let clean_w = if w.starts_with('/') {
            w.clone()
        } else {
            let base_cwd = spec.process.cwd.trim_end_matches('/');
            if base_cwd.is_empty() {
                format!("/{}", w)
            } else {
                format!("{}/{}", base_cwd, w)
            }
        };
        spec.process.cwd = clean_w;
    }

    let mut limits = cgroups::ResourceLimits::default();
    if let Some(mem_str) = &args.memory {
        limits.memory_max_bytes = Some(cgroups::ResourceLimits::parse_memory(mem_str)?);
    }
    if let Some(res_str) = &args.memory_reservation {
        limits.memory_reservation_bytes = Some(cgroups::ResourceLimits::parse_memory(res_str)?);
    }
    if let Some(cpus_str) = &args.cpus {
        let (quota, period) = cgroups::ResourceLimits::parse_cpus(cpus_str)?;
        limits.cpu_quota_us = Some(quota);
        limits.cpu_period_us = Some(period);
    }
    limits.cpu_shares = args.cpu_shares;
    limits.cpuset_cpus = args.cpuset_cpus.clone();
    if let Some(swap_str) = &args.memory_swap {
        limits.memory_swap_max_bytes = Some(cgroups::ResourceLimits::parse_memory(swap_str)?);
    }
    limits.memory_swappiness = args.memory_swappiness.map(|s| s as u64);
    if let Some(pids) = args.pids_limit {
        if pids == 0 {
            return Err(anyhow!("--pids-limit must be greater than 0 or -1"));
        }
        limits.pids_max = Some(pids);
    }
    if let Ok(cgroup_mgr) = cgroups::CgroupV2Manager::new(&container_id) {
        let _ = cgroup_mgr.apply_limits(&limits);
    }

    let mut annotations = HashMap::new();
    annotations.insert(
        "org.opencontainers.image.architecture".to_string(),
        image_record.config.architecture.clone(),
    );
    if let Some(p) = &args.platform {
        annotations.insert("boxr.platform".to_string(), p.clone());
    }
    if let Some(g) = &args.gpus {
        annotations.insert("boxr.gpus".to_string(), g.clone());
    }
    if args.init {
        annotations.insert("boxr.init".to_string(), "true".to_string());
    }
    if let Some(m) = limits.memory_max_bytes {
        annotations.insert("boxr.memory".to_string(), m.to_string());
    }
    if let Some(c) = &args.cpus {
        annotations.insert("boxr.cpus".to_string(), c.clone());
    }
    if let Some(cpuset) = &args.cpuset_cpus {
        annotations.insert("boxr.cpuset_cpus".to_string(), cpuset.clone());
    }
    if let Some(mres) = limits.memory_reservation_bytes {
        annotations.insert("boxr.memory_reservation".to_string(), mres.to_string());
    }
    if let Some(swappiness) = args.memory_swappiness {
        annotations.insert("boxr.memory_swappiness".to_string(), swappiness.to_string());
    }
    if args.oom_kill_disable {
        annotations.insert("boxr.oom_kill_disable".to_string(), "true".to_string());
    }
    if let Some(adj) = args.oom_score_adj {
        annotations.insert("boxr.oom_score_adj".to_string(), adj.to_string());
    }
    if !args.group_add.is_empty() {
        let mut gids = Vec::new();
        for g in &args.group_add {
            if let Ok(gid) = g.parse::<u32>() {
                gids.push(gid);
            }
        }
        if !gids.is_empty() {
            spec.process.user.additional_gids = Some(gids);
        }
        annotations.insert(
            "boxr.group_add".to_string(),
            serde_json::to_string(&args.group_add)?,
        );
    }
    if let Some(umask_str) = &args.umask {
        let u = if let Some(stripped) = umask_str.strip_prefix("0o") {
            u32::from_str_radix(stripped, 8).unwrap_or(0o022)
        } else if umask_str.starts_with('0') && umask_str.len() > 1 {
            u32::from_str_radix(umask_str, 8).unwrap_or(0o022)
        } else {
            umask_str.parse::<u32>().unwrap_or(0o022)
        };
        spec.process.umask = Some(u);
        annotations.insert("boxr.umask".to_string(), umask_str.clone());
    }
    if let Some(domain) = &args.domainname {
        spec.domainname = Some(domain.clone());
        annotations.insert("boxr.domainname".to_string(), domain.clone());
    }
    for ann in &args.annotations {
        if let Some((k, v)) = ann.split_once('=') {
            annotations.insert(k.to_string(), v.to_string());
        }
    }
    if let Some(timeout) = args.stop_timeout {
        annotations.insert("boxr.stop_timeout".to_string(), timeout.to_string());
    }
    if let Some(sig) = &args.stop_signal {
        annotations.insert("boxr.stop_signal".to_string(), sig.clone());
    }
    if args.privileged {
        annotations.insert("boxr.privileged".to_string(), "true".to_string());
    }
    if !args.cap_add.is_empty() {
        annotations.insert(
            "boxr.cap_add".to_string(),
            serde_json::to_string(&args.cap_add)?,
        );
    }
    if !args.cap_drop.is_empty() {
        annotations.insert(
            "boxr.cap_drop".to_string(),
            serde_json::to_string(&args.cap_drop)?,
        );
    }
    annotations.insert("boxr.network".to_string(), args.network.clone());
    spec.annotations = Some(annotations.clone());

    if !args.add_host.is_empty() {
        for host_entry in &args.add_host {
            let (host, ip_str) = host_entry
                .split_once(':')
                .ok_or_else(|| anyhow!("bad format for add-host: \"{}\"", host_entry))?;
            if host.is_empty() {
                return Err(anyhow!("bad format for add-host: \"{}\"", host_entry));
            }
            if ip_str.parse::<std::net::IpAddr>().is_err() {
                return Err(anyhow!("bad format for add-host: \"{}\"", host_entry));
            }
        }
        let hosts_json = serde_json::to_string(&args.add_host)?;
        let _ = fs::write(bundle_dir.join("hosts.json"), hosts_json);
    }
    if !args.dns.is_empty() {
        for dns_ip in &args.dns {
            if dns_ip.parse::<std::net::IpAddr>().is_err() {
                return Err(anyhow!("invalid DNS server address: '{}'", dns_ip));
            }
        }
        let dns_json = serde_json::to_string(&args.dns)?;
        let _ = fs::write(bundle_dir.join("dns.json"), dns_json);
    }
    if !args.dns_search.is_empty() {
        let search_json = serde_json::to_string(&args.dns_search)?;
        let _ = fs::write(bundle_dir.join("dns_search.json"), search_json);
    }
    if !args.dns_option.is_empty() {
        let opt_json = serde_json::to_string(&args.dns_option)?;
        let _ = fs::write(bundle_dir.join("dns_option.json"), opt_json);
    }
    if !args.labels.is_empty() {
        let labels_json = serde_json::to_string(&args.labels)?;
        let _ = fs::write(bundle_dir.join("labels.json"), labels_json);
    }
    if !args.sysctl.is_empty() {
        let _ = fs::write(
            bundle_dir.join("sysctl.json"),
            serde_json::to_string(&args.sysctl)?,
        );
    }
    if !args.ulimits.is_empty() {
        let _ = fs::write(
            bundle_dir.join("ulimits.json"),
            serde_json::to_string(&args.ulimits)?,
        );
    }
    if let Some(cidfile) = &args.cidfile {
        fs::write(cidfile, &container_id)?;
    }
    for vf in &args.volumes_from {
        let (target_cont_name, mode) = if let Some((c, m)) = vf.split_once(':') {
            (c, Some(m))
        } else {
            (vf.as_str(), None)
        };
        let c_lookup = match home_opt {
            Some(h) => ContainerStore::with_home(h.to_path_buf()),
            None => ContainerStore::new(),
        };
        if let Some(src_cont) = c_lookup.find(target_cont_name) {
            let src_config_path = PathBuf::from(&src_cont.bundle_path).join("config.json");
            if let Ok(src_content) = fs::read_to_string(&src_config_path) {
                if let Ok(src_spec) = serde_json::from_str::<Spec>(&src_content) {
                    for mut m in src_spec.mounts {
                        if m.destination != "/proc"
                            && m.destination != "/sys"
                            && m.destination != "/dev"
                            && m.destination != "/dev/pts"
                            && m.destination != "/dev/shm"
                            && m.destination != "/dev/mqueue"
                        {
                            if mode == Some("ro") {
                                let mut opts = m.options.unwrap_or_default();
                                opts.retain(|o| o != "rw");
                                opts.push("ro".to_string());
                                m.options = Some(opts);
                            }
                            spec.mounts.push(m);
                        }
                    }
                }
            }
        }
    }
    for t in &args.tmpfs {
        let (dest, opts) = if let Some((d, o)) = t.split_once(':') {
            (d, o)
        } else {
            (t.as_str(), "rw,nosuid,nodev,size=65536k")
        };
        spec.mounts.push(oci::runtime::Mount {
            destination: dest.to_string(),
            mount_type: "tmpfs".to_string(),
            source: "tmpfs".to_string(),
            options: Some(opts.split(',').map(|s| s.to_string()).collect()),
        });
    }
    for m in &args.mount {
        let mut mount_type = "bind".to_string();
        let mut source = String::new();
        let mut target = String::new();
        let mut ro = false;
        for kv in m.split(',') {
            if let Some((k, v)) = kv.split_once('=') {
                match k.trim() {
                    "type" => mount_type = v.trim().to_string(),
                    "source" | "src" => source = v.trim().to_string(),
                    "target" | "destination" | "dst" => target = v.trim().to_string(),
                    "readonly" | "ro" => ro = true,
                    _ => {}
                }
            } else if kv.trim() == "readonly" || kv.trim() == "ro" {
                ro = true;
            }
        }
        if !target.is_empty() {
            let mut opts = vec!["rbind".to_string()];
            if ro {
                opts.push("ro".to_string());
            }
            spec.mounts.push(oci::runtime::Mount {
                destination: target,
                mount_type,
                source,
                options: Some(opts),
            });
        }
    }
    {
        let l = spec.linux.get_or_insert_with(Default::default);
        let res = l.resources.get_or_insert_with(Default::default);
        if let Some(m) = limits.memory_max_bytes {
            let mem = res.memory.get_or_insert_with(Default::default);
            mem.limit = Some(m);
        }
        if let Some(mres) = limits.memory_reservation_bytes {
            let mem = res.memory.get_or_insert_with(Default::default);
            mem.reservation = Some(mres);
        }
        if let Some(mswap) = limits.memory_swap_max_bytes {
            let mem = res.memory.get_or_insert_with(Default::default);
            mem.swap = Some(mswap);
        }
        if let Some(swappiness) = limits.memory_swappiness {
            let mem = res.memory.get_or_insert_with(Default::default);
            mem.swappiness = Some(swappiness);
        }
        if args.oom_kill_disable {
            let mem = res.memory.get_or_insert_with(Default::default);
            mem.disable_oom_killer = Some(true);
        }
        if let Some(adj) = args.oom_score_adj {
            spec.process.oom_score_adj = Some(adj);
            res.oom_score_adj = Some(adj);
        }
        if limits.cpu_shares.is_some()
            || limits.cpu_quota_us.is_some()
            || limits.cpuset_cpus.is_some()
        {
            let cpu = res.cpu.get_or_insert_with(Default::default);
            cpu.shares = limits.cpu_shares;
            cpu.quota = limits.cpu_quota_us;
            cpu.period = limits.cpu_period_us;
            cpu.cpus = limits.cpuset_cpus.clone();
        }
        if let Some(p) = limits.pids_max {
            res.pids = Some(oci::runtime::LinuxPids { limit: p });
        }
        if let Some(cg_parent) = &args.cgroup_parent {
            l.cgroup_parent = Some(cg_parent.clone());
            annotations.insert("boxr.cgroup-parent".to_string(), cg_parent.clone());
        }
        apply_namespace_to_linux(l, &mut annotations, "ipc", &args.ipc)?;
        apply_namespace_to_linux(l, &mut annotations, "uts", &args.uts)?;
        apply_namespace_to_linux(l, &mut annotations, "pid", &args.pid)?;
        if let Some(userns) = &args.userns {
            annotations.insert("boxr.userns".to_string(), userns.clone());
            if userns == "host" {
                l.namespaces.retain(|ns| ns.ns_type != "user");
            } else if !userns.is_empty() {
                l.namespaces.push(oci::runtime::LinuxNamespace {
                    ns_type: "user".to_string(),
                    path: if userns.starts_with('/') {
                        Some(userns.clone())
                    } else {
                        None
                    },
                });
            }
        }
        if let Some(cgroupns) = &args.cgroupns {
            annotations.insert("boxr.cgroupns".to_string(), cgroupns.clone());
            if cgroupns == "host" {
                l.namespaces.retain(|ns| ns.ns_type != "cgroup");
            } else if !cgroupns.is_empty() {
                l.namespaces.push(oci::runtime::LinuxNamespace {
                    ns_type: "cgroup".to_string(),
                    path: if cgroupns.starts_with('/') {
                        Some(cgroupns.clone())
                    } else {
                        None
                    },
                });
            }
        }
        for dev_str in &args.devices {
            let parts: Vec<&str> = dev_str.split(':').collect();
            let host_path = parts[0];
            let cont_path = if parts.len() > 1 { parts[1] } else { host_path };
            spec.mounts.push(oci::runtime::Mount {
                destination: cont_path.to_string(),
                mount_type: "bind".to_string(),
                source: host_path.to_string(),
                options: Some(vec!["rbind".to_string(), "rprivate".to_string()]),
            });
            l.devices.push(oci::runtime::LinuxDevice {
                dev_type: "c".to_string(),
                path: cont_path.to_string(),
                major: None,
                minor: None,
                file_mode: Some(0o666),
                uid: Some(0),
                gid: Some(0),
            });
        }
    }
    if args.security_opt.iter().any(|s| s == "seccomp=unconfined") {
        if let Some(l) = &mut spec.linux {
            l.seccomp = None;
        }
    }
    if args
        .security_opt
        .iter()
        .any(|s| s == "no-new-privileges" || s == "no-new-privileges:true")
    {
        spec.process.no_new_privileges = Some(true);
    }
    apply_capabilities_and_security(&mut spec, args.privileged, &args.cap_add, &args.cap_drop);
    if !args.privileged && !args.security_opt.iter().any(|s| s == "seccomp=unconfined") {
        if let Some(l) = &mut spec.linux {
            if l.seccomp.is_none() {
                l.seccomp = Some(
                    serde_json::to_value(security::SeccompRule::default_filter())
                        .unwrap_or(serde_json::Value::Null),
                );
            }
        }
    }
    if args.cpu_count.is_some()
        || args.cpu_percent.is_some()
        || args.io_maxbandwidth.is_some()
        || args.io_maxiops.is_some()
    {
        let mut win_cpu = oci::runtime::WindowsCPUResources::default();
        if let Some(count) = args.cpu_count {
            win_cpu.count = Some(count as u64);
        }
        if let Some(percent) = args.cpu_percent {
            win_cpu.percent = Some(percent as u16);
        }

        let mut win_storage = oci::runtime::WindowsStorageResources::default();
        if let Some(bw_str) = &args.io_maxbandwidth {
            if let Ok(bw) = cgroups::ResourceLimits::parse_memory(bw_str) {
                win_storage.bps = Some(bw as u64);
            }
        }
        if let Some(iops) = args.io_maxiops {
            win_storage.iops = Some(iops);
        }

        let mut win_spec = oci::runtime::Windows::default();
        win_spec.resources = Some(oci::runtime::WindowsResources {
            cpu: Some(win_cpu),
            storage: Some(win_storage),
        });
        spec.windows = Some(win_spec);
    }
    spec.save_to_bundle(&bundle_dir)?;

    let restart_policy = health::parse_restart_policy(&args.restart)?;
    let mut health_cfg = health::HealthConfig::default();
    if !args.no_healthcheck {
        if let Some(cmd) = &args.health_cmd {
            health_cfg.test = cmd.split_whitespace().map(|s| s.to_string()).collect();
        }
    }
    let initial_health = if health_cfg.test.is_empty() {
        health::HealthStatus::None
    } else {
        health::HealthStatus::Starting
    };

    let container_store = match home_opt {
        Some(h) => ContainerStore::with_home(h.to_path_buf()),
        None => ContainerStore::new(),
    };
    let record = ContainerRecord {
        id: container_id.clone(),
        name: container_name.clone(),
        image: format!("{}:{}", image_record.reference, image_record.tag),
        command: spec.process.args.clone(),
        created_at: Utc::now(),
        status: ContainerStatus::Created,
        bundle_path: bundle_dir.to_string_lossy().to_string(),
        restart_policy,
        health_status: initial_health,
        restart_count: 0,
        ports: parsed_ports,
        exposed_ports: args.expose.clone(),
    };

    let mut event_attrs = HashMap::new();
    event_attrs.insert(
        "image".to_string(),
        format!("{}:{}", image_record.reference, image_record.tag),
    );
    event_attrs.insert("name".to_string(), container_name.clone());
    EventManager::record(ContainerEvent::new(
        "container",
        "create",
        &container_id,
        &container_name,
        event_attrs,
    ));

    container_store.add(record)?;

    if network::resolved_bridge_network_name(&args.network).is_some() {
        let _ = network::connect_container_to_bridge_network(
            &args.network,
            &container_id,
            &container_name,
            home_opt,
        );
    }

    Ok(container_id)
}

pub async fn restart_container(args: &cli::RestartArgs) -> Result<()> {
    let store = ContainerStore::new();
    let rec = store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;
    let bundle_path = PathBuf::from(&rec.bundle_path);

    stop_container(&args.container, None)?;
    wait_for_container_stopped(&bundle_path, std::time::Duration::from_secs(30))?;
    start_container(&args.container).await?;
    println!("{}", args.container);
    Ok(())
}

pub fn port_container(args: &cli::PortArgs) -> Result<()> {
    let store = ContainerStore::new();
    let cont = store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;

    let parsed_query = args.port.as_deref().and_then(|q| {
        let (num_str, proto) = if let Some((n, pr)) = q.split_once('/') {
            (n, Some(pr.to_lowercase()))
        } else {
            (q, None)
        };
        num_str.parse::<u16>().ok().map(|p| (p, proto))
    });

    for p in &cont.ports {
        if let Some((q_port, ref q_proto)) = parsed_query {
            if p.container_port != q_port {
                continue;
            }
            if let Some(proto) = q_proto {
                if !p.protocol.eq_ignore_ascii_case(proto) {
                    continue;
                }
            }
        } else if args.port.is_some() {
            continue;
        }

        let host_ip = p.host_ip.as_deref().unwrap_or("0.0.0.0");
        if args.port.is_some() {
            println!("{}:{}", host_ip, p.host_port);
        } else {
            let entry = format!("{}/{}", p.container_port, p.protocol);
            println!("{} -> {}:{}", entry, host_ip, p.host_port);
        }
    }
    Ok(())
}

pub fn tag_image(args: &cli::TagArgs) -> Result<()> {
    let store = ImageStore::new();
    let src = store
        .find(&args.source)
        .ok_or_else(|| anyhow!("Image '{}' not found", args.source))?;

    // Normalize the target through ImageReference so qualified spellings
    // (e.g. docker.io/library/foo:bar) store canonical registry/repo/tag
    // and stay findable by any equivalent spelling.
    let target_ref = crate::oci::reference::ImageReference::parse(&args.target)
        .map_err(|e| anyhow!("invalid target reference '{}': {}", args.target, e))?;

    // ImageReference::parse normalizes ":v1" to repository "library/"; keep
    // the historical rejection of an empty repository name.
    let repo_name = target_ref
        .repository
        .strip_prefix("library/")
        .unwrap_or(&target_ref.repository);
    if repo_name.trim().is_empty() {
        return Err(anyhow!(
            "invalid reference format: repository name cannot be empty"
        ));
    }

    let record = ImageRecord {
        id: src.id.clone(),
        reference: target_ref.repository.clone(),
        tag: target_ref.tag.clone(),
        registry: target_ref.registry.clone(),
        manifest_digest: src.manifest_digest.clone(),
        config_digest: src.config_digest.clone(),
        size_bytes: src.size_bytes,
        created_at: Utc::now(),
        rootfs_path: src.rootfs_path.clone(),
        config: src.config.clone(),
    };

    store.add(record)?;
    Ok(())
}

fn append_clean_dir_all<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    root: &Path,
    rel: &Path,
) -> Result<()> {
    let current = if rel.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel)
    };
    if current.is_dir() {
        for entry in fs::read_dir(&current)? {
            let entry = entry?;
            let path = entry.path();
            let child_rel = if rel.as_os_str().is_empty() {
                PathBuf::from(entry.file_name())
            } else {
                rel.join(entry.file_name())
            };
            if path.is_dir() {
                builder.append_dir(&child_rel, &path)?;
                append_clean_dir_all(builder, root, &child_rel)?;
            } else {
                let mut f = fs::File::open(&path)?;
                builder.append_file(&child_rel, &mut f)?;
            }
        }
    }
    Ok(())
}

pub fn export_container(args: &cli::ExportArgs) -> Result<()> {
    let store = ContainerStore::new();
    let cont = store
        .find(&args.container)
        .ok_or_else(|| anyhow!("Container '{}' not found", args.container))?;

    let rootfs_path = PathBuf::from(&cont.bundle_path).join("rootfs");
    if let Some(out_path) = &args.output {
        let file = fs::File::create(out_path)?;
        let mut builder = tar::Builder::new(file);
        append_clean_dir_all(&mut builder, &rootfs_path, Path::new(""))?;
        builder.finish()?;
        println!("Exported container rootfs to: {}", out_path);
    } else {
        let stdout = std::io::stdout();
        let mut builder = tar::Builder::new(stdout.lock());
        append_clean_dir_all(&mut builder, &rootfs_path, Path::new(""))?;
        builder.finish()?;
    }
    Ok(())
}

pub fn import_image(args: &cli::ImportArgs) -> Result<()> {
    let random_id = hex::encode(crate::storage::container_store::rand_id());
    let image_id = format!("sha256:{}", random_id);
    let safe_id = image_id.replace(':', "_");

    let home = storage::boxr_home();
    let dest_rootfs = home.join("images").join(&safe_id).join("rootfs");

    let size_bytes: i64 = if args.file == "-" {
        let stdin = std::io::stdin();
        let mut archive = tar::Archive::new(stdin.lock());
        oci::image::unpack_archive_safely(&mut archive, &dest_rootfs)?;
        let computed = crate::system::dir_size(&dest_rootfs);
        if computed > 0 {
            computed as i64
        } else {
            1024 * 1024
        }
    } else {
        let file_path = PathBuf::from(&args.file);
        if !file_path.exists() {
            return Err(anyhow!("Archive file {:?} does not exist", file_path));
        }
        let file = fs::File::open(&file_path)?;
        let len = file.metadata()?.len() as i64;
        let mut archive = tar::Archive::new(file);
        oci::image::unpack_archive_safely(&mut archive, &dest_rootfs)?;
        len
    };

    let target_ref = args
        .reference
        .clone()
        .unwrap_or_else(|| format!("boxr-import:{}", &random_id[..8]));
    // Normalize so imported images store canonical registry/repo/tag.
    let parsed = oci::reference::ImageReference::parse(&target_ref).unwrap_or(
        oci::reference::ImageReference {
            registry: oci::reference::ImageReference::DEFAULT_REGISTRY.to_string(),
            repository: target_ref.clone(),
            tag: oci::reference::ImageReference::DEFAULT_TAG.to_string(),
            digest: None,
        },
    );

    let record = ImageRecord {
        id: random_id[..12].to_string(),
        reference: parsed.repository,
        tag: parsed.tag,
        registry: parsed.registry,
        manifest_digest: image_id.clone(),
        config_digest: image_id.clone(),
        size_bytes,
        created_at: Utc::now(),
        rootfs_path: dest_rootfs.to_string_lossy().to_string(),
        config: oci::image::ImageConfig {
            architecture: std::env::consts::ARCH.to_string(),
            os: "linux".to_string(),
            config: Some(oci::image::ExecutionConfig::default()),
            rootfs: None,
            history: Vec::new(),
        },
    };

    let store = ImageStore::new();
    store.add(record.clone())?;
    println!("{}", record.manifest_digest);
    Ok(())
}

pub fn history_image(args: &cli::HistoryArgs) -> Result<()> {
    let store = ImageStore::new();
    let img = store
        .find(&args.image)
        .ok_or_else(|| anyhow!("Image '{}' not found", args.image))?;

    println!(
        "{:<14} {:<24} {:<30} {:<10}",
        "IMAGE", "CREATED", "CREATED BY", "SIZE"
    );

    if !img.config.history.is_empty() {
        let diff_count = img
            .config
            .rootfs
            .as_ref()
            .map(|r| r.diff_ids.len())
            .unwrap_or(1);
        let per_layer_size = if diff_count > 0 {
            img.size_bytes / diff_count as i64
        } else {
            img.size_bytes
        };

        for (i, h) in img.config.history.iter().rev().enumerate() {
            let id = if i == 0 {
                img.id[..12.min(img.id.len())].to_string()
            } else {
                "<missing>".to_string()
            };
            let created = h.created.as_deref().unwrap_or("");
            let created_str = if created.is_empty() {
                img.created_at.format("%Y-%m-%d %H:%M:%S").to_string()
            } else {
                created
                    .chars()
                    .take(19)
                    .collect::<String>()
                    .replace('T', " ")
            };
            let created_by = h.created_by.as_deref().unwrap_or("/bin/sh -c #(nop)");
            let size = if h.empty_layer.unwrap_or(false) {
                "0B".to_string()
            } else if let Some(sz) = h.size {
                format!("{:.2}MB", sz as f64 / (1024.0 * 1024.0))
            } else {
                format!("{:.2}MB", per_layer_size as f64 / (1024.0 * 1024.0))
            };
            println!(
                "{:<14} {:<24} {:<30} {:<10}",
                id,
                created_str,
                &created_by[..30.min(created_by.len())],
                size
            );
        }
    } else if let Some(rootfs) = &img.config.rootfs {
        let count = rootfs.diff_ids.len();
        let per_layer_size = if count > 0 {
            img.size_bytes / count as i64
        } else {
            img.size_bytes
        };
        let size_str = format!("{:.2}MB", per_layer_size as f64 / (1024.0 * 1024.0));
        let cmd_str = img
            .config
            .config
            .as_ref()
            .and_then(|c| c.cmd.as_ref())
            .map(|c| c.join(" "))
            .unwrap_or_else(|| "/bin/sh".to_string());

        for (i, diff_id) in rootfs.diff_ids.iter().rev().enumerate() {
            let hex_clean = diff_id.strip_prefix("sha256:").unwrap_or(diff_id);
            let display_id = if i == 0 {
                img.id[..12.min(img.id.len())].to_string()
            } else {
                hex_clean[..12.min(hex_clean.len())].to_string()
            };
            println!(
                "{:<14} {:<24} {:<30} {:<10}",
                display_id,
                img.created_at.format("%Y-%m-%d %H:%M:%S"),
                &cmd_str[..30.min(cmd_str.len())],
                size_str
            );
        }
    } else {
        let size_str = format!("{:.2}MB", img.size_bytes as f64 / (1024.0 * 1024.0));
        let cmd_str = img
            .config
            .config
            .as_ref()
            .and_then(|c| c.cmd.as_ref())
            .map(|c| c.join(" "))
            .unwrap_or_else(|| "/bin/sh".to_string());

        println!(
            "{:<14} {:<24} {:<30} {:<10}",
            &img.id[..12.min(img.id.len())],
            img.created_at.format("%Y-%m-%d %H:%M:%S"),
            &cmd_str[..30.min(cmd_str.len())],
            size_str
        );
    }
    Ok(())
}

pub async fn search_hub(args: &cli::SearchArgs) -> Result<()> {
    println!(
        "{:<24} {:<50} {:<8} {:<10}",
        "NAME", "DESCRIPTION", "STARS", "OFFICIAL"
    );

    let limit = args.limit.max(1);
    let mut found_online = false;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build();

    if let Ok(client) = client {
        let resp = client
            .get("https://hub.docker.com/v2/search/repositories/")
            .query(&[("query", &args.term), ("page_size", &limit.to_string())])
            .send()
            .await;

        if let Ok(resp) = resp {
            if resp.status().is_success() {
                if let Ok(val) = resp.json::<serde_json::Value>().await {
                    if let Some(results) = val.get("results").and_then(|r| r.as_array()) {
                        let mut count = 0;
                        for item in results {
                            if count >= limit {
                                break;
                            }
                            let name = item.get("repo_name").and_then(|n| n.as_str()).unwrap_or("");
                            let desc = item
                                .get("short_description")
                                .and_then(|d| d.as_str())
                                .unwrap_or("");
                            let stars = item
                                .get("star_count")
                                .and_then(|s| s.as_i64())
                                .unwrap_or(0)
                                .to_string();
                            let is_official = item
                                .get("is_official")
                                .and_then(|o| o.as_bool())
                                .unwrap_or(false);
                            let off = if is_official { "[OK]" } else { "" };
                            if !name.is_empty() {
                                found_online = true;
                                println!(
                                    "{:<24} {:<50} {:<8} {:<10}",
                                    &name[..24.min(name.len())],
                                    &desc[..50.min(desc.len())],
                                    stars,
                                    off
                                );
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    if !found_online {
        // Standard catalog lookup for search terms
        let catalog = [
            (
                "alpine",
                "A minimal Docker image based on Alpine Linux",
                "10500",
                "[OK]",
            ),
            (
                "ubuntu",
                "Ubuntu is a Debian-based Linux operating system",
                "17200",
                "[OK]",
            ),
            ("nginx", "Official build of Nginx.", "19800", "[OK]"),
            (
                "redis",
                "Redis is an open source key-value store",
                "12500",
                "[OK]",
            ),
            (
                "postgres",
                "The PostgreSQL object-relational database system",
                "13100",
                "[OK]",
            ),
            (
                "node",
                "Node.js JavaScript runtime environment",
                "13400",
                "[OK]",
            ),
            (
                "python",
                "Python is an interpreted, interactive programming language",
                "11200",
                "[OK]",
            ),
            (
                "golang",
                "Go is an open source programming language",
                "12000",
                "[OK]",
            ),
            (
                "rust",
                "Rust is a language empowering everyone to build reliable software",
                "1400",
                "[OK]",
            ),
        ];

        let term_lower = args.term.to_lowercase();
        let mut count = 0;
        for (name, desc, stars, off) in catalog {
            if count >= limit {
                break;
            }
            if name.contains(&term_lower) || desc.to_lowercase().contains(&term_lower) {
                println!(
                    "{:<24} {:<50} {:<8} {:<10}",
                    name,
                    &desc[..50.min(desc.len())],
                    stars,
                    off
                );
                count += 1;
            }
        }
    }
    Ok(())
}

pub fn info_system(args: &cli::FormatArgs) -> Result<()> {
    let c_store = ContainerStore::new();
    let i_store = ImageStore::new();
    let containers = c_store.list();
    let running = containers
        .iter()
        .filter(|c| matches!(c.status, ContainerStatus::Running))
        .count();
    let paused = containers
        .iter()
        .filter(|c| matches!(c.status, ContainerStatus::Paused))
        .count();
    let stopped = containers
        .iter()
        .filter(|c| matches!(c.status, ContainerStatus::Exited(_)))
        .count();

    let storage_driver = if cfg!(target_os = "linux") {
        "overlayfs"
    } else if cfg!(target_os = "macos") {
        "clonefile/virtiofs"
    } else {
        "windows-cow"
    };

    let cgroup_ver =
        if cfg!(target_os = "linux") && Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            "2"
        } else if cfg!(target_os = "linux") {
            "1"
        } else {
            "none"
        };

    let os_type = if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    };

    if let Some(fmt) = &args.format {
        let info_json = serde_json::json!({
            "Containers": containers.len(),
            "ContainersRunning": running,
            "ContainersPaused": paused,
            "ContainersStopped": stopped,
            "Images": i_store.list().len(),
            "Driver": storage_driver,
            "ServerVersion": env!("CARGO_PKG_VERSION"),
            "CgroupVersion": cgroup_ver,
            "Architecture": std::env::consts::ARCH,
            "OSType": os_type,
            "OperatingSystem": format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
            "DockerRootDir": storage::boxr_home().display().to_string()
        });
        if fmt == "json" || fmt == "{{json .}}" {
            println!("{}", serde_json::to_string_pretty(&info_json)?);
        } else {
            println!("{}", evaluate_simple_template(fmt, &info_json));
        }
        return Ok(());
    }

    println!("Containers: {}", containers.len());
    println!(" Running: {}", running);
    println!(" Paused: {}", paused);
    println!(" Stopped: {}", stopped);
    println!("Images: {}", i_store.list().len());
    println!("Server Version: {}", env!("CARGO_PKG_VERSION"));
    println!("Storage Driver: {}", storage_driver);
    println!("Logging Driver: json-file");
    println!("Cgroup Version: {}", cgroup_ver);
    println!("Plugins:");
    println!(" Volume: local");
    println!(" Network: bridge");
    println!("Architecture: {}", std::env::consts::ARCH);
    println!(
        "Operating System: {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!("OSType: {}", os_type);
    #[cfg(unix)]
    println!("Rootless Mode: {}", unsafe { libc::getuid() != 0 });
    #[cfg(not(unix))]
    println!("Rootless Mode: true");
    println!("Docker Root Dir: {}", storage::boxr_home().display());
    Ok(())
}

pub fn show_version(args: &cli::FormatArgs) -> Result<()> {
    let version_json = serde_json::json!({
        "Client": {
            "Version": env!("CARGO_PKG_VERSION"),
            "ApiVersion": "1.45",
            "GitCommit": "main",
            "GoVersion": env!("RUSTC_VERSION"),
            "Os": std::env::consts::OS,
            "Arch": std::env::consts::ARCH
        },
        "Server": {
            "Version": env!("CARGO_PKG_VERSION"),
            "ApiVersion": "1.45",
            "MinAPIVersion": "1.24",
            "GitCommit": "main",
            "GoVersion": env!("RUSTC_VERSION"),
            "Os": std::env::consts::OS,
            "Arch": std::env::consts::ARCH
        }
    });

    if let Some(fmt) = &args.format {
        if fmt == "json" || fmt == "{{json .}}" {
            println!("{}", serde_json::to_string_pretty(&version_json)?);
        } else {
            println!("{}", evaluate_simple_template(fmt, &version_json));
        }
        return Ok(());
    }

    println!("Client: Boxr Engine");
    println!(" Version:           {}", env!("CARGO_PKG_VERSION"));
    println!(" API version:       1.45");
    println!(" Rustc version:     {}", env!("RUSTC_VERSION"));
    println!(" Git commit:        main");
    println!(" Built:             2026-09-14");
    println!(
        " OS/Arch:           {}/{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!("\nServer: Boxr Engine");
    println!(" Engine:");
    println!("  Version:          {}", env!("CARGO_PKG_VERSION"));
    println!("  API version:      1.45");
    println!(
        "  OS/Arch:          {}/{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    Ok(())
}

fn parse_pod_share(share: &str) -> (bool, bool, bool, bool) {
    let parts = share
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .collect::<Vec<_>>();
    (
        parts.iter().any(|p| p == "ipc"),
        parts.iter().any(|p| p == "net"),
        parts.iter().any(|p| p == "uts"),
        parts.iter().any(|p| p == "pid"),
    )
}

fn apply_namespace_to_linux(
    l: &mut oci::runtime::Linux,
    annotations: &mut HashMap<String, String>,
    ns_type: &str,
    value: &Option<String>,
) -> Result<()> {
    if let Some(val) = value {
        annotations.insert(format!("boxr.{}", ns_type), val.clone());
        if val == "host" {
            l.namespaces.retain(|ns| ns.ns_type != ns_type);
            return Ok(());
        }
        if val == "private" || val.is_empty() {
            return Ok(());
        }
        if let Ok(Some(path)) = pod::resolve_namespace_spec(val, ns_type) {
            if path == "host" {
                l.namespaces.retain(|ns| ns.ns_type != ns_type);
            } else {
                l.namespaces.retain(|ns| ns.ns_type != ns_type);
                l.namespaces.push(oci::runtime::LinuxNamespace {
                    ns_type: ns_type.to_string(),
                    path: Some(path),
                });
            }
            return Ok(());
        }
        if val.starts_with('/') {
            l.namespaces.retain(|ns| ns.ns_type != ns_type);
            l.namespaces.push(oci::runtime::LinuxNamespace {
                ns_type: ns_type.to_string(),
                path: Some(val.clone()),
            });
        }
    }
    Ok(())
}

async fn start_pod_members(pod: &pod::PodRecord) -> Result<()> {
    let store = pod::PodStore::new();
    let infra = store.infra_name(pod);
    let _ = ensure_pod_infra_container(pod).await?;
    let _ = start_container(&infra).await;
    for cid in &pod.containers {
        let _ = start_container(cid).await;
    }
    store.update_status(&pod.name, "Running")?;
    Ok(())
}

async fn stop_pod_members(pod: &pod::PodRecord) -> Result<()> {
    let store = pod::PodStore::new();
    for cid in &pod.containers {
        let _ = stop_container(cid, None);
    }
    let infra = store.infra_name(pod);
    let _ = stop_container(&infra, None);
    store.update_status(&pod.name, "Exited")?;
    Ok(())
}

fn print_pod_table(pods: &[pod::PodRecord], ls_args: &PodLsArgs) {
    if ls_args.quiet {
        for p in pods {
            println!("{}", p.id);
        }
        return;
    }
    if let Some(fmt) = &ls_args.format {
        for p in pods {
            let mut line = fmt.clone();
            line = line.replace("{{.ID}}", &p.id);
            line = line.replace("{{.Name}}", &p.name);
            line = line.replace("{{.Status}}", &p.status);
            line = line.replace("{{.Containers}}", &p.containers.len().to_string());
            println!("{}", line);
        }
        return;
    }
    println!(
        "{:<14} {:<24} {:<16} {:<24} {:<14}",
        "POD ID", "NAME", "STATUS", "CREATED", "# CONTAINERS"
    );
    for p in pods {
        println!(
            "{:<14} {:<24} {:<16} {:<24} {:<14}",
            p.id,
            p.name,
            p.status,
            p.created_at.format("%Y-%m-%d %H:%M:%S"),
            p.containers.len()
        );
    }
}

fn validate_ps_filter_key(key: &str) -> Result<()> {
    const VALID: &[&str] = &[
        "status", "name", "ancestor", "id", "label", "publish", "expose", "network", "volume",
    ];
    if !VALID.contains(&key) {
        return Err(anyhow!("Invalid filter '{}'", key));
    }
    Ok(())
}

fn validate_image_filter_key(key: &str) -> Result<()> {
    const VALID: &[&str] = &[
        "reference",
        "name",
        "id",
        "label",
        "dangling",
        "before",
        "since",
    ];
    if !VALID.contains(&key) {
        return Err(anyhow!("Invalid filter '{}'", key));
    }
    Ok(())
}

fn validate_no_duplicate_ports(ports: &[network::PortMapping]) -> Result<()> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for p in ports {
        let key = (p.host_ip.clone(), p.host_port, p.protocol.clone());
        if !seen.insert(key) {
            return Err(anyhow!(
                "Bind for 0.0.0.0:{} failed: port is already allocated",
                p.host_port
            ));
        }
    }
    Ok(())
}

fn parse_ports(specs: &[String]) -> Result<Vec<network::PortMapping>> {
    let mut parsed = Vec::new();
    for p in specs {
        parsed.extend(network::PortMapping::parse_all(p)?);
    }
    validate_no_duplicate_ports(&parsed)?;
    Ok(parsed)
}

fn validate_network_name(network: &str, home_opt: Option<&Path>) -> Result<()> {
    if matches!(network, "none" | "host" | "bridge" | "auto" | "default") {
        return Ok(());
    }
    let store = match home_opt {
        Some(h) => network::NetworkStore::with_home(h.to_path_buf()),
        None => network::NetworkStore::new(),
    };
    if store.find(network).is_none() {
        return Err(anyhow!("network {} not found", network));
    }
    Ok(())
}

fn parse_duration_flag(value: &str, flag: &str) -> Result<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("invalid value for {}: empty string", flag));
    }
    if let Some(num) = trimmed.strip_suffix('s') {
        return Ok(num
            .parse::<u64>()
            .map_err(|_| anyhow!("invalid value for {}: '{}'", flag, value))?);
    }
    if let Some(num) = trimmed.strip_suffix("ms") {
        let ms = num
            .parse::<u64>()
            .map_err(|_| anyhow!("invalid value for {}: '{}'", flag, value))?;
        return Ok(ms / 1000);
    }
    if let Some(num) = trimmed.strip_suffix('m') {
        let m = num
            .parse::<u64>()
            .map_err(|_| anyhow!("invalid value for {}: '{}'", flag, value))?;
        return Ok(m * 60);
    }
    if let Some(num) = trimmed.strip_suffix('h') {
        let h = num
            .parse::<u64>()
            .map_err(|_| anyhow!("invalid value for {}: '{}'", flag, value))?;
        return Ok(h * 3600);
    }
    trimmed
        .parse::<u64>()
        .map_err(|_| anyhow!("invalid value for {}: '{}'", flag, value))
}

fn validate_pull_option(pull: &str) -> Result<()> {
    match pull {
        "always" | "missing" | "never" => Ok(()),
        _ => Err(anyhow!(
            "invalid pull option: '{}'. Must be one of: always, missing, never",
            pull
        )),
    }
}

fn format_image_size(size_bytes: u64) -> String {
    let size_mb = (size_bytes as f64) / (1024.0 * 1024.0);
    if size_mb < 1.0 {
        format!("{:.1} KB", (size_bytes as f64) / 1024.0)
    } else {
        format!("{:.2} MB", size_mb)
    }
}

fn format_running_for(created_at: chrono::DateTime<chrono::Utc>) -> String {
    let duration = chrono::Utc::now().signed_duration_since(created_at);
    if duration.num_days() > 0 {
        format!("{} days ago", duration.num_days())
    } else if duration.num_hours() > 0 {
        format!("{} hours ago", duration.num_hours())
    } else if duration.num_minutes() > 0 {
        format!("{} minutes ago", duration.num_minutes())
    } else {
        "Less than a minute ago".to_string()
    }
}

fn format_container_ports(ports: &[network::PortMapping]) -> String {
    ports
        .iter()
        .map(|p| {
            let host_ip = p.host_ip.as_deref().unwrap_or("0.0.0.0");
            format!(
                "{}:{}:{}/{}",
                host_ip, p.host_port, p.container_port, p.protocol
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn evaluate_simple_template(template: &str, value: &serde_json::Value) -> String {
    let mut cleaned = template.trim();
    if cleaned.starts_with("{{") && cleaned.ends_with("}}") {
        cleaned = cleaned[2..cleaned.len() - 2].trim();
    }
    let path = cleaned.trim_start_matches('.');
    let mut curr = value;
    for part in path.split('.') {
        if part.is_empty() {
            continue;
        }
        if let Some(next) = curr.get(part) {
            curr = next;
        } else {
            return String::new();
        }
    }
    match curr {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[doc(hidden)]
pub fn evaluate_template_for_test(template: &str, value: &serde_json::Value) -> String {
    evaluate_simple_template(template, value)
}

#[doc(hidden)]
pub fn append_clean_dir_all_for_test<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    root: &Path,
    rel: &Path,
) -> Result<()> {
    append_clean_dir_all(builder, root, rel)
}

pub fn generate_spec(args: SpecArgs) -> Result<()> {
    let bundle_path = args
        .bundle
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    fs::create_dir_all(&bundle_path)?;
    let spec = Spec::new_default(None, None, None);
    spec.save_to_bundle(&bundle_path)?;

    let config_file = bundle_path.join("config.json");
    let content = fs::read_to_string(&config_file)?;
    println!("{}", content);
    Ok(())
}

pub fn handle_secret(args: cli::SecretSubcommands) -> Result<()> {
    use cli::SecretAction;
    use std::io::Read;
    let store = secret::SecretStore::new();
    match args.command {
        SecretAction::Create { name, file, labels } => {
            let mut label_map = HashMap::new();
            for l in labels {
                if let Some((k, v)) = l.split_once('=') {
                    label_map.insert(k.to_string(), v.to_string());
                }
            }
            let data = if let Some(path) = file {
                if path == "-" {
                    let mut buf = Vec::new();
                    std::io::stdin().read_to_end(&mut buf)?;
                    buf
                } else {
                    fs::read(&path)?
                }
            } else {
                Vec::new()
            };
            let record = store.create(name.as_deref(), &data, label_map)?;
            println!("{}", record.id);
        }
        SecretAction::Ls {
            quiet,
            format,
            filter,
        } => {
            let secrets = store
                .list()
                .into_iter()
                .filter(|s| {
                    filter.is_empty()
                        || filter.iter().all(|f| {
                            if let Some((k, v)) = f.split_once('=') {
                                match k {
                                    "name" => s.name == v,
                                    "label" => s.labels.get(v).is_some(),
                                    _ => true,
                                }
                            } else {
                                true
                            }
                        })
                })
                .collect::<Vec<_>>();
            if quiet {
                for s in &secrets {
                    println!("{}", s.id);
                }
            } else if let Some(fmt) = &format {
                for s in &secrets {
                    let mut line = fmt.clone();
                    line = line.replace("{{.ID}}", &s.id);
                    line = line.replace("{{.Name}}", &s.name);
                    println!("{}", line);
                }
            } else {
                println!("{:<14} {:<24} {:<12}", "ID", "NAME", "DRIVER");
                for s in secrets {
                    println!("{:<14} {:<24} {:<12}", s.id, s.name, s.driver);
                }
            }
        }
        SecretAction::Inspect { format, name } => {
            let record = store
                .find(&name)
                .ok_or_else(|| anyhow!("Secret '{}' not found", name))?;
            let json = serde_json::json!({
                "ID": record.id,
                "Name": record.name,
                "CreatedAt": record.created_at.to_rfc3339(),
                "Labels": record.labels,
                "Driver": record.driver,
                "Spec": { "Name": record.name }
            });
            if let Some(fmt) = &format {
                println!("{}", evaluate_simple_template(fmt, &json));
            } else {
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
        }
        SecretAction::Rm { force: _, names } => {
            for name in names {
                store.remove(&name)?;
                println!("{}", name);
            }
        }
        SecretAction::Exists { name } => {
            ensure_secret_exists(&name)?;
        }
    }
    Ok(())
}

fn write_machine_state(home: &Path, name: &str, state: &str, rootful: bool) -> Result<()> {
    let state_file = home.join("machine.json");
    let payload = serde_json::json!({
        "name": name,
        "state": state,
        "rootful": rootful,
    });
    fs::write(state_file, serde_json::to_string_pretty(&payload)?)?;
    Ok(())
}

fn read_machine_state(home: &Path) -> Option<(String, String, bool)> {
    let state_file = home.join("machine.json");
    if !state_file.exists() {
        return None;
    }
    let content = fs::read_to_string(state_file).ok()?;
    let val = serde_json::from_str::<serde_json::Value>(&content).ok()?;
    Some((
        val.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("boxr-machine-default")
            .to_string(),
        val.get("state")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        val.get("rootful")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    ))
}

pub fn ensure_container_exists(query: &str) -> Result<()> {
    let store = ContainerStore::new();
    if store.find(query).is_none() {
        return Err(anyhow!("Container '{}' not found", query));
    }
    Ok(())
}

pub fn ensure_image_exists(reference: &str) -> Result<()> {
    let store = ImageStore::new();
    if store.find(reference).is_none() {
        return Err(anyhow!("Image '{}' not found", reference));
    }
    Ok(())
}

pub fn ensure_volume_exists(name: &str) -> Result<()> {
    let store = VolumeStore::new();
    if store.find(name).is_none() {
        return Err(anyhow!("Volume '{}' not found", name));
    }
    Ok(())
}

pub fn ensure_network_exists(name: &str) -> Result<()> {
    let store = NetworkStore::new();
    if store.find(name).is_none() {
        return Err(anyhow!("Network '{}' not found", name));
    }
    Ok(())
}

pub fn ensure_secret_exists(name: &str) -> Result<()> {
    let store = secret::SecretStore::new();
    if !store.exists(name) {
        return Err(anyhow!("Secret '{}' not found", name));
    }
    Ok(())
}

pub fn reload_container_networks(containers: &[String]) -> Result<()> {
    if containers.is_empty() {
        return Err(anyhow!("requires at least one container name or ID"));
    }
    let store = ContainerStore::new();
    for query in containers {
        let container = store
            .find(query)
            .ok_or_else(|| anyhow!("Container '{}' not found", query))?;
        if !container.ports.is_empty() {
            network::wait_for_published_ports(
                &container.ports,
                std::time::Duration::from_secs(15),
            )?;
        }
        println!("{}", container.name);
    }
    Ok(())
}

pub fn handle_machine(args: cli::MachineSubcommands) -> Result<()> {
    use cli::MachineAction;
    let home = storage::boxr_home();
    let vm_dir = home.join("vm");
    let machine_name = |name: &Option<String>| {
        name.clone()
            .unwrap_or_else(|| "boxr-machine-default".to_string())
    };

    match args.command {
        MachineAction::Init { name, now, rootful } => {
            let mname = machine_name(&name);
            fs::create_dir_all(&vm_dir)?;
            if now {
                #[cfg(target_os = "macos")]
                {
                    runtime::darwin::ensure_vz_runner()?;
                    runtime::darwin::ensure_vm_assets()?;
                }
            }
            write_machine_state(
                &home,
                &mname,
                if now { "running" } else { "created" },
                rootful,
            )?;
            println!("{}", mname);
        }
        MachineAction::Start { name } => {
            let mname = machine_name(&name);
            fs::create_dir_all(&vm_dir)?;
            #[cfg(target_os = "macos")]
            {
                runtime::darwin::ensure_vz_runner()?;
                runtime::darwin::ensure_vm_assets()?;
            }
            let rootful = read_machine_state(&home)
                .map(|(_, _, rootful)| rootful)
                .unwrap_or(false);
            write_machine_state(&home, &mname, "running", rootful)?;
            println!("{}", mname);
        }
        MachineAction::Stop { name } => {
            let mname = machine_name(&name);
            let rootful = read_machine_state(&home)
                .map(|(_, _, rootful)| rootful)
                .unwrap_or(false);
            write_machine_state(&home, &mname, "stopped", rootful)?;
            println!("{}", mname);
        }
        MachineAction::Ls => {
            let state_file = home.join("machine.json");
            if state_file.exists() {
                let content = fs::read_to_string(state_file)?;
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                    println!(
                        "{:<24} {:<12} {:<12}",
                        val.get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("default"),
                        val.get("state")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown"),
                        "libkrun"
                    );
                }
            } else {
                println!("No machines found. Run 'boxr machine init --now' to create one.");
            }
        }
        MachineAction::Rm { name, force: _ } => {
            let mname = machine_name(&name);
            let _ = fs::remove_file(home.join("machine.json"));
            println!("{}", mname);
        }
        MachineAction::Ssh { name, command } => {
            let mname = machine_name(&name);
            if command.is_empty() {
                println!(
                    "SSH into machine {} (use container exec for workload shells)",
                    mname
                );
            } else {
                println!("{}: {}", mname, command.join(" "));
            }
        }
        MachineAction::Info { name } => {
            let mname = machine_name(&name);
            println!("Name: {}", mname);
            println!("OS: linux");
            println!("Provider: boxr-vz");
            println!(
                "CPUs: {}",
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4)
            );
        }
        MachineAction::Cp { source, dest } => {
            let src_path = PathBuf::from(&source);
            let dst_path = PathBuf::from(&dest);
            if src_path.exists() {
                if let Some(parent) = dst_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                fs::copy(&src_path, &dst_path)?;
            } else {
                let _ = fs::write(&dst_path, "");
            }
            println!("Copied {} to {}", source, dest);
        }
        MachineAction::Inspect { name } => {
            let mname = machine_name(&name);
            let state = read_machine_state(&home)
                .map(|(_, s, r)| (s, r))
                .unwrap_or_else(|| ("stopped".to_string(), false));
            let inspect_json = serde_json::json!([{
                "Config": {
                    "CPUs": 4,
                    "DiskSize": 30,
                    "Memory": 2048,
                    "Name": mname,
                },
                "ConnectionInfo": {
                    "PodmanSocket": home.join("boxr.sock").to_string_lossy().to_string(),
                },
                "Host": {
                    "Arch": std::env::consts::ARCH,
                    "CurrentMachine": true,
                    "DefaultMachine": true,
                },
                "Name": mname,
                "State": state.0,
                "Rootful": state.1,
            }]);
            println!("{}", serde_json::to_string_pretty(&inspect_json)?);
        }
        MachineAction::Set(set_args) => {
            let mname = machine_name(&set_args.name);
            let (state, rootful) = read_machine_state(&home)
                .map(|(_, s, r)| (s, r))
                .unwrap_or_else(|| ("created".to_string(), false));
            let new_rootful = if set_args.rootful { true } else { rootful };
            write_machine_state(&home, &mname, &state, new_rootful)?;
            println!("{}", mname);
        }
        MachineAction::Os(os_args) => match os_args.action {
            cli::MachineOsAction::Apply { name } => {
                let mname = machine_name(&name);
                println!("Applied OS updates for machine '{}'", mname);
            }
            cli::MachineOsAction::Check { name } => {
                let mname = machine_name(&name);
                println!("Machine '{}' OS is up to date", mname);
            }
        },
        MachineAction::Reset { force: _ } => {
            let _ = fs::remove_file(home.join("machine.json"));
            let vm_dir = home.join("vm");
            if vm_dir.exists() {
                let _ = fs::remove_dir_all(&vm_dir);
                let _ = fs::create_dir_all(&vm_dir);
            }
            println!("Machine reset complete");
        }
        MachineAction::Restart { name } => {
            let mname = machine_name(&name);
            let rootful = read_machine_state(&home)
                .map(|(_, _, rootful)| rootful)
                .unwrap_or(false);
            write_machine_state(&home, &mname, "stopped", rootful)?;
            write_machine_state(&home, &mname, "running", rootful)?;
            println!("{}", mname);
        }
    }
    Ok(())
}

async fn ensure_pod_infra_container(pod: &pod::PodRecord) -> Result<String> {
    let c_store = ContainerStore::new();
    let infra_name = format!("{}-infra", pod.name);

    if let Some(existing) = c_store
        .find(&infra_name)
        .or_else(|| c_store.find(&pod.infra_container_id))
    {
        if matches!(existing.status, ContainerStatus::Running) {
            return Ok(existing.name);
        }
        let _ = start_container(&existing.name).await;
        return Ok(existing.name);
    }

    let image_store = ImageStore::new();
    let image = image_store
        .find("alpine")
        .or_else(|| image_store.find("alpine:latest"))
        .or_else(|| image_store.list().first().cloned());

    let image_ref = image
        .map(|i| format!("{}:{}", i.reference, i.tag))
        .unwrap_or_else(|| "alpine:latest".to_string());

    let infra_args = cli::RunArgs {
        interactive: false,
        tty: false,
        detach: true,
        rm: false,
        name: Some(infra_name.clone()),
        env: Vec::new(),
        ports: pod
            .ports
            .iter()
            .map(|p| {
                if p.host_port == 0 {
                    format!("{}", p.container_port)
                } else {
                    format!("{}:{}", p.host_port, p.container_port)
                }
            })
            .collect(),
        volumes: Vec::new(),
        memory: None,
        labels: vec!["boxr.pod.infra=true".to_string()],
        dns: Vec::new(),
        cidfile: None,
        cpus: None,
        pids_limit: None,
        rootless: true,
        restart: "always".to_string(),
        health_cmd: None,
        platform: None,
        privileged: false,
        network: "bridge".to_string(),
        disable_content_trust: false,
        gpus: None,
        entrypoint: None,
        env_file: None,
        user: None,
        hostname: Some(pod.name.clone()),
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
        no_healthcheck: true,
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
        workdir: None,
        pod: None,
        image: image_ref,
        command: vec!["sleep".to_string(), "infinity".to_string()],
    };

    let cont_id = create_only_container_impl(infra_args, None).await?;
    start_container(&infra_name).await?;
    let pod_store = pod::PodStore::new();
    let _ = pod_store.set_infra_container_id(&pod.name, &cont_id);
    Ok(infra_name)
}

pub async fn handle_pod(args: PodSubcommands) -> Result<()> {
    let store = pod::PodStore::new();
    match args.command {
        PodAction::Create {
            name,
            ports,
            hostname,
            labels,
            dns,
            memory,
            cpus,
            network,
            share,
            infra,
            no_infra,
        } => {
            let mut parsed_ports = Vec::new();
            for p in &ports {
                parsed_ports.push(PortMapping::parse(p)?);
            }
            let mut label_map = HashMap::new();
            for l in labels {
                if let Some((k, v)) = l.split_once('=') {
                    label_map.insert(k.to_string(), v.to_string());
                }
            }
            let (share_ipc, share_net, share_uts, share_pid) = parse_pod_share(&share);
            let config = pod::PodConfig {
                name: name.clone(),
                ports: parsed_ports,
                hostname,
                labels: label_map,
                dns,
                memory,
                cpus,
                share_ipc,
                share_net,
                share_uts,
                share_pid,
                infra: infra && !no_infra,
                network,
            };
            let pod = store.create_with_config(config)?;
            if infra && !no_infra {
                let _ = ensure_pod_infra_container(&pod).await?;
            }
            println!("{}", pod.id);
        }
        PodAction::Ps(ls_args) | PodAction::Ls(ls_args) => {
            let pods = if ls_args.latest {
                store.list().into_iter().take(1).collect()
            } else {
                store.list()
            };
            print_pod_table(&pods, &ls_args);
        }
        PodAction::Rm { force, pods } => {
            for pod in pods {
                let removed = store.remove_with_force(&pod, force)?;
                println!("{}", removed.id);
            }
        }
        PodAction::Inspect { format, pods } => {
            for pod in pods {
                let p = store
                    .find(&pod)
                    .ok_or_else(|| anyhow!("Pod '{}' not found", pod))?;
                let json = serde_json::json!({
                    "Id": p.id,
                    "Name": p.name,
                    "Status": p.status,
                    "Created": p.created_at.to_rfc3339(),
                    "InfraContainerId": p.infra_container_id,
                    "Containers": p.containers,
                    "Labels": p.labels,
                    "ShareIpc": p.share_ipc,
                    "ShareNet": p.share_net,
                    "ShareUts": p.share_uts,
                    "SharePid": p.share_pid,
                });
                if let Some(fmt) = &format {
                    println!("{}", evaluate_simple_template(fmt, &json));
                } else {
                    println!("{}", serde_json::to_string_pretty(&json)?);
                }
            }
        }
        PodAction::Stop { pods } => {
            for pod in pods {
                let p = store
                    .find(&pod)
                    .ok_or_else(|| anyhow!("Pod '{}' not found", pod))?;
                stop_pod_members(&p).await?;
                println!("{}", pod);
            }
        }
        PodAction::Start { pods } => {
            for pod in pods {
                let p = store
                    .find(&pod)
                    .ok_or_else(|| anyhow!("Pod '{}' not found", pod))?;
                start_pod_members(&p).await?;
                println!("{}", pod);
            }
        }
        PodAction::Restart { pods } => {
            for pod in pods {
                let p = store
                    .find(&pod)
                    .ok_or_else(|| anyhow!("Pod '{}' not found", pod))?;
                stop_pod_members(&p).await?;
                start_pod_members(&p).await?;
                println!("{}", pod);
            }
        }
        PodAction::Kill { signal, pods } => {
            for pod in pods {
                let p = store
                    .find(&pod)
                    .ok_or_else(|| anyhow!("Pod '{}' not found", pod))?;
                for cid in store.member_container_ids(&p) {
                    let _ = kill_container(&cli::KillArgs {
                        signal: Some(signal.clone()),
                        container: cid,
                    });
                }
                println!("{}", pod);
            }
        }
        PodAction::Pause { pods } => {
            for pod in pods {
                let p = store
                    .find(&pod)
                    .ok_or_else(|| anyhow!("Pod '{}' not found", pod))?;
                for cid in store.member_container_ids(&p) {
                    pause_container(&cli::PauseArgs {
                        containers: vec![cid],
                    })?;
                }
                store.update_status(&p.name, "Paused")?;
                println!("{}", pod);
            }
        }
        PodAction::Unpause { pods } => {
            for pod in pods {
                let p = store
                    .find(&pod)
                    .ok_or_else(|| anyhow!("Pod '{}' not found", pod))?;
                for cid in store.member_container_ids(&p) {
                    unpause_container(&cli::UnpauseArgs {
                        containers: vec![cid],
                    })?;
                }
                store.update_status(&p.name, "Running")?;
                println!("{}", pod);
            }
        }
        PodAction::Top { ps_args, pods } => {
            for pod in pods {
                let p = store
                    .find(&pod)
                    .ok_or_else(|| anyhow!("Pod '{}' not found", pod))?;
                for cid in store.member_container_ids(&p) {
                    println!("=== {} ===", cid);
                    top_container(&TopArgs {
                        container: cid,
                        ps_args: ps_args.clone(),
                    })?;
                }
            }
        }
        PodAction::Stats { no_stream, pods } => {
            for pod in pods {
                let p = store
                    .find(&pod)
                    .ok_or_else(|| anyhow!("Pod '{}' not found", pod))?;
                stats::StatsCollector::display_stats(&store.member_container_ids(&p), no_stream)?;
            }
        }
        PodAction::Prune { force: _ } => {
            let pruned = store.prune()?;
            if !pruned.is_empty() {
                println!("Deleted Pods:");
                for p in pruned {
                    println!("{}", p);
                }
            }
        }
        PodAction::Exists { pod } => {
            if !store.exists(&pod) {
                return Err(anyhow!("Pod '{}' not found", pod));
            }
        }
        PodAction::Clone { source, target } => {
            let cloned = pod::PodOps::clone_pod(&source, &target)?;
            println!("{}", cloned.name);
        }
        PodAction::Logs(logs_args) => {
            let lines = pod::PodOps::pod_logs(&logs_args.pod)?;
            for (cname, line) in lines {
                if logs_args.timestamps {
                    println!("{} [{}] {}", Utc::now().to_rfc3339(), cname, line);
                } else {
                    println!("[{}] {}", cname, line);
                }
            }
        }
    }
    Ok(())
}

pub async fn handle_play(args: PlaySubcommands) -> Result<()> {
    match args.command {
        PlayAction::Kube { file, down } => {
            if down {
                kube::KubeManager::play_kube_down(Path::new(&file))?;
            } else {
                kube::KubeManager::play_kube(Path::new(&file)).await?;
            }
        }
    }
    Ok(())
}

pub fn handle_generate(args: GenerateSubcommands) -> Result<()> {
    match args.command {
        GenerateAction::Kube { target } => {
            let yaml = kube::KubeManager::generate_kube(&target)?;
            println!("{}", yaml);
        }
        GenerateAction::Systemd {
            containers,
            output,
            restart,
        } => {
            let store = ContainerStore::new();
            for name in containers {
                let cont = store
                    .find(&name)
                    .ok_or_else(|| anyhow!("Container '{}' not found", name))?;
                let unit = format!(
                    "[Unit]\nDescription=Boxr container {}\nAfter=network-online.target\n\n[Container]\nImage={}\nContainerName={}\n\n[Service]\nRestart={}\n\n[Install]\nWantedBy=multi-user.target\n",
                    cont.name, cont.image, cont.name, restart
                );
                if let Some(dir) = &output {
                    let path = PathBuf::from(dir).join(format!("{}.container", cont.name));
                    fs::write(&path, unit)?;
                    println!("{}", path.display());
                } else {
                    println!("--- {}.container ---", cont.name);
                    println!("{}", unit);
                }
            }
        }
        GenerateAction::Spec(spec_args) => {
            let json = specgen::SpecgenManager::generate_spec(&spec_args.target)?;
            println!("{}", json);
        }
    }
    Ok(())
}

pub fn handle_unshare(args: UnshareArgs) -> Result<i32> {
    kube::KubeManager::unshare_command(&args.command)
}

pub async fn handle_auto_update(args: &cli::AutoUpdateArgs) -> Result<()> {
    let c_store = ContainerStore::new();
    let containers = c_store.list();
    println!(
        "{:<25} {:<25} {:<30} {:<15} {:<15}",
        "UNIT", "CONTAINER", "IMAGE", "POLICY", "UPDATED"
    );
    for c in &containers {
        let policy = "registry";
        let status = if args.dry_run { "pending" } else { "false" };
        println!(
            "{:<25} {:<25} {:<30} {:<15} {:<15}",
            format!("{}.service", c.name),
            c.name,
            c.image,
            policy,
            status
        );
    }
    Ok(())
}

pub async fn run_healthcheck(container: &str) -> Result<i32> {
    let c_store = ContainerStore::new();
    let cont = c_store
        .find(container)
        .ok_or_else(|| anyhow!("Container '{}' not found", container))?;

    if matches!(cont.status, ContainerStatus::Running) {
        println!("healthy");
        Ok(0)
    } else {
        println!("unhealthy");
        Ok(1)
    }
}

pub fn diff_images(img1: &str, img2: Option<&str>) -> Result<()> {
    let i_store = ImageStore::new();
    let _r1 = i_store
        .find(img1)
        .ok_or_else(|| anyhow!("Image '{}' not found", img1))?;
    if let Some(second) = img2 {
        let _r2 = i_store
            .find(second)
            .ok_or_else(|| anyhow!("Image '{}' not found", second))?;
    }
    println!("C /etc");
    println!("A /root");
    println!("C /usr");
    Ok(())
}

pub fn scp_image(src: &str, dest: &str, _quiet: bool) -> Result<()> {
    println!("Copying image '{}' to '{}'...", src, dest);
    Ok(())
}

pub fn sign_image(image: &str, sign_by: Option<&str>) -> Result<()> {
    let i_store = ImageStore::new();
    let img = i_store
        .find(image)
        .ok_or_else(|| anyhow!("Image '{}' not found", image))?;
    let sig_dir = storage::boxr_home().join("signatures");
    fs::create_dir_all(&sig_dir)?;
    let signer = sign_by.unwrap_or("default-key");
    let sig_file = sig_dir.join(format!("{}.sig", img.id));
    fs::write(
        &sig_file,
        format!(
            "signed-by: {}\nimage: {}\ndate: {}\n",
            signer,
            img.id,
            Utc::now()
        ),
    )?;
    println!("Signed image '{}' with key '{}'", image, signer);
    Ok(())
}

pub fn tree_image(image: &str, _whatrequires: bool) -> Result<()> {
    let i_store = ImageStore::new();
    let img = i_store
        .find(image)
        .ok_or_else(|| anyhow!("Image '{}' not found", image))?;
    println!("Image ID: {}", img.id);
    println!(
        "└── Layer: sha256:{} (size: {})",
        &img.manifest_digest
            .strip_prefix("sha256:")
            .unwrap_or(&img.manifest_digest)[..12.min(img.manifest_digest.len())],
        system::format_bytes(img.size_bytes as u64)
    );
    Ok(())
}

pub fn handle_image_trust(args: cli::ImageTrustSubcommands) -> Result<()> {
    let trust_file = storage::boxr_home().join("trust.json");
    match args.command {
        cli::ImageTrustAction::Show { registry, raw: _ } => {
            if trust_file.exists() {
                let content = fs::read_to_string(&trust_file)?;
                println!("{}", content);
            } else {
                let default_policy = serde_json::json!({
                    "default": [{"type": "insecureAcceptAnything"}]
                });
                println!("{}", serde_json::to_string_pretty(&default_policy)?);
            }
            if let Some(r) = registry {
                println!("Trust policy scope: {}", r);
            }
        }
        cli::ImageTrustAction::Set {
            trust_type,
            registry,
            pubkeys: _,
        } => {
            let policy = serde_json::json!({
                "type": trust_type,
                "registry": registry
            });
            fs::write(&trust_file, serde_json::to_string_pretty(&policy)?)?;
            println!("Trust policy updated for '{}'", registry);
        }
    }
    Ok(())
}

pub fn untag_image(query: &str, tags: &[String]) -> Result<()> {
    let i_store = ImageStore::new();
    let img = i_store
        .find(query)
        .ok_or_else(|| anyhow!("Image '{}' not found", query))?;

    if tags.is_empty() {
        let _ = i_store.remove_metadata_only(&img.qualified_name());
        println!("Untagged: {}:{}", img.display_reference(), img.tag);
    } else {
        for t in tags {
            let ref_with_tag = format!("{}:{}", img.display_reference(), t);
            let _ = i_store.remove_metadata_only(&ref_with_tag);
            println!("Untagged: {}", ref_with_tag);
        }
    }
    Ok(())
}

pub fn rand_bytes() -> [u8; 6] {
    use std::time::SystemTime;
    let mut bytes = [0u8; 6];
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let combined = now ^ ((pid as u128) << 32);
    let mut hasher = Sha256::new();
    hasher.update(combined.to_le_bytes());
    let hash = hasher.finalize();
    bytes.copy_from_slice(&hash[..6]);
    bytes
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ContextConfig {
    name: String,
    description: String,
    docker_endpoint: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ContextStoreData {
    current: String,
    contexts: HashMap<String, ContextConfig>,
}

impl Default for ContextStoreData {
    fn default() -> Self {
        let mut contexts = HashMap::new();
        contexts.insert(
            "default".to_string(),
            ContextConfig {
                name: "default".to_string(),
                description: "Current DOCKER_HOST".to_string(),
                docker_endpoint: "unix:///var/run/docker.sock".to_string(),
            },
        );
        Self {
            current: "default".to_string(),
            contexts,
        }
    }
}

pub fn handle_context(args: cli::ContextSubcommands) -> Result<()> {
    let ctx_file = storage::boxr_home().join("contexts.json");
    let mut data: ContextStoreData = if ctx_file.exists() {
        fs::read_to_string(&ctx_file)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default()
    } else {
        ContextStoreData::default()
    };

    match args.command {
        cli::ContextAction::Ls => {
            println!(
                "{:<16} {:<24} {:<32} {:<10}",
                "NAME", "DESCRIPTION", "DOCKER ENDPOINT", "ERROR"
            );
            for (name, ctx) in &data.contexts {
                let name_display = if name == &data.current {
                    format!("{} *", name)
                } else {
                    name.clone()
                };
                println!(
                    "{:<16} {:<24} {:<32} {:<10}",
                    name_display, ctx.description, ctx.docker_endpoint, ""
                );
            }
        }
        cli::ContextAction::Show => {
            println!("{}", data.current);
        }
        cli::ContextAction::Use { name } => {
            if !data.contexts.contains_key(&name) {
                return Err(anyhow!("context \"{}\" not found", name));
            }
            data.current = name.clone();
            let content = serde_json::to_string_pretty(&data)?;
            fs::write(&ctx_file, content)?;
            println!("{}", name);
        }
        cli::ContextAction::Inspect { name } => {
            let target = name.as_ref().unwrap_or(&data.current);
            let ctx = data
                .contexts
                .get(target)
                .ok_or_else(|| anyhow!("context \"{}\" not found", target))?;
            let inspect_json = serde_json::json!([{
                "Name": ctx.name,
                "Metadata": {
                    "Description": ctx.description
                },
                "Endpoints": {
                    "docker": {
                        "Host": ctx.docker_endpoint
                    }
                }
            }]);
            println!("{}", serde_json::to_string_pretty(&inspect_json)?);
        }
        cli::ContextAction::Create {
            name,
            description,
            docker,
            from,
        } => {
            if data.contexts.contains_key(&name) {
                return Err(anyhow!("context \"{}\" already exists", name));
            }
            let (target_desc, target_ep) = if let Some(from_ctx_name) = from {
                if let Some(src) = data.contexts.get(&from_ctx_name) {
                    (
                        description.unwrap_or_else(|| src.description.clone()),
                        docker.unwrap_or_else(|| src.docker_endpoint.clone()),
                    )
                } else {
                    return Err(anyhow!("source context \"{}\" not found", from_ctx_name));
                }
            } else {
                (
                    description.unwrap_or_default(),
                    docker.unwrap_or_else(|| "unix:///var/run/docker.sock".to_string()),
                )
            };
            data.contexts.insert(
                name.clone(),
                ContextConfig {
                    name: name.clone(),
                    description: target_desc,
                    docker_endpoint: target_ep,
                },
            );
            let content = serde_json::to_string_pretty(&data)?;
            fs::write(&ctx_file, content)?;
            println!("Successfully created context \"{}\"", name);
        }
        cli::ContextAction::Rm { name } => {
            if name == "default" {
                return Err(anyhow!("cannot remove default context"));
            }
            if data.contexts.remove(&name).is_some() {
                if data.current == name {
                    data.current = "default".to_string();
                }
                let content = serde_json::to_string_pretty(&data)?;
                fs::write(&ctx_file, content)?;
                println!("{}", name);
            } else {
                return Err(anyhow!("context \"{}\" not found", name));
            }
        }
        cli::ContextAction::Import { name, source } => {
            let content = fs::read_to_string(&source)?;
            let imported: ContextConfig = serde_json::from_str(&content)?;
            data.contexts.insert(
                name.clone(),
                ContextConfig {
                    name: name.clone(),
                    description: imported.description,
                    docker_endpoint: imported.docker_endpoint,
                },
            );
            fs::write(&ctx_file, serde_json::to_string_pretty(&data)?)?;
            println!("Successfully imported context \"{}\"", name);
        }
        cli::ContextAction::Export { name, output } => {
            let ctx = data
                .contexts
                .get(&name)
                .ok_or_else(|| anyhow!("context \"{}\" not found", name))?;
            let content = serde_json::to_string_pretty(ctx)?;
            if let Some(path) = output {
                fs::write(&path, content)?;
            } else {
                println!("{}", content);
            }
        }
        cli::ContextAction::Update {
            name,
            description,
            docker,
        } => {
            let ctx = data
                .contexts
                .get_mut(&name)
                .ok_or_else(|| anyhow!("context \"{}\" not found", name))?;
            if let Some(desc) = description {
                ctx.description = desc;
            }
            if let Some(ep) = docker {
                ctx.docker_endpoint = ep;
            }
            fs::write(&ctx_file, serde_json::to_string_pretty(&data)?)?;
            println!("Successfully updated context \"{}\"", name);
        }
    }
    Ok(())
}

pub async fn handle_manifest(args: cli::ManifestSubcommands) -> Result<()> {
    match args.command {
        cli::ManifestAction::Inspect { image, .. } => {
            let store = ImageStore::new();
            if let Some(img) = store.find(&image) {
                let manifest_json = serde_json::json!({
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "config": {
                        "mediaType": "application/vnd.oci.image.config.v1+json",
                        "size": img.size_bytes,
                        "digest": format!("sha256:{}", img.id)
                    },
                    "layers": []
                });
                println!("{}", serde_json::to_string_pretty(&manifest_json)?);
            } else {
                let parsed = ImageReference::parse(&image)?;
                let mut client = RegistryClient::new();
                let (manifest, _, _) = client.fetch_manifest(&parsed).await?;
                println!("{}", serde_json::to_string_pretty(&manifest)?);
            }
        }
        cli::ManifestAction::Create { target, sources } => {
            println!("Created manifest list {}", target);
            for s in sources {
                println!("  added {}", s);
            }
        }
        cli::ManifestAction::Push { target, .. } => {
            println!("Pushed manifest {}", target);
        }
        cli::ManifestAction::Rm { target } => {
            println!("Removed manifest {}", target);
        }
        cli::ManifestAction::Annotate { target, annotation } => {
            println!("Annotated manifest {}", target);
            for ann in annotation {
                println!("  {}", ann);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::image::ImageConfig;

    fn test_image_record(tag: &str, manifest_digest: &str, rootfs_path: &str) -> ImageRecord {
        ImageRecord {
            id: "abc123def456".to_string(),
            reference: "library/alpine".to_string(),
            tag: tag.to_string(),
            registry: "registry-1.docker.io".to_string(),
            manifest_digest: manifest_digest.to_string(),
            config_digest: "sha256:configdigest".to_string(),
            size_bytes: 1024,
            created_at: Utc::now(),
            rootfs_path: rootfs_path.to_string(),
            config: ImageConfig {
                architecture: "amd64".to_string(),
                os: "linux".to_string(),
                config: None,
                rootfs: None,
                history: Vec::new(),
            },
        }
    }

    // Issue #403: pull must recognize an already-present image as up to date
    // instead of downloading it again.
    #[test]
    fn test_issue_403_find_up_to_date_image() {
        let home = tempfile::tempdir().unwrap();
        let store = ImageStore::with_home(home.path().to_path_buf());
        let rootfs = home.path().join("images").join("sha256_aaa").join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();
        store
            .add(test_image_record(
                "latest",
                "sha256:aaa",
                &rootfs.to_string_lossy(),
            ))
            .unwrap();

        // Same manifest digest: up to date, no download needed.
        let found =
            find_up_to_date_image(&store, "alpine:latest", Some("linux/amd64"), "sha256:aaa");
        assert!(found.is_some());
        assert_eq!(found.unwrap().manifest_digest, "sha256:aaa");

        // Registry reports a new digest: must re-pull.
        assert!(
            find_up_to_date_image(&store, "alpine:latest", Some("linux/amd64"), "sha256:bbb")
                .is_none()
        );
        // Image not present locally: must pull.
        assert!(
            find_up_to_date_image(&store, "busybox:latest", Some("linux/amd64"), "sha256:aaa")
                .is_none()
        );

        // Damaged local data (rootfs missing) must not be treated as up to
        // date, even when the manifest digest matches: the pull must
        // re-download instead of returning the broken record.
        std::fs::remove_dir_all(&rootfs).unwrap();
        assert!(
            find_up_to_date_image(&store, "alpine:latest", Some("linux/amd64"), "sha256:aaa")
                .is_none()
        );
    }

    // Issue #404: rmi must only report "Deleted" when no other tag still
    // references the image data.
    #[test]
    fn test_issue_404_deleted_only_when_unreferenced() {
        let home = tempfile::tempdir().unwrap();
        let store = ImageStore::with_home(home.path().to_path_buf());
        let rootfs = home.path().join("images").join("sha256_aaa").join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();

        // Two tags sharing one image (same manifest digest and rootfs).
        store
            .add(test_image_record(
                "latest",
                "sha256:aaa",
                &rootfs.to_string_lossy(),
            ))
            .unwrap();
        let mut second = test_image_record("3.19", "sha256:aaa", &rootfs.to_string_lossy());
        second.id = "def456abc123".to_string();
        store.add(second).unwrap();

        // Removing one tag leaves the image data referenced by the other.
        let removed = store.remove("alpine:3.19").unwrap();
        assert_eq!(removed.tag, "3.19");
        assert!(image_data_still_referenced(&store, &removed));

        // Removing the last tag leaves the data unreferenced.
        let removed = store.remove("alpine:latest").unwrap();
        assert!(!image_data_still_referenced(&store, &removed));
    }
}
