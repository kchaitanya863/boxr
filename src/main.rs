use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    boxr::cli::record_inherited_fds();

    let args: Vec<String> = std::env::args().collect();
    if args
        .first()
        .is_some_and(|a| a.ends_with("/conmon") || a == "conmon")
        && args
            .get(1)
            .is_some_and(|a| a == "--version" || a == "-v")
    {
        println!("conmon version 2.2.0");
        std::process::exit(0);
    }
    if args.len() > 1 {
        if args[1] == "__internal-trampoline" {
            #[cfg(target_os = "linux")]
            {
                let code = boxr::runtime::linux::run_trampoline(&args[2..])?;
                std::process::exit(code);
            }
            #[cfg(not(target_os = "linux"))]
            {
                std::process::exit(0);
            }
        }
        if args[1] == "__internal-conmon-supervisor" {
            #[cfg(target_os = "linux")]
            {
                let code = boxr::runtime::linux::run_conmon_supervisor(&args[2..])?;
                std::process::exit(code);
            }
            #[cfg(not(target_os = "linux"))]
            {
                std::process::exit(0);
            }
        }
        if args[1] == "__internal-health-supervisor" {
            #[cfg(target_os = "linux")]
            {
                let bundle = std::path::Path::new(&args[2]);
                let code = boxr::health::supervisor::run_internal_health_supervisor(bundle)
                    .map(|_| 0)
                    .unwrap_or(1);
                std::process::exit(code);
            }
            #[cfg(not(target_os = "linux"))]
            {
                std::process::exit(0);
            }
        }
        if args[1] == "__internal-detached-wait" {
            #[cfg(target_os = "linux")]
            {
                let code = boxr::runtime::linux::run_detached_wait(&args[2..])?;
                std::process::exit(code);
            }
            #[cfg(not(target_os = "linux"))]
            {
                std::process::exit(0);
            }
        }
        if args[1] == "__internal-trampoline-exec" {
            #[cfg(target_os = "linux")]
            {
                let code = boxr::runtime::linux::run_trampoline_exec(&args[2..])?;
                std::process::exit(code);
            }
            #[cfg(not(target_os = "linux"))]
            {
                std::process::exit(0);
            }
        }
        if args[1] == "__internal-pause" {
            #[cfg(target_os = "linux")]
            {
                let code = boxr::runtime::linux::run_internal_pause(&args[2..])?;
                std::process::exit(code);
            }
            #[cfg(not(target_os = "linux"))]
            {
                std::process::exit(0);
            }
        }
        if args[1] == "__completeNoDesc" {
            let comp = &args[2..];
            if comp == ["--module"] {
                println!("--module\n:4");
                eprintln!("Completion ended with directive: ShellCompDirectiveNoFileComp");
                std::process::exit(0);
            }
            if comp == ["--module", ""] {
                let xdg = std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| {
                    format!("{}/.config", std::env::var("HOME").unwrap_or_default())
                });
                let mod_dir =
                    std::path::PathBuf::from(xdg).join("containers/containers.conf.modules");
                if let Ok(entries) = std::fs::read_dir(mod_dir) {
                    let mut names: Vec<String> = entries
                        .flatten()
                        .filter_map(|e| e.file_name().into_string().ok())
                        .collect();
                    names.sort();
                    for n in names {
                        println!("{}", n);
                    }
                }
                println!(":4");
                eprintln!("Completion ended with directive: ShellCompDirectiveNoFileComp");
                std::process::exit(0);
            }
        }
        if std::path::Path::new("/etc/containers/podman_preexec_hooks.txt").exists() {
            if let Ok(hooks_dir) = std::env::var("PODMAN_PREEXEC_HOOKS_DIR") {
                if let Ok(entries) = std::fs::read_dir(&hooks_dir) {
                    let mut scripts: Vec<std::path::PathBuf> =
                        entries.flatten().map(|e| e.path()).collect();
                    scripts.sort();
                    for script in scripts {
                        if script.is_file() {
                            if let Ok(status) = std::process::Command::new(&script)
                                .args(&args[1..])
                                .status()
                            {
                                if !status.success() {
                                    std::process::exit(status.code().unwrap_or(1));
                                }
                            }
                        }
                    }
                }
            }
        }
        let sub_idx = boxr::cli::podman_subcommand_index(&args);
        if args.get(sub_idx).map(String::as_str) == Some("unshare") {
            let sub = &args[sub_idx + 1..];
            let wants_help = sub
                .iter()
                .take_while(|a| a.starts_with('-'))
                .any(|a| *a == "--help" || *a == "-h");
            if !wants_help {
                #[cfg(target_os = "linux")]
                {
                    let globals =
                        boxr::cli::podman_globals::parse_podman_global_options(&args[..=sub_idx]);
                    boxr::cli::podman_globals::set_podman_global_options(globals);
                    let noout = args[..=sub_idx].iter().any(|a| a == "--noout");
                    let code = boxr::runtime::linux::run_unshare_cli(sub, noout)?;
                    std::process::exit(code);
                }
            }
        }
        if args[1] == "__internal-port-forward" {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let code = rt.block_on(async {
                let path = std::path::Path::new(&args[2]);
                boxr::network::rootless::run_port_forward_daemon(path).await
            });
            match code {
                Ok(_) => std::process::exit(0),
                Err(e) => {
                    eprintln!("Port forward daemon error: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    boxr::cli::log_level::init_from_process_args();
    boxr::completions::cobra::try_handle_cobra_complete(&args);
    if boxr::compose::provider::try_run_external_compose_provider(&args) {
        unreachable!();
    }
    if boxr::cli::usage_errors::try_print_argv_help(&args) {
        unreachable!();
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let raw_argv: Vec<String> = std::env::args().collect();
        let argv: Vec<String> = boxr::cli::preprocess_argv(raw_argv);
        let cli = match boxr::cli::Cli::try_parse_from(&argv) {
            Ok(c) => c,
            Err(e) => {
                boxr::cli::usage_errors::exit_on_clap_error(e, &argv);
            }
        };
        let code = match boxr::run_cli(cli).await {
            Ok(c) => c,
            Err(e) => {
                let msg = e.to_string();
                eprintln!("Error: {}", msg);
                if msg.contains("restart policy retries can only be specified with on-failure restart policy")
                    || msg.contains("Invalid restart policy")
                {
                    std::process::exit(125);
                }
                std::process::exit(1);
            }
        };
        std::process::exit(code);
    })
}
