use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let args: Vec<String> = std::env::args().collect();
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
        if args[1] == "unshare" {
            let sub = &args[2..];
            let wants_help = sub.is_empty() || sub.iter().any(|a| a == "--help" || a == "-h");
            if !wants_help {
                #[cfg(target_os = "linux")]
                {
                    let code = boxr::runtime::linux::run_unshare_cli(sub, false)?;
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

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        boxr::cli::log_level::init_from_process_args();
        let raw_argv: Vec<String> = std::env::args().collect();
        if boxr::compose::provider::try_run_external_compose_provider(&raw_argv) {
            unreachable!();
        }
        if boxr::cli::usage_errors::try_print_argv_help(&raw_argv) {
            unreachable!();
        }
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
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };
        std::process::exit(code);
    })
}
