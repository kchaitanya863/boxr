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
            #[cfg(target_os = "linux")]
            {
                let code = boxr::runtime::linux::run_unshare_cli(&args[2..])?;
                std::process::exit(code);
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
        let cli = match boxr::cli::Cli::try_parse() {
            Ok(c) => c,
            Err(e) => {
                e.print().ok();
                std::process::exit(125);
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
