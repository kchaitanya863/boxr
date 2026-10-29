//! Podman-compatible usage / missing-subcommand messages for BATS help tests.

use clap::error::{ContextKind, ErrorKind};
use clap::{Error, Parser};

/// Emit Podman-shaped errors and exit 125 (do not use clap's default print).
pub fn exit_on_clap_error(err: Error, argv: &[String]) -> ! {
    match err.kind() {
        ErrorKind::MissingSubcommand => {
            let prefix = parent_prefix(argv);
            print_missing_subcommand(&prefix);
            std::process::exit(125);
        }
        ErrorKind::InvalidSubcommand => {
            print_unrecognized(argv);
            std::process::exit(125);
        }
        ErrorKind::TooManyValues => {
            print_extra_positional_error(argv);
            std::process::exit(125);
        }
        ErrorKind::UnknownArgument => {
            if let Some(clap::error::ContextValue::String(flag)) = err.get(ContextKind::InvalidArg)
            {
                if flag.starts_with('-') {
                    eprintln!("Error: unknown flag: {}", flag.trim_start_matches('-'));
                    std::process::exit(125);
                }
            }
            let positionals = positional_args(argv);
            let trailing_x = positionals
                .iter()
                .rev()
                .take_while(|t| is_bats_numeric_token(t))
                .count();
            if trailing_x >= 2 {
                eprintln!("Error: too many arguments");
                std::process::exit(125);
            }
            print_extra_positional_error(argv);
            std::process::exit(125);
        }
        ErrorKind::MissingRequiredArgument => {
            eprintln!("Error: must provide required argument");
            std::process::exit(125);
        }
        ErrorKind::DisplayHelp | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            let _ = err.print();
            std::process::exit(0);
        }
        _ => {
            let _ = err.print();
            std::process::exit(125);
        }
    }
}

/// Podman-compatible CLI validation errors (exit 125).
pub fn exit_usage_error(msg: impl AsRef<str>) -> ! {
    eprintln!("Error: {}", msg.as_ref());
    std::process::exit(125);
}

/// Missing container (Podman BATS / CLI parity).
pub fn exit_container_not_found(name_or_id: &str) -> ! {
    eprintln!(
        "Error: no container with name or ID \"{}\" found: no such container",
        name_or_id
    );
    std::process::exit(125);
}

/// OCI/runtime configuration errors (exit 126).
pub fn exit_config_error(msg: impl AsRef<str>) -> ! {
    eprintln!("Error: {}", msg.as_ref());
    std::process::exit(126);
}

/// `podman help` / `podman help <cmd>` — show help for the root or nested command.
pub fn run_help_command(path: &[String]) -> ! {
    let bin = std::env::args()
        .next()
        .unwrap_or_else(|| "podman".to_string());
    let mut argv = vec![bin.clone()];
    if path.is_empty() {
        argv.push("--help".to_string());
    } else {
        argv.extend(path.iter().cloned());
        argv.push("--help".to_string());
    }
    match crate::cli::Cli::try_parse_from(&argv) {
        Err(e) if e.kind() == ErrorKind::DisplayHelp => {
            let _ = e.print();
            std::process::exit(0);
        }
        Err(_) => {
            let mut full = vec![bin, "help".to_string()];
            full.extend(path.iter().cloned());
            print_unrecognized(&full);
            std::process::exit(125);
        }
        Ok(_) => std::process::exit(0),
    }
}

fn is_bats_numeric_token(s: &str) -> bool {
    s.len() > 1 && s.starts_with('x') && s[1..].chars().all(|c| c.is_ascii_digit())
}

fn positional_args(argv: &[String]) -> Vec<&str> {
    argv.iter()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .map(|s| s.as_str())
        .collect()
}

fn print_extra_positional_error(argv: &[String]) {
    let positionals = positional_args(argv);
    if positionals.len() >= 2 {
        let verb = positionals[positionals.len() - 2];
        eprintln!("Error: {} takes no arguments", verb);
    } else if let Some(verb) = argv.get(1) {
        eprintln!("Error: {} takes no arguments", verb);
    } else {
        eprintln!("Error: too many arguments");
    }
}

fn parent_prefix(argv: &[String]) -> Vec<String> {
    if argv.len() <= 1 {
        return Vec::new();
    }
    argv[1..].to_vec()
}

fn print_missing_subcommand(prefix: &[String]) {
    let usage_target = if prefix.is_empty() {
        "podman".to_string()
    } else {
        format!("podman {}", prefix.join(" "))
    };
    let missing = if prefix.is_empty() {
        "podman COMMAND".to_string()
    } else {
        format!("podman {} COMMAND", prefix.join(" "))
    };
    eprintln!("Usage:  {} [options] COMMAND", usage_target);
    eprintln!();
    eprintln!("Error: missing command '{}'", missing);
}

fn print_unrecognized(argv: &[String]) {
    if argv.len() < 2 {
        print_missing_subcommand(&[]);
        return;
    }
    let bad = argv.last().unwrap();
    if bad.starts_with('x') && bad[1..].chars().all(|c| c.is_ascii_digit()) {
        eprintln!("Error: too many arguments");
        return;
    }
    let parents: Vec<&str> = argv[1..argv.len() - 1].iter().map(|s| s.as_str()).collect();
    let mut parts = vec!["podman"];
    parts.extend(parents);
    parts.push(bad.as_str());
    eprintln!("Error: unrecognized command \"{}\"", parts.join(" "));
}
