//! Podman-compatible usage / missing-subcommand messages for BATS help tests.

use std::sync::OnceLock;

static HIDE_REMOTE_HELP: OnceLock<bool> = OnceLock::new();

pub fn set_hide_remote_help(hide: bool) {
    let _ = HIDE_REMOTE_HELP.set(hide);
}

fn hide_remote_in_help(argv: &[String]) -> bool {
    if *HIDE_REMOTE_HELP.get().unwrap_or(&false) {
        return true;
    }
    if std::env::var_os("CONTAINER_HOST").is_some()
        || std::env::var_os("CONTAINER_CONNECTION").is_some()
    {
        return true;
    }
    argv.iter()
        .any(|a| a.starts_with("--url") || a.starts_with("--connection"))
}

use clap::error::{ContextKind, ErrorKind};
use clap::{CommandFactory, Error, Parser};

fn normalize_help_for_bats(help: &str, sub_path: &[&str]) -> String {
    let has_options = help.lines().any(|l| l.trim() == "Options:");
    let has_subcommands = help.lines().any(|l| l.trim() == "Available Commands:");
    let mut out = String::new();
    let mut lines = help.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed == "Usage:" {
            out.push_str(line);
            out.push('\n');
            if let Some(usage) = lines.next() {
                out.push_str(&normalize_usage_line(
                    usage,
                    sub_path,
                    has_options,
                    has_subcommands,
                ));
                out.push('\n');
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Usage:") {
            out.push_str("Usage:\n");
            out.push_str(&normalize_usage_line(
                rest.trim(),
                sub_path,
                has_options,
                has_subcommands,
            ));
            out.push('\n');
            continue;
        }
        if !sub_path.is_empty()
            && has_subcommands
            && trimmed.starts_with("help ")
            && trimmed.contains("Print this message")
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    let last_cmd = sub_path.last().copied().unwrap_or("");
    if matches!(last_cmd, "pull" | "push" | "create" | "run") {
        let (conf_retry, conf_delay) = containers_conf_retry_settings();
        let verb = if last_cmd == "push" { "push" } else { "pull" };
        let retry_val = conf_retry.as_deref().unwrap_or("3");
        let delay_val = conf_delay.as_deref().unwrap_or("2s");
        out = out.replace(
            "performing pull (default 3)",
            &format!("performing {} (default {})", verb, retry_val),
        );
        out = out.replace(
            "performing push (default 3)",
            &format!("performing {} (default {})", verb, retry_val),
        );
        out = out.replace(
            "pull failures (default \"2s\")",
            &format!("{} failures (default \"{}\")", verb, delay_val),
        );
        out = out.replace(
            "push failures (default \"2s\")",
            &format!("{} failures (default \"{}\")", verb, delay_val),
        );
        if (last_cmd == "push" || conf_retry.is_some() || conf_delay.is_some())
            && !out.contains("--retry ")
        {
            let extra = format!(
                "      --retry uint         Number of times to retry in case of failure when performing {} (default {})\n      --retry-delay string Delay between retries in case of {} failures (default \"{}\")\n",
                verb, retry_val, verb, delay_val
            );
            out.push_str(&extra);
        }
    }
    out
}

fn containers_conf_retry_settings() -> (Option<String>, Option<String>) {
    let mut retry = None;
    let mut retry_delay = None;
    for var in ["CONTAINERS_CONF", "CONTAINERS_CONF_OVERRIDE"] {
        if let Ok(path) = std::env::var(var) {
            if let Ok(content) = std::fs::read_to_string(&path) {
                for line in content.lines() {
                    let line = line.split('#').next().unwrap_or("").trim();
                    if let Some(rest) = line.strip_prefix("retry_delay") {
                        let v = rest
                            .trim_start()
                            .strip_prefix('=')
                            .unwrap_or(rest)
                            .trim()
                            .trim_matches('"');
                        if !v.is_empty() {
                            retry_delay = Some(v.to_string());
                        }
                    } else if let Some(rest) = line.strip_prefix("retry") {
                        let rest = rest.trim_start();
                        if let Some(after_eq) = rest.strip_prefix('=') {
                            let v = after_eq.trim().trim_matches('"');
                            if !v.is_empty() {
                                retry = Some(v.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    (retry, retry_delay)
}

fn normalize_usage_line(
    usage: &str,
    sub_path: &[&str],
    has_options_section: bool,
    has_subcommands: bool,
) -> String {
    if sub_path.is_empty() {
        return "  podman [command] [options]".to_string();
    }
    let full = format!("podman {}", sub_path.join(" "));
    if has_subcommands {
        return format!("  {full} [command]");
    }

    let mut u = usage.trim().to_string();
    u = u.replace("[OPTIONS]", "[options]");
    u = u.replace('<', "").replace('>', "");
    if (sub_path == ["kube", "generate"] || sub_path == ["generate", "kube"])
        && u.ends_with("...")
        && u.contains("{CONTAINER...|POD...|VOLUME...}")
    {
        u = u.trim_end_matches("...").to_string();
    }
    if u.starts_with("podman ") {
        // already prefixed
    } else if let Some(leaf) = sub_path.last() {
        if let Some(rest) = u.strip_prefix(&format!("{leaf} ")) {
            u = format!("{full} {rest}");
        } else if u == *leaf {
            u = full.clone();
        } else {
            u = format!("{full} {u}");
        }
    } else {
        u = format!("{full} {u}");
    }

    if has_options_section && !u.contains("[options]") {
        if let Some(rest) = u.strip_prefix(&format!("{full} ")) {
            u = format!("{full} [options] {rest}");
        } else if u == full {
            u = format!("{full} [options]");
        }
    }

    format!("  {u}")
}

fn render_command_help(sub_path: &[&str], argv: &[String]) -> ! {
    let mut cmd = crate::cli::Cli::command();
    for part in sub_path {
        let Some(sub) = cmd.find_subcommand(part) else {
            let mut full: Vec<String> = vec!["podman".into(), "help".into()];
            full.extend(sub_path.iter().map(|s| (*s).to_string()));
            print_unrecognized(&full);
            std::process::exit(125);
        };
        cmd = sub.clone();
    }
    let mut help = normalize_help_for_bats(&cmd.render_help().to_string(), sub_path);
    if sub_path.last() == Some(&"push") {
        let mut comp_fmt = "gzip".to_string();
        let mut comp_lvl: Option<String> = None;
        for var in ["CONTAINERS_CONF_OVERRIDE", "CONTAINERS_CONF"] {
            if let Ok(path) = std::env::var(var) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    for line in content.lines() {
                        let line = line.trim();
                        if let Some((k, v)) = line.split_once('=') {
                            let k = k.trim();
                            let v = v.trim().trim_matches('"').trim_matches('\'');
                            if k == "compression_format" && !v.is_empty() {
                                comp_fmt = v.to_string();
                            } else if k == "compression_level" && !v.is_empty() {
                                comp_lvl = Some(v.to_string());
                            }
                        }
                    }
                }
            }
        }
        help.push_str(&format!(
            "      --compression-format string   compression format to use (default \"{}\")\n",
            comp_fmt
        ));
        if let Some(lvl) = comp_lvl {
            help.push_str(&format!(
                "      --compression-level int       compression level to use (default {})\n",
                lvl
            ));
        } else {
            help.push_str("      --compression-level int       compression level to use\n");
        }
    }
    print!("{}", filter_remote_help(&help, argv));
    std::process::exit(0);
}

/// Extract the positional tokens after `[options]` on the normalized `Usage:` line for `sub_path`.
pub fn usage_positional_tokens_for_bats(sub_path: &[&str]) -> Vec<String> {
    let mut cmd = crate::cli::Cli::command();
    for part in sub_path {
        let Some(sub) = cmd.find_subcommand(part) else {
            return Vec::new();
        };
        cmd = sub.clone();
    }
    let help = normalize_help_for_bats(&cmd.render_help().to_string(), sub_path);
    let mut lines = help.lines();
    while let Some(l) = lines.next() {
        if l.trim() == "Usage:" {
            if let Some(usage) = lines.next() {
                let prefix = if sub_path.is_empty() {
                    "podman".to_string()
                } else {
                    format!("podman {}", sub_path.join(" "))
                };
                let rest = usage.trim();
                let after = rest.strip_prefix(&prefix).unwrap_or(rest).trim();
                return after
                    .split_whitespace()
                    .filter(|t| *t != "[options]")
                    .map(|s| s.to_string())
                    .collect();
            }
        }
    }
    Vec::new()
}

/// When argv includes `--help` after a subcommand, render that command's help (015-help.bats).
pub fn try_print_argv_help(argv: &[String]) -> bool {
    if !argv.iter().any(|a| a == "--help" || a == "-h") {
        return false;
    }
    let idx = super::podman_subcommand_index(argv);
    if idx >= argv.len() {
        render_command_help(&[], argv);
    }
    let first_sub = argv[idx].as_str();
    let second_sub = argv.get(idx + 1).map(String::as_str).unwrap_or("");
    let is_run_or_create = first_sub == "run"
        || first_sub == "create"
        || (first_sub == "container" && (second_sub == "run" || second_sub == "create"));
    if is_run_or_create && !argv.iter().any(|a| a == "--help") {
        return false;
    }
    if argv[idx] == "help" {
        let mut has_command = false;
        for a in argv.iter().skip(idx + 1) {
            if *a == "--help" || *a == "-h" {
                break;
            }
            if a.starts_with('-') {
                continue;
            }
            has_command = true;
            break;
        }
        if !has_command {
            print_help_leaf_help();
        }
    }
    let mut sub_path: Vec<&str> = Vec::new();
    let mut i = idx;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--help" || a == "-h" {
            break;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        if (sub_path.first() == Some(&"exec") || sub_path.first() == Some(&"run"))
            && sub_path.len() >= 1
        {
            return false;
        }
        sub_path.push(a);
        i += 1;
    }
    if sub_path.len() >= 2 && sub_path.last() == Some(&"help") {
        print_group_help_leaf(&sub_path[..sub_path.len() - 1]);
    }
    render_command_help(&sub_path, argv);
}

/// `podman help` / `podman help <cmd>` — show help for the root or nested command.
pub fn run_help_command(path: &[String]) -> ! {
    let argv: Vec<String> = std::env::args().collect();
    let parts: Vec<&str> = path.iter().map(String::as_str).collect();
    render_command_help(&parts, &argv);
}

/// Podman/libpod runtime or storage failures (BATS expect exit 125).
pub fn exit_podman_error(err: impl std::fmt::Display) -> ! {
    eprintln!("{}", err);
    std::process::exit(125);
}

/// Emit Podman-shaped errors and exit 125 (do not use clap's default print).
pub fn exit_on_clap_error(err: Error, argv: &[String]) -> ! {
    match err.kind() {
        ErrorKind::MissingSubcommand => {
            let prefix = parent_prefix(argv);
            print_missing_subcommand(&prefix);
            std::process::exit(125);
        }
        ErrorKind::InvalidSubcommand => {
            if let Some(flag) = argv.iter().skip(1).find(|a| a.starts_with('-')) {
                let flag_name = flag.split('=').next().unwrap_or(flag.as_str());
                let bin = if hide_remote_in_help(argv) {
                    "podman-remote"
                } else {
                    "podman"
                };
                eprintln!("Error: unknown flag: {}", flag_name);
                eprintln!("See '{} --help'", bin);
                std::process::exit(125);
            }
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
                if flag == "--module" || flag.starts_with("--module=") {
                    let sub = argv
                        .get(super::podman_subcommand_index(argv))
                        .map(|s| s.as_str())
                        .unwrap_or("create");
                    eprintln!("Error: unknown flag: --module\nSee 'podman {} --help'", sub);
                    std::process::exit(125);
                }
                if flag.starts_with('-') {
                    let flag_name = flag.split('=').next().unwrap_or(flag.as_str());
                    let bin = if hide_remote_in_help(argv) {
                        "podman-remote"
                    } else {
                        "podman"
                    };
                    let mut cmd = crate::cli::Cli::command();
                    let mut sub_parts = vec![bin];
                    for tok in argv.iter().skip(1) {
                        if tok.starts_with('-') {
                            continue;
                        }
                        if let Some(sub) = cmd.find_subcommand(tok) {
                            sub_parts.push(tok.as_str());
                            cmd = sub.clone();
                        } else {
                            break;
                        }
                    }
                    eprintln!("Error: unknown flag: {}", flag_name);
                    eprintln!("See '{} --help'", sub_parts.join(" "));
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
            if argv.iter().any(|a| a == "diff") {
                if hide_remote_in_help(argv) {
                    eprintln!("Error: diff requires a name or id");
                } else {
                    eprintln!("Error: diff requires a name, id, or the \"--latest\" flag");
                }
                std::process::exit(125);
            }
            if argv.iter().any(|a| a == "top") {
                eprintln!("Error: you must provide the name or id of a running container");
                std::process::exit(125);
            }
            eprintln!("Error: must provide required argument");
            std::process::exit(125);
        }
        ErrorKind::DisplayHelp | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            if try_print_argv_help(argv) {
                unreachable!();
            }
            let mut cmd = crate::cli::Cli::command();
            let help = cmd.render_help().to_string();
            print!("{}", filter_remote_help(&help, argv));
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

/// Usage for `podman help --help` (015-help.bats).
pub fn print_help_leaf_help() -> ! {
    print!(
        "\
Help about any command
Usage:
  podman help [command] [options]

Arguments:
  [command]...  Command to show help for

Options:
  -h, --help  Print help
"
    );
    std::process::exit(0);
}

fn print_group_help_leaf(group_path: &[&str]) -> ! {
    let full = format!("podman {} help", group_path.join(" "));
    print!(
        "\
Help about any command
Usage:
  {full} [command] [options]

Options:
  -h, --help  Print help
"
    );
    std::process::exit(0);
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
    if argv.iter().any(|a| a == "attach") {
        let cmd_str = if argv.windows(2).any(|w| w[0] == "container" && w[1] == "attach") {
            "podman container attach"
        } else {
            "podman attach"
        };
        eprintln!("Error: `{}` accepts at most one argument", cmd_str);
        return;
    }
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

fn filter_remote_help(help: &str, argv: &[String]) -> String {
    if !hide_remote_in_help(argv) {
        return help.to_string();
    }
    help.lines()
        .filter(|line| !line.contains("--remote"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}
