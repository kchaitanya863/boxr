//! External compose provider support (`PODMAN_COMPOSE_PROVIDER`, `compose_providers` in `containers.conf`).

use std::fs;
use std::io::ErrorKind;
use std::process::Command;

/// Check if an external compose provider is configured and execute it if so.
/// Returns `true` if handled (in which case it exits the process directly).
pub fn try_run_external_compose_provider(raw_argv: &[String]) -> bool {
    let sub_idx = crate::cli::podman_subcommand_index(raw_argv);
    if sub_idx >= raw_argv.len() || raw_argv[sub_idx] != "compose" {
        return false;
    }

    let Some((provider, warning_logs)) = resolve_compose_provider() else {
        return false;
    };

    let compose_args: Vec<String> = if raw_argv.len() > sub_idx + 1 {
        raw_argv[sub_idx + 1..].to_vec()
    } else {
        Vec::new()
    };

    let is_help =
        compose_args.is_empty() || compose_args.iter().any(|a| a == "--help" || a == "-h");

    // When `podman compose` is invoked with no arguments, Podman treats it as `compose --help`
    // and passes `["--help"]` to the external provider.
    let provider_args: Vec<String> = if compose_args.is_empty() {
        vec!["--help".to_string()]
    } else {
        compose_args.clone()
    };

    let docker_host = resolve_docker_host(raw_argv);
    let docker_config = std::env::var("DOCKER_CONFIG").unwrap_or_default();

    let mut cmd = Command::new(&provider);
    cmd.args(&provider_args);
    cmd.env("DOCKER_HOST", docker_host);
    cmd.env("DOCKER_BUILDKIT", "0");
    if !docker_config.is_empty() {
        cmd.env("DOCKER_CONFIG", docker_config);
    }

    if is_help {
        match cmd.output() {
            Ok(out) => {
                println!(
                    "Run compose workloads via an external provider such as docker-compose or podman-compose"
                );
                if warning_logs {
                    eprintln!(
                        "====>> Executing external compose provider {:?}. Please see podman-compose(1) for how to disable this message. <<====",
                        provider
                    );
                }
                use std::io::Write;
                let _ = std::io::stdout().write_all(&out.stdout);
                let _ = std::io::stderr().write_all(&out.stderr);
                std::process::exit(out.status.code().unwrap_or(1));
            }
            Err(e) => {
                if warning_logs {
                    eprintln!(
                        "====>> Executing external compose provider {:?}. Please see podman-compose(1) for how to disable this message. <<====",
                        provider
                    );
                }
                let args_str = provider_args.join(" ");
                let invoked = if args_str.is_empty() {
                    provider.clone()
                } else {
                    format!("{} {}", provider, args_str)
                };
                let reason = format_exec_error(&e);
                eprintln!("Error: executing {}: {}: {}", invoked, provider, reason);
                std::process::exit(125);
            }
        }
    }

    if warning_logs {
        eprintln!(
            "====>> Executing external compose provider {:?}. Please see podman-compose(1) for how to disable this message. <<====",
            provider
        );
    }

    match cmd.status() {
        Ok(status) => {
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(e) => {
            let args_str = provider_args.join(" ");
            let invoked = if args_str.is_empty() {
                provider.clone()
            } else {
                format!("{} {}", provider, args_str)
            };
            let reason = format_exec_error(&e);
            eprintln!("Error: executing {}: {}: {}", invoked, provider, reason);
            std::process::exit(125);
        }
    }
}

fn format_exec_error(e: &std::io::Error) -> String {
    match e.kind() {
        ErrorKind::PermissionDenied => "permission denied".to_string(),
        ErrorKind::NotFound => "no such file or directory".to_string(),
        _ => e.to_string().to_lowercase(),
    }
}

fn resolve_docker_host(raw_argv: &[String]) -> String {
    if let Ok(val) = std::env::var("DOCKER_HOST") {
        if !val.is_empty() {
            return val;
        }
    }
    // Check `--url` in argv
    let mut i = 1;
    while i < raw_argv.len() {
        if let Some(u) = raw_argv[i].strip_prefix("--url=") {
            return u.to_string();
        }
        if raw_argv[i] == "--url" && i + 1 < raw_argv.len() {
            return raw_argv[i + 1].clone();
        }
        i += 1;
    }
    if let Ok(ch) = std::env::var("CONTAINER_HOST") {
        if !ch.is_empty() {
            return ch;
        }
    }
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run".to_string());
    format!(
        "unix://{}/podman/podman.sock",
        runtime_dir.trim_end_matches('/')
    )
}

fn resolve_compose_provider() -> Option<(String, bool)> {
    let mut warning_logs = true;
    let mut conf_provider: Option<String> = None;

    for var in ["CONTAINERS_CONF_OVERRIDE", "CONTAINERS_CONF"] {
        let Ok(path) = std::env::var(var) else {
            continue;
        };
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        if let Some(w) = parse_compose_warning_logs(&content) {
            warning_logs = w;
        }
        if conf_provider.is_none() {
            conf_provider = parse_compose_providers(&content).into_iter().next();
        }
    }

    if let Ok(env_prov) = std::env::var("PODMAN_COMPOSE_PROVIDER") {
        if !env_prov.trim().is_empty() {
            return Some((env_prov.trim().to_string(), warning_logs));
        }
    }

    conf_provider.map(|p| (p, warning_logs))
}

fn parse_compose_warning_logs(content: &str) -> Option<bool> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() || trimmed.starts_with('[') {
            continue;
        }
        let Some((k, v)) = trimmed.split_once('=') else {
            continue;
        };
        if k.trim() == "compose_warning_logs" {
            let val = v.split('#').next().unwrap_or(v).trim().trim_matches('"');
            return match val.to_lowercase().as_str() {
                "false" | "0" | "no" => Some(false),
                "true" | "1" | "yes" => Some(true),
                _ => None,
            };
        }
    }
    None
}

fn parse_compose_providers(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_array = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if !in_array {
            if trimmed.starts_with("compose_providers") && trimmed.contains('[') {
                in_array = true;
                out.extend(extract_quoted(trimmed));
                if trimmed.contains(']') {
                    in_array = false;
                }
            }
            continue;
        }
        out.extend(extract_quoted(trimmed));
        if trimmed.contains(']') {
            in_array = false;
        }
    }
    out
}

fn extract_quoted(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find('"') {
        rest = &rest[start + 1..];
        if let Some(end) = rest.find('"') {
            out.push(rest[..end].to_string());
            rest = &rest[end + 1..];
        } else {
            break;
        }
    }
    out
}
