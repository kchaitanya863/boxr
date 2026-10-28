//! Podman/Docker-compatible `--ulimit` parsing and application.

use anyhow::{anyhow, Context, Result};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ParsedUlimit {
    pub rlimit_resource: u32,
    pub inspect_name: &'static str,
    pub soft: i64,
    pub hard: i64,
}

fn rlimit_name_parts(name: &str) -> Option<(&'static str, u32)> {
    match name {
        "core" => Some(("RLIMIT_CORE", libc::RLIMIT_CORE)),
        "cpu" => Some(("RLIMIT_CPU", libc::RLIMIT_CPU)),
        "data" => Some(("RLIMIT_DATA", libc::RLIMIT_DATA)),
        "fsize" => Some(("RLIMIT_FSIZE", libc::RLIMIT_FSIZE)),
        "locks" => Some(("RLIMIT_LOCKS", libc::RLIMIT_LOCKS)),
        "memlock" => Some(("RLIMIT_MEMLOCK", libc::RLIMIT_MEMLOCK)),
        "msgqueue" => Some(("RLIMIT_MSGQUEUE", libc::RLIMIT_MSGQUEUE)),
        "nice" => Some(("RLIMIT_NICE", libc::RLIMIT_NICE)),
        "nofile" => Some(("RLIMIT_NOFILE", libc::RLIMIT_NOFILE)),
        "nproc" => Some(("RLIMIT_NPROC", libc::RLIMIT_NPROC)),
        "rss" => Some(("RLIMIT_RSS", libc::RLIMIT_RSS)),
        "rtprio" => Some(("RLIMIT_RTPRIO", libc::RLIMIT_RTPRIO)),
        "rttime" => Some(("RLIMIT_RTTIME", libc::RLIMIT_RTTIME)),
        "sigpending" => Some(("RLIMIT_SIGPENDING", libc::RLIMIT_SIGPENDING)),
        "stack" => Some(("RLIMIT_STACK", libc::RLIMIT_STACK)),
        _ => None,
    }
}

fn parse_limit_token(tok: &str) -> Result<i64> {
    if tok == "-1" || tok.eq_ignore_ascii_case("unlimited") {
        return Ok(-1);
    }
    tok.parse::<i64>()
        .with_context(|| format!("ulimit limit value {:?}", tok))
}

/// Validate a `--ulimit` value (`name=soft:hard`). Exits via caller on Podman-shaped errors.
pub fn parse_ulimit_option(spec: &str) -> Result<ParsedUlimit> {
    let (name, limits) = spec
        .split_once('=')
        .ok_or_else(|| anyhow!("ulimit option \"{}\" requires name=SOFT:HARD", spec))?;
    let (soft_s, hard_s) = limits
        .split_once(':')
        .ok_or_else(|| anyhow!("ulimit option \"{}\" requires name=SOFT:HARD", spec))?;
    let (inspect_name, rlimit_resource) = rlimit_name_parts(name).ok_or_else(|| {
        anyhow!(
            "ulimit option \"{}\" requires name=SOFT:HARD, failed to be parsed: invalid ulimit name: {}",
            spec,
            name
        )
    })?;
    let soft = parse_limit_token(soft_s.trim())?;
    let hard = parse_limit_token(hard_s.trim())?;
    if soft == -1 && hard != -1 {
        return Err(anyhow!(
            "ulimit option \"{}\" requires name=SOFT:HARD, failed to be parsed: ulimit soft limit must be less than or equal to hard limit: soft: -1 (unlimited), hard: {}",
            spec,
            hard
        ));
    }
    if soft != -1 && hard != -1 && soft > hard {
        return Err(anyhow!(
            "ulimit option \"{}\" requires name=SOFT:HARD, failed to be parsed: ulimit soft limit must be less than or equal to hard limit: soft: {}, hard: {}",
            spec,
            soft,
            hard
        ));
    }
    Ok(ParsedUlimit {
        rlimit_resource,
        inspect_name,
        soft,
        hard,
    })
}

pub fn validate_ulimit_cli_options(ulimits: &[String]) -> Result<()> {
    for u in ulimits {
        parse_ulimit_option(u)?;
    }
    Ok(())
}

pub fn ulimits_inspect_json(ulimits: &[String]) -> Result<serde_json::Value> {
    let mut entries = Vec::new();
    for u in ulimits {
        let p = parse_ulimit_option(u)?;
        entries.push(serde_json::json!({
            "Name": p.inspect_name,
            "Soft": p.soft,
            "Hard": p.hard,
        }));
    }
    Ok(serde_json::Value::Array(entries))
}

fn rlim_from_i64(v: i64) -> libc::rlim_t {
    if v < 0 {
        libc::rlim_t::MAX
    } else {
        v as libc::rlim_t
    }
}

/// Apply limits from `ulimits.json` in the bundle (must run in the container child before exec).
pub fn apply_ulimits_from_bundle(bundle_path: &Path) -> Result<()> {
    let path = bundle_path.join("ulimits.json");
    if !path.exists() {
        return Ok(());
    }
    let content = std::fs::read_to_string(&path)?;
    let specs: Vec<String> = serde_json::from_str(&content)?;
    for spec in &specs {
        let p = parse_ulimit_option(spec)?;
        let lim = libc::rlimit {
            rlim_cur: rlim_from_i64(p.soft),
            rlim_max: rlim_from_i64(p.hard),
        };
        if unsafe { libc::setrlimit(p.rlimit_resource as libc::__rlimit_resource_t, &lim) } != 0 {
            return Err(anyhow!(
                "setrlimit {}: {}",
                p.inspect_name,
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

pub fn write_inspect_ulimits(bundle_path: &Path, ulimits: &[String]) -> Result<()> {
    if ulimits.is_empty() {
        return Ok(());
    }
    let json = ulimits_inspect_json(ulimits)?;
    std::fs::write(
        bundle_path.join("host_ulimits.json"),
        serde_json::to_string(&json)?,
    )?;
    Ok(())
}
