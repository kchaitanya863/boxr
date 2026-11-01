//! Podman/Docker-compatible `--ulimit` parsing and application.

use anyhow::{Context, Result, anyhow};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ParsedUlimit {
    pub rlimit_resource: u32,
    pub inspect_name: &'static str,
    pub soft: i64,
    pub hard: i64,
}

#[cfg(target_os = "linux")]
const RLIMIT_LOCKS: u32 = libc::RLIMIT_LOCKS as u32;
#[cfg(not(target_os = "linux"))]
const RLIMIT_LOCKS: u32 = 10;

#[cfg(target_os = "linux")]
const RLIMIT_MSGQUEUE: u32 = libc::RLIMIT_MSGQUEUE as u32;
#[cfg(not(target_os = "linux"))]
const RLIMIT_MSGQUEUE: u32 = 12;

#[cfg(target_os = "linux")]
const RLIMIT_NICE: u32 = libc::RLIMIT_NICE as u32;
#[cfg(not(target_os = "linux"))]
const RLIMIT_NICE: u32 = 13;

#[cfg(target_os = "linux")]
const RLIMIT_RTPRIO: u32 = libc::RLIMIT_RTPRIO as u32;
#[cfg(not(target_os = "linux"))]
const RLIMIT_RTPRIO: u32 = 14;

#[cfg(target_os = "linux")]
const RLIMIT_RTTIME: u32 = libc::RLIMIT_RTTIME as u32;
#[cfg(not(target_os = "linux"))]
const RLIMIT_RTTIME: u32 = 15;

#[cfg(target_os = "linux")]
const RLIMIT_SIGPENDING: u32 = libc::RLIMIT_SIGPENDING as u32;
#[cfg(not(target_os = "linux"))]
const RLIMIT_SIGPENDING: u32 = 11;

#[cfg(unix)]
const RLIMIT_CORE: u32 = libc::RLIMIT_CORE as u32;
#[cfg(not(unix))]
const RLIMIT_CORE: u32 = 4;

#[cfg(unix)]
const RLIMIT_CPU: u32 = libc::RLIMIT_CPU as u32;
#[cfg(not(unix))]
const RLIMIT_CPU: u32 = 0;

#[cfg(unix)]
const RLIMIT_DATA: u32 = libc::RLIMIT_DATA as u32;
#[cfg(not(unix))]
const RLIMIT_DATA: u32 = 2;

#[cfg(unix)]
const RLIMIT_FSIZE: u32 = libc::RLIMIT_FSIZE as u32;
#[cfg(not(unix))]
const RLIMIT_FSIZE: u32 = 1;

#[cfg(unix)]
const RLIMIT_MEMLOCK: u32 = libc::RLIMIT_MEMLOCK as u32;
#[cfg(not(unix))]
const RLIMIT_MEMLOCK: u32 = 8;

#[cfg(unix)]
const RLIMIT_NOFILE: u32 = libc::RLIMIT_NOFILE as u32;
#[cfg(not(unix))]
const RLIMIT_NOFILE: u32 = 7;

#[cfg(unix)]
const RLIMIT_NPROC: u32 = libc::RLIMIT_NPROC as u32;
#[cfg(not(unix))]
const RLIMIT_NPROC: u32 = 6;

#[cfg(unix)]
const RLIMIT_RSS: u32 = libc::RLIMIT_RSS as u32;
#[cfg(not(unix))]
const RLIMIT_RSS: u32 = 5;

#[cfg(unix)]
const RLIMIT_STACK: u32 = libc::RLIMIT_STACK as u32;
#[cfg(not(unix))]
const RLIMIT_STACK: u32 = 3;

fn rlimit_name_parts(name: &str) -> Option<(&'static str, u32)> {
    match name {
        "core" => Some(("RLIMIT_CORE", RLIMIT_CORE)),
        "cpu" => Some(("RLIMIT_CPU", RLIMIT_CPU)),
        "data" => Some(("RLIMIT_DATA", RLIMIT_DATA)),
        "fsize" => Some(("RLIMIT_FSIZE", RLIMIT_FSIZE)),
        "locks" => Some(("RLIMIT_LOCKS", RLIMIT_LOCKS)),
        "memlock" => Some(("RLIMIT_MEMLOCK", RLIMIT_MEMLOCK)),
        "msgqueue" => Some(("RLIMIT_MSGQUEUE", RLIMIT_MSGQUEUE)),
        "nice" => Some(("RLIMIT_NICE", RLIMIT_NICE)),
        "nofile" => Some(("RLIMIT_NOFILE", RLIMIT_NOFILE)),
        "nproc" => Some(("RLIMIT_NPROC", RLIMIT_NPROC)),
        "rss" => Some(("RLIMIT_RSS", RLIMIT_RSS)),
        "rtprio" => Some(("RLIMIT_RTPRIO", RLIMIT_RTPRIO)),
        "rttime" => Some(("RLIMIT_RTTIME", RLIMIT_RTTIME)),
        "sigpending" => Some(("RLIMIT_SIGPENDING", RLIMIT_SIGPENDING)),
        "stack" => Some(("RLIMIT_STACK", RLIMIT_STACK)),
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
    let (name, limits) = spec.split_once('=').ok_or_else(|| {
        anyhow!(
            "ulimit option \"{}\" requires name=SOFT:HARD, failed to be parsed: invalid ulimit argument {}",
            spec,
            spec
        )
    })?;
    let (soft_s, hard_s) = limits.split_once(':').ok_or_else(|| {
        anyhow!(
            "ulimit option \"{}\" requires name=SOFT:HARD, failed to be parsed: invalid ulimit argument {}",
            spec,
            spec
        )
    })?;
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
        if u.eq_ignore_ascii_case("host") {
            continue;
        }
        parse_ulimit_option(u)?;
    }
    Ok(())
}

pub fn ulimits_inspect_json(ulimits: &[String]) -> Result<serde_json::Value> {
    let mut entries = Vec::new();
    for u in ulimits {
        if u.eq_ignore_ascii_case("host") {
            continue;
        }
        let p = parse_ulimit_option(u)?;
        entries.push(serde_json::json!({
            "Name": p.inspect_name,
            "Soft": p.soft,
            "Hard": p.hard,
        }));
    }
    Ok(serde_json::Value::Array(entries))
}

#[cfg(target_os = "linux")]
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
        if spec.eq_ignore_ascii_case("host") {
            continue;
        }
        let p = parse_ulimit_option(spec)?;
        #[cfg(target_os = "linux")]
        {
            let mut cur = rlim_from_i64(p.soft);
            let mut max = rlim_from_i64(p.hard);
            let mut host_lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if unsafe { libc::getrlimit(p.rlimit_resource as _, &mut host_lim) } == 0 {
                if max > host_lim.rlim_max {
                    max = host_lim.rlim_max;
                }
                if cur > max {
                    cur = max;
                }
            }
            let lim = libc::rlimit {
                rlim_cur: cur,
                rlim_max: max,
            };
            if unsafe { libc::setrlimit(p.rlimit_resource as _, &lim) } != 0 {
                return Err(anyhow!(
                    "setrlimit {}: {}",
                    p.inspect_name,
                    std::io::Error::last_os_error()
                ));
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = p;
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
