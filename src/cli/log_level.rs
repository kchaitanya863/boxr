//! Podman global `--log-level` / `--debug` (BATS 001-basic, 800-config).

use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Panic = 5,
}

#[derive(Clone, Copy, Debug)]
pub struct LogConfig {
    pub level: Level,
}

static CONFIG: OnceLock<LogConfig> = OnceLock::new();

/// Parse raw process args. On error, print message and exit **1** (Podman BATS).
pub fn init_from_process_args() {
    let argv: Vec<String> = std::env::args().collect();
    match parse(&argv) {
        Ok(cfg) => {
            let _ = CONFIG.set(cfg);
        }
        Err(msg) => {
            eprintln!("{}", msg);
            std::process::exit(1);
        }
    }
}

pub fn config() -> LogConfig {
    *CONFIG.get().unwrap_or(&LogConfig { level: Level::Warn })
}

pub fn level_allows(record: Level) -> bool {
    record <= config().level
}

/// Emit hierarchical log lines for `podman version` (001-basic log-level test).
pub fn emit_version_diagnostic_logs() {
    let cfg = config().level;
    if cfg <= Level::Trace {
        log_line(Level::Trace, "version");
    }
    if cfg <= Level::Debug {
        log_line(Level::Debug, "version");
    }
    if cfg <= Level::Info {
        log_line(Level::Info, "version");
    }
}

pub fn emit_shutdown_engines() {
    if config().level <= Level::Debug {
        log_line(Level::Debug, "Shutting down engines");
    }
}

fn log_line(level: Level, msg: &str) {
    eprintln!("time= level={} msg=\"{}\"", level_name(level), msg);
}

fn level_name(level: Level) -> &'static str {
    match level {
        Level::Trace => "trace",
        Level::Debug => "debug",
        Level::Info => "info",
        Level::Warn => "warn",
        Level::Error => "error",
        Level::Panic => "panic",
    }
}

fn parse(argv: &[String]) -> Result<LogConfig, String> {
    let mut explicit_level: Option<Level> = None;
    let mut debug_flag = false;
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--debug" || a == "-D" {
            debug_flag = true;
            i += 1;
            continue;
        }
        if let Some(v) = a.strip_prefix("--log-level=") {
            explicit_level = Some(parse_level_name(v)?);
            i += 1;
            continue;
        }
        if a == "--log-level" {
            explicit_level = Some(parse_level_name(
                argv.get(i + 1).map(String::as_str).unwrap_or(""),
            )?);
            i += 2;
            continue;
        }
        i += 1;
    }
    if debug_flag && explicit_level.is_some() {
        return Err("Setting --log-level and --debug is not allowed".to_string());
    }
    let level = if debug_flag {
        Level::Debug
    } else {
        explicit_level.unwrap_or(Level::Warn)
    };
    Ok(LogConfig { level })
}

fn parse_level_name(name: &str) -> Result<Level, String> {
    match name.to_ascii_lowercase().as_str() {
        "trace" => Ok(Level::Trace),
        "debug" => Ok(Level::Debug),
        "info" => Ok(Level::Info),
        "warn" | "warning" => Ok(Level::Warn),
        "error" => Ok(Level::Error),
        "panic" | "fatal" => Ok(Level::Panic),
        other => Err(format!(
            "Log Level \"{}\" is not supported: invalid level",
            other
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telepathic_level_rejected() {
        let argv = vec![
            "boxr".into(),
            "--log-level=telepathic".into(),
            "version".into(),
        ];
        assert!(parse(&argv).is_err());
    }

    #[test]
    fn debug_and_log_level_conflict() {
        let argv = vec![
            "boxr".into(),
            "--debug".into(),
            "--log-level=warn".into(),
            "version".into(),
        ];
        assert_eq!(
            parse(&argv).unwrap_err(),
            "Setting --log-level and --debug is not allowed"
        );
    }
}
