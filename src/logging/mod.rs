use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, FixedOffset, TimeZone, Utc};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub fn is_file_log_driver(driver: Option<&str>) -> bool {
    matches!(driver, Some("k8s-file") | Some("json-file"))
}

pub fn append_k8s_log_chunk(path: &Path, stream: &str, data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let ts = chrono::Local::now()
        .format("%Y-%m-%dT%H:%M:%S%.9f%:z")
        .to_string();
    let flag = if data.ends_with(b"\n") { "F" } else { "P" };
    file.write_all(format!("{} {} {} ", ts, stream, flag).as_bytes())?;
    file.write_all(data)?;
    if !data.ends_with(b"\n") {
        file.write_all(b"\n")?;
    }
    Ok(())
}

pub fn format_tty_crlf(chunk: &[u8], prev_was_cr: &mut bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(chunk.len() + 8);
    for &b in chunk {
        if b == b'\n' && !*prev_was_cr {
            out.push(b'\r');
        }
        out.push(b);
        *prev_was_cr = b == b'\r';
    }
    out
}

pub fn tee_k8s_stream<R: Read>(
    mut reader: R,
    log_path: std::path::PathBuf,
    stream: &'static str,
    attach: bool,
) {
    tee_k8s_stream_with_tty(reader, log_path, stream, attach, false);
}

pub fn tee_k8s_stream_with_tty<R: Read>(
    mut reader: R,
    log_path: std::path::PathBuf,
    stream: &'static str,
    attach: bool,
    tty: bool,
) {
    let mut buf = [0u8; 8192];
    let mut attach_out: Box<dyn Write + Send> = if attach {
        if stream == "stderr" {
            Box::new(std::io::stderr())
        } else {
            Box::new(std::io::stdout())
        }
    } else {
        Box::new(std::io::sink())
    };
    let mut prev_cr = false;
    while let Ok(n) = reader.read(&mut buf) {
        if n == 0 {
            break;
        }
        if stream == "stderr" {
            std::thread::sleep(Duration::from_millis(5));
        }
        let chunk = &buf[..n];
        let _ = append_k8s_log_chunk(&log_path, stream, chunk);
        if tty && stream == "stdout" {
            let formatted = format_tty_crlf(chunk, &mut prev_cr);
            let _ = attach_out.write_all(&formatted);
        } else {
            let _ = attach_out.write_all(chunk);
        }
        let _ = attach_out.flush();
    }
}

#[derive(Debug, Clone)]
pub struct K8sLogEntry {
    pub timestamp: DateTime<FixedOffset>,
    pub stream: String,
    pub is_stderr: bool,
    pub partial: bool,
    pub payload: Vec<u8>,
}

pub fn parse_logs_time_filter(value: &str) -> Result<DateTime<FixedOffset>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("empty logs time filter"));
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(dt);
    }
    if let Ok(dt) = chrono::DateTime::parse_from_str(trimmed, "%+") {
        return Ok(dt);
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%.f%z",
    ] {
        if let Ok(dt) = chrono::DateTime::parse_from_str(trimmed, fmt) {
            return Ok(dt);
        }
    }
    if trimmed.starts_with('-') {
        let dur = parse_duration_value(&trimmed[1..])?;
        let dt = Utc::now() - dur;
        return Ok(dt.with_timezone(&FixedOffset::east_opt(0).unwrap()));
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        let secs = trimmed
            .parse::<i64>()
            .context("parse unix timestamp for logs filter")?;
        let dt = Utc
            .timestamp_opt(secs, 0)
            .single()
            .context("invalid unix time")?;
        return Ok(dt.with_timezone(&FixedOffset::east_opt(0).unwrap()));
    }
    let dur = parse_duration_value(trimmed)?;
    let dt = Utc::now() - dur;
    Ok(dt.with_timezone(&FixedOffset::east_opt(0).unwrap()))
}

fn parse_duration_value(value: &str) -> Result<Duration> {
    let trimmed = value.trim();
    if let Some(num) = trimmed.strip_suffix("ms") {
        return Ok(Duration::from_secs_f64(num.parse::<f64>()? / 1000.0));
    }
    if let Some(num) = trimmed.strip_suffix('s') {
        return Ok(Duration::from_secs_f64(num.parse()?));
    }
    if let Some(num) = trimmed.strip_suffix('m') {
        return Ok(Duration::from_secs(num.parse::<u64>()? * 60));
    }
    if let Some(num) = trimmed.strip_suffix('h') {
        return Ok(Duration::from_secs(num.parse::<u64>()? * 3600));
    }
    Ok(Duration::from_secs(trimmed.parse()?))
}

fn parse_duration_seconds(value: &str) -> Result<u64> {
    Ok(parse_duration_value(value)?.as_secs())
}

/// Wall-clock follow timeout for values like `3s` / `500ms` (not RFC3339 timestamps).
pub fn parse_follow_until_timeout(until: &str) -> Option<Duration> {
    let trimmed = until.trim();
    if trimmed.is_empty() || trimmed.contains('T') {
        return None;
    }
    if trimmed.starts_with('-') {
        return None;
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) && trimmed.len() > 6 {
        return None;
    }
    parse_duration_value(trimmed).ok()
}

fn drop_k8s_payload(payload: &[u8]) -> bool {
    std::str::from_utf8(payload)
        .ok()
        .is_some_and(|s| s.trim() == "Terminated")
}

fn filter_k8s_entries(
    mut entries: Vec<K8sLogEntry>,
    since: Option<DateTime<FixedOffset>>,
    until: Option<DateTime<FixedOffset>>,
) -> Vec<K8sLogEntry> {
    entries.retain(|e| !drop_k8s_payload(&e.payload));
    if let Some(dt) = since {
        entries.retain(|e| e.timestamp >= dt);
    }
    if let Some(dt) = until {
        entries.retain(|e| e.timestamp <= dt);
    }
    entries
}

fn filter_k8s_entries_opts(
    entries: Vec<K8sLogEntry>,
    since: Option<&str>,
    until: Option<&str>,
) -> Vec<K8sLogEntry> {
    let since_dt = since.and_then(|s| parse_logs_time_filter(s).ok());
    let until_dt = until.and_then(|u| {
        if parse_follow_until_timeout(u).is_some() {
            None
        } else {
            parse_logs_time_filter(u).ok()
        }
    });
    filter_k8s_entries(entries, since_dt, until_dt)
}

pub fn write_log_text(text: &str, timestamps: bool) -> Result<()> {
    write_log_text_opts(text, timestamps, false)
}

pub fn write_log_text_opts(text: &str, timestamps: bool, follow_chunk: bool) -> Result<()> {
    if text.is_empty() {
        return Ok(());
    }
    let mut out = std::io::stdout();
    if timestamps {
        for line in text.split('\n') {
            writeln!(out, "{} {}", Utc::now().to_rfc3339(), line)?;
        }
    } else {
        out.write_all(text.as_bytes())?;
        if follow_chunk && !text.ends_with('\n') {
            out.write_all(b"\n")?;
        } else if !follow_chunk
            && text.contains('\n')
            && !text.ends_with('\n')
            && !text.ends_with('\r')
        {
            out.write_all(b"\n")?;
        }
    }
    out.flush()?;
    Ok(())
}

fn parse_k8s_log_line(line: &[u8]) -> Option<K8sLogEntry> {
    if line.is_empty() {
        return None;
    }
    let s = std::str::from_utf8(line).ok()?;
    for stream in ["stdout", "stderr"] {
        for (flag, partial) in [("F", false), ("P", true)] {
            let needle = format!(" {stream} {flag} ");
            if let Some(pos) = s.find(&needle) {
                let ts_str = s[..pos].trim();
                let payload = s[pos + needle.len()..].as_bytes().to_vec();
                let timestamp = DateTime::parse_from_rfc3339(ts_str)
                    .or_else(|_| chrono::DateTime::parse_from_str(ts_str, "%+"))
                    .ok()?;
                return Some(K8sLogEntry {
                    timestamp,
                    stream: stream.to_string(),
                    is_stderr: stream == "stderr",
                    partial,
                    payload,
                });
            }
        }
    }
    None
}

fn looks_like_k8s_record_start(line: &[u8]) -> bool {
    line.len() >= 5
        && line[0].is_ascii_digit()
        && line[1].is_ascii_digit()
        && line[2].is_ascii_digit()
        && line[3].is_ascii_digit()
        && line[4] == b'-'
}

pub fn read_k8s_log_entries(path: &Path) -> Result<Vec<K8sLogEntry>> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut entries = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if looks_like_k8s_record_start(line) {
            if !current.is_empty() {
                if let Some(entry) = parse_k8s_log_line(&current) {
                    entries.push(entry);
                }
                current.clear();
            }
            current.extend_from_slice(line);
        } else if !current.is_empty() {
            current.push(b'\n');
            current.extend_from_slice(line);
        }
    }
    if !current.is_empty() {
        if let Some(entry) = parse_k8s_log_line(&current) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

pub fn reconstruct_k8s_lines(entries: &[K8sLogEntry]) -> Vec<Vec<u8>> {
    reconstruct_k8s_lines_opts(entries, true)
}

pub fn reconstruct_k8s_lines_opts(
    entries: &[K8sLogEntry],
    include_trailing_partial: bool,
) -> Vec<Vec<u8>> {
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut partial: Vec<u8> = Vec::new();
    for e in entries {
        if e.partial {
            partial.extend_from_slice(&e.payload);
            continue;
        }
        let mut line = partial.clone();
        partial.clear();
        line.extend_from_slice(&e.payload);
        lines.push(line);
    }
    if include_trailing_partial && !partial.is_empty() {
        lines.push(partial);
    }
    lines
}

pub fn reconstruct_k8s_lines_with_ts(
    entries: &[K8sLogEntry],
) -> Vec<(DateTime<FixedOffset>, Vec<u8>)> {
    let mut lines: Vec<(DateTime<FixedOffset>, Vec<u8>)> = Vec::new();
    let mut partial: Vec<u8> = Vec::new();
    for e in entries {
        if e.partial {
            partial.extend_from_slice(&e.payload);
            continue;
        }
        let mut line = partial.clone();
        partial.clear();
        line.extend_from_slice(&e.payload);
        lines.push((e.timestamp, line));
    }
    if !partial.is_empty() {
        if let Some(ts) = entries.last().map(|e| e.timestamp) {
            lines.push((ts, partial));
        }
    }
    lines
}

fn tail_log_lines_with_ts(
    mut lines: Vec<(DateTime<FixedOffset>, Vec<u8>)>,
    tail: Option<usize>,
) -> Vec<(DateTime<FixedOffset>, Vec<u8>)> {
    let Some(n) = tail else {
        return lines;
    };
    if n == 0 {
        return Vec::new();
    }
    if lines.len() <= n {
        return lines;
    }
    lines.split_off(lines.len() - n)
}

pub fn format_log_lines_timestamped(lines: &[(DateTime<FixedOffset>, Vec<u8>)]) -> String {
    let mut out = String::new();
    for (i, (ts, line)) in lines.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&ts.to_rfc3339_opts(chrono::SecondsFormat::Nanos, false));
        out.push(' ');
        out.push_str(&String::from_utf8_lossy(line));
    }
    out
}

pub fn format_log_lines(lines: &[Vec<u8>]) -> String {
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&String::from_utf8_lossy(line));
    }
    out
}

fn expand_embedded_newlines(lines: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for line in lines {
        let mut parts = line.split(|b| *b == b'\n').peekable();
        while let Some(part) = parts.next() {
            if part.is_empty() && parts.peek().is_none() {
                continue;
            }
            out.push(part.to_vec());
        }
    }
    out
}

fn expand_embedded_newlines_ts(
    lines: Vec<(DateTime<FixedOffset>, Vec<u8>)>,
) -> Vec<(DateTime<FixedOffset>, Vec<u8>)> {
    let mut out = Vec::new();
    for (ts, line) in lines {
        for part in line.split(|b| *b == b'\n') {
            if part.is_empty() {
                continue;
            }
            out.push((ts, part.to_vec()));
        }
    }
    out
}

pub fn tail_log_lines(mut lines: Vec<Vec<u8>>, tail: Option<usize>) -> Vec<Vec<u8>> {
    let Some(n) = tail else {
        return lines;
    };
    if n == 0 {
        return Vec::new();
    }
    if lines.len() <= n {
        return lines;
    }
    lines.split_off(lines.len() - n)
}

/// Extract user-visible log payload from k8s-file / CRI log lines (legacy flat decode).
pub fn decode_k8s_log_file(path: &Path) -> Result<String> {
    let entries = read_k8s_log_entries(path)?;
    Ok(format_log_lines(&reconstruct_k8s_lines(&entries)))
}

pub fn resolve_container_log_path(
    bundle_path: &Path,
    annotations: &std::collections::HashMap<String, String>,
) -> Option<PathBuf> {
    if annotations
        .get("boxr.log_driver")
        .is_some_and(|d| d == "journald")
    {
        return annotations
            .get("boxr.journald_capture")
            .map(PathBuf::from)
            .filter(|p| p.exists());
    }
    if let Some(p) = annotations
        .get("boxr.log_path")
        .map(PathBuf::from)
        .filter(|p| p.exists())
    {
        return Some(p);
    }
    if annotations
        .get("boxr.log_driver")
        .is_some_and(|d| is_file_log_driver(Some(d.as_str())))
    {
        if let Some(name) = bundle_path.file_name().and_then(|s| s.to_str()) {
            let ctr = bundle_path.join(format!("{name}-ctr.log"));
            return Some(ctr);
        }
    }
    let logs_txt = bundle_path.join("logs.txt");
    if logs_txt.exists() {
        return Some(logs_txt);
    }
    None
}

pub fn is_k8s_log_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.contains("ctr.log") || s.contains("journald")
}

pub fn read_log_output(
    path: &Path,
    since: Option<&str>,
    until: Option<&str>,
    tail: Option<usize>,
) -> Result<String> {
    read_log_output_opts(path, since, until, tail, false)
}

pub fn read_log_output_opts(
    path: &Path,
    since: Option<&str>,
    until: Option<&str>,
    tail: Option<usize>,
    timestamps: bool,
) -> Result<String> {
    if is_k8s_log_path(path) || path.to_string_lossy().contains("-ctr.log") {
        let entries = filter_k8s_entries_opts(read_k8s_log_entries(path)?, since, until);
        if timestamps {
            let lines = tail_log_lines_with_ts(
                expand_embedded_newlines_ts(reconstruct_k8s_lines_with_ts(&entries)),
                tail,
            );
            return Ok(format_log_lines_timestamped(&lines));
        }
        let mut lines = expand_embedded_newlines(reconstruct_k8s_lines(&entries));
        lines = tail_log_lines(lines, tail);
        return Ok(format_log_lines(&lines));
    }
    let content = fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<&str> = content
        .lines()
        .filter(|l| l.trim() != "Terminated")
        .filter(|l| !looks_like_k8s_record_start(l.as_bytes()))
        .filter(|l| {
            !l.contains(" stdout F ") && !l.contains(" stderr F ") && !l.contains(" stdout P ")
        })
        .collect();
    if let Some(t) = tail {
        if t == 0 {
            lines.clear();
        } else if lines.len() > t {
            lines = lines[lines.len() - t..].to_vec();
        }
    }
    Ok(lines.join("\n"))
}

/// After SIGTERM/stop, conmon may still be flushing trap handlers into the k8s log file.
pub fn wait_k8s_log_quiescent(bundle_path: &Path) {
    let Some(name) = bundle_path.file_name().and_then(|s| s.to_str()) else {
        return;
    };
    let path = bundle_path.join(format!("{name}-ctr.log"));
    if !path.exists() {
        return;
    }
    let start = Instant::now();
    let mut last_len = 0u64;
    let mut stable = 0u32;
    while start.elapsed() < Duration::from_millis(2500) {
        let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if len == last_len {
            stable += 1;
            if stable >= 4 {
                break;
            }
        } else {
            stable = 0;
            last_len = len;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn stream_k8s_container_logs(
    path: &Path,
    since: Option<&str>,
    until: Option<&str>,
    tail: Option<usize>,
    follow: bool,
    timestamps: bool,
    mut is_running: impl FnMut() -> bool,
) -> Result<()> {
    let print_lines = |lines: &[Vec<u8>]| -> Result<()> {
        if lines.is_empty() {
            return Ok(());
        }
        write_log_text_opts(&format_log_lines(lines), timestamps, true)
    };

    if !follow {
        if is_k8s_log_path(path) {
            let entries = filter_k8s_entries_opts(read_k8s_log_entries(path)?, since, until);
            if entries.iter().any(|e| e.is_stderr || e.stream == "stderr")
                && since.is_none()
                && until.is_none()
                && tail.is_none()
                && !timestamps
            {
                let mut out_entries = Vec::new();
                let mut err_entries = Vec::new();
                for e in entries {
                    if e.is_stderr || e.stream == "stderr" {
                        err_entries.push(e);
                    } else {
                        out_entries.push(e);
                    }
                }
                let out_lines = expand_embedded_newlines(reconstruct_k8s_lines(&out_entries));
                let err_lines = expand_embedded_newlines(reconstruct_k8s_lines(&err_entries));
                if !out_lines.is_empty() {
                    write_log_text_opts(&format_log_lines(&out_lines), false, true)?;
                }
                if !err_lines.is_empty() {
                    let err_text = format_log_lines(&err_lines);
                    let mut stderr = std::io::stderr();
                    stderr.write_all(err_text.as_bytes())?;
                    if !err_text.ends_with('\n') {
                        stderr.write_all(b"\n")?;
                    }
                    stderr.flush()?;
                }
                return Ok(());
            }
        }
        let text = read_log_output_opts(path, since, until, tail, timestamps)?;
        return write_log_text_opts(&text, false, false);
    }

    let follow_started = Instant::now();
    let since_cutoff = since.and_then(|s| parse_logs_time_filter(s).ok());
    let until_cutoff = until.and_then(|u| {
        if parse_follow_until_timeout(u).is_some() {
            None
        } else {
            parse_logs_time_filter(u).ok()
        }
    });
    let timeout_deadline = std::env::var("PODMAN_TIMEOUT")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .map(|secs| follow_started + Duration::from_secs_f64(secs));
    let follow_timeout = until.and_then(parse_follow_until_timeout);
    let initial_entry_count = read_k8s_log_entries(path).map(|e| e.len()).unwrap_or(0);

    let mut printed_lines = 0usize;
    let mut printed_since_lines = 0usize;

    loop {
        if let Some(limit) = follow_timeout {
            if follow_started.elapsed() >= limit {
                break;
            }
        }
        if let Some(deadline) = timeout_deadline {
            if Instant::now() >= deadline {
                eprintln!("timeout: sending signal TERM to command 'podman logs'");
                std::process::exit(124);
            }
        }

        let running = is_running();
        if !running {
            std::thread::sleep(Duration::from_millis(50));
        }
        let entries = filter_k8s_entries(read_k8s_log_entries(path)?, since_cutoff, until_cutoff);
        if since.is_some() {
            let new_entries: Vec<K8sLogEntry> =
                entries.into_iter().skip(initial_entry_count).collect();
            let new_lines = tail_log_lines(
                expand_embedded_newlines(reconstruct_k8s_lines_opts(&new_entries, !running)),
                tail,
            );
            if printed_since_lines < new_lines.len() {
                print_lines(&new_lines[printed_since_lines..])?;
                printed_since_lines = new_lines.len();
            }
        } else {
            let lines = tail_log_lines(
                expand_embedded_newlines(reconstruct_k8s_lines_opts(&entries, !running)),
                tail,
            );
            if printed_lines < lines.len() {
                print_lines(&lines[printed_lines..])?;
                printed_lines = lines.len();
            }
        }

        if !running {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_reconstruct_partial_k8s_lines() {
        let mut f = NamedTempFile::new().unwrap();
        let ts = "2026-10-28T16:03:41.284873688+00:00";
        write!(
            f,
            "{ts} stdout F podman1\r\n{ts} stdout P podman2\n{ts} stdout F \r\n{ts} stdout F podman3\r\n"
        )
        .unwrap();
        let entries = read_k8s_log_entries(f.path()).unwrap();
        let lines = reconstruct_k8s_lines(&entries);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], b"podman1\r");
        assert_eq!(lines[1], b"podman2\r");
        assert_eq!(lines[2], b"podman3\r");
        let t2 = tail_log_lines(lines, Some(2));
        assert_eq!(format_log_lines(&t2), "podman2\r\npodman3\r");
    }

    #[test]
    fn test_reconstruct_boxr_timestamp_partial() {
        let ts = "2026-10-28T16:30:20.802135813+00:00";
        let content = format!(
            "{ts} stdout F podman1\r\n{ts} stdout P podman2\n{ts} stdout F \r\n{ts} stdout F podman3\r\n"
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-ctr.log");
        std::fs::write(&path, content).unwrap();
        let out = read_log_output(&path, None, None, Some(2)).unwrap();
        assert_eq!(out, "podman2\r\npodman3\r");
    }

    #[test]
    fn test_parse_logs_relative_since() {
        let dt = parse_logs_time_filter("-1s").unwrap();
        assert!(dt < Utc::now());
    }
}
