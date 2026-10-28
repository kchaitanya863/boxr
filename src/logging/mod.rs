use anyhow::Result;
use chrono::Local;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

pub fn is_file_log_driver(driver: Option<&str>) -> bool {
    matches!(driver, Some("k8s-file") | Some("json-file"))
}

pub fn append_k8s_log_chunk(path: &Path, stream: &str, data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let ts = Local::now().format("%Y-%m-%dT%H:%M:%S%.9f%:z").to_string();
    file.write_all(format!("{} {} F ", ts, stream).as_bytes())?;
    file.write_all(data)?;
    if !data.ends_with(b"\n") {
        file.write_all(b"\n")?;
    }
    Ok(())
}

pub fn tee_k8s_stream<R: Read>(
    mut reader: R,
    log_path: std::path::PathBuf,
    stream: &'static str,
    attach: bool,
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
    while let Ok(n) = reader.read(&mut buf) {
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        let _ = append_k8s_log_chunk(&log_path, stream, chunk);
        let _ = attach_out.write_all(chunk);
        let _ = attach_out.flush();
    }
}

/// Extract user-visible log payload from k8s-file / CRI log lines.
pub fn decode_k8s_log_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let mut out = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Some(payload) = k8s_log_line_payload(line) {
            out.extend_from_slice(payload);
            if !payload.ends_with(b"\n") {
                out.push(b'\n');
            }
        }
    }
    while out.last() == Some(&b'\n') {
        out.pop();
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

fn k8s_log_line_payload(line: &[u8]) -> Option<&[u8]> {
    for marker in [b" stdout F ", b" stderr F "] {
        if let Some(pos) = line.windows(marker.len()).position(|w| w == marker) {
            return Some(&line[pos + marker.len()..]);
        }
    }
    None
}
