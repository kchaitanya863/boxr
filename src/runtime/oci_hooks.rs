//! OCI hooks from Podman `--hooks-dir` (settings.json).

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn hook_settings_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

pub fn run_hooks_from_bundle(bundle_path: &Path, stage: &str) -> Result<()> {
    let hooks_file = bundle_path.join("hooks_dir");
    if !hooks_file.exists() {
        return Ok(());
    }
    let dir = PathBuf::from(fs_read_trim(&hooks_file)?);
    run_hooks_dir(&dir, stage)
}

pub fn run_hooks_dir(dir: &Path, stage: &str) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for json_path in hook_settings_files(dir) {
        run_settings_json(&json_path, stage)?;
    }
    Ok(())
}

fn run_settings_json(path: &Path, stage: &str) -> Result<()> {
    let content = std::fs::read_to_string(path)?;
    let v: serde_json::Value = serde_json::from_str(&content)?;
    let stages = v
        .get("stages")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !stages.iter().any(|s| *s == stage) {
        return Ok(());
    }
    let hook_path = v
        .get("hook")
        .and_then(|h| h.get("path"))
        .and_then(|p| p.as_str())
        .context("hook.path missing in hooks settings")?;
    let mut child = Command::new(hook_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn hook {}", hook_path))?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(b"{}");
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow::anyhow!(
            "hook {} exited with {}",
            hook_path,
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

fn fs_read_trim(path: &Path) -> Result<String> {
    Ok(std::fs::read_to_string(path)?.trim().to_string())
}
