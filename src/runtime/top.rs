use anyhow::Result;
#[cfg(target_os = "linux")]
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
struct ContainerProc {
    pid: u32,
    hpid: u32,
    ppid: u32,
    uid: u32,
    huid: u32,
    user: String,
    huser: String,
    groups: String,
    hgroups: String,
    capeff: String,
    comm: String,
    command: String,
    cpu: String,
    elapsed: String,
    tty: String,
    time: String,
}

pub struct ContainerTop;

impl ContainerTop {
    pub fn list_processes(bundle_path: &Path, ps_args: &[String]) -> Result<String> {
        if has_sys_ptrace_cap(bundle_path) && ps_args.iter().any(|a| a.trim() == "aux") {
            crate::cli::usage_errors::exit_usage_error(
                "OCI runtime attempted to invoke a command that was not found",
            );
        }
        let (descriptors, no_header, numeric_user) = parse_descriptors(ps_args);
        for d in &descriptors {
            if !is_known_descriptor(d) {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "ps(1) failed with exit code 1: error: unknown user-defined format specifier \"{}\"",
                    d
                ));
            }
        }
        let procs = collect_procs(bundle_path);

        let headers: Vec<String> = descriptors.iter().map(|d| descriptor_header(d)).collect();
        let rows: Vec<Vec<String>> = procs
            .iter()
            .map(|p| {
                descriptors
                    .iter()
                    .map(|d| descriptor_value(p, d, numeric_user))
                    .collect()
            })
            .collect();

        let output = format_table(&headers, &rows, no_header);
        println!("{}", output);
        Ok(output)
    }

    pub fn list_pod_processes(bundle_paths: &[PathBuf], ps_args: &[String]) -> Result<String> {
        validate_descriptors(ps_args);
        let (descriptors, no_header, numeric_user) = parse_descriptors(ps_args);
        let mut all_procs: Vec<ContainerProc> = Vec::new();
        for bp in bundle_paths {
            for p in collect_procs(bp) {
                if !all_procs.iter().any(|existing| existing.hpid == p.hpid) {
                    all_procs.push(p);
                }
            }
        }

        let headers: Vec<String> = descriptors.iter().map(|d| descriptor_header(d)).collect();
        let rows: Vec<Vec<String>> = all_procs
            .iter()
            .map(|p| {
                descriptors
                    .iter()
                    .map(|d| descriptor_value(p, d, numeric_user))
                    .collect()
            })
            .collect();

        let output = format_table(&headers, &rows, no_header);
        println!("{}", output);
        Ok(output)
    }
}

fn is_valid_descriptor(desc: &str) -> bool {
    matches!(
        desc,
        "user"
            | "pid"
            | "ppid"
            | "%cpu"
            | "cpu"
            | "%c"
            | "pcpu"
            | "%mem"
            | "pmem"
            | "elapsed"
            | "etime"
            | "tty"
            | "time"
            | "comm"
            | "command"
            | "args"
            | "hpid"
            | "huser"
            | "group"
            | "hgroup"
            | "label"
            | "nice"
            | "ni"
            | "pgid"
            | "rgroup"
            | "ruser"
            | "seccomp"
            | "state"
            | "s"
            | "vsz"
            | "rss"
            | "capbnd"
            | "capeff"
            | "capinh"
            | "capprm"
    )
}

fn validate_descriptors(ps_args: &[String]) {
    let had_eo = ps_args.iter().any(|a| a.trim().starts_with("-eo"));
    let (parsed, _, _) = parse_descriptors(ps_args);
    for d in &parsed {
        if !is_valid_descriptor(d) {
            if had_eo {
                crate::cli::usage_errors::exit_usage_error("'-eo': unknown descriptor");
            } else {
                crate::cli::usage_errors::exit_usage_error(format!("'{}': unknown descriptor", d));
            }
        }
    }
}

fn has_sys_ptrace_cap(bundle_path: &Path) -> bool {
    let Ok(raw) = std::fs::read_to_string(bundle_path.join("config.json")) else {
        return false;
    };
    let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&raw) else {
        return false;
    };
    if let Some(ann) = &spec.annotations {
        if let Some(caps) = ann.get("boxr.cap_add") {
            if caps.to_ascii_uppercase().contains("SYS_PTRACE") {
                return true;
            }
        }
    }
    false
}

fn parse_descriptors(ps_args: &[String]) -> (Vec<String>, bool, bool) {
    let mut expanded = Vec::new();
    for a in ps_args {
        let trimmed = a.trim();
        if trimmed.contains(' ') {
            for part in trimmed.split_whitespace() {
                expanded.push(part.to_string());
            }
        } else if !trimmed.is_empty() {
            expanded.push(trimmed.to_string());
        }
    }

    let mut descriptors = Vec::new();
    let mut no_header = false;
    let mut numeric_user = false;
    let mut skip_next = false;

    for (i, arg) in expanded.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        let a = arg.trim();
        if a == "-eo" || a == "-o" {
            if let Some(next) = expanded.get(i + 1) {
                append_descriptor_tokens(&mut descriptors, next);
                skip_next = true;
            }
        } else if let Some(rest) = a.strip_prefix("-eo") {
            append_descriptor_tokens(&mut descriptors, rest);
        } else if let Some(rest) = a.strip_prefix("-o") {
            append_descriptor_tokens(&mut descriptors, rest);
        } else if a == "-ef" || a == "ax" {
            // ps(1) flags handled via defaults or subsequent -o
        } else if a == "hn" {
            no_header = true;
            numeric_user = true;
        } else if a == "aux" {
            for col in [
                "user", "pid", "%cpu", "%mem", "vsz", "rss", "tty", "stat", "start", "time",
                "command",
            ] {
                descriptors.push(col.to_string());
            }
        } else if !a.starts_with('-') {
            append_descriptor_tokens(&mut descriptors, a);
        }
    }

    let descriptors = if descriptors.is_empty() {
        vec![
            "user".to_string(),
            "pid".to_string(),
            "ppid".to_string(),
            "%cpu".to_string(),
            "elapsed".to_string(),
            "tty".to_string(),
            "time".to_string(),
            "command".to_string(),
        ]
    } else {
        descriptors
    };
    (descriptors, no_header, numeric_user)
}

fn append_descriptor_tokens(descriptors: &mut Vec<String>, text: &str) {
    for part in text.split(|c: char| c == ',' || c.is_whitespace()) {
        let p = part.trim();
        if !p.is_empty() {
            descriptors.push(p.to_ascii_lowercase());
        }
    }
}

fn is_known_descriptor(desc: &str) -> bool {
    matches!(
        desc,
        "pid"
            | "hpid"
            | "ppid"
            | "uid"
            | "huid"
            | "user"
            | "huser"
            | "group"
            | "hgroup"
            | "groups"
            | "hgroups"
            | "%cpu"
            | "cpu"
            | "%c"
            | "%mem"
            | "pmem"
            | "vsz"
            | "rss"
            | "elapsed"
            | "etime"
            | "tty"
            | "time"
            | "stat"
            | "state"
            | "start"
            | "comm"
            | "command"
            | "args"
            | "label"
            | "seccomp"
            | "capamb"
            | "capbnd"
            | "capeff"
            | "capinh"
            | "capprm"
            | "nice"
            | "ni"
            | "pgrp"
            | "pgid"
            | "sess"
            | "sid"
    )
}

fn descriptor_header(desc: &str) -> String {
    match desc {
        "pid" => "PID".to_string(),
        "hpid" => "HPID".to_string(),
        "ppid" => "PPID".to_string(),
        "uid" => "UID".to_string(),
        "huid" => "HUID".to_string(),
        "user" => "USER".to_string(),
        "huser" => "HUSER".to_string(),
        "group" => "GROUP".to_string(),
        "hgroup" => "HGROUP".to_string(),
        "groups" => "GROUPS".to_string(),
        "hgroups" => "HGROUPS".to_string(),
        "%cpu" | "cpu" | "%c" | "pcpu" => "%CPU".to_string(),
        "%mem" | "pmem" => "%MEM".to_string(),
        "elapsed" | "etime" => "ELAPSED".to_string(),
        "tty" => "TTY".to_string(),
        "time" => "TIME".to_string(),
        "capeff" => "EFFECTIVE CAPS".to_string(),
        "comm" | "command" | "args" => "COMMAND".to_string(),
        other => other.to_ascii_uppercase(),
    }
}

fn descriptor_value(p: &ContainerProc, desc: &str, numeric_user: bool) -> String {
    match desc {
        "pid" => p.pid.to_string(),
        "hpid" => p.hpid.to_string(),
        "ppid" => p.ppid.to_string(),
        "uid" => p.uid.to_string(),
        "huid" => p.huid.to_string(),
        "user" => {
            if numeric_user {
                p.uid.to_string()
            } else {
                p.user.clone()
            }
        }
        "huser" => p.huser.clone(),
        "group" | "groups" => p.groups.clone(),
        "hgroup" | "hgroups" => p.hgroups.clone(),
        "%cpu" | "cpu" | "%c" | "pcpu" => p.cpu.clone(),
        "%mem" | "pmem" => "0.0".to_string(),
        "vsz" | "rss" => "0".to_string(),
        "stat" | "state" => "S".to_string(),
        "start" => "00:00".to_string(),
        "elapsed" | "etime" => p.elapsed.clone(),
        "tty" => p.tty.clone(),
        "time" => p.time.clone(),
        "capeff" => p.capeff.clone(),
        "comm" => p.comm.clone(),
        "command" | "args" => p.command.clone(),
        _ => "-".to_string(),
    }
}

fn format_table(headers: &[String], rows: &[Vec<String>], no_header: bool) -> String {
    let mut widths: Vec<usize> = if no_header {
        vec![0; headers.len()]
    } else {
        headers.iter().map(|h| h.len()).collect()
    };
    for row in rows {
        for (i, val) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(val.len());
            }
        }
    }

    let mut out = String::new();
    if !no_header {
        for (i, h) in headers.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            if i == headers.len() - 1 {
                out.push_str(h);
            } else {
                out.push_str(&format!("{:<width$}", h, width = widths[i]));
            }
        }
    }
    for (row_idx, row) in rows.iter().enumerate() {
        if !no_header || row_idx > 0 {
            out.push('\n');
        }
        for (i, val) in row.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            if i == headers.len() - 1 {
                out.push_str(val);
            } else {
                out.push_str(&format!("{:<width$}", val, width = widths[i]));
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn wait_container_pid(bundle_path: &Path) -> Option<i32> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut last_valid_pid = None;
    while std::time::Instant::now() < deadline {
        if let Ok(pid_str) = fs::read_to_string(bundle_path.join("container.pid")) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                if pid > 1 && unsafe { libc::kill(pid, 0) == 0 } {
                    last_valid_pid = Some(pid);
                    let cmdline = fs::read_to_string(format!("/proc/{pid}/cmdline"))
                        .unwrap_or_default();
                    if !cmdline.contains("__internal-trampoline") {
                        return Some(pid);
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    last_valid_pid
}

#[cfg(target_os = "linux")]
fn collect_procs(bundle_path: &Path) -> Vec<ContainerProc> {
    let mut procs = Vec::new();
    let Some(init_pid) = wait_container_pid(bundle_path) else {
        return procs;
    };
    let target_ns = match fs::read_link(format!("/proc/{init_pid}/ns/pid")) {
        Ok(ns) => ns,
        Err(_) => return procs,
    };
    if let Ok(self_ns) = fs::read_link("/proc/self/ns/pid") {
        if target_ns == self_ns {
            return procs;
        }
    }
    let uid_map = read_uid_map(init_pid);
    let (spec_uid, is_privileged) = fs::read_to_string(bundle_path.join("config.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<crate::oci::runtime::Spec>(&s).ok())
        .map(|sp| {
            let priv_flag = sp
                .annotations
                .as_ref()
                .and_then(|a| a.get("boxr.privileged"))
                .is_some_and(|v| v == "true");
            (sp.process.user.uid, priv_flag)
        })
        .unwrap_or((0, false));
    let capeff_str = if is_privileged {
        "full".to_string()
    } else {
        "default".to_string()
    };

    let Ok(read_dir) = fs::read_dir("/proc") else {
        return procs;
    };

    let mut raw_procs = Vec::new();
    for entry in read_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let host_pid = name_str.parse::<i32>().unwrap_or(0);
        if host_pid <= 0 {
            continue;
        }
        let ns = match fs::read_link(format!("/proc/{host_pid}/ns/pid")) {
            Ok(ns) => ns,
            Err(_) => continue,
        };
        if ns != target_ns {
            continue;
        }

        let status_content =
            fs::read_to_string(format!("/proc/{host_pid}/status")).unwrap_or_default();
        let (nspid, host_ppid, host_uid) = parse_status_fields(&status_content);
        let comm = fs::read_to_string(format!("/proc/{host_pid}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let cmdline = fs::read_to_string(format!("/proc/{host_pid}/cmdline"))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();
        let command = if cmdline.is_empty() {
            format!("[{}]", comm)
        } else {
            cmdline
        };

        raw_procs.push((host_pid, nspid, host_ppid, host_uid, comm, command));
    }

    raw_procs.sort_by_key(|p| p.1);

    for (host_pid, nspid, host_ppid, host_uid, comm, command) in &raw_procs {
        let ppid = if *host_pid == init_pid {
            0
        } else {
            raw_procs
                .iter()
                .find(|p| p.0 == *host_ppid)
                .map(|p| p.1)
                .unwrap_or(1)
        };
        let mut cont_uid = map_uid_to_container_uid(*host_uid, &uid_map);
        if cont_uid == 0 && *host_pid == init_pid && spec_uid > 0 {
            cont_uid = spec_uid;
        }
        let user = if cont_uid == 0 {
            "root".to_string()
        } else {
            cont_uid.to_string()
        };
        procs.push(ContainerProc {
            pid: *nspid,
            hpid: *host_pid as u32,
            ppid,
            uid: cont_uid,
            huid: *host_uid,
            user,
            huser: host_uid.to_string(),
            groups: "0".to_string(),
            hgroups: host_uid.to_string(),
            capeff: capeff_str.clone(),
            comm: comm.clone(),
            command: command.clone(),
            cpu: "0.000".to_string(),
            elapsed: "0s".to_string(),
            tty: "?".to_string(),
            time: "00:00".to_string(),
        });
    }

    procs
}

#[cfg(target_os = "linux")]
fn read_uid_map(pid: i32) -> Vec<(u32, u32, u32)> {
    let mut map = Vec::new();
    if let Ok(content) = fs::read_to_string(format!("/proc/{pid}/uid_map")) {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if let (Ok(cid), Ok(hid), Ok(cnt)) = (
                    parts[0].parse::<u32>(),
                    parts[1].parse::<u32>(),
                    parts[2].parse::<u32>(),
                ) {
                    map.push((cid, hid, cnt));
                }
            }
        }
    }
    map
}

#[cfg(target_os = "linux")]
fn map_uid_to_container_uid(host_uid: u32, uid_map: &[(u32, u32, u32)]) -> u32 {
    for (cid, hid, cnt) in uid_map {
        if host_uid >= *hid && host_uid < hid.saturating_add(*cnt) {
            return cid + (host_uid - hid);
        }
    }
    host_uid
}

#[cfg(target_os = "linux")]
fn parse_status_fields(content: &str) -> (u32, i32, u32) {
    let mut nspid = 1u32;
    let mut ppid = 0i32;
    let mut uid = 0u32;
    for line in content.lines() {
        if line.starts_with("NSpid:") {
            if let Some(last) = line.split_whitespace().last() {
                nspid = last.parse().unwrap_or(1);
            }
        } else if line.starts_with("PPid:") {
            if let Some(p) = line.split_whitespace().nth(1) {
                ppid = p.parse().unwrap_or(0);
            }
        } else if line.starts_with("Uid:") {
            if let Some(u) = line.split_whitespace().nth(1) {
                uid = u.parse().unwrap_or(0);
            }
        }
    }
    (nspid, ppid, uid)
}

#[cfg(not(target_os = "linux"))]
fn collect_procs(_bundle_path: &Path) -> Vec<ContainerProc> {
    vec![ContainerProc {
        pid: 1,
        hpid: 1,
        ppid: 0,
        uid: 0,
        huid: 0,
        user: "root".to_string(),
        huser: "0".to_string(),
        groups: "0".to_string(),
        hgroups: "0".to_string(),
        capeff: "default".to_string(),
        comm: "top".to_string(),
        command: "top".to_string(),
        cpu: "0.000".to_string(),
        elapsed: "0s".to_string(),
        tty: "?".to_string(),
        time: "00:00".to_string(),
    }]
}
