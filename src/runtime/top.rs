use anyhow::Result;
#[cfg(target_os = "linux")]
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
struct ContainerProc {
    pid: u32,
    hpid: u32,
    ppid: u32,
    user: String,
    huser: String,
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
        let descriptors = parse_descriptors(ps_args);
        let procs = collect_procs(bundle_path);

        let headers: Vec<String> = descriptors.iter().map(|d| descriptor_header(d)).collect();
        let rows: Vec<Vec<String>> = procs
            .iter()
            .map(|p| descriptors.iter().map(|d| descriptor_value(p, d)).collect())
            .collect();

        let output = format_table(&headers, &rows);
        println!("{}", output);
        Ok(output)
    }
}

fn parse_descriptors(ps_args: &[String]) -> Vec<String> {
    let mut descriptors = Vec::new();
    let mut skip_next = false;

    for (i, arg) in ps_args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        let a = arg.trim();
        if a == "-eo" || a == "-o" {
            if let Some(next) = ps_args.get(i + 1) {
                append_descriptor_tokens(&mut descriptors, next);
                skip_next = true;
            }
        } else if let Some(rest) = a.strip_prefix("-eo") {
            append_descriptor_tokens(&mut descriptors, rest);
        } else if let Some(rest) = a.strip_prefix("-o") {
            append_descriptor_tokens(&mut descriptors, rest);
        } else if !a.starts_with('-') {
            append_descriptor_tokens(&mut descriptors, a);
        }
    }

    if descriptors.is_empty() {
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
    }
}

fn append_descriptor_tokens(descriptors: &mut Vec<String>, text: &str) {
    for part in text.split(|c: char| c == ',' || c.is_whitespace()) {
        let p = part.trim();
        if !p.is_empty() {
            descriptors.push(p.to_ascii_lowercase());
        }
    }
}

fn descriptor_header(desc: &str) -> String {
    match desc {
        "pid" => "PID".to_string(),
        "ppid" => "PPID".to_string(),
        "user" => "USER".to_string(),
        "group" => "GROUP".to_string(),
        "%cpu" | "cpu" => "%CPU".to_string(),
        "%mem" | "pmem" => "%MEM".to_string(),
        "elapsed" | "etime" => "ELAPSED".to_string(),
        "tty" => "TTY".to_string(),
        "time" => "TIME".to_string(),
        "comm" | "command" | "args" => "COMMAND".to_string(),
        other => other.to_ascii_uppercase(),
    }
}

fn descriptor_value(p: &ContainerProc, desc: &str) -> String {
    match desc {
        "pid" => p.pid.to_string(),
        "hpid" => p.hpid.to_string(),
        "ppid" => p.ppid.to_string(),
        "user" => p.user.clone(),
        "huser" => p.huser.clone(),
        "%cpu" | "cpu" => p.cpu.clone(),
        "elapsed" | "etime" => p.elapsed.clone(),
        "tty" => p.tty.clone(),
        "time" => p.time.clone(),
        "comm" => p.comm.clone(),
        "command" | "args" => p.command.clone(),
        _ => "-".to_string(),
    }
}

fn format_table(headers: &[String], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, val) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(val.len());
            }
        }
    }

    let mut out = String::new();
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
    for row in rows {
        out.push('\n');
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
    while std::time::Instant::now() < deadline {
        if let Ok(pid_str) = fs::read_to_string(bundle_path.join("container.pid")) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                if pid > 1 && unsafe { libc::kill(pid, 0) == 0 } {
                    return Some(pid);
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    None
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
        let user = map_uid_to_user(*host_uid, &uid_map);
        procs.push(ContainerProc {
            pid: *nspid,
            hpid: *host_pid as u32,
            ppid,
            user,
            huser: host_uid.to_string(),
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
fn map_uid_to_user(host_uid: u32, uid_map: &[(u32, u32, u32)]) -> String {
    for (cid, hid, cnt) in uid_map {
        if host_uid >= *hid && host_uid < hid.saturating_add(*cnt) {
            let container_uid = cid + (host_uid - hid);
            if container_uid == 0 {
                return "root".to_string();
            }
            return container_uid.to_string();
        }
    }
    if host_uid == 0 {
        "root".to_string()
    } else {
        host_uid.to_string()
    }
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
        user: "root".to_string(),
        huser: "0".to_string(),
        comm: "top".to_string(),
        command: "top".to_string(),
        cpu: "0.000".to_string(),
        elapsed: "0s".to_string(),
        tty: "?".to_string(),
        time: "00:00".to_string(),
    }]
}
