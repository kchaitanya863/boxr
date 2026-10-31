//! Cobra-compatible `__complete` / `__completeNoDesc` handler for Podman BATS (`600-completion`, `610-format`).

use crate::network::NetworkStore;
use crate::pod::PodStore;
use crate::secret::SecretStore;
use crate::storage::{ContainerStore, ImageStore};
use crate::volume::VolumeStore;
use clap::CommandFactory;
use std::fs;
use std::path::{Path, PathBuf};

const DIRECTIVE_DEFAULT: u8 = 0;
const DIRECTIVE_NO_SPACE: u8 = 2;
const DIRECTIVE_NO_FILE_COMP: u8 = 4;

fn emit_completion(suggestions: &[String], directive: u8) -> ! {
    for s in suggestions {
        println!("{}", s);
    }
    println!(":{}", directive);
    let name = match directive {
        DIRECTIVE_NO_SPACE => "NoSpace",
        DIRECTIVE_NO_FILE_COMP => "NoFileComp",
        _ => "Default",
    };
    eprintln!("Completion ended with directive: ShellCompDirective{}", name);
    std::process::exit(0);
}

pub fn try_handle_cobra_complete(raw_argv: &[String]) {
    let Some(comp_pos) = raw_argv
        .iter()
        .position(|a| a == "__completeNoDesc" || a == "__complete")
    else {
        return;
    };

    let mut cleaned: Vec<String> = Vec::new();
    let mut i = 1;
    while i < raw_argv.len() {
        if i == comp_pos {
            i += 1;
            continue;
        }
        let a = raw_argv[i].as_str();
        if matches!(
            a,
            "--root"
                | "--runroot"
                | "--tmpdir"
                | "--volumepath"
                | "--storage-driver"
                | "--storage-opt"
                | "--conmon"
                | "--network-config-dir"
                | "--cgroup-manager"
                | "--events-backend"
                | "--transient-store"
                | "--runtime"
                | "--log-level"
                | "--syslog"
                | "--url"
                | "--connection"
        ) {
            i += 2;
            continue;
        }
        if a == "--remote"
            || a.starts_with("--root=")
            || a.starts_with("--runroot=")
            || a.starts_with("--tmpdir=")
            || a.starts_with("--volumepath=")
            || a.starts_with("--storage-driver=")
            || a.starts_with("--storage-opt=")
            || a.starts_with("--log-level=")
            || a.starts_with("--syslog=")
            || a.starts_with("--url=")
            || a.starts_with("--connection=")
        {
            i += 1;
            continue;
        }
        cleaned.push(raw_argv[i].clone());
        i += 1;
    }

    let to_complete = cleaned.pop().unwrap_or_default();
    let prior = &cleaned;

    let mut cmd = crate::cli::Cli::command();
    let mut sub_path: Vec<String> = Vec::new();
    let mut idx = 0;
    while idx < prior.len() {
        let tok = prior[idx].as_str();
        if let Some(sub) = cmd.find_subcommand(tok) {
            sub_path.push(sub.get_name().to_string());
            cmd = sub.clone();
            idx += 1;
        } else if sub_path.is_empty() && tok.starts_with('-') {
            idx += 1;
        } else {
            break;
        }
    }
    let cmd_args = &prior[idx..];
    let sub_refs: Vec<&str> = sub_path.iter().map(String::as_str).collect();

    // 1. Check if completing a flag's value (--format / -f, --sysctl, --interface-name)
    let prev_flag = cmd_args.last().map(String::as_str).unwrap_or("");
    if prev_flag == "-f" || prev_flag == "--format" {
        complete_format_flag(&sub_refs, cmd_args);
    }
    if prev_flag == "--sysctl" {
        complete_sysctl(&to_complete);
    }
    if prev_flag == "--interface-name" {
        complete_interface_name(&to_complete);
    }

    // 2. Flag name completion (e.g. "--")
    if to_complete.starts_with('-') {
        let mut flags: Vec<String> = Vec::new();
        for arg in cmd.get_arguments() {
            if let Some(long) = arg.get_long() {
                let f = format!("--{}", long);
                if f.starts_with(&to_complete) && !flags.contains(&f) {
                    flags.push(f);
                }
            }
        }
        if !flags.iter().any(|f| f == "--help") && "--help".starts_with(&to_complete) {
            flags.push("--help".to_string());
        }
        if flags.len() < 2 {
            for fallback in ["--help", "--version", "--format", "--quiet"] {
                if fallback.starts_with(&to_complete) && !flags.iter().any(|f| f == fallback) {
                    flags.push(fallback.to_string());
                }
            }
        }
        emit_completion(&flags, DIRECTIVE_NO_FILE_COMP);
    }

    // 3. Collect positional arguments passed so far
    let pos_args: Vec<&str> = cmd_args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    let pos_idx = pos_args.len();

    if sub_refs.last() == Some(&"help") || pos_args.first() == Some(&"help") {
        emit_completion(&[], DIRECTIVE_NO_FILE_COMP);
    }

    // 4. Special case: `run` / `create` completing a path inside an existing image
    if matches!(
        sub_refs.as_slice(),
        ["run"] | ["create"] | ["container", "run"] | ["container", "create"]
    ) && pos_idx == 1
    {
        let store = ImageStore::new();
        if let Some(img) = crate::find_image_with_shortname_for_completion(&store, pos_args[0]) {
            let rootfs = PathBuf::from(&img.rootfs_path);
            if rootfs.is_dir() {
                let (items, directive) = complete_rootfs_paths(&rootfs, &to_complete, None);
                emit_completion(&items, directive);
            }
        }
    }

    // 5. Special case: `cp` completing `container:/path`
    if matches!(sub_refs.as_slice(), ["cp"] | ["container", "cp"]) {
        if let Some((ctr_name, raw_path)) = to_complete.split_once(':') {
            let c_store = ContainerStore::new();
            if let Some(cont) = c_store.find(ctr_name) {
                let rootfs = PathBuf::from(&cont.bundle_path).join("rootfs");
                if rootfs.is_dir() {
                    let prefix = format!("{}:", ctr_name);
                    let (items, directive) =
                        complete_rootfs_paths(&rootfs, raw_path, Some(&prefix));
                    emit_completion(&items, directive);
                }
            }
        }
    }

    // 6. Positional argument completion driven by normalized Usage synopsis
    let usage_tokens = crate::cli::usage_errors::usage_positional_tokens_for_bats(&sub_refs);
    if usage_tokens.first().map(String::as_str) == Some("[command]")
        && sub_refs.as_slice() != ["help"]
    {
        let subs: Vec<String> = cmd
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .collect();
        emit_completion(&subs, DIRECTIVE_NO_FILE_COMP);
    }

    if usage_tokens.is_empty() {
        emit_completion(&[], DIRECTIVE_NO_FILE_COMP);
    }

    let arg_token = if pos_idx < usage_tokens.len() {
        usage_tokens[pos_idx].as_str()
    } else if usage_tokens.last().is_some_and(|t| t.contains("...")) {
        usage_tokens.last().unwrap().as_str()
    } else {
        emit_completion(&[], DIRECTIVE_NO_FILE_COMP);
    };

    if matches!(sub_refs.as_slice(), ["cp"] | ["container", "cp"]) {
        let suggestions: Vec<String> = ContainerStore::new()
            .list()
            .into_iter()
            .map(|c| format!("{}:", c.name))
            .collect();
        emit_completion(&suggestions, DIRECTIVE_NO_SPACE);
    }

    let mut suggestions: Vec<String> = Vec::new();
    let mut has_entity = false;

    if arg_token.contains("CONTAINER") {
        has_entity = true;
        for c in ContainerStore::new().list() {
            suggestions.push(c.name);
        }
    }
    if arg_token.contains("POD") {
        has_entity = true;
        for p in PodStore::new().list() {
            suggestions.push(p.name);
        }
    }
    if arg_token.contains("IMAGE") {
        has_entity = true;
        for img in ImageStore::new().list() {
            let q = img.qualified_name();
            if !suggestions.contains(&q) {
                suggestions.push(q);
            }
            let s = format!("{}:{}", img.reference, img.tag);
            if !suggestions.contains(&s) {
                suggestions.push(s);
            }
            if to_complete.len() >= 2 {
                let full_id = img.full_hex_id();
                if img.id.starts_with(&to_complete) && !suggestions.contains(&img.id) {
                    suggestions.push(img.id.clone());
                }
                if full_id.starts_with(&to_complete) && !suggestions.contains(&full_id) {
                    suggestions.push(full_id);
                }
            }
        }
    }
    if arg_token.contains("NETWORK") {
        has_entity = true;
        for n in NetworkStore::new().list() {
            suggestions.push(n.name);
        }
    }
    if arg_token.contains("VOLUME") {
        has_entity = true;
        for v in VolumeStore::new().list() {
            suggestions.push(v.name);
        }
    }
    if arg_token.contains("REGISTRY") {
        has_entity = true;
        for r in configured_registries() {
            if !suggestions.contains(&r) {
                suggestions.push(r);
            }
        }
    }
    if arg_token.contains("SECRET") {
        has_entity = true;
        for s in SecretStore::new().list() {
            suggestions.push(s.name);
        }
    }

    let is_path_like = ["PATH", "CONTEXT", "FILE", "COMMAND", "ARG...", "URI"]
        .iter()
        .any(|k| arg_token.contains(k));
    if is_path_like && !has_entity {
        emit_completion(&[], DIRECTIVE_DEFAULT);
    }

    emit_completion(&suggestions, DIRECTIVE_NO_FILE_COMP);
}

fn complete_format_flag(sub_refs: &[&str], cmd_args: &[String]) -> ! {
    if sub_refs == ["inspect"] {
        let mut target: Option<&str> = None;
        let mut i = 0;
        while i < cmd_args.len() {
            let a = cmd_args[i].as_str();
            if a == "-f" || a == "--format" || a == "--type" || a == "-t" {
                i += 2;
                continue;
            }
            if a.starts_with('-') {
                i += 1;
                continue;
            }
            target = Some(a);
            break;
        }
        let fields: &[&str] = if let Some(t) = target {
            if ContainerStore::new().find(t).is_some() {
                &["{{.Args}}", "{{.Config}}", "{{.Id}}", "{{.State}}"]
            } else if crate::find_image_with_shortname_for_completion(&ImageStore::new(), t)
                .is_some()
                || ImageStore::new().list().iter().any(|img| {
                    img.reference == t
                        || img.reference.rsplit('/').next() == Some(t)
                        || img.qualified_name().starts_with(&format!("{}:", t))
                        || img.qualified_name().starts_with(&format!("localhost/{}:", t))
                        || img.id.starts_with(t)
                })
            {
                &["{{.Digest}}", "{{.Id}}", "{{.RepoTags}}", "{{.Size}}"]
            } else if VolumeStore::new().find(t).is_some() {
                &["{{.Anonymous}}", "{{.Driver}}", "{{.Mountpoint}}", "{{.Name}}"]
            } else if PodStore::new().find(t).is_some() {
                &["{{.BlkioDeviceReadBps}}", "{{.Containers}}", "{{.Id}}", "{{.Name}}"]
            } else if NetworkStore::new().find(t).is_some() {
                &["{{.DNSEnabled}}", "{{.Driver}}", "{{.ID}}", "{{.Name}}"]
            } else {
                &["{{.Args}}", "{{.Config}}", "{{.Id}}", "{{.State}}"]
            }
        } else {
            &["{{.Args}}", "{{.Config}}", "{{.Id}}", "{{.State}}"]
        };
        let out: Vec<String> = fields.iter().map(|s| (*s).to_string()).collect();
        emit_completion(&out, DIRECTIVE_NO_FILE_COMP);
    }

    let is_go_template_cmd = matches!(
        sub_refs,
        ["history"]
            | ["image", "history"]
            | ["image", "inspect"]
            | ["container", "inspect"]
            | ["artifact", "inspect"]
            | ["volume", "inspect"]
            | ["secret", "inspect"]
            | ["network", "inspect"]
            | ["ps"]
            | ["image", "search"]
            | ["search"]
            | ["pod", "inspect"]
            | ["events"]
            | ["system", "events"]
            | ["container", "stats"]
            | ["pod", "stats"]
            | ["stats"]
    );
    if is_go_template_cmd {
        let out = vec![
            "{{.ID}}".to_string(),
            "{{.Name}}".to_string(),
            "{{.Status}}".to_string(),
        ];
        emit_completion(&out, DIRECTIVE_NO_FILE_COMP);
    }
    emit_completion(&["oci".to_string(), "docker".to_string()], DIRECTIVE_NO_FILE_COMP);
}

fn complete_sysctl(prefix: &str) -> ! {
    let mut out = Vec::new();
    let rel = prefix.replace('.', "/");
    let dir_part = if let Some((d, _)) = rel.rsplit_once('/') {
        d
    } else {
        ""
    };
    let search_dir = Path::new("/proc/sys").join(dir_part);
    if let Ok(entries) = fs::read_dir(&search_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let candidate = if dir_part.is_empty() {
                name
            } else {
                format!("{}.{}", dir_part.replace('/', "."), name)
            };
            if candidate.starts_with(prefix) {
                out.push(candidate);
            }
        }
    }
    if out.is_empty() && prefix.starts_with("net.") {
        out.push("net.ipv4.ip_forward".to_string());
        out.push("net.ipv4.conf.all.forwarding".to_string());
    }
    out.sort();
    emit_completion(&out, DIRECTIVE_NO_FILE_COMP);
}

fn complete_interface_name(prefix: &str) -> ! {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(prefix) {
                out.push(name);
            }
        }
    }
    if "lo".starts_with(prefix) && !out.iter().any(|s| s == "lo") {
        out.push("lo".to_string());
    }
    out.sort();
    emit_completion(&out, DIRECTIVE_NO_FILE_COMP);
}

fn configured_registries() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(path) = std::env::var("CONTAINERS_REGISTRIES_CONF") {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("unqualified-search-registries") {
                    let mut rest = trimmed;
                    while let Some(s) = rest.find('"') {
                        rest = &rest[s + 1..];
                        if let Some(e) = rest.find('"') {
                            out.push(rest[..e].to_string());
                            rest = &rest[e + 1..];
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }
    for default_reg in ["quay.io", "docker.io", "registry.fedoraproject.org"] {
        if !out.iter().any(|r| r == default_reg) {
            out.push(default_reg.to_string());
        }
    }
    out
}

fn resolve_clamped_in_rootfs(rootfs: &Path, rel: &str) -> PathBuf {
    let mut comps: Vec<String> = Vec::new();
    for part in rel.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                comps.pop();
            }
            other => comps.push(other.to_string()),
        }
    }
    let mut p = rootfs.to_path_buf();
    for c in comps {
        p.push(c);
    }
    p
}

fn complete_rootfs_paths(
    rootfs: &Path,
    raw_query: &str,
    ctr_prefix: Option<&str>,
) -> (Vec<String>, u8) {
    let pfx = ctr_prefix.unwrap_or("");
    if raw_query.is_empty() {
        let mut items = Vec::new();
        if let Ok(entries) = fs::read_dir(rootfs) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                if is_dir {
                    items.push(format!("{}/{}/", pfx, name));
                } else {
                    items.push(format!("{}/{}", pfx, name));
                }
            }
        }
        items.sort();
        return (items, DIRECTIVE_DEFAULT);
    }

    // Check if raw_query (without trailing slash) directly names a directory in rootfs
    let probe = resolve_clamped_in_rootfs(rootfs, raw_query);
    if !raw_query.ends_with('/') && probe.is_dir() {
        let mut children = Vec::new();
        if let Ok(entries) = fs::read_dir(&probe) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                let base = raw_query.trim_end_matches('/');
                if is_dir {
                    children.push(format!("{}{}/{}/", pfx, base, name));
                } else {
                    children.push(format!("{}{}/{}", pfx, base, name));
                }
            }
        }
        children.sort();
        if children.is_empty() {
            // Empty directory: suggest `<dir>/` with ShellCompDirectiveNoSpace (:2)
            return (
                vec![format!("{}{}/", pfx, raw_query.trim_end_matches('/'))],
                DIRECTIVE_NO_SPACE,
            );
        }
        return (children, DIRECTIVE_DEFAULT);
    }

    let (dir_prefix, file_prefix) = if let Some(idx) = raw_query.rfind('/') {
        (&raw_query[..=idx], &raw_query[idx + 1..])
    } else {
        ("", raw_query)
    };

    let search_dir = resolve_clamped_in_rootfs(rootfs, dir_prefix);
    let mut items = Vec::new();
    if let Ok(entries) = fs::read_dir(&search_dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.starts_with(file_prefix) {
                continue;
            }
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir {
                items.push(format!("{}{}{}/", pfx, dir_prefix, name));
            } else {
                items.push(format!("{}{}{}", pfx, dir_prefix, name));
            }
        }
    }
    items.sort();
    (items, DIRECTIVE_DEFAULT)
}
