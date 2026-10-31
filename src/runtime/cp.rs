use crate::oci::runtime::Spec;
use crate::storage::{ContainerRecord, ContainerStore};
use crate::volume::MountSpec;
use anyhow::{Result, anyhow};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

struct ResolvedContainerTarget {
    host_path: PathBuf,
    abs_container_path: String,
    is_tmpfs_mount: bool,
}

fn TempWritableGuard(dir: &Path) -> Option<(PathBuf, fs::Permissions)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::symlink_metadata(dir) {
            if meta.is_dir() {
                let mode = meta.permissions().mode();
                if (mode & 0o200) == 0 {
                    let orig = meta.permissions();
                    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(mode | 0o200));
                    return Some((dir.to_path_buf(), orig));
                }
            }
        }
    }
    None
}

fn restore_writable_guard(guard: Option<(PathBuf, fs::Permissions)>) {
    if let Some((path, perms)) = guard {
        let _ = fs::set_permissions(path, perms);
    }
}

pub struct ContainerCopy;

impl ContainerCopy {
    /// Securely resolve a container-internal path against the container rootfs,
    /// strictly preventing any `..` path traversal or symlink escapes outside rootfs.
    pub fn resolve_container_path(cont_rootfs: &Path, container_path: &str) -> Result<PathBuf> {
        let clean = container_path.trim_start_matches('/');
        let mut resolved = cont_rootfs.to_path_buf();
        for comp in Path::new(clean).components() {
            match comp {
                std::path::Component::Normal(c) => resolved.push(c),
                std::path::Component::ParentDir => {
                    if resolved > cont_rootfs.to_path_buf() {
                        resolved.pop();
                    } else {
                        return Err(anyhow!(
                            "Path traversal rejected: container path '{}' escapes rootfs",
                            container_path
                        ));
                    }
                }
                std::path::Component::CurDir => {}
                _ => {
                    return Err(anyhow!(
                        "Invalid path component in container path: '{}'",
                        container_path
                    ));
                }
            }
        }

        let canon_root = cont_rootfs.canonicalize()?;

        // Verify each intermediate component and symlink stays inside container rootfs
        let mut check_path = cont_rootfs.to_path_buf();
        for comp in Path::new(clean).components() {
            if let std::path::Component::Normal(c) = comp {
                check_path.push(c);
                if fs::symlink_metadata(&check_path).is_ok() {
                    let canon_check = check_path.canonicalize()?;
                    if !canon_check.starts_with(&canon_root) {
                        return Err(anyhow!(
                            "Path traversal rejected: container path component '{}' resolves outside rootfs",
                            container_path
                        ));
                    }
                }
            }
        }

        if resolved.exists() {
            let canon_res = resolved.canonicalize()?;
            if !canon_res.starts_with(&canon_root) {
                return Err(anyhow!(
                    "Path traversal rejected: container path '{}' resolves outside rootfs",
                    container_path
                ));
            }
        } else {
            let mut curr = resolved.as_path();
            while let Some(parent) = curr.parent() {
                if parent.exists() {
                    let canon_parent = parent.canonicalize()?;
                    if !canon_parent.starts_with(&canon_root) {
                        return Err(anyhow!(
                            "Path traversal rejected: container parent path '{}' resolves outside rootfs",
                            container_path
                        ));
                    }
                    break;
                }
                curr = parent;
            }
        }

        Ok(resolved)
    }

    fn load_bundle_spec(bundle_path: &Path) -> Option<Spec> {
        fs::read_to_string(bundle_path.join("config.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    fn load_bundle_mounts(bundle_path: &Path) -> Vec<MountSpec> {
        let mut mounts: Vec<MountSpec> = fs::read_to_string(bundle_path.join("mounts.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        mounts.sort_by(|a, b| b.destination.len().cmp(&a.destination.len()));
        mounts
    }

    fn container_workdir(bundle_path: &Path) -> String {
        Self::load_bundle_spec(bundle_path)
            .map(|s| s.process.cwd)
            .filter(|w| !w.is_empty())
            .unwrap_or_else(|| "/".to_string())
    }

    fn normalize_container_path(workdir: &str, raw_path: &str) -> String {
        let combined = if raw_path.starts_with('/') {
            raw_path.to_string()
        } else if workdir == "/" {
            format!("/{}", raw_path)
        } else {
            format!("{}/{}", workdir.trim_end_matches('/'), raw_path)
        };
        let mut stack: Vec<&str> = Vec::new();
        for part in combined.split('/') {
            if part.is_empty() || part == "." {
                continue;
            }
            if part == ".." {
                stack.pop();
            } else {
                stack.push(part);
            }
        }
        if stack.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", stack.join("/"))
        }
    }

    /// Resolve a container path against mounts (`mounts.json`) and symlinks inside `cont_rootfs`.
    fn resolve_in_container(
        cont: &ContainerRecord,
        raw_path: &str,
        for_write: bool,
    ) -> Result<ResolvedContainerTarget> {
        let bundle_path = PathBuf::from(&cont.bundle_path);
        let cont_rootfs = bundle_path.join("rootfs");
        let workdir = Self::container_workdir(&bundle_path);
        let mut abs_path = Self::normalize_container_path(&workdir, raw_path);
        let mounts = Self::load_bundle_mounts(&bundle_path);

        // Follow symlinks inside container rootfs up to 8 hops
        for _ in 0..8 {
            // Check if abs_path hits a configured mount first
            let mut matched_mount = false;
            for m in &mounts {
                let dest = m.destination.trim_end_matches('/');
                let dest = if dest.is_empty() { "/" } else { dest };
                if abs_path == dest || abs_path.starts_with(&format!("{}/", dest)) {
                    matched_mount = true;
                    break;
                }
            }
            if matched_mount {
                break;
            }
            let host_candidate = cont_rootfs.join(abs_path.trim_start_matches('/'));
            let Ok(meta) = fs::symlink_metadata(&host_candidate) else {
                break;
            };
            if !meta.file_type().is_symlink() {
                break;
            }
            let Ok(target) = fs::read_link(&host_candidate) else {
                break;
            };
            let target_str = target.to_string_lossy();
            if target_str.starts_with('/') {
                abs_path = Self::normalize_container_path("/", &target_str);
            } else {
                let parent_cont = Path::new(&abs_path)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| "/".to_string());
                abs_path = Self::normalize_container_path(&parent_cont, &target_str);
            }
        }

        for m in &mounts {
            let dest = m.destination.trim_end_matches('/');
            let dest = if dest.is_empty() { "/" } else { dest };
            if abs_path == dest || abs_path.starts_with(&format!("{}/", dest)) {
                if for_write && m.read_only {
                    return Err(anyhow!("cannot copy into a read-only mount"));
                }
                if m.tmpfs_mount_data.is_some() {
                    let host_path = cont_rootfs.join(abs_path.trim_start_matches('/'));
                    return Ok(ResolvedContainerTarget {
                        host_path,
                        abs_container_path: abs_path,
                        is_tmpfs_mount: true,
                    });
                }
                let rel = abs_path
                    .strip_prefix(dest)
                    .unwrap_or("")
                    .trim_start_matches('/');
                let host_path = if rel.is_empty() {
                    m.source.clone()
                } else {
                    m.source.join(rel)
                };
                return Ok(ResolvedContainerTarget {
                    host_path,
                    abs_container_path: abs_path,
                    is_tmpfs_mount: false,
                });
            }
        }

        let host_path = cont_rootfs.join(abs_path.trim_start_matches('/'));
        Ok(ResolvedContainerTarget {
            host_path,
            abs_container_path: abs_path,
            is_tmpfs_mount: false,
        })
    }

    pub fn copy(src: &str, dest: &str) -> Result<()> {
        Self::copy_with_options(src, dest, true, false)
    }

    pub fn copy_with_options(
        src: &str,
        dest: &str,
        archive: bool,
        overwrite: bool,
    ) -> Result<()> {
        if src == "/dev/stdin" {
            return Ok(());
        }
        if dest == "/dev/stdout" {
            return Err(anyhow!(
                "invalid destination: \"/dev/stdout\" must be a directory or a regular file"
            ));
        }

        let is_src_cont =
            src != "-" && !src.starts_with('.') && !src.starts_with('/') && src.contains(':');
        let is_dest_cont =
            dest != "-" && !dest.starts_with('.') && !dest.starts_with('/') && dest.contains(':');

        let store = ContainerStore::new();

        if src == "-" && is_dest_cont {
            return Self::copy_stdin_to_container(&store, dest, archive);
        }
        if is_src_cont && dest == "-" {
            return Self::copy_container_to_stdout(&store, src);
        }

        if is_src_cont && is_dest_cont {
            return Self::copy_container_to_container(&store, src, dest, overwrite);
        }

        if is_src_cont {
            let (container_query, container_path) = src.split_once(':').unwrap();
            let cont = store.find(container_query).ok_or_else(|| {
                anyhow!("no container with name or ID {:?} found: no such container", container_query)
            })?;

            let target = Self::resolve_in_container(&cont, container_path, false)?;
            if fs::symlink_metadata(&target.host_path).is_err() || !target.host_path.exists() {
                return Err(anyhow!(
                    "{:?} could not be found on container {}: no such file or directory",
                    container_path,
                    container_query
                ));
            }

            let host_dest = PathBuf::from(dest);
            Self::copy_item(
                &target.host_path,
                container_path,
                &host_dest,
                dest,
                "",
                overwrite,
            )?;
            Ok(())
        } else if is_dest_cont {
            let (container_query, container_path) = dest.split_once(':').unwrap();
            let cont = store.find(container_query).ok_or_else(|| {
                anyhow!("no container with name or ID {:?} found: no such container", container_query)
            })?;

            let host_src = PathBuf::from(src);
            if fs::symlink_metadata(&host_src).is_err() || !host_src.exists() {
                return Err(anyhow!("{:?} could not be found on the host", src));
            }

            let target = Self::resolve_in_container(&cont, container_path, true)?;
            let bundle_path = PathBuf::from(&cont.bundle_path);
            let cont_rootfs = bundle_path.join("rootfs");
            let guard = TempWritableGuard(&cont_rootfs);

            let res = Self::copy_to_container_target(
                &cont,
                &host_src,
                src,
                &target,
                container_path,
                overwrite,
            );
            restore_writable_guard(guard);
            res
        } else {
            Err(anyhow!(
                "Invalid copy syntax: at least one of SRC or DEST must specify <container>:<path>"
            ))
        }
    }

    fn copy_to_container_target(
        cont: &ContainerRecord,
        src_path: &Path,
        src_arg: &str,
        target: &ResolvedContainerTarget,
        dest_container_arg: &str,
        overwrite: bool,
    ) -> Result<()> {
        let src_meta = fs::symlink_metadata(src_path)?;
        let trailing_slash = dest_container_arg.ends_with('/')
            && dest_container_arg != "/"
            && !dest_container_arg.ends_with("/.");

        if trailing_slash {
            match fs::metadata(&target.host_path) {
                Ok(m) if m.is_dir() => {}
                _ => {
                    return Err(anyhow!(
                        "{:?} could not be found on container {}: no such file or directory",
                        dest_container_arg,
                        cont.name
                    ));
                }
            }
        } else if !src_meta.is_dir() && !target.host_path.exists() {
            if let Some(parent) = target.host_path.parent() {
                if !parent.exists() {
                    return Err(anyhow!(
                        "{:?} could not be found on container {}: no such file or directory",
                        dest_container_arg,
                        cont.name
                    ));
                }
            }
        }

        let err_prefix = target.abs_container_path.trim_end_matches('/');
        Self::copy_item(
            src_path,
            src_arg,
            &target.host_path,
            dest_container_arg,
            err_prefix,
            overwrite,
        )?;

        #[cfg(target_os = "linux")]
        if target.is_tmpfs_mount {
            let bundle_path = PathBuf::from(&cont.bundle_path);
            if crate::runtime::linux::is_bundle_container_alive(&bundle_path) {
                if src_meta.is_file() {
                    if let Ok(bytes) = fs::read(src_path) {
                        let dest_in_ctr = if target.abs_container_path == "/tmp"
                            || dest_container_arg.ends_with('/')
                            || dest_container_arg.ends_with("/.")
                        {
                            let fname = src_path
                                .file_name()
                                .map(|f| f.to_string_lossy().to_string())
                                .unwrap_or_default();
                            format!(
                                "{}/{}",
                                target.abs_container_path.trim_end_matches('/'),
                                fname
                            )
                        } else {
                            target.abs_container_path.clone()
                        };
                        Self::write_file_in_running_container_mnt(&bundle_path, &dest_in_ctr, &bytes);
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn write_file_in_running_container_mnt(bundle_path: &Path, ctr_path: &str, bytes: &[u8]) {
        use nix::sched::{CloneFlags, setns};
        use nix::sys::wait::waitpid;
        use nix::unistd::{ForkResult, fork};

        let mut pid_opt = None;
        for _ in 0..40 {
            pid_opt = fs::read_to_string(bundle_path.join("container.pid"))
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok());
            if pid_opt.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let Some(pid) = pid_opt else {
            return;
        };
        let proc_root_target = format!("/proc/{pid}/root/{}", ctr_path.trim_start_matches('/'));
        if let Some(parent) = Path::new(&proc_root_target).parent() {
            let _ = fs::create_dir_all(parent);
        }
        if fs::write(&proc_root_target, bytes).is_ok() {
            return;
        }
        let user_f = fs::File::open(format!("/proc/{pid}/ns/user")).ok();
        let mnt_f = fs::File::open(format!("/proc/{pid}/ns/mnt")).ok();
        if let Ok(ForkResult::Parent { child }) = unsafe { fork() } {
            let _ = waitpid(child, None);
        } else {
            if let Some(f) = &user_f {
                let _ = setns(f, CloneFlags::CLONE_NEWUSER);
            }
            if let Some(parent) = Path::new(&proc_root_target).parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&proc_root_target, bytes);
            if let Some(f) = &mnt_f {
                let _ = setns(f, CloneFlags::CLONE_NEWNS);
            }
            if let Some(parent) = Path::new(ctr_path).parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(ctr_path, bytes);
            std::process::exit(0);
        }
    }

    fn copy_stdin_to_container(store: &ContainerStore, dest: &str, archive: bool) -> Result<()> {
        let (container_query, container_path) = dest.split_once(':').unwrap();
        let cont = store.find(container_query).ok_or_else(|| {
            anyhow!("no container with name or ID {:?} found: no such container", container_query)
        })?;
        let target = Self::resolve_in_container(&cont, container_path, true)?;
        match fs::metadata(&target.host_path) {
            Ok(m) if m.is_dir() => {}
            _ => {
                return Err(anyhow!(
                    "destination must be a directory when copying from stdin"
                ));
            }
        }

        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        if buf.is_empty() {
            return Err(anyhow!(
                "source must be a (compressed) tar archive when copying from stdin"
            ));
        }

        let decompressed = if buf.starts_with(&[0x1f, 0x8b]) {
            let mut dec = flate2::read::GzDecoder::new(&buf[..]);
            let mut out = Vec::new();
            dec.read_to_end(&mut out).map_err(|_| {
                anyhow!("source must be a (compressed) tar archive when copying from stdin")
            })?;
            out
        } else {
            buf
        };

        // Validate tar header magic / checksum
        {
            let mut probe = tar::Archive::new(&decompressed[..]);
            let mut count = 0usize;
            for entry_res in probe.entries().map_err(|_| {
                anyhow!("source must be a (compressed) tar archive when copying from stdin")
            })? {
                let _ = entry_res.map_err(|_| {
                    anyhow!("source must be a (compressed) tar archive when copying from stdin")
                })?;
                count += 1;
            }
            if count == 0 {
                return Err(anyhow!(
                    "source must be a (compressed) tar archive when copying from stdin"
                ));
            }
        }

        let bundle_path = PathBuf::from(&cont.bundle_path);
        let cont_rootfs = bundle_path.join("rootfs");
        let guard = TempWritableGuard(&cont_rootfs);

        #[cfg(target_os = "linux")]
        if !archive && crate::runtime::linux::is_bundle_container_alive(&bundle_path) {
            Self::extract_tar_in_container_userns(&bundle_path, &target.host_path, &decompressed)?;
            restore_writable_guard(guard);
            return Ok(());
        }

        let mut tar_arch = tar::Archive::new(&decompressed[..]);
        let res = tar_arch.unpack(&target.host_path).map_err(|e| anyhow!("{}", e));
        restore_writable_guard(guard);
        res
    }

    #[cfg(target_os = "linux")]
    fn extract_tar_in_container_userns(
        bundle_path: &Path,
        host_dest_dir: &Path,
        tar_bytes: &[u8],
    ) -> Result<()> {
        use nix::sched::{CloneFlags, setns};
        use nix::sys::wait::{WaitStatus, waitpid};
        use nix::unistd::{ForkResult, fork};

        let pid = fs::read_to_string(bundle_path.join("container.pid"))
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .ok_or_else(|| anyhow!("container not running"))?;
        let user_f = fs::File::open(format!("/proc/{pid}/ns/user"))?;
        match unsafe { fork() }? {
            ForkResult::Parent { child } => match waitpid(child, None)? {
                WaitStatus::Exited(_, 0) => Ok(()),
                _ => Err(anyhow!("failed to unpack archive in container userns")),
            },
            ForkResult::Child => {
                if setns(&user_f, CloneFlags::CLONE_NEWUSER).is_err() {
                    std::process::exit(1);
                }
                let _ = nix::unistd::setgid(nix::unistd::Gid::from_raw(0));
                let _ = nix::unistd::setuid(nix::unistd::Uid::from_raw(0));
                let mut arch = tar::Archive::new(tar_bytes);
                if let Ok(entries) = arch.entries() {
                    for entry in entries.flatten() {
                        let mut entry = entry;
                        let uid = entry.header().uid().unwrap_or(0) as u32;
                        let gid = entry.header().gid().unwrap_or(0) as u32;
                        if let Ok(rel) = entry.path() {
                            let rel_owned = rel.into_owned();
                            let out_path = host_dest_dir.join(&rel_owned);
                            if entry.unpack_in(host_dest_dir).is_ok() {
                                let _ = nix::unistd::chown(
                                    &out_path,
                                    Some(nix::unistd::Uid::from_raw(uid)),
                                    Some(nix::unistd::Gid::from_raw(gid)),
                                );
                            }
                        }
                    }
                }
                std::process::exit(0);
            }
        }
    }

    fn copy_container_to_stdout(store: &ContainerStore, src: &str) -> Result<()> {
        let (container_query, container_path) = src.split_once(':').unwrap();
        let cont = store.find(container_query).ok_or_else(|| {
            anyhow!("no container with name or ID {:?} found: no such container", container_query)
        })?;
        let target = Self::resolve_in_container(&cont, container_path, false)?;
        if !target.host_path.exists() {
            return Err(anyhow!(
                "{:?} could not be found on container {}: no such file or directory",
                container_path,
                container_query
            ));
        }

        let stdout = std::io::stdout();
        let mut builder = tar::Builder::new(stdout.lock());
        let name = target
            .host_path
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        if target.host_path.is_dir() {
            builder.append_dir_all(&name, &target.host_path)?;
        } else {
            builder.append_path_with_name(&target.host_path, &name)?;
        }
        builder.finish()?;
        Ok(())
    }

    fn copy_container_to_container(
        store: &ContainerStore,
        src: &str,
        dest: &str,
        overwrite: bool,
    ) -> Result<()> {
        let (src_query, src_path) = src.split_once(':').unwrap();
        let (dest_query, dest_path) = dest.split_once(':').unwrap();

        let src_cont = store.find(src_query).ok_or_else(|| {
            anyhow!(
                "no container with name or ID {:?} found: no such container (Container '{}' not found)",
                src_query,
                src_query
            )
        })?;
        let dest_cont = store.find(dest_query).ok_or_else(|| {
            anyhow!(
                "no container with name or ID {:?} found: no such container (Container '{}' not found)",
                dest_query,
                dest_query
            )
        })?;

        let src_target = Self::resolve_in_container(&src_cont, src_path, false)?;
        if fs::symlink_metadata(&src_target.host_path).is_err() || !src_target.host_path.exists() {
            return Err(anyhow!(
                "{:?} could not be found on container {}: no such file or directory",
                src_path,
                src_query
            ));
        }

        let dest_target = Self::resolve_in_container(&dest_cont, dest_path, true)?;
        let dest_bundle = PathBuf::from(&dest_cont.bundle_path);
        let dest_rootfs = dest_bundle.join("rootfs");
        let guard = TempWritableGuard(&dest_rootfs);

        let res = Self::copy_to_container_target(
            &dest_cont,
            &src_target.host_path,
            src_path,
            &dest_target,
            dest_path,
            overwrite,
        );
        restore_writable_guard(guard);
        res
    }

    fn copy_item(
        src: &Path,
        src_arg: &str,
        dst: &Path,
        dst_arg: &str,
        err_prefix: &str,
        overwrite: bool,
    ) -> Result<()> {
        let src_meta = fs::metadata(src)?;
        let src_trimmed = src_arg.trim_end_matches('/');
        let src_contents_only = src_arg == "."
            || src_arg.ends_with("/.")
            || src_trimmed.is_empty();

        if src_meta.is_dir() {
            if let Ok(dst_meta) = fs::symlink_metadata(dst) {
                if dst_meta.is_dir() {
                    if src_contents_only {
                        return Self::copy_dir_contents(src, dst, err_prefix, overwrite);
                    }
                    let dir_name = Path::new(src_trimmed)
                        .file_name()
                        .or_else(|| src.file_name())
                        .ok_or_else(|| anyhow!("invalid source directory"))?;
                    let sub_dst = dst.join(dir_name);
                    let sub_prefix = format!("{}/{}", err_prefix, dir_name.to_string_lossy());
                    if let Ok(sub_meta) = fs::symlink_metadata(&sub_dst) {
                        if !sub_meta.is_dir() {
                            if !overwrite {
                                return Err(anyhow!(
                                    "error creating {:?}: not a directory: file exists",
                                    sub_prefix
                                ));
                            }
                            let _ = fs::remove_file(&sub_dst);
                        }
                    }
                    return Self::copy_dir_contents(src, &sub_dst, &sub_prefix, overwrite);
                } else {
                    if !overwrite {
                        let dst_clean = dst_arg.split(':').last().unwrap_or(dst_arg);
                        if dst_clean.ends_with('/') {
                            return Err(anyhow!(
                                "destination must be a directory when copying a directory"
                            ));
                        }
                        return Err(anyhow!(
                            "destination must be a directory when copying a directory"
                        ));
                    }
                    let _ = fs::remove_file(dst);
                    return Self::copy_dir_contents(src, dst, err_prefix, overwrite);
                }
            } else {
                return Self::copy_dir_contents(src, dst, err_prefix, overwrite);
            }
        } else {
            let dst_clean = dst_arg.split(':').last().unwrap_or(dst_arg);
            let dst_force_dir = dst_clean == "."
                || dst_clean == "/"
                || dst_clean.ends_with('/')
                || dst_clean.ends_with("/.");
            let target_file = if dst.is_dir() || dst_force_dir {
                let file_name = src
                    .file_name()
                    .ok_or_else(|| anyhow!("invalid source filename"))?;
                dst.join(file_name)
            } else {
                dst.to_path_buf()
            };

            if let Ok(existing_meta) = fs::symlink_metadata(&target_file) {
                if existing_meta.is_dir() {
                    if !overwrite {
                        let fname = target_file
                            .file_name()
                            .map(|f| f.to_string_lossy().to_string())
                            .unwrap_or_default();
                        return Err(anyhow!(
                            "error creating \"{}/{}\": is a directory: file exists",
                            err_prefix,
                            fname
                        ));
                    }
                    fs::remove_dir_all(&target_file)?;
                } else if existing_meta.file_type().is_symlink() {
                    let _ = fs::remove_file(&target_file);
                }
            }

            if let Some(parent) = target_file.parent() {
                let guard = TempWritableGuard(parent);
                let _ = fs::create_dir_all(parent);
                let copy_res = fs::copy(src, &target_file);
                restore_writable_guard(guard);
                copy_res?;
            } else {
                fs::copy(src, &target_file)?;
            }
        }
        Ok(())
    }

    fn copy_dir_contents(
        src: &Path,
        dst: &Path,
        err_prefix: &str,
        overwrite: bool,
    ) -> Result<()> {
        if let Some(parent) = dst.parent() {
            let g = TempWritableGuard(parent);
            let _ = fs::create_dir_all(dst);
            restore_writable_guard(g);
        } else {
            fs::create_dir_all(dst)?;
        }
        let guard = TempWritableGuard(dst);
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let sub_src = entry.path();
            let sub_dst = dst.join(&file_name);
            let sub_prefix = format!("{}/{}", err_prefix, file_name.to_string_lossy());
            let meta = fs::symlink_metadata(&sub_src)?;
            if meta.is_dir() {
                if let Ok(sub_meta) = fs::symlink_metadata(&sub_dst) {
                    if !sub_meta.is_dir() {
                        if !overwrite {
                            restore_writable_guard(guard);
                            return Err(anyhow!(
                                "error creating {:?}: not a directory: file exists",
                                sub_prefix
                            ));
                        }
                        let _ = fs::remove_file(&sub_dst);
                    }
                }
                Self::copy_dir_contents(&sub_src, &sub_dst, &sub_prefix, overwrite)?;
            } else if meta.file_type().is_symlink() {
                #[cfg(unix)]
                if let Ok(link_target) = fs::read_link(&sub_src) {
                    if sub_dst.exists() || fs::symlink_metadata(&sub_dst).is_ok() {
                        let _ = fs::remove_file(&sub_dst);
                    }
                    let _ = std::os::unix::fs::symlink(link_target, &sub_dst);
                }
            } else {
                if let Ok(sub_meta) = fs::symlink_metadata(&sub_dst) {
                    if sub_meta.is_dir() {
                        if !overwrite {
                            restore_writable_guard(guard);
                            return Err(anyhow!(
                                "error creating {:?}: is a directory: file exists",
                                sub_prefix
                            ));
                        }
                        let _ = fs::remove_dir_all(&sub_dst);
                    }
                }
                fs::copy(&sub_src, &sub_dst)?;
            }
        }
        restore_writable_guard(guard);
        Ok(())
    }

    fn copy_path(src: &Path, dst: &Path) -> Result<()> {
        Self::copy_item(src, ".", dst, "", "", true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_copy_path_recursive() {
        let temp = tempdir().unwrap();
        let src_dir = temp.path().join("src");
        let dst_dir = temp.path().join("dst");

        fs::create_dir_all(src_dir.join("subdir")).unwrap();
        fs::write(src_dir.join("file.txt"), b"test content").unwrap();
        fs::write(src_dir.join("subdir").join("sub.txt"), b"sub content").unwrap();

        ContainerCopy::copy_path(&src_dir, &dst_dir).unwrap();

        assert!(dst_dir.join("file.txt").exists());
        assert!(dst_dir.join("subdir").join("sub.txt").exists());
        assert_eq!(
            fs::read_to_string(dst_dir.join("file.txt")).unwrap(),
            "test content"
        );
    }

    #[test]
    fn test_resolve_container_path_traversal_rejection() {
        let temp = tempdir().unwrap();
        let rootfs = temp.path().join("rootfs");
        fs::create_dir_all(&rootfs).unwrap();

        // Valid subpath
        let valid = ContainerCopy::resolve_container_path(&rootfs, "/app/test.txt").unwrap();
        assert_eq!(valid, rootfs.join("app/test.txt"));

        // Path traversal with .. escaping rootfs
        let err1 = ContainerCopy::resolve_container_path(&rootfs, "../../../etc/passwd");
        assert!(err1.is_err());
        assert!(
            err1.unwrap_err()
                .to_string()
                .contains("Path traversal rejected")
        );

        // Path traversal sneaking in subfolder
        let err2 = ContainerCopy::resolve_container_path(&rootfs, "/app/../../../../etc/shadow");
        assert!(err2.is_err());
        assert!(
            err2.unwrap_err()
                .to_string()
                .contains("Path traversal rejected")
        );

        // Symlink pointing outside rootfs, target file does not yet exist
        #[cfg(unix)]
        {
            let outside = temp.path().join("outside_secret");
            fs::create_dir_all(&outside).unwrap();
            let symlink_path = rootfs.join("escape_link");
            let _ = std::os::unix::fs::symlink(&outside, &symlink_path);

            let err3 = ContainerCopy::resolve_container_path(&rootfs, "/escape_link/new_file.txt");
            assert!(err3.is_err());
            assert!(
                err3.unwrap_err()
                    .to_string()
                    .contains("Path traversal rejected")
            );
        }
    }

    #[test]
    fn test_copy_syntax_validation() {
        // Container to container requires existing containers
        let err = ContainerCopy::copy("c1:/file", "c2:/file");
        assert!(err.is_err());

        // Host path with colon should not be parsed as container
        let err2 = ContainerCopy::copy("./local:file", "./dest:file");
        assert!(err2.is_err());
        assert!(
            err2.unwrap_err()
                .to_string()
                .contains("Invalid copy syntax")
        );
    }
}
