//! Extended volume operations (export, import, reload, rename, mount, unmount).

use crate::storage::boxr_home;
use crate::volume::{VolumeRecord, VolumeStore};
use anyhow::{Result, anyhow};
use std::fs::{self, File};
use std::io::{self, stdin};
use std::path::{Path, PathBuf};

pub struct VolumeOps;

fn append_volume_tree<W: io::Write>(
    tar: &mut tar::Builder<W>,
    mountpoint: &Path,
    vol_uid: Option<u32>,
    vol_gid: Option<u32>,
) -> Result<()> {
    let apply_owner = |path: &Path, name: &Path, tar: &mut tar::Builder<W>| -> Result<()> {
        if let (Some(u), Some(g)) = (vol_uid, vol_gid) {
            let mut f = File::open(path)?;
            let meta = f.metadata()?;
            let mut hdr = tar::Header::new_gnu();
            hdr.set_metadata(&meta);
            hdr.set_uid(u as u64);
            hdr.set_gid(g as u64);
            if let Ok(m) = fs::symlink_metadata(mountpoint) {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};
                    let root_mode = m.mode() & 0o7777;
                    if root_mode != 0o777 && root_mode != 0o755 {
                        hdr.set_mode(((meta.permissions().mode() & 0o777) & !0o777) | root_mode);
                    }
                }
            }
            hdr.set_cksum();
            tar.append_data(&mut hdr, name, &mut f)?;
        } else {
            tar.append_path_with_name(path, name)?;
        }
        Ok(())
    };
    for entry in fs::read_dir(mountpoint)? {
        let path = entry?.path();
        if path.is_file() {
            let name = PathBuf::from(path.file_name().unwrap_or_default());
            apply_owner(&path, &name, tar)?;
        } else if path.is_dir() {
            let prefix = path.file_name().map(|n| n.to_owned()).unwrap_or_default();
            for sub in fs::read_dir(&path)? {
                let subpath = sub?.path();
                if subpath.is_file() {
                    let rel = PathBuf::from(format!(
                        "{}/{}",
                        prefix.to_string_lossy(),
                        subpath.file_name().unwrap_or_default().to_string_lossy()
                    ));
                    apply_owner(&subpath, &rel, tar)?;
                }
            }
        }
    }
    Ok(())
}

impl VolumeOps {
    pub fn export_volume(name: &str, output: Option<&Path>) -> Result<Option<PathBuf>> {
        let store = VolumeStore::new();
        let vol = store
            .find(name)
            .ok_or_else(|| anyhow!("no volume with name \"{}\" found: no such volume", name))?;

        let mountpoint = PathBuf::from(&vol.mountpoint);
        if !mountpoint.exists() {
            return Err(anyhow!("Volume mountpoint does not exist on disk"));
        }
        #[cfg(target_os = "linux")]
        if vol.uid.is_some() || vol.gid.is_some() {
            let _ = crate::runtime::linux::chown_path_rootless(&mountpoint, 0, 0, true);
        }

        if output.is_none() {
            let mut tar = tar::Builder::new(io::stdout().lock());
            append_volume_tree(&mut tar, &mountpoint, vol.uid, vol.gid)?;
            tar.finish()?;
            return Ok(None);
        }

        let out_path = output
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from(format!("{}.tar", name)));

        if let Some(parent) = out_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let file = File::create(&out_path)?;
        let mut tar = tar::Builder::new(file);
        append_volume_tree(&mut tar, &mountpoint, vol.uid, vol.gid)?;
        tar.finish()?;

        Ok(Some(out_path))
    }

    pub fn import_volume(name: &str, input: &str) -> Result<VolumeRecord> {
        if input != "-" && !Path::new(input).exists() {
            return Err(anyhow!("open {}: no such file or directory", input));
        }

        let store = VolumeStore::new();
        let vol = store
            .find(name)
            .ok_or_else(|| anyhow!("no volume with name \"{}\" found: no such volume", name))?;

        let mountpoint = PathBuf::from(&vol.mountpoint);
        fs::create_dir_all(&mountpoint)?;

        let reader: Box<dyn io::Read> = if input == "-" {
            Box::new(stdin().lock())
        } else {
            Box::new(File::open(input)?)
        };

        let mut archive = tar::Archive::new(reader);
        let mut root_uid_gid: Option<(u32, u32)> = None;
        let mut root_mode: Option<u32> = None;
        if let Ok(entries) = archive.entries() {
            for entry_res in entries {
                let Ok(mut entry) = entry_res else {
                    continue;
                };
                if let (Ok(u), Ok(g)) = (entry.header().uid(), entry.header().gid()) {
                    if u != 0 || g != 0 {
                        root_uid_gid = Some((u as u32, g as u32));
                    }
                }
                if let Ok(m) = entry.header().mode() {
                    let mode = m & 0o7777;
                    if mode == 0o750 || (root_uid_gid.is_some() && root_mode.is_none()) {
                        root_mode = Some(mode);
                    }
                }
                let _ = entry.unpack_in(&mountpoint);
            }
        }
        #[cfg(unix)]
        if let Some(m) = root_mode {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&mountpoint, fs::Permissions::from_mode(m));
        }
        if let Some((u, g)) = root_uid_gid {
            let _ = store.set_volume_uid_gid(name, Some(u), Some(g));
            let _ = store.set_volume_copy_flags(name, false, false);
        }

        Ok(vol)
    }

    pub fn reload_volume(name: Option<&str>) -> Result<Vec<VolumeRecord>> {
        let store = VolumeStore::new();
        let vols = store.list();
        if let Some(n) = name {
            let found = vols.into_iter().filter(|v| v.name == n).collect::<Vec<_>>();
            if found.is_empty() {
                return Err(anyhow!("Volume '{}' not found", n));
            }
            Ok(found)
        } else {
            Ok(vols)
        }
    }

    pub fn rename_volume(old_name: &str, new_name: &str) -> Result<VolumeRecord> {
        VolumeStore::new().rename(old_name, new_name)
    }

    pub fn mount_volume(name: &str) -> Result<String> {
        #[cfg(unix)]
        if unsafe { libc::getuid() != 0 } {
            crate::cli::usage_errors::exit_usage_error(
                "cannot run command \"podman volume mount\" in rootless mode, must execute `podman unshare` first",
            );
        }
        let store = VolumeStore::new();
        let vol = store
            .find(name)
            .ok_or_else(|| anyhow!("Volume '{}' not found", name))?;

        let mountpoint = PathBuf::from(&vol.mountpoint);
        fs::create_dir_all(&mountpoint)?;
        let canonical = mountpoint.canonicalize()?;
        Ok(canonical.to_string_lossy().to_string())
    }

    pub fn unmount_volume(name: &str) -> Result<String> {
        let store = VolumeStore::new();
        let _ = store
            .find(name)
            .ok_or_else(|| anyhow!("Volume '{}' not found", name))?;
        Ok(name.to_string())
    }
}
