//! Extended volume operations (export, import, reload, rename, mount, unmount).

use crate::storage::boxr_home;
use crate::volume::{VolumeRecord, VolumeStore};
use anyhow::{Result, anyhow};
use std::fs::{self, File};
use std::io::{self, stdin};
use std::path::{Path, PathBuf};

pub struct VolumeOps;

fn append_volume_tree<W: io::Write>(tar: &mut tar::Builder<W>, mountpoint: &Path) -> Result<()> {
    for entry in fs::read_dir(mountpoint)? {
        let path = entry?.path();
        if path.is_file() {
            let name = path
                .file_name()
                .map(|n| n.to_owned())
                .unwrap_or_default();
            tar.append_path_with_name(&path, name)?;
        } else if path.is_dir() {
            let prefix = path
                .file_name()
                .map(|n| n.to_owned())
                .unwrap_or_default();
            for sub in fs::read_dir(&path)? {
                let subpath = sub?.path();
                if subpath.is_file() {
                    let rel = format!(
                        "{}/{}",
                        prefix.to_string_lossy(),
                        subpath.file_name().unwrap_or_default().to_string_lossy()
                    );
                    tar.append_path_with_name(&subpath, rel)?;
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
            .ok_or_else(|| anyhow!("Volume '{}' not found", name))?;

        let mountpoint = PathBuf::from(&vol.mountpoint);
        if !mountpoint.exists() {
            return Err(anyhow!("Volume mountpoint does not exist on disk"));
        }

        if output.is_none() {
            let mut tar = tar::Builder::new(io::stdout().lock());
            append_volume_tree(&mut tar, &mountpoint)?;
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
        append_volume_tree(&mut tar, &mountpoint)?;
        tar.finish()?;

        Ok(Some(out_path))
    }

    pub fn import_volume(name: &str, input: &str) -> Result<VolumeRecord> {
        if input != "-" && !Path::new(input).exists() {
            return Err(anyhow!("Import file '{}' not found", input));
        }

        let store = VolumeStore::new();
        let vol = if let Some(v) = store.find(name) {
            v
        } else {
            store.create(Some(name), None)?
        };

        let mountpoint = PathBuf::from(&vol.mountpoint);
        fs::create_dir_all(&mountpoint)?;

        if input == "-" {
            let mut archive = tar::Archive::new(stdin());
            archive.unpack(&mountpoint)?;
        } else {
            let file = File::open(input)?;
            let mut archive = tar::Archive::new(file);
            archive.unpack(&mountpoint)?;
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
        let store = VolumeStore::new();
        let vol = store
            .find(old_name)
            .ok_or_else(|| anyhow!("Volume '{}' not found", old_name))?;

        if store.find(new_name).is_some() {
            return Err(anyhow!("Volume '{}' already exists", new_name));
        }

        let old_dir = PathBuf::from(&vol.mountpoint);
        let new_dir = boxr_home().join("volumes").join(new_name).join("_data");
        if let Some(parent) = new_dir.parent() {
            fs::create_dir_all(parent)?;
        }

        if old_dir.exists() {
            fs::rename(&old_dir, &new_dir)?;
            let _ = fs::remove_dir(old_dir.parent().unwrap_or(&old_dir));
        } else {
            fs::create_dir_all(&new_dir)?;
        }

        store.remove(old_name)?;
        let new_rec = store.create_with_options(
            Some(new_name),
            &vol.driver,
            Some(vol.labels.clone()),
            &vol.scope,
            Some(vol.options.clone()),
        )?;

        Ok(new_rec)
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
