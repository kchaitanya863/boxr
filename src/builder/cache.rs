use crate::storage::boxr_home;
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

pub struct BuildCache;

impl BuildCache {
    fn cache_dir() -> PathBuf {
        boxr_home().join("buildcache")
    }

    pub fn get(key: &str) -> Option<PathBuf> {
        let key_dir = Self::cache_dir().join(key);
        let dir = key_dir.join("rootfs");
        if key_dir.join(".complete").exists() && dir.exists() {
            Some(dir)
        } else {
            None
        }
    }

    pub fn put(key: &str, rootfs: &Path) -> Result<()> {
        let cache = Self::cache_dir();
        fs::create_dir_all(&cache)?;
        let final_key_dir = cache.join(key);
        if final_key_dir.join(".complete").exists() {
            return Ok(());
        }
        let tmp_key_dir = cache.join(format!(".tmp-{}-{}", key, std::process::id()));
        let _ = fs::remove_dir_all(&tmp_key_dir);
        let tmp_rootfs = tmp_key_dir.join("rootfs");
        fs::create_dir_all(&tmp_rootfs)?;
        copy_dir_all(rootfs, &tmp_rootfs)?;
        let _ = fs::write(tmp_key_dir.join(".complete"), b"1");
        if fs::rename(&tmp_key_dir, &final_key_dir).is_err() {
            let _ = fs::remove_dir_all(&tmp_key_dir);
        }
        Ok(())
    }

    pub fn prune() -> Result<usize> {
        let cache = Self::cache_dir();
        if cache.exists() {
            let mut count = 0;
            for entry in fs::read_dir(&cache)? {
                let path = entry?.path();
                if path.is_dir() {
                    let _ = fs::remove_dir_all(&path);
                    count += 1;
                }
            }
            Ok(count)
        } else {
            Ok(0)
        }
    }

    pub fn disk_usage() -> Result<(usize, u64)> {
        let cache = Self::cache_dir();
        if !cache.exists() {
            return Ok((0, 0));
        }

        let mut count = 0;
        let mut total_size = 0u64;
        for entry in fs::read_dir(&cache)? {
            let path = entry?.path();
            if path.is_dir() {
                count += 1;
                total_size += crate::system::dir_size(&path);
            }
        }
        Ok((count, total_size))
    }
}

pub fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());

        if ty.is_dir() {
            copy_dir_all(&from, &to)?;
        } else if ty.is_symlink() {
            #[cfg(unix)]
            {
                if let Ok(target) = fs::read_link(&from) {
                    let _ = std::os::unix::fs::symlink(target, &to);
                }
            }
        } else {
            let _ = fs::copy(&from, &to);
        }
    }
    Ok(())
}
