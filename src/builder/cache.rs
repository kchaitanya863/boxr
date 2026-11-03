use crate::storage::boxr_home;
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

#[derive(Debug, Clone)]
pub struct LayerCacheEntry {
    pub key: String,
    pub rootfs: PathBuf,
    pub size_bytes: u64,
    pub completed: bool,
}

static CACHE_REGISTRY: OnceLock<RwLock<HashMap<String, LayerCacheEntry>>> = OnceLock::new();

fn registry() -> &'static RwLock<HashMap<String, LayerCacheEntry>> {
    CACHE_REGISTRY.get_or_init(|| {
        let mut map = HashMap::new();
        let cache = BuildCache::cache_dir();
        if let Ok(entries) = fs::read_dir(&cache) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let key = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default()
                        .to_string();
                    if !key.starts_with('.') && path.join(".complete").exists() {
                        let rootfs = path.join("rootfs");
                        if rootfs.exists() {
                            map.insert(
                                key.clone(),
                                LayerCacheEntry {
                                    key,
                                    rootfs,
                                    size_bytes: 0,
                                    completed: true,
                                },
                            );
                        }
                    }
                }
            }
        }
        RwLock::new(map)
    })
}

pub struct BuildCache;

impl BuildCache {
    pub fn cache_dir() -> PathBuf {
        boxr_home().join("buildcache")
    }

    pub fn get(key: &str) -> Option<PathBuf> {
        // Fast in-memory lookup to avoid synchronous disk stats/reads
        if let Ok(reg) = registry().read() {
            if let Some(entry) = reg.get(key) {
                if entry.completed && entry.rootfs.exists() {
                    return Some(entry.rootfs.clone());
                }
            }
        }

        // Fallback to disk lookup if not resident in memory (or written externally)
        let key_dir = Self::cache_dir().join(key);
        let dir = key_dir.join("rootfs");
        if key_dir.join(".complete").exists() && dir.exists() {
            if let Ok(mut reg) = registry().write() {
                reg.insert(
                    key.to_string(),
                    LayerCacheEntry {
                        key: key.to_string(),
                        rootfs: dir.clone(),
                        size_bytes: 0,
                        completed: true,
                    },
                );
            }
            Some(dir)
        } else {
            None
        }
    }

    pub fn get_entry(key: &str) -> Option<LayerCacheEntry> {
        if let Some(rootfs) = Self::get(key) {
            let reg = registry().read().ok()?;
            reg.get(key).cloned().or_else(|| {
                Some(LayerCacheEntry {
                    key: key.to_string(),
                    rootfs,
                    size_bytes: 0,
                    completed: true,
                })
            })
        } else {
            None
        }
    }

    pub fn register(key: &str, rootfs: PathBuf) {
        if let Ok(mut reg) = registry().write() {
            reg.insert(
                key.to_string(),
                LayerCacheEntry {
                    key: key.to_string(),
                    rootfs,
                    size_bytes: 0,
                    completed: true,
                },
            );
        }
    }

    pub fn has(key: &str) -> bool {
        Self::get(key).is_some()
    }

    pub fn put(key: &str, rootfs: &Path) -> Result<()> {
        let cache = Self::cache_dir();
        fs::create_dir_all(&cache)?;
        let final_key_dir = cache.join(key);
        if final_key_dir.join(".complete").exists() {
            let final_rootfs = final_key_dir.join("rootfs");
            Self::register(key, final_rootfs);
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
        let final_rootfs = final_key_dir.join("rootfs");
        Self::register(key, final_rootfs);
        Ok(())
    }

    pub fn prune() -> Result<usize> {
        if let Ok(mut reg) = registry().write() {
            reg.clear();
        }
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

        // Avoid synchronous directory walks if already computed and resident
        if let Ok(reg) = registry().read() {
            if !reg.is_empty() && reg.values().all(|e| e.size_bytes > 0) {
                let count = reg.len();
                let total: u64 = reg.values().map(|e| e.size_bytes).sum();
                return Ok((count, total));
            }
        }

        let mut count = 0;
        let mut total_size = 0u64;
        let mut updates = Vec::new();
        for entry in fs::read_dir(&cache)? {
            let path = entry?.path();
            if path.is_dir() {
                let key = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default()
                    .to_string();
                if !key.starts_with('.') && path.join(".complete").exists() {
                    count += 1;
                    let sz = crate::system::dir_size(&path);
                    total_size += sz;
                    updates.push((key, path.join("rootfs"), sz));
                }
            }
        }
        if let Ok(mut reg) = registry().write() {
            for (k, rootfs, sz) in updates {
                reg.insert(
                    k.clone(),
                    LayerCacheEntry {
                        key: k,
                        rootfs,
                        size_bytes: sz,
                        completed: true,
                    },
                );
            }
        }
        Ok((count, total_size))
    }
}

pub fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        if !dst.exists() {
            if let (Ok(s), Ok(d)) = (
                CString::new(src.as_os_str().as_bytes()),
                CString::new(dst.as_os_str().as_bytes()),
            ) {
                if unsafe { libc::clonefile(s.as_ptr(), d.as_ptr(), 0) } == 0 {
                    return Ok(());
                }
            }
        }
    }

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
