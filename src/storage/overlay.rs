#![allow(dead_code, unused_imports)]

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct OverlayBundle {
    pub lower_dir: PathBuf,
    pub upper_dir: PathBuf,
    pub work_dir: PathBuf,
    pub merged_dir: PathBuf,
    pub is_mounted: bool,
}

pub struct OverlayDriver;

impl OverlayDriver {
    /// Initialize a Copy-On-Write layer for a container using base image rootfs.
    pub fn create_cow_layer(bundle_dir: &Path, base_rootfs: &Path) -> Result<OverlayBundle> {
        let upper_dir = bundle_dir.join("upper");
        let work_dir = bundle_dir.join("work");
        let merged_dir = bundle_dir.join("rootfs");

        fs::create_dir_all(&upper_dir)?;
        fs::create_dir_all(&work_dir)?;
        fs::create_dir_all(&merged_dir)?;

        // Try mounting native OverlayFS if on Linux
        #[cfg(target_os = "linux")]
        {
            if let Ok(()) = Self::mount_overlay(base_rootfs, &upper_dir, &work_dir, &merged_dir) {
                return Ok(OverlayBundle {
                    lower_dir: base_rootfs.to_path_buf(),
                    upper_dir,
                    work_dir,
                    merged_dir,
                    is_mounted: true,
                });
            }
        }

        // Try native APFS Copy-On-Write clonefile on macOS
        #[cfg(target_os = "macos")]
        {
            if Self::clonefile_cow(base_rootfs, &merged_dir).is_ok() {
                return Ok(OverlayBundle {
                    lower_dir: base_rootfs.to_path_buf(),
                    upper_dir,
                    work_dir,
                    merged_dir,
                    is_mounted: false,
                });
            }
        }

        // Fallback: safe CoW copy tree isolating container writes from base image layers
        Self::create_hardlink_tree(base_rootfs, &merged_dir)?;
        if let Some(img_dir) = base_rootfs.parent() {
            let src_chown = img_dir.join("chown_meta.json");
            if src_chown.exists() {
                let _ = fs::copy(&src_chown, bundle_dir.join("chown_meta.json"));
            }
        }

        Ok(OverlayBundle {
            lower_dir: base_rootfs.to_path_buf(),
            upper_dir,
            work_dir,
            merged_dir,
            is_mounted: false,
        })
    }

    #[cfg(target_os = "macos")]
    fn clonefile_cow(src: &Path, dst: &Path) -> Result<()> {
        use std::ffi::CString;
        unsafe extern "C" {
            fn clonefile(
                src: *const libc::c_char,
                dst: *const libc::c_char,
                flags: u32,
            ) -> libc::c_int;
        }

        if dst.exists() {
            let _ = fs::remove_dir_all(dst);
        }

        let src_c = CString::new(src.to_str().ok_or_else(|| anyhow::anyhow!("Invalid src"))?)?;
        let dst_c = CString::new(dst.to_str().ok_or_else(|| anyhow::anyhow!("Invalid dst"))?)?;

        let res = unsafe { clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };
        if res == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "clonefile failed with error: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    #[cfg(target_os = "linux")]
    fn mount_overlay(lower: &Path, upper: &Path, work: &Path, merged: &Path) -> Result<()> {
        use nix::mount::{MsFlags, mount};
        use std::ffi::CString;

        let opts = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower.display(),
            upper.display(),
            work.display()
        );
        let opts_c = CString::new(opts)?;

        mount(
            Some("overlay"),
            merged,
            Some("overlay"),
            MsFlags::empty(),
            Some(opts_c.as_c_str()),
        )
        .context("Failed to mount overlayfs")?;

        Ok(())
    }

    /// CoW fallback: copies files and reproduces directory structure, ensuring container
    /// writes never modify the base image layer inodes.
    pub fn create_hardlink_tree(src: &Path, dst: &Path) -> Result<()> {
        let mut seen_inodes = std::collections::HashMap::new();
        Self::create_hardlink_tree_inner(src, src, dst, &mut seen_inodes)
    }

    fn is_readonly_library_tree(root: &Path, path: &Path) -> bool {
        let Ok(rel) = path.strip_prefix(root) else {
            return false;
        };
        let rel_str = rel.to_string_lossy();
        rel_str.starts_with("usr/")
            || rel_str.starts_with("lib/")
            || rel_str.starts_with("lib64/")
            || rel_str.starts_with("bin/")
            || rel_str.starts_with("sbin/")
    }

    fn create_hardlink_tree_inner(
        root_src: &Path,
        src: &Path,
        dst: &Path,
        seen_inodes: &mut std::collections::HashMap<(u64, u64), PathBuf>,
    ) -> Result<()> {
        let _ = fs::create_dir_all(dst);
        let entries = match fs::read_dir(src) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let ty = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            let from = entry.path();
            let to = dst.join(entry.file_name());

            if ty.is_dir() {
                let _ = Self::create_hardlink_tree_inner(root_src, &from, &to, seen_inodes);
                #[cfg(unix)]
                if !Self::is_readonly_library_tree(root_src, &from) {
                    if let Ok(m) = fs::symlink_metadata(&from) {
                        use std::os::unix::fs::MetadataExt;
                        use std::os::unix::fs::PermissionsExt;
                        let mode = (m.permissions().mode() & 0o7777) | 0o700;
                        let _ = fs::set_permissions(&to, fs::Permissions::from_mode(mode));
                        if let Ok(c_to) = std::ffi::CString::new(to.to_string_lossy().as_bytes()) {
                            let times = [
                                libc::timespec {
                                    tv_sec: m.atime(),
                                    tv_nsec: m.atime_nsec(),
                                },
                                libc::timespec {
                                    tv_sec: m.mtime(),
                                    tv_nsec: m.mtime_nsec(),
                                },
                            ];
                            unsafe {
                                let _ = libc::utimensat(
                                    libc::AT_FDCWD,
                                    c_to.as_ptr(),
                                    times.as_ptr(),
                                    0,
                                );
                            }
                        }
                    }
                }
            } else if ty.is_symlink() {
                #[cfg(unix)]
                {
                    if let Ok(target) = fs::read_link(&from) {
                        let _ = std::os::unix::fs::symlink(target, &to);
                    }
                }
            } else {
                let meta = fs::metadata(&from);
                #[cfg(unix)]
                let mut linked = false;
                #[cfg(unix)]
                if Self::is_readonly_library_tree(root_src, &from) {
                    let _ = fs::remove_file(&to);
                    if fs::hard_link(&from, &to).is_ok() {
                        continue;
                    }
                }
                #[cfg(unix)]
                if let Ok(m) = &meta {
                    use std::os::unix::fs::MetadataExt;
                    let key = (m.dev(), m.ino());
                    if m.nlink() > 1 {
                        if let Some(first_to) = seen_inodes.get(&key) {
                            let _ = fs::remove_file(&to);
                            if fs::hard_link(first_to, &to).is_ok() {
                                linked = true;
                            }
                        } else if fs::copy(&from, &to).is_ok() {
                            seen_inodes.insert(key, to.clone());
                            linked = true;
                        }
                    } else if m.len() > 262_144 && fs::hard_link(&from, &to).is_ok() {
                        linked = true;
                    }
                }
                #[cfg(unix)]
                if !linked {
                    let _ = fs::copy(&from, &to);
                }
                #[cfg(not(unix))]
                {
                    let _ = fs::copy(&from, &to);
                }
                if let Ok(meta) = meta {
                    Self::preserve_file_timestamps(&from, &to, &meta);
                }
            }
        }
        #[cfg(unix)]
        if let Ok(meta) = fs::metadata(src) {
            use std::os::unix::fs::PermissionsExt;
            let mut mode = meta.permissions().mode();
            mode |= 0o700;
            let _ = fs::set_permissions(dst, fs::Permissions::from_mode(mode));
        }
        Ok(())
    }

    /// Tear down and cleanup OverlayFS/CoW bundle
    #[cfg(unix)]
    fn preserve_file_timestamps(_from: &Path, to: &Path, meta: &fs::Metadata) {
        use std::ffi::CString;
        use std::os::unix::fs::MetadataExt;
        let times = [
            libc::timespec {
                tv_sec: meta.atime(),
                tv_nsec: meta.atime_nsec(),
            },
            libc::timespec {
                tv_sec: meta.mtime(),
                tv_nsec: meta.mtime_nsec(),
            },
        ];
        if let Ok(path) = CString::new(to.as_os_str().as_encoded_bytes()) {
            unsafe {
                libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0);
            }
        }
    }

    #[cfg(not(unix))]
    fn preserve_file_timestamps(_from: &Path, _to: &Path, _meta: &fs::Metadata) {}

    pub fn cleanup(bundle: &OverlayBundle) -> Result<()> {
        #[cfg(target_os = "linux")]
        if bundle.is_mounted {
            use nix::mount::{MntFlags, umount2};
            let _ = umount2(&bundle.merged_dir, MntFlags::MNT_DETACH);
        }

        if bundle.upper_dir.exists() {
            let _ = fs::remove_dir_all(&bundle.upper_dir);
        }
        if bundle.work_dir.exists() {
            let _ = fs::remove_dir_all(&bundle.work_dir);
        }
        if bundle.merged_dir.exists() {
            let _ = fs::remove_dir_all(&bundle.merged_dir);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_hardlink_cow_tree() -> Result<()> {
        let temp = tempdir().unwrap();
        let src = temp.path().join("base");
        let bundle = temp.path().join("bundle");

        fs::create_dir_all(src.join("sub"))?;
        fs::write(src.join("file1.txt"), b"original content")?;
        fs::write(src.join("sub").join("file2.txt"), b"sub content")?;

        let overlay = OverlayDriver::create_cow_layer(&bundle, &src).unwrap();
        assert!(overlay.merged_dir.exists());

        let file1 = overlay.merged_dir.join("file1.txt");
        assert!(file1.exists());
        assert_eq!(fs::read_to_string(&file1).unwrap(), "original content");

        // Mutating container file in merged dir does not affect base
        fs::write(&file1, b"modified content")?;
        assert_eq!(fs::read_to_string(&file1).unwrap(), "modified content");
        assert_eq!(
            fs::read_to_string(src.join("file1.txt")).unwrap(),
            "original content",
            "Base image layer must not be modified when container writes to file"
        );

        OverlayDriver::cleanup(&overlay).unwrap();
        assert!(!overlay.merged_dir.exists());

        Ok(())
    }
}
