use anyhow::{Result, anyhow};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiffChangeType {
    Changed,
    Added,
    Deleted,
}

impl std::fmt::Display for DiffChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiffChangeType::Changed => write!(f, "C"),
            DiffChangeType::Added => write!(f, "A"),
            DiffChangeType::Deleted => write!(f, "D"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiffRecord {
    pub change_type: DiffChangeType,
    pub path: String,
}

pub struct FilesystemDiff;

impl FilesystemDiff {
    fn is_internal_ignored(rel_str: &str, file_name: &str, is_top_level: bool) -> bool {
        if is_top_level && (file_name == "proc" || file_name == "sys" || file_name == "dev") {
            return true;
        }
        if is_top_level
            && (file_name == "libboxr_perm.so"
                || file_name == "libboxr_perm_x86_64.so"
                || file_name == "boxr-busybox"
                || file_name == "boxr-init.sh"
                || file_name == "boxr-run.sh"
                || file_name == "boxr-exitcode"
                || file_name == "logs.txt"
                || file_name.starts_with("boxr-exec-"))
        {
            return true;
        }
        rel_str == "/.containerenv"
            || rel_str == "/run/.containerenv"
            || rel_str == "/.oldroot"
            || rel_str == "/etc/resolv.conf"
            || rel_str == "/etc/hosts"
            || rel_str == "/etc/hostname"
    }

    fn record_parent_changed(rel_path: &Path, changed_dirs: &mut HashSet<String>) {
        let mut current = rel_path.parent();
        while let Some(parent) = current {
            let parent_str = parent.to_string_lossy();
            if !parent_str.is_empty() {
                changed_dirs.insert(format!("/{}", parent_str));
            }
            current = parent.parent();
        }
    }

    /// Compare container rootfs (or upperdir) against base rootfs
    pub fn compare(base_rootfs: &Path, container_rootfs: &Path) -> Result<Vec<DiffRecord>> {
        let mut diffs = Vec::new();
        let mut seen_base_files = HashSet::new();
        let mut changed_dirs = HashSet::new();

        if !container_rootfs.exists() {
            return Err(anyhow!(
                "Container rootfs not found at {:?}",
                container_rootfs
            ));
        }

        Self::walk_and_compare(
            container_rootfs,
            container_rootfs,
            base_rootfs,
            &mut diffs,
            &mut seen_base_files,
            &mut changed_dirs,
        )?;

        if base_rootfs.exists() {
            Self::check_deleted_from_base(
                base_rootfs,
                base_rootfs,
                container_rootfs,
                &mut diffs,
                &seen_base_files,
                &mut changed_dirs,
            )?;
        }

        for dir in changed_dirs {
            if !diffs.iter().any(|d| d.path == dir) {
                diffs.push(DiffRecord {
                    change_type: DiffChangeType::Changed,
                    path: dir,
                });
            }
        }

        diffs.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(diffs)
    }

    fn walk_and_compare(
        current_dir: &Path,
        root_dir: &Path,
        base_dir: &Path,
        diffs: &mut Vec<DiffRecord>,
        seen_base: &mut HashSet<PathBuf>,
        changed_dirs: &mut HashSet<String>,
    ) -> Result<()> {
        for entry in fs::read_dir(current_dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let is_top = current_dir == root_dir;

            let rel_path = path.strip_prefix(root_dir)?;
            let rel_str = format!("/{}", rel_path.to_string_lossy());

            if Self::is_internal_ignored(&rel_str, file_name, is_top) {
                if rel_str == "/etc/hostname"
                    && base_dir.exists()
                    && !base_dir.join(rel_path).exists()
                {
                    Self::record_parent_changed(rel_path, changed_dirs);
                }
                continue;
            }

            // Check for OCI whiteout file
            if let Some(deleted_name) = file_name.strip_prefix(".wh.") {
                let deleted_rel = rel_path
                    .parent()
                    .unwrap_or(Path::new(""))
                    .join(deleted_name);
                diffs.push(DiffRecord {
                    change_type: DiffChangeType::Deleted,
                    path: format!("/{}", deleted_rel.to_string_lossy()),
                });
                Self::record_parent_changed(&deleted_rel, changed_dirs);
                continue;
            }

            seen_base.insert(rel_path.to_path_buf());
            let base_equiv = base_dir.join(rel_path);

            let base_meta = fs::symlink_metadata(&base_equiv);
            if base_meta.is_err() {
                diffs.push(DiffRecord {
                    change_type: DiffChangeType::Added,
                    path: rel_str.clone(),
                });
                Self::record_parent_changed(rel_path, changed_dirs);
            } else {
                let base_meta = base_meta.unwrap();
                let cont_meta = fs::symlink_metadata(&path)?;

                if cont_meta.file_type().is_symlink() || base_meta.file_type().is_symlink() {
                    if cont_meta.file_type() != base_meta.file_type() {
                        diffs.push(DiffRecord {
                            change_type: DiffChangeType::Changed,
                            path: rel_str.clone(),
                        });
                        Self::record_parent_changed(rel_path, changed_dirs);
                    } else if let (Ok(t1), Ok(t2)) =
                        (fs::read_link(&path), fs::read_link(&base_equiv))
                    {
                        if t1 != t2 {
                            diffs.push(DiffRecord {
                                change_type: DiffChangeType::Changed,
                                path: rel_str.clone(),
                            });
                            Self::record_parent_changed(rel_path, changed_dirs);
                        }
                    }
                } else if cont_meta.file_type().is_file() && base_meta.file_type().is_file() {
                    #[cfg(unix)]
                    let same_inode = {
                        use std::os::unix::fs::MetadataExt;
                        cont_meta.ino() == base_meta.ino() && cont_meta.dev() == base_meta.dev()
                    };
                    #[cfg(not(unix))]
                    let same_inode = false;

                    if !same_inode {
                        let mut is_different = cont_meta.len() != base_meta.len();
                        #[cfg(unix)]
                        if !is_different {
                            use std::os::unix::fs::MetadataExt;
                            if (cont_meta.mode() & 0o7777) != (base_meta.mode() & 0o7777) {
                                is_different = true;
                            }
                        }
                        if !is_different {
                            if let (Ok(c1), Ok(c2)) = (fs::read(&path), fs::read(&base_equiv)) {
                                if c1 != c2 {
                                    is_different = true;
                                }
                            }
                        }
                        if is_different {
                            diffs.push(DiffRecord {
                                change_type: DiffChangeType::Changed,
                                path: rel_str.clone(),
                            });
                            Self::record_parent_changed(rel_path, changed_dirs);
                        }
                    }
                } else if cont_meta.file_type().is_dir() && base_meta.file_type().is_dir() {
                    // Directories are marked Changed via record_parent_changed when children are modified
                }
            }

            if path.is_dir() && !path.is_symlink() {
                Self::walk_and_compare(
                    &path,
                    root_dir,
                    base_dir,
                    diffs,
                    seen_base,
                    changed_dirs,
                )?;
            }
        }
        Ok(())
    }

    fn check_deleted_from_base(
        current_dir: &Path,
        base_root: &Path,
        container_root: &Path,
        diffs: &mut Vec<DiffRecord>,
        seen: &HashSet<PathBuf>,
        changed_dirs: &mut HashSet<String>,
    ) -> Result<()> {
        for entry in fs::read_dir(current_dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let is_top = current_dir == base_root;

            let rel_path = path.strip_prefix(base_root)?;
            let rel_str = format!("/{}", rel_path.to_string_lossy());

            if Self::is_internal_ignored(&rel_str, file_name, is_top) {
                continue;
            }

            if !seen.contains(rel_path)
                && fs::symlink_metadata(container_root.join(rel_path)).is_err()
            {
                if !diffs.iter().any(|d| d.path == rel_str) {
                    diffs.push(DiffRecord {
                        change_type: DiffChangeType::Deleted,
                        path: rel_str.clone(),
                    });
                    Self::record_parent_changed(rel_path, changed_dirs);
                }
            }

            if path.is_dir() && !path.is_symlink() {
                Self::check_deleted_from_base(
                    &path,
                    base_root,
                    container_root,
                    diffs,
                    seen,
                    changed_dirs,
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_filesystem_diff() -> Result<()> {
        let temp = tempdir().unwrap();
        let base = temp.path().join("base");
        let container = temp.path().join("container");

        fs::create_dir_all(&base)?;
        fs::create_dir_all(&container)?;

        // Common file
        fs::write(base.join("common.txt"), b"v1")?;
        fs::write(container.join("common.txt"), b"v2")?;

        // Added file
        fs::write(container.join("new.txt"), b"new")?;

        // Deleted file
        fs::write(base.join("old.txt"), b"old")?;

        // Nested dev directory (should NOT be skipped like root /dev)
        let nested_dev = container.join("app").join("dev");
        fs::create_dir_all(&nested_dev)?;
        fs::write(nested_dev.join("config.json"), b"nested dev content")?;

        // Injected hypervisor runtime files (should be filtered out)
        fs::write(container.join("libboxr_perm.so"), b"bin")?;
        fs::write(container.join("boxr-run.sh"), b"sh")?;

        let diffs = FilesystemDiff::compare(&base, &container).unwrap();
        assert!(
            !diffs
                .iter()
                .any(|d| d.path == "/libboxr_perm.so" || d.path == "/boxr-run.sh"),
            "Injected runtime scaffolding must be filtered from diff"
        );
        assert!(
            diffs
                .iter()
                .any(|d| d.change_type == DiffChangeType::Changed && d.path == "/common.txt")
        );
        assert!(
            diffs
                .iter()
                .any(|d| d.change_type == DiffChangeType::Added && d.path == "/new.txt")
        );
        assert!(
            diffs
                .iter()
                .any(|d| d.change_type == DiffChangeType::Deleted && d.path == "/old.txt")
        );
        assert!(
            diffs
                .iter()
                .any(|d| d.change_type == DiffChangeType::Added && d.path == "/app/dev/config.json"),
            "Nested directories named dev must not be skipped"
        );

        Ok(())
    }
}
