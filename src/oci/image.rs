use anyhow::{Context, Result, anyhow};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Archive;

/// Known OCI and Docker media types
#[allow(dead_code)]
pub mod media_types {
    pub const OCI_INDEX_V1: &str = "application/vnd.oci.image.index.v1+json";
    pub const OCI_MANIFEST_V1: &str = "application/vnd.oci.image.manifest.v1+json";
    pub const OCI_IMAGE_CONFIG_V1: &str = "application/vnd.oci.image.config.v1+json";
    pub const OCI_LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
    pub const OCI_LAYER_TAR_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

    pub const DOCKER_MANIFEST_LIST_V2: &str =
        "application/vnd.docker.distribution.manifest.list.v2+json";
    pub const DOCKER_MANIFEST_V2: &str = "application/vnd.docker.distribution.manifest.v2+json";
    pub const DOCKER_CONTAINER_IMAGE_V1: &str = "application/vnd.docker.container.image.v1+json";
    pub const DOCKER_LAYER_TAR_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Platform {
    pub architecture: String,
    pub os: String,
    #[serde(rename = "os.version", skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Descriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
}

/// Returns true when a manifest-list descriptor points at a runnable container image
/// (not an attestation, provenance, or other artifact manifest).
pub fn is_runnable_image_descriptor(desc: &Descriptor) -> bool {
    let mt = desc.media_type.to_ascii_lowercase();
    if mt.contains("attestation") || mt.contains("provenance") {
        return false;
    }

    if let Some(annotations) = &desc.annotations {
        for (key, value) in annotations {
            let key_l = key.to_ascii_lowercase();
            let val_l = value.to_ascii_lowercase();
            if key_l.contains("reference.type") && val_l.contains("attestation") {
                return false;
            }
            if key_l.contains("artifacttype") && val_l.contains("attestation") {
                return false;
            }
        }
    }

    if let Some(platform) = &desc.platform {
        let os = platform.os.to_ascii_lowercase();
        let arch = platform.architecture.to_ascii_lowercase();
        if os == "unknown" || arch == "unknown" {
            return false;
        }
        if os != "linux" {
            return false;
        }
    }

    matches!(
        mt.as_str(),
        media_types::OCI_MANIFEST_V1 | media_types::DOCKER_MANIFEST_V2
    ) || mt.contains("image.manifest")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestListOrIndex {
    #[serde(rename = "schemaVersion")]
    pub schema_version: i32,
    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub manifests: Vec<Descriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: i32,
    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutionConfig {
    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(rename = "Env", skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    #[serde(rename = "Entrypoint", skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd", skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    #[serde(rename = "WorkingDir", skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
    #[serde(rename = "Volumes", skip_serializing_if = "Option::is_none")]
    pub volumes: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "ExposedPorts", skip_serializing_if = "Option::is_none")]
    pub exposed_ports: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "Healthcheck", skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<crate::health::HealthConfig>,
    #[serde(rename = "StopSignal", skip_serializing_if = "Option::is_none")]
    pub stop_signal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootFsConfig {
    #[serde(rename = "type")]
    pub fs_type: String,
    pub diff_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HistoryEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub empty_layer: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageConfig {
    pub architecture: String,
    pub os: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<ExecutionConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<RootFsConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<HistoryEntry>,
}

/// Unpacks a layer archive (.tar or .tar.gz) into a target rootfs directory.
/// Accurately handles OCI whiteout files:
/// - `.wh..wh..opq`: Opaque whiteout, marks parent directory as opaque (clears existing entries in destination)
/// - `.wh.<name>`: Explicit whiteout, indicates that `<name>` in the same directory should be removed.
pub fn unpack_layer(layer_archive_path: &Path, target_dir: &Path) -> Result<()> {
    fs::create_dir_all(target_dir)
        .with_context(|| format!("Failed to create target rootfs directory: {:?}", target_dir))?;

    let file = File::open(layer_archive_path)
        .with_context(|| format!("Failed to open layer archive: {:?}", layer_archive_path))?;

    // Check if gzipped by reading first 2 bytes (0x1f, 0x8b)
    let mut header = [0u8; 2];
    let mut reader: Box<dyn Read> = {
        let mut f = File::open(layer_archive_path)?;
        let n = f.read(&mut header).unwrap_or(0);
        if n == 2 && header[0] == 0x1f && header[1] == 0x8b {
            Box::new(GzDecoder::new(file))
        } else {
            Box::new(file)
        }
    };

    let mut archive = Archive::new(&mut reader);
    // Don't unpack entries that match whiteout markers directly as regular files
    let mut pending_whiteouts: Vec<PathBuf> = Vec::new();
    let canon_target = target_dir.canonicalize()?;

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let entry_path = entry.path()?.to_path_buf();

        // Reject absolute paths, root directories, drive prefixes, or '..' escaping target_dir
        for comp in entry_path.components() {
            if matches!(
                comp,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            ) {
                return Err(anyhow!(
                    "Tar-slip path traversal rejected in layer entry: {:?}",
                    entry_path
                ));
            }
        }

        let file_name = entry_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        if file_name == ".wh..wh..opq" {
            // Opaque whiteout: clear previous content in this directory
            if let Some(parent) = entry_path.parent() {
                let dest_parent = target_dir.join(parent);
                if dest_parent.exists() {
                    let canon_parent = dest_parent.canonicalize()?;
                    if !canon_parent.starts_with(&canon_target) {
                        return Err(anyhow!(
                            "Whiteout path escapes target directory: {:?}",
                            entry_path
                        ));
                    }
                    for dir_entry in fs::read_dir(&dest_parent)? {
                        let path = dir_entry?.path();
                        if path.is_dir() {
                            let _ = fs::remove_dir_all(&path);
                        } else {
                            let _ = fs::remove_file(&path);
                        }
                    }
                }
            }
            continue;
        }

        if let Some(stripped_wh) = file_name.strip_prefix(".wh.") {
            if stripped_wh.contains('/') || stripped_wh.contains('\\') || stripped_wh.contains("..")
            {
                return Err(anyhow!(
                    "Invalid whiteout target filename: {:?}",
                    stripped_wh
                ));
            }
            // Explicit whiteout: remove corresponding file/folder in parent
            if let Some(parent) = entry_path.parent() {
                let to_remove = target_dir.join(parent).join(stripped_wh);
                let dest_parent = target_dir.join(parent);
                if dest_parent.exists() {
                    let canon_parent = dest_parent.canonicalize()?;
                    if !canon_parent.starts_with(&canon_target) {
                        return Err(anyhow!(
                            "Whiteout path escapes target directory: {:?}",
                            entry_path
                        ));
                    }
                }
                pending_whiteouts.push(to_remove);
            }
            continue;
        }

        // Normal file unpacking
        let dest = target_dir.join(&entry_path);
        // Ensure parent directory exists and has write permissions
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(p) {
                    let mut perms = meta.permissions();
                    let mode = perms.mode();
                    if mode & 0o700 != 0o700 {
                        perms.set_mode(mode | 0o755);
                        let _ = fs::set_permissions(p, perms);
                    }
                }
            }
        }

        // Unpack entry safely
        let _is_dir = entry.header().entry_type().is_dir();
        if let Err(e) = entry.unpack_in(target_dir) {
            // On non-root platforms (like macOS), some chown/mknod operations in tar might fail.
            // In that case, fallback to manually extracting content.
            if !dest.exists() {
                eprintln!(
                    "Direct unpack warning ({}), attempting fallback: {:?}",
                    e, dest
                );
            }
        }

        // Restore original permissions from tar header (including sticky bit and world-write permissions)
        #[cfg(unix)]
        if dest.exists() {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(header_mode) = entry.header().mode() {
                let mut target_mode = header_mode;
                if _is_dir && (target_mode & 0o700 != 0o700) {
                    target_mode |= 0o755;
                }
                let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(target_mode));
            }
        }
    }

    // Apply pending whiteout removals
    for wh in pending_whiteouts {
        if wh.exists() || fs::symlink_metadata(&wh).is_ok() {
            if let Ok(canon_wh) = wh.canonicalize() {
                if !canon_wh.starts_with(&canon_target) {
                    continue; // Skip any unsafe path outside target_dir
                }
            }
            if wh.is_dir() {
                let _ = fs::remove_dir_all(&wh);
            } else {
                let _ = fs::remove_file(&wh);
            }
        }
    }

    Ok(())
}

/// Safely unpack a tar archive into a target directory, preventing tar-slip path traversal.
pub fn unpack_archive_safely<R: Read>(
    archive: &mut tar::Archive<R>,
    target_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(target_dir)?;
    let canon_target = target_dir.canonicalize()?;

    for entry_res in archive.entries()? {
        let mut entry = entry_res?;
        let entry_path = entry.path()?.to_path_buf();

        // Reject absolute paths, root directories, drive prefixes, or '..' escaping target_dir
        for comp in entry_path.components() {
            if matches!(
                comp,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            ) {
                return Err(anyhow!(
                    "Tar-slip path traversal rejected in archive: {:?}",
                    entry_path
                ));
            }
        }

        let dest = target_dir.join(&entry_path);

        // If entry is a symlink, validate target doesn't escape target_dir
        if entry.header().entry_type().is_symlink() {
            if let Ok(Some(link_target)) = entry.link_name() {
                let target_path = link_target.as_ref();
                // Absolute symlink targets (e.g. /bin/sh -> /bin/busybox) are
                // common in container images. Resolve them relative to the
                // container rootfs (canon_target), not the host root.
                let resolved = if target_path.is_absolute() {
                    let mut r = canon_target.clone();
                    for comp in target_path.components() {
                        if let std::path::Component::Normal(c) = comp {
                            r.push(c);
                        }
                    }
                    r
                } else {
                    // Resolve symlink target relative to entry parent
                    let parent_dir = if let Some(parent) = entry_path.parent() {
                        canon_target.join(parent)
                    } else {
                        canon_target.clone()
                    };
                    let mut r = parent_dir;
                    for comp in target_path.components() {
                        match comp {
                            std::path::Component::Normal(c) => r.push(c),
                            std::path::Component::ParentDir => {
                                if !r.pop() || !r.starts_with(&canon_target) {
                                    return Err(anyhow!(
                                        "Tar-slip symlink escape rejected: target {:?} escapes {:?}",
                                        target_path,
                                        target_dir
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }
                    r
                };
                // Final check: resolved target must stay within the container rootfs.
                if !resolved.starts_with(&canon_target) {
                    return Err(anyhow!(
                        "Tar-slip symlink escape rejected: target {:?} escapes {:?}",
                        target_path,
                        target_dir
                    ));
                }
            }
        }

        // Validate that no existing ancestor of dest is a symlink resolving outside target_dir
        let mut curr = dest.as_path();
        while let Some(parent) = curr.parent() {
            if parent.exists() {
                let canon_parent = parent.canonicalize()?;
                if !canon_parent.starts_with(&canon_target) {
                    return Err(anyhow!(
                        "Tar-slip path traversal rejected: ancestor {:?} resolves outside target directory",
                        parent
                    ));
                }
                break;
            }
            curr = parent;
        }

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        entry.unpack_in(target_dir)?;

        // For symlinks, skip the canonicalize check: the target was already
        // validated above to stay within the container rootfs. Following the
        // symlink here would resolve against the host filesystem (e.g.
        // /etc/ssl/certs), incorrectly flagging legitimate container
        // absolute symlinks (issue #407).
        if !entry.header().entry_type().is_symlink() && dest.exists() {
            let canon_dest = dest.canonicalize()?;
            if !canon_dest.starts_with(&canon_target) {
                let _ = fs::remove_file(&dest);
                return Err(anyhow!(
                    "Archive entry escapes target directory: {:?}",
                    entry_path
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tempfile::tempdir;

    #[test]
    fn test_unpack_tar_gz_layer() {
        let temp = tempdir().unwrap();
        let archive_path = temp.path().join("layer.tar.gz");
        let dest_path = temp.path().join("rootfs");

        // Create a gzipped tar archive with a file
        let file = File::create(&archive_path).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = tar::Builder::new(encoder);

        let data = b"hello from layer";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "test.txt", &data[..])
            .unwrap();
        builder.finish().unwrap();
        let gz = builder.into_inner().unwrap();
        gz.finish().unwrap();

        // Unpack
        unpack_layer(&archive_path, &dest_path).unwrap();

        let extracted_file = dest_path.join("test.txt");
        assert!(extracted_file.exists());
        let content = fs::read_to_string(extracted_file).unwrap();
        assert_eq!(content, "hello from layer");
    }

    #[test]
    fn test_unpack_archive_safely_tar_slip_rejection() {
        let temp = tempdir().unwrap();
        let target_dir = temp.path().join("target");
        fs::create_dir_all(&target_dir).unwrap();

        let malicious_data = b"malicious content";
        let mut tar_bytes = Vec::new();
        let mut header = tar::Header::new_gnu();
        header.set_size(malicious_data.len() as u64);
        header.set_mode(0o644);
        let raw_bytes = header.as_mut_bytes();
        let name_bytes = b"../escaped.txt";
        raw_bytes[..name_bytes.len()].copy_from_slice(name_bytes);
        header.set_cksum();

        tar_bytes.extend_from_slice(header.as_bytes());
        tar_bytes.extend_from_slice(malicious_data);
        let padding = 512 - (malicious_data.len() % 512);
        if padding < 512 {
            tar_bytes.extend(std::iter::repeat(0).take(padding));
        }
        tar_bytes.extend(std::iter::repeat(0).take(1024));

        let mut archive = tar::Archive::new(&tar_bytes[..]);
        let res = unpack_archive_safely(&mut archive, &target_dir);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("Tar-slip path traversal rejected")
        );
        assert!(!temp.path().join("escaped.txt").exists());
    }

    #[test]
    fn test_unpack_layer_whiteout_traversal_rejection() {
        let temp = tempdir().unwrap();
        let target_dir = temp.path().join("target");
        fs::create_dir_all(&target_dir).unwrap();

        let _malicious_data = b"";
        let mut tar_bytes = Vec::new();
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        let raw_bytes = header.as_mut_bytes();
        let name_bytes = b"../../../../etc/.wh.shadow";
        raw_bytes[..name_bytes.len()].copy_from_slice(name_bytes);
        header.set_cksum();

        tar_bytes.extend_from_slice(header.as_bytes());
        tar_bytes.extend(std::iter::repeat(0).take(1024));

        let archive_path = temp.path().join("malicious_layer.tar");
        fs::write(&archive_path, tar_bytes).unwrap();

        let res = unpack_layer(&archive_path, &target_dir);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("Tar-slip path traversal rejected in layer entry")
        );
    }

    #[test]
    fn test_unpack_archive_safely_symlink_escape_rejection() {
        let temp = tempdir().unwrap();
        let target_dir = temp.path().join("target");
        fs::create_dir_all(&target_dir).unwrap();

        // Create an archive containing a symlink with relative path escaping outside target
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        // Relative symlink that escapes the target dir via ..
        let _ = header.set_link_name("../../etc");
        header.set_cksum();
        builder
            .append_data(&mut header, "a/evil_link", &[][..])
            .unwrap();
        let tar_bytes = builder.into_inner().unwrap();

        let mut archive = tar::Archive::new(&tar_bytes[..]);
        let res = unpack_archive_safely(&mut archive, &target_dir);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("Tar-slip symlink escape rejected")
        );
    }

    #[test]
    fn test_unpack_archive_safely_absolute_symlink_allowed() {
        // Absolute symlink targets (e.g. /bin/sh -> /bin/busybox) are common
        // in container images. They resolve within the container rootfs and
        // must be allowed (issue #407).
        let temp = tempdir().unwrap();
        let target_dir = temp.path().join("target");
        fs::create_dir_all(&target_dir).unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        let _ = header.set_link_name("/bin/busybox");
        header.set_cksum();
        builder.append_data(&mut header, "bin/sh", &[][..]).unwrap();
        let tar_bytes = builder.into_inner().unwrap();

        let mut archive = tar::Archive::new(&tar_bytes[..]);
        let res = unpack_archive_safely(&mut archive, &target_dir);
        assert!(res.is_ok());
    }

    #[test]
    fn test_unpack_archive_safely_benign_relative_symlink_allowed() {
        let temp = tempdir().unwrap();
        let target_dir = temp.path().join("target");
        fs::create_dir_all(&target_dir).unwrap();

        let mut builder = tar::Builder::new(Vec::new());

        let data = b"target content";
        let mut h1 = tar::Header::new_gnu();
        h1.set_size(data.len() as u64);
        h1.set_mode(0o644);
        h1.set_cksum();
        builder.append_data(&mut h1, "file.txt", &data[..]).unwrap();

        let mut h2 = tar::Header::new_gnu();
        h2.set_entry_type(tar::EntryType::Symlink);
        h2.set_size(0);
        h2.set_mode(0o777);
        h2.set_link_name("../file.txt").unwrap();
        h2.set_cksum();
        builder
            .append_data(&mut h2, "sub/link.txt", &[][..])
            .unwrap();

        let tar_bytes = builder.into_inner().unwrap();
        let mut archive = tar::Archive::new(&tar_bytes[..]);
        let res = unpack_archive_safely(&mut archive, &target_dir);
        assert!(
            res.is_ok(),
            "Benign relative symlink within target must succeed: {:?}",
            res
        );
    }

    #[test]
    fn test_is_runnable_image_descriptor_filters_attestations() {
        let image = Descriptor {
            media_type: media_types::OCI_MANIFEST_V1.to_string(),
            digest: "sha256:abc".to_string(),
            size: 100,
            platform: Some(Platform {
                architecture: "arm64".to_string(),
                os: "linux".to_string(),
                os_version: None,
                variant: None,
            }),
            annotations: None,
        };
        assert!(is_runnable_image_descriptor(&image));

        let attestation = Descriptor {
            media_type: media_types::OCI_MANIFEST_V1.to_string(),
            digest: "sha256:def".to_string(),
            size: 100,
            platform: Some(Platform {
                architecture: "unknown".to_string(),
                os: "unknown".to_string(),
                os_version: None,
                variant: None,
            }),
            annotations: Some(HashMap::from([(
                "vnd.docker.reference.type".to_string(),
                "attestation".to_string(),
            )])),
        };
        assert!(!is_runnable_image_descriptor(&attestation));
    }
}
