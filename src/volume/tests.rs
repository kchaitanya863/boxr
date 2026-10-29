use super::*;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

#[test]
fn test_volume_lifecycle() {
    let temp = tempdir().unwrap();
    let store = VolumeStore {
        index_file: temp.path().join("volumes.json"),
        volumes_dir: temp.path().join("volumes"),
    };

    // Create named volume
    let vol = store.create(Some("test-data"), None).unwrap();
    assert_eq!(vol.name, "test-data");
    assert!(PathBuf::from(&vol.mountpoint).exists());

    // Find
    let found = store.find("test-data").unwrap();
    assert_eq!(found.name, "test-data");

    // List
    assert_eq!(store.list().len(), 1);

    // Resolve mount for named volume
    let mount = store.resolve_mount("test-data:/app/data:ro").unwrap();
    assert_eq!(mount.destination, "/app/data");
    assert!(mount.read_only);
    assert!(mount.is_volume);

    // Remove
    store.remove("test-data").unwrap();
    assert!(store.find("test-data").is_none());
    assert_eq!(store.list().len(), 0);

    // Relative path traversal rejection
    let err = store.resolve_mount("../../../etc:/data");
    assert!(err.is_err());
    assert!(
        err.unwrap_err()
            .to_string()
            .contains("Path traversal rejected")
    );

    // Absolute path traversal rejection
    let err = store.resolve_mount("/foo/../../../etc:/data");
    assert!(err.is_err());
    assert!(
        err.unwrap_err()
            .to_string()
            .contains("Path traversal rejected")
    );

    // Destination path traversal rejection
    let err = store.resolve_mount("/tmp/data:../../../../etc");
    assert!(err.is_err());
    assert!(
        err.unwrap_err()
            .to_string()
            .contains("Invalid volume destination")
    );

    let err2 = store.resolve_mount("/tmp/data:relative/path");
    assert!(err2.is_err());
    assert!(
        err2.unwrap_err()
            .to_string()
            .contains("Invalid volume destination")
    );

    // Named volume name traversal rejection
    let err_name = store.create(Some("../../pwn"), None);
    assert!(err_name.is_err());
    assert!(
        err_name
            .unwrap_err()
            .to_string()
            .contains("Invalid volume name")
    );

    let err_name2 = store.create(Some("sub/dir"), None);
    assert!(err_name2.is_err());
    assert!(
        err_name2
            .unwrap_err()
            .to_string()
            .contains("Invalid volume name")
    );
}

#[test]
fn test_volume_prune_preserves_active_containers() {
    let temp = tempdir().unwrap();
    let home = temp.path().to_path_buf();
    let store = VolumeStore::with_home(home.clone());
    let c_store = crate::storage::ContainerStore::with_home(home.clone());

    // Create two volumes: one used, one unused
    store.create(Some("used-vol"), None).unwrap();
    store.create(Some("unused-vol"), None).unwrap();

    // Create a dummy container that mounts "used-vol"
    let bundle_dir = home.join("containers").join("c1");
    fs::create_dir_all(&bundle_dir).unwrap();
    let spec_content = r#"
        {
            "ociVersion": "1.0.2",
            "process": { "terminal": false, "user": { "uid": 0, "gid": 0 }, "args": ["sh"], "env": [], "cwd": "/" },
            "root": { "path": "rootfs", "readonly": false },
            "mounts": [
                { "destination": "/data", "type": "bind", "source": "/test/volumes/used-vol/_data" }
            ]
        }"#;
    fs::write(bundle_dir.join("config.json"), spec_content).unwrap();

    let c_record = crate::storage::ContainerRecord {
        id: "c1".to_string(),
        name: "test-c1".to_string(),
        image: "alpine".to_string(),
        command: vec!["sh".to_string()],
        created_at: chrono::Utc::now(),
        status: crate::storage::ContainerStatus::Running,
        bundle_path: bundle_dir.to_string_lossy().to_string(),
        restart_policy: crate::health::RestartPolicy::No,
        health_status: crate::health::HealthStatus::None,
        restart_count: 0,
        ports: Vec::new(),
        exposed_ports: Vec::new(),
    };
    c_store.add(c_record).unwrap();

    // Prune -a: only unused-vol must be deleted, used-vol must be preserved!
    let pruned = store.prune_with_options(true, &[]).unwrap();
    assert_eq!(pruned, vec!["unused-vol".to_string()]);
    assert!(store.find("used-vol").is_some());
    assert!(store.find("unused-vol").is_none());
}

#[test]
fn test_volume_remove_in_use_validation() {
    let temp = tempdir().unwrap();
    let home = temp.path().to_path_buf();
    let store = VolumeStore::with_home(home.clone());
    let c_store = crate::storage::ContainerStore::with_home(home.clone());

    store.create(Some("mounted-vol"), None).unwrap();

    let bundle_dir = home.join("containers").join("c2");
    fs::create_dir_all(&bundle_dir).unwrap();
    let spec_content = r#"
        {
            "ociVersion": "1.0.2",
            "process": { "terminal": false, "user": { "uid": 0, "gid": 0 }, "args": ["sh"], "env": [], "cwd": "/" },
            "root": { "path": "rootfs", "readonly": false },
            "mounts": [
                { "destination": "/app/data", "type": "bind", "source": "/test/volumes/mounted-vol/_data" }
            ]
        }"#;
    fs::write(bundle_dir.join("config.json"), spec_content).unwrap();

    let c_record = crate::storage::ContainerRecord {
        id: "c2".to_string(),
        name: "test-c2".to_string(),
        image: "alpine".to_string(),
        command: vec!["sh".to_string()],
        created_at: chrono::Utc::now(),
        status: crate::storage::ContainerStatus::Running,
        bundle_path: bundle_dir.to_string_lossy().to_string(),
        restart_policy: crate::health::RestartPolicy::No,
        health_status: crate::health::HealthStatus::None,
        restart_count: 0,
        ports: Vec::new(),
        exposed_ports: Vec::new(),
    };
    c_store.add(c_record).unwrap();

    // Attempting to remove mounted volume without force must fail
    let res = store.remove("mounted-vol");
    assert!(res.is_err());
    assert!(
        res.unwrap_err()
            .to_string()
            .contains("volume is being used")
    );

    // Removing with force=true must succeed
    let res_force = store.remove_with_force("mounted-vol", true);
    assert!(res_force.is_ok());
}
