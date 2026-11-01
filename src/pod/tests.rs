use super::*;
use tempfile::tempdir;

#[test]
fn test_pod_store_lifecycle() {
    let temp = tempdir().unwrap();
    let store = PodStore::with_home(temp.path().to_path_buf());

    let pod = store.create(Some("test-pod"), Vec::new()).unwrap();
    assert_eq!(pod.name, "test-pod");
    assert_eq!(store.list().len(), 1);
    assert!(pod.share_ipc);
    assert!(pod.share_net);

    assert!(store.find("test-pod").is_some());
    assert!(store.exists("test-pod"));

    store.add_container_to_pod("test-pod", "cont123").unwrap();
    let updated = store.find("test-pod").unwrap();
    assert_eq!(updated.containers, vec!["cont123".to_string()]);
    assert_eq!(updated.status, "Running");

    store.remove("test-pod").unwrap();
    assert_eq!(store.list().len(), 0);
}

#[test]
fn test_pod_config_defaults() {
    let cfg = PodConfig::default();
    assert!(cfg.share_ipc);
    assert!(cfg.share_net);
    assert!(!cfg.share_pid);
}

#[test]
fn test_resolve_namespace_spec_host() {
    let r = resolve_namespace_spec("host", "net").unwrap();
    assert_eq!(r, Some("host".to_string()));
}

#[test]
fn test_pod_prune_removes_exited() {
    let temp = tempdir().unwrap();
    let store = PodStore::with_home(temp.path().to_path_buf());
    let pod = store.create(Some("exited-pod"), Vec::new()).unwrap();
    store.update_status(&pod.name, "Exited").unwrap();
    let pruned = store.prune().unwrap();
    assert!(pruned.contains(&"exited-pod".to_string()));
    assert!(store.find("exited-pod").is_none());
}

#[test]
fn test_apply_pod_to_run_args() {
    let pod = PodRecord {
        id: "abc".to_string(),
        name: "mypod".to_string(),
        created_at: Utc::now(),
        status: "Created".to_string(),
        infra_container_id: "mypod-infra".to_string(),
        containers: vec![],
        ports: vec![],
        hostname: Some("podhost".to_string()),
        labels: HashMap::from([("app".to_string(), "web".to_string())]),
        dns: vec!["8.8.8.8".to_string()],
        dns_search: vec![],
        dns_option: vec![],
        add_host: vec![],
        mac_address: None,
        ip: None,
        infra_image: None,
        infra_command: None,
        infra_name: None,
        exit_policy: "continue".to_string(),
        restart_policy: None,
        userns: None,
        volumes: vec![],
        memory: Some("512m".to_string()),
        cpus: None,
        share_ipc: true,
        share_net: true,
        share_uts: true,
        share_pid: false,
        infra: true,
        network: None,
    };
    let mut args = crate::cli::RunArgs {
        registry_auth: Default::default(),
        interactive: false,
        tty: false,
        detach: true,
        rm: false,
        replace: false,
        rmi: false,
        name: Some("worker".to_string()),
        env: vec![],
        unsetenv: vec![],
        unsetenv_all: false,
        systemd: None,
        ports: vec![],
        volumes: vec![],
        image_volume: None,
        memory: None,
        kernel_memory: None,
        labels: vec![],
        dns: vec![],
        cidfile: None,
        conmon_pidfile: None,
        cpus: None,
        pids_limit: None,
        rootless: true,
        restart: "no".to_string(),
        health_cmd: None,
        secret: Vec::new(),
        health_startup_cmd: None,
        health_startup_interval: None,
        health_startup_timeout: None,
        health_startup_retries: None,
        health_startup_success: None,
        health_max_log_count: None,
        health_max_log_size: None,
        health_log_destination: None,
        platform: None,
        privileged: false,
        network: "bridge".to_string(),
        disable_content_trust: false,
        gpus: None,
        entrypoint: None,
        tz: Vec::new(),
        env_file: None,
        user: None,
        hostuser: vec![],
        group_entry: vec![],
        hostname: None,
        no_hostname: false,
        add_host: vec![],
        shm_size: None,
        cap_add: vec![],
        cap_drop: vec![],
        read_only: false,
        http_proxy: false,
        read_only_tmpfs: None,
        init: false,
        tmpfs: vec![],
        devices: vec![],
        security_opt: vec![],
        cpu_shares: None,
        cpuset_cpus: None,
        memory_swap: None,
        memory_reservation: None,
        dns_search: vec![],
        dns_option: vec![],
        expose: vec![],
        sysctl: vec![],
        stop_timeout: None,
        stop_signal: None,
        annotations: vec![],
        ulimits: vec![],
        hooks_dir: None,
        conmon_syslog: false,
        ipc: None,
        pid: None,
        uts: None,
        userns: Vec::new(),
        uidmap: Vec::new(),
        gidmap: vec![],
        cgroupns: None,
        cgroup_parent: None,
        isolation: None,
        cpu_count: None,
        cpu_percent: None,
        io_maxbandwidth: None,
        io_maxiops: None,
        publish_all: false,
        ip: None,
        ip6: None,
        mac_address: None,
        link: vec![],
        network_alias: vec![],
        mount: vec![],
        health_interval: None,
        health_timeout: None,
        health_retries: None,
        health_start_period: None,
        health_on_failure: None,
        health_start_interval: None,
        no_healthcheck: false,
        attach: vec![],
        preserve_fds: None,
        preserve_fd: vec![],
        pull: None,
        quiet: false,
        log_driver: vec![],
        log_opt: vec![],
        sdnotify: None,
        cgroups: None,
        pod_id_file: None,
        oom_kill_disable: false,
        oom_score_adj: None,
        group_add: vec![],
        label_file: None,
        umask: None,
        domainname: None,
        detach_keys: None,
        blkio_weight: None,
        blkio_weight_device: vec![],
        cpu_period: None,
        cpu_quota: None,
        cpu_rt_period: None,
        cpu_rt_runtime: None,
        cpuset_mems: None,
        device_cgroup_rule: vec![],
        device_read_bps: vec![],
        device_read_iops: vec![],
        device_write_bps: vec![],
        device_write_iops: vec![],
        link_local_ip: vec![],
        memory_swappiness: None,
        cgroup_conf: Vec::new(),
        runtime: None,
        sig_proxy: true,
        storage_opt: vec![],
        use_api_socket: false,
        volume_driver: None,
        volumes_from: vec![],
        workdir: None,
        pod: Some("mypod".to_string()),
        rootfs: None,
        default_mounts_file: None,
        init_ctr: None,
        timeout: None,
        image: "alpine".to_string(),
        command: vec![],
        passwd: true,
        ..Default::default()
    };
    apply_pod_to_run_args(&pod, "mypod-infra", &mut args);
    assert_eq!(args.network, "container:mypod-infra");
    assert_eq!(args.ipc, Some("container:mypod-infra".to_string()));
    assert_eq!(args.hostname, Some("podhost".to_string()));
    assert_eq!(args.dns, vec!["8.8.8.8".to_string()]);
    assert!(args.labels.iter().any(|l| l.contains("app=web")));
}
