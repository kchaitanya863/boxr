use boxr::network::PortMapping;
use boxr::network::pasta::{NetworkMode, PastaConfig, PastaDriver};
use std::path::PathBuf;

#[test]
fn test_pasta_config_defaults() {
    let cfg = PastaConfig::new();
    assert_eq!(cfg.ifname, Some("eth0".to_string()));
    assert!(cfg.quiet);
    assert!(cfg.port_mappings.is_empty());
    assert!(cfg.netns_pid.is_none());
    assert!(cfg.netns_path.is_none());
}

#[test]
fn test_pasta_config_for_pid_args() {
    let ports = vec![
        PortMapping::parse("8080:80").unwrap(),
        PortMapping::parse("127.0.0.1:443:443/tcp").unwrap(),
        PortMapping::parse("5353:53/udp").unwrap(),
    ];

    let mut cfg = PastaConfig::for_pid(4200, &ports);
    cfg.address = Some("192.168.1.100".to_string());
    cfg.gateway = Some("192.168.1.1".to_string());
    cfg.dns = vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()];

    let args = cfg.build_args();

    // Verify presence of flags
    assert!(args.contains(&"--config-net".to_string()));
    assert!(args.contains(&"-q".to_string()));
    assert!(args.contains(&"-I".to_string()));
    assert!(args.contains(&"eth0".to_string()));
    assert!(args.contains(&"-a".to_string()));
    assert!(args.contains(&"192.168.1.100".to_string()));
    assert!(args.contains(&"-g".to_string()));
    assert!(args.contains(&"192.168.1.1".to_string()));

    // Verify DNS
    let dns_indices: Vec<usize> = args
        .iter()
        .enumerate()
        .filter(|(_, a)| *a == "-D")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(dns_indices.len(), 2);
    assert_eq!(args[dns_indices[0] + 1], "1.1.1.1");
    assert_eq!(args[dns_indices[1] + 1], "9.9.9.9");

    // Verify TCP and UDP port mapping specifications
    assert!(args.contains(&"-t".to_string()));
    assert!(args.contains(&"8080:80".to_string()));
    assert!(args.contains(&"127.0.0.1/443:443".to_string()));
    assert!(args.contains(&"-u".to_string()));
    assert!(args.contains(&"5353:53".to_string()));

    // Verify PID is passed as the last positional parameter
    assert_eq!(args.last().unwrap(), "4200");
}

#[test]
fn test_pasta_config_with_netns_path() {
    let mut cfg = PastaConfig::new();
    cfg.netns_path = Some(PathBuf::from("/proc/123/ns/net"));
    let args = cfg.build_args();

    assert_eq!(args.last().unwrap(), "/proc/123/ns/net");
}

#[test]
fn test_network_mode_parsing_variants() {
    assert_eq!(NetworkMode::parse("pasta"), NetworkMode::Pasta);
    assert_eq!(NetworkMode::parse("PASTA"), NetworkMode::Pasta);
    assert_eq!(NetworkMode::parse("  pasta  "), NetworkMode::Pasta);
    assert_eq!(NetworkMode::parse("host"), NetworkMode::Host);
    assert_eq!(NetworkMode::parse("none"), NetworkMode::None);
    assert_eq!(NetworkMode::parse("bridge"), NetworkMode::Bridge);
    assert_eq!(NetworkMode::parse("auto"), NetworkMode::Auto);
    assert_eq!(NetworkMode::parse(""), NetworkMode::Auto);
    assert_eq!(NetworkMode::parse("boxr0"), NetworkMode::Bridge);
    assert_eq!(NetworkMode::parse("custom-net"), NetworkMode::Bridge);
}

#[test]
fn test_network_mode_netns_requirements() {
    assert!(NetworkMode::Pasta.requires_new_netns());
    assert!(NetworkMode::None.requires_new_netns());
    assert!(!NetworkMode::Host.requires_new_netns());
    assert!(NetworkMode::Bridge.requires_new_netns());
    assert!(NetworkMode::Auto.requires_new_netns());
    assert!(NetworkMode::UserNet.requires_new_netns());

    assert!(NetworkMode::Pasta.should_use_pasta());
    assert!(!NetworkMode::None.should_use_pasta());
    assert!(!NetworkMode::Host.should_use_pasta());
    assert!(!NetworkMode::Bridge.should_use_pasta());
}

#[test]
fn test_pasta_driver_detection() {
    // Tests that detection runs without panic on any platform
    let available = PastaDriver::is_available();
    let bin = PastaDriver::binary_path();
    if available {
        assert!(bin.is_some());
    } else {
        assert!(bin.is_none());
    }
}
