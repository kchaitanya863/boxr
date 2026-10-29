use super::*;

#[test]
fn test_rootless_user_config_defaults() {
    let config = RootlessUserConfig::default();
    assert!(!config.uid_mappings.is_empty());
    assert!(!config.gid_mappings.is_empty());
    assert_eq!(config.uid_mappings[0].container_id, 0);
    assert_eq!(config.gid_mappings[0].container_id, 0);
}

#[test]
fn test_parse_subid_content() {
    let subuid_content = "\
# /etc/subuid comment
root:100000:65536
vagrant:165536:65536
1000:231072:65536
";
    // Lookup by username
    let range1 = RootlessUserConfig::parse_subid_content(subuid_content, 1001, Some("vagrant"));
    assert_eq!(
        range1,
        Some(SubordinateRange {
            start: 165536,
            count: 65536
        })
    );

    // Lookup by uid
    let range2 = RootlessUserConfig::parse_subid_content(subuid_content, 1000, None);
    assert_eq!(
        range2,
        Some(SubordinateRange {
            start: 231072,
            count: 65536
        })
    );

    // Non-existent user
    let range3 = RootlessUserConfig::parse_subid_content(subuid_content, 9999, Some("nonexistent"));
    assert_eq!(range3, None);
}

#[test]
fn test_seccomp_default_rules() {
    let seccomp = SeccompRule::default_filter();
    assert_eq!(seccomp.default_action, "SCMP_ACT_ALLOW");
    assert!(!seccomp.syscalls.is_empty());
    let blocked = &seccomp.syscalls[0];
    assert_eq!(blocked.action, "SCMP_ACT_ERRNO");
    assert!(blocked.names.contains(&"reboot".to_string()));
    assert!(blocked.names.contains(&"swapon".to_string()));
}

#[test]
fn test_capability_profile_customization() {
    let mut profile = CapabilityProfile::default();
    assert!(profile.bounding.contains(&"CAP_CHOWN".to_string()));
    assert!(profile.bounding.contains(&"CAP_NET_RAW".to_string()));

    // Drop specific capability
    profile.bounding.retain(|c| c != "CAP_NET_RAW");
    assert!(!profile.bounding.contains(&"CAP_NET_RAW".to_string()));

    // Add capability
    profile.bounding.push("CAP_NET_ADMIN".to_string());
    assert!(profile.bounding.contains(&"CAP_NET_ADMIN".to_string()));

    // Drop all
    profile.bounding.clear();
    assert!(profile.bounding.is_empty());
}
