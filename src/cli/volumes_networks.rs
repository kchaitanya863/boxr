use clap::Args;

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct VolumeSubcommands {
    #[command(subcommand)]
    pub command: VolumeAction,
}

#[derive(clap::Subcommand, Debug)]
pub enum VolumeAction {
    Create(VolumeCreateArgs),
    #[command(alias = "list")]
    Ls(VolumeLsArgs),
    Inspect {
        #[arg(short = 'f', long = "format")]
        format: Option<String>,
        name: String,
    },
    Rm(VolumeRmArgs),
    Prune(VolumePruneArgs),
    /// Export volume data to a tar archive
    Export(VolumeExportArgs),
    /// Import volume data from a tar archive
    Import(VolumeImportArgs),
    /// Reload volume plugins or configuration
    Reload {
        name: Option<String>,
    },
    /// Rename a volume
    Rename {
        #[arg(value_name = "NAME", num_args = 1..=2)]
        names: Vec<String>,
    },
    /// Mount a volume filesystem
    Mount {
        name: String,
    },
    /// Unmount a volume filesystem
    #[command(alias = "umount")]
    Unmount {
        name: String,
    },
    /// Return 0 if the volume exists, 1 otherwise
    Exists {
        name: String,
    },
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct VolumeCreateArgs {
    /// Volume name via --name
    #[arg(long = "name")]
    pub name_flag: Option<String>,
    /// Volume name (positional)
    #[arg(value_name = "NAME")]
    pub name: Option<String>,
    /// Specify volume driver name (default "local")
    #[arg(short = 'd', long = "driver", default_value = "local")]
    pub driver: String,
    /// Set driver specific options
    #[arg(short = 'o', long = "opt")]
    pub opts: Vec<String>,
    /// Set metadata for a volume
    #[arg(long = "label")]
    pub labels: Vec<String>,
    /// Do not fail if the volume already exists
    #[arg(long = "ignore")]
    pub ignore: bool,
    /// Cluster Volume availability (active, pause, drain)
    #[arg(long = "availability")]
    pub availability: Option<String>,
    /// Cluster Volume group
    #[arg(long = "group")]
    pub group: Option<String>,
    /// Minimum size of the Cluster Volume in bytes
    #[arg(long = "limit-bytes")]
    pub limit_bytes: Option<String>,
    /// Maximum size of the Cluster Volume in bytes
    #[arg(long = "required-bytes")]
    pub required_bytes: Option<String>,
    /// Cluster Volume access scope (single, multi)
    #[arg(long = "scope")]
    pub scope: Option<String>,
    /// Cluster Volume secrets
    #[arg(long = "secret")]
    pub secret: Vec<String>,
    /// Cluster Volume access sharing
    #[arg(long = "sharing")]
    pub sharing: Option<String>,
    /// Topology that the Cluster Volume would be preferred in
    #[arg(long = "topology-preferred")]
    pub topology_preferred: Vec<String>,
    /// Topology that the Cluster Volume must be accessible from
    #[arg(long = "topology-required")]
    pub topology_required: Vec<String>,
    /// Cluster Volume access type (mount, block)
    #[arg(long = "type")]
    pub vol_type: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct VolumeRmArgs {
    #[arg(short = 'f', long = "force")]
    pub force: bool,
    #[arg(short = 'a', long = "all")]
    pub all: bool,
    /// Accepted for Podman teardown compatibility (ignored for volumes)
    #[arg(short = 't', long = "time", hide = true, allow_hyphen_values = true)]
    pub time: Option<i32>,
    pub names: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct VolumeLsArgs {
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,
    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,
    #[arg(long = "format")]
    pub format: Option<String>,
    #[arg(short = 'n', long = "noheading")]
    pub noheading: bool,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct VolumePruneArgs {
    #[arg(short = 'f', long = "force")]
    pub force: bool,
    #[arg(short = 'a', long = "all")]
    pub all: bool,
    #[arg(long = "filter")]
    pub filter: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct NetworkSubcommands {
    #[command(subcommand)]
    pub command: NetworkAction,
}

#[derive(clap::Subcommand, Debug)]
pub enum NetworkAction {
    Create {
        name: String,
        /// Driver to manage the Network (default "bridge")
        #[arg(short = 'd', long = "driver", default_value = "bridge")]
        driver: String,
        /// Subnet in CIDR format
        #[arg(long = "subnet")]
        subnet: Option<String>,
        /// IPv4 or IPv6 Gateway for the master subnet
        #[arg(long = "gateway")]
        gateway: Option<String>,
        /// Restrict external access to the network
        #[arg(long = "internal")]
        internal: bool,
        /// Enable manual container attachment
        #[arg(long = "attachable")]
        attachable: bool,
        /// Set metadata on a network
        #[arg(long = "label")]
        labels: Vec<String>,
        /// Auxiliary IPv4 or IPv6 addresses
        #[arg(long = "aux-address")]
        aux_address: Vec<String>,
        /// The network from which to copy the configuration
        #[arg(long = "config-from")]
        config_from: Option<String>,
        /// Create a configuration only network
        #[arg(long = "config-only")]
        config_only: bool,
        /// Create swarm routing-mesh network
        #[arg(long = "ingress")]
        ingress: bool,
        /// Allocate container ip from a sub-range
        #[arg(long = "ip-range")]
        ip_range: Option<String>,
        /// IP Address Management Driver
        #[arg(long = "ipam-driver")]
        ipam_driver: Option<String>,
        /// Set IPAM driver specific options
        #[arg(long = "ipam-opt")]
        ipam_opt: Vec<String>,
        /// Enable or disable IPv4 address assignment
        #[arg(long = "ipv4")]
        ipv4: bool,
        /// Enable or disable IPv6 address assignment
        #[arg(long = "ipv6")]
        ipv6: bool,
        /// Set driver specific options
        #[arg(short = 'o', long = "opt")]
        opts: Vec<String>,
        /// Control the network's scope
        #[arg(long = "scope")]
        scope: Option<String>,
    },
    #[command(alias = "list")]
    Ls(NetworkLsArgs),
    Inspect {
        #[arg(short = 'f', long = "format")]
        format: Option<String>,
        name: String,
    },
    Rm {
        #[arg(short = 'f', long = "force")]
        force: bool,
        #[arg(long = "ignore")]
        ignore: bool,
        #[arg(short = 't', long = "time", hide = true, allow_hyphen_values = true)]
        time: Option<i32>,
        names: Vec<String>,
    },
    Prune(NetworkPruneArgs),
    Connect {
        network: String,
        container: String,
    },
    /// Disconnect a container from a network
    Disconnect {
        #[arg(short = 'f', long = "force")]
        force: bool,
        network: String,
        container: String,
    },
    /// Update network configuration
    Update(NetworkUpdateArgs),
    /// Reload firewall rules and port forwarding for a container (Podman parity)
    Reload {
        #[arg(short = 'a', long = "all")]
        all: bool,
        #[arg(short = 'l', long = "latest")]
        latest: bool,
        containers: Vec<String>,
    },
    /// Return 0 if the network exists, 1 otherwise
    Exists {
        name: String,
    },
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct NetworkLsArgs {
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,
    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,
    #[arg(long = "format")]
    pub format: Option<String>,
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,
    #[arg(short = 'n', long = "noheading")]
    pub noheading: bool,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct NetworkPruneArgs {
    #[arg(short = 'f', long = "force")]
    pub force: bool,
    #[arg(long = "filter")]
    pub filter: Vec<String>,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct VolumeExportArgs {
    /// Volume name
    pub name: String,
    /// Output archive path (default: <name>.tar)
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct VolumeImportArgs {
    /// Volume name
    pub name: String,
    /// Path to tarball archive to import
    pub input: String,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct NetworkUpdateArgs {
    /// Network name to update
    pub network: String,
    /// DNS servers to add
    #[arg(long = "dns-add")]
    pub dns_add: Vec<String>,
    /// DNS servers to drop
    #[arg(long = "dns-drop")]
    pub dns_drop: Vec<String>,
    /// Labels to add (key=value)
    #[arg(long = "label-add")]
    pub label_add: Vec<String>,
    /// Labels to drop (key)
    #[arg(long = "label-drop")]
    pub label_drop: Vec<String>,
}
