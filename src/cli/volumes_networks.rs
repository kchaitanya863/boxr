use clap::Args;

#[derive(Args, Debug)]
pub struct VolumeSubcommands {
    #[command(subcommand)]
    pub command: VolumeAction,
}

#[derive(clap::Subcommand, Debug)]
pub enum VolumeAction {
    Create {
        /// Volume name via --name
        #[arg(long = "name")]
        name_flag: Option<String>,
        /// Volume name (positional)
        name: Option<String>,
        /// Specify volume driver name (default "local")
        #[arg(short = 'd', long = "driver", default_value = "local")]
        driver: String,
        /// Set driver specific options
        #[arg(short = 'o', long = "opt")]
        opts: Vec<String>,
        /// Set metadata for a volume
        #[arg(long = "label")]
        labels: Vec<String>,
        /// Cluster Volume availability (active, pause, drain)
        #[arg(long = "availability")]
        availability: Option<String>,
        /// Cluster Volume group
        #[arg(long = "group")]
        group: Option<String>,
        /// Minimum size of the Cluster Volume in bytes
        #[arg(long = "limit-bytes")]
        limit_bytes: Option<String>,
        /// Maximum size of the Cluster Volume in bytes
        #[arg(long = "required-bytes")]
        required_bytes: Option<String>,
        /// Cluster Volume access scope (single, multi)
        #[arg(long = "scope")]
        scope: Option<String>,
        /// Cluster Volume secrets
        #[arg(long = "secret")]
        secret: Vec<String>,
        /// Cluster Volume access sharing
        #[arg(long = "sharing")]
        sharing: Option<String>,
        /// Topology that the Cluster Volume would be preferred in
        #[arg(long = "topology-preferred")]
        topology_preferred: Vec<String>,
        /// Topology that the Cluster Volume must be accessible from
        #[arg(long = "topology-required")]
        topology_required: Vec<String>,
        /// Cluster Volume access type (mount, block)
        #[arg(long = "type")]
        vol_type: Option<String>,
    },
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
        old_name: String,
        new_name: String,
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
pub struct VolumeRmArgs {
    #[arg(short = 'f', long = "force")]
    pub force: bool,
    #[arg(short = 'a', long = "all")]
    pub all: bool,
    pub names: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct VolumeLsArgs {
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,
    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,
    #[arg(long = "format")]
    pub format: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct VolumePruneArgs {
    #[arg(short = 'f', long = "force")]
    pub force: bool,
    #[arg(short = 'a', long = "all")]
    pub all: bool,
    #[arg(long = "filter")]
    pub filter: Vec<String>,
}

#[derive(Args, Debug)]
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
    Ls(NetworkLsArgs),
    Inspect {
        #[arg(short = 'f', long = "format")]
        format: Option<String>,
        name: String,
    },
    Rm {
        name: String,
    },
    Prune(NetworkPruneArgs),
    Connect {
        network: String,
        container: String,
    },
    /// Disconnect a container from a network
    Disconnect {
        network: String,
        container: String,
    },
    /// Update network configuration
    Update(NetworkUpdateArgs),
    /// Reload firewall rules and port forwarding for a container (Podman parity)
    Reload {
        containers: Vec<String>,
    },
    /// Return 0 if the network exists, 1 otherwise
    Exists {
        name: String,
    },
}

#[derive(Args, Debug, Clone, Default)]
pub struct NetworkLsArgs {
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,
    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,
    #[arg(long = "format")]
    pub format: Option<String>,
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct NetworkPruneArgs {
    #[arg(short = 'f', long = "force")]
    pub force: bool,
    #[arg(long = "filter")]
    pub filter: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct VolumeExportArgs {
    /// Volume name
    pub name: String,
    /// Output archive path (default: <name>.tar)
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct VolumeImportArgs {
    /// Volume name
    pub name: String,
    /// Path to tarball archive to import
    pub input: String,
}

#[derive(Args, Debug, Clone, Default)]
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
