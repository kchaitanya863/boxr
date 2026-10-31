use clap::{Args, Subcommand};

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct DaemonArgs {
    #[arg(short = 's', long = "socket")]
    pub socket: Option<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct SpecArgs {
    /// Path to bundle directory where config.json should be created (default: current directory)
    #[arg(short = 'b', long = "bundle")]
    pub bundle: Option<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct StatsArgs {
    /// Disable streaming stats and only pull the first result
    #[arg(long = "no-stream")]
    pub no_stream: bool,

    #[arg(short = 'a', long = "all")]
    pub all: bool,

    #[arg(long = "format")]
    pub format: Option<String>,

    #[arg(long = "no-trunc")]
    pub no_trunc: bool,

    /// Target container IDs or names
    pub containers: Vec<String>,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct EventsArgs {
    /// Show all events created since timestamp
    #[arg(long = "since", allow_hyphen_values = true)]
    pub since: Option<String>,

    #[arg(long = "until", allow_hyphen_values = true)]
    pub until: Option<String>,

    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,

    #[arg(long = "format")]
    pub format: Option<String>,

    #[arg(
        long = "stream",
        default_value_t = true,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true,
        action = clap::ArgAction::Set,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub stream: bool,

    #[arg(long = "events-backend")]
    pub events_backend: Option<String>,

    #[arg(
        long = "no-trunc",
        default_value_t = true,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    pub no_trunc: bool,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct CompletionArgs {
    /// Target shell (bash, zsh, fish)
    #[arg(default_value = "zsh")]
    pub shell: String,

    /// Install completion script automatically into user shell directory
    #[arg(long = "install")]
    pub install: bool,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct AliasArgs {
    /// Install wrapper script in ~/.boxr/bin/docker
    #[arg(long = "install")]
    pub install: bool,

    /// Output shell alias command
    #[arg(long = "eval")]
    pub eval: bool,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct ContextSubcommands {
    #[command(subcommand)]
    pub command: ContextAction,
}

#[derive(Subcommand, Debug)]
pub enum ContextAction {
    /// List contexts
    #[command(alias = "list")]
    Ls,
    /// Print current context
    Show,
    /// Set the current docker context
    Use { name: String },
    /// Display detailed information on one or more contexts
    Inspect { name: Option<String> },
    /// Create a context
    Create {
        name: String,
        #[arg(long = "description")]
        description: Option<String>,
        #[arg(long = "docker")]
        docker: Option<String>,
        /// Create context from a named context
        #[arg(long = "from")]
        from: Option<String>,
    },
    /// Remove one or more contexts
    Rm { name: String },
    /// Import a context
    Import { name: String, source: String },
    /// Export a context
    Export {
        name: String,
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },
    /// Update a context
    Update {
        name: String,
        #[arg(long = "description")]
        description: Option<String>,
        #[arg(long = "docker")]
        docker: Option<String>,
    },
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct SystemSubcommands {
    #[command(subcommand)]
    pub command: SystemAction,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct SystemDfArgs {
    #[arg(short = 'f', long = "format")]
    pub format: Option<String>,
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum SystemAction {
    /// Show boxr disk usage
    Df(SystemDfArgs),
    /// Display system-wide information
    Info(FormatArgs),
    /// Get real time events from the server
    Events(EventsArgs),
    /// Remove unused data
    Prune {
        #[arg(short = 'a', long = "all")]
        all: bool,
        #[arg(short = 'f', long = "force")]
        force: bool,
        #[arg(long = "volumes")]
        volumes: bool,
        #[arg(long = "filter")]
        filter: Vec<String>,
    },
    /// Check system configuration and storage health
    Check {
        /// Remove damaged layers, images, and containers
        #[arg(short = 'r', long = "repair")]
        repair: bool,
        /// Remove damaged containers even if they are referenced
        #[arg(short = 'f', long = "force")]
        force: bool,
        /// Maximum allowed age of unreferenced layers
        #[arg(short = 'm', long = "max", allow_hyphen_values = true)]
        max: Option<String>,
        /// Quick check without verifying layer digests
        #[arg(short = 'q', long = "quick")]
        quick: bool,
    },
    /// Manage remote system destination connections
    Connection(SystemConnectionSubcommands),
    /// Migrate container storage to current version
    Migrate,
    /// Renumber container state files and locks
    Renumber,
    /// Reset storage completely
    Reset {
        #[arg(short = 'f', long = "force")]
        force: bool,
    },
    /// Run an API service for Podman/Docker clients
    Service {
        /// Timeout in seconds until service stops when idle
        #[arg(short = 't', long = "time", alias = "timeout")]
        timeout: Option<u64>,
        /// Set CORS Headers
        #[arg(long = "cors")]
        cors: Option<String>,
        /// PEM file containing TLS serving certificate
        #[arg(long = "tls-cert")]
        tls_cert: Option<String>,
        /// PEM file containing TLS serving certificate private key
        #[arg(long = "tls-key")]
        tls_key: Option<String>,
        /// Only trust client connections with certificates signed by this CA PEM file
        #[arg(long = "tls-client-ca")]
        tls_client_ca: Option<String>,
        /// Listening URI (e.g. unix:///path/to/sock or tcp://host:port)
        uri: Option<String>,
    },
    /// Prepare Hyper-V virtualization prerequisites
    #[command(name = "hyperv-prep")]
    HypervPrep,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub action: ServiceAction,
}

#[derive(Subcommand, Debug)]
pub enum ServiceAction {
    /// Install daemon service with autostart at login / boot
    Install,
    /// Start the background service
    Start,
    /// Stop the background service
    Stop,
    /// View the live service status
    Status,
    /// Uninstall the service definition
    Uninstall,
}

#[derive(Args, Debug, Default, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct FormatArgs {
    /// Format output using a custom template: 'json' or Go template
    #[arg(short = 'f', long = "format", num_args = 0..=1, default_missing_value = "")]
    pub format: Option<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct PodSubcommands {
    #[command(subcommand)]
    pub command: PodAction,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct PodTopArgs {
    /// Pod to inspect
    pub pod: String,
    /// Format descriptors or ps arguments
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub descriptors: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct PodLsArgs {
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,
    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,
    #[arg(long = "format")]
    pub format: Option<String>,
    #[arg(long = "sort")]
    pub sort: Option<String>,
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,
    #[arg(short = 'l', long = "latest")]
    pub latest: bool,

    #[arg(short = 'n', long = "noheading")]
    pub noheading: bool,

    #[arg(value_name = "POD")]
    pub pods: Vec<String>,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct PodCreateArgs {
    /// Pod name
    #[arg(short = 'n', long = "name")]
    pub name: Option<String>,
    /// Publish port (e.g. 8080:80)
    #[arg(short = 'p', long = "publish")]
    pub ports: Vec<String>,
    /// Set pod hostname
    #[arg(long = "hostname")]
    pub hostname: Option<String>,
    /// Set metadata labels (key=value)
    #[arg(short = 'l', long = "label")]
    pub labels: Vec<String>,
    /// Custom DNS servers
    #[arg(long = "dns")]
    pub dns: Vec<String>,
    /// Set custom DNS search domains
    #[arg(long = "dns-search")]
    pub dns_search: Vec<String>,
    /// Set custom DNS options
    #[arg(long = "dns-option", alias = "dns-opt")]
    pub dns_option: Vec<String>,
    /// Add a custom host-to-IP mapping (host:ip)
    #[arg(long = "add-host")]
    pub add_host: Vec<String>,
    /// Pod network interface MAC address
    #[arg(long = "mac-address")]
    pub mac_address: Option<String>,
    /// Pod static IPv4 address
    #[arg(long = "ip")]
    pub ip: Option<String>,
    /// Write the pod ID to the file
    #[arg(long = "pod-id-file")]
    pub pod_id_file: Option<String>,
    /// Custom image for infra container
    #[arg(long = "infra-image")]
    pub infra_image: Option<String>,
    /// Custom command for infra container
    #[arg(long = "infra-command")]
    pub infra_command: Option<String>,
    /// Custom name for infra container
    #[arg(long = "infra-name")]
    pub infra_name: Option<String>,
    /// Replace an existing pod with the same name
    #[arg(long = "replace")]
    pub replace: bool,
    /// Behaviour when the last container exits (continue or stop)
    #[arg(long = "exit-policy")]
    pub exit_policy: Option<String>,
    /// Restart policy to follow when containers exit
    #[arg(long = "restart")]
    pub restart: Option<String>,
    /// User namespace to use
    #[arg(long = "userns")]
    pub userns: Option<String>,
    /// Memory limit for all containers in the pod
    #[arg(short = 'm', long = "memory")]
    pub memory: Option<String>,
    /// Limit memory + swap
    #[arg(long = "memory-swap")]
    pub memory_swap: Option<String>,
    /// CPU limit for all containers in the pod
    #[arg(long = "cpus")]
    pub cpus: Option<String>,
    /// CPU shares (relative weight)
    #[arg(long = "cpu-shares")]
    pub cpu_shares: Option<u64>,
    /// CPUs in which to allow execution
    #[arg(long = "cpuset-cpus")]
    pub cpuset_cpus: Option<String>,
    /// Memory nodes (MEMs) in which to allow execution
    #[arg(long = "cpuset-mems")]
    pub cpuset_mems: Option<String>,
    /// Limit read rate (bytes per second) from a device
    #[arg(long = "device-read-bps")]
    pub device_read_bps: Vec<String>,
    /// Limit write rate (bytes per second) to a device
    #[arg(long = "device-write-bps")]
    pub device_write_bps: Vec<String>,
    /// Block IO weight
    #[arg(long = "blkio-weight")]
    pub blkio_weight: Option<u16>,
    /// Volumes to mount in all containers in the pod
    #[arg(short = 'v', long = "volume")]
    pub volumes: Vec<String>,
    /// Network mode for the pod
    #[arg(long = "network", alias = "net")]
    pub network: Option<String>,
    /// Share namespaces: ipc, net, uts, pid (comma-separated)
    #[arg(
        long = "share",
        default_value = "ipc,net,uts",
        num_args = 0..=1,
        default_missing_value = ""
    )]
    pub share: String,
    /// Create an infra container
    #[arg(
        long = "infra",
        default_value_t = true,
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub infra: bool,
    /// Do not create an infra container
    #[arg(long = "no-infra", default_value_t = false)]
    pub no_infra: bool,
    /// Write the infra container's conmon PID to the file
    #[arg(long = "infra-conmon-pidfile")]
    pub infra_conmon_pidfile: Option<String>,
    /// Pod name (positional; same as --name)
    #[arg(value_name = "NAME")]
    pub pod: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum PodAction {
    /// Create a pod
    Create(PodCreateArgs),
    /// List pods
    #[command(alias = "list")]
    Ps(PodLsArgs),
    /// List pods
    Ls(PodLsArgs),
    /// Remove one or more pods
    Rm {
        #[arg(short = 'f', long = "force")]
        force: bool,
        #[arg(short = 't', long = "time", allow_hyphen_values = true, value_name = "SECONDS")]
        time: Option<i32>,
        #[arg(short = 'a', long = "all")]
        all: bool,
        #[arg(long = "ignore")]
        ignore: bool,
        #[arg(long = "pod-id-file")]
        pod_id_file: Vec<String>,
        pods: Vec<String>,
    },
    /// Display detailed information on one or more pods
    Inspect {
        #[arg(short = 'f', long = "format")]
        format: Option<String>,
        #[arg(short = 'l', long = "latest")]
        latest: bool,
        pods: Vec<String>,
    },
    /// Stop one or more pods
    Stop {
        #[arg(short = 't', long = "time", allow_hyphen_values = true, value_name = "SECONDS")]
        time: Option<i32>,
        #[arg(short = 'a', long = "all")]
        all: bool,
        #[arg(short = 'i', long = "ignore")]
        ignore: bool,
        #[arg(long = "pod-id-file")]
        pod_id_file: Vec<String>,
        pods: Vec<String>,
    },
    /// Start one or more pods
    Start {
        #[arg(short = 'a', long = "all")]
        all: bool,
        #[arg(long = "pod-id-file")]
        pod_id_file: Vec<String>,
        pods: Vec<String>,
    },
    /// Restart one or more pods
    Restart {
        #[arg(short = 'a', long = "all")]
        all: bool,
        pods: Vec<String>,
    },
    /// Kill pods with a signal
    Kill {
        #[arg(
            short = 's',
            long = "signal",
            default_value = "SIGKILL",
            allow_hyphen_values = true
        )]
        signal: String,
        pods: Vec<String>,
    },
    /// Pause pods
    Pause { pods: Vec<String> },
    /// Unpause pods
    Unpause { pods: Vec<String> },
    /// Display the running processes of containers in pods
    Top(PodTopArgs),
    /// Display a live stream of pod resource usage statistics
    Stats {
        #[arg(long = "no-stream")]
        no_stream: bool,
        #[arg(long = "format")]
        format: Option<String>,
        pods: Vec<String>,
    },
    /// Remove all stopped pods
    Prune {
        #[arg(short = 'f', long = "force")]
        force: bool,
    },
    /// Check if a pod exists
    Exists { pod: String },
    /// Clone a pod and its containers
    Clone {
        /// Source pod name or ID
        source: String,
        /// Target pod name
        target: String,
    },
    /// Fetch logs for all containers in a pod
    Logs(PodLogsArgs),
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct PlaySubcommands {
    #[command(subcommand)]
    pub command: PlayAction,
}

#[derive(Subcommand, Debug)]
pub enum PlayAction {
    /// Play a pod from a Kubernetes YAML file
    Kube(crate::cli::kube::KubePlayArgs),
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct GenerateSubcommands {
    #[command(subcommand)]
    pub command: GenerateAction,
}

#[derive(Subcommand, Debug)]
pub enum GenerateAction {
    /// Generate Kubernetes Pod YAML for a container or pod
    Kube(crate::cli::kube::KubeGenerateArgs),
    /// [DEPRECATED] Generate systemd units
    #[command(
        about = "[DEPRECATED] Generate systemd units",
        long_about = "[DEPRECATED] Generate systemd units.\n  The generated units can later be controlled via systemctl(1).\n\nDEPRECATED command:\nIt is recommended to use Quadlets for running containers and pods under systemd.\n\nPlease refer to podman-systemd.unit(5) for details."
    )]
    Systemd {
        /// Container or pod name(s) to generate units for
        containers: Vec<String>,
        /// Output directory (default: stdout)
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
        /// Use container/pod names instead of IDs
        #[arg(short = 'n', long = "name")]
        name: bool,
        /// Generate .service files instead of printing to stdout
        #[arg(short = 'f', long = "files")]
        files: bool,
        /// Create a new container or pod instead of starting an existing one
        #[arg(long = "new", num_args = 0..=1, require_equals = true, default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
        new: Option<bool>,
        /// Make it a template file and use %i and %I specifiers
        #[arg(long = "template")]
        template: bool,
        /// Systemd restart-policy
        #[arg(long = "restart-policy", alias = "restart")]
        restart_policy: Option<String>,
        /// Systemd restart-sec
        #[arg(long = "restart-sec")]
        restart_sec: Option<u64>,
        /// Start timeout override
        #[arg(long = "start-timeout")]
        start_timeout: Option<u64>,
        /// Stop timeout override
        #[arg(long = "stop-timeout", short = 't', visible_alias = "time")]
        stop_timeout: Option<u64>,
        /// Skip header generation
        #[arg(long = "no-header")]
        no_header: bool,
        /// Systemd unit name prefix for containers
        #[arg(long = "container-prefix", default_value = "container")]
        container_prefix: String,
        /// Systemd unit name prefix for pods
        #[arg(long = "pod-prefix", default_value = "pod")]
        pod_prefix: String,
        /// Systemd unit name separator between name/id and prefix
        #[arg(long = "separator", default_value = "-")]
        separator: String,
        /// Print the created units in specified format (json)
        #[arg(long = "format")]
        format: Option<String>,
        /// Add (weak) requirement dependencies to the generated unit file
        #[arg(long = "wants")]
        wants: Vec<String>,
        /// Add dependencies order to the generated unit file
        #[arg(long = "after")]
        after: Vec<String>,
        /// Similar to wants, but declares stronger requirement dependencies
        #[arg(long = "requires")]
        requires: Vec<String>,
        /// Set environment variables to the systemd unit files
        #[arg(short = 'e', long = "env")]
        env: Vec<String>,
    },
    /// Generate Podman Specgen JSON for a container
    Spec(GenerateSpecArgs),
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct UnshareArgs {
    /// Join the rootless network namespace
    #[arg(long = "rootless-netns")]
    pub rootless_netns: bool,
    /// Command to run inside new user namespace
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct AutoUpdateArgs {
    /// Only check for updates without pulling or restarting
    #[arg(long = "dry-run")]
    pub dry_run: bool,
    /// Path of the authentication file
    #[arg(long = "authfile")]
    pub authfile: Option<String>,
    /// Format output using JSON or Go template
    #[arg(long = "format")]
    pub format: Option<String>,
    /// Rollback to previous image if update fails
    #[arg(long = "rollback", num_args = 0..=1, require_equals = true, default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
    pub rollback: Option<bool>,
    /// Filter containers based on conditions given
    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,
    /// Require HTTPS and verify certificates when contacting registries
    #[arg(long = "tls-verify", num_args = 0..=1, require_equals = true, default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
    pub tls_verify: Option<bool>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct HealthcheckSubcommands {
    #[command(subcommand)]
    pub command: HealthcheckAction,
}

#[derive(Subcommand, Debug)]
pub enum HealthcheckAction {
    /// Run health check on a container
    Run {
        /// Ignore the healthcheck result (exit 0 even if unhealthy)
        #[arg(long = "ignore-result")]
        ignore_result: bool,
        /// Container to run health check for
        container: String,
    },
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct PodLogsArgs {
    /// Pod to fetch logs from
    pub pod: Option<String>,
    /// Show timestamps
    #[arg(short = 't', long = "timestamps")]
    pub timestamps: bool,
    /// Number of lines to show from the end of the logs
    #[arg(short = 'n', long = "tail")]
    pub tail: Option<usize>,
    /// Output container names instead of container IDs
    #[arg(long = "names")]
    pub names: bool,
    /// Filter logs by container name or ID
    #[arg(short = 'c', long = "container")]
    pub container: Option<String>,
    /// Follow log output
    #[arg(short = 'f', long = "follow")]
    pub follow: bool,
    /// Show logs since timestamp
    #[arg(long = "since")]
    pub since: Option<String>,
    /// Show logs until timestamp
    #[arg(long = "until")]
    pub until: Option<String>,
    /// Act on the latest pod
    #[arg(short = 'l', long = "latest")]
    pub latest: bool,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct GenerateSpecArgs {
    /// Print the spec to a file instead of stdout
    #[arg(short = 'f', long = "filename")]
    pub filename: Option<String>,
    /// Print the spec in compact format
    #[arg(short = 'c', long = "compact")]
    pub compact: bool,
    /// Specify a new name for the generated spec
    #[arg(short = 'n', long = "name", num_args = 0..=1, default_missing_value = "true", require_equals = true, value_parser = clap::builder::BoolishValueParser::new())]
    pub name: Option<bool>,
    /// Container or pod name or ID to generate Specgen JSON for
    #[arg(value_name = "TARGET")]
    pub target: String,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct SystemConnectionSubcommands {
    #[command(subcommand)]
    pub command: SystemConnectionAction,
}

#[derive(Subcommand, Debug)]
pub enum SystemConnectionAction {
    /// List system connections
    #[command(alias = "list")]
    Ls {
        #[arg(short = 'f', long = "format")]
        format: Option<String>,
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
    },
    /// Add a new system connection
    Add {
        /// Destination name
        name: String,
        /// Destination URI
        uri: Option<String>,
        /// Default connection
        #[arg(short = 'd', long = "default")]
        default: bool,
        /// Path to SSH identity file
        #[arg(long = "identity")]
        identity: Option<String>,
        /// Path to podman socket on remote host
        #[arg(long = "socket-path")]
        socket_path: Option<String>,
        /// Farm to add connection to
        #[arg(long = "farm")]
        farm: Option<String>,
        /// TLS CA cert
        #[arg(long = "tls-ca")]
        tls_ca: Option<String>,
        /// TLS client cert
        #[arg(long = "tls-cert")]
        tls_cert: Option<String>,
        /// TLS client key
        #[arg(long = "tls-key")]
        tls_key: Option<String>,
    },
    /// Remove a system connection
    #[command(alias = "remove")]
    Rm {
        #[arg(short = 'a', long = "all")]
        all: bool,
        /// Destination name
        name: Option<String>,
    },
    /// Set the default system connection
    Default {
        /// Destination name
        name: String,
    },
    /// Rename a system connection
    Rename {
        old: String,
        new: String,
    },
}
