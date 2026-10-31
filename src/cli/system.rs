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
        #[arg(short = 't', long = "time")]
        timeout: Option<u64>,
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
    #[arg(short = 'f', long = "format")]
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
    #[arg(long = "name")]
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
    /// Memory limit for all containers in the pod
    #[arg(short = 'm', long = "memory")]
    pub memory: Option<String>,
    /// CPU limit for all containers in the pod
    #[arg(long = "cpus")]
    pub cpus: Option<String>,
    /// Network mode for the pod
    #[arg(long = "network", alias = "net")]
    pub network: Option<String>,
    /// User namespace mode for the pod
    #[arg(long = "userns")]
    pub userns: Option<String>,
    /// Add a custom host-to-IP mapping (host:ip)
    #[arg(long = "add-host")]
    pub add_host: Vec<String>,
    /// Share namespaces: ipc, net, uts, pid (comma-separated)
    #[arg(
        long = "share",
        default_value = "ipc,net,uts",
        num_args = 0..=1,
        default_missing_value = ""
    )]
    pub share: String,
    /// Create an infra container
    #[arg(long = "infra", default_value_t = true)]
    pub infra: bool,
    /// Do not create an infra container
    #[arg(long = "no-infra", default_value_t = false)]
    pub no_infra: bool,
    /// Custom image for infra container
    #[arg(long = "infra-image")]
    pub infra_image: Option<String>,
    /// Custom command for infra container
    #[arg(long = "infra-command")]
    pub infra_command: Option<String>,
    /// Custom name for infra container
    #[arg(long = "infra-name")]
    pub infra_name: Option<String>,
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
        #[arg(short = 't', long = "time", value_name = "SECONDS")]
        time: Option<u32>,
        #[arg(short = 'a', long = "all")]
        all: bool,
        #[arg(long = "ignore")]
        ignore: bool,
        pods: Vec<String>,
    },
    /// Display detailed information on one or more pods
    Inspect {
        #[arg(short = 'f', long = "format")]
        format: Option<String>,
        pods: Vec<String>,
    },
    /// Stop one or more pods
    Stop { pods: Vec<String> },
    /// Start one or more pods
    Start { pods: Vec<String> },
    /// Restart one or more pods
    Restart { pods: Vec<String> },
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
    /// Generate systemd unit files for a container (Quadlet-compatible)
    Systemd {
        /// Container name(s) to generate units for
        containers: Vec<String>,
        /// Output directory (default: stdout)
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
        /// Restart policy for generated unit
        #[arg(long = "restart", default_value = "always")]
        restart: String,
    },
    /// Generate Podman Specgen JSON for a container
    Spec(GenerateSpecArgs),
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct UnshareArgs {
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
    pub pod: String,
    /// Show timestamps
    #[arg(short = 't', long = "timestamps")]
    pub timestamps: bool,
    /// Number of lines to show from the end of the logs
    #[arg(short = 'n', long = "tail")]
    pub tail: Option<usize>,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct GenerateSpecArgs {
    /// Container name or ID to generate Specgen JSON for
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
    Ls,
    /// Add a new system connection
    Add {
        /// Destination name
        name: String,
        /// Destination URI
        uri: String,
        /// Default connection
        #[arg(long = "default")]
        default: bool,
    },
    /// Remove a system connection
    Rm {
        /// Destination name
        name: String,
    },
    /// Set the default system connection
    Default {
        /// Destination name
        name: String,
    },
}
