use clap::{Args, Subcommand};

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct MachineSubcommands {
    #[command(subcommand)]
    pub command: MachineAction,
}

#[derive(Subcommand, Debug)]
pub enum MachineAction {
    /// Initialize a new virtual machine
    Init {
        /// Machine name
        name: Option<String>,
        /// Create and start in one step
        #[arg(long = "now")]
        now: bool,
        /// Run machine in rootful mode
        #[arg(long = "rootful")]
        rootful: bool,
    },
    /// Start a virtual machine
    Start { name: Option<String> },
    /// Stop a virtual machine
    Stop { name: Option<String> },
    /// List virtual machines
    #[command(alias = "list")]
    Ls {
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
        #[arg(short = 'n', long = "noheading", alias = "no-heading")]
        noheading: bool,
        #[arg(long = "format")]
        format: Option<String>,
    },
    /// Remove a virtual machine
    Rm {
        name: Option<String>,
        #[arg(short = 'f', long = "force")]
        force: bool,
    },
    /// SSH into a virtual machine
    Ssh {
        name: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Display machine host info
    Info { name: Option<String> },
    /// Copy files between host and virtual machine
    Cp { source: String, dest: String },
    /// Inspect details of a virtual machine
    Inspect { name: Option<String> },
    /// Set machine properties
    Set(MachineSetArgs),
    /// Manage the virtual machine operating system
    Os(MachineOsArgs),
    /// Reset a virtual machine
    Reset {
        #[arg(short = 'f', long = "force")]
        force: bool,
    },
    /// Restart a virtual machine
    Restart { name: Option<String> },
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct MachineSetArgs {
    /// Machine name
    pub name: Option<String>,
    /// Number of CPUs
    #[arg(long = "cpus")]
    pub cpus: Option<u64>,
    /// Memory size in MB
    #[arg(short = 'm', long = "memory")]
    pub memory: Option<u64>,
    /// Disk size in GB
    #[arg(long = "disk-size")]
    pub disk_size: Option<u64>,
    /// Rootful mode
    #[arg(long = "rootful")]
    pub rootful: bool,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct MachineOsArgs {
    #[command(subcommand)]
    pub action: MachineOsAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum MachineOsAction {
    /// Apply an OS update to the machine
    Apply { name: Option<String> },
    /// Check for available OS updates
    Check { name: Option<String> },
}
