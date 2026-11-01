use super::run::RunArgs;
use clap::Args;

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct StopArgs {
    /// Seconds to wait before killing the container
    #[arg(short = 't', long = "time", alias = "timeout")]
    pub time: Option<i32>,

    /// Signal to send to the container
    #[arg(short = 's', long = "signal")]
    pub signal: Option<String>,

    /// Stop all running containers
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    /// Act on the latest container
    #[arg(short = 'l', long = "latest")]
    pub latest: bool,

    /// Ignore errors when a container cannot be stopped
    #[arg(long = "ignore")]
    pub ignore: bool,

    /// Suppress output
    #[arg(long = "noout")]
    pub noout: bool,

    /// Read container ID from the given file
    #[arg(long = "cidfile")]
    pub cidfile: Option<String>,

    #[arg(value_name = "CONTAINER")]
    pub containers: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct StartArgs {
    /// Attach container's STDOUT and STDERR and forward signals
    #[arg(short = 'a', long = "attach")]
    pub attach: bool,

    /// Proxy received signals to the process
    #[arg(
        long = "sig-proxy",
        default_value_t = true,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    pub sig_proxy: bool,

    /// Attach container's STDIN
    #[arg(short = 'i', long = "interactive")]
    pub interactive: bool,

    /// Override the key sequence for detaching a container
    #[arg(long = "detach-keys")]
    pub detach_keys: Option<String>,

    /// Restore from a checkpoint
    #[arg(long = "checkpoint")]
    pub checkpoint: Option<String>,

    /// Directory from which to restore the checkpoint
    #[arg(long = "checkpoint-dir")]
    pub checkpoint_dir: Option<String>,

    /// Start all created or exited containers
    #[arg(long = "all")]
    pub all: bool,

    /// Act on the latest container
    #[arg(short = 'l', long = "latest")]
    pub latest: bool,

    /// Filter output based on conditions provided
    #[arg(long = "filter")]
    pub filter: Vec<String>,

    #[arg(value_name = "CONTAINER")]
    pub containers: Vec<String>,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct LogsArgs {
    /// Follow log output
    #[arg(short = 'f', long = "follow")]
    pub follow: bool,

    /// Show timestamps
    #[arg(short = 't', long = "timestamps")]
    pub timestamps: bool,

    /// Show extra details provided to logs
    #[arg(long = "details")]
    pub details: bool,

    /// Show logs since timestamp (e.g. 2013-01-02T13:23:37Z) or relative (e.g. 42m, -1s)
    #[arg(long = "since", allow_hyphen_values = true)]
    pub since: Option<String>,

    /// Show logs before a timestamp (e.g. 2013-01-02T13:23:37Z) or relative (e.g. 42m, 3s)
    #[arg(long = "until", allow_hyphen_values = true)]
    pub until: Option<String>,

    /// Number of lines to show from the end of the logs
    #[arg(short = 'n', long = "tail")]
    pub tail: Option<usize>,

    #[arg(required = true)]
    pub containers: Vec<String>,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP, disable_help_flag = true)]
pub struct ExecArgs {
    #[arg(short = 'i', long = "interactive")]
    pub interactive: bool,

    /// Allocate a pseudo-TTY
    #[arg(short = 't', long = "tty")]
    pub tty: bool,

    /// Detached mode: run command in the background
    #[arg(short = 'd', long = "detach")]
    pub detach: bool,

    /// Act on the latest container
    #[arg(short = 'l', long = "latest")]
    pub latest: bool,

    /// Give extended privileges to the command
    #[arg(long = "privileged")]
    pub privileged: bool,

    /// Read in a file of environment variables
    #[arg(long = "env-file")]
    pub env_file: Option<String>,

    /// Override the key sequence for detaching a container
    #[arg(long = "detach-keys")]
    pub detach_keys: Option<String>,

    /// Working directory inside the container
    #[arg(short = 'w', long = "workdir")]
    pub workdir: Option<String>,

    /// Username or UID (format: <name|uid>)
    #[arg(short = 'u', long = "user")]
    pub user: Option<String>,

    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,

    /// Pass down N additional file descriptors (starting at fd 3)
    #[arg(long = "preserve-fds")]
    pub preserve_fds: Option<u32>,

    /// Pass down specific file descriptors (comma-separated, e.g. 9,40)
    #[arg(long = "preserve-fd")]
    pub preserve_fd: Vec<String>,

    pub container: String,

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

impl ExecArgs {
    pub fn resolved_preserve_fds(&self) -> Vec<u32> {
        RunArgs::resolved_preserve_fds_from(self.preserve_fds, &self.preserve_fd)
    }
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct PauseArgs {
    /// Pause all running containers
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    /// Act on the latest container
    #[arg(short = 'l', long = "latest")]
    pub latest: bool,

    /// Read container ID from the given file
    #[arg(long = "cidfile")]
    pub cidfile: Vec<String>,

    /// Filter output based on conditions provided
    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,

    /// Containers to pause
    pub containers: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct UnpauseArgs {
    /// Unpause all paused containers
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    /// Act on the latest container
    #[arg(short = 'l', long = "latest")]
    pub latest: bool,

    /// Read container ID from the given file
    #[arg(long = "cidfile")]
    pub cidfile: Vec<String>,

    /// Filter output based on conditions provided
    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,

    /// Containers to unpause
    pub containers: Vec<String>,
}

#[derive(Args, Debug, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct WaitArgs {
    /// Ignore missing containers
    #[arg(long = "ignore")]
    pub ignore: bool,

    /// Condition to wait on (e.g. running, stopped, exited)
    #[arg(long = "condition")]
    pub condition: Vec<String>,

    /// Time interval to wait before polling for completion
    #[arg(short = 'i', long = "interval")]
    pub interval: Option<String>,

    /// Act on the latest container
    #[arg(short = 'l', long = "latest")]
    pub latest: bool,
    /// Containers to wait on
    pub containers: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct AttachArgs {
    /// Do not attach STDIN
    #[arg(long = "no-stdin")]
    pub no_stdin: bool,

    /// Proxy received signals to the process
    #[arg(
        long = "sig-proxy",
        default_value_t = true,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    pub sig_proxy: bool,

    /// Override the key sequence for detaching a container
    #[arg(long = "detach-keys")]
    pub detach_keys: Option<String>,

    /// Act on the latest container
    #[arg(short = 'l', long = "latest")]
    pub latest: bool,

    /// Container to attach to
    pub container: Option<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct KillArgs {
    /// Signal to send (e.g. SIGHUP, SIGTERM, SIGKILL)
    #[arg(short = 's', long = "signal", allow_hyphen_values = true)]
    pub signal: Option<String>,

    /// Signal all running containers
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    /// Container to kill
    #[arg(default_value = "")]
    pub container: String,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct RestartArgs {
    /// Seconds to wait before killing the container
    #[arg(short = 't', long = "time", default_value_t = 10)]
    pub time: u32,

    #[arg(short = 's', long = "signal")]
    pub signal: Option<String>,

    /// Container to restart
    pub container: String,
}
