use clap::{Args, Subcommand};

use super::image::RegistryAuthArgs;

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct RunArgs {
    #[command(flatten)]
    pub registry_auth: RegistryAuthArgs,
    #[arg(short = 'i', long = "interactive")]
    pub interactive: bool,

    #[arg(
        short = 't',
        long = "tty",
        action = clap::ArgAction::Set,
        default_value = "false",
        value_parser = clap::value_parser!(bool)
    )]
    pub tty: bool,

    #[arg(short = 'd', long = "detach")]
    pub detach: bool,

    #[arg(long = "rm")]
    pub rm: bool,

    #[arg(long = "name")]
    pub name: Option<String>,

    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,

    /// Unset environment variables
    #[arg(long = "unsetenv")]
    pub unsetenv: Vec<String>,

    /// Unset all default environment variables
    #[arg(long = "unsetenv-all")]
    pub unsetenv_all: bool,

    /// Run container in systemd mode (Podman-compatible flag; accepted for parity)
    #[arg(long = "systemd")]
    pub systemd: Option<String>,

    #[arg(short = 'p', long = "publish")]
    pub ports: Vec<String>,

    #[arg(short = 'v', long = "volume")]
    pub volumes: Vec<String>,

    /// Working directory inside the container
    #[arg(short = 'w', long = "workdir")]
    pub workdir: Option<String>,

    #[arg(short = 'm', long = "memory")]
    pub memory: Option<String>,

    /// Set metadata on container (format: <key>=<value>)
    #[arg(short = 'l', long = "label")]
    pub labels: Vec<String>,

    /// Set custom DNS servers
    #[arg(long = "dns")]
    pub dns: Vec<String>,

    /// Write the container ID to the file
    #[arg(long = "cidfile")]
    pub cidfile: Option<String>,

    /// Set environment variables from a file
    #[arg(long = "env-file")]
    pub env_file: Option<String>,

    /// Number of CPUs (e.g. 1.5)
    #[arg(long = "cpus")]
    pub cpus: Option<String>,

    /// Tune container pids limit (set -1 for unlimited)
    #[arg(long = "pids-limit")]
    pub pids_limit: Option<i64>,

    /// Username or UID (format: <name|uid>[:<group|gid>])
    #[arg(short = 'u', long = "user")]
    pub user: Option<String>,

    /// Container host name
    #[arg(long = "hostname")]
    pub hostname: Option<String>,

    /// Add a custom host-to-IP mapping (host:ip)
    #[arg(long = "add-host")]
    pub add_host: Vec<String>,

    /// Run container in rootless mode
    #[arg(long = "rootless", default_value_t = true)]
    pub rootless: bool,

    /// Restart policy to apply when a container exits
    #[arg(long = "restart", default_value = "no")]
    pub restart: String,

    /// Command to run to check health
    #[arg(long = "health-cmd")]
    pub health_cmd: Option<String>,

    /// Set platform if server is multi-platform
    #[arg(long = "platform")]
    pub platform: Option<String>,

    /// Connect a container to a network
    #[arg(long = "network", alias = "net", default_value = "auto")]
    pub network: String,

    #[arg(long = "disable-content-trust")]
    pub disable_content_trust: bool,

    /// Give extended privileges to this container
    #[arg(long = "privileged")]
    pub privileged: bool,

    /// GPU devices to add to the container ('all' to pass all GPUs)
    #[arg(long = "gpus")]
    pub gpus: Option<String>,

    /// Overwrite the default ENTRYPOINT of the image
    #[arg(long = "entrypoint")]
    pub entrypoint: Option<String>,

    /// Set timezone in container
    #[arg(long = "tz", action = clap::ArgAction::Append)]
    pub tz: Vec<String>,

    /// Size of /dev/shm
    #[arg(long = "shm-size")]
    pub shm_size: Option<String>,

    /// Add Linux capabilities
    #[arg(long = "cap-add")]
    pub cap_add: Vec<String>,

    /// Drop Linux capabilities
    #[arg(long = "cap-drop")]
    pub cap_drop: Vec<String>,

    /// Mount the container's root filesystem as read only
    #[arg(long = "read-only")]
    pub read_only: bool,

    /// Run an init inside the container that forwards signals and reaps processes
    #[arg(long = "init")]
    pub init: bool,

    /// Mount a tmpfs directory
    #[arg(long = "tmpfs")]
    pub tmpfs: Vec<String>,

    /// Add a host device to the container
    #[arg(long = "device")]
    pub devices: Vec<String>,

    /// Security Options
    #[arg(long = "security-opt")]
    pub security_opt: Vec<String>,

    /// CPU shares (relative weight)
    #[arg(short = 'c', long = "cpu-shares")]
    pub cpu_shares: Option<u64>,

    /// Limit CPU CFS (Completely Fair Scheduler) period
    #[arg(long = "cpu-period")]
    pub cpu_period: Option<u64>,

    /// Limit CPU CFS (Completely Fair Scheduler) quota
    #[arg(long = "cpu-quota")]
    pub cpu_quota: Option<i64>,

    /// CPUs in which to allow execution (0-3, 0,1)
    #[arg(long = "cpuset-cpus")]
    pub cpuset_cpus: Option<String>,

    /// Swap limit equal to memory plus swap: '-1' to enable unlimited swap
    #[arg(long = "memory-swap")]
    pub memory_swap: Option<String>,

    /// Memory soft limit
    #[arg(long = "memory-reservation")]
    pub memory_reservation: Option<String>,

    /// Set custom DNS search domains
    #[arg(long = "dns-search")]
    pub dns_search: Vec<String>,

    /// Set DNS options
    #[arg(long = "dns-option")]
    pub dns_option: Vec<String>,

    /// Expose a port or a range of ports
    #[arg(long = "expose")]
    pub expose: Vec<String>,

    /// Sysctl options
    #[arg(long = "sysctl")]
    pub sysctl: Vec<String>,

    /// Timeout (in seconds) to stop a container
    #[arg(long = "stop-timeout")]
    pub stop_timeout: Option<u64>,

    /// Signal to stop the container
    #[arg(long = "stop-signal")]
    pub stop_signal: Option<String>,

    /// Add an annotation to the container (passed through to the OCI runtime)
    #[arg(long = "annotation")]
    pub annotations: Vec<String>,

    /// Ulimit options
    #[arg(long = "ulimit")]
    pub ulimits: Vec<String>,

    /// IPC mode to use
    #[arg(long = "ipc")]
    pub ipc: Option<String>,

    /// PID namespace to use
    #[arg(long = "pid")]
    pub pid: Option<String>,

    /// UTS namespace to use
    #[arg(long = "uts")]
    pub uts: Option<String>,

    /// User namespace to use
    #[arg(long = "userns")]
    pub userns: Option<String>,

    /// Cgroup namespace to use
    #[arg(long = "cgroupns")]
    pub cgroupns: Option<String>,

    /// Optional parent cgroup for the container
    #[arg(long = "cgroup-parent")]
    pub cgroup_parent: Option<String>,

    /// Container isolation technology
    #[arg(long = "isolation")]
    pub isolation: Option<String>,

    /// Number of CPUs (Windows only)
    #[arg(long = "cpu-count")]
    pub cpu_count: Option<i64>,

    /// CPU percent (Windows only)
    #[arg(long = "cpu-percent")]
    pub cpu_percent: Option<i64>,

    /// Maximum IO bandwidth limit for the system drive (Windows only)
    #[arg(long = "io-maxbandwidth")]
    pub io_maxbandwidth: Option<String>,

    /// Maximum IOps limit for the system drive (Windows only)
    #[arg(long = "io-maxiops")]
    pub io_maxiops: Option<u64>,

    /// Publish all exposed ports to random ports
    #[arg(short = 'P', long = "publish-all")]
    pub publish_all: bool,

    /// IPv4 address (e.g., 172.30.100.104)
    #[arg(long = "ip")]
    pub ip: Option<String>,

    /// IPv6 address (e.g., 2001:db8::33)
    #[arg(long = "ip6")]
    pub ip6: Option<String>,

    /// Container MAC address (e.g., 92:d0:c6:0a:29:33)
    #[arg(long = "mac-address")]
    pub mac_address: Option<String>,

    /// Add link to another container
    #[arg(long = "link")]
    pub link: Vec<String>,

    /// Add network-scoped alias for the container
    #[arg(long = "network-alias")]
    pub network_alias: Vec<String>,

    /// Attach a filesystem mount to the container
    #[arg(long = "mount")]
    pub mount: Vec<String>,

    /// Time between running the check (ms|s|m|h) (default 30s)
    #[arg(long = "health-interval")]
    pub health_interval: Option<String>,

    /// Maximum time to allow one check to run (ms|s|m|h) (default 30s)
    #[arg(long = "health-timeout")]
    pub health_timeout: Option<String>,

    /// Consecutive failures needed to report unhealthy
    #[arg(long = "health-retries")]
    pub health_retries: Option<u32>,

    /// Start period for the container to initialize before starting health-retries countdown
    #[arg(long = "health-start-period")]
    pub health_start_period: Option<String>,

    /// Time between running the check during the start period
    #[arg(long = "health-start-interval")]
    pub health_start_interval: Option<String>,

    /// Disable any container-specified HEALTHCHECK
    #[arg(long = "no-healthcheck")]
    pub no_healthcheck: bool,

    /// Attach to STDIN, STDOUT or STDERR
    #[arg(short = 'a', long = "attach")]
    pub attach: Vec<String>,

    /// Pull image before running ("always", "missing", "never")
    #[arg(long = "pull")]
    pub pull: Option<String>,

    /// Suppress the pull output
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Logging driver for the container
    #[arg(long = "log-driver")]
    pub log_driver: Option<String>,

    /// Log driver options
    #[arg(long = "log-opt")]
    pub log_opt: Vec<String>,

    /// Disable OOM Killer
    #[arg(long = "oom-kill-disable")]
    pub oom_kill_disable: bool,

    /// Tune host's OOM preferences (-1000 to 1000)
    #[arg(long = "oom-score-adj")]
    pub oom_score_adj: Option<i32>,

    /// Add additional groups to join (format: <group|gid>)
    #[arg(long = "group-add")]
    pub group_add: Vec<String>,

    /// Read in a line delimited file of labels
    #[arg(long = "label-file")]
    pub label_file: Option<String>,

    /// Apply umask to container
    #[arg(long = "umask")]
    pub umask: Option<String>,

    /// Container NIS domain name
    #[arg(long = "domainname")]
    pub domainname: Option<String>,

    /// Override the key sequence for detaching a container
    #[arg(long = "detach-keys")]
    pub detach_keys: Option<String>,

    /// Block IO (relative weight), between 10 and 1000, or 0 to disable (default 0)
    #[arg(long = "blkio-weight")]
    pub blkio_weight: Option<u16>,

    /// Block IO weight (relative device weight)
    #[arg(long = "blkio-weight-device")]
    pub blkio_weight_device: Vec<String>,

    /// Limit CPU real-time period in microseconds
    #[arg(long = "cpu-rt-period")]
    pub cpu_rt_period: Option<i64>,

    /// Limit CPU real-time runtime in microseconds
    #[arg(long = "cpu-rt-runtime")]
    pub cpu_rt_runtime: Option<i64>,

    /// MEMs in which to allow execution (0-3, 0,1)
    #[arg(long = "cpuset-mems")]
    pub cpuset_mems: Option<String>,

    /// Add a rule to the cgroup allowed devices list
    #[arg(long = "device-cgroup-rule")]
    pub device_cgroup_rule: Vec<String>,

    /// Limit read rate (bytes per second) from a device
    #[arg(long = "device-read-bps")]
    pub device_read_bps: Vec<String>,

    /// Limit read rate (IO per second) from a device
    #[arg(long = "device-read-iops")]
    pub device_read_iops: Vec<String>,

    /// Limit write rate (bytes per second) to a device
    #[arg(long = "device-write-bps")]
    pub device_write_bps: Vec<String>,

    /// Limit write rate (IO per second) to a device
    #[arg(long = "device-write-iops")]
    pub device_write_iops: Vec<String>,

    /// Container IPv4/IPv6 link-local addresses
    #[arg(long = "link-local-ip")]
    pub link_local_ip: Vec<String>,

    /// Tune container memory swappiness (0 to 100)
    #[arg(long = "memory-swappiness")]
    pub memory_swappiness: Option<u64>,

    /// Runtime to use for this container
    #[arg(long = "runtime")]
    pub runtime: Option<String>,

    /// Proxy received signals to the process
    #[arg(long = "sig-proxy", default_value_t = true)]
    pub sig_proxy: bool,

    /// Storage driver options for the container
    #[arg(long = "storage-opt")]
    pub storage_opt: Vec<String>,

    /// Use the daemon API socket
    #[arg(long = "use-api-socket")]
    pub use_api_socket: bool,

    /// Optional volume driver for the container
    #[arg(long = "volume-driver")]
    pub volume_driver: Option<String>,

    /// Mount volumes from the specified container(s)
    #[arg(long = "volumes-from")]
    pub volumes_from: Vec<String>,

    /// Run container in an existing pod
    #[arg(long = "pod")]
    pub pod: Option<String>,

    /// Maximum time in seconds to run before killing the container
    #[arg(long = "timeout")]
    pub timeout: Option<u64>,

    pub image: String,

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

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

    /// Filter output based on conditions provided
    #[arg(long = "filter")]
    pub filter: Vec<String>,

    #[arg(value_name = "CONTAINER")]
    pub containers: Vec<String>,
}

#[derive(Args, Debug)]
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

    /// Show logs since timestamp (e.g. 2013-01-02T13:23:37Z) or relative (e.g. 42m)
    #[arg(long = "since")]
    pub since: Option<String>,

    /// Show logs before a timestamp (e.g. 2013-01-02T13:23:37Z) or relative (e.g. 42m)
    #[arg(long = "until")]
    pub until: Option<String>,

    /// Number of lines to show from the end of the logs
    #[arg(short = 'n', long = "tail")]
    pub tail: Option<usize>,

    pub container: String,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ExecArgs {
    #[arg(short = 'i', long = "interactive")]
    pub interactive: bool,

    /// Allocate a pseudo-TTY
    #[arg(short = 't', long = "tty")]
    pub tty: bool,

    /// Detached mode: run command in the background
    #[arg(short = 'd', long = "detach")]
    pub detach: bool,

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

    pub container: String,

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct InspectArgs {
    /// Format output using a custom template: 'json' or Go template
    #[arg(short = 'f', long = "format")]
    pub format: Option<String>,

    /// Display total file sizes if the type is container
    #[arg(short = 's', long = "size")]
    pub size: bool,

    /// Return JSON for specified type (container|image)
    #[arg(long = "type")]
    pub obj_type: Option<String>,

    /// Display the latest created container
    #[arg(short = 'l', long = "latest")]
    pub latest: bool,

    pub targets: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct ContainerSubcommands {
    #[command(subcommand)]
    pub command: ContainerAction,
}

#[derive(Subcommand, Debug)]
pub enum ContainerAction {
    Run(RunArgs),
    Create(RunArgs),
    Start(StartArgs),
    Stop(StopArgs),
    Restart(RestartArgs),
    Kill(KillArgs),
    Rm(RmArgs),
    Pause(PauseArgs),
    Unpause(UnpauseArgs),
    Wait(WaitArgs),
    Exec(ExecArgs),
    Attach(AttachArgs),
    Logs(LogsArgs),
    #[command(alias = "ps")]
    Ls(PsArgs),
    Inspect(InspectArgs),
    Top(TopArgs),
    Port(PortArgs),
    Cp(CpArgs),
    Diff(DiffArgs),
    Prune(ContainerPruneArgs),
    Update(UpdateArgs),
    Export(ExportArgs),
    Rename(RenameArgs),
    Stats(super::system::StatsArgs),
    Commit(CommitArgs),
    /// Checkpoint a container
    Checkpoint(ContainerCheckpointArgs),
    /// Restore a container from a checkpoint
    Restore(ContainerRestoreArgs),
    /// Clean up container network and storage
    Cleanup(ContainerCleanupArgs),
    /// Clone a container into a new container
    Clone(ContainerCloneArgs),
    /// Initialize a container
    Init {
        container: String,
    },
    /// Run a container using an image label command
    Runlabel(ContainerRunlabelArgs),
    /// Mount a container filesystem
    Mount {
        container: String,
    },
    /// Unmount a container filesystem
    #[command(alias = "umount")]
    Unmount {
        container: String,
    },
    /// Return 0 if the container exists, 1 otherwise
    Exists {
        container: String,
    },
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ContainerPruneArgs {
    #[arg(short = 'f', long = "force")]
    pub force: bool,
    #[arg(long = "filter")]
    pub filter: Vec<String>,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct PsArgs {
    /// Show all containers (default shows just running)
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    /// Only display numeric IDs
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Display total file sizes
    #[arg(short = 's', long = "size")]
    pub size: bool,

    /// Don't truncate output
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,

    /// Format output using a custom template (e.g. json, table)
    #[arg(long = "format", allow_hyphen_values = true)]
    pub format: Option<String>,

    /// Show n last created containers (includes all states)
    #[arg(short = 'n', long = "last")]
    pub last: Option<usize>,

    /// Show the latest created container (includes all states)
    #[arg(short = 'l', long = "latest")]
    pub latest: bool,

    /// Filter output based on conditions provided
    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,

    /// Sort by name, id, or created (Podman-compatible)
    #[arg(long = "sort")]
    pub sort: Option<String>,

    /// Do not print headers
    #[arg(long = "noheading")]
    pub noheading: bool,

    /// Display external containers (buildah, etc.)
    #[arg(long = "external")]
    pub external: bool,

    /// Container names or IDs (accepted only for validation; not supported with --latest)
    #[arg(value_name = "CONTAINER")]
    pub containers: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct RmArgs {
    /// Force the removal of a running container
    #[arg(short = 'f', long = "force")]
    pub force: bool,

    /// Remove anonymous volumes associated with the container
    #[arg(short = 'v', long = "volumes")]
    pub volumes: bool,

    /// Remove the specified link
    #[arg(short = 'l', long = "link")]
    pub link: bool,

    /// Remove all containers
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    /// Seconds to wait before killing a container (0 = immediate)
    #[arg(short = 't', long = "time", value_name = "SECONDS")]
    pub time: Option<u32>,

    /// Ignore errors when a container cannot be removed
    #[arg(long = "ignore")]
    pub ignore: bool,

    /// Remove dependent containers before removing the container
    #[arg(long = "depend")]
    pub depend: bool,

    /// Container IDs or names to remove
    pub containers: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct DiffArgs {
    /// Container to inspect changes on
    pub container: String,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct TopArgs {
    /// Container to inspect processes on
    pub container: String,

    /// Optional ps arguments
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub ps_args: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct CommitArgs {
    /// Commit message
    #[arg(short = 'm', long = "message")]
    pub message: Option<String>,

    /// Author (e.g., "John Doe <john@example.com>")
    #[arg(short = 'a', long = "author")]
    pub author: Option<String>,

    /// Pause container during commit
    #[arg(short = 'p', long = "pause", default_value_t = true)]
    pub pause: bool,

    /// Container to commit
    pub container: String,

    /// Repository and optional tag (e.g., "my-image:v1")
    pub repo_tag: Option<String>,

    #[arg(long = "change")]
    pub change: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct PauseArgs {
    /// Containers to pause
    #[arg(required = true)]
    pub containers: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct UnpauseArgs {
    /// Containers to unpause
    #[arg(required = true)]
    pub containers: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct RenameArgs {
    /// Container to rename
    pub container: String,

    /// New name for the container
    pub new_name: String,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct WaitArgs {
    /// Ignore missing containers
    #[arg(long = "ignore")]
    pub ignore: bool,

    /// Containers to wait on
    #[arg(required = true)]
    pub containers: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct CpArgs {
    /// Source path (e.g. "my-container:/app/file" or "./local-file")
    pub src: String,

    /// Destination path (e.g. "./dest" or "my-container:/app/dest")
    pub dest: String,

    #[arg(long = "archive")]
    pub archive: bool,

    #[arg(long = "follow-link")]
    pub follow_link: bool,

    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct UpdateArgs {
    /// Memory limit
    #[arg(short = 'm', long = "memory")]
    pub memory: Option<String>,

    /// Memory soft limit
    #[arg(long = "memory-reservation")]
    pub memory_reservation: Option<String>,

    /// Swap limit equal to memory plus swap
    #[arg(long = "memory-swap")]
    pub memory_swap: Option<String>,

    /// CPU limit
    #[arg(long = "cpus")]
    pub cpus: Option<String>,

    /// CPU shares (relative weight)
    #[arg(short = 'c', long = "cpu-shares")]
    pub cpu_shares: Option<u64>,

    /// Limit CPU CFS (Completely Fair Scheduler) period
    #[arg(long = "cpu-period")]
    pub cpu_period: Option<u64>,

    /// Limit CPU CFS (Completely Fair Scheduler) quota
    #[arg(long = "cpu-quota")]
    pub cpu_quota: Option<i64>,

    /// CPUs in which to allow execution (0-3, 0,1)
    #[arg(long = "cpuset-cpus")]
    pub cpuset_cpus: Option<String>,

    /// MEMs in which to allow execution (0-3, 0,1)
    #[arg(long = "cpuset-mems")]
    pub cpuset_mems: Option<String>,

    /// Block IO (relative weight), between 10 and 1000, or 0 to disable
    #[arg(long = "blkio-weight")]
    pub blkio_weight: Option<u16>,

    /// Limit the CPU real-time period in microseconds
    #[arg(long = "cpu-rt-period")]
    pub cpu_rt_period: Option<i64>,

    /// Limit the CPU real-time runtime in microseconds
    #[arg(long = "cpu-rt-runtime")]
    pub cpu_rt_runtime: Option<i64>,

    /// Maximum number of PIDs
    #[arg(long = "pids-limit")]
    pub pids_limit: Option<i64>,

    /// Restart policy to apply when a container exits
    #[arg(long = "restart")]
    pub restart: Option<String>,

    /// Container to update
    pub container: String,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct AttachArgs {
    /// Do not attach STDIN
    #[arg(long = "no-stdin")]
    pub no_stdin: bool,

    /// Container to attach to
    pub container: String,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct KillArgs {
    /// Signal to send (e.g. SIGHUP, SIGTERM, SIGKILL)
    #[arg(short = 's', long = "signal")]
    pub signal: Option<String>,

    /// Container to kill
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

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct PortArgs {
    /// Container to inspect ports on
    pub container: String,

    /// Optional private port / protocol (e.g. 80/tcp)
    pub port: Option<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ExportArgs {
    /// Write to a file, instead of STDOUT
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Container to export
    pub container: String,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ContainerCheckpointArgs {
    /// Container to checkpoint
    pub container: String,

    /// Export checkpoint to a tar.gz archive
    #[arg(short = 'e', long = "export")]
    pub export: Option<String>,

    /// Keep all temporary checkpoint files
    #[arg(short = 'k', long = "keep")]
    pub keep: bool,

    /// Leave the container running after checkpoint
    #[arg(short = 'R', long = "leave-running")]
    pub leave_running: bool,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ContainerRestoreArgs {
    /// Container to restore
    pub container: String,

    /// Import checkpoint from a tar.gz archive
    #[arg(short = 'i', long = "import")]
    pub import: Option<String>,

    /// Keep all temporary checkpoint files
    #[arg(short = 'k', long = "keep")]
    pub keep: bool,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ContainerCleanupArgs {
    /// Container to cleanup
    pub container: Option<String>,

    /// Cleanup all containers
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    /// Remove the container after cleanup
    #[arg(long = "rm")]
    pub rm: bool,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ContainerCloneArgs {
    /// Container to clone from
    pub source: String,

    /// Name for the cloned container
    pub target: String,

    /// Start the container after cloning
    #[arg(long = "run")]
    pub run: bool,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ContainerRunlabelArgs {
    #[command(flatten)]
    pub registry_auth: RegistryAuthArgs,
    /// Label key to execute
    pub label: String,

    /// Image containing the label
    pub image: String,

    /// Extra arguments passed to the label command
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub extra_args: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct MountArgs {
    /// Container to mount
    pub container: String,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct UnmountArgs {
    /// Container to unmount
    pub container: String,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct InitArgs {
    /// Container to initialize
    pub container: String,
}
