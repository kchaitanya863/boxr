use crate::cli::image::RegistryAuthArgs;
use clap::Args;

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

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ContainerExistsArgs {
    /// Check external storage containers (e.g. buildah)
    #[arg(long = "external")]
    pub external: bool,

    #[arg(value_name = "CONTAINER")]
    pub container: String,
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

    /// Display namespace information (for custom --format templates)
    #[arg(long = "ns")]
    pub ns: bool,

    /// Container names or IDs (accepted only for validation; not supported with --latest)
    #[arg(value_name = "CONTAINER")]
    pub containers: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct RmArgs {
    /// Force the removal of a running container
    #[arg(short = 'f', long = "force")]
    pub force: bool,

    /// Remove anonymous volumes associated with the container
    #[arg(short = 'v', long = "volumes")]
    pub volumes: bool,

    /// Remove the specified link
    #[arg(long = "link")]
    pub link: bool,

    /// Act on the latest container
    #[arg(short = 'l', long = "latest")]
    pub latest: bool,

    /// Remove all containers
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    /// Seconds to wait before killing a container (0 = immediate, -1 = no limit)
    #[arg(
        short = 't',
        long = "time",
        value_name = "SECONDS",
        allow_hyphen_values = true
    )]
    pub time: Option<i32>,

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
    /// Format output using a custom template or 'json'
    #[arg(short = 'f', long = "format")]
    pub format: Option<String>,

    /// Act on the latest container
    #[arg(short = 'l', long = "latest")]
    pub latest: bool,

    /// Container to inspect changes on
    #[arg(required_unless_present = "latest")]
    pub container: Option<String>,
}

#[derive(Args, Debug)]
#[command(trailing_var_arg = true, help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct TopArgs {
    /// Container to inspect processes on
    pub container: String,

    /// Optional ps arguments
    #[arg(allow_hyphen_values = true)]
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
pub struct RenameArgs {
    /// Container to rename
    pub container: String,

    /// New name for the container
    pub new_name: String,
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
    /// Name for the cloned container
    #[arg(long = "name")]
    pub name: Option<String>,

    /// Start the container after cloning
    #[arg(long = "run")]
    pub run: bool,

    /// Destroy the original container after cloning
    #[arg(long = "destroy")]
    pub destroy: bool,

    /// Force removing the original container (requires --destroy)
    #[arg(short = 'f', long = "force")]
    pub force: bool,

    /// CPU limit for the cloned container
    #[arg(long = "cpus")]
    pub cpus: Option<String>,

    /// Memory limit for the cloned container
    #[arg(long = "memory")]
    pub memory: Option<String>,

    /// Join an existing pod
    #[arg(long = "pod")]
    pub pod: Option<String>,

    /// Container to clone from
    #[arg(value_name = "CONTAINER")]
    pub source: String,

    /// Name for the clone (positional)
    #[arg(value_name = "NAME")]
    pub positional_name: Option<String>,

    /// Image for the clone (positional)
    #[arg(value_name = "IMAGE")]
    pub positional_image: Option<String>,
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
