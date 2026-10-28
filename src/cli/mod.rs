pub mod artifact;
pub mod usage_errors;
pub mod container;
pub mod farm;
pub mod image;
pub mod kube;
pub mod machine;
pub mod quadlet;
pub mod secret;
pub mod system;
pub mod volumes_networks;

pub use artifact::*;
pub use container::*;
pub use farm::*;
pub use image::*;
pub use kube::*;
pub use machine::*;
pub use quadlet::*;
pub use secret::*;
pub use system::*;
pub use volumes_networks::*;

use clap::{Args, Parser, Subcommand};
use std::sync::OnceLock;

/// When argv contains `--rm=false`, clap would otherwise treat `--rm` as a boolean flag.
pub static RUN_RM_EXPLICIT_FALSE: OnceLock<bool> = OnceLock::new();

/// Podman `run --read-only=false` (clap `SetTrue` cannot represent this).
pub static READ_ONLY_EXPLICIT_FALSE: OnceLock<bool> = OnceLock::new();

/// Strip `--rm=false` before clap parsing (Podman accepts `run --rmi --rm=false`).
/// Podman global flags that take a value; stripped before clap (e2e / storage init).
const PODMAN_GLOBAL_VALUE_FLAGS: &[&str] = &[
    "--root",
    "--runroot",
    "--tmpdir",
    "--storage-driver",
    "--conmon",
    "--network-config-dir",
    "--cgroup-manager",
    "--events-backend",
    "--transient-store",
];

pub fn preprocess_argv(argv: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut rm_false = false;
    let mut read_only_false = false;
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--rm=false" {
            rm_false = true;
            i += 1;
            continue;
        }
        if a == "--read-only=false" {
            read_only_false = true;
            i += 1;
            continue;
        }
        if a == "--read-only=true" {
            out.push("--read-only".to_string());
            i += 1;
            continue;
        }
        if PODMAN_GLOBAL_VALUE_FLAGS.contains(&a.as_str()) {
            i += 2;
            continue;
        }
        out.push(a.clone());
        i += 1;
    }
    if rm_false {
        let _ = RUN_RM_EXPLICIT_FALSE.set(true);
    }
    if read_only_false {
        let _ = READ_ONLY_EXPLICIT_FALSE.set(true);
    }
    out
}

/// Help layout expected by Podman `test/system/015-help.bats` (`grep -A1 '^Usage:'`).
pub const PODMAN_LEAF_HELP: &str = "\
{about-with-newline}\
Usage:\n  \
{usage}\n\
\n\
{all-args}\
";

/// Empty Podman stub commands (swarm, plugin, …) for help-test compatibility.
#[derive(Args, Debug, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct StubCommandArgs {}

/// `podman help [command]` (Podman BATS 015-help).
#[derive(Args, Debug, Default)]
#[command(
    about = "Help about any command",
    help_template = crate::cli::PODMAN_LEAF_HELP,
    override_usage = "podman help [command] [options]"
)]
pub struct HelpArgs {
    #[arg(value_name = "command")]
    pub command: Vec<String>,
}

pub const PODMAN_GROUP_HELP: &str = "\
{about-with-newline}\
Usage:\n  \
{usage}\n\
\n\
Available Commands:\n\
{subcommands}\n\
\n\
Options:\n\
{options}\
";

#[derive(Parser, Debug)]
#[command(
    name = "podman",
    bin_name = "podman",
    author = "Boxr Contributors",
    version,
    about = "Manage pods, containers and images",
    long_about = "Manage pods, containers and images",
    subcommand_required = true,
    arg_required_else_help = false,
    disable_help_subcommand = true,
    help_template = crate::cli::PODMAN_GROUP_HELP
)]
pub struct Cli {
    /// Path of the authentication file (Podman-compatible global flag)
    #[arg(global = true, long = "authfile")]
    pub authfile: Option<String>,
    /// Suppress stdout from supported commands (Podman global flag)
    #[arg(global = true, long = "noout")]
    pub noout: bool,
    /// Write container ID to a file instead of stdout (Podman global flag)
    #[arg(global = true, long = "out", value_name = "FILE")]
    pub out: Option<String>,
    /// Flags passed through to the OCI runtime (Podman global flag)
    #[arg(global = true, long = "runtime-flag", value_name = "FLAG")]
    pub runtime_flag: Vec<String>,
    /// Log container output via syslog (accepted for Podman BATS; no-op in boxr)
    #[arg(global = true, long = "syslog")]
    pub syslog: bool,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Help about any command
    Help(HelpArgs),

    /// Pull an image from an OCI registry (Docker Hub, GHCR, Quay, etc.)
    Pull(PullArgs),

    /// Run a command in a new container
    Run(RunArgs),

    /// Create a new container without starting it
    Create(RunArgs),

    /// Restart one or more containers
    Restart(RestartArgs),

    /// List port mappings or a specific mapping for the container
    Port(PortArgs),

    /// Create a tag TARGET_IMAGE that refers to SOURCE_IMAGE
    Tag(TagArgs),

    /// Export a container's filesystem as a tar archive
    Export(ExportArgs),

    /// Import the contents from a tarball to create a filesystem image
    Import(ImportArgs),

    /// Show the history of an image
    History(HistoryArgs),

    /// Search Docker Hub for images
    Search(SearchArgs),

    /// Display system-wide information
    Info(FormatArgs),

    /// Show the boxr version information
    Version(FormatArgs),

    /// Stop a running container
    Stop(StopArgs),

    /// Start a stopped container
    Start(StartArgs),

    /// Fetch the logs of a container
    Logs(LogsArgs),

    /// Run a command in an existing container
    Exec(ExecArgs),

    /// Return low-level information on Boxr objects
    Inspect(InspectArgs),

    /// Build an image from a Dockerfile
    Build(BuildArgs),

    /// Manage Docker Compose projects
    Compose(ComposeArgs),

    /// Save one or more images to a tar archive
    Save(SaveArgs),

    /// Load an image from a tar archive or STDIN
    Load(LoadArgs),

    /// Push an image to an OCI registry
    Push(PushArgs),

    /// Log in to a Docker registry
    Login(LoginArgs),

    /// Log out from a Docker registry
    Logout(LogoutArgs),

    /// Manage volumes
    Volume(VolumeSubcommands),

    /// Manage networks
    Network(NetworkSubcommands),

    /// Start the Boxr daemon process
    Daemon(DaemonArgs),

    /// List containers
    Ps(PsArgs),

    /// List images
    Images(ImagesArgs),

    /// Remove one or more containers
    Rm(RmArgs),

    /// Remove one or more images
    Rmi(RmiArgs),

    /// Manage containers
    Container(ContainerSubcommands),

    /// Manage images
    Image(ImageSubcommands),

    /// Manage builds
    Builder(BuilderSubcommands),

    /// Display a live stream of container(s) resource usage statistics
    Stats(StatsArgs),

    /// Get real time events from the server
    Events(EventsArgs),

    /// Generate shell auto-completion scripts
    Completion(CompletionArgs),

    /// Set up a transparent docker alias wrapper
    Alias(AliasArgs),

    /// Inspect changes to files on a container's filesystem
    Diff(DiffArgs),

    /// Display the running processes of a container
    Top(TopArgs),

    /// Create a new image from a container's changes
    Commit(CommitArgs),

    /// Pause all processes within one or more containers
    Pause(PauseArgs),

    /// Unpause all processes within one or more containers
    Unpause(UnpauseArgs),

    /// Rename a container
    Rename(RenameArgs),

    /// Block until one or more containers stop, then print their exit codes
    Wait(WaitArgs),

    /// Copy files/folders between a container and the local filesystem
    Cp(CpArgs),

    /// Update configuration of one or more containers
    Update(UpdateArgs),

    /// Attach local standard input, output, and error streams to a running container
    Attach(AttachArgs),

    /// Kill one or more running containers
    Kill(KillArgs),

    /// Manage system disk usage and cleanups
    System(SystemSubcommands),

    /// Manage pods
    Pod(PodSubcommands),

    /// Play a pod from a structured file
    Play(PlaySubcommands),

    /// Generate structured specifications for containers or pods
    Generate(GenerateSubcommands),

    /// Run a command in a user namespace
    Unshare(UnshareArgs),

    /// Generate a standard OCI runtime specification (config.json)
    Spec(SpecArgs),

    /// Manage Docker contexts
    Context(ContextSubcommands),

    /// Manage Docker image manifests and manifest lists
    Manifest(ManifestSubcommands),

    /// Manage the Boxr background daemon service (launchd on macOS, systemd on Linux)
    Service(ServiceArgs),

    /// Manage Swarm (stub)
    Swarm(StubCommandArgs),

    /// Manage plugins (stub)
    Plugin(StubCommandArgs),

    /// Manage Swarm configs (stub)
    Config(StubCommandArgs),

    /// Manage secrets
    Secret(SecretSubcommands),

    /// Manage Swarm nodes (stub)
    Node(StubCommandArgs),

    /// Manage trust (stub)
    Trust(StubCommandArgs),

    /// Manage Podman-style virtual machines (macOS / Windows)
    Machine(MachineSubcommands),

    /// Mount a container's root filesystem and return the mount path
    Mount(MountArgs),

    /// Unmount a container's root filesystem
    #[command(alias = "umount")]
    Unmount(UnmountArgs),

    /// Manage OCI artifacts
    Artifact(ArtifactSubcommands),

    /// Farm out builds to machines running podman for different architectures
    Farm(FarmSubcommands),

    /// Auto-update containers based on updated images
    #[command(name = "auto-update")]
    AutoUpdate(AutoUpdateArgs),

    /// Run health check on a container
    Healthcheck(HealthcheckSubcommands),

    /// Manage Quadlet systemd unit files
    Quadlet(QuadletSubcommands),

    /// Modern Kubernetes YAML resources manager (play, down, generate, apply)
    Kube(KubeSubcommands),

    /// Initialize a container
    Init(InitArgs),

    /// Remove one or more tags from an image
    Untag(UntagArgs),
}
