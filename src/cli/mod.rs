pub mod artifact;
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

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "boxr",
    author = "Boxr Contributors",
    version,
    about = "A fast, lightweight OCI container engine and runtime written in Rust",
    long_about = "boxr is a complete Open Container Initiative (OCI) compliant container engine, image builder, compose orchestrator, and runtime written in Rust.",
    subcommand_required = true,
    arg_required_else_help = false
)]
pub struct Cli {
    /// Path of the authentication file (Podman-compatible global flag)
    #[arg(global = true, long = "authfile")]
    pub authfile: Option<String>,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
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
    Swarm,

    /// Manage plugins (stub)
    Plugin,

    /// Manage Swarm configs (stub)
    Config,

    /// Manage secrets
    Secret(SecretSubcommands),

    /// Manage Swarm nodes (stub)
    Node,

    /// Manage trust (stub)
    Trust,

    /// Manage Podman-style virtual machines (macOS / Windows)
    Machine(MachineSubcommands),

    /// Mount a container's root filesystem and return the mount path
    Mount { container: String },

    /// Unmount a container's root filesystem
    #[command(alias = "umount")]
    Unmount { container: String },

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
    Init { container: String },

    /// Remove one or more tags from an image
    Untag(UntagArgs),
}
