use clap::{Args, Subcommand};

#[derive(Args, Debug, Clone)]
pub struct PullArgs {
    /// Set platform if server is multi-platform (e.g. linux/amd64, linux/arm64)
    #[arg(long = "platform")]
    pub platform: Option<String>,

    pub image: String,
}

#[derive(Args, Debug)]
pub struct SaveArgs {
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
    pub image: String,
}

#[derive(Args, Debug)]
pub struct LoadArgs {
    #[arg(short = 'i', long = "input")]
    pub input: Option<String>,
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,
}

#[derive(Args, Debug)]
pub struct PushArgs {
    pub image: String,
}

#[derive(Args, Debug)]
pub struct LoginArgs {
    #[arg(short = 'u', long = "username")]
    pub username: Option<String>,
    #[arg(short = 'p', long = "password")]
    pub password: Option<String>,
    #[arg(long = "password-stdin")]
    pub password_stdin: bool,
    pub server: Option<String>,
}

#[derive(Args, Debug)]
pub struct LogoutArgs {
    pub server: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct BuildArgs {
    #[arg(short = 't', long = "tag")]
    pub tags: Vec<String>,

    #[arg(short = 'f', long = "file", default_value = "Dockerfile")]
    pub file: String,

    #[arg(long = "no-cache")]
    pub no_cache: bool,

    /// Set build-time variables
    #[arg(long = "build-arg")]
    pub build_args: Vec<String>,

    /// Set the target build stage to build
    #[arg(long = "target")]
    pub target: Option<String>,

    /// Add a custom host-to-IP mapping (host:ip)
    #[arg(long = "add-host")]
    pub add_host: Vec<String>,

    /// Set memory limit for build
    #[arg(short = 'm', long = "memory")]
    pub memory: Option<String>,

    /// Size of /dev/shm
    #[arg(long = "shm-size")]
    pub shm_size: Option<String>,

    /// Always remove intermediate containers
    #[arg(long = "rm", default_value_t = true)]
    pub rm: bool,

    /// Do not cache specified stages
    #[arg(long = "no-cache-filter")]
    pub no_cache_filter: Vec<String>,

    /// Set build-time CPU shares
    #[arg(short = 'c', long = "cpu-shares")]
    pub cpu_shares: Option<u64>,

    /// CPUs in which to allow execution (0-3, 0,1)
    #[arg(long = "cpuset-cpus")]
    pub cpuset_cpus: Option<String>,

    /// MEMs in which to allow execution (0-3, 0,1)
    #[arg(long = "cpuset-mems")]
    pub cpuset_mems: Option<String>,

    /// Limit CPU CFS period
    #[arg(long = "cpu-period")]
    pub cpu_period: Option<u64>,

    /// Limit CPU CFS quota
    #[arg(long = "cpu-quota")]
    pub cpu_quota: Option<i64>,

    /// Set platform if server is multi-platform
    #[arg(long = "platform")]
    pub platform: Option<String>,

    /// Set isolation technology
    #[arg(long = "isolation")]
    pub isolation: Option<String>,

    /// Label to set on the image
    #[arg(long = "label")]
    pub labels: Vec<String>,

    /// Suppress the build output and print image ID on success
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Squash newly built layers into a single new layer
    #[arg(long = "squash")]
    pub squash: bool,

    #[arg(long = "disable-content-trust")]
    pub disable_content_trust: bool,

    #[arg(long = "output")]
    pub output: Option<String>,

    #[arg(long = "progress")]
    pub progress: Option<String>,

    #[arg(long = "secret")]
    pub secret: Vec<String>,

    #[arg(long = "ssh")]
    pub ssh: Vec<String>,

    #[arg(default_value = ".")]
    pub path: String,
}

#[derive(Args, Debug)]
pub struct BuilderSubcommands {
    #[command(subcommand)]
    pub command: BuilderAction,
}

#[derive(Subcommand, Debug)]
pub enum BuilderAction {
    /// Prune build cache
    Prune(BuilderPruneArgs),
    /// Build an image
    Build(BuildArgs),
    /// Show build cache disk usage
    Du,
}

#[derive(Args, Debug, Clone, Default)]
pub struct BuilderPruneArgs {
    #[arg(short = 'a', long = "all")]
    pub all: bool,
    #[arg(short = 'f', long = "force")]
    pub force: bool,
    #[arg(long = "filter")]
    pub filter: Vec<String>,
    #[arg(long = "keep-storage")]
    pub keep_storage: Option<String>,
}

#[derive(Args, Debug)]
pub struct ComposeArgs {
    #[arg(short = 'f', long = "file", default_value = "docker-compose.yml")]
    pub file: String,

    #[command(subcommand)]
    pub command: ComposeSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum ComposeSubcommand {
    Up(ComposeUpArgs),
    Down(ComposeDownArgs),
    Ps(ComposePsArgs),
    Logs(ComposeLogsArgs),
    Config,
    Restart(ComposeRestartArgs),
    Exec(ComposeExecArgs),
    Build(ComposeBuildArgs),
    Stop(ComposeServiceArgs),
    Start(ComposeServiceArgs),
    Rm(ComposeRmArgs),
    Cp(ComposeCpArgs),
    Create,
    Events,
    Images,
    Kill(ComposeServiceArgs),
    Ls,
    Pause(ComposeServiceArgs),
    Port(ComposePortArgs),
    Pull,
    Push,
    Run(ComposeRunArgs),
    Top(ComposeServiceArgs),
    Unpause(ComposeServiceArgs),
    Version,
    Wait(ComposeServiceArgs),
}

#[derive(Args, Debug, Default)]
pub struct ComposeUpArgs {
    #[arg(short = 'd', long = "detach")]
    pub detach: bool,
    #[arg(long = "build")]
    pub build: bool,
    #[arg(long = "no-build")]
    pub no_build: bool,
    #[arg(long = "no-start")]
    pub no_start: bool,
    #[arg(long = "force-recreate")]
    pub force_recreate: bool,
    #[arg(long = "no-deps")]
    pub no_deps: bool,
    #[arg(long = "no-recreate")]
    pub no_recreate: bool,
    #[arg(long = "pull")]
    pub pull: Option<String>,
    #[arg(long = "quiet-pull")]
    pub quiet_pull: bool,
    #[arg(long = "remove-orphans")]
    pub remove_orphans: bool,
    #[arg(long = "renew-anon-volumes")]
    pub renew_anon_volumes: bool,
    #[arg(long = "scale")]
    pub scale: Vec<String>,
    #[arg(long = "timeout")]
    pub timeout: Option<String>,
    #[arg(long = "wait-timeout")]
    pub wait_timeout: Option<String>,
    #[arg(long = "wait")]
    pub wait: bool,
    #[arg(long = "timestamps")]
    pub timestamps: bool,
}

#[derive(Args, Debug, Default)]
pub struct ComposeDownArgs {
    #[arg(short = 'v', long = "volumes")]
    pub volumes: bool,
    #[arg(long = "remove-orphans")]
    pub remove_orphans: bool,
    #[arg(long = "rmi")]
    pub rmi: Option<String>,
    #[arg(long = "timeout")]
    pub timeout: Option<String>,
}

#[derive(Args, Debug, Default)]
pub struct ComposePsArgs {
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,
    #[arg(long = "format")]
    pub format: Option<String>,
    #[arg(short = 'a', long = "all")]
    pub all: bool,
    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,
    #[arg(long = "services")]
    pub services: bool,
    #[arg(long = "status")]
    pub status: Vec<String>,
}

#[derive(Args, Debug, Default)]
pub struct ComposeLogsArgs {
    pub service: Option<String>,
    #[arg(short = 'f', long = "follow")]
    pub follow: bool,
    #[arg(long = "tail")]
    pub tail: Option<String>,
    #[arg(short = 't', long = "timestamps")]
    pub timestamps: bool,
    #[arg(long = "no-color")]
    pub no_color: bool,
    #[arg(long = "no-log-prefix")]
    pub no_log_prefix: bool,
    #[arg(long = "since")]
    pub since: Option<String>,
    #[arg(long = "until")]
    pub until: Option<String>,
}

#[derive(Args, Debug, Default)]
pub struct ComposeRestartArgs {
    pub service: Option<String>,
    #[arg(long = "no-deps")]
    pub no_deps: bool,
}

#[derive(Args, Debug, Default)]
pub struct ComposeExecArgs {
    pub service: String,

    /// Detached mode: run command in the background
    #[arg(short = 'd', long = "detach")]
    pub detach: bool,

    /// Disable pseudo-TTY allocation (Docker `-T` parity)
    #[arg(short = 'T', long = "no-TTY")]
    pub no_tty: bool,

    /// Keep STDIN open even if not attached
    #[arg(short = 'i', long = "interactive")]
    pub interactive: bool,

    /// Give extended privileges to the command
    #[arg(long = "privileged")]
    pub privileged: bool,

    /// Read in a file of environment variables
    #[arg(long = "env-file")]
    pub env_file: Option<String>,

    /// Username or UID
    #[arg(short = 'u', long = "user")]
    pub user: Option<String>,

    /// Working directory inside the container
    #[arg(short = 'w', long = "workdir")]
    pub workdir: Option<String>,

    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug, Default)]
pub struct ComposeBuildArgs {
    pub service: Option<String>,
    #[arg(long = "no-cache")]
    pub no_cache: bool,
    #[arg(long = "build-arg")]
    pub build_arg: Vec<String>,
    #[arg(long = "pull")]
    pub pull: bool,
    #[arg(long = "push")]
    pub push: bool,
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,
}

#[derive(Args, Debug, Default)]
pub struct ComposeServiceArgs {
    pub service: Option<String>,
}

#[derive(Args, Debug, Default)]
pub struct ComposeRmArgs {
    #[arg(short = 'f', long = "force")]
    pub force: bool,
    #[arg(short = 's', long = "stop")]
    pub stop: bool,
    pub service: Option<String>,
}

#[derive(Args, Debug)]
pub struct ComposeCpArgs {
    pub src: String,
    pub dest: String,
}

#[derive(Args, Debug, Default)]
pub struct ComposeRunArgs {
    pub service: String,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ComposePortArgs {
    pub service: String,
    pub private_port: u16,
}

#[derive(Args, Debug)]
pub struct ImageSubcommands {
    #[command(subcommand)]
    pub command: ImageAction,
}

#[derive(Subcommand, Debug)]
pub enum ImageAction {
    #[command(alias = "list")]
    Ls(ImagesArgs),
    Build(BuildArgs),
    Pull(PullArgs),
    Push(PushArgs),
    Tag(TagArgs),
    #[command(alias = "rmi")]
    Rm(RmiArgs),
    Inspect(super::container::InspectArgs),
    History(HistoryArgs),
    Save(SaveArgs),
    Load(LoadArgs),
    Import(ImportArgs),
    Prune(ImagePruneArgs),
    /// Inspect differences between image layers or images
    Diff(ImageDiffArgs),
    /// Securely copy images between hosts
    Scp(ImageScpArgs),
    /// Sign an image
    Sign(ImageSignArgs),
    /// Print image layer hierarchy tree
    Tree(ImageTreeArgs),
    /// Manage image trust policies
    Trust(ImageTrustSubcommands),
    /// Untag an image
    Untag(UntagArgs),
    /// Mount an image filesystem
    Mount {
        image: String,
    },
    /// Unmount an image filesystem
    #[command(alias = "umount")]
    Unmount {
        image: String,
    },
    /// Return 0 if the image exists, 1 otherwise
    Exists {
        image: String,
    },
}

#[derive(Args, Debug, Clone, Default)]
pub struct ImagePruneArgs {
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    #[arg(short = 'f', long = "force")]
    pub force: bool,

    #[arg(long = "filter")]
    pub filter: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct ImagesArgs {
    /// Only show numeric IDs
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Show all images (default hides intermediate images)
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    /// Show digests
    #[arg(long = "digests")]
    pub digests: bool,

    /// Don't truncate output
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,

    /// List multi-platform images as a tree (EXPERIMENTAL)
    #[arg(long = "tree")]
    pub tree: bool,

    /// Format output using a custom template (e.g. json, table)
    #[arg(long = "format")]
    pub format: Option<String>,

    /// Filter output based on conditions provided
    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,
}

#[derive(Args, Debug)]
pub struct RmiArgs {
    /// Force removal of the image
    #[arg(short = 'f', long = "force")]
    pub force: bool,

    /// Do not delete untagged parents
    #[arg(long = "no-prune")]
    pub no_prune: bool,

    /// Remove only the given platform variant
    #[arg(long = "platform")]
    pub platform: Option<String>,

    /// Image references or IDs to remove
    #[arg(required = true)]
    pub images: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ManifestSubcommands {
    #[command(subcommand)]
    pub command: ManifestAction,
}

#[derive(Subcommand, Debug)]
pub enum ManifestAction {
    /// Display an image manifest, or manifest list
    Inspect {
        image: String,
        #[arg(long = "insecure")]
        insecure: bool,
    },
    /// Create a local manifest list for annotating and pushing to a registry
    Create {
        target: String,
        #[arg(required = true)]
        sources: Vec<String>,
    },
    /// Push a manifest list to a repository
    Push {
        target: String,
        #[arg(long = "insecure")]
        insecure: bool,
        #[arg(long = "purge")]
        purge: bool,
    },
    /// Remove one or more manifest lists
    Rm { target: String },
    /// Add or update annotations on a manifest list
    Annotate {
        target: String,
        #[arg(long = "annotation")]
        annotation: Vec<String>,
    },
}

#[derive(Args, Debug)]
pub struct TagArgs {
    /// Source image
    pub source: String,

    /// Target image and tag
    pub target: String,
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// The URL or - to read from STDIN
    pub file: String,

    /// Repository and optional tag to apply
    pub reference: Option<String>,

    #[arg(long = "change")]
    pub change: Vec<String>,

    #[arg(short = 'm', long = "message")]
    pub message: Option<String>,

    #[arg(long = "platform")]
    pub platform: Option<String>,
}

#[derive(Args, Debug)]
pub struct HistoryArgs {
    /// Image to show history for
    pub image: String,

    #[arg(short = 'f', long = "format")]
    pub format: Option<String>,

    #[arg(long = "human", default_value_t = true)]
    pub human: bool,

    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    #[arg(long = "no-trunc")]
    pub no_trunc: bool,
}

#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Max number of search results
    #[arg(long = "limit", default_value_t = 25)]
    pub limit: usize,

    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,

    #[arg(long = "format")]
    pub format: Option<String>,

    #[arg(long = "no-trunc")]
    pub no_trunc: bool,

    /// Search term
    pub term: String,
}

#[derive(Args, Debug, Clone)]
pub struct ImageDiffArgs {
    /// Base image (or first image)
    pub image1: String,

    /// Second image to compare against (optional)
    pub image2: Option<String>,

    /// Format output
    #[arg(long = "format")]
    pub format: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ImageScpArgs {
    /// Source image spec (e.g. [user@]host::image)
    pub source: String,

    /// Destination image spec
    pub destination: String,

    /// Suppress status output
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ImageSignArgs {
    /// Image to sign
    pub image: String,

    /// Key identity to sign with
    #[arg(long = "sign-by")]
    pub sign_by: Option<String>,

    /// Directory for signatures
    #[arg(long = "directory")]
    pub directory: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ImageTreeArgs {
    /// Image to show tree for
    pub image: String,

    /// Show what images require this image
    #[arg(long = "whatrequires")]
    pub whatrequires: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ImageTrustSubcommands {
    #[command(subcommand)]
    pub command: ImageTrustAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ImageTrustAction {
    /// Show trust policy
    Show {
        /// Registry or scope
        registry: Option<String>,
        /// Display raw policy JSON
        #[arg(long = "raw")]
        raw: bool,
    },
    /// Set trust policy
    Set {
        /// Trust type (accept, reject, signedBy)
        #[arg(short = 't', long = "type", default_value = "accept")]
        trust_type: String,
        /// Registry or scope
        registry: String,
        /// Public keys for signedBy
        #[arg(long = "pubkeys")]
        pubkeys: Vec<String>,
    },
}

#[derive(Args, Debug, Clone)]
pub struct UntagArgs {
    /// Image to untag
    pub image: String,

    /// Tags to remove
    #[arg(trailing_var_arg = true)]
    pub tags: Vec<String>,
}
