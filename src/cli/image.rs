use clap::{Args, Subcommand};

pub use super::image_ops::*;
pub use super::manifest::*;
pub use super::trust::*;

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct RegistryAuthArgs {
    /// Path of the authentication file
    #[arg(long = "authfile")]
    pub authfile: Option<String>,

    /// Path to a directory with TLS certificates for registry access
    #[arg(long = "cert-dir")]
    pub cert_dir: Option<String>,

    /// Username:password for registry operations
    #[arg(long = "creds")]
    pub creds: Option<String>,

    /// Require HTTPS and verify certificates when contacting registries
    #[arg(
        long = "tls-verify",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set,
        value_parser = clap::builder::BoolishValueParser::new(),
        hide = true
    )]
    pub tls_verify: Option<bool>,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct PullArgs {
    /// Set platform if server is multi-platform (e.g. linux/amd64, linux/arm64)
    #[arg(long = "platform")]
    pub platform: Option<String>,

    /// Set architecture
    #[arg(long = "arch")]
    pub arch: Option<String>,

    /// Set OS
    #[arg(long = "os")]
    pub os: Option<String>,

    /// Pull image policy ("always", "missing", "never", "newer")
    #[arg(long = "policy")]
    pub policy: Option<String>,

    /// Number of times to retry in case of failure when performing pull (default 3)
    #[arg(long = "retry", default_value_t = 3)]
    pub retry: u32,

    /// Delay between retries in case of pull failures (default "2s")
    #[arg(long = "retry-delay", default_value = "2s")]
    pub retry_delay: String,

    /// Suppress output information when pulling images
    #[arg(short = 'q', long = "quiet", overrides_with = "quiet")]
    pub quiet: bool,

    #[arg(short = 'a', long = "all-tags", hide = true)]
    pub all_tags: bool,

    #[arg(long = "decryption-key", hide = true)]
    pub decryption_key: Vec<String>,

    #[arg(long = "signature-policy", hide = true)]
    pub signature_policy: Option<String>,

    #[command(flatten)]
    pub registry_auth: RegistryAuthArgs,

    pub image: String,

    #[arg(hide = true)]
    pub extra_images: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct SaveArgs {
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
    #[arg(short = 'q', long = "quiet", overrides_with = "quiet")]
    pub quiet: bool,
    #[arg(long = "format")]
    pub format: Option<String>,
    #[arg(short = 'm', long = "multi-image-archive")]
    pub multi_image_archive: bool,
    #[arg(long = "uncompressed")]
    pub uncompressed: bool,
    #[arg(long = "oci-accept-uncompressed-layers")]
    pub oci_accept_uncompressed_layers: bool,
    /// Image(s) to save
    #[arg(value_name = "IMAGE")]
    pub images: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct LoadArgs {
    #[arg(short = 'i', long = "input")]
    pub input: Option<String>,
    #[arg(short = 'q', long = "quiet", overrides_with = "quiet")]
    pub quiet: bool,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct PushArgs {
    #[command(flatten)]
    pub registry_auth: RegistryAuthArgs,
    /// Number of times to retry in case of failure when performing push (default 3)
    #[arg(long = "retry", default_value_t = 3)]
    pub retry: u32,
    /// Delay between retries in case of push failures (default "2s")
    #[arg(long = "retry-delay", default_value = "2s")]
    pub retry_delay: String,
    #[arg(short = 'f', long = "format", hide = true)]
    pub format: Option<String>,
    #[arg(long = "compression-format", hide = true)]
    pub compression_format: Option<String>,
    #[arg(long = "compression-level", allow_hyphen_values = true, hide = true)]
    pub compression_level: Option<i32>,
    #[arg(
        long = "force-compression",
        num_args = 0..=1,
        default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new(),
        hide = true
    )]
    pub force_compression: Option<bool>,
    #[arg(long = "encryption-key", hide = true)]
    pub encryption_key: Vec<String>,
    #[arg(long = "remove-signatures", hide = true)]
    pub remove_signatures: bool,
    #[arg(long = "digestfile", hide = true)]
    pub digestfile: Option<String>,
    #[arg(long = "signature-policy", hide = true)]
    pub signature_policy: Option<String>,
    #[arg(long = "sign-by", hide = true)]
    pub sign_by: Option<String>,
    #[arg(long = "sign-by-sigstore", hide = true)]
    pub sign_by_sigstore: Option<String>,
    #[arg(long = "sign-by-sigstore-private-key", hide = true)]
    pub sign_by_sigstore_private_key: Option<String>,
    #[arg(long = "sign-passphrase-file", hide = true)]
    pub sign_passphrase_file: Option<String>,
    #[arg(long = "sign-by-sq-fingerprint", hide = true)]
    pub sign_by_sq_fingerprint: Option<String>,
    #[arg(long = "platform", hide = true)]
    pub platform: Option<String>,
    #[arg(short = 'q', long = "quiet", hide = true)]
    pub quiet: bool,
    /// Source image
    pub source: String,
    /// Destination name on the registry (optional)
    pub destination: Option<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct LoginArgs {
    #[command(flatten)]
    pub registry_auth: RegistryAuthArgs,
    #[arg(short = 'u', long = "username")]
    pub username: Option<String>,
    #[arg(short = 'p', long = "password")]
    pub password: Option<String>,
    #[arg(long = "password-stdin")]
    pub password_stdin: bool,
    #[arg(long = "compat-auth-file")]
    pub compat_auth_file: Option<String>,
    #[arg(long = "secret")]
    pub secret: Option<String>,
    #[arg(value_name = "REGISTRY")]
    pub server: Option<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct LogoutArgs {
    #[command(flatten)]
    pub registry_auth: RegistryAuthArgs,
    #[arg(long = "compat-auth-file")]
    pub compat_auth_file: Option<String>,
    #[arg(short = 'a', long = "all")]
    pub all: bool,
    #[arg(value_name = "REGISTRY")]
    pub server: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct BuildArgs {
    #[command(flatten)]
    pub registry_auth: RegistryAuthArgs,
    #[arg(short = 't', long = "tag")]
    pub tags: Vec<String>,

    #[arg(long = "manifest", hide = true)]
    pub manifest: Option<String>,

    #[arg(long = "annotation", hide = true)]
    pub annotations: Vec<String>,

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

    /// Squash all layers into a single layer
    #[arg(long = "squash-all")]
    pub squash_all: bool,

    /// Accepted for Podman BATS compatibility (boxr does not layer-cache builds)
    #[arg(
        long = "layers",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub layers: Option<String>,

    /// Add Linux capabilities during build (accepted; applied at run time in boxr)
    #[arg(long = "cap-add")]
    pub cap_add: Vec<String>,

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

    /// Pull image policy ("missing", "always", "never", "newer") (default "missing")
    #[arg(
        long = "pull",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub pull: Option<String>,

    #[arg(long = "pull-never", hide = true)]
    pub pull_never: bool,

    /// User namespace to use for build containers
    #[arg(long = "userns")]
    pub userns: Option<String>,

    /// Sets the configuration for network namespaces when handling RUN instructions
    #[arg(long = "network", alias = "net", hide = true)]
    pub network: Option<String>,

    #[arg(long = "pull-always", hide = true)]
    pub pull_always: bool,

    #[arg(long = "format", hide = true)]
    pub format: Option<String>,

    #[arg(long = "logfile", hide = true)]
    pub logfile: Option<String>,

    #[arg(long = "ignorefile", hide = true)]
    pub ignorefile: Option<String>,

    #[arg(long = "dns-search", hide = true)]
    pub dns_search: Vec<String>,

    #[arg(long = "ulimit", hide = true)]
    pub ulimits: Vec<String>,

    #[arg(long = "security-opt", hide = true)]
    pub security_opt: Vec<String>,

    #[arg(long = "jobs", hide = true)]
    pub jobs: Option<u32>,

    #[arg(long = "unsetenv")]
    pub unsetenv: Vec<String>,

    #[arg(default_value = ".")]
    pub path: String,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
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
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
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
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
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
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
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
    /// Service names to create and start (default: all services)
    pub services: Vec<String>,
}

#[derive(Args, Debug, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
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
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
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
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
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
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ComposeRestartArgs {
    pub service: Option<String>,
    #[arg(long = "no-deps")]
    pub no_deps: bool,
}

#[derive(Args, Debug, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
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
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
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
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ComposeServiceArgs {
    pub service: Option<String>,
}

#[derive(Args, Debug, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ComposeRmArgs {
    #[arg(short = 'f', long = "force")]
    pub force: bool,
    #[arg(short = 's', long = "stop")]
    pub stop: bool,
    pub service: Option<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ComposeCpArgs {
    pub src: String,
    pub dest: String,
}

#[derive(Args, Debug, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ComposeRunArgs {
    pub service: String,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ComposePortArgs {
    pub service: String,
    pub private_port: u16,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
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
    Search(SearchArgs),
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
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ImagePruneArgs {
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    #[arg(short = 'f', long = "force")]
    pub force: bool,

    #[arg(long = "external")]
    pub external: bool,

    #[arg(long = "filter")]
    pub filter: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
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

    /// Do not print column headings
    #[arg(short = 'n', long = "noheading", alias = "no-heading")]
    pub noheading: bool,

    /// Format output using a custom template (e.g. json, table)
    #[arg(long = "format", allow_hyphen_values = true)]
    pub format: Option<String>,

    /// Filter output based on conditions provided
    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,

    /// Sort by repository, tag, id, or created (Podman-compatible)
    #[arg(long = "sort")]
    pub sort: Option<String>,

    /// Filter by image name or ID
    #[arg(value_name = "IMAGE")]
    pub image: Option<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct RmiArgs {
    /// Remove all images
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    /// Force removal of the image
    #[arg(short = 'f', long = "force")]
    pub force: bool,

    /// Ignore errors if a specified image does not exist
    #[arg(short = 'i', long = "ignore")]
    pub ignore: bool,

    /// Do not delete untagged parents
    #[arg(long = "no-prune")]
    pub no_prune: bool,

    /// Remove only the given platform variant
    #[arg(long = "platform")]
    pub platform: Option<String>,

    /// Image references or IDs to remove
    pub images: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct TagArgs {
    /// Source image
    pub source: String,

    /// Target image and tag (one or more)
    #[arg(required = true)]
    pub targets: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ImportArgs {
    /// The URL or - to read from STDIN
    pub file: String,

    /// Repository and optional tag to apply
    pub reference: Option<String>,

    #[arg(short = 'c', long = "change")]
    pub change: Vec<String>,

    #[arg(short = 'm', long = "message")]
    pub message: Option<String>,

    #[arg(long = "platform")]
    pub platform: Option<String>,

    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    #[arg(long = "os")]
    pub os: Option<String>,

    #[arg(long = "arch")]
    pub arch: Option<String>,

    #[arg(long = "variant")]
    pub variant: Option<String>,

    #[arg(long = "signature-policy")]
    pub signature_policy: Option<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct HistoryArgs {
    /// Image to show history for
    pub image: String,

    #[arg(short = 'f', long = "format", allow_hyphen_values = true)]
    pub format: Option<String>,

    #[arg(
        short = 'H',
        long = "human",
        default_value = "true",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub human: bool,

    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    #[arg(long = "no-trunc")]
    pub no_trunc: bool,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct SearchArgs {
    #[command(flatten)]
    pub registry_auth: RegistryAuthArgs,
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
