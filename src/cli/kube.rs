use clap::{Args, Subcommand};

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct KubePlayArgs {
    /// Path to Kubernetes YAML file (or '-' for stdin, or URL)
    pub file: String,
    /// Tear down resources from the YAML file
    #[arg(long = "down")]
    pub down: bool,
    /// Replace existing pods and containers
    #[arg(long = "replace")]
    pub replace: bool,
    /// Start the pod after creating it
    #[arg(
        long = "start",
        default_value_t = true,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    pub start: bool,
    /// Start a service container before all pods
    #[arg(
        long = "service-container",
        default_value_t = false,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    pub service_container: bool,
    /// Logging driver for the container
    #[arg(long = "log-driver")]
    pub log_driver: Option<String>,
    /// Logging driver options
    #[arg(long = "log-opt")]
    pub log_opt: Vec<String>,
    /// Connect pod to network(s)
    #[arg(long = "network", visible_alias = "net")]
    pub network: Vec<String>,
    /// Build images even if they are found in the local storage
    #[arg(
        long = "build",
        default_value_t = false,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    pub build: bool,
    /// Use directory at path to find Containerfile for --build
    #[arg(long = "context-dir")]
    pub context_dir: Option<String>,
    /// Add annotations to pod(s) (key=value)
    #[arg(long = "annotation")]
    pub annotations: Vec<String>,
    /// Add labels to pod(s) (key=value)
    #[arg(short = 'l', long = "label")]
    pub labels: Vec<String>,
    /// Do not truncate annotations
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,
    /// Clean up all objects created when a SIGTERM/SIGINT is received or pods exit
    #[arg(short = 'w', long = "wait")]
    pub wait: bool,
    /// Use K8s configmap YAML at path to provide env variable values
    #[arg(long = "configmap")]
    pub configmaps: Vec<String>,
    /// Path of the authentication file
    #[arg(long = "authfile")]
    pub authfile: Option<String>,
    /// Require HTTPS and verify certificates when contacting registries
    #[arg(
        long = "tls-verify",
        default_value_t = true,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    pub tls_verify: bool,
    /// Publish a pod's port(s) to the host
    #[arg(long = "publish")]
    pub publish: Vec<String>,
    /// Suppress output information when pulling images
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,
    /// Directory path for seccomp profiles
    #[arg(long = "seccomp-profile-root")]
    pub seccomp_profile_root: Option<String>,
    /// User namespace mode
    #[arg(long = "userns")]
    pub userns: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct KubeDownArgs {
    /// Path to Kubernetes YAML file
    pub file: String,
    /// Remove volumes as well
    #[arg(long = "force")]
    pub force: bool,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct KubeGenerateArgs {
    /// Write output to the specified path
    #[arg(short = 'f', long = "filename")]
    pub filename: Option<String>,
    /// Generate YAML for a Kubernetes service object
    #[arg(short = 's', long = "service")]
    pub service: bool,
    /// Container or pod name(s)
    #[arg(required = true)]
    pub targets: Vec<String>,
}

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct KubeSubcommands {
    #[command(subcommand)]
    pub command: KubeAction,
}

#[derive(Subcommand, Debug)]
pub enum KubeAction {
    /// Play a pod or deployment from a Kubernetes YAML file
    Play(KubePlayArgs),
    /// Tear down resources created by play kube
    Down(KubeDownArgs),
    /// Generate Kubernetes YAML for an existing container or pod
    Generate(KubeGenerateArgs),
    /// Apply Kubernetes resources from a YAML file
    Apply(KubePlayArgs),
}
