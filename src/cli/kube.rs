use clap::{Args, Subcommand};

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct KubeSubcommands {
    #[command(subcommand)]
    pub command: KubeAction,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct KubeGenerateArgs {
    /// Write output to the specified path
    #[arg(short = 'f', long = "filename")]
    pub filename: Option<String>,
    /// Generate a Kubernetes service object in addition to the Pod or Deployment object
    #[arg(short = 's', long = "service")]
    pub service: bool,
    /// Generate the specified Kubernetes kind (pod, deployment, job, daemonset, replicaset)
    #[arg(short = 't', long = "type")]
    pub kind_type: Option<String>,
    /// Set the replicas number for Deployment kind
    #[arg(short = 'r', long = "replicas")]
    pub replicas: Option<i32>,
    /// Don't truncate annotations to the Kubernetes maximum length of 63 characters
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,
    /// Container, pod, or volume names/IDs to generate YAML for
    #[arg(required = true, value_name = "{CONTAINER...|POD...|VOLUME...}")]
    pub targets: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct KubePlayArgs {
    /// Path to Kubernetes YAML file
    #[arg(value_name = "KUBEFILE|-")]
    pub file: String,
    /// Tear down resources from the YAML file
    #[arg(long = "down")]
    pub down: bool,
    /// Replace existing pods and containers with the same name
    #[arg(long = "replace")]
    pub replace: bool,
    /// Start the pod after creating it (default true)
    #[arg(
        long = "start",
        default_value_t = true,
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub start: bool,
    /// Build images even if they are found in the local storage
    #[arg(
        long = "build",
        default_value_t = false,
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub build: bool,
    /// Directory at which Dockerfile/Containerfile can be found
    #[arg(long = "context-dir")]
    pub context_dir: Option<String>,
    /// Starts a service container before all pods
    #[arg(
        long = "service-container",
        default_value_t = false,
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub service_container: bool,
    /// Connect pod to network(s)
    #[arg(long = "network", alias = "net")]
    pub network: Vec<String>,
    /// Static MAC address for pod interface
    #[arg(long = "mac-address")]
    pub mac_address: Option<String>,
    /// Static IP address for pod
    #[arg(long = "ip")]
    pub ip: Vec<String>,
    /// Set user namespace mode for the pod
    #[arg(long = "userns")]
    pub userns: Option<String>,
    /// Logging driver for the container
    #[arg(long = "log-driver")]
    pub log_driver: Option<String>,
    /// Logging driver options
    #[arg(long = "log-opt")]
    pub log_opt: Vec<String>,
    /// Path to a configmap YAML file
    #[arg(long = "configmap")]
    pub configmap: Vec<String>,
    /// Add annotations to pod
    #[arg(long = "annotation")]
    pub annotation: Vec<String>,
    /// Publish a pod's port, or a range of ports, to the host
    #[arg(long = "publish")]
    pub publish: Vec<String>,
    /// Publish all exposed ports to random ports on the host interfaces
    #[arg(long = "publish-all")]
    pub publish_all: bool,
    /// Wait for the pod to finish and clean up
    #[arg(short = 'w', long = "wait")]
    pub wait: bool,
    /// Suppress output information when pulling images
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,
    /// Do not create `/etc/hosts` within the pod's containers
    #[arg(long = "no-hosts")]
    pub no_hosts: bool,
    /// Do not use image or containerhosts in /etc/hosts
    #[arg(long = "no-hostname")]
    pub no_hostname: bool,
    /// Path of the authentication file
    #[arg(long = "authfile")]
    pub authfile: Option<String>,
    /// Use certificates at path
    #[arg(long = "cert-dir")]
    pub cert_dir: Option<String>,
    /// Credentials `USERNAME:PASSWORD` to use for authenticating to a registry
    #[arg(long = "creds")]
    pub creds: Option<String>,
    /// Require HTTPS and verify certificates when contacting registries
    #[arg(
        long = "tls-verify",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub tls_verify: Option<bool>,
    /// seccomp profile root directory
    #[arg(long = "seccomp-profile-root")]
    pub seccomp_profile_root: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct KubeDownArgs {
    /// Path to Kubernetes YAML file
    #[arg(value_name = "KUBEFILE|-")]
    pub file: String,
    /// Also remove volumes created by play kube
    #[arg(long = "force")]
    pub force: bool,
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
    Apply {
        /// Path to Kubernetes YAML file
        file: String,
    },
}

