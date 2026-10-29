use clap::{Args, Subcommand};

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct KubeSubcommands {
    #[command(subcommand)]
    pub command: KubeAction,
}

#[derive(Subcommand, Debug)]
pub enum KubeAction {
    /// Play a pod or deployment from a Kubernetes YAML file
    Play {
        /// Path to Kubernetes YAML file
        file: String,
        /// Tear down resources from the YAML file
        #[arg(long = "down")]
        down: bool,
    },
    /// Tear down resources created by play kube
    Down {
        /// Path to Kubernetes YAML file
        file: String,
    },
    /// Generate Kubernetes YAML for an existing container or pod
    Generate {
        /// Container or pod name
        target: String,
    },
    /// Apply Kubernetes resources from a YAML file
    Apply {
        /// Path to Kubernetes YAML file
        file: String,
    },
}
