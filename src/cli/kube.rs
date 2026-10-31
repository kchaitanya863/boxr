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
        /// Replace existing pods and containers
        #[arg(long = "replace", num_args = 0..=1, require_equals = true, default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
        replace: bool,
        /// Starts a service container before all pods
        #[arg(long = "service-container", num_args = 0..=1, require_equals = true, default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
        service_container: bool,
        /// Specify how the service container exit code is determined
        #[arg(long = "service-exit-code-propagation")]
        service_exit_code_propagation: Option<String>,
        /// Logging driver for the container
        #[arg(long = "log-driver")]
        log_driver: Option<String>,
        /// Specify network mode or network names
        #[arg(long = "network")]
        network: Vec<String>,
        /// Build images if Containerfile exists
        #[arg(long = "build", num_args = 0..=1, require_equals = true, default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
        build: bool,
        /// Clean up all objects created when a SIGTERM is received or pods exit
        #[arg(long = "wait", short = 'w', num_args = 0..=1, require_equals = true, default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
        wait: bool,
        /// Publish a container's port, or a range of ports, to the host
        #[arg(long = "publish")]
        publish: Vec<String>,
        /// Add annotations to the pod
        #[arg(long = "annotation")]
        annotation: Vec<String>,
        /// User namespace to use
        #[arg(long = "userns")]
        userns: Option<String>,
    },
    /// Tear down resources created by play kube
    Down {
        /// Path to Kubernetes YAML file
        file: String,
        /// Remove volumes as well
        #[arg(long = "force", num_args = 0..=1, require_equals = true, default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
        force: bool,
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
