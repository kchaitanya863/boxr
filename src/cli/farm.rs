use clap::{Args, Subcommand};

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct FarmSubcommands {
    #[command(subcommand)]
    pub command: FarmAction,
}

#[derive(Subcommand, Debug)]
pub enum FarmAction {
    /// Build an image on all nodes in a farm and bundle them into a manifest list
    Build(FarmBuildArgs),

    /// Create a new farm
    Create {
        /// Farm name
        name: String,
        /// Remote connections to add to the farm
        connections: Vec<String>,
    },

    /// List existing farms
    #[command(alias = "list")]
    Ls {
        /// Format farm output using Go template
        #[arg(long = "format")]
        format: Option<String>,
        /// Print farm names only
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
        /// Do not print headers
        #[arg(short = 'n', long = "noheading")]
        noheading: bool,
    },

    /// Remove one or more farms
    #[command(alias = "remove")]
    Rm {
        /// Remove all farms
        #[arg(short = 'a', long = "all")]
        all: bool,
        /// Farm name(s) to remove
        names: Vec<String>,
    },

    /// Update an existing farm
    Update {
        /// Farm name to update
        name: String,
        /// Connections to add to the farm
        #[arg(short = 'a', long = "add", value_delimiter = ',')]
        add: Vec<String>,
        /// Connections to remove from the farm
        #[arg(short = 'r', long = "remove", value_delimiter = ',')]
        remove: Vec<String>,
        /// Set as default farm
        #[arg(
            short = 'd',
            long = "default",
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true",
            value_parser = clap::builder::BoolishValueParser::new()
        )]
        default: Option<bool>,
    },
}

#[derive(Args, Debug, Clone, Default)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct FarmBuildArgs {
    /// Farm name to build on
    #[arg(long = "farm")]
    pub farm: Option<String>,
    /// Tag for the built image and manifest list
    #[arg(short = 't', long = "tag")]
    pub tag: Option<String>,
    /// Path to Dockerfile or Containerfile
    #[arg(short = 'f', long = "file")]
    pub file: Option<String>,
    /// Target platforms to build (e.g. linux/amd64,linux/arm64)
    #[arg(long = "platforms")]
    pub platforms: Option<String>,
    /// Build on local machine as well
    #[arg(
        short = 'l',
        long = "local",
        num_args = 0..=1,
        default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub local: Option<bool>,
    /// Remove built images from farm nodes on success
    #[arg(long = "cleanup")]
    pub cleanup: bool,
    /// Path of the authentication file
    #[arg(long = "authfile")]
    pub authfile: Option<String>,
    /// Require HTTPS and verify certificates when talking to the container registry
    #[arg(
        long = "tls-verify",
        num_args = 0..=1,
        default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub tls_verify: Option<bool>,
    /// Credentials (USERNAME:PASSWORD) to use for authenticating to a registry
    #[arg(long = "creds")]
    pub creds: Option<String>,
    /// Use certificates at the specified path to access the registry
    #[arg(long = "cert-dir")]
    pub cert_dir: Option<String>,
    /// Build context directory (default: current directory)
    pub context: Option<String>,
}
