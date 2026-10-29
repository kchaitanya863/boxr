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
    Ls,

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
        #[arg(long = "add")]
        add: Vec<String>,
        /// Connections to remove from the farm
        #[arg(long = "remove")]
        remove: Vec<String>,
        /// Set as default farm
        #[arg(long = "default")]
        default: bool,
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
    #[arg(short = 'l', long = "local")]
    pub local: bool,
    /// Build context directory (default: current directory)
    pub context: Option<String>,
}
