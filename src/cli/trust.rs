use clap::{Args, Subcommand};

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
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
