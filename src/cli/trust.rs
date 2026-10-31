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
        /// Path to signature policy file
        #[arg(long = "signature-policy")]
        signature_policy: Option<String>,
        /// Output as JSON
        #[arg(short = 'j', long = "json")]
        json: bool,
        /// Registry or scope
        registry: Option<String>,
        /// Display raw policy JSON
        #[arg(long = "raw")]
        raw: bool,
        /// Do not print column headings
        #[arg(short = 'n', long = "noheading")]
        noheading: bool,
        /// Path to registries.d directory
        #[arg(long = "registrypath", hide = true)]
        registrypath: Option<String>,
    },
    /// Set trust policy
    Set {
        /// Path to signature policy file
        #[arg(long = "signature-policy")]
        signature_policy: Option<String>,
        /// Trust type (accept, reject, signedBy)
        #[arg(short = 't', long = "type", default_value = "accept")]
        trust_type: String,
        /// Registry or scope
        registry: String,
        /// Public keys for signedBy
        #[arg(short = 'f', long = "pubkeysfile", alias = "pubkeys")]
        pubkeys: Vec<String>,
    },
}
