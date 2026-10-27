use clap::{Args, Subcommand};

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct SecretSubcommands {
    #[command(subcommand)]
    pub command: SecretAction,
}

#[derive(Subcommand, Debug)]
pub enum SecretAction {
    /// Create a secret from a file or stdin
    Create {
        /// Secret name
        #[arg(value_name = "NAME")]
        #[arg(long = "name")]
        name: Option<String>,
        /// Read secret from file (use - for stdin)
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
        /// Set metadata labels (key=value)
        #[arg(long = "label")]
        labels: Vec<String>,
    },
    /// List secrets
    #[command(alias = "list")]
    Ls {
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
        #[arg(long = "format")]
        format: Option<String>,
        #[arg(short = 'f', long = "filter")]
        filter: Vec<String>,
    },
    /// Display detailed information on one or more secrets
    Inspect {
        #[arg(short = 'f', long = "format")]
        format: Option<String>,
        name: String,
    },
    /// Remove one or more secrets
    Rm {
        #[arg(short = 'f', long = "force")]
        force: bool,
        names: Vec<String>,
    },
    /// Return 0 if the secret exists, 1 otherwise
    Exists { name: String },
}
