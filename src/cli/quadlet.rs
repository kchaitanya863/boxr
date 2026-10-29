use clap::{Args, Subcommand};

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct QuadletSubcommands {
    #[command(subcommand)]
    pub command: QuadletAction,
}

#[derive(Subcommand, Debug)]
pub enum QuadletAction {
    /// List installed Quadlet files
    #[command(alias = "list")]
    Ls,
    /// Install a Quadlet unit file into the Quadlet directory
    Install {
        /// Path to Quadlet file (.container, .kube, .volume, .network, .artifact)
        file: String,
    },
    /// Print the contents of a Quadlet file
    Print {
        /// Name or path of Quadlet file
        file: String,
    },
    /// Remove an installed Quadlet file
    Rm {
        /// Name of Quadlet file to remove
        name: String,
    },
}
