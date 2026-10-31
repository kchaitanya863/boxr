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
    Ls {
        /// Filter output based on conditions given
        #[arg(short = 'f', long = "filter")]
        filter: Vec<String>,
        /// Pretty-print quadlets to JSON or a Go template
        #[arg(long = "format")]
        format: Option<String>,
        /// Do not print headers
        #[arg(short = 'n', long = "noheading")]
        noheading: bool,
    },
    /// Install a Quadlet unit file or directory
    Install {
        /// Install as a quadlet application
        #[arg(short = 'a', long = "application")]
        application: Option<String>,
        /// Reload systemd after installing quadlets
        #[arg(long = "reload-systemd", num_args = 0..=1, require_equals = true, default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
        reload_systemd: Option<bool>,
        /// Replace the installation if it already exists
        #[arg(short = 'r', long = "replace", num_args = 0..=1, require_equals = true, default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
        replace: bool,
        /// Path(s) or URL(s) to Quadlet file(s) or directory
        #[arg(required = true)]
        files: Vec<String>,
    },
    /// Print the contents of a Quadlet file
    #[command(alias = "cat")]
    Print {
        /// Name or path of Quadlet file
        file: String,
    },
    /// Remove installed Quadlet file(s)
    Rm {
        /// Remove all installed quadlets
        #[arg(short = 'a', long = "all")]
        all: bool,
        /// Remove running quadlets as well
        #[arg(short = 'f', long = "force")]
        force: bool,
        /// Do not error if quadlet does not exist
        #[arg(short = 'i', long = "ignore")]
        ignore: bool,
        /// Remove an application directory and all its contents
        #[arg(long = "recursive")]
        recursive: bool,
        /// Reload systemd after removing quadlets
        #[arg(long = "reload-systemd", num_args = 0..=1, require_equals = true, default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
        reload_systemd: Option<bool>,
        /// Name(s) of Quadlet file(s) or application to remove
        names: Vec<String>,
    },
}
