use clap::{Args, Subcommand};

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct ArtifactSubcommands {
    #[command(subcommand)]
    pub command: ArtifactAction,
}

#[derive(Subcommand, Debug)]
pub enum ArtifactAction {
    /// Add an artifact to the artifact store
    Add {
        /// Append files to an existing artifact
        #[arg(short = 'a', long = "append")]
        append: bool,
        /// Replace an existing artifact
        #[arg(long = "replace")]
        replace: bool,
        /// Name of the artifact
        name: String,
        /// Path to the artifact file
        file: String,
        /// Media type of the artifact
        #[arg(
            long = "type",
            default_value = "application/vnd.oci.image.layer.v1.tar"
        )]
        media_type: String,
    },
    /// Extract an artifact to disk
    Extract {
        /// Name or digest of the artifact
        name: String,
        /// Destination path
        #[arg(default_value = ".")]
        dest: String,
    },
    /// Display detailed information on an artifact
    Inspect {
        /// Format output using Go template
        #[arg(short = 'f', long = "format")]
        format: Option<String>,
        /// Name or digest of the artifact
        name: String,
    },
    /// List artifacts in the store
    #[command(alias = "list")]
    Ls,
    /// Pull an artifact from an OCI registry
    Pull {
        /// Suppress output information when pulling
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
        /// Require HTTPS and verify certificates
        #[arg(
            long = "tls-verify",
            default_value_t = true,
            num_args = 0..=1,
            default_missing_value = "true",
            require_equals = true,
            action = clap::ArgAction::Set,
            value_parser = clap::builder::BoolishValueParser::new()
        )]
        tls_verify: bool,
        /// OCI artifact reference
        reference: String,
    },
    /// Push an artifact to an OCI registry
    Push {
        /// Suppress output information when pushing
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
        /// Require HTTPS and verify certificates
        #[arg(
            long = "tls-verify",
            default_value_t = true,
            num_args = 0..=1,
            default_missing_value = "true",
            require_equals = true,
            action = clap::ArgAction::Set,
            value_parser = clap::builder::BoolishValueParser::new()
        )]
        tls_verify: bool,
        /// OCI artifact reference
        reference: String,
    },
    /// Remove one or more artifacts from the store
    Rm {
        /// Remove all artifacts
        #[arg(short = 'a', long = "all")]
        all: bool,
        /// Ignore errors if artifact does not exist
        #[arg(short = 'i', long = "ignore")]
        ignore: bool,
        /// Name or digest of the artifact(s)
        names: Vec<String>,
    },
}
