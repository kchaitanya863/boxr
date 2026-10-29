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
        /// Name or digest of the artifact
        name: String,
    },
    /// List artifacts in the store
    #[command(alias = "list")]
    Ls,
    /// Pull an artifact from an OCI registry
    Pull {
        /// OCI artifact reference
        reference: String,
    },
    /// Push an artifact to an OCI registry
    Push {
        /// OCI artifact reference
        reference: String,
    },
    /// Remove an artifact from the store
    Rm {
        /// Name or digest of the artifact
        name: String,
    },
}
