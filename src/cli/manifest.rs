use super::image::RegistryAuthArgs;
use clap::{Args, Subcommand};

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct ManifestSubcommands {
    #[command(flatten)]
    pub registry_auth: RegistryAuthArgs,
    #[command(subcommand)]
    pub command: ManifestAction,
}

#[derive(Subcommand, Debug)]
pub enum ManifestAction {
    /// Display an image manifest, or manifest list
    Inspect {
        #[arg(long = "authfile")]
        authfile: Option<String>,
        image: String,
        #[arg(long = "insecure")]
        insecure: bool,
    },
    /// Create a local manifest list for annotating and pushing to a registry
    Create {
        #[arg(long = "authfile")]
        authfile: Option<String>,
        target: String,
        #[arg(required = true)]
        sources: Vec<String>,
    },
    /// Push a manifest list to a repository
    Push {
        #[arg(long = "authfile")]
        authfile: Option<String>,
        target: String,
        #[arg(long = "insecure")]
        insecure: bool,
        #[arg(long = "purge")]
        purge: bool,
    },
    /// Remove one or more manifest lists
    Rm {
        #[arg(long = "authfile")]
        authfile: Option<String>,
        target: String,
    },
    /// Add or update annotations on a manifest list
    Annotate {
        #[arg(long = "authfile")]
        authfile: Option<String>,
        target: String,
        #[arg(long = "annotation")]
        annotation: Vec<String>,
    },
    /// Add an image to a manifest list
    Add {
        #[arg(long = "authfile")]
        authfile: Option<String>,
        manifest_list: String,
        source: String,
    },
}
