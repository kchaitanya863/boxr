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
        /// Artifact type (sets manifest artifactType)
        #[arg(long = "type")]
        artifact_type: Option<String>,
        /// File media type (sets layer mediaType)
        #[arg(long = "file-type")]
        file_type: Option<String>,
        /// Annotations to add to the artifact layer (key=value)
        #[arg(long = "annotation")]
        annotation: Vec<String>,
        /// Name of the artifact
        name: String,
        /// Path(s) to the artifact file(s)
        #[arg(required = true)]
        files: Vec<String>,
    },
    /// Extract an artifact to disk
    Extract {
        /// Only extract blob with the given digest
        #[arg(long = "digest")]
        digest: Option<String>,
        /// Only extract blob with the given title
        #[arg(long = "title")]
        title: Option<String>,
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
    Ls {
        /// Format output using Go template or json
        #[arg(long = "format")]
        format: Option<String>,
        /// Do not print column headings
        #[arg(short = 'n', long = "noheading")]
        noheading: bool,
        /// Do not truncate output
        #[arg(long = "no-trunc")]
        no_trunc: bool,
        /// Only display artifact digests
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
    },
    /// Pull an artifact from an OCI registry
    Pull {
        #[command(flatten)]
        registry_auth: crate::cli::image::RegistryAuthArgs,
        /// Number of times to retry in case of failure when performing pull
        #[arg(long = "retry", default_value_t = 3)]
        retry: u32,
        /// Delay between retries in case of pull failures
        #[arg(long = "retry-delay", default_value = "2s")]
        retry_delay: String,
        /// Suppress output information when pulling
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
        /// OCI artifact reference
        reference: String,
    },
    /// Push an artifact to an OCI registry
    Push {
        #[command(flatten)]
        registry_auth: crate::cli::image::RegistryAuthArgs,
        /// Number of times to retry in case of failure when performing push
        #[arg(long = "retry", default_value_t = 3)]
        retry: u32,
        /// Delay between retries in case of push failures
        #[arg(long = "retry-delay", default_value = "2s")]
        retry_delay: String,
        /// Suppress output information when pushing
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
        /// OCI artifact reference
        reference: String,
        /// Optional destination reference
        destination: Option<String>,
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
