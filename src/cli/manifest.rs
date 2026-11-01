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
        #[arg(
            long = "insecure",
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true",
            action = clap::ArgAction::Set,
            value_parser = clap::builder::BoolishValueParser::new()
        )]
        insecure: Option<bool>,
        #[arg(
            long = "tls-verify",
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true",
            action = clap::ArgAction::Set,
            value_parser = clap::builder::BoolishValueParser::new(),
            hide = true
        )]
        tls_verify: Option<bool>,
        #[arg(short = 'v', long = "verbose", hide = true)]
        verbose: bool,
    },
    /// Create a local manifest list for annotating and pushing to a registry
    Create {
        #[arg(long = "authfile")]
        authfile: Option<String>,
        #[arg(short = 'a', long = "amend")]
        amend: bool,
        #[arg(long = "annotation", hide = true)]
        annotation: Vec<String>,
        target: String,
        #[arg(hide = true)]
        sources: Vec<String>,
    },
    /// Check if a manifest list exists in local storage
    Exists { target: String },
    /// Push a manifest list to a repository
    Push {
        #[arg(long = "authfile")]
        authfile: Option<String>,
        #[arg(long = "creds", hide = true)]
        creds: Option<String>,
        #[arg(long = "cert-dir", hide = true)]
        cert_dir: Option<String>,
        target: String,
        #[arg(hide = true)]
        destination: Option<String>,
        #[arg(
            long = "insecure",
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true",
            action = clap::ArgAction::Set,
            value_parser = clap::builder::BoolishValueParser::new()
        )]
        insecure: Option<bool>,
        #[arg(
            long = "tls-verify",
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true",
            action = clap::ArgAction::Set,
            value_parser = clap::builder::BoolishValueParser::new(),
            hide = true
        )]
        tls_verify: Option<bool>,
        #[arg(short = 'p', long = "purge", alias = "rm")]
        purge: bool,
        #[arg(short = 'q', long = "quiet", hide = true)]
        quiet: bool,
        #[arg(long = "all", hide = true)]
        all: bool,
        #[arg(long = "remove-signatures", hide = true)]
        remove_signatures: bool,
        #[arg(
            long = "force-compression",
            num_args = 0..=1,
            default_missing_value = "true",
            value_parser = clap::builder::BoolishValueParser::new(),
            hide = true
        )]
        force_compression: Option<bool>,
        #[arg(long = "compression-format", hide = true)]
        compression_format: Option<String>,
        #[arg(long = "compression-level", hide = true)]
        compression_level: Option<i32>,
        #[arg(long = "add-compression", hide = true)]
        add_compression: Vec<String>,
        #[arg(long = "retry", hide = true)]
        retry: Option<u32>,
        #[arg(long = "retry-delay", hide = true)]
        retry_delay: Option<String>,
        #[arg(short = 'f', long = "format", hide = true)]
        format: Option<String>,
    },
    /// Remove an item from a manifest list
    Remove {
        #[arg(long = "authfile")]
        authfile: Option<String>,
        target: String,
        digest: Option<String>,
    },
    /// Remove one or more manifest lists
    Rm {
        #[arg(long = "authfile")]
        authfile: Option<String>,
        #[arg(short = 'i', long = "ignore", hide = true)]
        ignore: bool,
        target: String,
        #[arg(hide = true)]
        extra_targets: Vec<String>,
    },
    /// Add or update annotations on a manifest list
    Annotate {
        #[arg(long = "authfile")]
        authfile: Option<String>,
        target: String,
        #[arg(hide = true)]
        extra_args: Vec<String>,
        #[arg(long = "annotation")]
        annotation: Vec<String>,
        #[arg(long = "index", hide = true)]
        index: bool,
        #[arg(long = "subject", hide = true)]
        subject: Option<String>,
        #[arg(long = "os", hide = true)]
        os: Option<String>,
        #[arg(long = "arch", hide = true)]
        arch: Option<String>,
        #[arg(long = "os-version", hide = true)]
        os_version: Option<String>,
        #[arg(long = "os-features", value_delimiter = ',', hide = true)]
        os_features: Vec<String>,
        #[arg(long = "variant", hide = true)]
        variant: Option<String>,
    },
    /// Add an image to a manifest list
    Add {
        #[arg(long = "authfile")]
        authfile: Option<String>,
        #[arg(long = "creds", hide = true)]
        creds: Option<String>,
        #[arg(long = "cert-dir", hide = true)]
        cert_dir: Option<String>,
        #[arg(
            long = "tls-verify",
            num_args = 0..=1,
            default_missing_value = "true",
            value_parser = clap::builder::BoolishValueParser::new(),
            hide = true
        )]
        tls_verify: Option<bool>,
        #[arg(long = "all", hide = true)]
        all: bool,
        #[arg(long = "artifact", hide = true)]
        artifact: bool,
        #[arg(long = "artifact-subject", hide = true)]
        artifact_subject: Option<String>,
        #[arg(long = "artifact-type", allow_hyphen_values = true, hide = true)]
        artifact_type: Option<String>,
        #[arg(long = "artifact-config-type", allow_hyphen_values = true, hide = true)]
        artifact_config_type: Option<String>,
        #[arg(long = "artifact-config", allow_hyphen_values = true, hide = true)]
        artifact_config: Option<String>,
        #[arg(long = "artifact-layer-type", allow_hyphen_values = true, hide = true)]
        artifact_layer_type: Option<String>,
        #[arg(long = "artifact-exclude-titles", hide = true)]
        artifact_exclude_titles: bool,
        #[arg(long = "os", hide = true)]
        os: Option<String>,
        #[arg(long = "arch", hide = true)]
        arch: Option<String>,
        #[arg(long = "os-version", hide = true)]
        os_version: Option<String>,
        #[arg(long = "os-features", value_delimiter = ',', hide = true)]
        os_features: Vec<String>,
        #[arg(long = "variant", hide = true)]
        variant: Option<String>,
        #[arg(long = "annotation", hide = true)]
        annotation: Vec<String>,
        manifest_list: String,
        source: String,
        #[arg(hide = true)]
        extra_sources: Vec<String>,
    },
}
