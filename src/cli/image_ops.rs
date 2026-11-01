use clap::Args;

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ImageDiffArgs {
    /// Base image (or first image)
    pub image1: String,

    /// Second image to compare against (optional)
    pub image2: Option<String>,

    /// Format output
    #[arg(long = "format")]
    pub format: Option<String>,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ImageScpArgs {
    /// Format of the image transfer (e.g. oci-archive, docker-archive)
    #[arg(long = "format")]
    pub format: Option<String>,

    /// Compression format to use (gzip, zstd, none)
    #[arg(long = "compression-format")]
    pub compression_format: Option<String>,

    /// Compression level to use
    #[arg(long = "compression-level")]
    pub compression_level: Option<i32>,

    /// Source image spec (e.g. [user@]host::image)
    pub source: String,

    /// Destination image spec
    pub destination: Option<String>,

    /// Tag for destination image
    #[arg(value_name = "TAG")]
    pub tag: Option<String>,

    /// Suppress status output
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ImageSignArgs {
    /// Sign all manifests in a multi-architecture image
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    /// Image to sign
    pub image: String,

    /// Key identity to sign with
    #[arg(long = "sign-by")]
    pub sign_by: Option<String>,

    /// Directory for signatures
    #[arg(short = 'd', long = "directory")]
    pub directory: Option<String>,

    /// Path to a directory with TLS certificates
    #[arg(long = "cert-dir")]
    pub cert_dir: Option<String>,

    /// Path of the authentication file
    #[arg(long = "authfile")]
    pub authfile: Option<String>,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct ImageTreeArgs {
    /// Image to show tree for
    pub image: String,

    /// Show what images require this image
    #[arg(long = "whatrequires")]
    pub whatrequires: bool,
}

#[derive(Args, Debug, Clone)]
#[command(help_template = crate::cli::PODMAN_LEAF_HELP)]
pub struct UntagArgs {
    /// Image to untag
    pub image: String,

    /// Tags to remove
    #[arg(trailing_var_arg = true)]
    pub tags: Vec<String>,
}
