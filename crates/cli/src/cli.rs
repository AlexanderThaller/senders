//! Command-line argument definitions for `senders-cli`.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use url::Url;

/// Command-line client for a senders server: encrypts a file locally and
/// uploads only ciphertext, the same way the web frontend does.
#[derive(Debug, Parser)]
#[command(name = "senders-cli", version, about, long_about = None)]
pub struct Cli {
    /// Base URL of the senders server.
    #[arg(
        long,
        env = "SENDERS_CLI_URL",
        default_value = "http://localhost:47920",
        global = true
    )]
    pub url: Url,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The available subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt and upload a file, printing its share link.
    Upload(UploadArgs),
    /// Download and decrypt a share link.
    Download(DownloadArgs),
    /// Print the server's limits and auth mode.
    Info,
}

/// Arguments for `senders-cli upload`.
#[derive(Debug, Args)]
pub struct UploadArgs {
    /// File to encrypt and upload.
    pub file: PathBuf,

    /// Lifetime of the share, in seconds. The server clamps this to its own
    /// configured range.
    #[arg(long)]
    pub expires_in: Option<u64>,

    /// Number of downloads allowed before the file is destroyed. The server
    /// clamps this to its own configured range.
    #[arg(long)]
    pub max_downloads: Option<u32>,

    /// Require this passphrase to download, instead of relying on the link
    /// alone. Send it over a channel different from the link.
    #[arg(long, conflicts_with = "generate_password")]
    pub password: Option<String>,

    /// Generate a random passphrase instead of typing one, and print it.
    #[arg(long)]
    pub generate_password: bool,

    /// Name to record in the encrypted metadata. Defaults to the file's own
    /// name.
    #[arg(long)]
    pub name: Option<String>,

    /// MIME type to record in the encrypted metadata.
    #[arg(long, default_value = "application/octet-stream")]
    pub mime: String,
}

/// Arguments for `senders-cli download`.
#[derive(Debug, Args)]
pub struct DownloadArgs {
    /// Share link: `<url>/d/<id>#<secret>`, or bare `<id>#<secret>`.
    pub link: String,

    /// Where to write the decrypted file. Defaults to the name recorded in
    /// the encrypted metadata, in the current directory.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Passphrase, if the share requires one.
    #[arg(long)]
    pub password: Option<String>,
}
