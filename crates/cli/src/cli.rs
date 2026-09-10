//! Command-line argument definitions for `senders-cli`.

use clap::{Args, CommandFactory as _, Parser, Subcommand};
use std::path::PathBuf;
use url::Url;

/// Command-line client for a senders server: encrypts a file locally and
/// uploads only ciphertext, the same way the web frontend does.
#[derive(Debug, Parser)]
#[command(
    name = "senders-cli",
    version,
    about,
    long_about = None,
    // Upload is the default: `senders-cli FILE` means `senders-cli upload
    // FILE`, spelled as a flattened `DefaultUpload` beside an optional
    // subcommand. This keeps `senders-cli FILE download LINK` from parsing as
    // both at once.
    args_conflicts_with_subcommands = true
)]
pub struct Cli {
    /// Base URL of the senders server.
    #[arg(
        long,
        env = "SENDERS_CLI_URL",
        default_value = "http://localhost:47920",
        global = true
    )]
    pub url: Url,

    /// Do not draw a progress bar during a transfer. Redirected output needs
    /// no flag: the bar is only drawn when stderr is a terminal.
    #[arg(long, env = "SENDERS_CLI_NO_PROGRESS", global = true)]
    pub no_progress: bool,

    /// What to do. Omitted, the arguments below are an `upload`.
    #[command(subcommand)]
    pub command: Option<Command>,

    /// `upload`'s arguments, accepted without naming the subcommand.
    #[command(flatten)]
    pub upload: DefaultUpload,
}

impl Cli {
    /// The subcommand to run, resolving an absent one to `upload`.
    ///
    /// Not named `command`: that is `clap::CommandFactory`'s. The error is a
    /// `clap::Error` so that a bare `senders-cli` still exits with clap's
    /// usage message rather than an ordinary failure.
    pub fn into_command(self) -> Result<Command, clap::Error> {
        match self.command {
            Some(command) => Ok(command),
            None => Ok(Command::Upload(self.upload.into_args()?)),
        }
    }
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

    /// Everything else the upload takes.
    #[command(flatten)]
    pub options: UploadOptions,
}

/// The same, as `senders-cli FILE` spells it. The file is optional only so
/// that `senders-cli download …` parses: clap checks a flattened positional's
/// requirement even when a subcommand was given, so a required one here would
/// be demanded of every subcommand. `into_args` puts the requirement back.
#[derive(Debug, Args)]
pub struct DefaultUpload {
    /// File to encrypt and upload.
    pub file: Option<PathBuf>,

    /// Everything else the upload takes.
    #[command(flatten)]
    pub options: UploadOptions,
}

impl DefaultUpload {
    /// Reject an invocation that named no file and no subcommand.
    fn into_args(self) -> Result<UploadArgs, clap::Error> {
        let file = self.file.ok_or_else(|| {
            Cli::command().error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "a <FILE> to upload, or a subcommand, is required",
            )
        })?;

        Ok(UploadArgs {
            file,
            options: self.options,
        })
    }
}

/// The options `upload` takes either way.
#[derive(Debug, Args)]
pub struct UploadOptions {
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

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::{CommandFactory as _, Parser as _, error::ErrorKind};

    /// Parse, or say which clap error came back instead.
    fn parse(args: &[&str]) -> Result<Command, ErrorKind> {
        Cli::try_parse_from(args)
            .map_err(|err| err.kind())
            .and_then(|cli| cli.into_command().map_err(|err| err.kind()))
    }

    #[test]
    fn definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn a_bare_path_is_an_upload() {
        let Ok(Command::Upload(args)) = parse(&["senders-cli", "/tmp/blabla.txt"]) else {
            panic!("expected an upload")
        };
        assert_eq!(args.file.to_str(), Some("/tmp/blabla.txt"));
    }

    #[test]
    fn the_default_takes_the_upload_options() {
        let Ok(Command::Upload(args)) =
            parse(&["senders-cli", "--max-downloads", "3", "/tmp/blabla.txt"])
        else {
            panic!("expected an upload")
        };
        assert_eq!(args.options.max_downloads, Some(3));
    }

    #[test]
    fn upload_is_still_spellable() {
        let Ok(Command::Upload(args)) = parse(&["senders-cli", "upload", "/tmp/blabla.txt"]) else {
            panic!("expected an upload")
        };
        assert_eq!(args.file.to_str(), Some("/tmp/blabla.txt"));
    }

    /// The flattened `DefaultUpload::file` must not be demanded of the
    /// subcommands that have no use for it.
    #[test]
    fn the_other_subcommands_need_no_file() {
        assert!(matches!(parse(&["senders-cli", "info"]), Ok(Command::Info)));
        assert!(matches!(
            parse(&["senders-cli", "download", "id#secret"]),
            Ok(Command::Download(_))
        ));
    }

    #[test]
    fn globals_reach_the_default() {
        let cli = Cli::try_parse_from(["senders-cli", "--no-progress", "/tmp/blabla.txt"])
            .expect("should parse");
        assert!(cli.no_progress);
    }

    /// `upload` keeps its own requirement, and a bare `senders-cli` is not
    /// silently an upload of nothing.
    #[test]
    fn a_missing_file_is_still_an_error() {
        assert_eq!(
            parse(&["senders-cli", "upload"]).err(),
            Some(ErrorKind::MissingRequiredArgument)
        );
        assert_eq!(
            parse(&["senders-cli"]).err(),
            Some(ErrorKind::MissingRequiredArgument)
        );
    }

    /// `args_conflicts_with_subcommands`: one or the other, never both.
    #[test]
    fn the_default_and_a_subcommand_do_not_mix() {
        assert_eq!(
            parse(&["senders-cli", "/tmp/blabla.txt", "info"]).err(),
            Some(ErrorKind::ArgumentConflict)
        );
    }
}
