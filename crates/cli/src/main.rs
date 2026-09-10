//! The `senders-cli` binary: parses arguments and dispatches to a command.

use clap::Parser as _;
use senders_cli::cli::{Cli, Command};
use senders_cli::commands;
use senders_cli::progress::Mode;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = reqwest::Client::new();
    let progress = if cli.no_progress {
        Mode::Off
    } else {
        Mode::Auto
    };

    let url = cli.url.clone();
    // clap's own error, so a bare `senders-cli` exits with a usage message.
    let command = cli.into_command().unwrap_or_else(|err| err.exit());

    match command {
        Command::Upload(args) => commands::upload::run(&client, &url, args, progress).await,
        Command::Download(args) => commands::download::run(&client, &url, args, progress).await,
        Command::Info => commands::info::run(&client, &url).await,
    }
}
