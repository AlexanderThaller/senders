//! `senders-cli info` — print the server's limits and auth mode.

use crate::api;
use reqwest::{Client, Url};

/// Fetch and print `GET /api/info`.
pub async fn run(client: &Client, base: &Url) -> anyhow::Result<()> {
    let info = api::server_info(client, base).await?;
    println!("max file size:  {} bytes", info.max_file_size);
    println!(
        "expiry range:   {}s .. {}s (default {}s)",
        info.min_expiry_secs, info.max_expiry_secs, info.default_expiry_secs
    );
    println!(
        "max downloads:  {} (default {})",
        info.max_downloads, info.default_max_downloads
    );
    println!("auth mode:      {}", info.auth_mode);
    println!("auth required:  {}", info.auth_required);
    match info.session {
        Some(session) => println!(
            "signed in as:   {}",
            session.email.as_deref().unwrap_or(&session.subject)
        ),
        None => println!("signed in as:   (not signed in)"),
    }
    Ok(())
}
