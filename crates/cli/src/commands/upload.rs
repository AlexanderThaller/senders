//! `senders-cli upload` — encrypt a file locally and hand the ciphertext to
//! the server.

use crate::api::{self, UploadParams};
use crate::cli::UploadArgs;
use crate::crypto::{self, FileKeys};
use crate::progress::Mode;
use crate::transfer;
use anyhow::Context as _;
use reqwest::{Client, Url};
use senders_proto::{
    AUTH_SALT_LEN, FileMetadata, NONCE_PREFIX_LEN, PBKDF2_ITERATIONS, SECRET_LEN, b64,
};
use std::sync::Arc;

/// Encrypt `args.file` under a freshly generated secret and upload it,
/// printing the share link (and passphrase, if any) to stdout.
pub async fn run(
    client: &Client,
    base: &Url,
    args: UploadArgs,
    progress: Mode,
) -> anyhow::Result<()> {
    let size = tokio::fs::metadata(&args.file)
        .await
        .with_context(|| format!("reading {}", args.file.display()))?
        .len();

    let secret = crypto::random_bytes(SECRET_LEN);
    let mut keys = FileKeys::derive(&secret)?;
    let nonce_prefix = crypto::random_bytes(NONCE_PREFIX_LEN);

    let password = if args.generate_password {
        Some(crypto::generate_passphrase())
    } else {
        args.password.clone()
    };
    let auth_salt = if let Some(password) = &password {
        let salt = crypto::random_bytes(AUTH_SALT_LEN);
        keys = keys.with_auth(crypto::pbkdf2(password, &salt, PBKDF2_ITERATIONS).to_vec());
        Some(salt)
    } else {
        None
    };

    let name = args.name.clone().unwrap_or_else(|| {
        args.file.file_name().map_or_else(
            || args.file.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        )
    });
    let metadata = FileMetadata {
        name,
        mime: args.mime.clone(),
        size,
    };

    // Everything below moves `keys` into the record-sealing stream, so pull
    // out what the upload headers need from it first.
    let auth_hash = keys.auth_hash();
    let sealed_metadata = keys.seal_metadata(&serde_json::to_vec(&metadata)?)?;
    let keys = Arc::new(keys);

    let file = tokio::fs::File::open(&args.file)
        .await
        .with_context(|| format!("opening {}", args.file.display()))?;
    // The bar counts the ciphertext handed to reqwest, which is what actually
    // goes over the wire; it therefore totals a tag per record more than the
    // file on disk.
    let bar = progress.bar(senders_proto::ciphertext_len(size), "Uploading");
    let body = reqwest::Body::wrap_stream(bar.track(transfer::seal_stream(
        file,
        Arc::clone(&keys),
        nonce_prefix.clone(),
        size,
    )));

    let params = UploadParams {
        metadata: b64::encode(&sealed_metadata),
        auth_hash: b64::encode(&auth_hash),
        nonce_prefix: b64::encode(&nonce_prefix),
        auth_salt: auth_salt.as_deref().map(b64::encode),
        expires_in: args.expires_in,
        max_downloads: args.max_downloads,
    };

    let response = api::upload(client, base, &params, body).await;
    // Close before printing either way: a live bar would otherwise be redrawn
    // over the link, or over the error.
    bar.close(&response);
    let response = response?;
    let link = senders_proto::link::share_url(base.as_str(), &response.id, &secret);

    println!("{link}");
    if let Some(password) = &password {
        eprintln!("Passphrase (send it over a channel different from the link): {password}");
    }
    eprintln!(
        "Owner token (save this to delete the share early): {}",
        response.owner_token
    );
    // Both of these are what the server settled on, not what was asked for:
    // it clamps --expires-in and --max-downloads to its own configured range,
    // and this is the only place that difference becomes visible.
    eprintln!("Expires: {}", describe_expiry(response.expires_at, now()));
    if let Some(max_downloads) = response.max_downloads {
        eprintln!("Downloads: {max_downloads} before the share is destroyed");
    }
    Ok(())
}

/// Seconds since the Unix epoch, the same clock `expires_at` is measured on.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// An absolute instant to note down, followed by the lifetime it works out to.
///
/// The relative half is the useful one in practice: it is how you notice the
/// server clamped `--expires-in` to something other than what you asked for.
/// Granularity matches the frontend's (`Lang::until` in `crates/web`), so the
/// same share does not read as two different lifetimes.
fn describe_expiry(expires_at: u64, now: u64) -> String {
    let stamp = i64::try_from(expires_at)
        .ok()
        .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
        .map_or_else(
            || format!("unix time {expires_at}"),
            |at| at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );
    let Some(left) = expires_at.checked_sub(now) else {
        return format!("{stamp} (already expired)");
    };
    let (days, hours, minutes) = (left / 86_400, (left % 86_400) / 3_600, (left % 3_600) / 60);
    let relative = match (days, hours) {
        (0, 0) => format!("{minutes} min"),
        (0, hours) => format!("{hours} h"),
        (days, hours) => format!("{days} d {hours} h"),
    };
    format!("{stamp} (in {relative})")
}

#[cfg(test)]
mod tests {
    use super::describe_expiry;

    /// 2026-09-17 15:08:00 UTC.
    const INSTANT: u64 = 1_789_657_680;

    #[test]
    fn expiry_reads_as_an_instant_and_a_lifetime() {
        assert_eq!(
            describe_expiry(INSTANT, INSTANT - 7 * 86_400),
            "2026-09-17 15:08:00 UTC (in 7 d 0 h)"
        );
        assert_eq!(
            describe_expiry(INSTANT, INSTANT - 5 * 3_600),
            "2026-09-17 15:08:00 UTC (in 5 h)"
        );
        assert_eq!(
            describe_expiry(INSTANT, INSTANT - 90),
            "2026-09-17 15:08:00 UTC (in 1 min)"
        );
    }

    #[test]
    fn an_expiry_in_the_past_says_so_rather_than_underflowing() {
        assert_eq!(
            describe_expiry(INSTANT, INSTANT + 1),
            "2026-09-17 15:08:00 UTC (already expired)"
        );
    }
}
