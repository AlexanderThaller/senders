//! `senders-cli upload` — encrypt a file locally and hand the ciphertext to
//! the server.

use crate::api::{self, UploadParams};
use crate::cli::UploadArgs;
use crate::crypto::{self, FileKeys};
use crate::transfer;
use anyhow::Context as _;
use reqwest::{Client, Url};
use senders_proto::{
    AUTH_SALT_LEN, FileMetadata, NONCE_PREFIX_LEN, PBKDF2_ITERATIONS, SECRET_LEN, b64,
};
use std::sync::Arc;

/// Encrypt `args.file` under a freshly generated secret and upload it,
/// printing the share link (and passphrase, if any) to stdout.
pub async fn run(client: &Client, base: &Url, args: UploadArgs) -> anyhow::Result<()> {
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
    let body = reqwest::Body::wrap_stream(transfer::seal_stream(
        file,
        Arc::clone(&keys),
        nonce_prefix.clone(),
        size,
    ));

    let params = UploadParams {
        metadata: b64::encode(&sealed_metadata),
        auth_hash: b64::encode(&auth_hash),
        nonce_prefix: b64::encode(&nonce_prefix),
        auth_salt: auth_salt.as_deref().map(b64::encode),
        expires_in: args.expires_in,
        max_downloads: args.max_downloads,
    };

    let response = api::upload(client, base, &params, body).await?;
    let link = senders_proto::link::share_url(base.as_str(), &response.id, &secret);

    println!("{link}");
    if let Some(password) = &password {
        eprintln!("Passphrase (send it over a channel different from the link): {password}");
    }
    eprintln!(
        "Owner token (save this to delete the share early): {}",
        response.owner_token
    );
    Ok(())
}
