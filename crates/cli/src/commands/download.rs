//! `senders-cli download` — resolve a share link, decrypt it, and save it.

use crate::api;
use crate::cli::DownloadArgs;
use crate::crypto::{self, FileKeys};
use crate::progress::Mode;
use crate::transfer;
use anyhow::Context as _;
use reqwest::{Client, Url};
use senders_proto::{AUTH_SALT_LEN, FileMetadata, b64};
use std::path::PathBuf;

/// Resolve, decrypt and save the file behind `args.link`.
pub async fn run(
    client: &Client,
    base: &Url,
    args: DownloadArgs,
    progress: Mode,
) -> anyhow::Result<()> {
    let (id, secret) = transfer::parse_link(&args.link)?;
    let mut keys = FileKeys::derive(&secret)?;

    let params = api::params(client, base, &id).await?;
    if params.has_password {
        let password = args
            .password
            .as_deref()
            .context("this share requires a passphrase — pass --password")?;
        let salt = params
            .auth_salt
            .as_deref()
            .context("the server reported a password but sent no salt")?;
        let salt = b64::decode_array::<AUTH_SALT_LEN>(salt)
            .context("the server's auth salt is malformed")?;
        let auth = crypto::pbkdf2(password, &salt, params.kdf_iterations);
        keys = keys.with_auth(auth.to_vec());
    }

    let meta_response = api::metadata(client, base, &id, &keys.auth).await?;
    let sealed =
        b64::decode(&meta_response.metadata).context("the server's metadata blob is malformed")?;
    let plaintext = keys.open_metadata(&sealed).map_err(|_| {
        anyhow::anyhow!("could not decrypt the metadata — wrong passphrase, or a bad link")
    })?;
    let file_metadata: FileMetadata = serde_json::from_slice(&plaintext)?;

    let nonce_prefix = b64::decode(&meta_response.nonce_prefix)
        .context("the server's nonce prefix is malformed")?;

    let output = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(&file_metadata.name));
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let out_file = tokio::fs::File::create(&output)
        .await
        .with_context(|| format!("creating {}", output.display()))?;

    let stream = api::download_stream(client, base, &id, &keys.auth).await?;
    // `meta_response.size` is the ciphertext length, which is what the bar
    // sees arriving; the plaintext size printed below is a tag per record less.
    let bar = progress.bar(meta_response.size, "Downloading");
    let result = transfer::open_stream(
        &keys,
        &nonce_prefix,
        meta_response.size,
        bar.track(stream),
        out_file,
    )
    .await;
    bar.close(&result);
    result.context(
        "downloading the file failed — any tampering, corruption or truncation surfaces \
         here rather than as a corrupted file",
    )?;

    let name = &file_metadata.name;
    let mime = &file_metadata.mime;
    let bytes = file_metadata.size;
    let path = output.display();
    println!("Saved {name} ({bytes} bytes, {mime}) to {path}");
    Ok(())
}
