//! Whole-file encrypt and decrypt pipelines.
//!
//! Mirrors `crates/web/src/transfer.rs`, but works against a filesystem and
//! `reqwest` instead of `Blob`s and `fetch`: both directions run record by
//! record, so at most one plaintext (or ciphertext) record is ever held in
//! memory regardless of file size. Record framing and the share-link format
//! itself live in `senders_proto::{stream, link}`, shared with `crates/web`.

use crate::api;
use crate::crypto::FileKeys;
use bytes::Bytes;
use futures_util::{Stream, StreamExt as _};
use senders_proto::stream::{cipher_record_count, plain_record_count, record_index};
use senders_proto::{CHUNK_CIPHERTEXT_SIZE, CHUNK_SIZE};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// Read `file` record by record, sealing each one under `keys`, and hand back
/// a stream of ciphertext chunks ready to be the body of the upload request.
///
/// Reading happens lazily as the HTTP client pulls on the stream, so this
/// never buffers more than one record of plaintext at a time.
pub fn seal_stream(
    file: File,
    keys: Arc<FileKeys>,
    nonce_prefix: Vec<u8>,
    size: u64,
) -> impl Stream<Item = std::io::Result<Bytes>> + Send + 'static {
    let records = plain_record_count(size);
    futures_util::stream::unfold((file, 0u32), move |(mut file, index)| {
        let keys = Arc::clone(&keys);
        let nonce_prefix = nonce_prefix.clone();
        async move {
            if index >= records {
                return None;
            }
            let mut buf = vec![0u8; CHUNK_SIZE];
            let mut filled = 0usize;
            while filled < buf.len() {
                match file.read(&mut buf[filled..]).await {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(err) => return Some((Err(err), (file, records))),
                }
            }
            buf.truncate(filled);
            let last = index + 1 == records;
            match keys.seal_record(&nonce_prefix, index, last, &buf) {
                Ok(sealed) => Some((Ok(Bytes::from(sealed)), (file, index + 1))),
                Err(err) => Some((Err(std::io::Error::other(err.to_string())), (file, records))),
            }
        }
    })
}

/// Decrypt a ciphertext stream into `output`, verifying record framing.
///
/// Any tampering, reordering or truncation makes a record fail to
/// authenticate, which surfaces here as an error rather than as partial data.
pub async fn open_stream<S, W>(
    keys: &FileKeys,
    nonce_prefix: &[u8],
    cipher_len: u64,
    stream: S,
    mut output: W,
) -> anyhow::Result<()>
where
    S: Stream<Item = api::Result<Bytes>>,
    W: AsyncWrite + Unpin,
{
    let total_records = cipher_record_count(cipher_len);
    let mut stream = std::pin::pin!(stream);
    let mut buffer: Vec<u8> = Vec::with_capacity(CHUNK_CIPHERTEXT_SIZE * 2);
    let mut index: u64 = 0;

    while let Some(chunk) = stream.next().await {
        buffer.extend_from_slice(&chunk?);
        // Every record except the last is exactly one full record long, so the
        // framing is unambiguous.
        while index + 1 < total_records && buffer.len() >= CHUNK_CIPHERTEXT_SIZE {
            let record: Vec<u8> = buffer.drain(..CHUNK_CIPHERTEXT_SIZE).collect();
            let plaintext = keys.open_record(nonce_prefix, record_index(index), false, &record)?;
            output.write_all(&plaintext).await?;
            index += 1;
        }
    }

    if index + 1 != total_records {
        anyhow::bail!("download ended early: got {index} of {total_records} records");
    }
    let plaintext = keys.open_record(nonce_prefix, record_index(index), true, &buffer)?;
    output.write_all(&plaintext).await?;
    output.flush().await?;
    Ok(())
}

/// Pull the share id and secret out of a link, in either the full
/// `<origin>/d/<id>#<secret>` form the frontend generates, or the bare
/// `<id>#<secret>` form. Secret decoding is `senders_proto::link`'s; only the
/// id extraction (there is no route parameter to hand it over, unlike in the
/// browser) is specific to this crate.
pub fn parse_link(link: &str) -> anyhow::Result<(String, Vec<u8>)> {
    let (before_hash, fragment) = link
        .split_once('#')
        .ok_or_else(|| anyhow::anyhow!("the link is missing the secret after '#'"))?;
    let secret = senders_proto::link::decode_secret(fragment)
        .ok_or_else(|| anyhow::anyhow!("the secret is missing, malformed, or the wrong length"))?;
    let id = before_hash
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .ok_or_else(|| anyhow::anyhow!("the link is missing a share id"))?;
    Ok((id.to_string(), secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use senders_proto::SECRET_LEN;
    use senders_proto::b64;

    #[test]
    fn parses_a_full_url_and_a_bare_id() {
        let secret = [7u8; SECRET_LEN];
        let full = format!("https://send.example/d/abc123#{}", b64::encode(secret));
        let (id, parsed) = parse_link(&full).expect("valid link");
        assert_eq!(id, "abc123");
        assert_eq!(parsed, secret);

        let bare = format!("abc123#{}", b64::encode(secret));
        let (id, parsed) = parse_link(&bare).expect("valid link");
        assert_eq!(id, "abc123");
        assert_eq!(parsed, secret);
    }

    #[test]
    fn rejects_links_missing_the_secret_or_id() {
        assert!(parse_link("abc123").is_err());
        assert!(parse_link("#not-base64url!!").is_err());
        assert!(parse_link(&format!("#{}", b64::encode([1u8; SECRET_LEN]))).is_err());
    }
}
