//! Ciphertext storage. The server never holds a key, so a blob is just an
//! opaque byte stream addressed by file id.

use bytes::Bytes;
use futures_util::Stream;
use std::pin::Pin;
use std::sync::Arc;

pub mod fs;
#[cfg(feature = "s3")]
pub mod s3;

/// A stream of ciphertext chunks, in either direction.
pub type ByteStream = Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send + 'static>>;

#[derive(Debug, thiserror::Error)]
/// Why a blob operation failed.
pub enum BlobError {
    #[error("blob not found")]
    /// No object is stored under that id.
    NotFound,
    #[error("upload exceeds the maximum allowed size")]
    /// The upload exceeded the configured maximum and was discarded.
    TooLarge,
    #[error(transparent)]
    /// Anything the backend itself reported.
    Other(#[from] anyhow::Error),
}

#[async_trait::async_trait]
/// Somewhere ciphertext can be put, fetched and deleted.
pub trait BlobStore: Send + Sync + 'static {
    /// Stream `body` into storage under `id`, refusing to write more than
    /// `max_size` bytes. Returns the number of bytes stored.
    ///
    /// Implementations must leave no partial object behind on failure.
    async fn put(&self, id: &str, body: ByteStream, max_size: u64) -> Result<u64, BlobError>;

    /// Stream the stored ciphertext back out.
    async fn get(&self, id: &str) -> Result<ByteStream, BlobError>;

    /// Remove the object. Deleting a missing object is not an error, so that
    /// the reaper is idempotent.
    async fn delete(&self, id: &str) -> Result<(), BlobError>;

    /// Cheap readiness probe for `/healthz`.
    async fn health(&self) -> Result<(), BlobError>;
}

/// A blob store shared across handlers.
pub type SharedBlobStore = Arc<dyn BlobStore>;

/// Build a blob store from a URI: `fs:<path>`, `file://<path>`, or
/// `s3://<bucket>[/<prefix>]`.
pub async fn from_uri(uri: &str) -> anyhow::Result<SharedBlobStore> {
    if let Some(path) = uri
        .strip_prefix("fs:")
        .or_else(|| uri.strip_prefix("file://"))
    {
        return Ok(Arc::new(fs::FsBlobStore::new(path).await?));
    }
    #[cfg(feature = "s3")]
    if let Some(rest) = uri.strip_prefix("s3://") {
        let (bucket, prefix) = match rest.split_once('/') {
            Some((b, p)) => (b, p.trim_end_matches('/')),
            None => (rest, ""),
        };
        return Ok(Arc::new(s3::S3BlobStore::new(bucket, prefix).await?));
    }
    #[cfg(not(feature = "s3"))]
    if uri.starts_with("s3://") {
        anyhow::bail!("this binary was built without the `s3` feature");
    }
    anyhow::bail!("unsupported storage URI {uri:?}; expected fs:<path> or s3://<bucket>[/<prefix>]")
}
