//! Filesystem blob store — the zero-dependency backend for local runs and
//! single-host deployments.

use super::{BlobError, BlobStore, ByteStream};
use futures_util::StreamExt;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    pub async fn new(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let root = root.as_ref().to_path_buf();
        tokio::fs::create_dir_all(&root).await?;
        Ok(Self { root })
    }

    /// Shard on the first two id characters so a busy instance does not put
    /// millions of entries in one directory.
    fn path_for(&self, id: &str) -> PathBuf {
        self.root.join(&id[..2]).join(id)
    }
}

#[async_trait::async_trait]
impl BlobStore for FsBlobStore {
    async fn put(&self, id: &str, mut body: ByteStream, max_size: u64) -> Result<u64, BlobError> {
        let final_path = self.path_for(id);
        let dir = final_path
            .parent()
            .expect("sharded path always has a parent");
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(anyhow::Error::from)?;
        let tmp_path = final_path.with_extension("part");

        // Write to a sibling temp file and rename, so a crashed upload can
        // never be served as a truncated blob.
        let result = async {
            let mut file = tokio::fs::File::create(&tmp_path)
                .await
                .map_err(anyhow::Error::from)?;
            let mut written: u64 = 0;
            while let Some(chunk) = body.next().await {
                let chunk = chunk.map_err(anyhow::Error::from)?;
                written += chunk.len() as u64;
                if written > max_size {
                    return Err(BlobError::TooLarge);
                }
                file.write_all(&chunk).await.map_err(anyhow::Error::from)?;
            }
            file.flush().await.map_err(anyhow::Error::from)?;
            file.sync_all().await.map_err(anyhow::Error::from)?;
            Ok(written)
        }
        .await;

        match result {
            Ok(written) => {
                tokio::fs::rename(&tmp_path, &final_path)
                    .await
                    .map_err(anyhow::Error::from)?;
                Ok(written)
            }
            Err(err) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                Err(err)
            }
        }
    }

    async fn get(&self, id: &str) -> Result<ByteStream, BlobError> {
        let file = match tokio::fs::File::open(self.path_for(id)).await {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(BlobError::NotFound);
            }
            Err(err) => return Err(anyhow::Error::from(err).into()),
        };
        Ok(Box::pin(tokio_util::io::ReaderStream::with_capacity(
            file,
            64 * 1024,
        )))
    }

    async fn delete(&self, id: &str) -> Result<(), BlobError> {
        match tokio::fs::remove_file(self.path_for(id)).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(anyhow::Error::from(err).into()),
        }
    }

    async fn health(&self) -> Result<(), BlobError> {
        tokio::fs::metadata(&self.root)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(())
    }
}
