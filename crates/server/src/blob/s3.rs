//! S3-compatible blob store (AWS S3, `MinIO`, Cloudflare R2, Ceph …).
//!
//! Credentials, region and `AWS_ENDPOINT_URL` come from the standard AWS
//! environment. Set `SENDERS_S3_PATH_STYLE=true` for `MinIO` and other servers
//! that do not do virtual-host-style addressing.

use super::{BlobError, BlobStore, ByteStream};
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream as AwsByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;

/// Multipart part size. S3 requires at least 5 MiB for every part but the last.
const PART_SIZE: usize = 8 * 1024 * 1024;

#[derive(Debug)]
/// Ciphertext stored as objects in an S3-compatible bucket.
pub struct S3BlobStore {
    client: Client,
    bucket: String,
    prefix: String,
}

impl S3BlobStore {
    /// Build a client from the ambient AWS environment.
    pub async fn new(bucket: &str, prefix: &str) -> anyhow::Result<Self> {
        let shared = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if std::env::var("SENDERS_S3_PATH_STYLE")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        {
            builder = builder.force_path_style(true);
        }
        Ok(Self {
            client: Client::from_conf(builder.build()),
            bucket: bucket.to_string(),
            prefix: prefix.trim_matches('/').to_string(),
        })
    }

    fn key_for(&self, id: &str) -> String {
        if self.prefix.is_empty() {
            format!("blobs/{}/{id}", &id[..2])
        } else {
            format!("{}/blobs/{}/{id}", self.prefix, &id[..2])
        }
    }

    /// Upload in parts, aborting the multipart upload if anything fails so we
    /// do not leave billable orphaned parts behind.
    async fn put_multipart(
        &self,
        key: &str,
        first: Bytes,
        mut body: ByteStream,
        max_size: u64,
    ) -> Result<u64, BlobError> {
        let created = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| anyhow::Error::from(e).context("create_multipart_upload"))?;
        let upload_id = created
            .upload_id()
            .ok_or_else(|| anyhow::anyhow!("S3 did not return an upload id"))?
            .to_string();

        let result = self
            .stream_parts(key, &upload_id, first, &mut body, max_size)
            .await;

        match result {
            Ok((parts, written)) => {
                self.client
                    .complete_multipart_upload()
                    .bucket(&self.bucket)
                    .key(key)
                    .upload_id(&upload_id)
                    .multipart_upload(
                        CompletedMultipartUpload::builder()
                            .set_parts(Some(parts))
                            .build(),
                    )
                    .send()
                    .await
                    .map_err(|e| anyhow::Error::from(e).context("complete_multipart_upload"))?;
                Ok(written)
            }
            Err(err) => {
                let _ = self
                    .client
                    .abort_multipart_upload()
                    .bucket(&self.bucket)
                    .key(key)
                    .upload_id(&upload_id)
                    .send()
                    .await;
                Err(err)
            }
        }
    }

    async fn stream_parts(
        &self,
        key: &str,
        upload_id: &str,
        first: Bytes,
        body: &mut ByteStream,
        max_size: u64,
    ) -> Result<(Vec<CompletedPart>, u64), BlobError> {
        let mut parts = Vec::new();
        let mut buffer = BytesMut::from(&first[..]);
        let mut written: u64 = first.len() as u64;
        let mut part_number = 1i32;

        loop {
            while buffer.len() >= PART_SIZE {
                let chunk = buffer.split_to(PART_SIZE).freeze();
                parts.push(self.upload_part(key, upload_id, part_number, chunk).await?);
                part_number += 1;
            }
            match body.next().await {
                Some(chunk) => {
                    let chunk = chunk.map_err(anyhow::Error::from)?;
                    written += chunk.len() as u64;
                    if written > max_size {
                        return Err(BlobError::TooLarge);
                    }
                    buffer.extend_from_slice(&chunk);
                }
                None => break,
            }
        }
        // A multipart upload must have at least one part; the tail may be
        // smaller than PART_SIZE, which S3 permits for the final part only.
        if !buffer.is_empty() || parts.is_empty() {
            parts.push(
                self.upload_part(key, upload_id, part_number, buffer.freeze())
                    .await?,
            );
        }
        Ok((parts, written))
    }

    async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: Bytes,
    ) -> Result<CompletedPart, BlobError> {
        let response = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(AwsByteStream::from(body))
            .send()
            .await
            .map_err(|e| anyhow::Error::from(e).context("upload_part"))?;
        Ok(CompletedPart::builder()
            .set_e_tag(response.e_tag().map(str::to_string))
            .part_number(part_number)
            .build())
    }
}

#[async_trait::async_trait]
impl BlobStore for S3BlobStore {
    async fn put(&self, id: &str, mut body: ByteStream, max_size: u64) -> Result<u64, BlobError> {
        let key = self.key_for(id);

        // Buffer up to one part before deciding how to upload: small files (the
        // common case) become a single PutObject instead of a three-request
        // multipart dance.
        let mut buffer = BytesMut::new();
        let mut stream_ended = false;
        while buffer.len() < PART_SIZE {
            if let Some(chunk) = body.next().await {
                let chunk = chunk.map_err(anyhow::Error::from)?;
                if buffer.len() as u64 + chunk.len() as u64 > max_size {
                    return Err(BlobError::TooLarge);
                }
                buffer.extend_from_slice(&chunk);
            } else {
                stream_ended = true;
                break;
            }
        }

        if stream_ended {
            let written = buffer.len() as u64;
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(&key)
                .body(AwsByteStream::from(buffer.freeze()))
                .send()
                .await
                .map_err(|e| anyhow::Error::from(e).context("put_object"))?;
            return Ok(written);
        }

        self.put_multipart(&key, buffer.freeze(), body, max_size)
            .await
    }

    async fn get(&self, id: &str) -> Result<ByteStream, BlobError> {
        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key_for(id))
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(err) => {
                let service = err.into_service_error();
                if service.is_no_such_key() {
                    return Err(BlobError::NotFound);
                }
                return Err(anyhow::Error::from(service).context("get_object").into());
            }
        };
        // `ByteStream` is not itself a `Stream`, so adapt it through its
        // `AsyncRead` view.
        Ok(Box::pin(tokio_util::io::ReaderStream::with_capacity(
            response.body.into_async_read(),
            64 * 1024,
        )))
    }

    async fn delete(&self, id: &str) -> Result<(), BlobError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(self.key_for(id))
            .send()
            .await
            .map_err(|e| anyhow::Error::from(e).context("delete_object"))?;
        Ok(())
    }

    async fn health(&self) -> Result<(), BlobError> {
        self.client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .map_err(|e| anyhow::Error::from(e).context("head_bucket"))?;
        Ok(())
    }
}
