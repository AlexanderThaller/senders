//! Whole-file encrypt and decrypt pipelines.
//!
//! Both directions work record by record and spill into `Blob`s as they go.
//! Browsers back large blobs with disk, so a multi-gigabyte transfer does not
//! have to fit in the JS heap at once.

use crate::api::{self, ApiError};
use crate::crypto::{self, FileKeys};
use js_sys::{Array, Uint8Array};
use senders_proto::{
    CHUNK_CIPHERTEXT_SIZE, CHUNK_SIZE, FileMetadata, NONCE_PREFIX_LEN, SECRET_LEN, b64,
};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Blob, BlobPropertyBag, File};

/// Records buffered before being flushed into an intermediate `Blob`.
const RECORDS_PER_BLOB: usize = 64;

type Result<T> = std::result::Result<T, ApiError>;

fn to_error(err: impl std::fmt::Display) -> ApiError {
    ApiError {
        status: 0,
        message: err.to_string(),
    }
}

/// Collects byte chunks, flushing to intermediate `Blob`s so the JS heap never
/// holds the whole payload.
#[derive(Default)]
struct BlobBuilder {
    pending: Vec<Uint8Array>,
    parts: Vec<Blob>,
}

impl BlobBuilder {
    fn push(&mut self, bytes: &[u8]) -> Result<()> {
        self.pending.push(Uint8Array::from(bytes));
        if self.pending.len() >= RECORDS_PER_BLOB {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let array = Array::new();
        for part in self.pending.drain(..) {
            array.push(&part);
        }
        self.parts.push(Blob::new_with_u8_array_sequence(&array)?);
        Ok(())
    }

    fn finish(mut self, mime: Option<&str>) -> Result<Blob> {
        self.flush()?;
        let array = Array::new();
        for part in &self.parts {
            array.push(part);
        }
        // A `Blob` of `Blob`s references its parts rather than copying them.
        Ok(match mime {
            Some(mime) => {
                let options = BlobPropertyBag::new();
                options.set_type(mime);
                Blob::new_with_blob_sequence_and_options(&array, &options)?
            }
            None => Blob::new_with_blob_sequence(&array)?,
        })
    }
}

/// Read `[start, end)` of a blob into memory.
async fn read_slice(blob: &Blob, start: f64, end: f64) -> Result<Vec<u8>> {
    let slice = blob.slice_with_f64_and_f64(start, end)?;
    let buffer = JsFuture::from(slice.array_buffer()).await?;
    Ok(Uint8Array::new(&buffer).to_vec())
}

/// A file encrypted and ready to upload.
pub struct SealedFile {
    /// The ciphertext, ready to be handed to the upload.
    pub blob: Blob,
    /// The URL-fragment secret. Never leaves the browser.
    pub secret: Vec<u8>,
    /// The keys derived from [`secret`](Self::secret).
    pub keys: FileKeys,
    /// The STREAM nonce prefix this file was sealed with.
    pub nonce_prefix: Vec<u8>,
    /// base64url sealed metadata blob, for the upload headers.
    pub metadata: String,
}

impl std::fmt::Debug for SealedFile {
    /// Hand-written so the secret cannot reach a log line: it is the whole key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedFile")
            .field("secret", &"<redacted>")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

/// Encrypt `file` under a freshly generated secret.
///
/// `on_progress` receives 0.0–1.0 as records are sealed.
pub async fn seal_file(file: &File, mut on_progress: impl FnMut(f64)) -> Result<SealedFile> {
    let secret = crypto::random_bytes(SECRET_LEN).map_err(to_error)?;
    let keys = FileKeys::derive(&secret).await.map_err(to_error)?;
    let nonce_prefix = crypto::random_bytes(NONCE_PREFIX_LEN).map_err(to_error)?;

    let blob: &Blob = file.as_ref();
    let size = blob.size();
    let chunk = crate::convert::len_to_f64(CHUNK_SIZE);
    // An empty file still gets one empty, authenticated record, so that
    // "zero bytes" is a fact the recipient can verify rather than assume.
    let records = senders_proto::stream::plain_record_count(crate::convert::to_u64(size));

    let mut builder = BlobBuilder::default();
    for index in 0..records {
        let start = f64::from(index) * chunk;
        let end = (start + chunk).min(size);
        let plaintext = read_slice(blob, start, end).await?;
        let sealed = keys
            .seal_record(&nonce_prefix, index, index + 1 == records, &plaintext)
            .await
            .map_err(to_error)?;
        builder.push(&sealed)?;
        on_progress(f64::from(index + 1) / f64::from(records));
    }

    let metadata = FileMetadata {
        name: file.name(),
        mime: {
            let mime = blob.type_();
            if mime.is_empty() {
                "application/octet-stream".to_string()
            } else {
                mime
            }
        },
        size: crate::convert::to_u64(size),
    };
    let sealed_metadata = keys
        .seal_metadata(&serde_json::to_vec(&metadata).map_err(to_error)?)
        .await
        .map_err(to_error)?;

    Ok(SealedFile {
        blob: builder.finish(None)?,
        secret,
        keys,
        nonce_prefix,
        metadata: b64::encode(&sealed_metadata),
    })
}

/// Stream the ciphertext down and decrypt it into a `Blob`.
///
/// Any tampering, reordering or truncation makes a record fail to
/// authenticate, which surfaces here as an error rather than as partial data.
pub async fn open_file(
    id: &str,
    keys: &FileKeys,
    nonce_prefix: &[u8],
    cipher_len: u64,
    mime: &str,
    on_progress: impl FnMut(f64),
) -> Result<Blob> {
    let stream = api::download_stream(id, &keys.auth).await?;
    open_stream(keys, nonce_prefix, cipher_len, mime, stream, on_progress).await
}

/// Decrypt a ciphertext stream into a `Blob`.
///
/// Split out from [`open_file`] so the record framing can be tested against an
/// in-memory stream with awkward chunk boundaries: the bytes arriving from the
/// network are cut at arbitrary points that have nothing to do with record
/// boundaries, and getting that re-framing wrong is the easiest way to ship a
/// client that cannot read its own files.
pub async fn open_stream(
    keys: &FileKeys,
    nonce_prefix: &[u8],
    cipher_len: u64,
    mime: &str,
    stream: impl futures_util::Stream<Item = Result<Vec<u8>>>,
    mut on_progress: impl FnMut(f64),
) -> Result<Blob> {
    use futures_util::StreamExt;

    let total_records = senders_proto::stream::cipher_record_count(cipher_len);
    let mut stream = Box::pin(stream);

    let mut builder = BlobBuilder::default();
    let mut buffer: Vec<u8> = Vec::with_capacity(CHUNK_CIPHERTEXT_SIZE * 2);
    let mut index: u64 = 0;

    while let Some(chunk) = stream.next().await {
        buffer.extend_from_slice(&chunk?);
        // Every record except the last is exactly one full record long, so the
        // framing is unambiguous.
        while index + 1 < total_records && buffer.len() >= CHUNK_CIPHERTEXT_SIZE {
            let record: Vec<u8> = buffer.drain(..CHUNK_CIPHERTEXT_SIZE).collect();
            let plaintext = keys
                .open_record(
                    nonce_prefix,
                    senders_proto::stream::record_index(index),
                    false,
                    &record,
                )
                .await
                .map_err(to_error)?;
            builder.push(&plaintext)?;
            index += 1;
            on_progress(crate::convert::to_f64(index) / crate::convert::to_f64(total_records));
        }
    }

    if index + 1 != total_records {
        return Err(to_error(format!(
            "download ended early: got {index} of {total_records} records"
        )));
    }
    let plaintext = keys
        .open_record(
            nonce_prefix,
            senders_proto::stream::record_index(index),
            true,
            &buffer,
        )
        .await
        .map_err(to_error)?;
    builder.push(&plaintext)?;
    on_progress(1.0);

    builder.finish(Some(mime))
}

/// Hand a decrypted blob to the browser as a download.
pub fn save_blob(blob: &Blob, filename: &str) -> Result<()> {
    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or_else(|| to_error("no document"))?;
    let url = web_sys::Url::create_object_url_with_blob(blob)?;
    let anchor: web_sys::HtmlAnchorElement = document.create_element("a")?.unchecked_into();
    anchor.set_href(&url);
    anchor.set_download(filename);
    anchor.click();
    // The blob stays alive until the URL is revoked; the click has already
    // handed it to the browser's download manager by now.
    web_sys::Url::revoke_object_url(&url)?;
    Ok(())
}

/// Build the share link. The secret goes in the fragment, which browsers do
/// not send to servers and which stays out of access logs and `Referer`.
/// The format itself lives in `senders_proto::link`, shared with
/// `crates/cli`.
#[must_use]
pub fn share_url(origin: &str, id: &str, secret: &[u8]) -> String {
    senders_proto::link::share_url(origin, id, secret)
}

/// Read the secret back out of `location.hash`. Decoding and validating it is
/// `senders_proto::link`'s; only reaching into `location.hash` is
/// browser-specific.
#[must_use]
pub fn secret_from_fragment() -> Option<Vec<u8>> {
    let hash = web_sys::window()?.location().hash().ok()?;
    let raw = hash.strip_prefix('#').unwrap_or(&hash);
    senders_proto::link::decode_secret(raw)
}
