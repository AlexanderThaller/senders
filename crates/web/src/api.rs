//! Thin HTTP client for the senders API.
//!
//! Uploads go through `XMLHttpRequest` because it is the only portable way to
//! get byte-level upload progress; downloads use `fetch` so the response body
//! can be consumed as a stream and decrypted record by record.

use futures_util::StreamExt;
use js_sys::Uint8Array;
use senders_proto::{FileParams, MetadataResponse, ServerInfo, UploadResponse, b64, header as hdr};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Blob, Headers, Request, RequestInit, Response};

#[derive(Debug, Clone)]
/// A failed API call.
pub struct ApiError {
    /// HTTP status, or `0` when the request never reached the server.
    pub status: u16,
    /// Message safe to show the user; the server's own wording when it sent one.
    pub message: String,
}

impl ApiError {
    fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    #[must_use]
    /// The download capability was rejected — usually a wrong passphrase.
    pub fn is_unauthorized(&self) -> bool {
        self.status == 401
    }

    #[must_use]
    /// The share is gone: expired, used up, or deleted.
    pub fn is_missing(&self) -> bool {
        self.status == 404 || self.status == 410
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<JsValue> for ApiError {
    fn from(value: JsValue) -> Self {
        ApiError::new(0, format!("network error: {value:?}"))
    }
}

impl From<crate::crypto::Error> for ApiError {
    fn from(value: crate::crypto::Error) -> Self {
        ApiError::new(0, value.0)
    }
}

/// Result shorthand for API calls.
pub type Result<T> = std::result::Result<T, ApiError>;

fn window() -> Result<web_sys::Window> {
    web_sys::window().ok_or_else(|| ApiError::new(0, "no window"))
}

/// Turn a non-2xx response into an [`ApiError`], preferring the server's own
/// message over a generic status line.
async fn check(response: Response) -> Result<Response> {
    if response.ok() {
        return Ok(response);
    }
    let status = response.status();
    let message = match JsFuture::from(response.text()?).await {
        Ok(text) => text
            .as_string()
            .and_then(|body| serde_json::from_str::<senders_proto::ApiError>(&body).ok())
            .map_or_else(
                || format!("request failed with status {status}"),
                |err| err.message,
            ),
        Err(_) => format!("request failed with status {status}"),
    };
    Err(ApiError::new(status, message))
}

async fn fetch(request: Request) -> Result<Response> {
    let response = JsFuture::from(window()?.fetch_with_request(&request)).await?;
    check(response.unchecked_into()).await
}

async fn json<T: serde::de::DeserializeOwned>(response: Response) -> Result<T> {
    let text = JsFuture::from(response.text()?)
        .await?
        .as_string()
        .ok_or_else(|| ApiError::new(0, "response body was not text"))?;
    serde_json::from_str(&text)
        .map_err(|err| ApiError::new(0, format!("malformed response: {err}")))
}

fn request(method: &str, url: &str, headers: &Headers) -> Result<Request> {
    let init = RequestInit::new();
    init.set_method(method);
    init.set_headers(headers);
    Request::new_with_str_and_init(url, &init).map_err(ApiError::from)
}

fn bearer(auth_key: &[u8]) -> Result<Headers> {
    let headers = Headers::new()?;
    headers.set(
        "Authorization",
        &format!("Bearer {}", b64::encode(auth_key)),
    )?;
    Ok(headers)
}

/// `GET /api/info` — limits and session state.
pub async fn server_info() -> Result<ServerInfo> {
    json(fetch(request("GET", "/api/info", &Headers::new()?)?).await?).await
}

/// Unauthenticated pre-flight: is a password needed, and with which salt?
/// `GET /api/files/{id}/params` — the unauthenticated pre-flight.
pub async fn params(id: &str) -> Result<FileParams> {
    json(
        fetch(request(
            "GET",
            &format!("/api/files/{id}/params"),
            &Headers::new()?,
        )?)
        .await?,
    )
    .await
}

/// `GET /api/files/{id}/metadata` — the sealed name/type blob.
pub async fn metadata(id: &str, auth_key: &[u8]) -> Result<MetadataResponse> {
    json(
        fetch(request(
            "GET",
            &format!("/api/files/{id}/metadata"),
            &bearer(auth_key)?,
        )?)
        .await?,
    )
    .await
}

/// `DELETE /api/files/{id}` — revoke a share.
pub async fn delete(id: &str, owner_token: &str) -> Result<()> {
    let headers = Headers::new()?;
    headers.set("X-Senders-Owner", owner_token)?;
    fetch(request("DELETE", &format!("/api/files/{id}"), &headers)?).await?;
    Ok(())
}

/// Parameters that ride alongside an upload body.
#[derive(Debug, Clone)]
pub struct UploadParams {
    /// base64url sealed metadata blob.
    pub metadata: String,
    /// base64url SHA-256 of the download capability.
    pub auth_hash: String,
    /// base64url STREAM nonce prefix.
    pub nonce_prefix: String,
    /// base64url PBKDF2 salt, when a passphrase is set.
    pub auth_salt: Option<String>,
    /// Requested lifetime in seconds.
    pub expires_in: u64,
    /// Requested download budget.
    pub max_downloads: u32,
}

/// POST the encrypted blob, reporting upload progress as a 0.0–1.0 fraction.
///
/// `XMLHttpRequest` is wrapped in a future by hand: the load/error/abort
/// handlers resolve a oneshot channel.
pub async fn upload(
    body: &Blob,
    params: &UploadParams,
    mut on_progress: impl FnMut(f64) + 'static,
) -> Result<UploadResponse> {
    let xhr = web_sys::XmlHttpRequest::new()?;
    xhr.open_with_async("POST", "/api/files", true)?;
    xhr.set_request_header(hdr::METADATA, &params.metadata)?;
    xhr.set_request_header(hdr::AUTH_HASH, &params.auth_hash)?;
    xhr.set_request_header(hdr::NONCE_PREFIX, &params.nonce_prefix)?;
    xhr.set_request_header(hdr::EXPIRES_IN, &params.expires_in.to_string())?;
    xhr.set_request_header(hdr::MAX_DOWNLOADS, &params.max_downloads.to_string())?;
    if let Some(salt) = &params.auth_salt {
        xhr.set_request_header(hdr::AUTH_SALT, salt)?;
    }

    let (tx, rx) = futures_channel::oneshot::channel::<()>();
    let on_settled = Closure::once(move |_event: web_sys::Event| {
        let _ = tx.send(());
    });
    xhr.set_onloadend(Some(on_settled.as_ref().unchecked_ref()));

    let on_upload_progress =
        Closure::<dyn FnMut(web_sys::ProgressEvent)>::new(move |event: web_sys::ProgressEvent| {
            if event.length_computable() && event.total() > 0.0 {
                on_progress(event.loaded() / event.total());
            }
        });
    xhr.upload()?
        .set_onprogress(Some(on_upload_progress.as_ref().unchecked_ref()));

    xhr.send_with_opt_blob(Some(body))?;
    let _ = rx.await;

    // Keep the closures alive until the request has settled.
    drop(on_settled);
    drop(on_upload_progress);

    let status = xhr.status()?;
    let text = xhr.response_text()?.unwrap_or_default();
    if status == 0 {
        return Err(ApiError::new(0, "the upload was interrupted"));
    }
    if !(200..300).contains(&status) {
        let message = serde_json::from_str::<senders_proto::ApiError>(&text).map_or_else(
            |_| format!("upload failed with status {status}"),
            |err| err.message,
        );
        return Err(ApiError::new(status, message));
    }
    serde_json::from_str(&text)
        .map_err(|err| ApiError::new(0, format!("malformed response: {err}")))
}

/// Fetch the ciphertext and hand back a stream of raw byte chunks.
///
/// Chunk boundaries here are network-sized, not record-sized; the caller
/// re-frames them into records.
pub async fn download_stream(
    id: &str,
    auth_key: &[u8],
) -> Result<impl futures_util::Stream<Item = Result<Vec<u8>>>> {
    let response = fetch(request(
        "GET",
        &format!("/api/files/{id}/blob"),
        &bearer(auth_key)?,
    )?)
    .await?;
    let body = response
        .body()
        .ok_or_else(|| ApiError::new(0, "the response had no body"))?;
    Ok(wasm_streams::ReadableStream::from_raw(body)
        .into_stream()
        .map(|chunk| match chunk {
            Ok(value) => Ok(Uint8Array::new(&value).to_vec()),
            Err(err) => Err(ApiError::from(err)),
        }))
}
