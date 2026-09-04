//! Thin HTTP client for the senders API.
//!
//! Mirrors `crates/web/src/api.rs`, minus everything that only makes sense in
//! a browser (there is no `XMLHttpRequest` progress event here, and no
//! `fetch` streaming body reader — `reqwest` covers both directions directly).

use futures_util::Stream;
use futures_util::TryStreamExt as _;
use reqwest::{Client, StatusCode, Url};
use senders_proto::{FileParams, MetadataResponse, ServerInfo, UploadResponse, b64, header as hdr};

/// A failed API call.
#[derive(Debug, Clone)]
pub struct ApiError {
    /// HTTP status, or `None` when the request never reached the server.
    pub status: Option<StatusCode>,
    /// Message safe to show the user; the server's own wording when it sent one.
    pub message: String,
}

impl ApiError {
    fn new(status: Option<StatusCode>, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    #[must_use]
    /// The download capability was rejected — usually a wrong passphrase.
    pub fn is_unauthorized(&self) -> bool {
        self.status == Some(StatusCode::UNAUTHORIZED)
    }

    #[must_use]
    /// The share is gone: expired, used up, or deleted.
    pub fn is_missing(&self) -> bool {
        matches!(self.status, Some(StatusCode::NOT_FOUND | StatusCode::GONE))
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApiError {}

impl From<reqwest::Error> for ApiError {
    fn from(err: reqwest::Error) -> Self {
        ApiError::new(err.status(), format!("network error: {err}"))
    }
}

/// Result shorthand for API calls.
pub type Result<T> = std::result::Result<T, ApiError>;

/// Turn a non-2xx response into an [`ApiError`], preferring the server's own
/// message over a generic status line.
async fn check(response: reqwest::Response) -> Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let message = match response.text().await {
        Ok(body) => serde_json::from_str::<senders_proto::ApiError>(&body).map_or_else(
            |_| format!("request failed with status {status}"),
            |err| err.message,
        ),
        Err(_) => format!("request failed with status {status}"),
    };
    Err(ApiError::new(Some(status), message))
}

fn bearer(request: reqwest::RequestBuilder, auth_key: &[u8]) -> reqwest::RequestBuilder {
    request.bearer_auth(b64::encode(auth_key))
}

/// `GET /api/info` — limits and session state.
pub async fn server_info(client: &Client, base: &Url) -> Result<ServerInfo> {
    let url = base
        .join("api/info")
        .expect("a fixed relative path joins any base");
    Ok(check(client.get(url).send().await?).await?.json().await?)
}

/// `GET /api/files/{id}/params` — is a password needed, and with which salt?
pub async fn params(client: &Client, base: &Url, id: &str) -> Result<FileParams> {
    let url = base
        .join(&format!("api/files/{id}/params"))
        .map_err(|err| ApiError::new(None, format!("invalid server URL: {err}")))?;
    Ok(check(client.get(url).send().await?).await?.json().await?)
}

/// `GET /api/files/{id}/metadata` — the sealed name/type blob.
pub async fn metadata(
    client: &Client,
    base: &Url,
    id: &str,
    auth_key: &[u8],
) -> Result<MetadataResponse> {
    let url = base
        .join(&format!("api/files/{id}/metadata"))
        .map_err(|err| ApiError::new(None, format!("invalid server URL: {err}")))?;
    let request = bearer(client.get(url), auth_key);
    Ok(check(request.send().await?).await?.json().await?)
}

/// `DELETE /api/files/{id}` — revoke a share.
pub async fn delete(client: &Client, base: &Url, id: &str, owner_token: &str) -> Result<()> {
    let url = base
        .join(&format!("api/files/{id}"))
        .map_err(|err| ApiError::new(None, format!("invalid server URL: {err}")))?;
    check(
        client
            .delete(url)
            .header("x-senders-owner", owner_token)
            .send()
            .await?,
    )
    .await?;
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
    /// Requested lifetime in seconds; `None` lets the server pick its default.
    pub expires_in: Option<u64>,
    /// Requested download budget; `None` lets the server pick its default.
    pub max_downloads: Option<u32>,
}

/// `POST /api/files` — stream the ciphertext body up, get a share id back.
pub async fn upload(
    client: &Client,
    base: &Url,
    params: &UploadParams,
    body: reqwest::Body,
) -> Result<UploadResponse> {
    let url = base
        .join("api/files")
        .expect("a fixed relative path joins any base");
    let mut request = client
        .post(url)
        .header(hdr::METADATA, &params.metadata)
        .header(hdr::AUTH_HASH, &params.auth_hash)
        .header(hdr::NONCE_PREFIX, &params.nonce_prefix);
    if let Some(salt) = &params.auth_salt {
        request = request.header(hdr::AUTH_SALT, salt);
    }
    if let Some(expires_in) = params.expires_in {
        request = request.header(hdr::EXPIRES_IN, expires_in.to_string());
    }
    if let Some(max_downloads) = params.max_downloads {
        request = request.header(hdr::MAX_DOWNLOADS, max_downloads.to_string());
    }
    Ok(check(request.body(body).send().await?)
        .await?
        .json()
        .await?)
}

/// Fetch the ciphertext and hand back a stream of raw byte chunks.
///
/// Chunk boundaries here are network-sized, not record-sized; the caller
/// re-frames them into records.
pub async fn download_stream(
    client: &Client,
    base: &Url,
    id: &str,
    auth_key: &[u8],
) -> Result<impl Stream<Item = Result<bytes::Bytes>>> {
    let url = base
        .join(&format!("api/files/{id}/blob"))
        .map_err(|err| ApiError::new(None, format!("invalid server URL: {err}")))?;
    let request = bearer(client.get(url), auth_key);
    let response = check(request.send().await?).await?;
    Ok(response.bytes_stream().map_err(ApiError::from))
}
