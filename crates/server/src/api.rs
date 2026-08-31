//! The file API.
//!
//! Everything here operates on opaque ciphertext. The server can tell you how
//! big a file is, when it expires and how many downloads are left; it cannot
//! read the file, its name, or its type. The decryption key never leaves the
//! browser — it lives in the URL fragment, which is not sent to servers.

use crate::auth::{AuthedUser, PublicOrAuthedUser};
use crate::error::{AppError, AppResult};
use crate::meta::{Claim, FileRecord};
use crate::state::AppState;
use crate::util;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use futures_util::TryStreamExt;
use senders_proto::{
    AUTH_SALT_LEN, FileParams, MetadataResponse, NONCE_PREFIX_LEN, OwnerInfo, PBKDF2_ITERATIONS,
    SetPasswordRequest, UploadResponse, b64, header as hdr,
};

/// Upper bound on the encrypted-metadata blob. A filename plus MIME type is a
/// few hundred bytes; this is generous while keeping the field from becoming
/// free storage.
const MAX_METADATA_LEN: usize = 4096;

/// Header carrying the owner token on owner-only routes.
const OWNER_HEADER: &str = "x-senders-owner";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/files",
            post(upload).layer(DefaultBodyLimit::disable()),
        )
        .route("/api/files/{id}/params", get(params))
        .route("/api/files/{id}/metadata", get(metadata))
        .route("/api/files/{id}/blob", get(download))
        .route("/api/files/{id}", delete(destroy))
        .route("/api/files/{id}/owner", get(owner_info))
        .route("/api/files/{id}/password", put(set_password))
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

/// Read a header that must decode to exactly `LEN` bytes of base64url.
fn required_b64<const LEN: usize>(headers: &HeaderMap, name: &str) -> AppResult<String> {
    let raw = header_value(headers, name)
        .ok_or_else(|| AppError::BadRequest(format!("missing {name} header")))?;
    if b64::decode_array::<LEN>(raw).is_none() {
        return Err(AppError::BadRequest(format!(
            "{name} must be {LEN} base64url-encoded bytes"
        )));
    }
    Ok(raw.to_string())
}

fn optional_number<T: std::str::FromStr>(headers: &HeaderMap, name: &str) -> AppResult<Option<T>> {
    match header_value(headers, name) {
        None => Ok(None),
        Some(raw) => raw
            .parse()
            .map(Some)
            .map_err(|_| AppError::BadRequest(format!("{name} must be a number"))),
    }
}

fn check_id(id: &str) -> AppResult<()> {
    if util::is_valid_id(id) {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// Load a record, treating an expired-but-not-yet-reaped file as gone.
async fn load(state: &AppState, id: &str) -> AppResult<FileRecord> {
    check_id(id)?;
    let record = state
        .meta
        .get(id)
        .await
        .map_err(AppError::Internal)?
        .ok_or(AppError::NotFound)?;
    if record.expires_at <= util::now() {
        return Err(AppError::NotFound);
    }
    Ok(record)
}

/// Verify the bearer download key against the stored hash. The server holds
/// only a SHA-256 digest, so a dump of the metadata store does not let an
/// attacker authenticate as a downloader.
fn check_download_auth(headers: &HeaderMap, record: &FileRecord) -> AppResult<()> {
    let presented = header_value(headers, header::AUTHORIZATION.as_str())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;
    let key = b64::decode(presented.trim()).ok_or(AppError::Unauthorized)?;
    let expected = b64::decode(&record.auth_hash).ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "stored auth hash for {} is malformed",
            record.id
        ))
    })?;
    if util::ct_eq(&util::sha256(&key), &expected) {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

/// Verify the owner token. The token is an opaque string issued at upload and
/// hashed as-is, so this compares the presented characters rather than the
/// bytes they happen to decode to.
fn check_owner(headers: &HeaderMap, record: &FileRecord) -> AppResult<()> {
    let presented = header_value(headers, OWNER_HEADER)
        .ok_or(AppError::Unauthorized)?
        .trim();
    let expected = b64::decode(&record.owner_hash).ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "stored owner hash for {} is malformed",
            record.id
        ))
    })?;
    if util::ct_eq(&util::sha256(presented.as_bytes()), &expected) {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

/// `POST /api/files` — stream ciphertext in, get a share id back.
///
/// Upload parameters travel as headers so the body can be piped straight to
/// blob storage without buffering the whole file.
async fn upload(
    State(state): State<AppState>,
    AuthedUser(session): AuthedUser,
    headers: HeaderMap,
    body: Body,
) -> AppResult<Json<UploadResponse>> {
    let metadata = header_value(&headers, hdr::METADATA)
        .ok_or_else(|| AppError::BadRequest(format!("missing {} header", hdr::METADATA)))?;
    if metadata.len() > MAX_METADATA_LEN {
        return Err(AppError::BadRequest(
            "encrypted metadata is too large".into(),
        ));
    }
    if b64::decode(metadata).is_none() {
        return Err(AppError::BadRequest(
            "encrypted metadata must be base64url".into(),
        ));
    }

    let auth_hash = required_b64::<32>(&headers, hdr::AUTH_HASH)?;
    let nonce_prefix = required_b64::<NONCE_PREFIX_LEN>(&headers, hdr::NONCE_PREFIX)?;
    let auth_salt = match header_value(&headers, hdr::AUTH_SALT) {
        Some(_) => Some(required_b64::<AUTH_SALT_LEN>(&headers, hdr::AUTH_SALT)?),
        None => None,
    };

    let expires_in = state
        .config
        .clamp_expiry(optional_number(&headers, hdr::EXPIRES_IN)?);
    let max_downloads = state
        .config
        .clamp_downloads(optional_number(&headers, hdr::MAX_DOWNLOADS)?);

    let id = util::random_id();
    let owner_token = util::random_token();

    let stream = body
        .into_data_stream()
        .map_err(|err| std::io::Error::other(err.to_string()));
    let size = match state
        .blobs
        .put(&id, Box::pin(stream), state.config.max_file_size)
        .await
    {
        Ok(size) => size,
        Err(crate::blob::BlobError::TooLarge) => return Err(AppError::TooLarge),
        Err(err) => return Err(AppError::Internal(anyhow::Error::from(err))),
    };

    let now = util::now();
    let record = FileRecord {
        id: id.clone(),
        metadata: metadata.to_string(),
        nonce_prefix,
        auth_hash,
        auth_salt,
        owner_hash: b64::encode(util::sha256(owner_token.as_bytes())),
        size,
        downloads: 0,
        max_downloads,
        created_at: now,
        expires_at: now + expires_in,
        owner_subject: session.map(|session| session.sub),
    };

    // If we cannot record the metadata the blob is unreachable, so drop it
    // rather than leaving ciphertext nobody will ever collect.
    if let Err(err) = state.meta.put(&record).await {
        let _ = state.blobs.delete(&id).await;
        return Err(AppError::Internal(err));
    }

    tracing::info!(%id, size, max_downloads, expires_in, "stored a file");
    Ok(Json(UploadResponse {
        id,
        owner_token,
        expires_at: record.expires_at,
    }))
}

/// `GET /api/files/{id}/params` — unauthenticated pre-flight.
///
/// A downloader needs to know whether a password is required (and with which
/// salt) *before* it can derive the auth key, so this route cannot itself be
/// behind the download auth key.
async fn params(
    State(state): State<AppState>,
    PublicOrAuthedUser(_): PublicOrAuthedUser,
    Path(id): Path<String>,
) -> AppResult<Json<FileParams>> {
    let record = load(&state, &id).await?;
    if record.downloads_remaining() == 0 {
        return Err(AppError::Exhausted);
    }
    Ok(Json(FileParams {
        id: record.id.clone(),
        has_password: record.has_password(),
        auth_salt: record.auth_salt.clone(),
        kdf_iterations: PBKDF2_ITERATIONS,
        expires_at: record.expires_at,
        downloads_remaining: record.downloads_remaining(),
    }))
}

/// `GET /api/files/{id}/metadata` — the encrypted name/type/size blob.
async fn metadata(
    State(state): State<AppState>,
    PublicOrAuthedUser(_): PublicOrAuthedUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<MetadataResponse>> {
    let record = load(&state, &id).await?;
    check_download_auth(&headers, &record)?;
    if record.downloads_remaining() == 0 {
        return Err(AppError::Exhausted);
    }
    Ok(Json(MetadataResponse {
        id: record.id.clone(),
        metadata: record.metadata.clone(),
        nonce_prefix: record.nonce_prefix.clone(),
        size: record.size,
        expires_at: record.expires_at,
        downloads_remaining: record.downloads_remaining(),
    }))
}

/// Destroys a file when dropped. Attached to the download stream so that a
/// "burn after reading" link is cleaned up as soon as the body is finished
/// with — whether it completed or the client hung up. The budget is already
/// spent at that point either way.
struct DestroyOnDrop {
    state: AppState,
    id: String,
}

impl Drop for DestroyOnDrop {
    fn drop(&mut self) {
        let state = self.state.clone();
        let id = std::mem::take(&mut self.id);
        tokio::spawn(async move {
            if let Err(err) = state.destroy(&id).await {
                // Not fatal: the reaper will pick it up at expiry.
                tracing::warn!(%id, error = ?err, "failed to destroy a spent file");
            } else {
                tracing::info!(%id, "destroyed a file after its final download");
            }
        });
    }
}

/// `GET /api/files/{id}/blob` — stream the ciphertext.
async fn download(
    State(state): State<AppState>,
    PublicOrAuthedUser(_): PublicOrAuthedUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let record = load(&state, &id).await?;
    check_download_auth(&headers, &record)?;

    // Claim the slot before opening the blob, so concurrent requests can never
    // together exceed the download budget.
    let claim = state
        .meta
        .claim_download(&id)
        .await
        .map_err(AppError::Internal)?;
    let last = match claim {
        Claim::NotFound => return Err(AppError::NotFound),
        Claim::Exhausted => return Err(AppError::Exhausted),
        Claim::Granted { last, .. } => last,
    };

    let stream = match state.blobs.get(&id).await {
        Ok(stream) => stream,
        Err(crate::blob::BlobError::NotFound) => return Err(AppError::NotFound),
        Err(err) => return Err(AppError::Internal(anyhow::Error::from(err))),
    };

    // Moving the guard into the stream's closure ties the file's lifetime to
    // the response body: dropping the body drops the guard.
    let guard = last.then(|| DestroyOnDrop {
        state: state.clone(),
        id: id.clone(),
    });
    let stream = stream.inspect_ok(move |_| {
        let _keep_alive = &guard;
    });

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, record.size.to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

/// `GET /api/files/{id}/owner` — upload status for whoever holds the token.
async fn owner_info(
    State(state): State<AppState>,
    PublicOrAuthedUser(_): PublicOrAuthedUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<OwnerInfo>> {
    let record = load(&state, &id).await?;
    check_owner(&headers, &record)?;
    Ok(Json(OwnerInfo {
        id: record.id.clone(),
        downloads: record.downloads,
        max_downloads: record.max_downloads,
        expires_at: record.expires_at,
        size: record.size,
        has_password: record.has_password(),
    }))
}

/// `DELETE /api/files/{id}` — revoke a share immediately.
async fn destroy(
    State(state): State<AppState>,
    PublicOrAuthedUser(_): PublicOrAuthedUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<StatusCode> {
    let record = load(&state, &id).await?;
    check_owner(&headers, &record)?;
    state.destroy(&id).await.map_err(AppError::Internal)?;
    tracing::info!(%id, "owner deleted a file");
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /api/files/{id}/password` — add, change, or clear the password.
///
/// The server only swaps opaque values: the new auth-key hash, and the KDF
/// salt the downloader will need.
async fn set_password(
    State(state): State<AppState>,
    PublicOrAuthedUser(_): PublicOrAuthedUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<SetPasswordRequest>,
) -> AppResult<StatusCode> {
    let record = load(&state, &id).await?;
    check_owner(&headers, &record)?;

    if b64::decode_array::<32>(&request.auth_hash).is_none() {
        return Err(AppError::BadRequest(
            "auth_hash must be 32 base64url-encoded bytes".into(),
        ));
    }
    if let Some(salt) = &request.auth_salt
        && b64::decode_array::<AUTH_SALT_LEN>(salt).is_none()
    {
        return Err(AppError::BadRequest(format!(
            "auth_salt must be {AUTH_SALT_LEN} base64url-encoded bytes"
        )));
    }

    let updated = state
        .meta
        .set_auth(&id, &request.auth_hash, request.auth_salt.as_deref())
        .await
        .map_err(AppError::Internal)?;
    if !updated {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}
