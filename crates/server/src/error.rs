//! One error type for every handler, rendered as a stable JSON body.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use senders_proto::ApiError;

#[derive(Debug, thiserror::Error)]
/// Everything a handler can fail with.
pub enum AppError {
    #[error("not found")]
    /// No such file, or it has expired.
    NotFound,
    #[error("unauthorized")]
    /// The download capability or owner token was missing or wrong.
    Unauthorized,
    #[error("forbidden")]
    /// Authenticated, but not permitted -- an off-allow-list email domain.
    Forbidden,
    #[error("{0}")]
    /// The request was malformed; the string is safe to show the caller.
    BadRequest(String),
    #[error("file is larger than the configured limit")]
    /// The upload exceeded the configured maximum.
    TooLarge,
    #[error("this link has no downloads left")]
    /// The download budget is spent.
    Exhausted,
    #[error(transparent)]
    /// Anything unexpected. Logged in full, reported opaquely.
    Internal(#[from] anyhow::Error),
}

impl AppError {
    fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
            Self::Exhausted => (StatusCode::GONE, "exhausted"),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();
        // Internal failures are logged in full but reported opaquely: the
        // client never learns about storage topology or backend errors.
        let message = match &self {
            Self::Internal(err) => {
                tracing::error!(error = ?err, "request failed");
                "internal server error".to_string()
            }
            // Spelled out rather than a wildcard so a new variant has to be
            // considered here, where the client-visible wording is decided.
            other @ (Self::NotFound
            | Self::Unauthorized
            | Self::Forbidden
            | Self::BadRequest(_)
            | Self::TooLarge
            | Self::Exhausted) => other.to_string(),
        };
        let body = axum::Json(ApiError {
            error: code.to_string(),
            message,
        });
        (status, body).into_response()
    }
}

/// Handler result shorthand.
pub type AppResult<T> = Result<T, AppError>;
