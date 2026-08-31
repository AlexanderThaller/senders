//! One error type for every handler, rendered as a stable JSON body.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use senders_proto::ApiError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not found")]
    NotFound,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("{0}")]
    BadRequest(String),
    #[error("file is larger than the configured limit")]
    TooLarge,
    #[error("this link has no downloads left")]
    Exhausted,
    #[error(transparent)]
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
            other => other.to_string(),
        };
        let body = axum::Json(ApiError {
            error: code.to_string(),
            message,
        });
        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
