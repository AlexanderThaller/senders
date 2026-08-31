//! Sessions and optional `OpenID` Connect login.
//!
//! Sessions are stateless: a signed, HMAC-SHA256-authenticated cookie carrying
//! the subject, a display name, and an expiry. Nothing needs to be stored
//! server-side, so replicas share sessions as long as they share
//! `SENDERS_SESSION_SECRET`.

use crate::config::AuthMode;
use crate::error::AppError;
use crate::state::AppState;
use crate::util;
use axum::extract::FromRequestParts;
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue};
use hmac::{Hmac, Mac};
use senders_proto::{SessionInfo, b64};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[cfg(feature = "oidc")]
pub mod oidc;

/// Cookie carrying the signed session.
pub const SESSION_COOKIE: &str = "senders_session";
/// Cookie carrying an in-flight login: PKCE verifier, nonce, CSRF state and
/// where to land afterwards.
pub const FLOW_COOKIE: &str = "senders_oidc_flow";

/// Contents of a session cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Stable identifier for the user, from the identity provider.
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Email address, when the provider supplies one.
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Display name, when the provider supplies one.
    pub name: Option<String>,
    /// Absolute expiry, seconds since the epoch.
    pub exp: u64,
}

impl Session {
    /// The subset of the session the frontend is allowed to see.
    #[must_use]
    pub fn info(&self) -> SessionInfo {
        SessionInfo {
            subject: self.sub.clone(),
            email: self.email.clone(),
            name: self.name.clone(),
        }
    }
}

type HmacSha256 = Hmac<Sha256>;

/// Signs and verifies cookie payloads.
pub struct SessionSigner {
    key: [u8; 32],
    secure: bool,
}

impl std::fmt::Debug for SessionSigner {
    /// Hand-written so the signing key cannot reach a log line: anyone holding
    /// it can mint a session for any user.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSigner")
            .field("key", &"<redacted>")
            .field("secure", &self.secure)
            .finish()
    }
}

impl SessionSigner {
    /// Build a signer. Without a configured secret a random key is generated,
    /// which means sessions do not survive a restart and are not shared
    /// between replicas.
    #[must_use]
    pub fn new(secret: Option<&str>, secure: bool) -> Self {
        let key = match secret {
            // Hash rather than truncate, so any length of configured secret
            // contributes all of its entropy.
            Some(secret) => util::sha256(secret.as_bytes()),
            None => util::random_bytes::<32>(),
        };
        Self { key, secure }
    }

    fn tag(&self, payload: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(payload);
        mac.finalize().into_bytes().into()
    }

    /// `<base64url(payload)>.<base64url(tag)>`
    pub fn sign<T: Serialize>(&self, value: &T) -> anyhow::Result<String> {
        let payload = serde_json::to_vec(value)?;
        let tag = self.tag(&payload);
        Ok(format!("{}.{}", b64::encode(&payload), b64::encode(tag)))
    }

    #[must_use]
    /// Check the tag and decode the payload, or `None` if either fails.
    pub fn verify<T: for<'de> Deserialize<'de>>(&self, token: &str) -> Option<T> {
        let (payload_b64, tag_b64) = token.split_once('.')?;
        let payload = b64::decode(payload_b64)?;
        let tag = b64::decode(tag_b64)?;
        if !util::ct_eq(&self.tag(&payload), &tag) {
            return None;
        }
        serde_json::from_slice(&payload).ok()
    }

    /// A `Set-Cookie` value. `max_age` of `None` clears the cookie.
    #[must_use]
    pub fn cookie(&self, name: &str, value: &str, max_age: Option<u64>) -> HeaderValue {
        let mut cookie = match max_age {
            Some(age) => format!("{name}={value}; Max-Age={age}"),
            None => format!("{name}=; Max-Age=0"),
        };
        cookie.push_str("; Path=/; HttpOnly; SameSite=Lax");
        if self.secure {
            cookie.push_str("; Secure");
        }
        HeaderValue::from_str(&cookie).expect("cookie components are base64url and ASCII")
    }

    /// A `Set-Cookie` value carrying a freshly signed session.
    pub fn session_cookie(&self, session: &Session, ttl: u64) -> anyhow::Result<HeaderValue> {
        Ok(self.cookie(SESSION_COOKIE, &self.sign(session)?, Some(ttl)))
    }

    /// A `Set-Cookie` value that deletes `name`.
    #[must_use]
    pub fn clear(&self, name: &str) -> HeaderValue {
        self.cookie(name, "", None)
    }
}

/// Read one cookie value out of a request's `Cookie` headers.
pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_string())
}

/// Append a `Set-Cookie` header, keeping any already present.
pub fn set_cookie(headers: &mut HeaderMap, value: HeaderValue) {
    headers.append(SET_COOKIE, value);
}

/// The signed-in user, if any. Extracting this never fails.
#[derive(Debug, Clone)]
pub struct CurrentUser(pub Option<Session>);

impl CurrentUser {
    /// The signed-in user's subject, if there is one.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.0.as_ref().map(|session| session.sub.as_str())
    }
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = std::convert::Infallible;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the extractor trait declares this async; there is nothing to await"
    )]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(CurrentUser(current_session(&parts.headers, state)))
    }
}

fn current_session(headers: &HeaderMap, state: &AppState) -> Option<Session> {
    let raw = read_cookie(headers, SESSION_COOKIE)?;
    let session: Session = state.sessions.verify(&raw)?;
    // A signature alone is not enough: an old cookie must stop working.
    (session.exp > util::now()).then_some(session)
}

/// Extractor for routes that must not run without a login. Which routes those
/// are depends on [`AuthMode`]; see [`require`].
#[derive(Debug, Clone)]
pub struct AuthedUser(pub Option<Session>);

impl FromRequestParts<AppState> for AuthedUser {
    type Rejection = AppError;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the extractor trait declares this async; there is nothing to await"
    )]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session = current_session(&parts.headers, state);
        require(state, session, AuthMode::Upload).map(AuthedUser)
    }
}

/// Like [`AuthedUser`] but only enforced when the whole service is hidden
/// (`--auth-mode all`). Used on download routes, which normally stay public so
/// share links work for people without an account.
#[derive(Debug, Clone)]
pub struct PublicOrAuthedUser(pub Option<Session>);

impl FromRequestParts<AppState> for PublicOrAuthedUser {
    type Rejection = AppError;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the extractor trait declares this async; there is nothing to await"
    )]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session = current_session(&parts.headers, state);
        require(state, session, AuthMode::All).map(PublicOrAuthedUser)
    }
}

/// Enforce a session when the configured mode is at least as strict as
/// `needed_at`. `Off` never requires one; `All` requires one everywhere.
fn require(
    state: &AppState,
    session: Option<Session>,
    needed_at: AuthMode,
) -> Result<Option<Session>, AppError> {
    let enforced = match state.config.auth_mode {
        AuthMode::Off => false,
        AuthMode::All => true,
        AuthMode::Upload => needed_at == AuthMode::Upload,
    };
    if enforced && session.is_none() {
        return Err(AppError::Unauthorized);
    }
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> SessionSigner {
        SessionSigner::new(Some("test-secret"), true)
    }

    fn session(exp: u64) -> Session {
        Session {
            sub: "user-1".into(),
            email: Some("a@b.c".into()),
            name: None,
            exp,
        }
    }

    #[test]
    fn signed_sessions_round_trip() {
        let signer = signer();
        let token = signer.sign(&session(123)).unwrap();
        let decoded: Session = signer.verify(&token).unwrap();
        assert_eq!(decoded.sub, "user-1");
        assert_eq!(decoded.exp, 123);
    }

    #[test]
    fn tampered_payloads_are_rejected() {
        let signer = signer();
        let token = signer.sign(&session(123)).unwrap();
        let (payload, tag) = token.split_once('.').unwrap();

        // Swap in a different subject but keep the original tag.
        let forged_payload = b64::encode(serde_json::to_vec(&session(999)).unwrap());
        assert!(
            signer
                .verify::<Session>(&format!("{forged_payload}.{tag}"))
                .is_none()
        );
        // Flip the tag.
        assert!(
            signer
                .verify::<Session>(&format!("{payload}.{}", b64::encode([0u8; 32])))
                .is_none()
        );
        // A cookie signed by a different key is worthless here.
        let other = SessionSigner::new(Some("other-secret"), true);
        assert!(
            signer
                .verify::<Session>(&other.sign(&session(123)).unwrap())
                .is_none()
        );
    }

    #[test]
    fn cookies_carry_hardening_attributes() {
        let value = signer().cookie(SESSION_COOKIE, "abc", Some(60));
        let value = value.to_str().unwrap();
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("SameSite=Lax"));
        assert!(value.contains("Secure"));
        assert!(
            !SessionSigner::new(None, false)
                .cookie("x", "y", Some(1))
                .to_str()
                .unwrap()
                .contains("Secure")
        );
    }

    #[test]
    fn cookie_parsing_picks_the_right_pair() {
        let mut headers = HeaderMap::new();
        headers.append(
            COOKIE,
            HeaderValue::from_static("other=1; senders_session=abc.def; trailing=2"),
        );
        assert_eq!(
            read_cookie(&headers, SESSION_COOKIE).as_deref(),
            Some("abc.def")
        );
        assert_eq!(read_cookie(&headers, "missing"), None);
    }
}
