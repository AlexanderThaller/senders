//! OpenID Connect authorization-code login with PKCE.
//!
//! This exists so the service can be put behind an identity provider without
//! deploying a separate `oauth2-proxy` container next to it.
//!
//! The in-flight flow (PKCE verifier, nonce, CSRF state, post-login
//! destination) rides in a short-lived signed cookie rather than server-side
//! state, keeping replicas interchangeable.

use crate::auth::{FLOW_COOKIE, SESSION_COOKIE, Session, set_cookie};
use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util;
use anyhow::Context as _;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header::LOCATION};
use axum::response::{IntoResponse, Response};
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};

/// `from_provider_metadata` sets the auth URI and *optionally* the token URI,
/// which is what pins these endpoint-state parameters.
type OidcClient = CoreClient<
    EndpointSet,      // authorization endpoint
    EndpointNotSet,   // device authorization endpoint
    EndpointNotSet,   // introspection endpoint
    EndpointNotSet,   // revocation endpoint
    EndpointMaybeSet, // token endpoint
    EndpointMaybeSet, // userinfo endpoint
>;

/// Flow state parked in a cookie between `/auth/login` and `/auth/callback`.
#[derive(Serialize, Deserialize)]
struct FlowState {
    verifier: String,
    nonce: String,
    csrf: String,
    next: String,
    exp: u64,
}

/// How long a login may sit half-finished before the flow cookie is refused.
const FLOW_TTL: u64 = 10 * 60;

pub struct Oidc {
    client: OidcClient,
    http: reqwest::Client,
    scopes: Vec<String>,
    allowed_domains: Vec<String>,
}

impl Oidc {
    /// Discover the provider and build a client. Called once at startup so a
    /// misconfigured issuer fails fast instead of at first login.
    pub async fn discover(config: &Config) -> anyhow::Result<Self> {
        let issuer = config
            .oidc_issuer
            .as_deref()
            .context("missing --oidc-issuer")?;
        let client_id = config
            .oidc_client_id
            .as_deref()
            .context("missing --oidc-client-id")?;

        // Refusing redirects is the documented mitigation for SSRF through the
        // discovery and token endpoints.
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .context("building the OIDC HTTP client")?;

        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(issuer.to_string()).context("invalid OIDC issuer URL")?,
            &http,
        )
        .await
        .with_context(|| format!("OIDC discovery failed for {issuer}"))?;

        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(client_id.to_string()),
            config.oidc_client_secret.clone().map(ClientSecret::new),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_uri()).context("invalid --public-url")?);

        let scopes = config
            .oidc_scopes
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "openid")
            .collect();

        Ok(Self {
            client,
            http,
            scopes,
            allowed_domains: config.allowed_domains(),
        })
    }

    fn authorize(&self, email: Option<&str>, verified: Option<bool>) -> Result<(), AppError> {
        authorize_email(&self.allowed_domains, email, verified)
    }
}

/// Enforce the email allow-list. An unverified email is never trusted for a
/// domain decision — otherwise anyone could claim `@yourcompany.com` by
/// setting it as an unverified profile address at their own provider.
fn authorize_email(
    allowed: &[String],
    email: Option<&str>,
    verified: Option<bool>,
) -> Result<(), AppError> {
    if allowed.is_empty() {
        return Ok(());
    }
    let Some(email) = email else {
        tracing::warn!(
            "rejecting login: an allow-list is configured but the provider sent no email claim"
        );
        return Err(AppError::Forbidden);
    };
    if verified != Some(true) {
        tracing::warn!(%email, "rejecting login: provider did not assert a verified email");
        return Err(AppError::Forbidden);
    }
    let domain = email
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if allowed.contains(&domain) {
        Ok(())
    } else {
        tracing::warn!(%domain, "rejecting login: email domain is not allow-listed");
        Err(AppError::Forbidden)
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    /// Where to land after a successful login.
    #[serde(default)]
    next: Option<String>,
}

/// Only same-origin, path-absolute destinations are accepted, so `?next=` can
/// never be used to bounce a user off to another site.
fn safe_next(next: Option<String>) -> String {
    match next {
        Some(next) if next.starts_with('/') && !next.starts_with("//") => next,
        _ => "/".to_string(),
    }
}

fn redirect_to(location: &str) -> Response {
    (StatusCode::SEE_OTHER, [(LOCATION, location.to_string())]).into_response()
}

pub async fn login(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> AppResult<Response> {
    let oidc = state.oidc.as_ref().ok_or(AppError::NotFound)?;

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = oidc
        .client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge);
    for scope in &oidc.scopes {
        request = request.add_scope(Scope::new(scope.clone()));
    }
    let (auth_url, csrf, nonce) = request.url();

    let flow = FlowState {
        verifier: verifier.into_secret(),
        nonce: nonce.secret().clone(),
        csrf: csrf.secret().clone(),
        next: safe_next(query.next),
        exp: util::now() + FLOW_TTL,
    };
    let cookie = state.sessions.cookie(
        FLOW_COOKIE,
        &state.sessions.sign(&flow).map_err(AppError::Internal)?,
        Some(FLOW_TTL),
    );

    let mut response = redirect_to(auth_url.as_str());
    set_cookie(response.headers_mut(), cookie);
    Ok(response)
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> AppResult<Response> {
    let oidc = state.oidc.as_ref().ok_or(AppError::NotFound)?;

    if let Some(error) = query.error {
        let detail = query.error_description.unwrap_or_default();
        tracing::warn!(%error, %detail, "identity provider rejected the login");
        return Err(AppError::BadRequest(format!("login failed: {error}")));
    }

    let raw_flow = crate::auth::read_cookie(&headers, FLOW_COOKIE)
        .ok_or_else(|| AppError::BadRequest("login session expired; please try again".into()))?;
    let flow: FlowState = state
        .sessions
        .verify(&raw_flow)
        .ok_or_else(|| AppError::BadRequest("login session is invalid; please try again".into()))?;
    if flow.exp <= util::now() {
        return Err(AppError::BadRequest(
            "login session expired; please try again".into(),
        ));
    }

    // CSRF: the state we handed the provider must be the one coming back.
    let returned_state = query.state.unwrap_or_default();
    if !util::ct_eq(returned_state.as_bytes(), flow.csrf.as_bytes()) {
        return Err(AppError::BadRequest("login state mismatch".into()));
    }
    let code = query
        .code
        .ok_or_else(|| AppError::BadRequest("missing authorization code".into()))?;

    let token_response = oidc
        .client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|err| AppError::Internal(anyhow::anyhow!("token endpoint unavailable: {err}")))?
        .set_pkce_verifier(PkceCodeVerifier::new(flow.verifier))
        .request_async(&oidc.http)
        .await
        .map_err(|err| AppError::Internal(anyhow::anyhow!("code exchange failed: {err}")))?;

    let id_token = token_response
        .id_token()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("provider returned no ID token")))?;
    let claims = id_token
        .claims(&oidc.client.id_token_verifier(), &Nonce::new(flow.nonce))
        .map_err(|err| {
            AppError::Internal(anyhow::anyhow!("ID token verification failed: {err}"))
        })?;

    let email = claims.email().map(|email| email.as_str().to_string());
    oidc.authorize(email.as_deref(), claims.email_verified())?;

    let session = Session {
        sub: claims.subject().as_str().to_string(),
        email,
        name: claims
            .name()
            .and_then(|name| name.get(None))
            .map(|name| name.as_str().to_string()),
        exp: util::now() + state.config.session_ttl,
    };
    tracing::info!(subject = %session.sub, "user signed in");

    let mut response = redirect_to(&flow.next);
    set_cookie(
        response.headers_mut(),
        state
            .sessions
            .session_cookie(&session, state.config.session_ttl)
            .map_err(AppError::Internal)?,
    );
    set_cookie(response.headers_mut(), state.sessions.clear(FLOW_COOKIE));
    Ok(response)
}

pub async fn logout(State(state): State<AppState>) -> Response {
    let mut response = redirect_to("/");
    set_cookie(response.headers_mut(), state.sessions.clear(SESSION_COOKIE));
    set_cookie(response.headers_mut(), state.sessions.clear(FLOW_COOKIE));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_destinations_cannot_leave_the_origin() {
        assert_eq!(safe_next(Some("/d/abc".into())), "/d/abc");
        assert_eq!(safe_next(Some("//evil.example/x".into())), "/");
        assert_eq!(safe_next(Some("https://evil.example".into())), "/");
        assert_eq!(safe_next(None), "/");
    }

    fn domains(list: &[&str]) -> Vec<String> {
        list.iter().map(|d| d.to_string()).collect()
    }

    #[test]
    fn domain_allow_list_requires_a_verified_matching_email() {
        let allowed = domains(&["example.com"]);
        assert!(authorize_email(&allowed, Some("a@example.com"), Some(true)).is_ok());
        // Case in the claim must not matter; the allow-list is lowercased.
        assert!(authorize_email(&allowed, Some("A@Example.COM"), Some(true)).is_ok());
        assert!(authorize_email(&allowed, Some("a@example.com"), Some(false)).is_err());
        assert!(authorize_email(&allowed, Some("a@example.com"), None).is_err());
        assert!(authorize_email(&allowed, Some("a@evil.com"), Some(true)).is_err());
        // A lookalike suffix must not satisfy an exact-domain allow-list.
        assert!(authorize_email(&allowed, Some("a@notexample.com"), Some(true)).is_err());
        assert!(authorize_email(&allowed, None, Some(true)).is_err());
    }

    #[test]
    fn an_empty_allow_list_admits_everyone() {
        assert!(authorize_email(&[], None, None).is_ok());
        assert!(authorize_email(&[], Some("anyone@anywhere"), Some(false)).is_ok());
    }
}
