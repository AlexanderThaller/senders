//! `senders` — an end-to-end encrypted file sharing service.
//!
//! The server is deliberately ignorant: it stores ciphertext, an encrypted
//! metadata blob, and hashes of the two capability tokens. Keys are derived in
//! the browser from a secret that lives in the URL fragment and is therefore
//! never transmitted.

pub mod api;
pub mod auth;
pub mod blob;
pub mod config;
pub mod error;
pub mod meta;
pub mod reaper;
pub mod state;
pub mod util;

use auth::{CurrentUser, SessionSigner};
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use config::Config;
use senders_proto::ServerInfo;
use state::AppState;
use std::sync::Arc;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

/// Wire up storage, sessions and (optionally) the identity provider.
pub async fn build_state(config: Config) -> anyhow::Result<AppState> {
    config.validate()?;

    let blobs = blob::from_uri(&config.storage).await?;
    let meta = meta::from_uri(&config.metadata).await?;
    if config.auth_mode.enabled() && config.session_secret.is_none() {
        tracing::warn!(
            "no --session-secret set: logins will not survive a restart and will not work across replicas"
        );
    }
    let sessions = Arc::new(SessionSigner::new(
        config.session_secret.as_deref(),
        !config.cookie_insecure,
    ));

    #[cfg(feature = "oidc")]
    let oidc = if config.auth_mode.enabled() {
        Some(Arc::new(auth::oidc::Oidc::discover(&config).await?))
    } else {
        None
    };

    Ok(AppState {
        config: Arc::new(config),
        blobs,
        meta,
        sessions,
        #[cfg(feature = "oidc")]
        oidc,
    })
}

pub fn router(state: AppState) -> Router {
    let static_dir = state.config.static_dir.clone();
    // Unknown paths fall through to the SPA shell so deep links like
    // `/d/<id>#<key>` load the app instead of 404ing.
    let frontend =
        ServeDir::new(&static_dir).fallback(ServeFile::new(static_dir.join("index.html")));

    let index_html = std::fs::read_to_string(static_dir.join("index.html")).ok();
    let csp = content_security_policy(index_html.as_deref());
    let csp = HeaderValue::from_str(&csp).expect("the policy is built from ASCII");

    let mut app = Router::new()
        .route("/api/info", get(info))
        .route("/healthz", get(healthz))
        .merge(api::routes());

    #[cfg(feature = "oidc")]
    {
        app = app
            .route("/auth/login", get(auth::oidc::login))
            .route("/auth/callback", get(auth::oidc::callback))
            .route("/auth/logout", get(auth::oidc::logout));
    }

    app.fallback_service(frontend)
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            csp,
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Extract the bodies of inline `<script>` elements, so their hashes can be
/// pinned in the CSP.
///
/// The frontend bundler emits an inline module script to boot the wasm. Rather
/// than opening the policy up with `'unsafe-inline'` — in an application whose
/// entire security rests on nothing else running in this tab — we hash exactly
/// the script we shipped and allow only that.
fn inline_scripts(html: &str) -> Vec<&str> {
    let mut scripts = Vec::new();
    let mut rest = html;
    while let Some(open) = rest.find("<script") {
        rest = &rest[open..];
        let Some(tag_end) = rest.find('>') else { break };
        let (tag, after) = rest.split_at(tag_end + 1);
        let Some(close) = after.find("</script>") else {
            break;
        };
        let (body, remainder) = after.split_at(close);
        // Scripts with a `src` are external and covered by `'self'`.
        if !tag.contains(" src=") && !body.trim().is_empty() {
            scripts.push(body);
        }
        rest = remainder;
    }
    scripts
}

/// Build the Content-Security-Policy, pinning the hash of every inline script
/// found in the shipped `index.html`.
///
/// The CSP matters more than usual here: an injected script would be running in
/// the one place that holds the decryption key. `wasm-unsafe-eval` is required
/// to instantiate the WebAssembly module; `connect-src 'self'` keeps a
/// compromised page from posting plaintext anywhere else.
fn content_security_policy(index_html: Option<&str>) -> String {
    use base64::Engine as _;

    let mut script_src = String::from("'self' 'wasm-unsafe-eval'");
    for script in index_html.map(inline_scripts).unwrap_or_default() {
        let digest = util::sha256(script.as_bytes());
        let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
        script_src.push_str(&format!(" 'sha256-{encoded}'"));
    }

    format!(
        "default-src 'self'; \
         script-src {script_src}; \
         style-src 'self'; \
         font-src 'self'; \
         img-src 'self' data: blob:; \
         connect-src 'self'; \
         object-src 'none'; \
         base-uri 'none'; \
         form-action 'self'; \
         frame-ancestors 'none'"
    )
}

async fn info(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
) -> Json<ServerInfo> {
    let config = &state.config;
    Json(ServerInfo {
        max_file_size: config.max_file_size,
        min_expiry_secs: senders_proto::MIN_EXPIRY_SECS,
        max_expiry_secs: config.effective_max_expiry(),
        default_expiry_secs: config.default_expiry,
        max_downloads: config.effective_max_downloads(),
        default_max_downloads: senders_proto::DEFAULT_MAX_DOWNLOADS,
        auth_mode: config.auth_mode.as_str().to_string(),
        auth_required: config.auth_mode.enabled(),
        session: session.as_ref().map(auth::Session::info),
    })
}

async fn healthz(State(state): State<AppState>) -> (StatusCode, &'static str) {
    match (state.meta.health().await, state.blobs.health().await) {
        (Ok(()), Ok(())) => (StatusCode::OK, "ok"),
        (meta, blobs) => {
            tracing::warn!(?meta, ?blobs, "health check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "unhealthy")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_scripts_are_found_and_external_ones_ignored() {
        let html = r#"<html><head>
            <script src="/app.js"></script>
            <script type="module">import init from '/a.js'; await init();</script>
            <script>  </script>
            </head></html>"#;
        let found = inline_scripts(html);
        assert_eq!(found.len(), 1, "only the non-empty inline script counts");
        assert!(found[0].contains("import init"));
    }

    #[test]
    fn the_policy_pins_the_shipped_bootstrap_script() {
        let html = "<script type=\"module\">boot();</script>";
        let policy = content_security_policy(Some(html));
        assert!(
            policy.contains("'sha256-"),
            "the inline script must be pinned by hash"
        );
        assert!(
            !policy.contains("'unsafe-inline'"),
            "never fall back to unsafe-inline"
        );

        // A different bundle produces a different pin.
        let other = content_security_policy(Some("<script type=\"module\">boot2();</script>"));
        assert_ne!(policy, other);
    }

    #[test]
    fn the_policy_locks_down_the_dangerous_directives() {
        let policy = content_security_policy(None);
        for directive in [
            "default-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
        ] {
            assert!(policy.contains(directive), "missing {directive}");
        }
    }
}
