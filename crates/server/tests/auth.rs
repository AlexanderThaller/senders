//! Access-control tests for the three auth modes.
//!
//! These build `AppState` directly rather than going through `build_state`, so
//! they exercise the enforcement logic without needing a live identity
//! provider to discover.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use senders_proto::{b64, header as hdr};
use senders_server::auth::{SESSION_COOKIE, Session, SessionSigner};
use senders_server::config::{AuthMode, Config};
use senders_server::state::AppState;
use std::sync::Arc;
use tower::ServiceExt as _;

struct Harness {
    state: AppState,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn new(mode: AuthMode) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let storage = format!("fs:{}", dir.path().display());
        let mut config =
            Config::parse_from_args(["senders", "--metadata", "memory:", "--storage", &storage]);
        config.auth_mode = mode;
        config.session_secret = Some("test-session-secret".into());

        let blobs = senders_server::blob::from_uri(&config.storage)
            .await
            .expect("blobs");
        let meta = senders_server::meta::from_uri(&config.metadata)
            .await
            .expect("meta");
        let sessions = Arc::new(SessionSigner::new(config.session_secret.as_deref(), false));

        let state = AppState {
            config: Arc::new(config),
            blobs,
            meta,
            sessions,
            #[cfg(feature = "oidc")]
            oidc: None,
        };
        Self { state, _dir: dir }
    }

    async fn call(&self, request: Request<Body>) -> StatusCode {
        senders_server::router(self.state.clone())
            .oneshot(request)
            .await
            .expect("router responds")
            .status()
    }

    /// A cookie for a session that is valid for another hour.
    fn valid_cookie(&self) -> String {
        self.cookie_expiring_at(now() + 3600)
    }

    fn cookie_expiring_at(&self, exp: u64) -> String {
        let session = Session {
            sub: "user-42".into(),
            email: Some("someone@example.com".into()),
            name: None,
            exp,
        };
        format!(
            "{SESSION_COOKIE}={}",
            self.state.sessions.sign(&session).expect("sign")
        )
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn upload(cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/files")
        .header(hdr::METADATA, b64::encode(b"metadata"))
        .header(hdr::AUTH_HASH, b64::encode([1u8; 32]))
        .header(hdr::NONCE_PREFIX, b64::encode([2u8; 7]));
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    builder.body(Body::from("ciphertext")).unwrap()
}

fn params(cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().uri("/api/files/aaaaaaaaaaaaaaaaaaaaaa/params");
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn with_auth_off_anyone_may_upload() {
    let harness = Harness::new(AuthMode::Off).await;
    assert_eq!(harness.call(upload(None)).await, StatusCode::OK);
}

#[tokio::test]
async fn upload_mode_gates_uploads_but_keeps_share_links_public() {
    let harness = Harness::new(AuthMode::Upload).await;

    assert_eq!(harness.call(upload(None)).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        harness.call(upload(Some(&harness.valid_cookie()))).await,
        StatusCode::OK
    );

    // A recipient without an account must still be able to follow a link:
    // 404 (no such file) rather than 401 (not signed in).
    assert_eq!(harness.call(params(None)).await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn all_mode_hides_downloads_too() {
    let harness = Harness::new(AuthMode::All).await;

    assert_eq!(harness.call(upload(None)).await, StatusCode::UNAUTHORIZED);
    assert_eq!(harness.call(params(None)).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        harness.call(params(Some(&harness.valid_cookie()))).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn an_expired_session_no_longer_authenticates() {
    let harness = Harness::new(AuthMode::Upload).await;
    let stale = harness.cookie_expiring_at(now() - 1);
    assert_eq!(
        harness.call(upload(Some(&stale))).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_forged_or_foreign_session_is_refused() {
    let harness = Harness::new(AuthMode::Upload).await;

    // Unsigned, and signed by somebody else's key.
    let unsigned = format!("{SESSION_COOKIE}=eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.xxxx");
    assert_eq!(
        harness.call(upload(Some(&unsigned))).await,
        StatusCode::UNAUTHORIZED
    );

    let foreign_signer = SessionSigner::new(Some("a-different-secret"), false);
    let session = Session {
        sub: "attacker".into(),
        email: None,
        name: None,
        exp: now() + 3600,
    };
    let foreign = format!(
        "{SESSION_COOKIE}={}",
        foreign_signer.sign(&session).unwrap()
    );
    assert_eq!(
        harness.call(upload(Some(&foreign))).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn the_uploader_is_recorded_when_signed_in() {
    let harness = Harness::new(AuthMode::Upload).await;
    let response = senders_server::router(harness.state.clone())
        .oneshot(upload(Some(&harness.valid_cookie())))
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let uploaded: senders_proto::UploadResponse = serde_json::from_slice(&body).unwrap();

    let record = harness.state.meta.get(&uploaded.id).await.unwrap().unwrap();
    assert_eq!(record.owner_subject.as_deref(), Some("user-42"));
}

#[tokio::test]
async fn server_info_reports_the_mode_and_session() {
    let harness = Harness::new(AuthMode::Upload).await;

    let fetch = |cookie: Option<String>| {
        let state = harness.state.clone();
        async move {
            let mut builder = Request::builder().uri("/api/info");
            if let Some(cookie) = cookie {
                builder = builder.header("cookie", cookie);
            }
            let response = senders_server::router(state)
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<senders_proto::ServerInfo>(&body).unwrap()
        }
    };

    let anonymous = fetch(None).await;
    assert_eq!(anonymous.auth_mode, "upload");
    assert!(anonymous.auth_required);
    assert!(
        anonymous.session.is_none(),
        "an anonymous visitor has no session"
    );

    let signed_in = fetch(Some(harness.valid_cookie())).await;
    let session = signed_in
        .session
        .expect("a signed-in visitor has a session");
    assert_eq!(session.subject, "user-42");
    assert_eq!(session.email.as_deref(), Some("someone@example.com"));
}
