//! End-to-end tests over the real router, with filesystem blobs in a temp dir
//! and the in-memory metadata store.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use senders_proto::{FileParams, MetadataResponse, OwnerInfo, UploadResponse, b64, header as hdr};
use senders_server::config::Config;
use senders_server::meta::FileRecord;
use senders_server::state::AppState;
use tower::ServiceExt as _;

/// A test harness holding the router plus the state, so tests can also poke
/// the stores directly when they need to simulate the passage of time.
struct Harness {
    state: AppState,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn new() -> Self {
        Self::with_args(&[]).await
    }

    async fn with_args(extra: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let storage = format!("fs:{}", dir.path().display());
        let mut args = vec!["senders", "--metadata", "memory:", "--storage", &storage];
        args.extend_from_slice(extra);
        let config = Config::parse_from_args(args);
        let state = senders_server::build_state(config).await.expect("state");
        Self { state, _dir: dir }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Vec<u8>) {
        let response = senders_server::router(self.state.clone())
            .oneshot(request)
            .await
            .expect("router responds");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body")
            .to_vec();
        (status, body)
    }
}

/// Stand-ins for the values the browser would compute. The server treats them
/// as opaque, so tests do not need real cryptography — only correct shapes.
struct Capabilities {
    auth_key: [u8; 32],
    metadata: String,
    nonce_prefix: [u8; 7],
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            auth_key: [7u8; 32],
            metadata: b64::encode(b"pretend this is sealed metadata"),
            nonce_prefix: [3u8; 7],
        }
    }
}

impl Capabilities {
    fn auth_hash(&self) -> String {
        b64::encode(sha256(&self.auth_key))
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", b64::encode(self.auth_key))
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn upload_request(caps: &Capabilities, body: &[u8], max_downloads: u32) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/files")
        .header(hdr::METADATA, &caps.metadata)
        .header(hdr::AUTH_HASH, caps.auth_hash())
        .header(hdr::NONCE_PREFIX, b64::encode(caps.nonce_prefix))
        .header(hdr::MAX_DOWNLOADS, max_downloads.to_string())
        .body(Body::from(body.to_vec()))
        .expect("the upload request is well formed")
}

fn get(uri: &str, bearer: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", bearer)
        .body(Body::empty())
        .expect("the GET request is well formed")
}

async fn upload(
    harness: &Harness,
    caps: &Capabilities,
    body: &[u8],
    max_downloads: u32,
) -> UploadResponse {
    let (status, response) = harness
        .call(upload_request(caps, body, max_downloads))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "upload failed: {}",
        String::from_utf8_lossy(&response)
    );
    serde_json::from_slice(&response).expect("upload response")
}

#[tokio::test]
async fn ciphertext_survives_a_round_trip_unchanged() {
    let harness = Harness::new().await;
    let caps = Capabilities::default();
    let payload = vec![0xABu8; 300_000];

    let uploaded = upload(&harness, &caps, &payload, 5).await;

    let (status, body) = harness
        .call(get(
            &format!("/api/files/{}/metadata", uploaded.id),
            &caps.bearer(),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    let metadata: MetadataResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        metadata.metadata, caps.metadata,
        "the metadata blob is stored verbatim"
    );
    assert_eq!(metadata.size, payload.len() as u64);
    assert_eq!(metadata.downloads_remaining, 5);

    let (status, body) = harness
        .call(get(
            &format!("/api/files/{}/blob", uploaded.id),
            &caps.bearer(),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body, payload,
        "the server must return byte-identical ciphertext"
    );
}

#[tokio::test]
async fn a_single_download_link_burns_after_reading() {
    let harness = Harness::new().await;
    let caps = Capabilities::default();
    let uploaded = upload(&harness, &caps, b"secret", 1).await;
    let blob_uri = format!("/api/files/{}/blob", uploaded.id);

    let (status, body) = harness.call(get(&blob_uri, &caps.bearer())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"secret");

    // The destroy task is spawned when the response body drops; give it a
    // moment, then confirm the link is dead either way.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let (status, _) = harness.call(get(&blob_uri, &caps.bearer())).await;
    assert!(
        status == StatusCode::GONE || status == StatusCode::NOT_FOUND,
        "a spent link must not serve again, got {status}"
    );
}

#[tokio::test]
async fn the_download_budget_is_enforced_exactly() {
    let harness = Harness::new().await;
    let caps = Capabilities::default();
    let uploaded = upload(&harness, &caps, b"secret", 3).await;
    let blob_uri = format!("/api/files/{}/blob", uploaded.id);

    for attempt in 1..=3 {
        let (status, _) = harness.call(get(&blob_uri, &caps.bearer())).await;
        assert_eq!(status, StatusCode::OK, "download {attempt} should succeed");
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let (status, _) = harness.call(get(&blob_uri, &caps.bearer())).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "the fourth download must be refused"
    );
}

#[tokio::test]
async fn the_wrong_download_key_is_rejected_before_any_ciphertext_moves() {
    let harness = Harness::new().await;
    let caps = Capabilities::default();
    let uploaded = upload(&harness, &caps, b"secret", 5).await;
    let wrong = format!("Bearer {}", b64::encode([9u8; 32]));

    for suffix in ["metadata", "blob"] {
        let (status, _) = harness
            .call(get(&format!("/api/files/{}/{suffix}", uploaded.id), &wrong))
            .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{suffix} must require the real key"
        );
    }

    // A rejected attempt must not consume the download budget.
    let (_, body) = harness
        .call(get(&format!("/api/files/{}/params", uploaded.id), ""))
        .await;
    let params: FileParams = serde_json::from_slice(&body).unwrap();
    assert_eq!(params.downloads_remaining, 5);
}

#[tokio::test]
async fn params_are_public_but_reveal_nothing_secret() {
    let harness = Harness::new().await;
    let caps = Capabilities::default();
    let uploaded = upload(&harness, &caps, b"secret", 2).await;

    let (status, body) = harness
        .call(
            Request::builder()
                .uri(format!("/api/files/{}/params", uploaded.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let text = String::from_utf8(body.clone()).unwrap();
    let params: FileParams = serde_json::from_slice(&body).unwrap();
    assert!(!params.has_password);
    assert_eq!(params.downloads_remaining, 2);
    assert!(
        !text.contains(&caps.auth_hash()),
        "the auth hash must never be served"
    );
    assert!(
        !text.contains(&caps.metadata),
        "encrypted metadata needs the download key"
    );
}

#[tokio::test]
async fn a_password_protected_upload_advertises_its_salt() {
    let harness = Harness::new().await;
    let caps = Capabilities::default();
    let salt = b64::encode([5u8; 16]);

    let request = Request::builder()
        .method("POST")
        .uri("/api/files")
        .header(hdr::METADATA, &caps.metadata)
        .header(hdr::AUTH_HASH, caps.auth_hash())
        .header(hdr::NONCE_PREFIX, b64::encode(caps.nonce_prefix))
        .header(hdr::AUTH_SALT, &salt)
        .body(Body::from("ciphertext"))
        .unwrap();
    let (status, body) = harness.call(request).await;
    assert_eq!(status, StatusCode::OK);
    let uploaded: UploadResponse = serde_json::from_slice(&body).unwrap();

    let (_, body) = harness
        .call(
            Request::builder()
                .uri(format!("/api/files/{}/params", uploaded.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let params: FileParams = serde_json::from_slice(&body).unwrap();
    assert!(params.has_password);
    assert_eq!(params.auth_salt.as_deref(), Some(salt.as_str()));
    assert!(
        params.kdf_iterations >= 100_000,
        "the KDF must be expensive"
    );
}

#[tokio::test]
async fn the_owner_token_can_read_status_and_revoke() {
    let harness = Harness::new().await;
    let caps = Capabilities::default();
    let uploaded = upload(&harness, &caps, b"secret", 9).await;

    let owner = |method: &str, uri: String, token: &str| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("x-senders-owner", token)
            .body(Body::empty())
            .unwrap()
    };

    let (status, body) = harness
        .call(owner(
            "GET",
            format!("/api/files/{}/owner", uploaded.id),
            &uploaded.owner_token,
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    let status_info: OwnerInfo = serde_json::from_slice(&body).unwrap();
    assert_eq!(status_info.max_downloads, 9);
    assert_eq!(status_info.downloads, 0);

    // Someone else's token must not work.
    let (status, _) = harness
        .call(owner(
            "DELETE",
            format!("/api/files/{}", uploaded.id),
            &b64::encode([1u8; 32]),
        ))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = harness
        .call(owner(
            "DELETE",
            format!("/api/files/{}", uploaded.id),
            &uploaded.owner_token,
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = harness
        .call(get(
            &format!("/api/files/{}/blob", uploaded.id),
            &caps.bearer(),
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a revoked file must be gone");
}

#[tokio::test]
async fn malformed_ids_cannot_escape_the_blob_directory() {
    let harness = Harness::new().await;
    let caps = Capabilities::default();

    for id in [
        "..",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "short",
        "aaaaaaaaaaaaaaaaaaaaaa/x",
    ] {
        let (status, _) = harness
            .call(get(&format!("/api/files/{id}/blob"), &caps.bearer()))
            .await;
        assert!(
            status.is_client_error(),
            "id {id:?} must be refused, got {status}"
        );
    }
}

#[tokio::test]
async fn uploads_above_the_configured_limit_are_refused() {
    let harness = Harness::with_args(&["--max-file-size", "1024"]).await;
    let caps = Capabilities::default();
    let (status, _) = harness
        .call(upload_request(&caps, &vec![0u8; 4096], 1))
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn uploads_missing_required_parameters_are_refused() {
    let harness = Harness::new().await;
    let caps = Capabilities::default();

    let bad = [
        // No metadata blob at all.
        Request::builder()
            .method("POST")
            .uri("/api/files")
            .header(hdr::AUTH_HASH, caps.auth_hash())
            .header(hdr::NONCE_PREFIX, b64::encode(caps.nonce_prefix))
            .body(Body::from("x")),
        // A nonce prefix of the wrong length would break record framing.
        Request::builder()
            .method("POST")
            .uri("/api/files")
            .header(hdr::METADATA, &caps.metadata)
            .header(hdr::AUTH_HASH, caps.auth_hash())
            .header(hdr::NONCE_PREFIX, b64::encode([0u8; 3]))
            .body(Body::from("x")),
        // An auth hash that is not a SHA-256 digest.
        Request::builder()
            .method("POST")
            .uri("/api/files")
            .header(hdr::METADATA, &caps.metadata)
            .header(hdr::AUTH_HASH, b64::encode([0u8; 8]))
            .header(hdr::NONCE_PREFIX, b64::encode(caps.nonce_prefix))
            .body(Body::from("x")),
    ];
    for request in bad {
        let (status, _) = harness.call(request.unwrap()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn expired_files_are_not_served_and_are_reaped() {
    let harness = Harness::new().await;
    let caps = Capabilities::default();
    let uploaded = upload(&harness, &caps, b"secret", 5).await;

    // Backdate the record rather than waiting a day.
    let mut record = harness.state.meta.get(&uploaded.id).await.unwrap().unwrap();
    record.expires_at = 1;
    harness.state.meta.put(&record).await.unwrap();

    let (status, _) = harness
        .call(get(
            &format!("/api/files/{}/blob", uploaded.id),
            &caps.bearer(),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an expired file must not be served"
    );

    let due = harness.state.meta.expired(1_000, 10).await.unwrap();
    assert!(
        due.contains(&uploaded.id),
        "the reaper must see the expired file"
    );
    harness.state.destroy(&uploaded.id).await.unwrap();
    assert!(
        harness
            .state
            .meta
            .get(&uploaded.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn requested_expiry_is_clamped_into_the_one_to_thirty_day_window() {
    let harness = Harness::new().await;
    let caps = Capabilities::default();

    for (requested, expected_days) in [(0u64, 1u64), (7 * 86_400, 7), (365 * 86_400, 30)] {
        let request = Request::builder()
            .method("POST")
            .uri("/api/files")
            .header(hdr::METADATA, &caps.metadata)
            .header(hdr::AUTH_HASH, caps.auth_hash())
            .header(hdr::NONCE_PREFIX, b64::encode(caps.nonce_prefix))
            .header(hdr::EXPIRES_IN, requested.to_string())
            .body(Body::from("x"))
            .unwrap();
        let (_, body) = harness.call(request).await;
        let uploaded: UploadResponse = serde_json::from_slice(&body).unwrap();

        let record: FileRecord = harness.state.meta.get(&uploaded.id).await.unwrap().unwrap();
        let lifetime = record.expires_at - record.created_at;
        assert_eq!(lifetime, expected_days * 86_400, "requested {requested}s");
    }
}

#[tokio::test]
async fn responses_carry_hardening_headers() {
    let harness = Harness::new().await;
    let response = senders_server::router(harness.state.clone())
        .oneshot(
            Request::builder()
                .uri("/api/info")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let headers = response.headers();
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    let csp = headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("default-src 'self'"));
    assert!(csp.contains("frame-ancestors 'none'"));
}

#[tokio::test]
async fn the_owner_can_add_and_clear_a_passphrase_after_the_fact() {
    let harness = Harness::new().await;
    let caps = Capabilities::default();
    let uploaded = upload(&harness, &caps, b"secret", 5).await;

    // A second capability, standing in for one derived from a passphrase.
    let new_key = [42u8; 32];
    let new_bearer = format!("Bearer {}", b64::encode(new_key));
    let salt = b64::encode([9u8; 16]);

    let set_password = |body: String, token: &str| {
        Request::builder()
            .method("PUT")
            .uri(format!("/api/files/{}/password", uploaded.id))
            .header("x-senders-owner", token)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    };

    // Someone without the owner token must not be able to change it.
    let body = format!(
        r#"{{"auth_hash":"{}","auth_salt":"{salt}"}}"#,
        b64::encode(sha256(&new_key))
    );
    let (status, _) = harness
        .call(set_password(body.clone(), &b64::encode([0u8; 32])))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = harness
        .call(set_password(body, &uploaded.owner_token))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The old capability is now worthless; the new one works.
    let (status, _) = harness
        .call(get(
            &format!("/api/files/{}/metadata", uploaded.id),
            &caps.bearer(),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the pre-passphrase key must stop working"
    );
    let (status, _) = harness
        .call(get(
            &format!("/api/files/{}/metadata", uploaded.id),
            &new_bearer,
        ))
        .await;
    assert_eq!(status, StatusCode::OK);

    // Downloaders are told a passphrase is needed, and which salt to use.
    let (_, body) = harness
        .call(
            Request::builder()
                .uri(format!("/api/files/{}/params", uploaded.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let params: FileParams = serde_json::from_slice(&body).unwrap();
    assert!(params.has_password);
    assert_eq!(params.auth_salt.as_deref(), Some(salt.as_str()));

    // Clearing the passphrase drops the salt again.
    let cleared = format!(r#"{{"auth_hash":"{}"}}"#, caps.auth_hash());
    let (status, _) = harness
        .call(set_password(cleared, &uploaded.owner_token))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, body) = harness
        .call(
            Request::builder()
                .uri(format!("/api/files/{}/params", uploaded.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let params: FileParams = serde_json::from_slice(&body).unwrap();
    assert!(!params.has_password);
    assert!(params.auth_salt.is_none());
}

#[tokio::test]
async fn malformed_passphrase_material_is_refused() {
    let harness = Harness::new().await;
    let caps = Capabilities::default();
    let uploaded = upload(&harness, &caps, b"secret", 5).await;

    for body in [
        // Auth hash that is not a 32-byte digest.
        format!(r#"{{"auth_hash":"{}"}}"#, b64::encode([1u8; 8])),
        // Salt of the wrong length.
        format!(
            r#"{{"auth_hash":"{}","auth_salt":"{}"}}"#,
            caps.auth_hash(),
            b64::encode([1u8; 3])
        ),
    ] {
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/files/{}/password", uploaded.id))
            .header("x-senders-owner", &uploaded.owner_token)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, _) = harness.call(request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
