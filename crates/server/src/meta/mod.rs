//! Metadata storage. Holds everything *about* a file that the server is
//! allowed to know: expiry, download budget, and hashes of the download and
//! owner tokens. Never any key material.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod memory;
pub mod redis;

/// Server-side record for one shared file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    /// Share identifier.
    pub id: String,
    /// base64url AES-GCM ciphertext of the file's JSON metadata.
    pub metadata: String,
    /// base64url STREAM nonce prefix.
    pub nonce_prefix: String,
    /// base64url SHA-256 of the download auth key.
    pub auth_hash: String,
    /// base64url PBKDF2 salt; `Some` exactly when the file is password-protected.
    pub auth_salt: Option<String>,
    /// base64url SHA-256 of the owner token.
    pub owner_hash: String,
    /// Ciphertext length in bytes.
    pub size: u64,
    /// Downloads served so far.
    pub downloads: u32,
    /// Total download budget.
    pub max_downloads: u32,
    /// Upload time, seconds since the Unix epoch.
    pub created_at: u64,
    /// Absolute expiry, seconds since the Unix epoch.
    pub expires_at: u64,
    /// OIDC subject of the uploader, when the service runs behind auth.
    pub owner_subject: Option<String>,
}

impl FileRecord {
    /// Whether a passphrase guards the download.
    #[must_use]
    pub fn has_password(&self) -> bool {
        self.auth_salt.is_some()
    }

    /// Downloads still allowed before the file is destroyed.
    #[must_use]
    pub fn downloads_remaining(&self) -> u32 {
        self.max_downloads.saturating_sub(self.downloads)
    }
}

/// Result of atomically claiming one download slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// No such file (or it already expired).
    NotFound,
    /// The download budget was already spent.
    Exhausted,
    /// Slot claimed. `last` means this was the final allowed download and the
    /// file must be destroyed once the response body has been delivered.
    Granted {
        /// Downloads still allowed after this one.
        remaining: u32,
        /// This was the final allowed download; destroy the file once the
        /// response body has been delivered.
        last: bool,
    },
}

#[async_trait::async_trait]
/// Where the facts about a share live: expiry, budget, and token hashes.
pub trait MetaStore: Send + Sync + 'static {
    /// Insert a new record. Also registers it for expiry-driven reaping.
    async fn put(&self, record: &FileRecord) -> anyhow::Result<()>;

    /// Look a record up, or `None` if there is no such share.
    async fn get(&self, id: &str) -> anyhow::Result<Option<FileRecord>>;

    /// Atomically increment the download counter, refusing to exceed the
    /// budget. Must be race-free across processes.
    async fn claim_download(&self, id: &str) -> anyhow::Result<Claim>;

    /// Replace the download auth material. `auth_salt` is `Some` for a
    /// password-protected file, `None` to drop the password.
    async fn set_auth(
        &self,
        id: &str,
        auth_hash: &str,
        auth_salt: Option<&str>,
    ) -> anyhow::Result<bool>;

    /// Forget a record. Deleting a missing one is not an error, so that the
    /// reaper is idempotent.
    async fn delete(&self, id: &str) -> anyhow::Result<()>;

    /// Ids whose expiry has passed, for the reaper.
    async fn expired(&self, now: u64, limit: usize) -> anyhow::Result<Vec<String>>;

    /// Cheap readiness probe for `/healthz`.
    async fn health(&self) -> anyhow::Result<()>;
}

/// A metadata store shared across handlers.
pub type SharedMetaStore = Arc<dyn MetaStore>;

/// Build a metadata store from a URI: `redis://…`, `rediss://…`,
/// `redis-cluster://…`, `unix://…`, or `memory:` for a single-process store.
pub async fn from_uri(uri: &str) -> anyhow::Result<SharedMetaStore> {
    if uri == "memory:" || uri == "memory" || uri == "memory://" {
        tracing::warn!(
            "using the in-memory metadata store: state is lost on restart and is not shared between replicas"
        );
        return Ok(Arc::new(memory::MemoryMetaStore::default()));
    }
    if uri.starts_with("redis://")
        || uri.starts_with("rediss://")
        || uri.starts_with("redis-cluster://")
        || uri.starts_with("redis+sentinel://")
        || uri.starts_with("unix://")
    {
        return Ok(Arc::new(redis::RedisMetaStore::connect(uri).await?));
    }
    anyhow::bail!("unsupported metadata URI {uri:?}; expected redis://… or memory:")
}
