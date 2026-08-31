//! Shared application state handed to every handler.

use crate::auth::SessionSigner;
use crate::blob::SharedBlobStore;
use crate::config::Config;
use crate::meta::SharedMetaStore;
use std::sync::Arc;

#[derive(Clone)]
/// Shared application state, cloned into every handler.
pub struct AppState {
    /// Runtime configuration.
    pub config: Arc<Config>,
    /// Where ciphertext lives.
    pub blobs: SharedBlobStore,
    /// Where the facts about each share live.
    pub meta: SharedMetaStore,
    /// Signs and verifies session cookies.
    pub sessions: Arc<SessionSigner>,
    #[cfg(feature = "oidc")]
    /// The identity provider, when login is enabled.
    pub oidc: Option<Arc<crate::auth::oidc::Oidc>>,
}

impl std::fmt::Debug for AppState {
    /// The stores are trait objects and the signer holds key material, so this
    /// reports the shape of the state rather than its contents.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("storage", &self.config.storage)
            .field("metadata", &self.config.metadata)
            .field("auth_mode", &self.config.auth_mode.as_str())
            .finish_non_exhaustive()
    }
}

impl AppState {
    /// Delete a file completely: blob first, then metadata. If the blob delete
    /// fails we keep the metadata so the reaper retries rather than orphaning
    /// stored ciphertext.
    pub async fn destroy(&self, id: &str) -> anyhow::Result<()> {
        self.blobs.delete(id).await?;
        self.meta.delete(id).await?;
        Ok(())
    }
}
