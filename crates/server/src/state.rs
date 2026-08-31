//! Shared application state handed to every handler.

use crate::auth::SessionSigner;
use crate::blob::SharedBlobStore;
use crate::config::Config;
use crate::meta::SharedMetaStore;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub blobs: SharedBlobStore,
    pub meta: SharedMetaStore,
    pub sessions: Arc<SessionSigner>,
    #[cfg(feature = "oidc")]
    pub oidc: Option<Arc<crate::auth::oidc::Oidc>>,
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
