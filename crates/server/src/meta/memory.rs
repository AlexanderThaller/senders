//! Process-local metadata store. Useful for `cargo test` and for kicking the
//! tyres without a Redis around; unsuitable for more than one replica.

use super::{Claim, FileRecord, MetaStore};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

#[derive(Debug, Default)]
/// Metadata held in this process only.
pub struct MemoryMetaStore {
    files: Mutex<HashMap<String, FileRecord>>,
}

impl MemoryMetaStore {
    /// Take the lock, recovering from poisoning.
    ///
    /// Every guarded section here is a single map operation, so a panic
    /// elsewhere cannot leave the map half-updated. Treating the mutex as
    /// unusable afterwards would turn one unrelated panic into a permanently
    /// broken store for no gain in safety.
    fn files(&self) -> MutexGuard<'_, HashMap<String, FileRecord>> {
        self.files.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait::async_trait]
impl MetaStore for MemoryMetaStore {
    async fn put(&self, record: &FileRecord) -> anyhow::Result<()> {
        self.files().insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn get(&self, id: &str) -> anyhow::Result<Option<FileRecord>> {
        Ok(self.files().get(id).cloned())
    }

    async fn claim_download(&self, id: &str) -> anyhow::Result<Claim> {
        let mut files = self.files();
        let Some(record) = files.get_mut(id) else {
            return Ok(Claim::NotFound);
        };
        if record.downloads >= record.max_downloads {
            return Ok(Claim::Exhausted);
        }
        record.downloads += 1;
        let remaining = record.max_downloads - record.downloads;
        Ok(Claim::Granted {
            remaining,
            last: remaining == 0,
        })
    }

    async fn set_auth(
        &self,
        id: &str,
        auth_hash: &str,
        auth_salt: Option<&str>,
    ) -> anyhow::Result<bool> {
        let mut files = self.files();
        let Some(record) = files.get_mut(id) else {
            return Ok(false);
        };
        record.auth_hash = auth_hash.to_string();
        record.auth_salt = auth_salt.map(str::to_string);
        Ok(true)
    }

    async fn delete(&self, id: &str) -> anyhow::Result<()> {
        self.files().remove(id);
        Ok(())
    }

    async fn expired(&self, now: u64, limit: usize) -> anyhow::Result<Vec<String>> {
        let files = self.files();
        Ok(files
            .values()
            .filter(|record| record.expires_at <= now)
            .take(limit)
            .map(|record| record.id.clone())
            .collect())
    }

    async fn health(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
