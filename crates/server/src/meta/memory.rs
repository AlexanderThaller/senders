//! Process-local metadata store. Useful for `cargo test` and for kicking the
//! tyres without a Redis around; unsuitable for more than one replica.

use super::{Claim, FileRecord, MetaStore};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
pub struct MemoryMetaStore {
    files: Mutex<HashMap<String, FileRecord>>,
}

#[async_trait::async_trait]
impl MetaStore for MemoryMetaStore {
    async fn put(&self, record: &FileRecord) -> anyhow::Result<()> {
        self.files
            .lock()
            .unwrap()
            .insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn get(&self, id: &str) -> anyhow::Result<Option<FileRecord>> {
        Ok(self.files.lock().unwrap().get(id).cloned())
    }

    async fn claim_download(&self, id: &str) -> anyhow::Result<Claim> {
        let mut files = self.files.lock().unwrap();
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
        let mut files = self.files.lock().unwrap();
        let Some(record) = files.get_mut(id) else {
            return Ok(false);
        };
        record.auth_hash = auth_hash.to_string();
        record.auth_salt = auth_salt.map(str::to_string);
        Ok(true)
    }

    async fn delete(&self, id: &str) -> anyhow::Result<()> {
        self.files.lock().unwrap().remove(id);
        Ok(())
    }

    async fn expired(&self, now: u64, limit: usize) -> anyhow::Result<Vec<String>> {
        let files = self.files.lock().unwrap();
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
