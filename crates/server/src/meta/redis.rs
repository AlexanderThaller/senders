//! Redis-backed metadata store (via `fred`).
//!
//! This is what lets the service run as stateless pods: with `s3://` blob
//! storage and Redis metadata, a replica keeps nothing on local disk.
//!
//! Layout:
//!   `senders:f:{id}`  HASH  { rec: JSON, downloads: int, max_downloads: int }
//!   `senders:exp`     ZSET  member = id, score = expires_at
//!
//! Each hash also carries a Redis TTL as a backstop, so a reaper that never
//! runs still cannot leak metadata past its expiry.

use super::{Claim, FileRecord, MetaStore};
use anyhow::Context as _;
use fred::prelude::*;

fn file_key(id: &str) -> String {
    format!("senders:f:{id}")
}

const EXPIRY_ZSET: &str = "senders:exp";

/// Claim one download slot. Returns `{status, remaining}` where status is
/// -1 = missing, 0 = exhausted, 1 = granted. Running this as a script keeps
/// the check-and-increment atomic across replicas.
const CLAIM_SCRIPT: &str = r#"
local key = KEYS[1]
if redis.call('EXISTS', key) == 0 then
  return {-1, 0}
end
local max = tonumber(redis.call('HGET', key, 'max_downloads')) or 0
local used = tonumber(redis.call('HGET', key, 'downloads')) or 0
if used >= max then
  return {0, 0}
end
used = redis.call('HINCRBY', key, 'downloads', 1)
return {1, max - used}
"#;

pub struct RedisMetaStore {
    client: Client,
}

impl RedisMetaStore {
    pub async fn connect(uri: &str) -> anyhow::Result<Self> {
        let config = Config::from_url(uri).with_context(|| format!("invalid redis URI {uri:?}"))?;
        let client = Builder::from_config(config)
            .with_connection_config(|cfg| {
                cfg.connection_timeout = std::time::Duration::from_secs(10);
            })
            .build()
            .context("building the redis client")?;
        client.init().await.context("connecting to redis")?;
        Ok(Self { client })
    }

    /// The record JSON is the source of truth; `downloads` lives in its own
    /// field so the Lua claim script can increment it without parsing JSON.
    async fn load(&self, id: &str) -> anyhow::Result<Option<FileRecord>> {
        let key = file_key(id);
        let fields: Option<(Option<String>, Option<u32>)> = {
            let rec: Option<String> = self.client.hget(&key, "rec").await?;
            let downloads: Option<u32> = self.client.hget(&key, "downloads").await?;
            Some((rec, downloads))
        };
        let Some((Some(rec), downloads)) = fields else {
            return Ok(None);
        };
        let mut record: FileRecord =
            serde_json::from_str(&rec).context("decoding stored record")?;
        record.downloads = downloads.unwrap_or(record.downloads);
        Ok(Some(record))
    }
}

#[async_trait::async_trait]
impl MetaStore for RedisMetaStore {
    async fn put(&self, record: &FileRecord) -> anyhow::Result<()> {
        let key = file_key(&record.id);
        let json = serde_json::to_string(record)?;
        let ttl = record.expires_at.saturating_sub(crate::util::now()).max(1);

        self.client
            .hset::<(), _, _>(
                &key,
                vec![
                    ("rec", Value::from(json)),
                    ("downloads", Value::from(record.downloads)),
                    ("max_downloads", Value::from(record.max_downloads)),
                ],
            )
            .await?;
        // Grace period so the reaper, not the TTL, is normally what deletes a
        // record — the reaper is the only path that also removes the blob.
        self.client
            .expire::<(), _>(&key, (ttl + 3600) as i64, None)
            .await?;
        self.client
            .zadd::<(), _, _>(
                EXPIRY_ZSET,
                None,
                None,
                false,
                false,
                (record.expires_at as f64, record.id.as_str()),
            )
            .await?;
        Ok(())
    }

    async fn get(&self, id: &str) -> anyhow::Result<Option<FileRecord>> {
        self.load(id).await
    }

    async fn claim_download(&self, id: &str) -> anyhow::Result<Claim> {
        let result: (i64, i64) = self
            .client
            .eval(CLAIM_SCRIPT, vec![file_key(id)], ())
            .await
            .context("running the download-claim script")?;
        Ok(match result {
            (-1, _) => Claim::NotFound,
            (0, _) => Claim::Exhausted,
            (_, remaining) => Claim::Granted {
                remaining: remaining.max(0) as u32,
                last: remaining <= 0,
            },
        })
    }

    async fn set_auth(
        &self,
        id: &str,
        auth_hash: &str,
        auth_salt: Option<&str>,
    ) -> anyhow::Result<bool> {
        let Some(mut record) = self.load(id).await? else {
            return Ok(false);
        };
        record.auth_hash = auth_hash.to_string();
        record.auth_salt = auth_salt.map(str::to_string);
        let json = serde_json::to_string(&record)?;
        self.client
            .hset::<(), _, _>(file_key(id), ("rec", json))
            .await?;
        Ok(true)
    }

    async fn delete(&self, id: &str) -> anyhow::Result<()> {
        self.client.del::<(), _>(file_key(id)).await?;
        self.client.zrem::<(), _, _>(EXPIRY_ZSET, id).await?;
        Ok(())
    }

    async fn expired(&self, now: u64, limit: usize) -> anyhow::Result<Vec<String>> {
        let ids: Vec<String> = self
            .client
            .zrangebyscore(
                EXPIRY_ZSET,
                f64::NEG_INFINITY,
                now as f64,
                false,
                Some((0, limit as i64)),
            )
            .await?;
        Ok(ids)
    }

    async fn health(&self) -> anyhow::Result<()> {
        let _: String = self.client.ping(None).await?;
        Ok(())
    }
}
