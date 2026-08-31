//! Background expiry sweep.
//!
//! Metadata carries a Redis TTL as a safety net, but only this task also
//! removes the ciphertext, so it is what actually enforces "gone after N days".

use crate::state::AppState;
use crate::util;
use std::time::Duration;

/// Ids handled per sweep. Bounded so a large backlog is worked through over
/// several ticks instead of stalling one long transaction.
const BATCH: usize = 256;

/// Sweep for expired files until `shutdown` fires.
///
/// This is the only path that deletes ciphertext as well as metadata, so it is
/// what actually enforces "gone after N days".
pub async fn run(
    state: AppState,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(err) = sweep(&state).await {
                    tracing::error!(error = ?err, "expiry sweep failed");
                }
            }
            _ = shutdown.changed() => {
                tracing::debug!("reaper shutting down");
                return;
            }
        }
    }
}

async fn sweep(state: &AppState) -> anyhow::Result<()> {
    let expired = state.meta.expired(util::now(), BATCH).await?;
    if expired.is_empty() {
        return Ok(());
    }
    let mut removed = 0usize;
    for id in &expired {
        match state.destroy(id).await {
            Ok(()) => removed += 1,
            // Leave the record in place so the next sweep retries; dropping it
            // here would orphan the ciphertext forever.
            Err(err) => tracing::warn!(%id, error = ?err, "could not reap an expired file"),
        }
    }
    tracing::info!(removed, considered = expired.len(), "reaped expired files");
    Ok(())
}
