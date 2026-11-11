//! In-memory store backed by `moka::future::Cache`.
//!
//! # Design
//! - `moka` provides sharded, lock-free LRU + TTL eviction — keys that stop
//!   arriving are automatically reclaimed without a background sweep task.
//! - Per-entry `tokio::sync::Mutex<State>` gives us an atomic read-modify-write
//!   without a global lock.  Contention is per-key, not per-shard.
//! - Hot path: one `Arc` deref + one async mutex lock.  No allocations after
//!   the first insertion for a given key.

use crate::{error::RateLimitError, store::Store};
use moka::future::Cache;
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

type Entry<S> = Arc<Mutex<S>>;

pub struct MemoryStore<S: Send + Sync + Clone + 'static> {
    cache: Cache<Vec<u8>, Entry<S>>,
    #[allow(dead_code)]
    ttl: Duration,
}

impl<S: Send + Sync + Clone + 'static> MemoryStore<S> {
    /// Create a store with `max_capacity` entries and per-entry `ttl`.
    ///
    /// A TTL of `2 × window` is a safe default: a key that is never touched
    /// again expires within two windows, keeping memory bounded.
    pub fn new(max_capacity: u64, ttl: Duration) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_idle(ttl)
            .build();
        Self { cache, ttl }
    }

    /// Convenience constructor using policy window to set TTL.
    pub fn for_window(max_capacity: u64, window: Duration) -> Self {
        Self::new(max_capacity, window * 2)
    }
}

impl<S> Store for MemoryStore<S>
where
    S: Send + Sync + Clone + 'static,
{
    type State = S;

    async fn fetch_and_update<'a, F>(
        &'a self,
        key: &'a [u8],
        update_fn: F,
        _now_ms: u64,
    ) -> Result<S, RateLimitError>
    where
        F: FnOnce(Option<&S>) -> S + Send + 'a,
    {
        // Fast path: entry already exists
        if let Some(entry) = self.cache.get(key).await {
            let mut guard = entry.lock().await;
            let next = update_fn(Some(&*guard));
            *guard = next.clone();
            return Ok(next);
        }

        // Slow path: first request for this key
        // Insert a placeholder then lock it to avoid a TOCTOU with a concurrent
        // first request for the same key.
        let new_state = update_fn(None);
        let entry = Arc::new(Mutex::new(new_state));

        // `get_with` is atomic: if two tasks race, only one inserts.
        let entry = self
            .cache
            .entry_by_ref(key)
            .or_insert_with(async { entry })
            .await
            .into_value();

        // We may have lost the race; re-read to ensure consistency.
        let guard = entry.lock().await;
        Ok(guard.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        algorithms::{gcra::Gcra, Algorithm},
        policy::Policy,
    };

    #[tokio::test]
    async fn independent_keys_do_not_interfere() {
        let store = MemoryStore::for_window(1024, Duration::from_secs(1));
        // This test issues 5 requests back-to-back at the same instant
        // (no time advances between them), so the policy needs burst=4
        // (limit-1) for all 5 to be legitimately allowed under GCRA —
        // without it, standard GCRA only allows 1 instant request
        // (burst+1 with the default burst=0). The test's actual intent
        // is verifying that two keys' counters don't interfere with each
        // other, not testing GCRA pacing, so granting enough burst to
        // make "5 instant requests" a valid premise is the correct fix,
        // not a workaround.
        let gcra = Gcra::new(Policy::per_second(5).with_burst(4));

        for key in [b"user-1" as &[u8], b"user-2"] {
            for _ in 0..5 {
                let result = store
                    .fetch_and_update(key, |s| gcra.next_state(s, 0), 0)
                    .await
                    .unwrap();
                assert!(gcra.decide(&result, 0).is_allowed());
            }
        }
    }

    #[tokio::test]
    async fn same_key_counts_requests() {
        let store = MemoryStore::for_window(1024, Duration::from_secs(1));
        // See independent_keys_do_not_interfere's comment: burst=1
        // (limit-1) is needed so both of the first 2 (of 3) back-to-back
        // requests at t=0 are legitimately allowed under GCRA.
        let gcra = Gcra::new(Policy::per_second(2).with_burst(1));

        for i in 0..3u32 {
            let now = 0u64; // all at t=0
            let result = store
                .fetch_and_update(b"user-x", |s| gcra.next_state(s, now), now)
                .await
                .unwrap();
            let d = gcra.decide(&result, now);
            if i < 2 {
                assert!(d.is_allowed(), "request {i} should be allowed");
            } else {
                assert!(!d.is_allowed(), "request {i} should be denied");
            }
        }
    }
}
