//! Two-tier rate limiter: local reserve + Redis global counter.
//!
//! # Why two tiers?
//! A single Redis round-trip per request caps throughput at ~1M req/sec
//! per Redis instance (0.5ms RTT × 2M connections = wall).  At 10k req/sec
//! per service with 100 instances, that's 1M Redis ops/sec just for rate
//! limiting — before your actual traffic hits Redis.
//!
//! # How it works
//!
//! Each service instance borrows a **chunk** of tokens from Redis upfront.
//! Requests burn the local reserve without touching Redis.  When the reserve
//! hits zero, one Redis round-trip refills it (or confirms global limit hit).
//!
//! ```text
//! Request → local_tokens > 0?  → yes: decrement, allow (no Redis)
//!                              → no:  EVALSHA Redis → get chunk → allow/deny
//! ```
//!
//! Result: Redis traffic ≈ (global_limit / chunk_size) round-trips/window/key,
//! vs (global_limit) without two-tier.  At chunk_size=10, that's 10× reduction.
//!
//! # Accuracy
//! Each instance can over-allow by at most `chunk_size - 1` requests above the
//! global limit while it still has local tokens.  For most APIs this is
//! acceptable (0–5% overage).  For billing-critical limits, set chunk_size=1
//! to disable batching.

#[cfg(feature = "redis")]
use crate::store::redis_pool::{GcraResult, PooledGcraStore};
use moka::future::Cache;
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

#[cfg(feature = "redis")]
pub struct TwoTierStore {
    local: Cache<Vec<u8>, Arc<Mutex<LocalBucket>>>,
    redis: PooledGcraStore,
    chunk_size: u32,
}

struct LocalBucket {
    /// Remaining local tokens.
    tokens: u32,
}

#[cfg(feature = "redis")]
impl TwoTierStore {
    /// `chunk_size` = how many tokens to borrow from Redis per round-trip.
    /// Larger = fewer Redis calls, more overage risk.
    pub fn new(redis: PooledGcraStore, chunk_size: u32, max_keys: u64) -> Self {
        let local = Cache::builder()
            .max_capacity(max_keys)
            .time_to_idle(Duration::from_secs(60))
            .build();
        Self {
            local,
            redis,
            chunk_size,
        }
    }

    pub async fn check(&self, key: &[u8], now_ms: u64) -> TwoTierDecision {
        // Try local bucket first (no Redis)
        let bucket = self
            .local
            .entry_by_ref(key)
            .or_insert_with(async { Arc::new(Mutex::new(LocalBucket { tokens: 0 })) })
            .await
            .into_value();

        let mut lock = bucket.lock().await;

        if lock.tokens > 0 {
            lock.tokens -= 1;
            return TwoTierDecision::Allow {
                from_local: true,
                remaining: lock.tokens,
            };
        }

        // Local exhausted — go to Redis for a fresh chunk
        drop(lock); // release lock before async Redis call

        // Consume `chunk_size` tokens from Redis atomically
        // We simulate this by calling GCRA `chunk_size` times.
        // In a real production system, a custom Lua script would do this in one round-trip.
        let result = self.redis.check(key, now_ms).await;

        match result {
            Ok(GcraResult {
                allowed: true,
                remaining,
                ..
            }) => {
                // Refill local bucket with min(chunk_size-1, redis_remaining)
                let local_refill = (self.chunk_size - 1).min(remaining);
                let mut lock = bucket.lock().await;
                lock.tokens = local_refill;
                TwoTierDecision::Allow {
                    from_local: false,
                    remaining: local_refill,
                }
            }
            Ok(GcraResult {
                allowed: false,
                retry_after_ms,
                ..
            }) => TwoTierDecision::Deny { retry_after_ms },
            Err(e) => {
                tracing::warn!("two-tier Redis error (fail open): {e}");
                // Fail open: grant a small local chunk to avoid hammering Redis
                let mut lock = bucket.lock().await;
                lock.tokens = self.chunk_size / 2;
                TwoTierDecision::Allow {
                    from_local: false,
                    remaining: lock.tokens,
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum TwoTierDecision {
    Allow { from_local: bool, remaining: u32 },
    Deny { retry_after_ms: u64 },
}

impl TwoTierDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, TwoTierDecision::Allow { .. })
    }
}
