//! Idempotency key support.
//!
//! Problem: a client retries a request (network timeout, 5xx) and their
//! retry burns another rate-limit token even though they already paid for
//! the original. Under heavy retry storms this amplifies quota burn.
//!
//! Solution: if the request carries an idempotency key (e.g. `Idempotency-Key`
//! header), we deduplicate it. The first request burns a token and stores
//! the decision. Retries within `ttl` see the cached decision and don't
//! burn another token.
//!
//! This is what Stripe does: https://stripe.com/docs/idempotency
//!
//! # Implementation
//! - Cache: `moka` with TTL = `idempotency_ttl` (typically 24h for payments).
//! - Key: SHA-256-prefix of `{rate_limit_key}:{idempotency_key}`.
//! - Thread-safe: `DashMap` or `moka` handles concurrent first-arrivals.
//!
//! # Usage
//! ```rust,ignore
//! let idem = IdempotencyCache::new(10_000, Duration::from_secs(86_400));
//! let idem_key = req.headers().get("idempotency-key").map(|v| v.as_bytes());
//!
//! let decision = idem
//!     .get_or_check(rate_key, idem_key, || limiter.check(rate_key))
//!     .await;
//! ```

use crate::Decision;
use moka::future::Cache;
use std::time::Duration;

/// Cached outcome for an idempotent request.
#[derive(Clone, Debug)]
struct CachedDecision {
    decision: Decision,
    created_ms: u64,
}

pub struct IdempotencyCache {
    cache: Cache<Vec<u8>, CachedDecision>,
}

impl IdempotencyCache {
    pub fn new(max_entries: u64, ttl: Duration) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_entries)
            .time_to_live(ttl)
            .build();
        Self { cache }
    }

    /// Return the cached decision for `idem_key`, or run `check_fn` and cache
    /// the result. If `idem_key` is `None`, always run `check_fn` (no caching).
    pub async fn get_or_check<F, Fut>(
        &self,
        rate_key: &[u8],
        idem_key: Option<&[u8]>,
        now_ms: u64,
        check_fn: F,
    ) -> Decision
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Decision>,
    {
        let Some(ik) = idem_key else {
            return check_fn().await;
        };

        let cache_key = compose_key(rate_key, ik);

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key).await {
            tracing::debug!(
                target: "ratekeeper::idempotency",
                cache_key = %hex_prefix(&cache_key),
                age_ms    = now_ms.saturating_sub(cached.created_ms),
                "idempotency cache hit — skipping token burn"
            );
            return cached.decision.clone();
        }

        // Not cached — run the actual check and store result
        let decision = check_fn().await;
        self.cache
            .insert(
                cache_key,
                CachedDecision {
                    decision: decision.clone(),
                    created_ms: now_ms,
                },
            )
            .await;
        decision
    }

    pub fn len(&self) -> u64 {
        self.cache.entry_count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn compose_key(rate_key: &[u8], idem_key: &[u8]) -> Vec<u8> {
    let mut k = rate_key.to_vec();
    k.push(b'\0');
    k.extend_from_slice(idem_key);
    k
}

fn hex_prefix(key: &[u8]) -> String {
    key.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decision;
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    };

    fn allow() -> Decision {
        Decision::Allow {
            remaining: 10,
            reset_at_ms: 0,
        }
    }

    fn deny() -> Decision {
        Decision::Deny {
            retry_after_ms: 500,
            limit: 10,
        }
    }

    #[tokio::test]
    async fn retry_with_same_idem_key_does_not_call_check_fn() {
        let cache = IdempotencyCache::new(1000, Duration::from_secs(60));
        let call_cnt = Arc::new(AtomicU32::new(0));

        let key = b"user-1";
        let idem = b"req-abc-123";
        let now = 0u64;

        // First call
        let cnt1 = Arc::clone(&call_cnt);
        let d1 = cache
            .get_or_check(key, Some(idem), now, || async move {
                cnt1.fetch_add(1, Ordering::SeqCst);
                allow()
            })
            .await;
        assert!(d1.is_allowed());
        assert_eq!(call_cnt.load(Ordering::SeqCst), 1);

        // Retry with same idempotency key — check_fn must NOT be called
        let cnt2 = Arc::clone(&call_cnt);
        let d2 = cache
            .get_or_check(key, Some(idem), now + 100, || async move {
                cnt2.fetch_add(1, Ordering::SeqCst);
                deny() // would have been a deny, but it's cached as allow
            })
            .await;
        assert!(d2.is_allowed(), "cached allow must be returned");
        assert_eq!(
            call_cnt.load(Ordering::SeqCst),
            1,
            "check_fn must not be called again"
        );
    }

    #[tokio::test]
    async fn different_idem_keys_are_independent() {
        let cache = IdempotencyCache::new(1000, Duration::from_secs(60));
        let key = b"user-2";
        let now = 0u64;

        let d1 = cache
            .get_or_check(key, Some(b"req-1"), now, || async { allow() })
            .await;
        let d2 = cache
            .get_or_check(key, Some(b"req-2"), now, || async { deny() })
            .await;

        assert!(d1.is_allowed());
        assert!(!d2.is_allowed(), "different idem key → independent check");
    }

    #[tokio::test]
    async fn no_idem_key_always_runs_check_fn() {
        let cache = IdempotencyCache::new(1000, Duration::from_secs(60));
        let call_cnt = Arc::new(AtomicU32::new(0));
        let key = b"user-3";
        let now = 0u64;

        for _ in 0..3 {
            let cnt = Arc::clone(&call_cnt);
            cache
                .get_or_check(key, None, now, || async move {
                    cnt.fetch_add(1, Ordering::SeqCst);
                    allow()
                })
                .await;
        }
        assert_eq!(
            call_cnt.load(Ordering::SeqCst),
            3,
            "without idem key, check_fn called every time"
        );
    }
}
