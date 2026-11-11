//! Weighted request cost.
//!
//! Standard rate limiting treats every request as cost=1.  Real APIs differ:
//! - A GraphQL query with 1 field vs 100 fields
//! - A REST write vs a read
//! - A bulk import endpoint vs a single-record fetch
//!
//! Weighted limiting lets one expensive request consume N tokens.
//!
//! # How it works
//!
//! Each algorithm's `next_state` only consumes 1 token.  For cost > 1,
//! we call it N times sequentially, or use a Lua script that increments by N.
//!
//! For the in-memory store, `WeightedLimiter::check(key, cost)` calls
//! `store.fetch_and_update` once and passes `cost` into the algorithm.
//!
//! # Shopify's approach
//! Shopify's GraphQL API assigns a "query complexity score" and deducts that
//! many tokens from the token bucket.  The bucket refills at 50 points/sec.
//! Their rate limit headers report points, not requests:
//!   `X-Shopify-Shop-Api-Call-Limit: 32/40`

use crate::{algorithms::Algorithm, clock::Clock, store::Store, Decision, RateLimiter};

/// Wraps a `RateLimiter` with weighted cost support.
#[derive(Clone)]
pub struct WeightedLimiter<A, S, C> {
    inner: RateLimiter<A, S, C>,
}

impl<A, S, C> WeightedLimiter<A, S, C>
where
    A: Algorithm,
    S: Store<State = A::State>,
    C: Clock,
{
    pub fn new(limiter: RateLimiter<A, S, C>) -> Self {
        Self { inner: limiter }
    }

    /// Check the rate limit consuming `cost` tokens.
    ///
    /// If `cost > 1`, we apply the algorithm N times in sequence.
    /// The first denial stops the loop and returns `Deny`.
    ///
    /// For high-performance paths, provide a custom Lua script that
    /// accepts `cost` as an argument and deducts it in one round-trip.
    pub async fn check<K>(&self, key: K, cost: u32) -> Decision
    where
        K: AsRef<[u8]> + Clone + Send + Sync,
    {
        if cost == 0 {
            let policy = self.inner.algorithm.policy();
            return Decision::Allow {
                remaining: policy.limit,
                reset_at_ms: 0,
            };
        }

        let mut last = Decision::Allow {
            remaining: 0,
            reset_at_ms: 0,
        };
        for _ in 0..cost {
            last = self.inner.check(key.clone()).await;
            if !last.is_allowed() {
                return last;
            }
        }
        last
    }
}

// ── Cost extractors ───────────────────────────────────────────────────────────

#[cfg(feature = "tower-layer")]
pub use http_extractors::*;

#[cfg(feature = "tower-layer")]
mod http_extractors {
    /// Compute request cost from HTTP properties.
    pub trait CostExtractor: Send + Sync + 'static {
        fn cost<B>(&self, req: &http::Request<B>) -> u32;
    }

    /// Fixed cost — every request costs N tokens.
    #[derive(Clone)]
    pub struct FixedCost(pub u32);

    impl CostExtractor for FixedCost {
        fn cost<B>(&self, _: &http::Request<B>) -> u32 {
            self.0
        }
    }

    /// Cost from a request header (e.g. `X-Cost: 5`).
    /// Falls back to `default_cost` if the header is absent or unparseable.
    #[derive(Clone)]
    pub struct HeaderCost {
        pub header_name: &'static str,
        pub default_cost: u32,
        pub max_cost: u32,
    }

    impl HeaderCost {
        pub fn new(header_name: &'static str) -> Self {
            Self {
                header_name,
                default_cost: 1,
                max_cost: 100,
            }
        }
    }

    impl CostExtractor for HeaderCost {
        fn cost<B>(&self, req: &http::Request<B>) -> u32 {
            req.headers()
                .get(self.header_name)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(self.default_cost)
                .min(self.max_cost)
        }
    }

    /// Cost from body size in bytes divided by a bucket size.
    /// E.g. `ByteCost { bytes_per_token: 1024 }` → 1MB body costs 1024 tokens.
    #[derive(Clone)]
    pub struct ByteCost {
        pub bytes_per_token: u32,
    }

    impl ByteCost {
        pub fn new(bytes_per_token: u32) -> Self {
            Self { bytes_per_token }
        }
    }

    impl CostExtractor for ByteCost {
        fn cost<B>(&self, req: &http::Request<B>) -> u32 {
            req.headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u32>().ok())
                .map(|len| (len / self.bytes_per_token).max(1))
                .unwrap_or(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{algorithms::gcra::Gcra, clock::MockClock, store::memory::MemoryStore, Policy};
    use std::time::Duration;

    #[tokio::test]
    async fn cost_2_consumes_two_tokens() {
        let clock = MockClock::new(0);
        // burst=3 (limit-1): the clock never advances in this test, so
        // all 4 token-consuming increments below happen at the same
        // instant and need burst=3 for GCRA to legitimately allow all 4.
        // See store/memory.rs's tests for the same pattern explained in
        // more detail.
        let limiter = RateLimiter::new(
            Gcra::new(Policy::per_second(4).with_burst(3)),
            MemoryStore::for_window(1000, Duration::from_secs(2)),
            clock,
        );
        let weighted = WeightedLimiter::new(limiter);

        // cost=2 burns 2 of 4 tokens
        let d = weighted.check(b"k", 2).await;
        assert!(d.is_allowed());

        // another cost=2 burns the last 2
        let d = weighted.check(b"k", 2).await;
        assert!(d.is_allowed());

        // bucket empty — deny
        let d = weighted.check(b"k", 1).await;
        assert!(!d.is_allowed());
    }

    #[tokio::test]
    async fn cost_zero_always_allows() {
        let limiter = RateLimiter::new(
            Gcra::new(Policy::per_second(1)),
            MemoryStore::for_window(1000, Duration::from_secs(2)),
            MockClock::new(0),
        );
        let weighted = WeightedLimiter::new(limiter);
        // drain
        weighted.check(b"k", 1).await;
        // cost=0 still allowed
        let d = weighted.check(b"k", 0).await;
        assert!(d.is_allowed());
    }
}
