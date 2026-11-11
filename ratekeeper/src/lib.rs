//! # ratekeeper
//!
//! World-class rate limiting for Rust.
//!
//! ## Algorithms
//! - **GCRA** — one `u64` per key, lock-free CAS, mathematically equivalent to token bucket.
//!   Best for high-throughput global limits. Smooth, no boundary spikes.
//! - **Token Bucket** — explicit burst capacity + refill rate. Best for per-user/per-key limits
//!   where short bursts are acceptable.
//! - **Sliding Window Counter** — two counters + weighted sum. Best for strict "X per minute"
//!   billing-grade enforcement with no boundary spike.
//!
//! ## Storage backends
//! - **In-memory** (`moka` LRU + TTL, `DashMap` sharded) — sub-microsecond hot path.
//! - **Redis** (Lua scripts, `EVALSHA`, atomic; `deadpool-redis` async pool) — distributed.
//!
//! ## Middleware
//! - **Tower `Layer`** — works with Axum, Tonic, Hyper.
//! - Pluggable `KeyExtractor` (IP, header, JWT claim, custom).
//! - Automatic `X-RateLimit-*` and `Retry-After` headers.
//!
//! ## Failure modes
//! - `FailBehavior::Open`     — allow all when store is unreachable.
//! - `FailBehavior::Closed`   — deny all when store is unreachable.
//! - `FailBehavior::Fallback` — drop to in-memory limiter with tighter quota.

pub mod adaptive;
pub mod admin;
pub mod algorithms;
pub mod clock;
pub mod core_nostd;
pub mod error;
pub mod hierarchical;
pub mod idempotency;
pub mod metrics;
pub mod observe;
pub mod policy;
pub mod store;
pub mod weighted;

#[cfg(feature = "tower-layer")]
pub mod middleware;

pub use algorithms::{gcra::Gcra, sliding_window::SlidingWindow, token_bucket::TokenBucket};
pub use clock::{Clock, SystemClock};
pub use error::RateLimitError;
pub use policy::Policy;
pub use store::Store;

use std::sync::Arc;

// ── Decision ────────────────────────────────────────────────────────────────

/// The outcome of a rate-limit check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Request is allowed.
    Allow {
        /// Remaining tokens/slots in the current window.
        remaining: u32,
        /// When the current window fully resets (absolute epoch-ms).
        reset_at_ms: u64,
    },
    /// Request is denied.
    Deny {
        /// How long the caller must wait before retrying (ms).
        retry_after_ms: u64,
        /// The limit that was exceeded.
        limit: u32,
    },
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }
}

// ── FailBehavior ─────────────────────────────────────────────────────────────

/// What to do when the backing store (e.g. Redis) is unavailable.
#[derive(Clone, Debug, Default)]
pub enum FailBehavior {
    /// Allow all requests — safest for revenue-critical paths.
    #[default]
    Open,
    /// Deny all requests — safest for security-critical paths.
    Closed,
}

// ── RateLimiter ──────────────────────────────────────────────────────────────

/// Composable rate limiter: `Algorithm + Store + Clock`.
///
/// Cheap to clone — wraps everything in `Arc`.
#[derive(Clone)]
pub struct RateLimiter<A, S, C = SystemClock> {
    pub(crate) algorithm: Arc<A>,
    pub(crate) store: Arc<S>,
    pub(crate) clock: C,
    pub(crate) fail_behavior: FailBehavior,
}

impl<A, S, C> RateLimiter<A, S, C>
where
    A: algorithms::Algorithm,
    S: Store<State = A::State>,
    C: Clock,
{
    pub fn new(algorithm: A, store: S, clock: C) -> Self {
        Self {
            algorithm: Arc::new(algorithm),
            store: Arc::new(store),
            clock,
            fail_behavior: FailBehavior::Open,
        }
    }

    pub fn with_fail_behavior(mut self, fb: FailBehavior) -> Self {
        self.fail_behavior = fb;
        self
    }

    /// Check (and update) the rate limit for `key`.
    pub async fn check<K>(&self, key: K) -> Decision
    where
        K: AsRef<[u8]> + Send + Sync,
    {
        let now_ms = self.clock.now_ms();
        let alg = Arc::clone(&self.algorithm);

        let result = self
            .store
            .fetch_and_update(key.as_ref(), |state| alg.next_state(state, now_ms), now_ms)
            .await;

        match result {
            Ok(state) => self.algorithm.decide(&state, now_ms),
            Err(e) => {
                tracing::warn!("rate-limit store error: {e}");
                match self.fail_behavior {
                    FailBehavior::Open => Decision::Allow {
                        remaining: 0,
                        reset_at_ms: 0,
                    },
                    FailBehavior::Closed => {
                        let policy = self.algorithm.policy();
                        Decision::Deny {
                            retry_after_ms: 1_000,
                            limit: policy.limit,
                        }
                    }
                }
            }
        }
    }
}
