pub mod memory;

#[cfg(feature = "redis")]
pub mod redis;

#[cfg(feature = "redis")]
pub mod redis_pool;

#[cfg(feature = "redis")]
pub mod two_tier;

use crate::error::RateLimitError;
use std::future::Future;

/// Pluggable state store. Decoupled from algorithms — swap in-memory for Redis
/// without touching a single line of algorithm code.
pub trait Store: Send + Sync + 'static {
    type State: Send + Sync + Clone + 'static;

    /// Atomically fetch-and-update the state for `key`.
    ///
    /// `update_fn` receives the current state (or `None` for a new key) and
    /// returns the new state.  The store guarantees the read-modify-write is
    /// atomic (CAS for memory, Lua EVALSHA for Redis).
    fn fetch_and_update<'a, F>(
        &'a self,
        key: &'a [u8],
        update_fn: F,
        now_ms: u64,
    ) -> impl Future<Output = Result<Self::State, RateLimitError>> + Send + 'a
    where
        F: FnOnce(Option<&Self::State>) -> Self::State + Send + 'a;
}
