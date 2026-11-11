pub mod gcra;
pub mod sliding_window;
pub mod token_bucket;

use crate::{policy::Policy, Decision};

/// Every rate-limiting algorithm implements this trait.
/// Stateless — all mutable state lives in the `Store`.
pub trait Algorithm: Send + Sync + 'static {
    /// The per-key state this algorithm needs persisted.
    type State: Send + Sync + Clone + 'static;

    /// Compute the *next* state given the current state (or `None` for a new key) and now.
    fn next_state(&self, current: Option<&Self::State>, now_ms: u64) -> Self::State;

    /// Given an *already-updated* state, produce the allow/deny decision.
    fn decide(&self, state: &Self::State, now_ms: u64) -> Decision;

    /// Return the policy driving this algorithm (for headers, fail-closed fallback).
    fn policy(&self) -> &Policy;
}
