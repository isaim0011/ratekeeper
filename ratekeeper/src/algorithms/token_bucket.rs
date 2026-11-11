//! Token Bucket algorithm.
//!
//! State: `{ tokens: f64, last_refill_ms: u64 }`
//! Refill rate: `policy.limit` tokens per `policy.window`.
//! Capacity (max burst): `policy.limit + policy.burst`.
//!
//! Explicit burst capacity makes this more intuitive to tune than GCRA
//! for per-user API keys where short spikes are acceptable.

use crate::{algorithms::Algorithm, policy::Policy, Decision};

#[derive(Debug, Clone)]
pub struct TokenBucketState {
    /// Available tokens (fractional for sub-second accuracy).
    pub tokens: f64,
    pub last_refill_ms: u64,
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    policy: Policy,
    capacity: f64,      // limit + burst
    refill_per_ms: f64, // tokens added per millisecond
}

impl TokenBucket {
    pub fn new(policy: Policy) -> Self {
        let capacity = (policy.limit + policy.burst) as f64;
        let refill_per_ms = policy.limit as f64 / policy.window_ms() as f64;
        Self {
            policy,
            capacity,
            refill_per_ms,
        }
    }

    fn refill(&self, state: &TokenBucketState, now_ms: u64) -> f64 {
        let elapsed = now_ms.saturating_sub(state.last_refill_ms) as f64;
        let refilled = state.tokens + elapsed * self.refill_per_ms;
        refilled.min(self.capacity)
    }
}

impl Algorithm for TokenBucket {
    type State = TokenBucketState;

    fn next_state(&self, current: Option<&TokenBucketState>, now_ms: u64) -> TokenBucketState {
        let tokens = match current {
            None => self.capacity - 1.0, // first request: full bucket minus one
            Some(s) => {
                let after_refill = self.refill(s, now_ms);
                (after_refill - 1.0).max(-1.0) // consume one token (allow -1 to signal deny)
            }
        };
        TokenBucketState {
            tokens,
            last_refill_ms: now_ms,
        }
    }

    fn decide(&self, state: &TokenBucketState, _now_ms: u64) -> Decision {
        if state.tokens >= 0.0 {
            Decision::Allow {
                remaining: state.tokens.floor() as u32,
                reset_at_ms: 0, // TB doesn't have a hard reset, continuous refill
            }
        } else {
            // tokens == -1.0 means we needed 1 more than available
            let wait_ms = (1.0 / self.refill_per_ms).ceil() as u64;
            Decision::Deny {
                retry_after_ms: wait_ms,
                limit: self.policy.limit,
            }
        }
    }

    fn policy(&self) -> &Policy {
        &self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn tb(limit: u32, window_secs: u64, burst: u32) -> TokenBucket {
        TokenBucket::new(Policy::new(limit, Duration::from_secs(window_secs)).with_burst(burst))
    }

    #[test]
    fn allows_full_bucket_on_first_request() {
        let t = tb(10, 1, 0);
        let s = t.next_state(None, 0);
        assert!(t.decide(&s, 0).is_allowed());
        assert_eq!(s.tokens.floor() as u32, 9); // 10 capacity - 1 consumed
    }

    #[test]
    fn denies_when_empty() {
        let t = tb(2, 1, 0);
        let mut state = None;
        let now = 0u64;
        for _ in 0..2 {
            let next = t.next_state(state.as_ref(), now);
            state = Some(next);
        }
        // 3rd request at same timestamp
        let next = t.next_state(state.as_ref(), now);
        assert!(!t.decide(&next, now).is_allowed());
    }

    #[test]
    fn refills_over_time() {
        let t = tb(10, 1, 0); // 10/sec = 1 token per 100ms
                              // drain fully
        let mut state = None;
        for _ in 0..10 {
            let next = t.next_state(state.as_ref(), 0);
            state = Some(next);
        }
        // after 500ms, should have ~5 tokens back
        let next = t.next_state(state.as_ref(), 500);
        assert!(t.decide(&next, 500).is_allowed());
        if let Decision::Allow { remaining, .. } = t.decide(&next, 500) {
            assert!(remaining >= 3, "expected ~4 remaining, got {remaining}");
        }
    }

    #[test]
    fn burst_increases_capacity() {
        let t = tb(5, 1, 5); // capacity = 10
        let s = t.next_state(None, 0);
        assert_eq!(s.tokens.floor() as u32, 9); // 10 - 1
    }
}
