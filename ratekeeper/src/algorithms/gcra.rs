//! GCRA — Generic Cell Rate Algorithm.
//!
//! Stores a single `u64` (Theoretical Arrival Time, ms) per key.
//! Mathematically equivalent to a token bucket.  No floats, no divisions on
//! the hot path, one CAS-compatible value → trivially fits in a Redis string.
//!
//! # How it works
//!
//! Each request has a "cost" of `cell_ms = window_ms / limit`.
//! We track TAT: the soonest time the *next* request can arrive.
//!
//! ```text
//! new_tat  = max(TAT, now) + cell_ms
//! allow_at = new_tat - burst_offset          (burst_offset = cell_ms * burst)
//! allow if allow_at ≤ now
//! ```
//!
//! On allow:  store `new_tat`, return remaining ≈ (burst_offset − (new_tat − now)) / cell_ms
//! On deny:   return retry_after = allow_at − now

use crate::{algorithms::Algorithm, policy::Policy, Decision};

#[derive(Debug, Clone)]
pub struct GcraState {
    /// Theoretical Arrival Time (ms since epoch).
    pub tat: u64,
}

/// GCRA rate limiter.
#[derive(Debug, Clone)]
pub struct Gcra {
    policy: Policy,
    cell_ms: u64,
    burst_offset: u64, // cell_ms * (burst + 1)  — space above limit
}

impl Gcra {
    pub fn new(policy: Policy) -> Self {
        let cell_ms = policy.cell_ms().max(1);
        let burst_offset = cell_ms * (policy.burst as u64 + 1);
        Self {
            policy,
            cell_ms,
            burst_offset,
        }
    }
}

impl Algorithm for Gcra {
    type State = GcraState;

    fn next_state(&self, current: Option<&GcraState>, now_ms: u64) -> GcraState {
        let tat = current.map(|s| s.tat).unwrap_or(now_ms);
        let new_tat = tat.max(now_ms) + self.cell_ms;
        GcraState { tat: new_tat }
    }

    fn decide(&self, state: &GcraState, now_ms: u64) -> Decision {
        // allow_at is when the slot was available; we've already written new_tat.
        // new_tat = now + cell_ms, so allow_at = new_tat - burst_offset
        let new_tat = state.tat;
        let allow_at = new_tat.saturating_sub(self.burst_offset);

        if allow_at <= now_ms {
            // Remaining ≈ how many more cells fit before TAT catches up to burst limit
            let remaining =
                ((now_ms + self.burst_offset).saturating_sub(new_tat)) / self.cell_ms.max(1);
            Decision::Allow {
                remaining: remaining as u32,
                reset_at_ms: new_tat,
            }
        } else {
            Decision::Deny {
                retry_after_ms: allow_at - now_ms,
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

    fn gcra(limit: u32, window_secs: u64, burst: u32) -> Gcra {
        Gcra::new(Policy::new(limit, Duration::from_secs(window_secs)).with_burst(burst))
    }

    #[test]
    fn allows_up_to_limit() {
        let g = gcra(5, 1, 0);
        let mut now = 0u64;
        let cell_ms = 1000 / 5; // 200ms

        for _ in 0..5 {
            let state = g.next_state(None, now);
            assert!(g.decide(&state, now).is_allowed());
            now += cell_ms;
        }
    }

    #[test]
    fn denies_over_limit() {
        let g = gcra(2, 1, 0);
        // Fill two slots
        let s1 = g.next_state(None, 0);
        let s2 = g.next_state(Some(&s1), 0);
        let d = g.decide(&s2, 0);
        assert!(!d.is_allowed());
        if let Decision::Deny { retry_after_ms, .. } = d {
            assert!(retry_after_ms > 0);
        }
    }

    #[test]
    fn burst_allows_extra() {
        // 1 req/sec sustained, burst of 4 (so 5 total at t=0)
        let g = gcra(1, 1, 4);
        let mut state = None;
        let now = 0u64;

        let mut allowed = 0u32;
        for _ in 0..6 {
            let next = g.next_state(state.as_ref(), now);
            if g.decide(&next, now).is_allowed() {
                allowed += 1;
            }
            state = Some(next);
        }
        assert_eq!(allowed, 5, "burst of 4 + 1 base = 5 allowed at t=0");
    }

    #[test]
    fn refills_after_window() {
        let g = gcra(5, 1, 0);
        // consume all 5
        let mut state = None;
        let mut now = 0u64;
        for _ in 0..5 {
            let next = g.next_state(state.as_ref(), now);
            state = Some(next);
            now += 200;
        }
        // 1 second later — should be allowed again
        now += 1_000;
        let next = g.next_state(state.as_ref(), now);
        assert!(g.decide(&next, now).is_allowed());
    }
}
