//! Sliding Window Counter.
//!
//! Fixes the fixed-window boundary problem with a weighted two-counter approach:
//!
//! ```text
//! effective_count = prev_count × (1 − elapsed_fraction) + curr_count
//! ```
//!
//! This approximates a true rolling window and overestimates by at most
//! 1 request per window (Cloudflare validated 0.003% error at 400M req).
//! Memory: O(1) — just two counters and a timestamp.
//!
//! Best for: strict API quotas, billing-grade enforcement.

use crate::{algorithms::Algorithm, policy::Policy, Decision};

#[derive(Debug, Clone)]
pub struct SlidingWindowState {
    pub prev_count: u32,
    pub curr_count: u32,
    pub window_start_ms: u64,
}

#[derive(Debug, Clone)]
pub struct SlidingWindow {
    policy: Policy,
}

impl SlidingWindow {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    fn effective_count(&self, state: &SlidingWindowState, now_ms: u64) -> f64 {
        let window_ms = self.policy.window_ms() as f64;
        let elapsed = (now_ms - state.window_start_ms) as f64;
        let elapsed_frac = (elapsed % window_ms) / window_ms;
        // Weight of the previous window that is still "in" the sliding window
        let prev_weight = 1.0 - elapsed_frac;
        state.prev_count as f64 * prev_weight + state.curr_count as f64
    }

    fn current_window_start(&self, now_ms: u64) -> u64 {
        let w = self.policy.window_ms();
        (now_ms / w) * w
    }
}

impl Algorithm for SlidingWindow {
    type State = SlidingWindowState;

    fn next_state(&self, current: Option<&SlidingWindowState>, now_ms: u64) -> SlidingWindowState {
        let window_start = self.current_window_start(now_ms);
        let window_ms = self.policy.window_ms();

        match current {
            None => SlidingWindowState {
                prev_count: 0,
                curr_count: 1,
                window_start_ms: window_start,
            },
            Some(s) => {
                let age = now_ms.saturating_sub(s.window_start_ms);

                if age < window_ms {
                    // Still in the same window
                    SlidingWindowState {
                        prev_count: s.prev_count,
                        curr_count: s.curr_count + 1,
                        window_start_ms: s.window_start_ms,
                    }
                } else if age < 2 * window_ms {
                    // Rolled into the next window
                    SlidingWindowState {
                        prev_count: s.curr_count,
                        curr_count: 1,
                        window_start_ms: window_start,
                    }
                } else {
                    // Two or more windows have passed — full reset
                    SlidingWindowState {
                        prev_count: 0,
                        curr_count: 1,
                        window_start_ms: window_start,
                    }
                }
            }
        }
    }

    fn decide(&self, state: &SlidingWindowState, now_ms: u64) -> Decision {
        let limit = self.policy.limit as f64;
        let eff = self.effective_count(state, now_ms);

        if eff <= limit {
            let remaining = (limit - eff).floor() as u32;
            let reset_at_ms = state.window_start_ms + self.policy.window_ms();
            Decision::Allow {
                remaining,
                reset_at_ms,
            }
        } else {
            // Time until the prev_count contribution decays enough to allow
            let window_ms = self.policy.window_ms() as f64;
            let needed_decay = eff - limit; // how many "prev" units need to decay
            let decay_frac = needed_decay / state.prev_count.max(1) as f64;
            let wait_ms = (decay_frac * window_ms).ceil() as u64;
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

    fn sw(limit: u32, window_secs: u64) -> SlidingWindow {
        SlidingWindow::new(Policy::new(limit, Duration::from_secs(window_secs)))
    }

    #[test]
    fn allows_up_to_limit_in_window() {
        let s = sw(5, 1);
        let mut state = None;
        let now = 0u64;

        for _ in 0..5 {
            let next = s.next_state(state.as_ref(), now);
            assert!(s.decide(&next, now).is_allowed());
            state = Some(next);
        }
        // 6th should be denied
        let next = s.next_state(state.as_ref(), now);
        assert!(!s.decide(&next, now).is_allowed());
    }

    #[test]
    fn no_boundary_spike() {
        // Classic fixed-window attack: 5 at t=990ms, 5 at t=1010ms
        // A fixed window would allow 10 total. Sliding window should deny.
        let s = sw(5, 1); // 5 per second
        let mut state = None;

        // 5 requests at the end of window 0
        for _ in 0..5 {
            let next = s.next_state(state.as_ref(), 990);
            state = Some(next);
        }
        // Try 5 more at the start of window 1
        let next = s.next_state(state.as_ref(), 1_010);
        assert!(
            !s.decide(&next, 1_010).is_allowed(),
            "sliding window must deny: 990ms overlap means prev window still has weight"
        );
    }

    #[test]
    fn resets_after_two_windows() {
        let s = sw(3, 1);
        let mut state = None;
        for _ in 0..3 {
            let next = s.next_state(state.as_ref(), 0);
            state = Some(next);
        }
        // 2 full windows later
        let next = s.next_state(state.as_ref(), 2_001);
        assert!(s.decide(&next, 2_001).is_allowed());
    }
}
