//! `no_std` compatible algorithm core.
//!
//! The fundamental rate-limiting math has zero dependency on std, async, or
//! any allocator. This module re-exposes the three algorithms in a form that
//! compiles to `wasm32-unknown-unknown`, embedded targets, and C FFI.
//!
//! # What is included
//! - `GcraCore` — pure function, no state storage, no allocation.
//! - `TokenBucketCore` — pure function.
//! - `SlidingWindowCore` — pure function.
//!
//! # What is excluded
//! Stores, async, Tower, Redis, moka — all require std/tokio and live in the
//! parent modules.
//!
//! # WASM usage
//! ```toml
//! [dependencies]
//! ratekeeper = { version = "0.4", default-features = false, features = ["core"] }
//! ```
//!
//! ```rust
//! use ratekeeper::core_nostd::{GcraCore, GcraState, CoreDecision};
//!
//! let core  = GcraCore::new(100, 1_000); // 100 req / 1000ms
//! let state = GcraState::new();
//! let (next_state, decision) = core.check(state, 0 /* now_ms */);
//! assert!(decision.allowed);
//! ```

// ── GcraCore ──────────────────────────────────────────────────────────────────

/// Pure-function GCRA. All state is in `GcraState` — no heap, no locks.
#[derive(Debug, Clone, Copy)]
pub struct GcraCore {
    cell_ms: u64,
    burst_offset: u64,
    limit: u32,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct GcraState {
    /// Theoretical Arrival Time (ms since epoch). 0 = never used.
    pub tat: u64,
}

impl GcraState {
    pub const fn new() -> Self {
        Self { tat: 0 }
    }
}

/// Decision returned by no-std core functions.
#[derive(Debug, Clone, Copy)]
pub struct CoreDecision {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after_ms: u64,
    pub reset_at_ms: u64,
}

impl CoreDecision {
    const fn allow(remaining: u32, reset_at_ms: u64) -> Self {
        Self {
            allowed: true,
            remaining,
            retry_after_ms: 0,
            reset_at_ms,
        }
    }
    const fn deny(retry_after_ms: u64, _limit: u32) -> Self {
        Self {
            allowed: false,
            remaining: 0,
            retry_after_ms,
            reset_at_ms: 0,
        }
    }
}

impl GcraCore {
    /// `limit` req per `window_ms` milliseconds, with `burst` extra tokens.
    pub const fn new(limit: u32, window_ms: u64) -> Self {
        Self::with_burst(limit, window_ms, 0)
    }

    pub const fn with_burst(limit: u32, window_ms: u64, burst: u32) -> Self {
        let cell_ms = if limit == 0 {
            1
        } else {
            window_ms / limit as u64
        };
        let burst_offset = cell_ms * (burst as u64 + 1);
        Self {
            cell_ms,
            burst_offset,
            limit,
        }
    }

    /// Pure check-and-update. Returns (new_state, decision).
    /// Call site is responsible for storing `new_state`.
    #[inline]
    pub const fn check(&self, state: GcraState, now_ms: u64) -> (GcraState, CoreDecision) {
        let tat = if state.tat == 0 { now_ms } else { state.tat };
        let new_tat = if tat > now_ms {
            tat + self.cell_ms
        } else {
            now_ms + self.cell_ms
        };
        let allow_at = new_tat.saturating_sub(self.burst_offset);

        let new_state = GcraState { tat: new_tat };

        if allow_at <= now_ms {
            let gap = now_ms + self.burst_offset;
            let divisor = if self.cell_ms > 1 { self.cell_ms } else { 1 };
            let remaining = if gap > new_tat {
                (gap - new_tat) / divisor
            } else {
                0
            };
            (new_state, CoreDecision::allow(remaining as u32, new_tat))
        } else {
            (new_state, CoreDecision::deny(allow_at - now_ms, self.limit))
        }
    }
}

// ── TokenBucketCore ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct TokenBucketCore {
    capacity: u64,      // × SCALE
    refill_per_ms: u64, // tokens per ms × SCALE
    limit: u32,
}

/// Fixed-point scale factor (avoids f64 on no-std targets).
const SCALE: u64 = 1_000_000;

#[derive(Debug, Clone, Copy)]
pub struct TokenBucketState {
    /// Available tokens × SCALE.
    pub tokens_scaled: u64,
    pub last_refill_ms: u64,
}

impl TokenBucketState {
    pub fn new(capacity_scaled: u64) -> Self {
        Self {
            tokens_scaled: capacity_scaled,
            last_refill_ms: 0,
        }
    }
}

impl TokenBucketCore {
    pub const fn new(limit: u32, window_ms: u64, burst: u32) -> Self {
        let capacity = (limit + burst) as u64 * SCALE;
        let refill_per_ms = match (limit as u64 * SCALE).checked_div(window_ms) {
            Some(v) => v,
            None => 0,
        };
        Self {
            capacity,
            refill_per_ms,
            limit,
        }
    }

    pub fn new_state(&self) -> TokenBucketState {
        TokenBucketState::new(self.capacity)
    }

    #[inline]
    pub fn check(&self, state: TokenBucketState, now_ms: u64) -> (TokenBucketState, CoreDecision) {
        // No "uninitialized" sentinel needed here, unlike a naive first
        // pass might assume: a freshly created `TokenBucketState` already
        // has `tokens_scaled` set to full capacity (see `new`), so even if
        // `last_refill_ms` (0) is read as a real timestamp on the very
        // first check, `refilled` is clamped to `self.capacity` below and
        // the result is identical either way. Treating 0 as a sentinel
        // instead was the actual bug: `last_refill_ms` legitimately equals
        // 0 after any check that happens to run at real time 0, and a
        // later check at a real, later `now_ms` would then wrongly
        // recompute `last = now_ms` (elapsed = 0, no refill credited)
        // instead of the correct `last = 0` (elapsed = now_ms, correct
        // refill).
        let elapsed = now_ms.saturating_sub(state.last_refill_ms);
        let refilled = (state.tokens_scaled + elapsed * self.refill_per_ms).min(self.capacity);

        if refilled >= SCALE {
            let new_tokens = refilled - SCALE;
            let new_state = TokenBucketState {
                tokens_scaled: new_tokens,
                last_refill_ms: now_ms,
            };
            let remaining = (new_tokens / SCALE) as u32;
            (new_state, CoreDecision::allow(remaining, 0))
        } else {
            // Tokens needed to reach SCALE
            let needed_scaled = SCALE - refilled;
            let wait_ms = if self.refill_per_ms == 0 {
                u64::MAX
            } else {
                needed_scaled.div_ceil(self.refill_per_ms)
            };
            let new_state = TokenBucketState {
                tokens_scaled: refilled,
                last_refill_ms: now_ms,
            };
            (new_state, CoreDecision::deny(wait_ms, self.limit))
        }
    }
}

// ── SlidingWindowCore ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct SlidingWindowCore {
    limit: u32,
    window_ms: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SlidingWindowCoreState {
    pub prev_count: u32,
    pub curr_count: u32,
    pub window_start_ms: u64,
    /// Explicit "has this state ever been written by `check`" flag. This
    /// replaces a real bug: the previous code used `window_start_ms == 0`
    /// as an "uninitialized" sentinel, which collides with window 0
    /// legitimately starting at ms 0 — every call made at a `now_ms` in
    /// `[0, window_ms)` kept re-triggering the "first ever use" reset
    /// branch forever, so `curr_count` could never accumulate past 1.
    pub initialized: bool,
}

impl SlidingWindowCore {
    pub const fn new(limit: u32, window_ms: u64) -> Self {
        Self { limit, window_ms }
    }

    #[inline]
    pub fn check(
        &self,
        state: SlidingWindowCoreState,
        now_ms: u64,
    ) -> (SlidingWindowCoreState, CoreDecision) {
        let window_start = (now_ms / self.window_ms) * self.window_ms;
        let age = now_ms.saturating_sub(state.window_start_ms);

        // `curr` is incremented *speculatively* here, to include the
        // request currently being decided, before `eff_num` is computed
        // below — matching `algorithms::sliding_window::SlidingWindow`
        // (the `std` sibling of this `no_std` core), whose `next_state`
        // always advances the counter first and whose `decide` then
        // checks the resulting (inclusive) effective count with `<=`.
        // The previous version computed `eff_num` from the *prior*
        // count only and compared with strict `<`, which answers "was
        // the limit already exceeded before this request" rather than
        // "does admitting this request exceed the limit" — the two are
        // off by exactly one request's worth of weight, which is why a
        // 990ms-overlapping boundary burst could slip through undetected
        // (see `tests::sliding_window_core_no_boundary_spike`, which
        // failed under the old comparison and passes under this one).
        let (prev, curr, ws) = if !state.initialized {
            (0u32, 1u32, window_start)
        } else if age < self.window_ms {
            (
                state.prev_count,
                state.curr_count + 1,
                state.window_start_ms,
            )
        } else if age < 2 * self.window_ms {
            (state.curr_count, 1u32, window_start)
        } else {
            (0u32, 1u32, window_start)
        };

        // Fixed-point weighted sum: (prev × (window - elapsed) + curr × window) / window
        let elapsed = now_ms - ws;
        // eff_num = prev × (window - elapsed) + curr × window   (all in ms units)
        let eff_num = prev as u64 * (self.window_ms - elapsed.min(self.window_ms))
            + curr as u64 * self.window_ms;
        // eff = eff_num / window_ms  (compare to limit × window_ms)
        let limit_num = self.limit as u64 * self.window_ms;

        if eff_num <= limit_num {
            let new_state = SlidingWindowCoreState {
                prev_count: prev,
                curr_count: curr,
                window_start_ms: ws,
                initialized: true,
            };
            let remaining_num = limit_num - eff_num;
            let remaining = (remaining_num / self.window_ms) as u32;
            let reset_at = ws + self.window_ms;
            (new_state, CoreDecision::allow(remaining, reset_at))
        } else {
            // Time until prev decays enough
            let excess_num = eff_num - limit_num + self.window_ms; // +1 token worth
            let wait_ms = if prev == 0 {
                self.window_ms
            } else {
                excess_num / prev as u64 + 1
            };
            let new_state = SlidingWindowCoreState {
                prev_count: prev,
                curr_count: curr,
                window_start_ms: ws,
                initialized: true,
            };
            (new_state, CoreDecision::deny(wait_ms, self.limit))
        }
    }
}

// ── C FFI ─────────────────────────────────────────────────────────────────────

/// C-compatible structs for FFI usage.
#[repr(C)]
pub struct CGcraState {
    pub tat: u64,
}

#[repr(C)]
pub struct CCoreDecision {
    pub allowed: u8, // 1 = allow, 0 = deny
    pub remaining: u32,
    pub retry_after_ms: u64,
    pub reset_at_ms: u64,
}

/// Check GCRA from C.
///
/// # Safety
/// `state` and `out` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn ratekeeper_gcra_check(
    limit: u32,
    window_ms: u64,
    burst: u32,
    state: *mut CGcraState,
    now_ms: u64,
    out: *mut CCoreDecision,
) {
    let core = GcraCore::with_burst(limit, window_ms, burst);
    let s = GcraState { tat: (*state).tat };
    let (ns, d) = core.check(s, now_ms);
    (*state).tat = ns.tat;
    *out = CCoreDecision {
        allowed: if d.allowed { 1 } else { 0 },
        remaining: d.remaining,
        retry_after_ms: d.retry_after_ms,
        reset_at_ms: d.reset_at_ms,
    };
}

/// C-compatible token bucket state. Field layout matches
/// `TokenBucketState` exactly (`tokens_scaled`, `last_refill_ms`), so no
/// FFI-specific sentinel ambiguity exists here: `ratekeeper_tb_init`
/// always writes a real `now_ms` into `last_refill_ms` at construction
/// time, the same fix applied to `TokenBucketCore::check` itself (see
/// that function's doc comment) — there is no "0 means uninitialized"
/// moment on this path at all.
#[repr(C)]
pub struct CTokenBucketState {
    pub tokens_scaled: u64,
    pub last_refill_ms: u64,
}

/// Initialize a token bucket's state to full capacity from C.
///
/// # Safety
/// `out_state` must be a valid non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn ratekeeper_tb_init(
    limit: u32,
    window_ms: u64,
    burst: u32,
    now_ms: u64,
    out_state: *mut CTokenBucketState,
) {
    let core = TokenBucketCore::new(limit, window_ms, burst);
    let state = core.new_state();
    *out_state = CTokenBucketState {
        tokens_scaled: state.tokens_scaled,
        last_refill_ms: now_ms,
    };
}

/// Check a token bucket from C.
///
/// # Safety
/// `state` and `out` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn ratekeeper_tb_check(
    limit: u32,
    window_ms: u64,
    burst: u32,
    state: *mut CTokenBucketState,
    now_ms: u64,
    out: *mut CCoreDecision,
) {
    let core = TokenBucketCore::new(limit, window_ms, burst);
    let s = TokenBucketState {
        tokens_scaled: (*state).tokens_scaled,
        last_refill_ms: (*state).last_refill_ms,
    };
    let (ns, d) = core.check(s, now_ms);
    (*state).tokens_scaled = ns.tokens_scaled;
    (*state).last_refill_ms = ns.last_refill_ms;
    *out = CCoreDecision {
        allowed: if d.allowed { 1 } else { 0 },
        remaining: d.remaining,
        retry_after_ms: d.retry_after_ms,
        reset_at_ms: d.reset_at_ms,
    };
}

/// C-compatible sliding-window state. Carries its own `initialized`
/// flag (not present on the Rust-only `SlidingWindowCoreState` ABI
/// before this — added alongside it) for the exact same reason: without
/// it, a `window_start_ms == 0` sentinel collides with a legitimately
/// zero window start. Callers across the FFI boundary pass real wall-
/// clock milliseconds (see `ratekeeper_now_ms`), so this is unlikely to
/// bite in practice the way it did internally — but there is no reason
/// to leave the same class of bug latent in a second, parallel ABI
/// surface just because it is harder to trigger here.
#[repr(C)]
#[derive(Default)]
pub struct CSlidingWindowState {
    pub prev_count: u32,
    pub curr_count: u32,
    pub window_start_ms: u64,
    pub initialized: u8,
}

/// Check a sliding window from C.
///
/// # Safety
/// `state` and `out` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn ratekeeper_sw_check(
    limit: u32,
    window_ms: u64,
    state: *mut CSlidingWindowState,
    now_ms: u64,
    out: *mut CCoreDecision,
) {
    let core = SlidingWindowCore::new(limit, window_ms);
    let s = SlidingWindowCoreState {
        prev_count: (*state).prev_count,
        curr_count: (*state).curr_count,
        window_start_ms: (*state).window_start_ms,
        initialized: (*state).initialized != 0,
    };
    let (ns, d) = core.check(s, now_ms);
    (*state).prev_count = ns.prev_count;
    (*state).curr_count = ns.curr_count;
    (*state).window_start_ms = ns.window_start_ms;
    (*state).initialized = if ns.initialized { 1 } else { 0 };
    *out = CCoreDecision {
        allowed: if d.allowed { 1 } else { 0 },
        remaining: d.remaining,
        retry_after_ms: d.retry_after_ms,
        reset_at_ms: d.reset_at_ms,
    };
}

/// Current wall-clock time in milliseconds since the Unix epoch. Exists
/// for FFI callers (e.g. the Python bindings) that have no std-library
/// clock of their own to source `now_ms` from — this crate's core is
/// `no_std` by design (see this module's own doc comment), so it can't
/// provide this to itself; this one function is the deliberate,
/// documented exception, available only through the FFI surface, not
/// `core_nostd`'s pure no-std API.
#[no_mangle]
pub extern "C" fn ratekeeper_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// This crate's version, as a static, null-terminated C string (valid
/// for the lifetime of the process — callers must not free it).
#[no_mangle]
pub extern "C" fn ratekeeper_version() -> *const core::ffi::c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── GCRA ─────────────────────────────────────────────────────────────────

    #[test]
    fn gcra_core_allows_at_rate() {
        let core = GcraCore::new(5, 1_000); // 5/sec → 200ms/token
        let mut s = GcraState::new();
        let mut t = 0u64;

        for i in 0..5u32 {
            let (ns, d) = core.check(s, t);
            assert!(d.allowed, "req {i} at t={t} should be allowed");
            s = ns;
            t += 200;
        }
        // At t=1000, 5 tokens issued — 6th at same pace should still be allowed
        // (new window); at t=800 it should be denied
        let (_, d) = core.check(s, 800);
        assert!(!d.allowed, "6th at t=800 should be denied");
    }

    #[test]
    fn gcra_core_burst_allows_extra() {
        // Standard GCRA burst tolerance is `burst + 1` back-to-back
        // requests, independent of `limit` — it is not a token-bucket
        // "limit instant + burst extra" model. The sibling `std` test
        // `algorithms::gcra::tests::burst_allows_extra` (limit=1, burst=4,
        // expects 5 = burst+1) proves this is the intended, correct
        // behavior of this library's GCRA, not an omission here: this
        // test previously asserted `limit + burst` (5), which doesn't
        // match either GCRA theory or this crate's own other passing
        // test of the same algorithm.
        let core = GcraCore::with_burst(2, 1_000, 3); // burst=3 → burst+1=4 at t=0
        let mut s = GcraState::new();
        let mut allowed = 0u32;
        for _ in 0..6 {
            let (ns, d) = core.check(s, 0);
            if d.allowed {
                allowed += 1;
            }
            s = ns;
        }
        assert_eq!(
            allowed, 4,
            "burst=3 → burst+1=4 back-to-back requests allowed at t=0"
        );
    }

    // ── Token Bucket ─────────────────────────────────────────────────────────

    #[test]
    fn token_bucket_core_allows_full_capacity() {
        let core = TokenBucketCore::new(10, 1_000, 0); // cap=10
        let mut s = core.new_state();
        for i in 0..10u32 {
            let (ns, d) = core.check(s, 0);
            assert!(d.allowed, "req {i} should be allowed from full bucket");
            s = ns;
        }
        let (_, d) = core.check(s, 0);
        assert!(!d.allowed, "11th should be denied");
    }

    #[test]
    fn token_bucket_core_refills() {
        let core = TokenBucketCore::new(10, 1_000, 0); // 10/sec = 1 per 100ms
        let mut s = core.new_state();
        // Drain
        for _ in 0..10 {
            let (ns, _) = core.check(s, 0);
            s = ns;
        }
        // After 500ms, ~5 tokens back
        let (ns, d) = core.check(s, 500);
        assert!(d.allowed, "should refill over time");
        assert!(
            ns.tokens_scaled / SCALE >= 3,
            "at least 3 tokens after 500ms"
        );
    }

    // ── Sliding Window ────────────────────────────────────────────────────────

    #[test]
    fn sliding_window_core_no_boundary_spike() {
        let core = SlidingWindowCore::new(5, 1_000);
        let mut s = SlidingWindowCoreState::default();

        // 5 at t=990 (end of window 0)
        for _ in 0..5 {
            let (ns, d) = core.check(s, 990);
            assert!(d.allowed);
            s = ns;
        }
        // 1 at t=1_010 (10ms into window 1) — should be denied
        let (_, d) = core.check(s, 1_010);
        assert!(!d.allowed, "boundary spike must be caught");
    }

    #[test]
    fn sliding_window_core_allows_after_full_window() {
        let core = SlidingWindowCore::new(3, 1_000);
        let mut s = SlidingWindowCoreState::default();
        for _ in 0..3 {
            let (ns, _) = core.check(s, 0);
            s = ns;
        }

        let (_, d) = core.check(s, 2_001);
        assert!(d.allowed, "fully expired after 2 windows");
    }

    // ── FFI ──────────────────────────────────────────────────────────────────

    #[test]
    fn ffi_gcra_check_allows_first_request() {
        let mut state = CGcraState { tat: 0 };
        let mut out = CCoreDecision {
            allowed: 0,
            remaining: 0,
            retry_after_ms: 0,
            reset_at_ms: 0,
        };
        unsafe {
            ratekeeper_gcra_check(10, 1_000, 0, &mut state, 0, &mut out);
        }
        assert_eq!(out.allowed, 1);
    }
}
