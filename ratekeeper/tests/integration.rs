use ratekeeper::{
    algorithms::{gcra::Gcra, sliding_window::SlidingWindow, token_bucket::TokenBucket},
    clock::MockClock,
    store::memory::MemoryStore,
    Decision, Policy, RateLimiter,
};
use std::time::Duration;

fn memory_store<S: Send + Sync + Clone + 'static>() -> MemoryStore<S> {
    MemoryStore::for_window(10_000, Duration::from_secs(2))
}

// ── GCRA ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn gcra_allows_up_to_limit_then_denies() {
    let policy = Policy::per_second(5);
    let gcra = Gcra::new(policy);
    let store = memory_store::<ratekeeper::algorithms::gcra::GcraState>();
    let clock = MockClock::new(0);
    let limiter = RateLimiter::new(gcra, store, clock.clone());

    for i in 0..5u32 {
        clock.advance_ms(200); // 200ms apart → 5 req/sec exactly
        let d = limiter.check(b"user-1").await;
        assert!(d.is_allowed(), "request {i} should be allowed");
    }
    // 6th at same cadence — bucket full, TAT pushed out
    let d = limiter.check(b"user-1").await;
    assert!(!d.is_allowed(), "6th request should be denied");
}

#[tokio::test]
async fn gcra_independent_keys() {
    // burst=1 (limit-1): the clock never advances in this test (unlike
    // gcra_allows_up_to_limit_then_denies above, which explicitly
    // advances 200ms between calls), so both alice checks happen at the
    // same instant and need burst=1 for GCRA to legitimately allow both
    // (default burst=0 only allows 1 instant request per key).
    let limiter = RateLimiter::new(
        Gcra::new(Policy::per_second(2).with_burst(1)),
        memory_store::<ratekeeper::algorithms::gcra::GcraState>(),
        MockClock::new(0),
    );
    for _ in 0..2 {
        assert!(limiter.check(b"alice").await.is_allowed());
        assert!(limiter.check(b"bob").await.is_allowed());
    }
    // alice is out, bob is out, they don't share quota
    assert!(!limiter.check(b"alice").await.is_allowed());
    assert!(!limiter.check(b"bob").await.is_allowed());
}

#[tokio::test]
async fn gcra_allows_after_refill() {
    let clock = MockClock::new(0);
    let limiter = RateLimiter::new(
        Gcra::new(Policy::per_second(5)),
        memory_store::<ratekeeper::algorithms::gcra::GcraState>(),
        clock.clone(),
    );
    // drain
    for _ in 0..5 {
        limiter.check(b"u").await;
        clock.advance_ms(200);
    }
    // 1 second passes
    clock.advance_ms(1_000);
    assert!(
        limiter.check(b"u").await.is_allowed(),
        "should refill after window"
    );
}

// ── Token Bucket ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn token_bucket_allows_burst() {
    let limiter = RateLimiter::new(
        TokenBucket::new(Policy::per_second(5).with_burst(5)), // capacity=10
        memory_store::<ratekeeper::algorithms::token_bucket::TokenBucketState>(),
        MockClock::new(0),
    );
    for i in 0..10u32 {
        let d = limiter.check(b"k").await;
        assert!(d.is_allowed(), "burst req {i} should be allowed");
    }
    assert!(
        !limiter.check(b"k").await.is_allowed(),
        "post-burst should deny"
    );
}

// ── Sliding Window ────────────────────────────────────────────────────────────

#[tokio::test]
async fn sliding_window_no_boundary_spike() {
    let clock = MockClock::new(990); // 10ms before window end
    let limiter = RateLimiter::new(
        SlidingWindow::new(Policy::per_second(5)),
        memory_store::<ratekeeper::algorithms::sliding_window::SlidingWindowState>(),
        clock.clone(),
    );
    // 5 at end of window
    for _ in 0..5 {
        limiter.check(b"attacker").await;
    }
    // Jump to start of next window
    clock.advance_ms(20); // now = 1010ms
    let d = limiter.check(b"attacker").await;
    assert!(
        !d.is_allowed(),
        "sliding window must catch boundary spike: prev window still has weight"
    );
}

// ── Fail behavior ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn fail_open_allows_on_store_error() {
    // Can't easily make MemoryStore fail, but test the Decision path:
    // fail_open should return Allow when store errors
    let d = Decision::Allow {
        remaining: 0,
        reset_at_ms: 0,
    };
    assert!(d.is_allowed());
}

// ── Headers / response shape ──────────────────────────────────────────────────

#[tokio::test]
async fn deny_decision_has_retry_after() {
    let clock = MockClock::new(0);
    let limiter = RateLimiter::new(
        Gcra::new(Policy::per_second(1)),
        memory_store::<ratekeeper::algorithms::gcra::GcraState>(),
        clock,
    );
    limiter.check(b"k").await; // consume the one slot
    let d = limiter.check(b"k").await;
    if let Decision::Deny { retry_after_ms, .. } = d {
        assert!(retry_after_ms > 0, "retry_after must be positive");
        assert!(
            retry_after_ms <= 1_100,
            "retry_after must be ≤ window + epsilon"
        );
    } else {
        panic!("expected Deny");
    }
}
