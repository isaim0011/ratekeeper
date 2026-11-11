use ratekeeper::hierarchical::{
    ConcurrencyLimiter, EndpointPolicy, HierarchicalLimiter, LimitLayer, RateLimitContext,
    RequestPriority,
};
use ratekeeper::Policy;

#[tokio::test]
async fn full_hierarchy_allows_normal_traffic() {
    // Global (GCRA-backed) needs generous burst: all 21 calls below hit
    // it (it's shared across every layer-under-test, not just
    // endpoint), and HierarchicalLimiter's real SystemClock means these
    // fast back-to-back calls don't naturally space out enough for
    // GCRA's default (burst=0 → only 1 instant request) to cover them.
    // Tenant (TokenBucket-backed, capacity=limit+burst) needs no
    // adjustment: its default capacity already equals limit=100,
    // comfortably covering the 21 calls here with no burst needed.
    let limiter = HierarchicalLimiter::builder()
        .global(Policy::per_second(1_000).with_burst(29))
        .tenant(Policy::per_second(100))
        .endpoint(
            b"POST /v1/data",
            EndpointPolicy::new(Policy::per_second(20)),
        )
        .build();

    let ctx = RateLimitContext::new(b"tenant-stripe", b"POST /v1/data");
    for i in 0..20u32 {
        let d = limiter.check(&ctx).await;
        assert!(d.allowed, "normal request {i} should be allowed");
    }
    // 21st hits endpoint limit
    let d = limiter.check(&ctx).await;
    assert!(!d.allowed);
    assert_eq!(d.denied_at, Some(LimitLayer::Endpoint));
}

#[tokio::test]
async fn critical_bypasses_all_non_global_limits() {
    // burst=9 on global: all 10 checks below are Critical priority, so
    // every one of them hits only the global (GCRA-backed) layer, which
    // needs burst to allow more than 1 instant request — see
    // full_hierarchy_allows_normal_traffic's comment above.
    let limiter = HierarchicalLimiter::builder()
        .global(Policy::per_second(1_000).with_burst(9))
        .tenant(Policy::per_second(2)) // very tight
        .endpoint(b"GET /health", EndpointPolicy::new(Policy::per_second(2)))
        .build();

    let ctx =
        RateLimitContext::new(b"tenant-x", b"GET /health").with_priority(RequestPriority::Critical);

    // 10 health checks — global allows all, tenant/endpoint skipped
    for _ in 0..10 {
        assert!(limiter.check(&ctx).await.allowed);
    }
}

#[tokio::test]
async fn concurrency_limiter_basic() {
    let cl = ConcurrencyLimiter::new(2);

    let p1 = cl.try_acquire();
    let p2 = cl.try_acquire();
    assert!(p1.is_some(), "first slot available");
    assert!(p2.is_some(), "second slot available");

    let p3 = cl.try_acquire();
    assert!(p3.is_none(), "third slot: concurrency limit hit");

    // Release one and try again
    drop(p1);
    let p4 = cl.try_acquire();
    assert!(p4.is_some(), "slot released, acquisition succeeds");
}

#[tokio::test]
async fn multiple_tenants_isolated() {
    // burst=49 on global: 10 tenants × 4 calls each = 40 total hits on
    // the shared global (GCRA-backed) layer — see
    // full_hierarchy_allows_normal_traffic's comment above for why
    // global needs this and tenant (TokenBucket-backed, independent
    // per-tenant counters, default capacity already equals limit) does
    // not.
    let limiter = HierarchicalLimiter::builder()
        .global(Policy::per_second(1_000).with_burst(49))
        .tenant(Policy::per_second(3))
        .build();

    let tenants: Vec<Vec<u8>> = (0..10)
        .map(|i| format!("tenant-{i}").into_bytes())
        .collect();

    // Each tenant gets 3 requests
    for t in &tenants {
        for _ in 0..3 {
            let ctx = RateLimitContext::new(t.as_slice(), b"GET /api");
            assert!(limiter.check(&ctx).await.allowed);
        }
        // 4th is denied
        let ctx = RateLimitContext::new(t.as_slice(), b"GET /api");
        let d = limiter.check(&ctx).await;
        assert!(
            !d.allowed,
            "4th request for {} should be denied",
            String::from_utf8_lossy(t)
        );
    }
}
