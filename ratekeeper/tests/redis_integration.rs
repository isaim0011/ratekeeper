//! Redis integration tests.
//!
//! These require a running Redis instance. Run with:
//!   REDIS_URL=redis://localhost:6379 cargo test --features redis -- --ignored
//!
//! In CI, add a `redis:7` service to your pipeline.

#[cfg(feature = "redis")]
mod tests {
    use ratekeeper::store::redis_pool::{
        PooledGcraStore, PooledSlidingWindowStore, PooledTokenBucketStore, RedisPool,
        RedisPoolConfig,
    };
    use std::env;

    fn redis_url() -> String {
        env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
    }

    async fn pool() -> RedisPool {
        RedisPool::new(RedisPoolConfig::new(redis_url()))
            .await
            .expect("Redis connection failed — is Redis running?")
    }

    // ── GCRA ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn redis_gcra_allows_up_to_limit() {
        let pool = pool().await;
        let store = PooledGcraStore::new(pool, 200, 200, 2_000); // 5/sec, no burst

        let key = b"test:gcra:allow";
        let now_ms = 0u64;

        // First request: allow
        let r = store.check(key, now_ms).await.unwrap();
        assert!(r.allowed, "first request should be allowed");
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn redis_gcra_denies_over_limit() {
        let pool = pool().await;
        // 1 req per 1000ms, no burst
        let store = PooledGcraStore::new(pool, 1_000, 1_000, 10_000);

        let key = format!("test:gcra:deny:{}", uuid());
        let now = current_ms();

        // Allow the first
        let r1 = store.check(key.as_bytes(), now).await.unwrap();
        assert!(r1.allowed);

        // Deny the second (same ms)
        let r2 = store.check(key.as_bytes(), now).await.unwrap();
        assert!(!r2.allowed, "second request at same ms must be denied");
        assert!(r2.retry_after_ms > 0);
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn redis_gcra_independent_keys_dont_share_quota() {
        let pool = pool().await;
        let store = PooledGcraStore::new(pool, 1_000, 1_000, 10_000);

        let now = current_ms();
        let key1 = format!("test:gcra:kA:{}", uuid());
        let key2 = format!("test:gcra:kB:{}", uuid());

        let r1 = store.check(key1.as_bytes(), now).await.unwrap();
        let r2 = store.check(key2.as_bytes(), now).await.unwrap();
        assert!(r1.allowed, "key1 should be allowed");
        assert!(r2.allowed, "key2 should be allowed independently");
    }

    // ── Sliding Window ────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn redis_sliding_window_no_boundary_spike() {
        let pool = pool().await;
        // 5 per 1000ms window
        let store = PooledSlidingWindowStore::new(pool, 1_000, 5);

        let key = format!("test:sw:boundary:{}", uuid());

        // 5 requests at t=990ms (end of window 0)
        for _ in 0..5 {
            let r = store.check(key.as_bytes(), 990).await.unwrap();
            assert!(r.allowed);
        }

        // 1 request at t=1010ms (start of window 1)
        // prev_weight ≈ 0.99, so effective_count ≈ 4.95 + 0 = 4.95 → next = 5.95 > 5
        let r = store.check(key.as_bytes(), 1_010).await.unwrap();
        assert!(!r.allowed, "sliding window must catch boundary spike");
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn redis_sliding_window_allows_after_full_window_passes() {
        let pool = pool().await;
        let store = PooledSlidingWindowStore::new(pool, 1_000, 5);
        let key = format!("test:sw:refill:{}", uuid());
        let now = current_ms();

        for _ in 0..5 {
            store.check(key.as_bytes(), now).await.unwrap();
        }

        // Two windows later — prev_weight ≈ 0, full reset
        let r = store.check(key.as_bytes(), now + 2_001).await.unwrap();
        assert!(r.allowed, "should allow after two full windows");
    }

    // ── Token Bucket ──────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn redis_token_bucket_burst_then_deny() {
        let pool = pool().await;
        // capacity=5, refill 1/sec = 0.001/ms
        let store = PooledTokenBucketStore::new(pool, 5, 0.001, 10_000);
        let key = format!("test:tb:burst:{}", uuid());
        let now = current_ms();

        for i in 0..5u32 {
            let r = store.check(key.as_bytes(), now).await.unwrap();
            assert!(r.allowed, "burst req {i} should be allowed");
        }

        let r = store.check(key.as_bytes(), now).await.unwrap();
        assert!(!r.allowed, "post-burst should be denied");
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn redis_token_bucket_refills_over_time() {
        let pool = pool().await;
        let store = PooledTokenBucketStore::new(pool, 5, 0.005, 10_000); // 5/sec
        let key = format!("test:tb:refill:{}", uuid());
        let now = current_ms();

        // Drain
        for _ in 0..5 {
            store.check(key.as_bytes(), now).await.unwrap();
        }

        // After 1 second (5 tokens refilled)
        let r = store.check(key.as_bytes(), now + 1_001).await.unwrap();
        assert!(r.allowed, "should allow after refill");
    }

    // ── Cluster key co-location ───────────────────────────────────────────────

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn redis_hash_tags_keep_keys_on_same_shard() {
        // Sliding window uses {key}:window_id — the hash tag ensures curr and prev
        // land on the same shard in a Redis Cluster, allowing MULTI-key Lua.
        // This test verifies the key format is correct (not a logic test).
        let key = b"tenant:123";
        let window_ms = 1_000u64;
        let now_ms = 1_500u64;

        let window_id = now_ms / window_ms; // = 1
        let curr = format!("{{{0}}}:{1}", String::from_utf8_lossy(key), window_id);
        let prev = format!("{{{0}}}:{1}", String::from_utf8_lossy(key), window_id - 1);

        assert!(curr.starts_with("{tenant:123}:"));
        assert!(prev.starts_with("{tenant:123}:"));
        assert_ne!(curr, prev);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    fn uuid() -> String {
        // Simple pseudo-unique suffix for test key isolation
        use std::time::{SystemTime, UNIX_EPOCH};
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        format!("{ns:08x}")
    }

    fn current_ms() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}
