# ratekeeper

> World-class rate limiting for Rust — and anything that calls Rust.

```
GCRA · Token Bucket · Sliding Window
In-memory · Redis · Two-tier (local + Redis)
Tower middleware · Axum extractor
Hierarchical (global → tenant → endpoint)
Priority lanes · Weighted cost · Idempotency
Adaptive backpressure · Admin API · Prometheus metrics
no_std core · C FFI · Python bindings
```

---

## Architecture

```
                    ┌───────────────────────────────────────┐
                    │           RateLimitLayer               │
                    │  (Tower middleware, key extraction,    │
                    │   X-RateLimit headers, 429 response)   │
                    └──────────────┬────────────────────────┘
                                   │
                    ┌──────────────▼────────────────────────┐
                    │         HierarchicalLimiter            │
                    │                                        │
                    │  1. Global GCRA cap  (DDoS shield)     │
                    │  2. Per-tenant token bucket            │
                    │  3. Per-endpoint sliding window        │
                    │  4. Concurrency semaphore              │
                    └──────────────┬────────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
   ┌──────────▼──────┐  ┌──────────▼──────┐  ┌────────▼────────┐
   │   GCRA          │  │  Token Bucket   │  │ Sliding Window  │
   │   (1 u64/key)   │  │  (f64 + u64)    │  │  (2 u32 + u64)  │
   │   Lock-free CAS │  │  Burst capacity │  │  No bdry spike  │
   └──────────┬──────┘  └──────────┬──────┘  └────────┬────────┘
              │                    │                    │
              └────────────────────┼────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
   ┌──────────▼──────┐  ┌──────────▼──────┐  ┌────────▼────────┐
   │  MemoryStore    │  │  TwoTierStore   │  │  RedisPool      │
   │  moka LRU+TTL   │  │  local + Redis  │  │  EVALSHA Lua    │
   │  per-entry lock │  │  10× less Redis │  │  atomic scripts │
   └─────────────────┘  └─────────────────┘  └─────────────────┘

                    ┌──────────────────────────────────────┐
                    │  Cross-cutting                       │
                    │  PolicyStore  — runtime policy admin │
                    │  AdaptiveLimiter — AIMD backpressure │
                    │  IdempotencyCache — retry dedup      │
                    │  Metrics (Prometheus) + tracing      │
                    └──────────────────────────────────────┘

                    ┌──────────────────────────────────────┐
                    │  Portable core (no_std)              │
                    │  GcraCore · TokenBucketCore          │
                    │  SlidingWindowCore                   │
                    │  C FFI · Python bindings             │
                    └──────────────────────────────────────┘
```

---

## Feature flags

| Feature | Adds |
|---|---|
| `memory` (default) | `MemoryStore` (moka + DashMap) |
| `redis` | `RedisPool`, `PooledGcraStore`, Lua scripts |
| `tower-layer` | Tower `Layer` + `Service` |
| `axum` | Axum extractor + Tower |
| `prometheus` | `PrometheusSink` |
| `full` | Everything |

---

## Quick start

```toml
[dependencies]
ratekeeper = { version = "0.4", features = ["memory", "tower-layer", "axum"] }
```

### GCRA — in-memory, Axum

```rust
use ratekeeper::{Gcra, Policy, RateLimiter, SystemClock};
use ratekeeper::store::memory::MemoryStore;
use ratekeeper::middleware::{RateLimitLayer, extractors::PeerIp};
use axum::{Router, routing::get};

let store   = MemoryStore::for_window(100_000, std::time::Duration::from_secs(1));
let limiter = RateLimiter::new(Gcra::new(Policy::per_second(100).with_burst(50)), store, SystemClock);

let app = Router::new()
    .route("/api/v1/data", get(handler))
    .layer(RateLimitLayer::new(limiter, PeerIp::new(true)));
```

### Hierarchical — global + tenant + endpoint

```rust
use ratekeeper::hierarchical::{HierarchicalLimiter, EndpointPolicy, RateLimitContext};

let limiter = HierarchicalLimiter::builder()
    .global(Policy::per_second(50_000))
    .tenant(Policy::per_minute(10_000))
    .endpoint("POST /v1/charges", EndpointPolicy::new(Policy::per_second(100)).with_concurrency(50))
    .build();

let ctx = RateLimitContext::new(tenant_id, "POST /v1/charges");
let d   = limiter.check(&ctx).await;
```

### Adaptive — auto-tighten under pressure

```rust
use ratekeeper::adaptive::{AdaptiveLimiter, ErrorRateSignal};
use std::{sync::Arc, time::Duration};

let errors  = ErrorRateSignal::new(10 /* window_secs */);
let limiter = Arc::new(
    AdaptiveLimiter::new(10_000)
        .with_signal(Arc::clone(&errors))
);
limiter.clone().start_background_update(Duration::from_millis(100));
// Somewhere in your error handler:
errors.record(true /* is_5xx */);
```

### Admin — runtime policy control

```rust
use ratekeeper::admin::{PolicyStore, PolicyCommand, KeyOverride};

let store = PolicyStore::new();
store.set_group("api", Policy::per_second(100)).await;

// Block an abuser instantly, no deploy needed
PolicyCommand::BlockKey { key: ip.into(), duration_secs: Some(300), reason: "abuse".into() }
    .apply(&store).await;

// Give a VIP more quota
store.set_key_override("api", vip_key, KeyOverride::CustomPolicy(Policy::per_second(10_000))).await;
```

### Python (via C FFI)

```python
from ratekeeper import GcraLimiter

lim = GcraLimiter(limit=100, window_ms=1000, burst=20)
if lim.is_allowed("user-123"):
    process_request()
else:
    return 429
```

---

## Response headers

| Header | Value |
|---|---|
| `X-RateLimit-Limit` | Policy limit |
| `X-RateLimit-Remaining` | Tokens left |
| `X-RateLimit-Reset` | Epoch-ms of reset |
| `Retry-After` | Seconds until retry (429 only) |

---

## Benchmarks (target)

| Scenario | Target |
|---|---|
| GCRA in-memory, single key | < 500 ns |
| GCRA in-memory, 10k keys | < 1 µs |
| Token bucket in-memory | < 1 µs |
| Redis GCRA (EVALSHA) | < 1 ms (RTT-bound) |
| Two-tier (local hit) | < 500 ns |
| Two-tier (Redis miss) | < 1 ms |

Run: `cargo xtask bench`

---

## Build phases

| Phase | Contents |
|---|---|
| 1 | GCRA + Token Bucket + Sliding Window, `MemoryStore`, Tower middleware |
| 2 | Redis (`deadpool-redis`, Lua EVALSHA, circuit breaker), two-tier store, CI |
| 3 | Hierarchical limits, priority lanes, weighted cost, concurrency cap |
| 4 | Admin API, adaptive backpressure (AIMD), idempotency cache, Prometheus, tracing |
| 5 | `no_std` core, C FFI header, Python bindings, `cargo xtask` |

---

## License

MIT OR Apache-2.0
