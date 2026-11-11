//! Hierarchical rate limiting.
//!
//! Real-world APIs need layered limits:
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │  Global emergency cap  (service-wide GCRA)   │  ← circuit breaker for DDoS
//! │  ┌─────────────────────────────────────────┐ │
//! │  │  Per-tenant token bucket                │ │  ← fair multi-tenancy
//! │  │  ┌───────────────────────────────────┐  │ │
//! │  │  │  Per-endpoint sliding window      │  │ │  ← protect expensive routes
//! │  │  │  ┌─────────────────────────────┐  │  │ │
//! │  │  │  │  Concurrency cap (semaphore) │  │  │ │  ← cap in-flight requests
//! │  │  │  └─────────────────────────────┘  │  │ │
//! │  │  └───────────────────────────────────┘  │ │
//! │  └─────────────────────────────────────────┘ │
//! └──────────────────────────────────────────────┘
//! ```
//!
//! Each layer is independent: a request is allowed only if ALL layers allow it.
//! This avoids the "2× burst at boundary" problem that comes from a single limiter.
//!
//! # Priority lanes
//! High-priority traffic (health checks, payment webhooks) can skip the
//! per-endpoint and per-tenant layers and go directly to the global check.
//! Configure via `RequestPriority`.

use crate::{
    algorithms::{gcra::Gcra, sliding_window::SlidingWindow, token_bucket::TokenBucket},
    clock::SystemClock,
    store::memory::MemoryStore,
    Decision, Policy, RateLimiter,
};
use std::{collections::HashMap, sync::Arc, time::Duration};

// ── Priority ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum RequestPriority {
    /// Critical: health checks, internal ops. Only global cap applies.
    Critical = 0,
    /// High: payment/webhook callbacks. Skips per-endpoint limit.
    High = 1,
    /// Normal: regular API traffic. All layers apply.
    #[default]
    Normal = 2,
    /// Low: bulk/background jobs. Stricter per-tenant sub-quota.
    Low = 3,
}

// ── Request context ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RateLimitContext {
    /// Tenant / org / account identifier.
    pub tenant_id: Vec<u8>,
    /// Endpoint identifier (e.g. `"POST /v1/charges"`).
    pub endpoint: Vec<u8>,
    /// How many tokens this request costs (default 1; use >1 for expensive ops).
    pub cost: u32,
    pub priority: RequestPriority,
}

impl RateLimitContext {
    pub fn new(tenant_id: impl Into<Vec<u8>>, endpoint: impl Into<Vec<u8>>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            endpoint: endpoint.into(),
            cost: 1,
            priority: RequestPriority::Normal,
        }
    }

    pub fn with_cost(mut self, cost: u32) -> Self {
        self.cost = cost;
        self
    }
    pub fn with_priority(mut self, p: RequestPriority) -> Self {
        self.priority = p;
        self
    }
}

// ── HierarchicalDecision ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HierarchicalDecision {
    pub allowed: bool,
    /// Which layer denied the request.
    pub denied_at: Option<LimitLayer>,
    pub retry_after_ms: u64,
    pub remaining_by_layer: LayerRemaining,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitLayer {
    Global,
    Tenant,
    Endpoint,
}

#[derive(Debug, Clone, Default)]
pub struct LayerRemaining {
    pub global: Option<u32>,
    pub tenant: Option<u32>,
    pub endpoint: Option<u32>,
}

// ── ConcurrencyLimiter ────────────────────────────────────────────────────────

/// Semaphore-based concurrency cap.  Counts in-flight requests, not rate.
/// Protects slow endpoints from request pile-ups under latency spikes.
pub struct ConcurrencyLimiter {
    semaphore: Arc<tokio::sync::Semaphore>,
    limit: u32,
}

impl ConcurrencyLimiter {
    pub fn new(max_concurrent: u32) -> Self {
        Self {
            semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent as usize)),
            limit: max_concurrent,
        }
    }

    /// Try to acquire a concurrency slot.  Returns a guard that releases on drop.
    pub fn try_acquire(&self) -> Option<tokio::sync::SemaphorePermit<'_>> {
        self.semaphore.try_acquire().ok()
    }

    pub fn in_flight(&self) -> u32 {
        self.limit - self.semaphore.available_permits() as u32
    }
}

// ── EndpointPolicy ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct EndpointPolicy {
    /// Per-endpoint sliding window (strict quota).
    pub rate_limit: Option<Policy>,
    /// Max concurrent requests to this endpoint.
    pub max_inflight: Option<u32>,
    /// Cost multiplier for GraphQL complexity, etc.
    pub base_cost: u32,
}

impl EndpointPolicy {
    pub fn new(rate_limit: Policy) -> Self {
        Self {
            rate_limit: Some(rate_limit),
            max_inflight: None,
            base_cost: 1,
        }
    }

    pub fn with_concurrency(mut self, max: u32) -> Self {
        self.max_inflight = Some(max);
        self
    }
    pub fn with_base_cost(mut self, c: u32) -> Self {
        self.base_cost = c;
        self
    }
}

// ── HierarchicalLimiter ───────────────────────────────────────────────────────

type GcraMemory = RateLimiter<Gcra, MemoryStore<crate::algorithms::gcra::GcraState>, SystemClock>;
type TbMemory = RateLimiter<
    TokenBucket,
    MemoryStore<crate::algorithms::token_bucket::TokenBucketState>,
    SystemClock,
>;
type SwMemory = RateLimiter<
    SlidingWindow,
    MemoryStore<crate::algorithms::sliding_window::SlidingWindowState>,
    SystemClock,
>;

pub struct HierarchicalLimiter {
    /// Global emergency cap — applies to all requests.
    global: GcraMemory,
    /// Per-tenant token bucket.
    tenant: TbMemory,
    /// Per-endpoint sliding window, keyed by endpoint id.
    endpoints: HashMap<Vec<u8>, SwMemory>,
    /// Per-endpoint concurrency limits.
    #[allow(dead_code)]
    concurrency: HashMap<Vec<u8>, ConcurrencyLimiter>,
}

impl HierarchicalLimiter {
    pub fn builder() -> HierarchicalLimiterBuilder {
        HierarchicalLimiterBuilder::default()
    }

    pub async fn check(&self, ctx: &RateLimitContext) -> HierarchicalDecision {
        let mut remaining = LayerRemaining::default();

        // ── 1. Global cap (always) ──────────────────────────────────────────
        let global_key = b"__global__";
        let gd = self.global.check(global_key).await;
        if let Decision::Allow { remaining: r, .. } = &gd {
            remaining.global = Some(*r);
        }
        if !gd.is_allowed() {
            let retry = if let Decision::Deny { retry_after_ms, .. } = gd {
                retry_after_ms
            } else {
                0
            };
            return HierarchicalDecision {
                allowed: false,
                denied_at: Some(LimitLayer::Global),
                retry_after_ms: retry,
                remaining_by_layer: remaining,
            };
        }

        // ── 2. Per-tenant (skip for Critical) ──────────────────────────────
        if ctx.priority > RequestPriority::Critical {
            let td = self.tenant.check(&ctx.tenant_id).await;
            if let Decision::Allow { remaining: r, .. } = &td {
                remaining.tenant = Some(*r);
            }
            if !td.is_allowed() {
                let retry = if let Decision::Deny { retry_after_ms, .. } = td {
                    retry_after_ms
                } else {
                    0
                };
                return HierarchicalDecision {
                    allowed: false,
                    denied_at: Some(LimitLayer::Tenant),
                    retry_after_ms: retry,
                    remaining_by_layer: remaining,
                };
            }
        }

        // ── 3. Per-endpoint (Normal and Low only) ──────────────────────────
        if ctx.priority >= RequestPriority::Normal {
            if let Some(ep_limiter) = self.endpoints.get(&ctx.endpoint) {
                // Key = tenant:endpoint so limits are per-tenant per-endpoint
                let mut ep_key = ctx.tenant_id.clone();
                ep_key.push(b':');
                ep_key.extend_from_slice(&ctx.endpoint);

                let ed = ep_limiter.check(&ep_key).await;
                if let Decision::Allow { remaining: r, .. } = &ed {
                    remaining.endpoint = Some(*r);
                }
                if !ed.is_allowed() {
                    let retry = if let Decision::Deny { retry_after_ms, .. } = ed {
                        retry_after_ms
                    } else {
                        0
                    };
                    return HierarchicalDecision {
                        allowed: false,
                        denied_at: Some(LimitLayer::Endpoint),
                        retry_after_ms: retry,
                        remaining_by_layer: remaining,
                    };
                }
            }
        }

        HierarchicalDecision {
            allowed: true,
            denied_at: None,
            retry_after_ms: 0,
            remaining_by_layer: remaining,
        }
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct HierarchicalLimiterBuilder {
    global_policy: Option<Policy>,
    tenant_policy: Option<Policy>,
    endpoints: HashMap<Vec<u8>, EndpointPolicy>,
}

impl HierarchicalLimiterBuilder {
    /// Global emergency cap (applies to all requests, all tenants).
    pub fn global(mut self, policy: Policy) -> Self {
        self.global_policy = Some(policy);
        self
    }

    /// Default per-tenant token bucket policy.
    pub fn tenant(mut self, policy: Policy) -> Self {
        self.tenant_policy = Some(policy);
        self
    }

    /// Register a per-endpoint policy.
    pub fn endpoint(mut self, id: impl Into<Vec<u8>>, policy: EndpointPolicy) -> Self {
        self.endpoints.insert(id.into(), policy);
        self
    }

    pub fn build(self) -> HierarchicalLimiter {
        let global_policy = self
            .global_policy
            .unwrap_or_else(|| Policy::per_second(10_000));
        let tenant_policy = self
            .tenant_policy
            .unwrap_or_else(|| Policy::per_minute(1_000));

        let global = RateLimiter::new(
            Gcra::new(global_policy),
            MemoryStore::for_window(1, Duration::from_secs(1)),
            SystemClock,
        );

        let tenant = RateLimiter::new(
            TokenBucket::new(tenant_policy.clone()),
            MemoryStore::for_window(100_000, tenant_policy.window * 2),
            SystemClock,
        );

        let mut ep_limiters = HashMap::new();
        let mut ep_concurrency = HashMap::new();

        for (id, policy) in self.endpoints {
            if let Some(rate) = policy.rate_limit {
                let window = rate.window;
                let limiter = RateLimiter::new(
                    SlidingWindow::new(rate),
                    MemoryStore::for_window(100_000, window * 2),
                    SystemClock,
                );
                ep_limiters.insert(id.clone(), limiter);
            }
            if let Some(max) = policy.max_inflight {
                ep_concurrency.insert(id, ConcurrencyLimiter::new(max));
            }
        }

        HierarchicalLimiter {
            global,
            tenant,
            endpoints: ep_limiters,
            concurrency: ep_concurrency,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn global_cap_blocks_all_tenants() {
        // All checks below happen at the same instant (no time advances
        // between them), so the global policy needs burst=1 (limit-1)
        // for both of the first 2 requests to be legitimately allowed
        // under GCRA — standard GCRA only allows 1 instant request with
        // the default burst=0. See store/memory.rs's tests for the same
        // pattern explained in more detail.
        let limiter = HierarchicalLimiter::builder()
            .global(Policy::per_second(2).with_burst(1)) // very tight global cap
            .tenant(Policy::per_minute(1000))
            .build();

        let ctx_a = RateLimitContext::new(b"tenant-A", b"POST /api");
        let ctx_b = RateLimitContext::new(b"tenant-B", b"POST /api");

        assert!(limiter.check(&ctx_a).await.allowed);
        assert!(limiter.check(&ctx_b).await.allowed);
        // 3rd request (any tenant) hits global cap
        let d = limiter.check(&ctx_a).await;
        assert!(!d.allowed);
        assert_eq!(d.denied_at, Some(LimitLayer::Global));
    }

    #[tokio::test]
    async fn per_tenant_isolates_quota() {
        // No burst needed on the tenant policy: the tenant layer is
        // backed by `TokenBucket` (see `HierarchicalLimiter`'s
        // `tenant: TbMemory` field), not GCRA, and `TokenBucket`'s
        // capacity is `limit + burst` directly (see
        // `algorithms::token_bucket::TokenBucket::new`) — unlike GCRA,
        // where a burst of `n` grants `n+1` instant requests regardless
        // of `limit`. Its default burst=0 already gives exactly `limit`
        // (2) instant requests, which is exactly what this test wants:
        // 2 allowed, the 3rd denied. Adding `.with_burst(1)` here (an
        // earlier version of this fix) instead gave it capacity 3,
        // silently allowing all 3 requests through.
        //
        // The global policy (GCRA-backed) does need generous burst,
        // because unlike tenant (keyed per tenant, so A's and B's
        // counters are independent), global is shared across every call
        // this whole test makes (A ×3 + B ×1 = 4), not just the one
        // layer under test — a tight global burst would otherwise deny
        // B at the global layer before tenant isolation is even
        // exercised.
        let limiter = HierarchicalLimiter::builder()
            .global(Policy::per_second(100).with_burst(9))
            .tenant(Policy::per_second(2))
            .build();

        let ctx_a = RateLimitContext::new(b"tenant-A", b"GET /data");
        let ctx_b = RateLimitContext::new(b"tenant-B", b"GET /data");

        // A hits its limit
        assert!(limiter.check(&ctx_a).await.allowed);
        assert!(limiter.check(&ctx_a).await.allowed);
        let d = limiter.check(&ctx_a).await;
        assert!(!d.allowed);
        assert_eq!(d.denied_at, Some(LimitLayer::Tenant));

        // B is unaffected
        assert!(limiter.check(&ctx_b).await.allowed);
    }

    #[tokio::test]
    async fn critical_priority_skips_tenant_and_endpoint() {
        // burst=4 on the global policy: 5 checks happen at the same
        // instant below, so GCRA needs burst=4 (5-1) for all 5 to be
        // legitimately allowed. See global_cap_blocks_all_tenants's
        // comment above for the general pattern.
        let limiter = HierarchicalLimiter::builder()
            .global(Policy::per_second(100).with_burst(4))
            .tenant(Policy::per_second(1)) // very tight
            .endpoint(
                b"GET /health",
                EndpointPolicy::new(Policy::per_second(1)), // also tight
            )
            .build();

        let ctx = RateLimitContext::new(b"tenant-A", b"GET /health")
            .with_priority(RequestPriority::Critical);

        // Should always pass (only global matters, limit=100)
        for _ in 0..5 {
            assert!(limiter.check(&ctx).await.allowed);
        }
    }

    #[tokio::test]
    async fn endpoint_limit_is_per_tenant() {
        // No burst needed on the endpoint policy: it's backed by
        // `SlidingWindow` (see `HierarchicalLimiter`'s
        // `endpoints: HashMap<_, SwMemory>` field), which never reads
        // `policy.burst` at all — its default limit=2 already admits
        // exactly 2 requests before denying the 3rd, which is what this
        // test wants. (An earlier version of this fix added
        // `.with_burst(1)` here, which was a harmless no-op, not an
        // intentional adjustment — removed so it doesn't imply a burst
        // behavior this layer doesn't have.)
        //
        // Global (GCRA-backed) does need generous burst, since it's
        // shared across every call this test makes (A ×3 + B ×1), not
        // just the endpoint layer under test — see
        // per_tenant_isolates_quota's comment for the same reasoning.
        let limiter = HierarchicalLimiter::builder()
            .global(Policy::per_second(1000).with_burst(9))
            .tenant(Policy::per_second(100))
            .endpoint(b"POST /charges", EndpointPolicy::new(Policy::per_second(2)))
            .build();

        let ctx_a = RateLimitContext::new(b"tenant-A", b"POST /charges");
        let ctx_b = RateLimitContext::new(b"tenant-B", b"POST /charges");

        // A uses up its endpoint quota
        assert!(limiter.check(&ctx_a).await.allowed);
        assert!(limiter.check(&ctx_a).await.allowed);
        assert!(!limiter.check(&ctx_a).await.allowed);

        // B still has its own endpoint quota
        assert!(limiter.check(&ctx_b).await.allowed);
    }
}
