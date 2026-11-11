//! Prometheus metrics for rate limiting decisions.
//!
//! # Metrics emitted
//!
//! | Name | Type | Labels | Description |
//! |---|---|---|---|
//! | `ratelimit_requests_total` | Counter | algorithm, decision, layer | All decisions |
//! | `ratelimit_denied_total` | Counter | algorithm, layer | Denied requests |
//! | `ratelimit_remaining` | Histogram | algorithm | Remaining tokens on allow |
//! | `ratelimit_retry_after_ms` | Histogram | algorithm | Retry-after on deny |
//! | `ratelimit_store_errors_total` | Counter | store, error_type | Store failures |
//! | `ratelimit_store_latency_ms` | Histogram | store, operation | Store round-trip latency |
//! | `ratelimit_circuit_open` | Gauge | store | 1 when circuit breaker is tripped |
//!
//! # Usage
//!
//! ```rust,ignore
//! use ratekeeper::metrics::Metrics;
//! use prometheus::Registry;
//!
//! let registry = Registry::new();
//! let metrics  = Metrics::register(&registry).unwrap();
//!
//! // Pass metrics into your limiter or Tower layer.
//! // All recording happens automatically in the instrumented wrapper.
//! ```

use std::sync::Arc;

// We use a simple hand-rolled metrics abstraction so the crate doesn't
// hard-depend on a specific Prometheus client. Users can bridge to
// `prometheus`, `metrics`, or `opentelemetry` via the `MetricsSink` trait.

/// Sink for rate-limit metric events. Implement this to plug in any
/// metrics backend (Prometheus, OpenTelemetry, StatsD, etc.).
pub trait MetricsSink: Send + Sync + 'static {
    fn record_decision(&self, event: &DecisionEvent);
    fn record_store_latency(&self, store: &str, operation: &str, latency_ms: f64);
    fn record_store_error(&self, store: &str, error_type: &str);
    fn set_circuit_open(&self, store: &str, open: bool);
}

/// A single rate-limit decision event.
#[derive(Debug, Clone)]
pub struct DecisionEvent {
    pub algorithm: &'static str,
    pub layer: &'static str,
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after_ms: u64,
    /// Wall-clock ms spent in the store (latency).
    pub store_latency_ms: f64,
}

// ── NoopSink ──────────────────────────────────────────────────────────────────

/// Default no-op sink — zero overhead when metrics are disabled.
#[derive(Clone, Default)]
pub struct NoopSink;

impl MetricsSink for NoopSink {
    fn record_decision(&self, _: &DecisionEvent) {}
    fn record_store_latency(&self, _: &str, _: &str, _: f64) {}
    fn record_store_error(&self, _: &str, _: &str) {}
    fn set_circuit_open(&self, _: &str, _: bool) {}
}

// ── PrometheusSink ────────────────────────────────────────────────────────────

/// Prometheus-compatible sink using `prometheus` crate.
/// Feature-gated under `feature = "prometheus"` (not wired yet — add to Cargo.toml
/// when ready). Shown here as the reference implementation.
#[cfg(feature = "prometheus")]
pub mod prometheus_sink {
    use super::{DecisionEvent, MetricsSink};
    use prometheus::{
        exponential_buckets, histogram_opts, opts, CounterVec, GaugeVec, HistogramVec, Registry,
    };

    pub struct PrometheusSink {
        requests_total: CounterVec,
        denied_total: CounterVec,
        remaining: HistogramVec,
        retry_after_ms: HistogramVec,
        store_errors: CounterVec,
        store_latency: HistogramVec,
        circuit_open: GaugeVec,
    }

    impl PrometheusSink {
        pub fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
            let requests_total = CounterVec::new(
                opts!("ratelimit_requests_total", "Total rate limit decisions"),
                &["algorithm", "decision", "layer"],
            )?;
            let denied_total = CounterVec::new(
                opts!("ratelimit_denied_total", "Total denied requests"),
                &["algorithm", "layer"],
            )?;
            let remaining = HistogramVec::new(
                histogram_opts!(
                    "ratelimit_remaining",
                    "Remaining tokens/slots on allow",
                    exponential_buckets(1.0, 2.0, 12)?
                ),
                &["algorithm"],
            )?;
            let retry_after_ms = HistogramVec::new(
                histogram_opts!(
                    "ratelimit_retry_after_ms",
                    "Retry-after on deny (ms)",
                    vec![10.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0, 60_000.0]
                ),
                &["algorithm"],
            )?;
            let store_errors = CounterVec::new(
                opts!("ratelimit_store_errors_total", "Store failures"),
                &["store", "error_type"],
            )?;
            let store_latency = HistogramVec::new(
                histogram_opts!(
                    "ratelimit_store_latency_ms",
                    "Store round-trip latency (ms)",
                    vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0]
                ),
                &["store", "operation"],
            )?;
            let circuit_open = GaugeVec::new(
                opts!(
                    "ratelimit_circuit_open",
                    "1 when circuit breaker is tripped"
                ),
                &["store"],
            )?;

            registry.register(Box::new(requests_total.clone()))?;
            registry.register(Box::new(denied_total.clone()))?;
            registry.register(Box::new(remaining.clone()))?;
            registry.register(Box::new(retry_after_ms.clone()))?;
            registry.register(Box::new(store_errors.clone()))?;
            registry.register(Box::new(store_latency.clone()))?;
            registry.register(Box::new(circuit_open.clone()))?;

            Ok(Self {
                requests_total,
                denied_total,
                remaining,
                retry_after_ms,
                store_errors,
                store_latency,
                circuit_open,
            })
        }
    }

    impl MetricsSink for PrometheusSink {
        fn record_decision(&self, e: &DecisionEvent) {
            let decision = if e.allowed { "allow" } else { "deny" };
            self.requests_total
                .with_label_values(&[e.algorithm, decision, e.layer])
                .inc();

            if e.allowed {
                self.remaining
                    .with_label_values(&[e.algorithm])
                    .observe(e.remaining as f64);
            } else {
                self.denied_total
                    .with_label_values(&[e.algorithm, e.layer])
                    .inc();
                self.retry_after_ms
                    .with_label_values(&[e.algorithm])
                    .observe(e.retry_after_ms as f64);
            }
        }

        fn record_store_latency(&self, store: &str, op: &str, latency_ms: f64) {
            self.store_latency
                .with_label_values(&[store, op])
                .observe(latency_ms);
        }

        fn record_store_error(&self, store: &str, error_type: &str) {
            self.store_errors
                .with_label_values(&[store, error_type])
                .inc();
        }

        fn set_circuit_open(&self, store: &str, open: bool) {
            self.circuit_open
                .with_label_values(&[store])
                .set(if open { 1.0 } else { 0.0 });
        }
    }
}

// ── InstrumentedStore ─────────────────────────────────────────────────────────

use crate::{error::RateLimitError, store::Store};
use std::time::Instant;

/// Wraps any `Store` and records latency + errors into a `MetricsSink`.
pub struct InstrumentedStore<S, M> {
    inner: S,
    metrics: Arc<M>,
    store_name: &'static str,
}

impl<S, M> InstrumentedStore<S, M>
where
    S: Store,
    M: MetricsSink,
{
    pub fn new(inner: S, metrics: Arc<M>, store_name: &'static str) -> Self {
        Self {
            inner,
            metrics,
            store_name,
        }
    }
}

impl<S, M> Store for InstrumentedStore<S, M>
where
    S: Store,
    M: MetricsSink,
{
    type State = S::State;

    async fn fetch_and_update<'a, F>(
        &'a self,
        key: &'a [u8],
        update_fn: F,
        now_ms: u64,
    ) -> Result<S::State, RateLimitError>
    where
        F: FnOnce(Option<&S::State>) -> S::State + Send + 'a,
    {
        let start = Instant::now();
        let result = self.inner.fetch_and_update(key, update_fn, now_ms).await;
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        match &result {
            Ok(_) => self
                .metrics
                .record_store_latency(self.store_name, "check", elapsed_ms),
            Err(e) => self
                .metrics
                .record_store_error(self.store_name, error_kind(e)),
        }

        result
    }
}

fn error_kind(e: &RateLimitError) -> &'static str {
    match e {
        RateLimitError::StoreUnavailable(_) => "unavailable",
        RateLimitError::Serialization(_) => "serialization",
        RateLimitError::Internal(_) => "internal",
        #[cfg(feature = "redis")]
        RateLimitError::Redis(_) => "redis",
    }
}

// ── tracing spans ─────────────────────────────────────────────────────────────

/// Emit a `tracing` span around a rate limit decision.
/// Zero-cost when the `tracing` subscriber is at WARN level.
#[macro_export]
macro_rules! trace_decision {
    ($decision:expr, $key:expr, $algorithm:literal) => {
        match &$decision {
            $crate::Decision::Allow { remaining, .. } => {
                tracing::debug!(
                    target: "ratekeeper",
                    algorithm = $algorithm,
                    key        = ?$key,
                    remaining  = remaining,
                    "allowed"
                );
            }
            $crate::Decision::Deny { retry_after_ms, limit } => {
                tracing::info!(
                    target: "ratekeeper",
                    algorithm      = $algorithm,
                    key            = ?$key,
                    retry_after_ms = retry_after_ms,
                    limit          = limit,
                    "denied"
                );
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        algorithms::gcra::Gcra, clock::MockClock, store::memory::MemoryStore, Policy, RateLimiter,
    };
    use std::{
        sync::atomic::{AtomicU32, Ordering},
        time::Duration,
    };

    // Simple counting sink for tests
    #[derive(Default)]
    struct CountingSink {
        allowed: AtomicU32,
        denied: AtomicU32,
        errors: AtomicU32,
    }

    impl MetricsSink for CountingSink {
        fn record_decision(&self, e: &DecisionEvent) {
            if e.allowed {
                self.allowed.fetch_add(1, Ordering::Relaxed);
            } else {
                self.denied.fetch_add(1, Ordering::Relaxed);
            }
        }
        fn record_store_latency(&self, _: &str, _: &str, _: f64) {}
        fn record_store_error(&self, _: &str, _: &str) {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        fn set_circuit_open(&self, _: &str, _: bool) {}
    }

    #[tokio::test]
    async fn instrumented_store_records_latency() {
        let inner = MemoryStore::for_window(1024, Duration::from_secs(1));
        let sink = Arc::new(CountingSink::default());
        let store = InstrumentedStore::new(inner, Arc::clone(&sink), "memory");
        let gcra = Gcra::new(Policy::per_second(5));
        let clock = MockClock::new(0);
        let lim = RateLimiter::new(gcra, store, clock);

        for _ in 0..5 {
            lim.check(b"k").await;
        }
        // No assertion on latency values — just ensure it doesn't panic
        // and that the store is callable.
    }
}
