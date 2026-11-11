use super::{extractors::KeyExtractor, service::RateLimitService};
use crate::{algorithms::Algorithm, clock::Clock, store::Store, RateLimiter};
use std::sync::Arc;
use tower::{Layer, Service};

/// Tower `Layer` that wraps any `Service` with rate limiting.
///
/// # Type parameters
/// - `A` — algorithm (`Gcra`, `TokenBucket`, `SlidingWindow`)
/// - `S` — backing store (`MemoryStore`, `RedisGcraStore`, …)
/// - `C` — clock (`SystemClock`, `MockClock`)
/// - `K` — key extractor (`PeerIp`, `HeaderKey`, `Global`, …)
#[derive(Clone)]
pub struct RateLimitLayer<A, St, C, K> {
    limiter: Arc<RateLimiter<A, St, C>>,
    extractor: K,
}

impl<A, St, C, K> RateLimitLayer<A, St, C, K>
where
    A: Algorithm,
    St: Store<State = A::State>,
    C: Clock,
    K: KeyExtractor,
{
    pub fn new(limiter: RateLimiter<A, St, C>, extractor: K) -> Self {
        Self {
            limiter: Arc::new(limiter),
            extractor,
        }
    }
}

impl<A, St, C, K, S> Layer<S> for RateLimitLayer<A, St, C, K>
where
    A: Algorithm + Clone,
    St: Store<State = A::State> + Clone,
    C: Clock,
    K: KeyExtractor,
    S: Service<http::Request<axum_core::body::Body>>,
{
    type Service = RateLimitService<A, St, C, K, S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            limiter: Arc::clone(&self.limiter),
            extractor: self.extractor.clone(),
        }
    }
}
