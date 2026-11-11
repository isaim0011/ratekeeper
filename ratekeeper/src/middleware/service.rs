use super::extractors::KeyExtractor;
use crate::{algorithms::Algorithm, clock::Clock, store::Store, Decision, RateLimiter};
use axum_core::{body::Body, response::Response};
use http::{header, Request, StatusCode};
use pin_project_lite::pin_project;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::Service;

#[derive(Clone)]
pub struct RateLimitService<A, St, C, K, S> {
    pub(crate) inner: S,
    pub(crate) limiter: Arc<RateLimiter<A, St, C>>,
    pub(crate) extractor: K,
}

impl<A, St, C, K, S> Service<Request<Body>> for RateLimitService<A, St, C, K, S>
where
    A: Algorithm + 'static,
    St: Store<State = A::State> + 'static,
    C: Clock + 'static,
    K: KeyExtractor,
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = RateLimitFuture<S>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let key = self
            .extractor
            .extract(&req)
            .unwrap_or_else(|| b"__unknown__".to_vec());

        let limiter = Arc::clone(&self.limiter);
        let mut inner = self.inner.clone();
        let policy = limiter.algorithm.policy().clone();

        let fut = async move {
            let decision = limiter.check(&key).await;
            match decision {
                Decision::Allow {
                    remaining,
                    reset_at_ms,
                } => {
                    let mut resp = inner.call(req).await?;
                    let headers = resp.headers_mut();
                    headers.insert(
                        "x-ratelimit-limit",
                        policy.limit.to_string().parse().unwrap(),
                    );
                    headers.insert(
                        "x-ratelimit-remaining",
                        remaining.to_string().parse().unwrap(),
                    );
                    if reset_at_ms > 0 {
                        headers.insert(
                            "x-ratelimit-reset",
                            reset_at_ms.to_string().parse().unwrap(),
                        );
                    }
                    Ok(resp)
                }
                Decision::Deny {
                    retry_after_ms,
                    limit,
                } => {
                    let retry_secs = (retry_after_ms / 1_000).max(1);
                    let body = format!(
                        r#"{{"error":"rate_limit_exceeded","limit":{limit},"retry_after_ms":{retry_after_ms}}}"#
                    );
                    let resp = Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header(header::CONTENT_TYPE, "application/json")
                        .header("x-ratelimit-limit", limit.to_string())
                        .header("x-ratelimit-remaining", "0")
                        .header("retry-after", retry_secs.to_string())
                        .body(Body::from(body))
                        .unwrap();
                    Ok(resp)
                }
            }
        };

        RateLimitFuture {
            inner: Box::pin(fut),
        }
    }
}

pin_project! {
    pub struct RateLimitFuture<S: Service<Request<Body>>> {
        #[pin]
        inner: Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>,
    }
}

impl<S> Future for RateLimitFuture<S>
where
    S: Service<Request<Body>, Response = Response>,
{
    type Output = Result<Response, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}
