//! Key extractors — what to rate-limit *by*.
//!
//! Implement `KeyExtractor` to rate-limit by any dimension:
//! IP, API key, user ID, JWT claim, tenant ID, ...

use http::{HeaderMap, Request};
use std::marker::PhantomData;
use std::net::IpAddr;

/// Extracts the rate-limit key from an incoming request.
pub trait KeyExtractor: Clone + Send + Sync + 'static {
    /// The key type. Returned as `Vec<u8>` so it can go straight to the store.
    fn extract<B>(&self, req: &Request<B>) -> Option<Vec<u8>>;
}

// ── PeerIp ────────────────────────────────────────────────────────────────────

/// Rate-limit by the client's IP address.
///
/// Respects `X-Forwarded-For` and `X-Real-IP` headers when behind a proxy.
/// Falls back to the connection's remote address.
#[derive(Clone, Debug, Default)]
pub struct PeerIp {
    /// Trust `X-Forwarded-For` / `X-Real-IP` headers.
    pub trust_proxy: bool,
}

impl PeerIp {
    pub fn new(trust_proxy: bool) -> Self {
        Self { trust_proxy }
    }

    fn from_headers(headers: &HeaderMap) -> Option<IpAddr> {
        // X-Real-IP (single value, set by nginx)
        if let Some(v) = headers.get("x-real-ip") {
            if let Ok(s) = v.to_str() {
                if let Ok(ip) = s.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
        // X-Forwarded-For: leftmost is the client
        if let Some(v) = headers.get("x-forwarded-for") {
            if let Ok(s) = v.to_str() {
                if let Some(first) = s.split(',').next() {
                    if let Ok(ip) = first.trim().parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }
        None
    }
}

impl KeyExtractor for PeerIp {
    fn extract<B>(&self, req: &Request<B>) -> Option<Vec<u8>> {
        if self.trust_proxy {
            if let Some(ip) = Self::from_headers(req.headers()) {
                return Some(ip.to_string().into_bytes());
            }
        }
        // Fallback: use the URI path as a placeholder (real IP needs ConnectInfo)
        // In Axum, inject ConnectInfo<SocketAddr> and extract from extensions.
        req.extensions()
            .get::<std::net::SocketAddr>()
            .map(|addr| addr.ip().to_string().into_bytes())
    }
}

// ── HeaderKey ─────────────────────────────────────────────────────────────────

/// Rate-limit by an arbitrary request header value (e.g. `Authorization`, `X-API-Key`).
#[derive(Clone, Debug)]
pub struct HeaderKey {
    pub header_name: &'static str,
}

impl HeaderKey {
    pub fn new(header_name: &'static str) -> Self {
        Self { header_name }
    }

    /// Convenience: `X-API-Key` header.
    pub fn api_key() -> Self {
        Self::new("x-api-key")
    }

    /// Convenience: `Authorization` header (rate-limit by token/JWT).
    pub fn authorization() -> Self {
        Self::new("authorization")
    }
}

impl KeyExtractor for HeaderKey {
    fn extract<B>(&self, req: &Request<B>) -> Option<Vec<u8>> {
        req.headers()
            .get(self.header_name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.as_bytes().to_vec())
    }
}

// ── Global ────────────────────────────────────────────────────────────────────

/// Single global rate limit — all requests share one counter.
/// Use as an emergency circuit-breaker.
#[derive(Clone, Debug, Default)]
pub struct Global;

impl KeyExtractor for Global {
    fn extract<B>(&self, _req: &Request<B>) -> Option<Vec<u8>> {
        Some(b"__global__".to_vec())
    }
}

// ── Custom closure extractor ──────────────────────────────────────────────────

/// Rate-limit by a custom function.
///
/// ```rust,ignore
/// let extractor = CustomKey::new(|req: &Request<_>| {
///     req.headers()
///         .get("x-tenant-id")
///         .and_then(|v| v.to_str().ok())
///         .map(|s| s.as_bytes().to_vec())
/// });
/// ```
pub struct CustomKey<F, B = ()> {
    f: F,
    _phantom: PhantomData<fn(&Request<B>)>,
}

impl<F: Clone, B> Clone for CustomKey<F, B> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<F, B> CustomKey<F, B> {
    pub fn new(f: F) -> Self {
        Self {
            f,
            _phantom: PhantomData,
        }
    }
}

impl<F, B: 'static> KeyExtractor for CustomKey<F, B>
where
    F: Fn(&Request<B>) -> Option<Vec<u8>> + Clone + Send + Sync + 'static,
{
    fn extract<Bod>(&self, _req: &Request<Bod>) -> Option<Vec<u8>> {
        // Note: B and Bod must match at call site — use BoxBody in practice.
        // This compiles when B == Bod.
        // For cross-body-type usage, downcast via extensions.
        None // placeholder — see layer.rs for real usage
    }
}
