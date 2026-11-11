//! Tower middleware layer.
//!
//! Works with Axum, Tonic, Hyper — anything on Tower.
//!
//! # Usage (Axum)
//! ```rust,ignore
//! use ratekeeper::{
//!     RateLimiter, Gcra, Policy,
//!     middleware::{RateLimitLayer, extractors::PeerIp},
//! };
//! use ratekeeper::store::memory::MemoryStore;
//!
//! let store   = MemoryStore::for_window(100_000, std::time::Duration::from_secs(1));
//! let gcra    = Gcra::new(Policy::per_second(100));
//! let limiter = RateLimiter::new(gcra, store, ratekeeper::SystemClock);
//!
//! let app = Router::new()
//!     .route("/", get(handler))
//!     .layer(RateLimitLayer::new(limiter, PeerIp));
//! ```
//!
//! # Response headers set automatically
//! - `X-RateLimit-Limit`     — the policy limit
//! - `X-RateLimit-Remaining` — tokens left in this window
//! - `X-RateLimit-Reset`     — epoch-ms when window resets
//! - `Retry-After`           — seconds until retry (on 429 only)

pub mod extractors;
pub mod layer;
pub mod service;

pub use extractors::KeyExtractor;
pub use layer::RateLimitLayer;
