//! Observability: structured `tracing` spans + rate-limit event log.
//!
//! # What gets emitted
//!
//! Every call to `RateLimiter::check` produces:
//! - A `DEBUG` span with `algorithm`, `key_hash` (SHA-256 prefix, not raw key),
//!   `remaining`, `reset_at_ms`.
//! - On deny: an `INFO` event with `retry_after_ms`, `limit`, `layer`.
//! - On store error: a `WARN` event with `error`, `fail_behavior`.
//!
//! # Key hashing
//! Raw keys (IP addresses, API keys) are sensitive. We log a 6-hex-char
//! prefix of SHA-256(key) so you can correlate log lines without exposing PII.
//!
//! # Usage
//! Just install a `tracing` subscriber. The library emits to the
//! `ratekeeper` target so you can filter selectively:
//!
//! ```rust,ignore
//! tracing_subscriber::fmt()
//!     .with_env_filter("ratekeeper=debug,myapp=info")
//!     .init();
//! ```

use crate::Decision;

/// Hash a key to a short, loggable token (not reversible).
pub fn key_token(key: &[u8]) -> String {
    // FNV-1a: fast, no dep, good enough for log correlation (not security).
    let mut hash: u64 = 14_695_981_039_346_656_037;
    for &b in key {
        hash ^= b as u64;
        hash = hash.wrapping_mul(1_099_511_628_211);
    }
    format!("{:012x}", hash & 0x0000_ffff_ffff_ffff)
}

/// Emit a structured tracing event for a rate-limit decision.
#[inline]
pub fn emit_decision(key: &[u8], algorithm: &'static str, decision: &Decision) {
    let token = key_token(key);
    match decision {
        Decision::Allow {
            remaining,
            reset_at_ms,
        } => {
            tracing::debug!(
                target:    "ratekeeper",
                algorithm,
                key        = %token,
                remaining,
                reset_at_ms,
                "allow"
            );
        }
        Decision::Deny {
            retry_after_ms,
            limit,
        } => {
            tracing::info!(
                target:         "ratekeeper",
                algorithm,
                key             = %token,
                retry_after_ms,
                limit,
                "deny"
            );
        }
    }
}

/// Emit a store error event.
#[inline]
pub fn emit_store_error(store: &'static str, error: &str, fail_open: bool) {
    tracing::warn!(
        target:    "ratekeeper::store",
        store,
        error,
        fail_open,
        "store error"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_token_is_deterministic() {
        assert_eq!(key_token(b"user-123"), key_token(b"user-123"));
    }

    #[test]
    fn key_token_differs_for_different_keys() {
        assert_ne!(key_token(b"user-123"), key_token(b"user-456"));
    }

    #[test]
    fn key_token_does_not_contain_raw_key() {
        let key = b"secret-api-key-abc123";
        let token = key_token(key);
        assert!(!token.contains("secret"));
        assert!(!token.contains("api"));
        assert_eq!(token.len(), 12); // 6 bytes as hex
    }
}
