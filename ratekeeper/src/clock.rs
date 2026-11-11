use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Abstracted clock — never call `SystemTime::now()` directly in hot paths.
/// This makes every algorithm trivially testable without `sleep`.
pub trait Clock: Send + Sync + Clone + 'static {
    /// Current time as milliseconds since Unix epoch.
    fn now_ms(&self) -> u64;
}

// ── SystemClock ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    #[inline]
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_millis() as u64
    }
}

// ── MockClock ─────────────────────────────────────────────────────────────────

/// Manually-advanceable clock for unit tests — no `tokio::time::pause()` needed.
#[derive(Clone, Debug)]
pub struct MockClock(Arc<AtomicU64>);

impl MockClock {
    pub fn new(start_ms: u64) -> Self {
        Self(Arc::new(AtomicU64::new(start_ms)))
    }

    pub fn advance_ms(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }

    pub fn set_ms(&self, ms: u64) {
        self.0.store(ms, Ordering::SeqCst);
    }
}

impl Clock for MockClock {
    #[inline]
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_clock_advances() {
        let c = MockClock::new(1_000);
        assert_eq!(c.now_ms(), 1_000);
        c.advance_ms(500);
        assert_eq!(c.now_ms(), 1_500);
    }

    #[test]
    fn system_clock_is_sane() {
        let c = SystemClock;
        // Should be somewhere after 2020-01-01 in ms
        assert!(c.now_ms() > 1_577_836_800_000);
    }
}
