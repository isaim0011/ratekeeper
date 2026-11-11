use std::time::Duration;

/// Rate limit policy: how many requests are allowed in what window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Maximum number of requests allowed per window.
    pub limit: u32,
    /// The time window.
    pub window: Duration,
    /// Maximum burst above the sustained rate (token bucket / GCRA).
    /// Set to `0` for no extra burst (strict).
    pub burst: u32,
}

impl Policy {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            burst: 0,
        }
    }

    pub fn with_burst(mut self, burst: u32) -> Self {
        self.burst = burst;
        self
    }

    /// Convenience: N requests per second.
    pub fn per_second(n: u32) -> Self {
        Self::new(n, Duration::from_secs(1))
    }

    /// Convenience: N requests per minute.
    pub fn per_minute(n: u32) -> Self {
        Self::new(n, Duration::from_secs(60))
    }

    /// Convenience: N requests per hour.
    pub fn per_hour(n: u32) -> Self {
        Self::new(n, Duration::from_secs(3600))
    }

    /// Window in milliseconds.
    #[inline]
    pub fn window_ms(&self) -> u64 {
        self.window.as_millis() as u64
    }

    /// Time between individual cells/tokens in ms (window / limit).
    #[inline]
    pub fn cell_ms(&self) -> u64 {
        self.window_ms() / self.limit as u64
    }
}
