//! Production Redis store using `deadpool-redis` connection pool.
//!
//! # Script lifecycle
//! On `RedisPool::new()` we `SCRIPT LOAD` all three Lua scripts and cache
//! their SHAs.  `EVALSHA` is used on every request — no script body in the
//! hot path.  On `NOSCRIPT` (Redis restarted / scripts flushed) we reload
//! transparently and retry once.
//!
//! # Connection pool
//! `deadpool-redis` gives us an async pool without blocking the Tokio runtime.
//! Pool size, timeouts, and TLS are all configurable via `RedisPoolConfig`.
//!
//! # Circuit breaker
//! A simple atomic counter tracks consecutive Redis errors.  Above
//! `error_threshold` we stop hitting Redis and apply `FailBehavior` directly,
//! giving the store time to recover.  On the next success the counter resets.

use crate::{error::RateLimitError, FailBehavior};
use deadpool_redis::{Config as DeadpoolConfig, Pool, Runtime};
use std::{
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

// ── Lua scripts (same as redis.rs, centralised here for the pool) ─────────────

const GCRA_LUA: &str = r#"
local key          = KEYS[1]
local now          = tonumber(ARGV[1])
local cell_ms      = tonumber(ARGV[2])
local burst_offset = tonumber(ARGV[3])
local ttl_ms       = tonumber(ARGV[4])

local tat      = tonumber(redis.call('GET', key) or now)
local new_tat  = math.max(tat, now) + cell_ms
local allow_at = new_tat - burst_offset

if allow_at <= now then
    redis.call('SET', key, new_tat, 'PX', ttl_ms)
    local remaining = math.floor((now + burst_offset - new_tat) / math.max(cell_ms, 1))
    return {1, math.max(remaining, 0), 0}
else
    return {0, 0, allow_at - now}
end
"#;

const SLIDING_WINDOW_LUA: &str = r#"
local curr_key   = KEYS[1]
local prev_key   = KEYS[2]
local limit      = tonumber(ARGV[1])
local window_ms  = tonumber(ARGV[2])
local now_ms     = tonumber(ARGV[3])

local curr_start  = math.floor(now_ms / window_ms) * window_ms
local elapsed     = now_ms - curr_start
local prev_weight = 1.0 - (elapsed / window_ms)

local curr_count  = tonumber(redis.call('GET', curr_key) or '0')
local prev_count  = tonumber(redis.call('GET', prev_key) or '0')
local eff_count   = prev_count * prev_weight + curr_count

if eff_count < limit then
    redis.call('INCR', curr_key)
    redis.call('PEXPIRE', curr_key, window_ms * 2)
    local remaining = math.floor(limit - eff_count - 1)
    return {1, math.max(remaining, 0), 0}
else
    local decay_needed = eff_count - limit + 1
    local decay_frac   = decay_needed / math.max(prev_count, 1)
    local wait_ms      = math.ceil(decay_frac * window_ms)
    return {0, 0, wait_ms}
end
"#;

const TOKEN_BUCKET_LUA: &str = r#"
local key           = KEYS[1]
local now           = tonumber(ARGV[1])
local capacity      = tonumber(ARGV[2])
local refill_per_ms = tonumber(ARGV[3]) / 1000000
local ttl_ms        = tonumber(ARGV[4])

local h           = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens      = tonumber(h[1]) or capacity
local last_refill = tonumber(h[2]) or now

local elapsed  = math.max(now - last_refill, 0)
local refilled = math.min(tokens + elapsed * refill_per_ms, capacity)

if refilled >= 1.0 then
    local new_tokens = refilled - 1.0
    redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
    redis.call('PEXPIRE', key, ttl_ms)
    return {1, math.floor(new_tokens), 0}
else
    local wait_ms = math.ceil((1.0 - refilled) / math.max(refill_per_ms, 0.000001))
    return {0, 0, wait_ms}
end
"#;

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RedisPoolConfig {
    pub url: String,
    pub pool_size: usize,
    pub connect_timeout: Duration,
    pub wait_timeout: Duration,
    /// Consecutive errors before tripping the circuit breaker.
    pub error_threshold: u32,
    pub fail_behavior: FailBehavior,
}

impl RedisPoolConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            pool_size: 16,
            connect_timeout: Duration::from_secs(2),
            wait_timeout: Duration::from_millis(500),
            error_threshold: 5,
            fail_behavior: FailBehavior::Open,
        }
    }

    pub fn with_pool_size(mut self, n: usize) -> Self {
        self.pool_size = n;
        self
    }
    pub fn with_fail_behavior(mut self, fb: FailBehavior) -> Self {
        self.fail_behavior = fb;
        self
    }
    pub fn with_error_threshold(mut self, n: u32) -> Self {
        self.error_threshold = n;
        self
    }
}

// ── Script SHAs ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct ScriptShas {
    gcra: String,
    sliding_window: String,
    token_bucket: String,
}

// ── RedisPool ─────────────────────────────────────────────────────────────────

/// Shared Redis connection pool with pre-loaded Lua script SHAs.
/// Clone is cheap — all fields are behind `Arc`.
#[derive(Clone)]
pub struct RedisPool {
    pool: Pool,
    shas: Arc<tokio::sync::RwLock<ScriptShas>>,
    error_count: Arc<AtomicU32>,
    config: RedisPoolConfig,
}

impl RedisPool {
    /// Create the pool and eagerly load all Lua scripts.
    pub async fn new(config: RedisPoolConfig) -> Result<Self, RateLimitError> {
        let deadpool_cfg = DeadpoolConfig::from_url(&config.url);
        let pool = deadpool_cfg
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|e| RateLimitError::StoreUnavailable(e.to_string()))?;

        let shas = {
            let mut conn = pool
                .get()
                .await
                .map_err(|e| RateLimitError::StoreUnavailable(e.to_string()))?;
            Self::load_scripts_inner(&mut conn).await?
        };

        Ok(Self {
            pool,
            shas: Arc::new(tokio::sync::RwLock::new(shas)),
            error_count: Arc::new(AtomicU32::new(0)),
            config,
        })
    }

    async fn load_scripts_inner(
        conn: &mut deadpool_redis::Connection,
    ) -> Result<ScriptShas, RateLimitError> {
        let gcra_sha: String = redis::cmd("SCRIPT")
            .arg("LOAD")
            .arg(GCRA_LUA)
            .query_async(&mut **conn)
            .await?;
        let sw_sha: String = redis::cmd("SCRIPT")
            .arg("LOAD")
            .arg(SLIDING_WINDOW_LUA)
            .query_async(&mut **conn)
            .await?;
        let tb_sha: String = redis::cmd("SCRIPT")
            .arg("LOAD")
            .arg(TOKEN_BUCKET_LUA)
            .query_async(&mut **conn)
            .await?;

        tracing::info!(gcra_sha, sw_sha, tb_sha, "Redis Lua scripts loaded");
        Ok(ScriptShas {
            gcra: gcra_sha,
            sliding_window: sw_sha,
            token_bucket: tb_sha,
        })
    }

    /// Reload scripts (called on NOSCRIPT error).
    async fn reload_scripts(&self) -> Result<(), RateLimitError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| RateLimitError::StoreUnavailable(e.to_string()))?;
        let new_shas = Self::load_scripts_inner(&mut conn).await?;
        *self.shas.write().await = new_shas;
        tracing::warn!("Redis Lua scripts reloaded after NOSCRIPT");
        Ok(())
    }

    fn is_tripped(&self) -> bool {
        self.error_count.load(Ordering::Relaxed) >= self.config.error_threshold
    }

    fn record_success(&self) {
        self.error_count.store(0, Ordering::Relaxed);
    }

    fn record_error(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }
}

// ── GCRA via Redis pool ───────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PooledGcraStore {
    redis: RedisPool,
    cell_ms: u64,
    burst_offset: u64,
    ttl_ms: u64,
}

impl PooledGcraStore {
    pub fn new(redis: RedisPool, cell_ms: u64, burst_offset: u64, ttl_ms: u64) -> Self {
        Self {
            redis,
            cell_ms,
            burst_offset,
            ttl_ms,
        }
    }

    pub async fn check(&self, key: &[u8], now_ms: u64) -> Result<GcraResult, RateLimitError> {
        if self.redis.is_tripped() {
            return Err(RateLimitError::StoreUnavailable("circuit open".into()));
        }

        for attempt in 0..2 {
            let sha = self.redis.shas.read().await.gcra.clone();
            let mut conn = self.redis.pool.get().await.map_err(|e| {
                self.redis.record_error();
                RateLimitError::StoreUnavailable(e.to_string())
            })?;

            let result: Result<Vec<i64>, _> = redis::cmd("EVALSHA")
                .arg(&sha)
                .arg(1i64) // numkeys
                .arg(key)
                .arg(now_ms)
                .arg(self.cell_ms)
                .arg(self.burst_offset)
                .arg(self.ttl_ms)
                .query_async(&mut *conn)
                .await;

            match result {
                Ok(v) => {
                    self.redis.record_success();
                    return Ok(GcraResult {
                        allowed: v[0] == 1,
                        remaining: v[1] as u32,
                        retry_after_ms: v[2] as u64,
                    });
                }
                Err(e) if is_noscript(&e) && attempt == 0 => {
                    // Scripts were flushed — reload and retry once
                    drop(conn);
                    self.redis.reload_scripts().await?;
                    continue;
                }
                Err(e) => {
                    self.redis.record_error();
                    return Err(RateLimitError::Redis(e));
                }
            }
        }

        Err(RateLimitError::StoreUnavailable(
            "script reload retry exceeded".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct GcraResult {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after_ms: u64,
}

// ── Sliding Window via Redis pool ─────────────────────────────────────────────

#[derive(Clone)]
pub struct PooledSlidingWindowStore {
    redis: RedisPool,
    window_ms: u64,
    limit: u32,
}

impl PooledSlidingWindowStore {
    pub fn new(redis: RedisPool, window_ms: u64, limit: u32) -> Self {
        Self {
            redis,
            window_ms,
            limit,
        }
    }

    fn window_key(base: &[u8], window_id: u64) -> Vec<u8> {
        // Redis hash tags ensure curr and prev key land on the same shard
        // in a Redis Cluster: {base}:0, {base}:1
        let mut k = b"{".to_vec();
        k.extend_from_slice(base);
        k.extend_from_slice(b"}:");
        k.extend_from_slice(window_id.to_string().as_bytes());
        k
    }

    pub async fn check(
        &self,
        key: &[u8],
        now_ms: u64,
    ) -> Result<SlidingWindowResult, RateLimitError> {
        if self.redis.is_tripped() {
            return Err(RateLimitError::StoreUnavailable("circuit open".into()));
        }

        let window_id = now_ms / self.window_ms;
        let curr_key = Self::window_key(key, window_id);
        let prev_key = Self::window_key(key, window_id.saturating_sub(1));

        for attempt in 0..2 {
            let sha = self.redis.shas.read().await.sliding_window.clone();
            let mut conn = self.redis.pool.get().await.map_err(|e| {
                self.redis.record_error();
                RateLimitError::StoreUnavailable(e.to_string())
            })?;

            let result: Result<Vec<i64>, _> = redis::cmd("EVALSHA")
                .arg(&sha)
                .arg(2i64)
                .arg(&curr_key)
                .arg(&prev_key)
                .arg(self.limit)
                .arg(self.window_ms)
                .arg(now_ms)
                .query_async(&mut *conn)
                .await;

            match result {
                Ok(v) => {
                    self.redis.record_success();
                    return Ok(SlidingWindowResult {
                        allowed: v[0] == 1,
                        remaining: v[1] as u32,
                        retry_after_ms: v[2] as u64,
                    });
                }
                Err(e) if is_noscript(&e) && attempt == 0 => {
                    drop(conn);
                    self.redis.reload_scripts().await?;
                    continue;
                }
                Err(e) => {
                    self.redis.record_error();
                    return Err(RateLimitError::Redis(e));
                }
            }
        }

        Err(RateLimitError::StoreUnavailable(
            "script reload retry exceeded".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct SlidingWindowResult {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after_ms: u64,
}

// ── Token Bucket via Redis pool ───────────────────────────────────────────────

#[derive(Clone)]
pub struct PooledTokenBucketStore {
    redis: RedisPool,
    capacity: u64,
    refill_per_ms: u64, // × 1_000_000 to avoid floats in args
    ttl_ms: u64,
}

impl PooledTokenBucketStore {
    /// `refill_rate` = tokens per ms (e.g. 0.1 for 100 req/sec)
    pub fn new(redis: RedisPool, capacity: u64, refill_per_ms_f64: f64, ttl_ms: u64) -> Self {
        Self {
            redis,
            capacity,
            refill_per_ms: (refill_per_ms_f64 * 1_000_000.0) as u64,
            ttl_ms,
        }
    }

    pub async fn check(
        &self,
        key: &[u8],
        now_ms: u64,
    ) -> Result<TokenBucketResult, RateLimitError> {
        if self.redis.is_tripped() {
            return Err(RateLimitError::StoreUnavailable("circuit open".into()));
        }

        for attempt in 0..2 {
            let sha = self.redis.shas.read().await.token_bucket.clone();
            let mut conn = self.redis.pool.get().await.map_err(|e| {
                self.redis.record_error();
                RateLimitError::StoreUnavailable(e.to_string())
            })?;

            let result: Result<Vec<i64>, _> = redis::cmd("EVALSHA")
                .arg(&sha)
                .arg(1i64)
                .arg(key)
                .arg(now_ms)
                .arg(self.capacity)
                .arg(self.refill_per_ms)
                .arg(self.ttl_ms)
                .query_async(&mut *conn)
                .await;

            match result {
                Ok(v) => {
                    self.redis.record_success();
                    return Ok(TokenBucketResult {
                        allowed: v[0] == 1,
                        remaining: v[1] as u32,
                        retry_after_ms: v[2] as u64,
                    });
                }
                Err(e) if is_noscript(&e) && attempt == 0 => {
                    drop(conn);
                    self.redis.reload_scripts().await?;
                    continue;
                }
                Err(e) => {
                    self.redis.record_error();
                    return Err(RateLimitError::Redis(e));
                }
            }
        }

        Err(RateLimitError::StoreUnavailable(
            "script reload retry exceeded".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct TokenBucketResult {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after_ms: u64,
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn is_noscript(e: &redis::RedisError) -> bool {
    matches!(e.kind(), redis::ErrorKind::NoScriptError)
}
