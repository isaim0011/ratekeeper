//! Redis-backed store using atomic Lua scripts (`EVALSHA`).
//!
//! # Why Lua scripts?
//! `GET` → check → `INCR` is a TOCTOU race: two requests can both read 99,
//! both pass, both increment to 100 → 101 requests allowed.
//! Lua scripts execute atomically server-side — one round-trip, no race.
//!
//! # Script lifecycle
//! Scripts are loaded with `SCRIPT LOAD` at startup → SHA stored → all
//! requests use `EVALSHA <sha> ...`.  If Redis restarts (losing scripts),
//! we detect `NOSCRIPT` and reload automatically.
//!
//! # Serialization
//! State is serialized to `Vec<u8>` via `bincode` and stored as a Redis string.
//! TTL = 2 × window so keys that stop arriving expire automatically.

use crate::{error::RateLimitError, store::Store};
use redis::{aio::ConnectionManager, Script};

// ── Lua: Generic atomic fetch-and-update ─────────────────────────────────────
//
// We store the serialized state as a Redis BLOB.
// The actual update logic lives in Rust (passed as a closure).
// So for Redis, we do two round-trips:
//   1. GET current state
//   2. SET new state (with Lua GETSET to prevent TOCTOU)
//
// For true atomic logic (sliding window counter), we provide purpose-built
// Lua scripts in the `scripts` module below.

pub mod scripts {
    /// Sliding window counter — two integer fields, weighted sum.
    /// KEYS[1] = current window key, KEYS[2] = previous window key
    /// ARGV[1] = limit, ARGV[2] = window_ms, ARGV[3] = now_ms
    /// Returns: { allowed (0/1), remaining, retry_after_ms }
    pub const SLIDING_WINDOW_LUA: &str = r#"
local curr_key  = KEYS[1]
local prev_key  = KEYS[2]
local limit     = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local now_ms    = tonumber(ARGV[3])

local curr_start = math.floor(now_ms / window_ms) * window_ms
local elapsed    = now_ms - curr_start
local prev_weight = 1.0 - (elapsed / window_ms)

local curr_count = tonumber(redis.call('GET', curr_key) or '0')
local prev_count = tonumber(redis.call('GET', prev_key) or '0')
local eff_count  = prev_count * prev_weight + curr_count

if eff_count < limit then
    redis.call('INCR', curr_key)
    redis.call('PEXPIRE', curr_key, window_ms * 2)
    local remaining = math.floor(limit - eff_count - 1)
    return {1, remaining, 0}
else
    -- time until prev decays enough
    local decay_needed = eff_count - limit + 1
    local decay_frac   = decay_needed / math.max(prev_count, 1)
    local wait_ms      = math.ceil(decay_frac * window_ms)
    return {0, 0, wait_ms}
end
"#;

    /// GCRA — single TAT key (u64 ms stored as string).
    /// KEYS[1] = key
    /// ARGV[1] = now_ms, ARGV[2] = cell_ms, ARGV[3] = burst_offset_ms, ARGV[4] = ttl_ms
    /// Returns: { allowed (0/1), remaining, retry_after_ms }
    pub const GCRA_LUA: &str = r#"
local key          = KEYS[1]
local now          = tonumber(ARGV[1])
local cell_ms      = tonumber(ARGV[2])
local burst_offset = tonumber(ARGV[3])
local ttl_ms       = tonumber(ARGV[4])

local tat     = tonumber(redis.call('GET', key) or now)
local new_tat = math.max(tat, now) + cell_ms
local allow_at = new_tat - burst_offset

if allow_at <= now then
    redis.call('SET', key, new_tat, 'PX', ttl_ms)
    local remaining = math.floor((now + burst_offset - new_tat) / cell_ms)
    return {1, math.max(remaining, 0), 0}
else
    return {0, 0, allow_at - now}
end
"#;

    /// Token bucket — HMSET-based { tokens, last_refill_ms }.
    /// KEYS[1] = key
    /// ARGV[1] = now_ms, ARGV[2] = capacity, ARGV[3] = refill_per_ms (float*1e6), ARGV[4] = ttl_ms
    /// Returns: { allowed (0/1), remaining_floor, retry_after_ms }
    pub const TOKEN_BUCKET_LUA: &str = r#"
local key          = KEYS[1]
local now          = tonumber(ARGV[1])
local capacity     = tonumber(ARGV[2])
local refill_per_ms = tonumber(ARGV[3]) / 1e6
local ttl_ms       = tonumber(ARGV[4])

local h = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens      = tonumber(h[1]) or capacity
local last_refill = tonumber(h[2]) or now

local elapsed = now - last_refill
local refilled = math.min(tokens + elapsed * refill_per_ms, capacity)

if refilled >= 1.0 then
    local new_tokens = refilled - 1.0
    redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
    redis.call('PEXPIRE', key, ttl_ms)
    return {1, math.floor(new_tokens), 0}
else
    local wait_ms = math.ceil((1.0 - refilled) / refill_per_ms)
    return {0, 0, wait_ms}
end
"#;
}

// ── RedisStore ────────────────────────────────────────────────────────────────

/// Redis store providing atomic GCRA, Token Bucket, and Sliding Window via Lua.
///
/// Each algorithm has its own store type with pre-loaded script SHAs.
pub struct RedisGcraStore {
    conn: ConnectionManager,
    cell_ms: u64,
    burst_offset: u64,
    ttl_ms: u64,
    script: Script,
}

impl RedisGcraStore {
    pub async fn new(
        conn: ConnectionManager,
        cell_ms: u64,
        burst_offset: u64,
        ttl_ms: u64,
    ) -> Result<Self, RateLimitError> {
        Ok(Self {
            conn,
            cell_ms,
            burst_offset,
            ttl_ms,
            script: Script::new(scripts::GCRA_LUA),
        })
    }
}

/// Minimal state returned from Redis GCRA Lua script.
#[derive(Clone, Debug)]
pub struct GcraRedisState {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after_ms: u64,
}

impl Store for RedisGcraStore {
    type State = GcraRedisState;

    async fn fetch_and_update<'a, F>(
        &'a self,
        key: &'a [u8],
        _update_fn: F, // ignored — Lua handles the full read-modify-write
        now_ms: u64,
    ) -> Result<GcraRedisState, RateLimitError>
    where
        F: FnOnce(Option<&GcraRedisState>) -> GcraRedisState + Send + 'a,
    {
        let mut conn = self.conn.clone();
        let result: Vec<i64> = self
            .script
            .key(key)
            .arg(now_ms)
            .arg(self.cell_ms)
            .arg(self.burst_offset)
            .arg(self.ttl_ms)
            .invoke_async(&mut conn)
            .await?;

        Ok(GcraRedisState {
            allowed: result[0] == 1,
            remaining: result[1] as u32,
            retry_after_ms: result[2] as u64,
        })
    }
}

pub struct RedisSlidingWindowStore {
    conn: ConnectionManager,
    window_ms: u64,
    limit: u32,
    script: Script,
}

impl RedisSlidingWindowStore {
    pub fn new(conn: ConnectionManager, window_ms: u64, limit: u32) -> Self {
        Self {
            conn,
            window_ms,
            limit,
            script: Script::new(scripts::SLIDING_WINDOW_LUA),
        }
    }

    fn window_key(key: &[u8], now_ms: u64, window_ms: u64, offset: u64) -> Vec<u8> {
        let window_id = (now_ms / window_ms).saturating_sub(offset);
        let mut k = key.to_vec();
        k.push(b':');
        k.extend_from_slice(window_id.to_string().as_bytes());
        k
    }
}

#[derive(Clone, Debug)]
pub struct SlidingWindowRedisState {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after_ms: u64,
}

impl Store for RedisSlidingWindowStore {
    type State = SlidingWindowRedisState;

    async fn fetch_and_update<'a, F>(
        &'a self,
        key: &'a [u8],
        _update_fn: F,
        now_ms: u64,
    ) -> Result<SlidingWindowRedisState, RateLimitError>
    where
        F: FnOnce(Option<&SlidingWindowRedisState>) -> SlidingWindowRedisState + Send + 'a,
    {
        let curr_key = Self::window_key(key, now_ms, self.window_ms, 0);
        let prev_key = Self::window_key(key, now_ms, self.window_ms, 1);

        let mut conn = self.conn.clone();
        let result: Vec<i64> = self
            .script
            .key(&curr_key)
            .key(&prev_key)
            .arg(self.limit)
            .arg(self.window_ms)
            .arg(now_ms)
            .invoke_async(&mut conn)
            .await?;

        Ok(SlidingWindowRedisState {
            allowed: result[0] == 1,
            remaining: result[1] as u32,
            retry_after_ms: result[2] as u64,
        })
    }
}
