//! Runtime policy management — change limits without restarting.
//!
//! # Problems solved
//!
//! 1. **Hot policy reload** — a bad actor starts hammering; ops wants to
//!    tighten their quota from 1000/min to 10/min right now, not at next deploy.
//!
//! 2. **Per-key overrides** — VIP customer needs 10× the standard quota;
//!    abusive key needs 0.
//!
//! 3. **Block/allowlist** — block a key entirely (returns 429 always),
//!    or allowlist it (bypass rate limiting entirely).
//!
//! 4. **Quota grants** — temporarily restore tokens for a key that was
//!    legitimately throttled (customer support action).
//!
//! # Architecture
//!
//! `PolicyStore` is an `Arc<RwLock<PolicyMap>>` consulted on every request
//! *before* the algorithm. Because it's a `RwLock`, reads (99.99% of traffic)
//! are contention-free; writes (rare policy changes) briefly block.
//!
//! For distributed deployments, push policy changes via Redis pub/sub:
//! each instance subscribes to `ratekeeper:policy:*` and updates its local
//! `PolicyStore` on receipt. This gives sub-second propagation across a fleet.

use crate::policy::Policy;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

// ── KeyOverride ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum KeyOverride {
    /// Block this key entirely — always 429.
    Block,
    /// Allow this key unconditionally — skip rate limiting.
    Allowlist,
    /// Apply a custom policy instead of the default.
    CustomPolicy(Policy),
    /// Temporarily boost the limit (expires at `until`).
    TemporaryBoost { policy: Policy, until: Instant },
}

impl KeyOverride {
    pub fn is_expired(&self) -> bool {
        match self {
            KeyOverride::TemporaryBoost { until, .. } => Instant::now() > *until,
            _ => false,
        }
    }
}

// ── PolicyEntry ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyEntry {
    pub policy: Policy,
    pub overrides: HashMap<Vec<u8>, KeyOverride>,
}

impl PolicyEntry {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            overrides: HashMap::new(),
        }
    }
}

// ── PolicyStore ───────────────────────────────────────────────────────────────

/// Thread-safe, runtime-mutable policy store.
/// Cheap to clone — wraps everything in `Arc`.
#[derive(Clone)]
pub struct PolicyStore {
    inner: Arc<RwLock<PolicyMap>>,
}

#[derive(Debug, Default)]
struct PolicyMap {
    /// Named policy groups (e.g. "default", "premium", "internal").
    groups: HashMap<String, PolicyEntry>,
    /// Global block list (checked before group lookup).
    blocked: HashMap<Vec<u8>, BlockedUntil>,
    /// Global allowlist.
    allowed: std::collections::HashSet<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct BlockedUntil {
    until: Option<Instant>, // None = permanent
    reason: String,
}

impl PolicyStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(PolicyMap::default())),
        }
    }

    // ── Write operations (rare) ───────────────────────────────────────────────

    /// Register or replace a named policy group.
    pub async fn set_group(&self, name: impl Into<String>, policy: Policy) {
        self.inner
            .write()
            .await
            .groups
            .insert(name.into(), PolicyEntry::new(policy));
    }

    /// Override the policy for a specific key within a group.
    pub async fn set_key_override(
        &self,
        group: &str,
        key: impl Into<Vec<u8>>,
        override_: KeyOverride,
    ) -> bool {
        let mut map = self.inner.write().await;
        if let Some(entry) = map.groups.get_mut(group) {
            entry.overrides.insert(key.into(), override_);
            true
        } else {
            false
        }
    }

    /// Block a key globally (across all groups).
    pub async fn block_key(
        &self,
        key: impl Into<Vec<u8>>,
        duration: Option<Duration>,
        reason: impl Into<String>,
    ) {
        let until = duration.map(|d| Instant::now() + d);
        self.inner.write().await.blocked.insert(
            key.into(),
            BlockedUntil {
                until,
                reason: reason.into(),
            },
        );
    }

    /// Remove a block from a key.
    pub async fn unblock_key(&self, key: &[u8]) -> bool {
        self.inner.write().await.blocked.remove(key).is_some()
    }

    /// Add a key to the global allowlist (bypasses all rate limiting).
    pub async fn allowlist_key(&self, key: impl Into<Vec<u8>>) {
        self.inner.write().await.allowed.insert(key.into());
    }

    /// Remove a key from the allowlist.
    pub async fn remove_allowlist(&self, key: &[u8]) -> bool {
        self.inner.write().await.allowed.remove(key)
    }

    /// Expire all temporary overrides and expired blocks.
    pub async fn gc(&self) {
        let mut map = self.inner.write().await;
        // Remove expired blocks
        map.blocked
            .retain(|_, b| b.until.is_none_or(|t| Instant::now() < t));
        // Remove expired temporary boosts
        for entry in map.groups.values_mut() {
            entry.overrides.retain(|_, ov| !ov.is_expired());
        }
    }

    // ── Read operations (hot path) ────────────────────────────────────────────

    /// Resolve the effective policy for `key` in `group`.
    /// Returns `None` if the key is globally blocked (caller should 429).
    /// Returns `Some(None)` if the key is allowlisted (caller should allow unconditionally).
    /// Returns `Some(Some(policy))` with the effective policy to apply.
    pub async fn resolve(&self, group: &str, key: &[u8]) -> PolicyResolution {
        let map = self.inner.read().await;

        // 1. Global allowlist
        if map.allowed.contains(key) {
            return PolicyResolution::Allowlisted;
        }

        // 2. Global blocklist
        if let Some(block) = map.blocked.get(key) {
            match block.until {
                Some(t) if Instant::now() > t => {
                    // Expired — treat as not blocked (GC will clean it up)
                }
                _ => {
                    return PolicyResolution::Blocked {
                        reason: block.reason.clone(),
                    }
                }
            }
        }

        // 3. Group lookup
        let Some(entry) = map.groups.get(group) else {
            return PolicyResolution::UseDefault;
        };

        // 4. Per-key override within the group
        if let Some(override_) = entry.overrides.get(key) {
            if override_.is_expired() {
                return PolicyResolution::Policy(entry.policy.clone());
            }
            return match override_ {
                KeyOverride::Block => PolicyResolution::Blocked {
                    reason: "key override".into(),
                },
                KeyOverride::Allowlist => PolicyResolution::Allowlisted,
                KeyOverride::CustomPolicy(p) => PolicyResolution::Policy(p.clone()),
                KeyOverride::TemporaryBoost { policy, .. } => {
                    PolicyResolution::Policy(policy.clone())
                }
            };
        }

        // 5. Default group policy
        PolicyResolution::Policy(entry.policy.clone())
    }

    pub async fn group_count(&self) -> usize {
        self.inner.read().await.groups.len()
    }
    pub async fn blocked_count(&self) -> usize {
        self.inner.read().await.blocked.len()
    }
    pub async fn allowed_count(&self) -> usize {
        self.inner.read().await.allowed.len()
    }
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub enum PolicyResolution {
    /// Key is globally allowlisted — skip rate limiting.
    Allowlisted,
    /// Key is blocked — return 429 immediately.
    Blocked { reason: String },
    /// No group found — use caller's default.
    UseDefault,
    /// Effective policy to apply.
    Policy(Policy),
}

// ── Redis pub/sub policy sync ─────────────────────────────────────────────────

/// Command published to `ratekeeper:policy:commands` channel.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op")]
pub enum PolicyCommand {
    SetGroup {
        group: String,
        limit: u32,
        window_ms: u64,
    },
    BlockKey {
        key: Vec<u8>,
        duration_secs: Option<u64>,
        reason: String,
    },
    UnblockKey {
        key: Vec<u8>,
    },
    AllowKey {
        key: Vec<u8>,
    },
    RemoveAllow {
        key: Vec<u8>,
    },
}

impl PolicyCommand {
    pub async fn apply(&self, store: &PolicyStore) {
        match self {
            Self::SetGroup {
                group,
                limit,
                window_ms,
            } => {
                let policy = Policy::new(*limit, Duration::from_millis(*window_ms));
                store.set_group(group.clone(), policy).await;
                tracing::info!(target: "ratekeeper::admin", op = "set_group", group, limit, window_ms);
            }
            Self::BlockKey {
                key,
                duration_secs,
                reason,
            } => {
                let dur = duration_secs.map(Duration::from_secs);
                store.block_key(key.clone(), dur, reason.clone()).await;
                tracing::info!(target: "ratekeeper::admin", op = "block_key", ?duration_secs, reason);
            }
            Self::UnblockKey { key } => {
                store.unblock_key(key).await;
                tracing::info!(target: "ratekeeper::admin", op = "unblock_key");
            }
            Self::AllowKey { key } => {
                store.allowlist_key(key.clone()).await;
                tracing::info!(target: "ratekeeper::admin", op = "allow_key");
            }
            Self::RemoveAllow { key } => {
                store.remove_allowlist(key).await;
                tracing::info!(target: "ratekeeper::admin", op = "remove_allow");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_and_resolve_group_policy() {
        let store = PolicyStore::new();
        store.set_group("default", Policy::per_second(100)).await;

        let r = store.resolve("default", b"user-1").await;
        assert!(matches!(r, PolicyResolution::Policy(_)));
    }

    #[tokio::test]
    async fn blocked_key_resolves_to_blocked() {
        let store = PolicyStore::new();
        store.set_group("default", Policy::per_second(100)).await;
        store.block_key(b"bad-actor", None, "abuse").await;

        let r = store.resolve("default", b"bad-actor").await;
        assert!(matches!(r, PolicyResolution::Blocked { .. }));
    }

    #[tokio::test]
    async fn allowlisted_key_bypasses_group() {
        let store = PolicyStore::new();
        store.set_group("default", Policy::per_second(1)).await;
        store.allowlist_key(b"internal-service").await;

        let r = store.resolve("default", b"internal-service").await;
        assert!(matches!(r, PolicyResolution::Allowlisted));
    }

    #[tokio::test]
    async fn per_key_override_takes_precedence() {
        let store = PolicyStore::new();
        store.set_group("default", Policy::per_second(10)).await;
        store
            .set_key_override(
                "default",
                b"vip-customer",
                KeyOverride::CustomPolicy(Policy::per_second(10_000)),
            )
            .await;

        let r = store.resolve("default", b"vip-customer").await;
        if let PolicyResolution::Policy(p) = r {
            assert_eq!(p.limit, 10_000);
        } else {
            panic!("expected custom policy");
        }
    }

    #[tokio::test]
    async fn temporary_boost_expires() {
        let store = PolicyStore::new();
        store.set_group("default", Policy::per_second(10)).await;
        store
            .set_key_override(
                "default",
                b"user-x",
                KeyOverride::TemporaryBoost {
                    policy: Policy::per_second(500),
                    until: Instant::now() - Duration::from_millis(1), // already expired
                },
            )
            .await;

        let r = store.resolve("default", b"user-x").await;
        // Expired boost → falls through to group default
        if let PolicyResolution::Policy(p) = r {
            assert_eq!(p.limit, 10, "expired boost should use group default");
        } else {
            panic!("expected group default policy");
        }
    }

    #[tokio::test]
    async fn unblock_removes_block() {
        let store = PolicyStore::new();
        store.block_key(b"user-y", None, "test").await;
        assert!(matches!(
            store.resolve("default", b"user-y").await,
            PolicyResolution::Blocked { .. }
        ));

        store.unblock_key(b"user-y").await;
        // After unblock, group not found → UseDefault
        assert!(matches!(
            store.resolve("default", b"user-y").await,
            PolicyResolution::UseDefault
        ));
    }

    #[tokio::test]
    async fn policy_command_set_group_applies() {
        let store = PolicyStore::new();
        let cmd = PolicyCommand::SetGroup {
            group: "api".into(),
            limit: 500,
            window_ms: 60_000,
        };
        cmd.apply(&store).await;

        let r = store.resolve("api", b"any-key").await;
        if let PolicyResolution::Policy(p) = r {
            assert_eq!(p.limit, 500);
        } else {
            panic!("expected policy after SetGroup command");
        }
    }
}
