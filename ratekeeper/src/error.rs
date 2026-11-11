use thiserror::Error;

#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("store unavailable: {0}")]
    StoreUnavailable(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[cfg(feature = "redis")]
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("internal error: {0}")]
    Internal(String),
}
