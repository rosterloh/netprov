//! Abstraction over "set the system (and, where the backend supports it, the
//! RTC) clock", so BLE Current Time Service handling can be tested without
//! touching the host clock — mirroring `NetworkFacade`/`facade_mock`.

use async_trait::async_trait;

#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct ClockError(pub String);

#[async_trait]
pub trait ClockFacade: Send + Sync {
    /// Sets the system clock to `unix_secs` (UTC seconds since the epoch).
    async fn set_time(&self, unix_secs: i64) -> Result<(), ClockError>;
}
