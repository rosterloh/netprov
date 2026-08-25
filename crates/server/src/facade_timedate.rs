//! Sets the system clock (and, via `timedated`, the RTC) over
//! `org.freedesktop.timedate1`. `timedated` handles the UTC-vs-local-RTC and
//! `/etc/adjtime` details itself, and needs no `CAP_SYS_TIME` in `netprovd` —
//! the privileged work happens in `timedated`, gated by polkit.

use crate::clock::{ClockError, ClockFacade};
use async_trait::async_trait;
use std::time::Duration;

/// Bound on the `SetTime` call.
///
/// `SetTime` is polkit-gated, and on a headless device there is no
/// authentication agent to answer, so the call can block indefinitely rather
/// than being denied. This runs inside the CurrentTime GATT write closure, so
/// blocking here means BlueZ never sends the ATT write response and the client
/// waits forever on a write it will never hear about. A local D-Bus round trip
/// to `timedated` is sub-second when it works at all.
const SET_TIME_TIMEOUT: Duration = Duration::from_secs(5);

pub struct TimedateFacade {
    zbus: zbus::Connection,
}

impl TimedateFacade {
    pub async fn new() -> anyhow::Result<Self> {
        let zbus = zbus::Connection::system().await?;
        Ok(Self { zbus })
    }
}

#[async_trait]
impl ClockFacade for TimedateFacade {
    /// `SetTime` fails with "Automatic time synchronization is enabled" while
    /// NTP is already on; that failure is surfaced to the caller rather than
    /// swallowed or forced off — if NTP already works, the clock doesn't need
    /// us, and overriding an operator's NTP policy here would be a surprise.
    async fn set_time(&self, unix_secs: i64) -> Result<(), ClockError> {
        let proxy = zbus::Proxy::new(
            &self.zbus,
            "org.freedesktop.timedate1",
            "/org/freedesktop/timedate1",
            "org.freedesktop.timedate1",
        )
        .await
        .map_err(|e| ClockError(e.to_string()))?;
        let usec_utc = unix_secs.saturating_mul(1_000_000);
        tokio::time::timeout(
            SET_TIME_TIMEOUT,
            proxy.call::<_, _, ()>("SetTime", &(usec_utc, false, false)),
        )
        .await
        .map_err(|_| {
            ClockError(format!(
                "timedated SetTime did not answer within {}s (polkit may be waiting for an \
                 authentication agent)",
                SET_TIME_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| ClockError(e.to_string()))
    }
}
