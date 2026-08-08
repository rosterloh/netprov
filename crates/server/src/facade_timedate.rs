//! Sets the system clock (and, via `timedated`, the RTC) over
//! `org.freedesktop.timedate1`. `timedated` handles the UTC-vs-local-RTC and
//! `/etc/adjtime` details itself, and needs no `CAP_SYS_TIME` in `netprovd` —
//! the privileged work happens in `timedated`, gated by polkit.

use crate::clock::{ClockError, ClockFacade};
use async_trait::async_trait;

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
        proxy
            .call::<_, _, ()>("SetTime", &(usec_utc, false, false))
            .await
            .map_err(|e| ClockError(e.to_string()))
    }
}
