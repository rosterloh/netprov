use crate::clock::{ClockError, ClockFacade};
use async_trait::async_trait;
use std::sync::Mutex;

/// Records the last `set_time` call instead of touching the host clock. No
/// test may set the machine's real clock (see #32).
#[derive(Default)]
pub struct MockClock {
    pub last_set_unix_secs: Mutex<Option<i64>>,
}

impl MockClock {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ClockFacade for MockClock {
    async fn set_time(&self, unix_secs: i64) -> Result<(), ClockError> {
        *self.last_set_unix_secs.lock().unwrap() = Some(unix_secs);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn records_the_last_set_call() {
        let clock = MockClock::new();
        assert!(clock.last_set_unix_secs.lock().unwrap().is_none());
        clock.set_time(1_735_689_600).await.unwrap();
        assert_eq!(
            *clock.last_set_unix_secs.lock().unwrap(),
            Some(1_735_689_600)
        );
    }
}
