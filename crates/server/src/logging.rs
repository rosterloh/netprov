use crate::key::KeySource;
use std::time::Duration;
use tokio::time;
use tracing::{info, warn};

pub const DEV_KEY_WARN_PERIOD: Duration = Duration::from_secs(60);
pub const DEV_KEY_WARN_MARKER: &str = "netprov: INSECURE: development key in use; run 'netprovd keygen --install' to install a production key";

pub fn log_startup_banner(source: &KeySource) {
    match source {
        KeySource::EnvPath(p) => info!(path = %p.display(), "PSK loaded from NETPROV_KEY_PATH"),
        KeySource::DefaultPath(p) => info!(path = %p.display(), "PSK loaded from default path"),
        KeySource::EmbeddedDev => {
            warn!("PSK loaded from EMBEDDED DEV KEY — this server is INSECURE")
        }
    }
}

/// Spawn a task that emits a warning every DEV_KEY_WARN_PERIOD when the
/// embedded dev key is active. No-op for any other source.
pub fn spawn_dev_key_warn_loop(source: KeySource) -> Option<tokio::task::JoinHandle<()>> {
    if !matches!(source, KeySource::EmbeddedDev) {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut ticker = time::interval(DEV_KEY_WARN_PERIOD);
        // Skip the immediate first tick (banner already logged at startup).
        ticker.tick().await;
        loop {
            ticker.tick().await;
            warn!("{DEV_KEY_WARN_MARKER}");
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn warn_loop_is_none_for_nondev_sources() {
        assert!(spawn_dev_key_warn_loop(KeySource::DefaultPath("/tmp/k".into())).is_none());
        assert!(spawn_dev_key_warn_loop(KeySource::EnvPath("/tmp/k".into())).is_none());
    }

    #[tokio::test]
    async fn warn_loop_spawns_for_dev_key() {
        let h = spawn_dev_key_warn_loop(KeySource::EmbeddedDev).unwrap();
        assert!(!h.is_finished());
        h.abort();
    }
}
