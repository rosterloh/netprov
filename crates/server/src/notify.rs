//! Thin wrapper around sd-notify so the rest of the codebase doesn't need to
//! care whether it's running under systemd.

use sd_notify::NotifyState;

/// Tell systemd we're ready. No-op if $NOTIFY_SOCKET is unset.
pub fn notify_ready() {
    let _ = sd_notify::notify(&[NotifyState::Ready]);
}

/// Tell systemd we're stopping.
pub fn notify_stopping() {
    let _ = sd_notify::notify(&[NotifyState::Stopping]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_with_no_socket_is_noop() {
        std::env::remove_var("NOTIFY_SOCKET");
        notify_ready(); // must not panic
        notify_stopping();
    }
}
