//! Per-peer state driven by GATT events.
//!
//! Owns a Session, a Reassembler for inbound request fragments, and a channel
//! to the per-peer notify writer. All four GATT callbacks for this peer close
//! over an Arc<PeerSession>.

use crate::facade::NetworkFacade;
use crate::rate_limit::RateLimiter;
use crate::session::{Session, dispatch};
use netprov_protocol::{
    InfoPayload, MAX_FRAME_LEN, MAX_MESSAGE_SIZE, PROTOCOL_VERSION, PSK_LEN, ProtocolError,
    Reassembler, Request, Response, TAG_LEN, decode_request, encode_response, fragment,
    parse_frame,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Bytes that need to be written out on the Request/Response notify stream.
/// Producer: PeerSession::on_request dispatch. Consumer: the notify-io writer
/// owned by run_ble_server().
pub type NotifyTx = mpsc::UnboundedSender<Vec<u8>>;
pub type NotifyRx = mpsc::UnboundedReceiver<Vec<u8>>;

pub struct PeerSession<F: NetworkFacade> {
    pub session: Mutex<Session<F>>,
    pub reassembler: Mutex<Reassembler>,
    pub notify_tx: NotifyTx,
    pub model: String,
    /// Notify-side fragment ceiling, set from the `CharacteristicWriter`'s
    /// negotiated MTU once the peer subscribes (see `run_ble_server`).
    /// Defaults to `MAX_FRAME_LEN` so a response dispatched before subscribe
    /// completes still fragments to a safe ceiling.
    pub mtu: AtomicUsize,
    /// Handles to in-flight dispatch tasks plus a "closed" flag, guarded by a
    /// single lock so `on_request`'s spawn-then-push can never race past
    /// `abort_handles`'s set-then-drain. Without this, a write arriving via
    /// the independent `CharacteristicWriteMethod::Fun` closure (gatt.rs)
    /// could push a new handle after `abort_handles` has already drained the
    /// vec, leaving it un-abortable and able to leak a late response onto
    /// the shared notify channel for the *next* peer.
    dispatch_state: Mutex<DispatchState>,
}

struct DispatchState {
    closed: bool,
    handles: Vec<JoinHandle<()>>,
}

impl<F: NetworkFacade + 'static> PeerSession<F> {
    pub fn new(
        psk: [u8; PSK_LEN],
        peer_id: String,
        facade: Arc<F>,
        rate_limiter: Arc<RateLimiter>,
        model: String,
        notify_tx: NotifyTx,
    ) -> Arc<Self> {
        Arc::new(Self {
            session: Mutex::new(Session::new(psk, peer_id, facade, rate_limiter)),
            reassembler: Mutex::new(Reassembler::new(MAX_MESSAGE_SIZE)),
            notify_tx,
            model,
            mtu: AtomicUsize::new(MAX_FRAME_LEN),
            dispatch_state: Mutex::new(DispatchState {
                closed: false,
                handles: Vec::new(),
            }),
        })
    }

    /// Sets the notify fragment ceiling, called once the peer subscribes and
    /// the writer's negotiated MTU is known.
    pub fn set_mtu(&self, mtu: usize) {
        self.mtu.store(mtu, Ordering::Relaxed);
    }

    /// Info read handler — unauthenticated. Encodes a CBOR InfoPayload.
    pub fn on_info(&self) -> Vec<u8> {
        let payload = InfoPayload {
            protocol_version: PROTOCOL_VERSION,
            supported_ops: 0x7F, // bits 0..=6 → all 7 v1 ops
            model: self.model.clone(),
        };
        let mut bytes = Vec::with_capacity(64);
        ciborium::into_writer(&payload, &mut bytes).expect("InfoPayload encodes");
        bytes
    }

    /// ChallengeNonce read handler — generates fresh nonce, invalidates any prior.
    pub fn on_nonce(&self) -> Vec<u8> {
        self.session.lock().unwrap().issue_nonce().to_vec()
    }

    /// AuthResponse write handler — returns true on success.
    pub fn on_auth(&self, tag: Vec<u8>) -> bool {
        if tag.len() != TAG_LEN {
            return false;
        }
        self.session.lock().unwrap().submit_auth(&tag)
    }

    /// Aborts all in-flight dispatch tasks and marks the session closed so
    /// any `on_request` call still in flight (racing this call via the
    /// separate GATT write closure) aborts its own handle instead of
    /// pushing it where it would never be seen again. Called when the peer
    /// session ends (disconnect/resubscribe) so no stray task lingers past
    /// the connection it was serving.
    pub fn abort_handles(&self) {
        let mut state = self.dispatch_state.lock().unwrap();
        state.closed = true;
        for h in state.handles.drain(..) {
            h.abort();
        }
    }

    /// Request write handler — reassembles fragments, dispatches complete
    /// messages, emits fragmented responses back via notify_tx.
    pub fn on_request(self: &Arc<Self>, value: Vec<u8>) {
        if !self.session.lock().unwrap().is_authenticated() {
            warn!("dropping request frame from unauthenticated peer");
            return;
        }
        let parsed = match parse_frame(&value) {
            Ok(f) => f,
            Err(e) => {
                warn!(error = ?e, "rejected malformed frame");
                return;
            }
        };
        let complete = match self.reassembler.lock().unwrap().push(parsed) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return,
            Err(e) => {
                warn!(error = ?e, "reassembler rejected frame");
                return;
            }
        };
        let req: Request = match decode_request(&complete) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = ?e, "rejected malformed request");
                return;
            }
        };

        // Extract the data we need under the lock, then drop it before awaiting.
        let (facade, authed) = {
            let s = self.session.lock().unwrap();
            (s.facade_clone(), s.is_authenticated())
        };

        let this = self.clone();
        let handle = tokio::spawn(async move {
            let resp = if !authed {
                Response {
                    request_id: req.request_id,
                    result: Err(ProtocolError::NotAuthenticated),
                }
            } else {
                dispatch(&*facade, req).await
            };
            let bytes = match encode_response(&resp) {
                Ok(b) => b,
                Err(e) => {
                    warn!(error = ?e, "failed to encode response");
                    return;
                }
            };
            // fragment's third arg is the total frame size (body + header),
            // capped at the peer's negotiated notify MTU (falls back to
            // MAX_FRAME_LEN until subscribe sets it).
            let max_fragment = this.mtu.load(Ordering::Relaxed);
            let frames = fragment(resp.request_id, &bytes, max_fragment);
            for f in frames {
                if this.notify_tx.send(f).is_err() {
                    debug!("notify channel closed");
                    return;
                }
            }
        });
        let mut state = self.dispatch_state.lock().unwrap();
        if state.closed {
            // Lost the race with abort_handles: this session has already
            // been torn down, so don't let the new task linger unseen.
            handle.abort();
            return;
        }
        state.handles.retain(|h| !h.is_finished());
        state.handles.push(handle);
    }
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;
    use crate::facade_mock::MockFacade;
    use crate::rate_limit::RateLimiter;
    use netprov_protocol::{NONCE_LEN, Op, Request, encode_request, fragment, hmac_compute};

    fn new_peer() -> (Arc<PeerSession<MockFacade>>, NotifyRx) {
        let (notify_tx, notify_rx) = mpsc::unbounded_channel();
        let peer = PeerSession::new(
            [0x11u8; PSK_LEN],
            "peer".into(),
            Arc::new(MockFacade::new()),
            Arc::new(RateLimiter::with_defaults()),
            "test-model".into(),
            notify_tx,
        );
        (peer, notify_rx)
    }

    /// A request frame from an unauthenticated peer must be dropped before
    /// it ever reaches the reassembler, and must not produce a response.
    #[tokio::test]
    async fn unauthenticated_request_leaves_no_reassembler_state() {
        let (peer, mut notify_rx) = new_peer();
        assert!(!peer.session.lock().unwrap().is_authenticated());

        let req = Request {
            request_id: 1,
            op: Op::ListInterfaces,
        };
        let bytes = encode_request(&req).unwrap();
        for f in fragment(req.request_id, &bytes, MAX_FRAME_LEN) {
            peer.on_request(f);
        }

        assert_eq!(
            peer.reassembler.lock().unwrap().partial_count(),
            0,
            "unauthenticated frame must not create reassembler state"
        );
        assert!(
            notify_rx.try_recv().is_err(),
            "unauthenticated request must not produce a response"
        );
    }

    /// Regression test for the abort_handles/on_request race: a write that
    /// arrives via the independent GATT write closure (gatt.rs) *after*
    /// abort_handles has already closed the session (the disconnect path in
    /// server.rs) must not spawn a task that lingers unseen — it must abort
    /// its own handle instead of pushing it. Without the `closed` flag
    /// serialized under the same lock as the handle vec, this stray task
    /// could later deliver a response frame to whichever peer connects next
    /// on the shared notify channel.
    #[tokio::test]
    async fn request_after_abort_handles_does_not_leak_a_task() {
        let (peer, mut notify_rx) = new_peer();

        // Authenticate, as a real client would before writing a request.
        let nonce_bytes = peer.on_nonce();
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_bytes);
        let tag = hmac_compute(&[0x11u8; PSK_LEN], &nonce);
        assert!(peer.on_auth(tag.to_vec()));

        // Simulate the disconnect path: the peer session is torn down and
        // all in-flight handles aborted *before* the stray write below
        // arrives (mirrors server.rs calling peer.abort_handles() while the
        // GATT write closure still holds the same Arc<PeerSession> via
        // `current`).
        peer.abort_handles();

        let req = Request {
            request_id: 9,
            op: Op::ListInterfaces,
        };
        let bytes = encode_request(&req).unwrap();
        for f in fragment(req.request_id, &bytes, MAX_FRAME_LEN) {
            peer.on_request(f);
        }

        assert!(
            peer.dispatch_state.lock().unwrap().handles.is_empty(),
            "a request racing abort_handles must not leave a dangling handle"
        );
        assert!(
            notify_rx.try_recv().is_err(),
            "a request racing abort_handles must not deliver a response \
             onto the shared notify channel"
        );
    }
}
