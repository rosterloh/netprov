//! Per-peer state driven by GATT events.
//!
//! Owns a Session, a Reassembler for inbound request fragments, and a channel
//! to the per-peer notify writer. All four GATT callbacks for this peer close
//! over an Arc<PeerSession>.

use crate::facade::NetworkFacade;
use crate::rate_limit::RateLimiter;
use crate::session::{Session, dispatch};
use netprov_protocol::{
    BoundedString, InfoPayload, MAX_FRAME_LEN, MAX_MESSAGE_SIZE, PROTOCOL_VERSION, PSK_LEN,
    ProtocolError, Reassembler, Request, Response, TAG_LEN, decode_request, encode_response,
    fragment, parse_frame,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Bytes that need to be written out on the Request/Response notify stream,
/// tagged with the id of the peer that produced them. Producer:
/// PeerSession::on_request dispatch. Consumer: the notify-io writer owned by
/// run_ble_server(). The tag lets the writer drop frames from a peer that has
/// since departed instead of leaking them onto the next peer's stream (see
/// run_ble_server and issue #13).
pub type NotifyTx = mpsc::UnboundedSender<(String, Vec<u8>)>;
pub type NotifyRx = mpsc::UnboundedReceiver<(String, Vec<u8>)>;

pub struct PeerSession<F: NetworkFacade> {
    /// Id of the peer this session serves (its BLE address, debug-formatted).
    /// Frames pushed to `notify_tx` are tagged with this so the notify writer
    /// can attribute — and drop — frames from a peer that has since departed.
    pub peer_id: String,
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
            peer_id: peer_id.clone(),
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
                // A frame we can't parse carries no recoverable request_id,
                // so there is no id to address a reply to. The client's
                // request timeout is the only backstop here.
                warn!(error = ?e, "rejected malformed frame");
                return;
            }
        };
        // From here the request_id is known, so every failure below is
        // answered with an error Response addressed to it rather than
        // silently dropped — a dropped reply is indistinguishable from a
        // slow op and hangs the client until its timeout.
        let request_id = parsed.request_id;
        let complete = match self.reassembler.lock().unwrap().push(parsed) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return,
            Err(e) => {
                warn!(error = ?e, "reassembler rejected frame");
                self.emit_response(Response {
                    request_id,
                    result: Err(ProtocolError::InvalidArgument {
                        reason: BoundedString::truncated(format!("malformed request framing: {e}")),
                    }),
                });
                return;
            }
        };
        let req: Request = match decode_request(&complete) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = ?e, "rejected malformed request");
                self.emit_response(Response {
                    request_id,
                    result: Err(ProtocolError::InvalidArgument {
                        reason: BoundedString::truncated(format!("undecodable request: {e}")),
                    }),
                });
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
            this.emit_response(resp);
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

    /// Encodes `resp`, fragments it to the peer's negotiated notify MTU
    /// (falling back to `MAX_FRAME_LEN` until subscribe sets it), and sends
    /// the frames on the notify channel.
    ///
    /// If `encode_response` fails the size check — e.g. an oversized
    /// dispatch result such as a large WifiScan — the response is replaced
    /// by a small, bounded `Internal` error carrying the same `request_id`.
    /// That substitute cannot itself exceed the limit, so the peer always
    /// receives a reply addressed to its request rather than hanging.
    fn emit_response(&self, resp: Response) {
        let request_id = resp.request_id;
        let bytes = match encode_response(&resp) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = ?e, "failed to encode response; substituting Internal error");
                let fallback = Response {
                    request_id,
                    result: Err(ProtocolError::Internal {
                        message: BoundedString::truncated("response too large to encode"),
                    }),
                };
                encode_response(&fallback)
                    .expect("bounded Internal error response always encodes within the size limit")
            }
        };
        let max_fragment = self.mtu.load(Ordering::Relaxed);
        for f in fragment(request_id, &bytes, max_fragment) {
            // Tag each frame with this peer's id so the notify writer only
            // delivers it while this peer is still the active subscriber.
            if self.notify_tx.send((self.peer_id.clone(), f)).is_err() {
                debug!("notify channel closed");
                return;
            }
        }
    }
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;
    use crate::facade_mock::MockFacade;
    use crate::rate_limit::RateLimiter;
    use netprov_protocol::{
        FRAME_HEADER_LEN, NONCE_LEN, Op, Request, decode_response, encode_request, fragment,
        hmac_compute,
    };

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

    /// Drives the shared-PSK auth handshake so the peer is authenticated,
    /// mirroring what a real client does before writing requests.
    fn authenticate(peer: &Arc<PeerSession<MockFacade>>) {
        let nonce_bytes = peer.on_nonce();
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_bytes);
        let tag = hmac_compute(&[0x11u8; PSK_LEN], &nonce);
        assert!(peer.on_auth(tag.to_vec()));
    }

    /// Drains the notify channel and reassembles the single response the
    /// server emitted, panicking if none arrived.
    fn recv_response(notify_rx: &mut NotifyRx) -> Response {
        let mut reassembler = Reassembler::new(MAX_MESSAGE_SIZE);
        while let Ok((_peer_id, frame)) = notify_rx.try_recv() {
            let parsed = parse_frame(&frame).expect("notify frame parses");
            if let Some(msg) = reassembler.push(parsed).expect("notify frames reassemble") {
                return decode_response(&msg).expect("response decodes");
            }
        }
        panic!("server produced no response");
    }

    /// A well-framed but undecodable request (valid framing, garbage CBOR)
    /// must draw an error Response addressed to the frame's request_id
    /// rather than being silently dropped — otherwise the client hangs.
    #[tokio::test]
    async fn undecodable_request_gets_error_response() {
        let (peer, mut notify_rx) = new_peer();
        authenticate(&peer);

        let request_id = 0x2a;
        // 0xff is a CBOR "break" stop code, invalid as a top-level item, so
        // decode_request rejects the reassembled payload.
        for f in fragment(request_id, &[0xffu8; 8], MAX_FRAME_LEN) {
            peer.on_request(f);
        }

        let resp = recv_response(&mut notify_rx);
        assert_eq!(resp.request_id, request_id);
        assert!(
            matches!(resp.result, Err(ProtocolError::InvalidArgument { .. })),
            "undecodable request must map to InvalidArgument, got {:?}",
            resp.result
        );
    }

    /// A frame the reassembler rejects (here: one more concurrent partial
    /// than allowed) must also draw an error Response instead of a drop.
    #[tokio::test]
    async fn reassembler_rejection_gets_error_response() {
        let (peer, mut notify_rx) = new_peer();
        authenticate(&peer);

        // Open `max_partials` distinct never-completed messages by sending a
        // single non-FIN fragment of a 2-frame message for each request_id.
        // A small MTU forces >1 fragment so the first is non-FIN.
        let payload = [0u8; 32];
        let mtu = FRAME_HEADER_LEN + 16;
        for rid in 0..4u16 {
            let first = fragment(rid, &payload, mtu).remove(0);
            peer.on_request(first);
        }
        assert!(
            notify_rx.try_recv().is_err(),
            "unfinished partials must not yet produce any response"
        );

        // The 5th distinct request_id trips TooManyPartials.
        let rejected_id = 99;
        let first = fragment(rejected_id, &payload, mtu).remove(0);
        peer.on_request(first);

        let resp = recv_response(&mut notify_rx);
        assert_eq!(resp.request_id, rejected_id);
        assert!(
            matches!(resp.result, Err(ProtocolError::InvalidArgument { .. })),
            "reassembler rejection must map to InvalidArgument, got {:?}",
            resp.result
        );
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
