//! Per-peer state driven by GATT events.
//!
//! Owns a Session, a Reassembler for inbound request fragments, and a channel
//! to the per-peer notify writer. All four GATT callbacks for this peer close
//! over an Arc<PeerSession>.

use crate::facade::NetworkFacade;
use crate::rate_limit::RateLimiter;
use crate::session::{dispatch, Session};
use netprov_protocol::{
    decode_request, encode_response, fragment, parse_frame, InfoPayload, ProtocolError,
    Reassembler, Request, Response, MAX_MESSAGE_SIZE, MAX_PAYLOAD_PER_FRAME, PROTOCOL_VERSION,
    PSK_LEN, TAG_LEN,
};
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
    /// Handles to in-flight dispatch tasks. Kept only so they aren't detached;
    /// future hardening: abort on peer disconnect (currently we rely on
    /// tokio runtime shutdown to drop them).
    pub dispatch_handles: Mutex<Vec<JoinHandle<()>>>,
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
            dispatch_handles: Mutex::new(Vec::new()),
        })
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

    /// Request write handler — reassembles fragments, dispatches complete
    /// messages, emits fragmented responses back via notify_tx.
    pub fn on_request(self: &Arc<Self>, value: Vec<u8>) {
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
            // fragment's third arg is total frame size (body + 5-byte header);
            // MAX_PAYLOAD_PER_FRAME = 507, so +5 gives the 512-byte BLE ceiling.
            let frames = fragment(resp.request_id, &bytes, MAX_PAYLOAD_PER_FRAME + 5);
            for f in frames {
                if this.notify_tx.send(f).is_err() {
                    debug!("notify channel closed");
                    return;
                }
            }
        });
        self.dispatch_handles.lock().unwrap().push(handle);
    }
}
