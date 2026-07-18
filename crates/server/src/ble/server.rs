//! BLE adapter initialization + per-peer connection fan-out.

use super::conn::PeerSession;
use super::gatt::{GattHandlers, build_application};
use crate::facade::NetworkFacade;
use crate::rate_limit::RateLimiter;
use bluer::{
    Address, Session as BluerSession,
    adv::{Advertisement, Type as AdvType},
    agent::Agent,
    gatt::local::CharacteristicControlEvent,
};
use futures_util::StreamExt;
use netprov_protocol::PSK_LEN;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub struct BleServerConfig {
    pub psk: [u8; PSK_LEN],
    /// Device model exposed via the Info characteristic. Per spec §11: model only, no serial.
    pub model: String,
    /// Bind to a specific controller (e.g. "hci0"). If None, bluer picks the default adapter.
    pub adapter_name: Option<String>,
}

/// Peer table shared by the GATT closures and the notify control loop:
/// the `PeerSession` for whichever single peer is currently active, keyed by
/// its address so a late subscribe (after auth) reuses rather than replaces it.
type PeerTable<F> = Arc<std::sync::Mutex<Option<(String, Arc<PeerSession<F>>)>>>;

/// Return value of `build_gatt_handlers`: the shared peer table, the notify
/// channel halves, and the wired-up `GattHandlers`.
type BuiltHandlers<F> = (
    PeerTable<F>,
    mpsc::UnboundedSender<Vec<u8>>,
    mpsc::UnboundedReceiver<Vec<u8>>,
    GattHandlers,
);

/// Returns the `PeerSession` for `addr`, reusing the one already installed in
/// `current` if it belongs to the same peer, or minting a fresh one
/// otherwise. Called from every GATT entry point (Info/ChallengeNonce read,
/// AuthResponse write, notify subscribe) so session creation never depends on
/// the order in which a client happens to touch the characteristics.
fn get_or_create_peer<F: NetworkFacade + 'static>(
    current: &PeerTable<F>,
    addr: Address,
    psk: [u8; PSK_LEN],
    facade: &Arc<F>,
    rate_limiter: &Arc<RateLimiter>,
    model: &str,
    notify_tx: &mpsc::UnboundedSender<Vec<u8>>,
) -> Arc<PeerSession<F>> {
    let peer_id = format!("{addr:?}");
    let mut guard = current.lock().unwrap();
    if let Some((existing_id, session)) = guard.as_ref()
        && *existing_id == peer_id
    {
        return session.clone();
    }
    let session = PeerSession::new(
        psk,
        peer_id.clone(),
        facade.clone(),
        rate_limiter.clone(),
        model.to_string(),
        notify_tx.clone(),
    );
    info!(peer = %peer_id, "peer session started");
    *guard = Some((peer_id, session.clone()));
    session
}

/// Builds the `GattHandlers` wired to `get_or_create_peer`, plus the shared
/// peer table and notify channel. Split out from `run_ble_server` so the
/// read-nonce/write-auth/subscribe/write-request ordering can be exercised in
/// a unit test without any bluer/BlueZ machinery.
fn build_gatt_handlers<F: NetworkFacade + 'static>(
    psk: [u8; PSK_LEN],
    model: String,
    facade: Arc<F>,
    rate_limiter: Arc<RateLimiter>,
) -> BuiltHandlers<F> {
    let current: PeerTable<F> = Arc::new(Default::default());
    let (notify_tx, notify_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let cur_info = current.clone();
    let cur_nonce = current.clone();
    let cur_auth = current.clone();
    let cur_req = current.clone();
    let facade_info = facade.clone();
    let facade_nonce = facade.clone();
    let facade_auth = facade;
    let rl_info = rate_limiter.clone();
    let rl_nonce = rate_limiter.clone();
    let rl_auth = rate_limiter;
    let model_info = model.clone();
    let model_nonce = model.clone();
    let model_auth = model;
    let notify_tx_info = notify_tx.clone();
    let notify_tx_nonce = notify_tx.clone();
    let notify_tx_auth = notify_tx.clone();
    let handlers = GattHandlers {
        on_info_read: Arc::new(move |addr| {
            get_or_create_peer(
                &cur_info,
                addr,
                psk,
                &facade_info,
                &rl_info,
                &model_info,
                &notify_tx_info,
            )
            .on_info()
        }),
        on_nonce_read: Arc::new(move |addr| {
            get_or_create_peer(
                &cur_nonce,
                addr,
                psk,
                &facade_nonce,
                &rl_nonce,
                &model_nonce,
                &notify_tx_nonce,
            )
            .on_nonce()
        }),
        on_auth_write: Arc::new(move |addr, value| {
            get_or_create_peer(
                &cur_auth,
                addr,
                psk,
                &facade_auth,
                &rl_auth,
                &model_auth,
                &notify_tx_auth,
            )
            .on_auth(value)
        }),
        on_request_write: Arc::new(move |value| {
            if let Some((_, p)) = cur_req.lock().unwrap().as_ref() {
                p.on_request(value);
            }
        }),
    };

    (current, notify_tx, notify_rx, handlers)
}

pub async fn run_ble_server<F>(
    cfg: BleServerConfig,
    facade: Arc<F>,
    rate_limiter: Arc<RateLimiter>,
    mut ready_cb: impl FnMut(),
) -> anyhow::Result<()>
where
    F: NetworkFacade + 'static,
{
    let session = BluerSession::new().await?;

    // The daemon runs headless (no display, no keyboard), so register a
    // no-IO-capability agent: BlueZ negotiates Just Works pairing, which
    // yields an encrypted link without any prompt but without MITM
    // protection either. The app-layer HMAC challenge (crates/server/src/ble/conn.rs)
    // is what actually authorizes commands; Just Works only satisfies the
    // `encrypt_authenticated_*` flags set on the sensitive characteristics
    // in gatt.rs. See README's security section for the residual-risk
    // discussion.
    let _agent_handle = session.register_agent(Agent::default()).await?;

    let adapter = match cfg.adapter_name.as_deref() {
        Some(n) => session.adapter(n)?,
        None => session.default_adapter().await?,
    };
    adapter.set_powered(true).await?;
    adapter.set_discoverable(true).await?;
    adapter.set_pairable(true).await?;
    info!(adapter_name = %adapter.name(), address = ?adapter.address().await?, "BLE adapter ready");

    // The PeerSession for the currently-connected peer, keyed by peer
    // address. bluer's Application is built once with static callbacks; the
    // callbacks forward to whatever PeerSession this Mutex currently holds.
    // v1 serves one peer at a time (spec goal); multi-peer concurrency is a
    // Part 3 concern.
    //
    // Session creation is independent of notification subscription: the
    // first GATT interaction (Info/ChallengeNonce read or AuthResponse
    // write) mints the session, so a client that authenticates before
    // subscribing (the SDK's normal flow) still finds live session state.
    let model = cfg.model.clone();
    let psk = cfg.psk;
    let (current, notify_tx, mut notify_rx, handlers) =
        build_gatt_handlers(psk, model.clone(), facade.clone(), rate_limiter.clone());

    let built = build_application(handlers);
    let _app_handle = adapter.serve_gatt_application(built.app).await?;
    let mut notify_control = built.notify_control;
    info!("GATT service registered");

    // Advertise the netprov service UUID so a scanning client can find us.
    let adv = Advertisement {
        advertisement_type: AdvType::Peripheral,
        service_uuids: {
            let mut s = BTreeSet::new();
            s.insert(super::uuids::SERVICE_UUID);
            s
        },
        discoverable: Some(true),
        local_name: Some(format!("netprovd-{}", cfg.model)),
        ..Default::default()
    };
    let _adv_handle = adapter.advertise(adv).await?;
    info!("advertising");

    // Readiness signal to systemd (or the caller).
    ready_cb();

    // Drive the notify control stream: when a peer subscribes, reuse the
    // already-minted PeerSession for that peer address (if the client
    // authenticated before subscribing) or mint one now, and pipe notify_rx
    // bytes into the writer.
    //
    // Structural note: while we're blocked inside the inner recv() loop for
    // peer A, the outer notify_control.next() is not polled. bluer buffers any
    // Notify event for peer B in its stream. Peer B is therefore served only
    // after peer A's loop exits — achieving serial single-peer semantics
    // without any explicit gate.
    loop {
        let evt = match notify_control.next().await {
            Some(e) => e,
            None => {
                warn!("notify control stream ended — adapter lost");
                return Ok(());
            }
        };
        match evt {
            CharacteristicControlEvent::Notify(notifier) => {
                let addr = notifier.device_address();
                let peer = get_or_create_peer(
                    &current,
                    addr,
                    psk,
                    &facade,
                    &rate_limiter,
                    &model,
                    &notify_tx,
                );
                // The writer's MTU is only known once the peer has
                // subscribed; plumb it into the PeerSession so on_request's
                // dispatch task fragments responses to what this connection
                // actually negotiated instead of the 512-byte ceiling.
                peer.set_mtu(notifier.mtu());
                let peer_id = format!("{addr:?}");
                info!(peer = %peer_id, mtu = notifier.mtu(), "peer subscribed");

                let mut notifier = notifier;
                while let Some(frame) = notify_rx.recv().await {
                    if let Err(e) = notifier.write_all(&frame).await {
                        debug!(error = ?e, "notify write failed; peer likely gone");
                        break;
                    }
                }
                // Drain any frames queued by this peer's dispatch tasks before
                // a new peer connects. Without this, a slow WifiScan completing
                // after disconnect would be delivered to the next peer (§7.5
                // single-peer serial semantics).
                while notify_rx.try_recv().is_ok() {}
                *current.lock().unwrap() = None;
                info!(peer = %peer_id, "peer session ended");
            }
            CharacteristicControlEvent::Write(_) => {
                // Writes are already handled by the CharacteristicWriteMethod::Fun
                // closure in gatt.rs; ignore here.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facade_mock::MockFacade;
    use netprov_protocol::{
        MAX_FRAME_LEN, NONCE_LEN, Op, Request, decode_response, encode_request, fragment,
        hmac_compute, parse_frame,
    };

    /// Simulates the exact GATT interaction order the SDK's BleClient now
    /// performs: read Info/nonce, write the auth tag, subscribe (notify),
    /// then write a request — and asserts the request is served
    /// successfully. This is the scenario that was broken before this fix:
    /// on a fresh connection `current` was `None` until subscribe, so
    /// on_nonce_read returned an empty nonce and auth failed.
    #[tokio::test]
    async fn auth_before_subscribe_then_request_succeeds() {
        let psk = [0x42u8; 32];
        let facade = Arc::new(MockFacade::new());
        let rate_limiter = Arc::new(RateLimiter::with_defaults());
        let addr = Address::new([1, 2, 3, 4, 5, 6]);

        let (current, notify_tx, mut notify_rx, handlers) = build_gatt_handlers(
            psk,
            "test-model".into(),
            facade.clone(),
            rate_limiter.clone(),
        );

        // 1. Read Info (unauthenticated, but this is also the SDK's first
        //    GATT touch and must mint a session).
        let info = (handlers.on_info_read)(addr);
        assert!(
            !info.is_empty(),
            "info read should mint a session and respond"
        );

        // 2. Read the challenge nonce.
        let nonce = (handlers.on_nonce_read)(addr);
        assert_eq!(
            nonce.len(),
            NONCE_LEN,
            "nonce must be populated pre-subscribe"
        );
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(&nonce);

        // 3. Write the HMAC auth tag.
        let tag = hmac_compute(&psk, &n);
        let authed = (handlers.on_auth_write)(addr, tag.to_vec());
        assert!(authed, "auth should succeed pre-subscribe");

        // 4. Subscribe: reuse the already-authenticated session rather than
        //    minting a fresh (unauthenticated) one.
        let peer = get_or_create_peer(
            &current,
            addr,
            psk,
            &facade,
            &rate_limiter,
            "test-model",
            &notify_tx,
        );
        assert!(
            peer.session.lock().unwrap().is_authenticated(),
            "subscribe must reuse the authenticated session, not replace it"
        );

        // 5. Write a request and confirm it's served.
        let req = Request {
            request_id: 7,
            op: Op::ListInterfaces,
        };
        let bytes = encode_request(&req).unwrap();
        for f in fragment(req.request_id, &bytes, MAX_FRAME_LEN) {
            (handlers.on_request_write)(f);
        }

        let mut reassembler =
            netprov_protocol::Reassembler::new(netprov_protocol::MAX_MESSAGE_SIZE);
        let resp = loop {
            let frame = notify_rx.recv().await.expect("response frame expected");
            let parsed = parse_frame(&frame).unwrap();
            if let Some(msg) = reassembler.push(parsed).unwrap() {
                break decode_response(&msg).unwrap();
            }
        };
        assert_eq!(resp.request_id, 7);
        assert!(
            resp.result.is_ok(),
            "authenticated request should succeed: {:?}",
            resp.result
        );
    }
}
