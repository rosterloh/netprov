//! BLE adapter initialization + per-peer connection fan-out.

use super::conn::PeerSession;
use super::gatt::{GattHandlers, build_application};
use crate::facade::NetworkFacade;
use crate::rate_limit::RateLimiter;
use bluer::{
    Session as BluerSession,
    adv::{Advertisement, Type as AdvType},
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
    let adapter = match cfg.adapter_name.as_deref() {
        Some(n) => session.adapter(n)?,
        None => session.default_adapter().await?,
    };
    adapter.set_powered(true).await?;
    adapter.set_discoverable(true).await?;
    adapter.set_pairable(true).await?;
    info!(adapter_name = %adapter.name(), address = ?adapter.address().await?, "BLE adapter ready");

    // The PeerSession for the currently-connected peer. bluer's Application is
    // built once with static callbacks; the callbacks forward to whatever
    // PeerSession this Mutex currently holds. v1 serves one peer at a time
    // (spec goal); multi-peer concurrency is a Part 3 concern.
    let current: Arc<std::sync::Mutex<Option<Arc<PeerSession<F>>>>> = Arc::new(Default::default());
    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let handlers = {
        let cur_info = current.clone();
        let cur_nonce = current.clone();
        let cur_auth = current.clone();
        let cur_req = current.clone();
        GattHandlers {
            on_info_read: Arc::new(move || {
                cur_info
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|p| p.on_info())
                    .unwrap_or_default()
            }),
            on_nonce_read: Arc::new(move || {
                cur_nonce
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|p| p.on_nonce())
                    .unwrap_or_default()
            }),
            on_auth_write: Arc::new(move |value| {
                cur_auth
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|p| p.on_auth(value))
                    .unwrap_or(false)
            }),
            on_request_write: Arc::new(move |value| {
                if let Some(p) = cur_req.lock().unwrap().as_ref() {
                    p.on_request(value);
                }
            }),
        }
    };

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

    let model = cfg.model.clone();
    let psk = cfg.psk;

    // Drive the notify control stream: when a peer subscribes, mint a
    // PeerSession for it and pipe notify_rx bytes into the writer.
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
                let peer_id = format!("{:?}", notifier.device_address());
                let peer = PeerSession::new(
                    psk,
                    peer_id.clone(),
                    facade.clone(),
                    rate_limiter.clone(),
                    model.clone(),
                    notify_tx.clone(),
                );
                info!(peer = %peer_id, "peer subscribed; session started");
                *current.lock().unwrap() = Some(peer);

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
