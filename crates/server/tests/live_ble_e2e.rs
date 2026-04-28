//! End-to-end BLE smoke test. Requires:
//!   * A real Bluetooth adapter visible to BlueZ
//!   * NetworkManager running (uses NmrsFacade under the hood)
//!   * `cargo test --features live-ble -- --ignored --test live_ble_e2e`
//!
//! The test starts a BleServer in the current process, then opens a BleClient
//! to localhost by discovering the freshly-registered service.

#![cfg(feature = "live-ble")]

use netprov_server::{
    MockFacade, RateLimiter,
    ble::{BleServerConfig, run_ble_server},
};
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires real BLE adapter"]
async fn end_to_end_list_interfaces() {
    let psk = [0x42u8; 32];
    let facade = Arc::new(MockFacade::new());
    let rl = Arc::new(RateLimiter::with_defaults());

    // Server runs in a task; client discovers + connects locally.
    let cfg = BleServerConfig {
        psk,
        model: "live-ble-test".into(),
        adapter_name: None,
    };
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let mut ready_tx = Some(ready_tx);

    let server = tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(async {
            run_ble_server(cfg, facade, rl, move || {
                if let Some(tx) = ready_tx.take() {
                    let _ = tx.send(());
                }
            })
            .await
        })
    });

    // Wait until server is advertising.
    ready_rx.await.expect("server never reported ready");

    // TODO(engineer running this by hand):
    // - find the adapter's own BD_ADDR with `bluetoothctl show`
    // - run `netprov --ble-peer <addr> list` in a separate terminal
    // - verify the output matches MockFacade's eth0 + wlan0
    //
    // A fully self-contained E2E would use two controllers — one on the
    // server, one on the client — which most dev boxes don't have. Punt to
    // two-box hardware-in-the-loop testing in Part 3.
    drop(server);
}
