//! Construct the bluer Application describing netprov's GATT service.

use super::uuids::{
    AUTH_RESPONSE_UUID, CHALLENGE_UUID, INFO_UUID, REQUEST_UUID, SERVICE_UUID,
};
use bluer::gatt::local::{
    characteristic_control, Application, Characteristic, CharacteristicControl,
    CharacteristicNotify, CharacteristicNotifyMethod, CharacteristicRead,
    CharacteristicWrite, CharacteristicWriteMethod, Service,
};
use std::sync::Arc;

/// Thin handle passed to each characteristic's closure so all four share state.
pub struct GattHandlers {
    pub on_info_read: Arc<dyn Fn() -> Vec<u8> + Send + Sync>,
    pub on_nonce_read: Arc<dyn Fn() -> Vec<u8> + Send + Sync>,
    pub on_auth_write: Arc<dyn Fn(Vec<u8>) -> bool + Send + Sync>,
    pub on_request_write: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
}

/// The result of `build_application`: the Application you register with
/// BlueZ, plus the control stream you poll to receive CharacteristicWriters
/// when a peer subscribes to notifications on REQUEST_UUID.
pub struct BuiltApp {
    pub app: Application,
    pub notify_control: CharacteristicControl,
}

pub fn build_application(h: GattHandlers) -> BuiltApp {
    let info_read = h.on_info_read.clone();
    let nonce_read = h.on_nonce_read.clone();
    let auth_write = h.on_auth_write.clone();
    let request_write = h.on_request_write.clone();

    let (notify_control, notify_handle) = characteristic_control();

    let app = Application {
        services: vec![Service {
            uuid: SERVICE_UUID,
            primary: true,
            characteristics: vec![
                // Info — unauthenticated read.
                Characteristic {
                    uuid: INFO_UUID,
                    read: Some(CharacteristicRead {
                        read: true,
                        fun: Box::new(move |_req| {
                            let out = (info_read)();
                            Box::pin(async move { Ok(out) })
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                // ChallengeNonce — fresh 32 bytes per read.
                Characteristic {
                    uuid: CHALLENGE_UUID,
                    read: Some(CharacteristicRead {
                        read: true,
                        fun: Box::new(move |_req| {
                            let out = (nonce_read)();
                            Box::pin(async move { Ok(out) })
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                // AuthResponse — write-only, returns error to terminate the
                // connection when auth fails.
                Characteristic {
                    uuid: AUTH_RESPONSE_UUID,
                    write: Some(CharacteristicWrite {
                        write: true,
                        write_without_response: false,
                        method: CharacteristicWriteMethod::Fun(Box::new(move |value, _req| {
                            let ok = (auth_write)(value);
                            Box::pin(async move {
                                if ok { Ok(()) }
                                else { Err(bluer::gatt::local::ReqError::NotAuthorized) }
                            })
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                // Request/Response — writeable (fragments in) + notify (fragments out).
                Characteristic {
                    uuid: REQUEST_UUID,
                    write: Some(CharacteristicWrite {
                        write: true,
                        write_without_response: true,
                        method: CharacteristicWriteMethod::Fun(Box::new(move |value, _req| {
                            (request_write)(value);
                            Box::pin(async move { Ok(()) })
                        })),
                        ..Default::default()
                    }),
                    notify: Some(CharacteristicNotify {
                        notify: true,
                        method: CharacteristicNotifyMethod::Io,
                        ..Default::default()
                    }),
                    control_handle: notify_handle,
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    };

    BuiltApp { app, notify_control }
}
