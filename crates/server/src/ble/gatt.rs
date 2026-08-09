//! Construct the bluer Application describing netprov's GATT service.

use super::conn::TimeSetError;
use super::uuids::{
    AUTH_RESPONSE_UUID, CHALLENGE_UUID, CTS_SERVICE_UUID, CURRENT_TIME_UUID, INFO_UUID,
    REQUEST_UUID, SERVICE_UUID,
};
use crate::session::AuthOutcome;
use bluer::Address;
use bluer::gatt::local::{
    Application, Characteristic, CharacteristicControl, CharacteristicNotify,
    CharacteristicNotifyMethod, CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod,
    Service, characteristic_control,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Thin handle passed to each characteristic's closure so all four share state.
/// The read/write handlers take the peer's device address so the server can
/// mint a `PeerSession` on first GATT interaction, independent of when (or
/// whether) the peer subscribes to notifications.
pub struct GattHandlers {
    pub on_info_read: Arc<dyn Fn(Address) -> Vec<u8> + Send + Sync>,
    pub on_nonce_read: Arc<dyn Fn(Address) -> Vec<u8> + Send + Sync>,
    pub on_auth_write: Arc<dyn Fn(Address, Vec<u8>) -> AuthOutcome + Send + Sync>,
    /// Serves the server's auth tag. `None` until this peer's own tag has
    /// verified.
    pub on_auth_read: Arc<dyn Fn(Address) -> Option<Vec<u8>> + Send + Sync>,
    pub on_request_write: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
    /// CurrentTime read — unauthenticated, stateless (mirrors `on_info_read`).
    pub on_time_read: Arc<dyn Fn(Address) -> Vec<u8> + Send + Sync>,
    /// CurrentTime write — async because it may call out to `ClockFacade`
    /// (D-Bus in production). Returns the protocol-level `TimeSetError`; the
    /// GATT closure built in `build_application` maps it to a `ReqError`.
    #[allow(clippy::type_complexity)]
    pub on_time_write:
        Arc<dyn Fn(Address, Vec<u8>) -> BoxFuture<Result<(), TimeSetError>> + Send + Sync>,
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
    let auth_read = h.on_auth_read.clone();
    let request_write = h.on_request_write.clone();
    let time_read = h.on_time_read.clone();
    let time_write = h.on_time_write.clone();

    let (notify_control, notify_handle) = characteristic_control();

    let app = Application {
        services: vec![
            Service {
                uuid: SERVICE_UUID,
                primary: true,
                characteristics: vec![
                    // Info — unauthenticated read.
                    Characteristic {
                        uuid: INFO_UUID,
                        read: Some(CharacteristicRead {
                            read: true,
                            fun: Box::new(move |req| {
                                let out = (info_read)(req.device_address);
                                Box::pin(async move { Ok(out) })
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    // ChallengeNonce — fresh 32 bytes per read. Requires an
                    // encrypted link so the nonce (and everything that follows
                    // on this connection) isn't exchanged over the air in the
                    // clear.
                    //
                    // `encrypt_read`, not `encrypt_authenticated_read`: the
                    // latter is BlueZ's BT_SECURITY_HIGH and needs an
                    // MITM-protected LTK, which a headless box registering a
                    // NoInputNoOutput agent can never negotiate — it made every
                    // read fail with "Encryption is insufficient". Impersonation
                    // is caught by the mutual PSK handshake instead, which is the
                    // only layer here that actually holds a shared secret.
                    Characteristic {
                        uuid: CHALLENGE_UUID,
                        read: Some(CharacteristicRead {
                            read: true,
                            encrypt_read: true,
                            fun: Box::new(move |req| {
                                let out = (nonce_read)(req.device_address);
                                Box::pin(async move { Ok(out) })
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    // AuthResponse — the peer writes its nonce and tag, then reads
                    // back the server's tag. The write returns an error to
                    // terminate the connection when auth fails. Requires an
                    // encrypted link.
                    Characteristic {
                        uuid: AUTH_RESPONSE_UUID,
                        write: Some(CharacteristicWrite {
                            write: true,
                            write_without_response: false,
                            encrypt_write: true,
                            method: CharacteristicWriteMethod::Fun(Box::new(move |value, req| {
                                let outcome = (auth_write)(req.device_address, value);
                                Box::pin(async move {
                                    match outcome {
                                        AuthOutcome::Ok(_) => Ok(()),
                                        // Distinct errors so a locked-out operator
                                        // is not told their key is wrong (#18).
                                        // ATT cannot carry the remaining time, so
                                        // the duration stays server-side in the
                                        // log; the client learns only *why*.
                                        AuthOutcome::BadTag => {
                                            Err(bluer::gatt::local::ReqError::NotAuthorized)
                                        }
                                        AuthOutcome::Locked { .. } => {
                                            Err(bluer::gatt::local::ReqError::NotPermitted)
                                        }
                                    }
                                })
                            })),
                            ..Default::default()
                        }),
                        read: Some(CharacteristicRead {
                            read: true,
                            encrypt_read: true,
                            fun: Box::new(move |req| {
                                let out = (auth_read)(req.device_address);
                                Box::pin(async move {
                                    // Nothing to serve until this peer's tag has
                                    // verified; NotAuthorized rather than an empty
                                    // value so a premature read is unambiguous.
                                    out.ok_or(bluer::gatt::local::ReqError::NotAuthorized)
                                })
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    // Request/Response — writeable (fragments in) + notify
                    // (fragments out). The write side requires an encrypted
                    // link; bluer's CharacteristicNotify has no separate
                    // encryption flag (notifications ride the same encrypted
                    // ATT connection once it's established for the write), so
                    // requiring encryption here protects Wi-Fi credentials
                    // (Op::ConnectWifi) and the response stream alike.
                    Characteristic {
                        uuid: REQUEST_UUID,
                        write: Some(CharacteristicWrite {
                            write: true,
                            write_without_response: true,
                            encrypt_write: true,
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
            },
            Service {
                uuid: CTS_SERVICE_UUID,
                primary: true,
                characteristics: vec![Characteristic {
                    uuid: CURRENT_TIME_UUID,
                    read: Some(CharacteristicRead {
                        read: true,
                        fun: Box::new(move |req| {
                            let out = (time_read)(req.device_address);
                            Box::pin(async move { Ok(out) })
                        }),
                        ..Default::default()
                    }),
                    write: Some(CharacteristicWrite {
                        write: true,
                        write_without_response: false,
                        // Not `encrypt_authenticated_write`: see the module
                        // comment on AUTH_RESPONSE_UUID above. The real trust
                        // boundary is `PeerSession::on_set_time`'s
                        // `is_authenticated()` check against the PSK
                        // handshake, not link-layer encryption.
                        encrypt_write: true,
                        method: CharacteristicWriteMethod::Fun(Box::new(move |value, req| {
                            let fut = (time_write)(req.device_address, value);
                            Box::pin(async move {
                                fut.await.map_err(|e| match e {
                                    TimeSetError::NotAuthenticated => {
                                        bluer::gatt::local::ReqError::NotAuthorized
                                    }
                                    TimeSetError::OutOfClamp => {
                                        bluer::gatt::local::ReqError::NotPermitted
                                    }
                                    TimeSetError::Malformed(_) | TimeSetError::ClockFailed(_) => {
                                        bluer::gatt::local::ReqError::Failed
                                    }
                                })
                            })
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    BuiltApp {
        app,
        notify_control,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Structural check that the encryption-required flags are set on the
    /// right characteristics. This can't exercise BlueZ/bonding without real
    /// hardware, but it does catch a regression where someone edits gatt.rs
    /// and drops a flag.
    ///
    /// These assert `encrypt_*`, *not* `encrypt_authenticated_*`. The
    /// authenticated variants are BT_SECURITY_HIGH and need an MITM-protected
    /// LTK, which a headless peripheral registering a NoInputNoOutput agent
    /// cannot negotiate — every read failed with "Encryption is insufficient"
    /// until this was lowered. Impersonation is caught by the mutual PSK
    /// handshake instead.
    #[test]
    fn sensitive_characteristics_require_encryption() {
        let handlers = GattHandlers {
            on_info_read: Arc::new(|_| Vec::new()),
            on_nonce_read: Arc::new(|_| Vec::new()),
            on_auth_write: Arc::new(|_, _| AuthOutcome::Ok([0u8; 32])),
            on_auth_read: Arc::new(|_| None),
            on_request_write: Arc::new(|_| {}),
            on_time_read: Arc::new(|_| Vec::new()),
            on_time_write: Arc::new(|_, _| Box::pin(async { Ok(()) })),
        };
        let built = build_application(handlers);
        let chars = &built.app.services[0].characteristics;

        let info = chars.iter().find(|c| c.uuid == INFO_UUID).unwrap();
        let read = info.read.as_ref().unwrap();
        assert!(
            !read.encrypt_authenticated_read && !read.encrypt_read,
            "Info must stay open per spec §11"
        );

        let challenge = chars.iter().find(|c| c.uuid == CHALLENGE_UUID).unwrap();
        assert!(
            challenge.read.as_ref().unwrap().encrypt_read,
            "ChallengeNonce read must require an encrypted link"
        );

        let auth = chars.iter().find(|c| c.uuid == AUTH_RESPONSE_UUID).unwrap();
        assert!(
            auth.write.as_ref().unwrap().encrypt_write,
            "AuthResponse write must require an encrypted link"
        );
        assert!(
            auth.read.as_ref().unwrap().encrypt_read,
            "AuthResponse read carries the server tag and must be encrypted"
        );

        let request = chars.iter().find(|c| c.uuid == REQUEST_UUID).unwrap();
        assert!(
            request.write.as_ref().unwrap().encrypt_write,
            "Request write must require an encrypted link"
        );

        let current_time = built.app.services[1]
            .characteristics
            .iter()
            .find(|c| c.uuid == CURRENT_TIME_UUID)
            .unwrap();
        assert!(
            current_time.write.as_ref().unwrap().encrypt_write,
            "CurrentTime write must require an encrypted link"
        );
        assert!(
            !current_time.read.as_ref().unwrap().encrypt_read,
            "CurrentTime read stays open, like Info — it only discloses the server's own clock"
        );
    }
}
