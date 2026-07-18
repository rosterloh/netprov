//! Construct the bluer Application describing netprov's GATT service.

use super::uuids::{AUTH_RESPONSE_UUID, CHALLENGE_UUID, INFO_UUID, REQUEST_UUID, SERVICE_UUID};
use bluer::Address;
use bluer::gatt::local::{
    Application, Characteristic, CharacteristicControl, CharacteristicNotify,
    CharacteristicNotifyMethod, CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod,
    Service, characteristic_control,
};
use std::sync::Arc;

/// Thin handle passed to each characteristic's closure so all four share state.
/// The read/write handlers take the peer's device address so the server can
/// mint a `PeerSession` on first GATT interaction, independent of when (or
/// whether) the peer subscribes to notifications.
pub struct GattHandlers {
    pub on_info_read: Arc<dyn Fn(Address) -> Vec<u8> + Send + Sync>,
    pub on_nonce_read: Arc<dyn Fn(Address) -> Vec<u8> + Send + Sync>,
    pub on_auth_write: Arc<dyn Fn(Address, Vec<u8>) -> bool + Send + Sync>,
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
                Characteristic {
                    uuid: CHALLENGE_UUID,
                    read: Some(CharacteristicRead {
                        read: true,
                        encrypt_authenticated_read: true,
                        fun: Box::new(move |req| {
                            let out = (nonce_read)(req.device_address);
                            Box::pin(async move { Ok(out) })
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                // AuthResponse — write-only, returns error to terminate the
                // connection when auth fails. Requires an encrypted link.
                Characteristic {
                    uuid: AUTH_RESPONSE_UUID,
                    write: Some(CharacteristicWrite {
                        write: true,
                        write_without_response: false,
                        encrypt_authenticated_write: true,
                        method: CharacteristicWriteMethod::Fun(Box::new(move |value, req| {
                            let ok = (auth_write)(req.device_address, value);
                            Box::pin(async move {
                                if ok {
                                    Ok(())
                                } else {
                                    Err(bluer::gatt::local::ReqError::NotAuthorized)
                                }
                            })
                        })),
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
                        encrypt_authenticated_write: true,
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

    BuiltApp {
        app,
        notify_control,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Structural check that the encryption-required flags from the
    /// security remediation (Task 2) are set on the right characteristics.
    /// This can't exercise BlueZ/bonding without real hardware, but it does
    /// catch a regression where someone edits gatt.rs and drops a flag.
    #[test]
    fn sensitive_characteristics_require_encryption() {
        let handlers = GattHandlers {
            on_info_read: Arc::new(|_| Vec::new()),
            on_nonce_read: Arc::new(|_| Vec::new()),
            on_auth_write: Arc::new(|_, _| true),
            on_request_write: Arc::new(|_| {}),
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
            challenge.read.as_ref().unwrap().encrypt_authenticated_read,
            "ChallengeNonce read must require an encrypted link"
        );

        let auth = chars.iter().find(|c| c.uuid == AUTH_RESPONSE_UUID).unwrap();
        assert!(
            auth.write.as_ref().unwrap().encrypt_authenticated_write,
            "AuthResponse write must require an encrypted link"
        );

        let request = chars.iter().find(|c| c.uuid == REQUEST_UUID).unwrap();
        assert!(
            request.write.as_ref().unwrap().encrypt_authenticated_write,
            "Request write must require an encrypted link"
        );
    }
}
