use crate::dto::*;
use crate::error::ProtocolError;
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;

/// Unauthenticated Info characteristic payload. Exposed pre-auth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfoPayload {
    pub protocol_version: u16,
    /// Bitmap of supported Op discriminants. Bit N set ⇒ Op discriminant N supported.
    pub supported_ops: u32,
    /// Short model identifier (no serial, per §11 open question resolution).
    pub model: String,
}

/// One operation per v1 op (§2 scope). Discriminant order is wire-stable —
/// appending new variants is allowed; reordering is a breaking change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    ListInterfaces,
    GetIpConfig { iface: String },
    WifiStatus,
    WifiScan,
    SetDhcp { iface: String },
    SetStaticIpv4 { iface: String, cfg: StaticIpv4 },
    ConnectWifi { ssid: String, credential: WifiCredential },
}

/// Server reply bodies, keyed by the request Op. One variant per Op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpResult {
    Interfaces(Vec<Interface>),
    IpConfig(IpConfig),
    WifiStatus(WifiStatus),
    WifiNetworks(Vec<WifiNetwork>),
    Ok,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub request_id: u16,
    pub op: Op,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub request_id: u16,
    pub result: Result<OpResult, ProtocolError>,
}

/// Loopback transport envelope. Used by Part 1's in-memory transport. Part 2
/// replaces envelope kinds with dedicated GATT characteristics, but the
/// Request/Response shapes remain identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Envelope {
    NonceRequest,
    NonceReply(#[serde(with = "serde_bytes")] Vec<u8>),
    AuthSubmit(#[serde(with = "serde_bytes")] Vec<u8>),
    AuthOk,
    AuthFail,
    Req(Request),
    Resp(Response),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let r = Request {
            request_id: 42,
            op: Op::SetDhcp { iface: "wlan0".into() },
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&r, &mut bytes).unwrap();
        let back: Request = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn response_ok_roundtrip() {
        let r = Response {
            request_id: 1,
            result: Ok(OpResult::Interfaces(vec![])),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&r, &mut bytes).unwrap();
        let back: Response = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn response_err_roundtrip() {
        let r = Response {
            request_id: 7,
            result: Err(ProtocolError::NotAuthenticated),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&r, &mut bytes).unwrap();
        let back: Response = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(r, back);
    }
}
