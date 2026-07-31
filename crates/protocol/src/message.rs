use crate::dto::*;
use crate::error::ProtocolError;
use serde::{Deserialize, Serialize};

/// v2 made the auth handshake mutual: `AuthSubmit` carries the client nonce
/// alongside its tag, and the server answers with a tag of its own. v1 peers
/// are not wire-compatible.
pub const PROTOCOL_VERSION: u16 = 2;

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
    GetIpConfig {
        iface: String,
    },
    WifiStatus,
    WifiScan,
    SetDhcp {
        iface: String,
    },
    SetStaticIpv4 {
        iface: String,
        cfg: StaticIpv4,
    },
    ConnectWifi {
        ssid: String,
        credential: WifiCredential,
    },
}

/// Number of `Op` variants, i.e. how many discriminant bits the Info bitmap
/// uses. `supported_ops_covers_every_op` fails to compile if an `Op` is added
/// without updating this.
pub const OP_COUNT: u32 = 7;

/// Every op this build knows about, as an Info `supported_ops` bitmap: bit N
/// is set iff `Op` discriminant N is supported.
///
/// Derived rather than written out, because appending an `Op` is explicitly
/// allowed without a version bump — exactly the change where a hand-maintained
/// constant gets forgotten and the server then advertises a op it does support
/// as missing (#21).
pub const SUPPORTED_OPS_ALL: u32 = (1u32 << OP_COUNT) - 1;

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
    /// Client nonce (`NONCE_LEN`) followed by the client tag (`TAG_LEN`).
    AuthSubmit(#[serde(with = "serde_bytes")] Vec<u8>),
    /// The server's own tag, proving it holds the PSK too.
    AuthOk(#[serde(with = "serde_bytes")] Vec<u8>),
    AuthFail,
    Req(Request),
    Resp(Response),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards [`SUPPORTED_OPS_ALL`] against an `Op` being appended without the
    /// bitmap following (#21).
    ///
    /// Two things break when a variant is added: the exhaustive `match` below
    /// stops compiling, and — once that is fixed — the array length no longer
    /// equals `OP_COUNT`. Between them, the bitmap cannot silently drift.
    #[test]
    fn supported_ops_covers_every_op() {
        let all = [
            Op::ListInterfaces,
            Op::GetIpConfig {
                iface: String::new(),
            },
            Op::WifiStatus,
            Op::WifiScan,
            Op::SetDhcp {
                iface: String::new(),
            },
            Op::SetStaticIpv4 {
                iface: String::new(),
                cfg: StaticIpv4 {
                    address: "192.0.2.1/24".parse().unwrap(),
                    gateway: None,
                    dns: vec![],
                },
            },
            Op::ConnectWifi {
                ssid: String::new(),
                credential: WifiCredential::Open,
            },
        ];
        assert_eq!(
            all.len() as u32,
            OP_COUNT,
            "an Op was added or removed — update OP_COUNT"
        );

        let mut seen = 0u32;
        for (index, op) in all.iter().enumerate() {
            // Exhaustive on purpose: a new variant must be given a bit here.
            let bit = match op {
                Op::ListInterfaces => 0,
                Op::GetIpConfig { .. } => 1,
                Op::WifiStatus => 2,
                Op::WifiScan => 3,
                Op::SetDhcp { .. } => 4,
                Op::SetStaticIpv4 { .. } => 5,
                Op::ConnectWifi { .. } => 6,
            };
            assert_eq!(bit, index as u32, "discriminant order is wire-stable");
            seen |= 1 << bit;
        }
        assert_eq!(seen, SUPPORTED_OPS_ALL);
    }

    #[test]
    fn request_roundtrip() {
        let r = Request {
            request_id: 42,
            op: Op::SetDhcp {
                iface: "wlan0".into(),
            },
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
