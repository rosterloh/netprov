# netprov Implementation Plan — Part 1: Core

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build netprov's core daemon + CLI logic (protocol, session, facade, validator, key loading, keygen, `NmrsFacade`) exercised by a loopback end-to-end test suite. Deliberately excludes BLE wiring and packaging — those live in Part 2.

**Architecture:** Cargo workspace with three crates: `protocol` (pure wire format), `server` (daemon logic + `netprovd` binary), `client` (CLI + `netprov` binary). The daemon's run loop is generic over any `AsyncRead + AsyncWrite` transport, so Part 1 can test the full client↔server round-trip over `tokio::io::duplex` without any BLE hardware. `NetworkFacade` trait abstracts NetworkManager behind a seam; `MockFacade` powers tests, `NmrsFacade` drives real NM under an opt-in `live-nm` feature flag.

**Tech Stack:** Rust stable, tokio, ciborium (CBOR), serde, hmac + sha2, async-trait, tracing + tracing-journald, clap, anyhow + thiserror, qrcode, proptest. `nmrs` and `zbus` only inside `NmrsFacade`. `bluer` is deferred to Part 2.

---

## Design Reference

Design spec: [`docs/superpowers/specs/2026-04-23-netprov-design.md`](../specs/2026-04-23-netprov-design.md). Section numbers (§) in this plan refer to sections in that spec.

## File Structure

Created in this plan (unless noted):

```
netprov/
├── Cargo.toml                              # workspace root
├── .gitignore
├── rust-toolchain.toml                     # pin to stable
├── README.md
├── crates/
│   ├── protocol/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                      # module re-exports
│   │       ├── dto.rs                      # Interface, IpConfig, WifiStatus, WifiNetwork,
│   │       │                               # StaticIpv4, WifiCredential, Security
│   │       ├── error.rs                    # ProtocolError, NetError, BoundedString
│   │       ├── message.rs                  # Request, Response, Op enum, InfoPayload
│   │       ├── codec.rs                    # CBOR encode/decode helpers
│   │       ├── framing.rs                  # Frame header + Reassembler
│   │       └── auth.rs                     # hmac_compute + constant-time verify
│   ├── server/
│   │   ├── Cargo.toml
│   │   ├── build.rs                        # emits embedded dev-key path
│   │   └── src/
│   │       ├── lib.rs                      # library surface for tests
│   │       ├── main.rs                     # binary entry, clap subcommands
│   │       ├── key.rs                      # load_key(), KeySource enum
│   │       ├── keygen.rs                   # keygen subcommand
│   │       ├── validate.rs                 # validate_static_ipv4()
│   │       ├── rate_limit.rs               # RateLimiter
│   │       ├── session.rs                  # Session state machine
│   │       ├── facade.rs                   # NetworkFacade trait
│   │       ├── facade_mock.rs              # MockFacade (cfg feature = "mock")
│   │       ├── facade_nmrs.rs              # NmrsFacade (cfg feature = "live-nm")
│   │       ├── server_loop.rs              # run_server generic over transport
│   │       └── logging.rs                  # tracing init + dev-key warn loop
│   └── client/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── main.rs
│           ├── cli.rs                      # clap arg structs
│           ├── client.rs                   # Client<T> — handshake + request/response
│           └── commands.rs                 # thin wrappers: one fn per CLI subcommand
├── packaging/
│   ├── dev-key.bin                         # 32-byte committed dev PSK
│   └── README.md                           # "don't use in production" warning
└── tests/
    └── loopback.rs                         # cross-crate integration tests
```

Not in this plan (Part 2): `packaging/netprovd.service`, `packaging/debian/`, cargo-deb metadata, sd-notify, `ble/` modules, `.github/workflows/`.

---

## Phase 0 — Workspace bootstrap

### Task 0.1: Create Cargo workspace scaffolding

**Files:**
- Create: `Cargo.toml`, `.gitignore`, `rust-toolchain.toml`, `README.md`

- [ ] **Step 1: Write workspace `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = ["crates/protocol", "crates/server", "crates/client"]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT OR Apache-2.0"
rust-version = "1.75"

[workspace.dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time", "io-util", "fs", "signal"] }
serde = { version = "1", features = ["derive"] }
serde_bytes = "0.11"
ciborium = "0.2"
anyhow = "1"
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }
tracing-journald = "0.3"
async-trait = "0.1"
clap = { version = "4", features = ["derive"] }
hmac = "0.12"
sha2 = "0.10"
subtle = "2"
rand = "0.8"
proptest = "1"
tokio-util = { version = "0.7", features = ["codec"] }
ipnet = "2"

[profile.release]
lto = "thin"
strip = true
```

- [ ] **Step 2: Write `.gitignore`**

```
/target
Cargo.lock.bak
```

- [ ] **Step 3: Write `rust-toolchain.toml`**

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

- [ ] **Step 4: Write `README.md`**

```markdown
# netprov

Rust BLE network provisioning daemon + CLI for headless embedded Linux.

See [design spec](docs/superpowers/specs/2026-04-23-netprov-design.md).
```

- [ ] **Step 5: Verify workspace resolves**

Run: `cargo metadata --format-version 1 --no-deps > /dev/null`
Expected: exit 0 (no members yet, but Cargo must not error on the `members` list — create empty placeholder crates first if needed).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml .gitignore rust-toolchain.toml README.md
git commit -m "chore: init Cargo workspace"
```

### Task 0.2: Create the three empty crates

**Files:**
- Create: `crates/{protocol,server,client}/Cargo.toml`, `crates/{protocol,server,client}/src/lib.rs`

- [ ] **Step 1: Create `crates/protocol/Cargo.toml`**

```toml
[package]
name = "netprov-protocol"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
serde.workspace = true
serde_bytes.workspace = true
ciborium.workspace = true
thiserror.workspace = true
hmac.workspace = true
sha2.workspace = true
subtle.workspace = true
ipnet = { workspace = true, features = ["serde"] }

[dev-dependencies]
proptest.workspace = true
```

- [ ] **Step 2: Create `crates/protocol/src/lib.rs`**

```rust
//! netprov wire protocol.
```

- [ ] **Step 3: Create `crates/server/Cargo.toml`**

```toml
[package]
name = "netprov-server"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[[bin]]
name = "netprovd"
path = "src/main.rs"

[features]
default = ["mock"]
mock = []
live-nm = ["dep:nmrs", "dep:zbus"]

[dependencies]
netprov-protocol = { path = "../protocol" }
tokio.workspace = true
serde.workspace = true
ciborium.workspace = true
anyhow.workspace = true
thiserror.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
tracing-journald.workspace = true
async-trait.workspace = true
clap.workspace = true
hmac.workspace = true
sha2.workspace = true
subtle.workspace = true
rand.workspace = true
tokio-util.workspace = true
ipnet = { workspace = true, features = ["serde"] }
qrcode = "0.14"
base64 = "0.22"

nmrs = { version = "0.1", optional = true }
zbus = { version = "5", optional = true }

[dev-dependencies]
tokio = { workspace = true, features = ["test-util"] }
proptest.workspace = true
```

> **Note:** Pin the exact `nmrs` version available on crates.io at implementation time. `0.1` here is a placeholder — verify with `cargo search nmrs` as the first action of Task 6.1.

- [ ] **Step 4: Create `crates/server/src/lib.rs` and `crates/server/src/main.rs`**

`crates/server/src/lib.rs`:
```rust
//! netprov server library.
```

`crates/server/src/main.rs`:
```rust
fn main() {
    println!("netprovd — stub");
}
```

- [ ] **Step 5: Create `crates/client/Cargo.toml`**

```toml
[package]
name = "netprov-client"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[[bin]]
name = "netprov"
path = "src/main.rs"

[dependencies]
netprov-protocol = { path = "../protocol" }
netprov-server = { path = "../server", features = ["mock"], optional = true }
tokio.workspace = true
serde.workspace = true
ciborium.workspace = true
anyhow.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
clap.workspace = true
hmac.workspace = true
sha2.workspace = true
tokio-util.workspace = true
ipnet = { workspace = true, features = ["serde"] }

[features]
default = []
loopback = ["dep:netprov-server"]
```

- [ ] **Step 6: Create `crates/client/src/lib.rs` and `crates/client/src/main.rs`**

`crates/client/src/lib.rs`:
```rust
//! netprov client library.
```

`crates/client/src/main.rs`:
```rust
fn main() {
    println!("netprov — stub");
}
```

- [ ] **Step 7: Verify workspace builds**

Run: `cargo build --workspace`
Expected: both binaries build, 0 errors, 0 warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/
git commit -m "chore: scaffold protocol, server, client crates"
```

---

## Phase 1 — Protocol crate

Build the wire format inside-out: DTOs → error types → message envelopes → CBOR codec → framing → auth helpers.

### Task 1.1: DTOs for network state

**Files:**
- Create: `crates/protocol/src/dto.rs`
- Modify: `crates/protocol/src/lib.rs`

Per spec §5 (shared DTOs), §8.1 (facade types).

- [ ] **Step 1: Write failing test in `crates/protocol/src/dto.rs`**

Create the file with:

```rust
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IfaceType { Ethernet, Wifi, Loopback, Other }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IfaceState { Up, Down, Unknown }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub iface_type: IfaceType,
    pub mac: Option<String>,
    pub state: IfaceState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ipv4Method { Auto, Manual }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpConfig {
    pub method: Ipv4Method,
    pub addresses: Vec<Ipv4Net>,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Security { Open, Wep, WpaPsk, Wpa2Psk, Wpa3 }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub signal: Option<u8>,
    pub security: Option<Security>,
    pub bssid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiStatus {
    pub ssid: Option<String>,
    pub signal: Option<u8>,
    pub security: Option<Security>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticIpv4 {
    pub address: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WifiCredential {
    Open,
    WpaPsk(String),
    Wpa2Psk(String),
    Wpa3(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iface_type_roundtrip() {
        for t in [IfaceType::Ethernet, IfaceType::Wifi, IfaceType::Loopback, IfaceType::Other] {
            let bytes = {
                let mut v = Vec::new();
                ciborium::into_writer(&t, &mut v).unwrap();
                v
            };
            let back: IfaceType = ciborium::from_reader(&bytes[..]).unwrap();
            assert_eq!(t, back);
        }
    }

    #[test]
    fn ip_config_roundtrip() {
        let cfg = IpConfig {
            method: Ipv4Method::Manual,
            addresses: vec!["192.168.1.10/24".parse().unwrap()],
            gateway: Some("192.168.1.1".parse().unwrap()),
            dns: vec!["1.1.1.1".parse().unwrap()],
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&cfg, &mut bytes).unwrap();
        let back: IpConfig = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(cfg, back);
    }
}
```

- [ ] **Step 2: Wire the module into `lib.rs`**

Edit `crates/protocol/src/lib.rs` to:

```rust
//! netprov wire protocol.

pub mod dto;

pub use dto::*;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p netprov-protocol`
Expected: 2 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/protocol/src/dto.rs crates/protocol/src/lib.rs
git commit -m "feat(protocol): add network DTOs with CBOR round-trip tests"
```

### Task 1.2: Error types — `BoundedString`, `NetError`, `ProtocolError`

**Files:**
- Create: `crates/protocol/src/error.rs`
- Modify: `crates/protocol/src/lib.rs`

Per spec §7.6 (error model — 512-byte bounded strings).

- [ ] **Step 1: Write failing test in `crates/protocol/src/error.rs`**

```rust
use serde::{Deserialize, Serialize};

pub const BOUNDED_STRING_MAX: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BoundedStringError {
    #[error("string exceeds {BOUNDED_STRING_MAX} byte limit ({got} bytes)")]
    TooLong { got: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedString(String);

impl BoundedString {
    pub fn new(s: impl Into<String>) -> Result<Self, BoundedStringError> {
        let s = s.into();
        if s.len() > BOUNDED_STRING_MAX {
            return Err(BoundedStringError::TooLong { got: s.len() });
        }
        Ok(Self(s))
    }

    pub fn truncated(s: impl Into<String>) -> Self {
        let mut s = s.into();
        if s.len() > BOUNDED_STRING_MAX {
            let mut cut = BOUNDED_STRING_MAX;
            while !s.is_char_boundary(cut) { cut -= 1; }
            s.truncate(cut);
        }
        Self(s)
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

impl Serialize for BoundedString {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for BoundedString {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() > BOUNDED_STRING_MAX {
            return Err(serde::de::Error::custom(format!(
                "string exceeds {BOUNDED_STRING_MAX} byte limit ({} bytes)", s.len()
            )));
        }
        Ok(Self(s))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum NetError {
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),
    #[error("network manager error: {0}")]
    NetworkManager(String),
    #[error("operation timed out")]
    Timeout,
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("not supported")]
    NotSupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum ProtocolError {
    #[error("not authenticated")]
    NotAuthenticated,
    #[error("rate limited; retry after {retry_after_seconds}s")]
    RateLimited { retry_after_seconds: u32 },
    #[error("not supported")]
    NotSupported,
    #[error("invalid argument: {reason}")]
    InvalidArgument { reason: BoundedString },
    #[error("network manager error: {message}")]
    NetworkManagerError { message: BoundedString },
    #[error("internal error: {message}")]
    Internal { message: BoundedString },
}

impl From<NetError> for ProtocolError {
    fn from(e: NetError) -> Self {
        match e {
            NetError::InterfaceNotFound(s) => ProtocolError::InvalidArgument {
                reason: BoundedString::truncated(format!("interface not found: {s}")),
            },
            NetError::NetworkManager(msg) => ProtocolError::NetworkManagerError {
                message: BoundedString::truncated(msg),
            },
            NetError::Timeout => ProtocolError::NetworkManagerError {
                message: BoundedString::new("timeout").unwrap(),
            },
            NetError::InvalidArgument(reason) => ProtocolError::InvalidArgument {
                reason: BoundedString::truncated(reason),
            },
            NetError::NotSupported => ProtocolError::NotSupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_string_accepts_under_limit() {
        let s = BoundedString::new("hello").unwrap();
        assert_eq!(s.as_str(), "hello");
    }

    #[test]
    fn bounded_string_rejects_over_limit() {
        let long = "x".repeat(BOUNDED_STRING_MAX + 1);
        assert!(matches!(
            BoundedString::new(long),
            Err(BoundedStringError::TooLong { got }) if got == BOUNDED_STRING_MAX + 1
        ));
    }

    #[test]
    fn bounded_string_truncated_respects_utf8() {
        let mut s = "a".repeat(BOUNDED_STRING_MAX - 1);
        s.push('€'); // 3 bytes, crosses the boundary
        let b = BoundedString::truncated(s);
        assert!(b.as_str().len() <= BOUNDED_STRING_MAX);
        assert!(std::str::from_utf8(b.as_str().as_bytes()).is_ok());
    }

    #[test]
    fn deserialization_rejects_oversize() {
        let long = "x".repeat(BOUNDED_STRING_MAX + 1);
        let mut bytes = Vec::new();
        ciborium::into_writer(&long, &mut bytes).unwrap();
        let r: Result<BoundedString, _> = ciborium::from_reader(&bytes[..]);
        assert!(r.is_err());
    }

    #[test]
    fn protocol_error_roundtrip() {
        let e = ProtocolError::RateLimited { retry_after_seconds: 60 };
        let mut bytes = Vec::new();
        ciborium::into_writer(&e, &mut bytes).unwrap();
        let back: ProtocolError = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(e, back);
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Append to `crates/protocol/src/lib.rs`:

```rust
pub mod error;
pub use error::*;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p netprov-protocol`
Expected: 7 passed (2 from Task 1.1 + 5 new).

- [ ] **Step 4: Commit**

```bash
git add crates/protocol/src/error.rs crates/protocol/src/lib.rs
git commit -m "feat(protocol): add BoundedString, NetError, ProtocolError"
```

### Task 1.3: Message envelope — `Op`, `Request`, `Response`, `InfoPayload`

**Files:**
- Create: `crates/protocol/src/message.rs`
- Modify: `crates/protocol/src/lib.rs`

Per spec §7.5 (request_id correlation), §7.6 (Result-shaped responses).

- [ ] **Step 1: Write failing test in `crates/protocol/src/message.rs`**

```rust
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
```

- [ ] **Step 2: Wire into `lib.rs`**

Append to `crates/protocol/src/lib.rs`:

```rust
pub mod message;
pub use message::*;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p netprov-protocol`
Expected: 10 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/protocol/src/message.rs crates/protocol/src/lib.rs
git commit -m "feat(protocol): add Op, Request, Response, InfoPayload"
```

### Task 1.4: CBOR codec helpers

**Files:**
- Create: `crates/protocol/src/codec.rs`
- Modify: `crates/protocol/src/lib.rs`

- [ ] **Step 1: Write failing test in `crates/protocol/src/codec.rs`**

```rust
use crate::message::{Request, Response};
use serde::{de::DeserializeOwned, Serialize};

pub const MAX_MESSAGE_SIZE: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("encode failed: {0}")]
    Encode(String),
    #[error("decode failed: {0}")]
    Decode(String),
    #[error("message exceeds {MAX_MESSAGE_SIZE} byte limit ({got} bytes)")]
    TooLarge { got: usize },
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::with_capacity(256);
    ciborium::into_writer(value, &mut out).map_err(|e| CodecError::Encode(e.to_string()))?;
    if out.len() > MAX_MESSAGE_SIZE {
        return Err(CodecError::TooLarge { got: out.len() });
    }
    Ok(out)
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    if bytes.len() > MAX_MESSAGE_SIZE {
        return Err(CodecError::TooLarge { got: bytes.len() });
    }
    ciborium::from_reader(bytes).map_err(|e| CodecError::Decode(e.to_string()))
}

pub fn encode_request(req: &Request) -> Result<Vec<u8>, CodecError> { encode(req) }
pub fn decode_request(bytes: &[u8]) -> Result<Request, CodecError> { decode(bytes) }
pub fn encode_response(resp: &Response) -> Result<Vec<u8>, CodecError> { encode(resp) }
pub fn decode_response(bytes: &[u8]) -> Result<Response, CodecError> { decode(bytes) }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Op, Request};

    #[test]
    fn encode_decode_symmetric() {
        let r = Request {
            request_id: 0xbeef,
            op: Op::ListInterfaces,
        };
        let bytes = encode_request(&r).unwrap();
        let back = decode_request(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn decode_rejects_oversize() {
        let too_big = vec![0u8; MAX_MESSAGE_SIZE + 1];
        assert!(matches!(
            decode::<Request>(&too_big),
            Err(CodecError::TooLarge { got }) if got == MAX_MESSAGE_SIZE + 1
        ));
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Append:

```rust
pub mod codec;
pub use codec::*;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p netprov-protocol`
Expected: 12 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/protocol/src/codec.rs crates/protocol/src/lib.rs
git commit -m "feat(protocol): add CBOR codec with MAX_MESSAGE_SIZE cap"
```

### Task 1.5: Framing — fragment + reassemble

**Files:**
- Create: `crates/protocol/src/framing.rs`
- Modify: `crates/protocol/src/lib.rs`

Per spec §7.2.

- [ ] **Step 1: Write failing tests in `crates/protocol/src/framing.rs`**

```rust
//! Fragmented framing over small GATT writes/notifies.
//!
//! Each physical frame carries: `[u16 request_id BE][u16 seq BE][u8 flags][payload]`.
//! `flags` bit 0 is `FIN` (last fragment in the message).

pub const FRAME_HEADER_LEN: usize = 5;
pub const FRAME_FLAG_FIN: u8 = 0x01;
pub const MAX_PAYLOAD_PER_FRAME: usize = 512 - FRAME_HEADER_LEN; // Web Bluetooth ceiling

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("frame too short ({0} bytes, need >= {FRAME_HEADER_LEN})")]
    TooShort(usize),
    #[error("reassembled message exceeds {limit} bytes")]
    MessageTooLarge { limit: usize },
    #[error("duplicate sequence number {seq} for request {request_id}")]
    DuplicateSeq { request_id: u16, seq: u16 },
    #[error("missing fragments for request {request_id} (have {got}, FIN at seq {fin_seq})")]
    MissingFragments { request_id: u16, got: usize, fin_seq: u16 },
}

pub fn fragment(
    request_id: u16,
    payload: &[u8],
    max_fragment: usize,
) -> Vec<Vec<u8>> {
    let body = max_fragment.saturating_sub(FRAME_HEADER_LEN).max(1);
    if payload.is_empty() {
        return vec![encode_frame(request_id, 0, FRAME_FLAG_FIN, &[])];
    }
    let total = payload.len().div_ceil(body);
    (0..total)
        .map(|i| {
            let start = i * body;
            let end = (start + body).min(payload.len());
            let flags = if i + 1 == total { FRAME_FLAG_FIN } else { 0 };
            encode_frame(request_id, i as u16, flags, &payload[start..end])
        })
        .collect()
}

fn encode_frame(request_id: u16, seq: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.extend_from_slice(&request_id.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.push(flags);
    out.extend_from_slice(payload);
    out
}

/// Per-connection, per-request reassembly buffer.
pub struct Reassembler {
    pub max_message: usize,
    state: std::collections::HashMap<u16, PartialMessage>,
}

struct PartialMessage {
    frags: std::collections::BTreeMap<u16, Vec<u8>>,
    fin_seq: Option<u16>,
    total_bytes: usize,
}

pub struct ParsedFrame<'a> {
    pub request_id: u16,
    pub seq: u16,
    pub fin: bool,
    pub payload: &'a [u8],
}

pub fn parse_frame(bytes: &[u8]) -> Result<ParsedFrame<'_>, FramingError> {
    if bytes.len() < FRAME_HEADER_LEN {
        return Err(FramingError::TooShort(bytes.len()));
    }
    Ok(ParsedFrame {
        request_id: u16::from_be_bytes([bytes[0], bytes[1]]),
        seq: u16::from_be_bytes([bytes[2], bytes[3]]),
        fin: bytes[4] & FRAME_FLAG_FIN != 0,
        payload: &bytes[FRAME_HEADER_LEN..],
    })
}

impl Reassembler {
    pub fn new(max_message: usize) -> Self {
        Self { max_message, state: Default::default() }
    }

    /// Feed one parsed fragment. Returns `Some(message_bytes)` when a FIN is
    /// received and all prior seqs are present.
    pub fn push(&mut self, f: ParsedFrame<'_>) -> Result<Option<Vec<u8>>, FramingError> {
        let entry = self.state.entry(f.request_id).or_insert_with(|| PartialMessage {
            frags: Default::default(),
            fin_seq: None,
            total_bytes: 0,
        });

        if entry.frags.contains_key(&f.seq) {
            return Err(FramingError::DuplicateSeq {
                request_id: f.request_id,
                seq: f.seq,
            });
        }
        entry.total_bytes += f.payload.len();
        if entry.total_bytes > self.max_message {
            self.state.remove(&f.request_id);
            return Err(FramingError::MessageTooLarge { limit: self.max_message });
        }
        entry.frags.insert(f.seq, f.payload.to_vec());
        if f.fin {
            entry.fin_seq = Some(f.seq);
        }

        if let Some(fin_seq) = entry.fin_seq {
            let expected = (fin_seq as usize) + 1;
            if entry.frags.len() == expected {
                let mut out = Vec::with_capacity(entry.total_bytes);
                for (_, frag) in entry.frags.iter() {
                    out.extend_from_slice(frag);
                }
                self.state.remove(&f.request_id);
                return Ok(Some(out));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_frame_roundtrip() {
        let payload = b"hello";
        let frames = fragment(1, payload, 512);
        assert_eq!(frames.len(), 1);
        let parsed = parse_frame(&frames[0]).unwrap();
        assert_eq!(parsed.request_id, 1);
        assert_eq!(parsed.seq, 0);
        assert!(parsed.fin);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn multi_frame_reassemble() {
        let payload: Vec<u8> = (0..1000u32).map(|x| (x & 0xff) as u8).collect();
        let frames = fragment(99, &payload, 64);
        let mut r = Reassembler::new(4096);
        let mut result = None;
        for f in &frames {
            let parsed = parse_frame(f).unwrap();
            if let Some(msg) = r.push(parsed).unwrap() {
                result = Some(msg);
            }
        }
        assert_eq!(result.unwrap(), payload);
    }

    #[test]
    fn too_short_frame_rejected() {
        assert!(matches!(parse_frame(b"abc"), Err(FramingError::TooShort(3))));
    }

    #[test]
    fn oversize_message_rejected() {
        let payload = vec![0u8; 1024];
        let frames = fragment(5, &payload, 64);
        let mut r = Reassembler::new(256);
        let mut err = None;
        for f in &frames {
            let parsed = parse_frame(f).unwrap();
            if let Err(e) = r.push(parsed) {
                err = Some(e);
                break;
            }
        }
        assert!(matches!(err, Some(FramingError::MessageTooLarge { .. })));
    }

    #[test]
    fn duplicate_seq_rejected() {
        let f0 = encode_frame(1, 0, 0, b"aa");
        let f0b = encode_frame(1, 0, 0, b"bb");
        let mut r = Reassembler::new(4096);
        r.push(parse_frame(&f0).unwrap()).unwrap();
        let err = r.push(parse_frame(&f0b).unwrap()).unwrap_err();
        assert!(matches!(err, FramingError::DuplicateSeq { .. }));
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Append:

```rust
pub mod framing;
pub use framing::*;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p netprov-protocol`
Expected: 17 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/protocol/src/framing.rs crates/protocol/src/lib.rs
git commit -m "feat(protocol): add fragment/reassemble framing"
```

### Task 1.6: Framing property test — round-trip

**Files:**
- Modify: `crates/protocol/src/framing.rs`

- [ ] **Step 1: Append property test to `framing.rs` tests module**

Inside the existing `#[cfg(test)] mod tests` block:

```rust
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fragment_reassemble_roundtrip(
            rid in any::<u16>(),
            payload in proptest::collection::vec(any::<u8>(), 0..2000usize),
            mtu in 16usize..512,
        ) {
            let frames = fragment(rid, &payload, mtu);
            let mut r = Reassembler::new(4096);
            let mut out = None;
            for f in &frames {
                let parsed = parse_frame(f).unwrap();
                if let Some(msg) = r.push(parsed).unwrap() {
                    out = Some(msg);
                }
            }
            prop_assert_eq!(out.unwrap(), payload);
        }
    }
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p netprov-protocol`
Expected: 18 passed (includes 256 property cases for `fragment_reassemble_roundtrip`).

- [ ] **Step 3: Commit**

```bash
git add crates/protocol/src/framing.rs
git commit -m "test(protocol): property test for framing round-trip"
```

### Task 1.7: Auth helpers — HMAC compute + constant-time verify

**Files:**
- Create: `crates/protocol/src/auth.rs`
- Modify: `crates/protocol/src/lib.rs`

Per spec §7.3 (HMAC-SHA256 challenge/response), §3 (constant-time compare).

- [ ] **Step 1: Write failing test in `crates/protocol/src/auth.rs`**

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const PSK_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;
pub const TAG_LEN: usize = 32;

pub type Psk = [u8; PSK_LEN];
pub type Nonce = [u8; NONCE_LEN];
pub type Tag = [u8; TAG_LEN];

pub fn hmac_compute(psk: &Psk, nonce: &Nonce) -> Tag {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(psk).expect("HMAC accepts any key len");
    mac.update(nonce);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&out);
    tag
}

pub fn hmac_verify(psk: &Psk, nonce: &Nonce, candidate: &[u8]) -> bool {
    if candidate.len() != TAG_LEN {
        return false;
    }
    let expected = hmac_compute(psk, nonce);
    expected.ct_eq(candidate).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_accepts_correct_tag() {
        let psk = [7u8; PSK_LEN];
        let nonce = [42u8; NONCE_LEN];
        let tag = hmac_compute(&psk, &nonce);
        assert!(hmac_verify(&psk, &nonce, &tag));
    }

    #[test]
    fn verify_rejects_wrong_psk() {
        let psk_a = [1u8; PSK_LEN];
        let psk_b = [2u8; PSK_LEN];
        let nonce = [0u8; NONCE_LEN];
        let tag = hmac_compute(&psk_a, &nonce);
        assert!(!hmac_verify(&psk_b, &nonce, &tag));
    }

    #[test]
    fn verify_rejects_wrong_length() {
        let psk = [0u8; PSK_LEN];
        let nonce = [0u8; NONCE_LEN];
        assert!(!hmac_verify(&psk, &nonce, b"too short"));
        assert!(!hmac_verify(&psk, &nonce, &[0u8; TAG_LEN + 1]));
    }

    #[test]
    fn different_nonces_produce_different_tags() {
        let psk = [0u8; PSK_LEN];
        let t1 = hmac_compute(&psk, &[1u8; NONCE_LEN]);
        let t2 = hmac_compute(&psk, &[2u8; NONCE_LEN]);
        assert_ne!(t1, t2);
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Append:

```rust
pub mod auth;
pub use auth::*;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p netprov-protocol`
Expected: 22 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/protocol/src/auth.rs crates/protocol/src/lib.rs
git commit -m "feat(protocol): add HMAC compute + constant-time verify"
```

---

## Phase 2 — Server core (no transport, no NM)

### Task 2.1: `NetworkFacade` trait

**Files:**
- Create: `crates/server/src/facade.rs`
- Modify: `crates/server/src/lib.rs`

Per spec §8.1.

- [ ] **Step 1: Write `crates/server/src/facade.rs`**

```rust
use async_trait::async_trait;
use netprov_protocol::{Interface, IpConfig, NetError, StaticIpv4, WifiCredential, WifiNetwork, WifiStatus};

#[async_trait]
pub trait NetworkFacade: Send + Sync {
    async fn list_interfaces(&self) -> Result<Vec<Interface>, NetError>;
    async fn get_ip_config(&self, iface: &str) -> Result<IpConfig, NetError>;
    async fn wifi_status(&self) -> Result<WifiStatus, NetError>;
    async fn scan_wifi(&self) -> Result<Vec<WifiNetwork>, NetError>;
    async fn set_dhcp(&self, iface: &str) -> Result<(), NetError>;
    async fn set_static_ipv4(&self, iface: &str, cfg: StaticIpv4) -> Result<(), NetError>;
    async fn connect_wifi(&self, ssid: &str, cred: WifiCredential) -> Result<(), NetError>;
}
```

- [ ] **Step 2: Wire into `lib.rs`**

`crates/server/src/lib.rs`:

```rust
//! netprov server library.

pub mod facade;
pub use facade::NetworkFacade;
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build -p netprov-server`
Expected: success.

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/facade.rs crates/server/src/lib.rs
git commit -m "feat(server): define NetworkFacade trait"
```

### Task 2.2: `MockFacade`

**Files:**
- Create: `crates/server/src/facade_mock.rs`
- Modify: `crates/server/src/lib.rs`

Per spec §8.1 (MockFacade), §10 (central to test tiers).

- [ ] **Step 1: Write failing test in `crates/server/src/facade_mock.rs`**

```rust
use crate::facade::NetworkFacade;
use async_trait::async_trait;
use netprov_protocol::*;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

/// A deterministic, in-memory NetworkFacade for tests. Not stable across
/// process restarts — pure test double.
pub struct MockFacade {
    inner: Mutex<MockState>,
}

struct MockState {
    interfaces: Vec<Interface>,
    ip_configs: HashMap<String, IpConfig>,
    scan: Vec<WifiNetwork>,
    wifi_status: WifiStatus,
    inject_error: Option<NetError>,
}

impl Default for MockFacade {
    fn default() -> Self {
        Self::new()
    }
}

impl MockFacade {
    pub fn new() -> Self {
        let interfaces = vec![
            Interface {
                name: "eth0".into(),
                iface_type: IfaceType::Ethernet,
                mac: Some("aa:bb:cc:00:11:22".into()),
                state: IfaceState::Up,
            },
            Interface {
                name: "wlan0".into(),
                iface_type: IfaceType::Wifi,
                mac: Some("aa:bb:cc:00:11:33".into()),
                state: IfaceState::Up,
            },
        ];
        let mut ip_configs = HashMap::new();
        ip_configs.insert("eth0".into(), IpConfig {
            method: Ipv4Method::Auto,
            addresses: vec!["192.168.1.50/24".parse().unwrap()],
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns: vec![Ipv4Addr::new(1, 1, 1, 1)],
        });
        ip_configs.insert("wlan0".into(), IpConfig {
            method: Ipv4Method::Auto,
            addresses: vec![],
            gateway: None,
            dns: vec![],
        });

        Self {
            inner: Mutex::new(MockState {
                interfaces,
                ip_configs,
                scan: vec![WifiNetwork {
                    ssid: "HomeWifi".into(),
                    signal: Some(80),
                    security: Some(Security::Wpa2Psk),
                    bssid: "de:ad:be:ef:00:01".into(),
                }],
                wifi_status: WifiStatus {
                    ssid: None,
                    signal: None,
                    security: None,
                },
                inject_error: None,
            }),
        }
    }

    pub fn inject_error(&self, e: NetError) {
        self.inner.lock().unwrap().inject_error = Some(e);
    }

    pub fn clear_error(&self) {
        self.inner.lock().unwrap().inject_error = None;
    }
}

fn take_injected(s: &mut MockState) -> Option<NetError> {
    s.inject_error.take()
}

#[async_trait]
impl NetworkFacade for MockFacade {
    async fn list_interfaces(&self) -> Result<Vec<Interface>, NetError> {
        let mut s = self.inner.lock().unwrap();
        if let Some(e) = take_injected(&mut s) { return Err(e); }
        Ok(s.interfaces.clone())
    }

    async fn get_ip_config(&self, iface: &str) -> Result<IpConfig, NetError> {
        let mut s = self.inner.lock().unwrap();
        if let Some(e) = take_injected(&mut s) { return Err(e); }
        s.ip_configs.get(iface).cloned()
            .ok_or_else(|| NetError::InterfaceNotFound(iface.to_string()))
    }

    async fn wifi_status(&self) -> Result<WifiStatus, NetError> {
        let mut s = self.inner.lock().unwrap();
        if let Some(e) = take_injected(&mut s) { return Err(e); }
        Ok(s.wifi_status.clone())
    }

    async fn scan_wifi(&self) -> Result<Vec<WifiNetwork>, NetError> {
        let mut s = self.inner.lock().unwrap();
        if let Some(e) = take_injected(&mut s) { return Err(e); }
        Ok(s.scan.clone())
    }

    async fn set_dhcp(&self, iface: &str) -> Result<(), NetError> {
        let mut s = self.inner.lock().unwrap();
        if let Some(e) = take_injected(&mut s) { return Err(e); }
        let cfg = s.ip_configs.get_mut(iface)
            .ok_or_else(|| NetError::InterfaceNotFound(iface.to_string()))?;
        cfg.method = Ipv4Method::Auto;
        cfg.addresses.clear();
        cfg.gateway = None;
        cfg.dns.clear();
        Ok(())
    }

    async fn set_static_ipv4(&self, iface: &str, new: StaticIpv4) -> Result<(), NetError> {
        let mut s = self.inner.lock().unwrap();
        if let Some(e) = take_injected(&mut s) { return Err(e); }
        let cfg = s.ip_configs.get_mut(iface)
            .ok_or_else(|| NetError::InterfaceNotFound(iface.to_string()))?;
        cfg.method = Ipv4Method::Manual;
        cfg.addresses = vec![new.address];
        cfg.gateway = new.gateway;
        cfg.dns = new.dns;
        Ok(())
    }

    async fn connect_wifi(&self, ssid: &str, _cred: WifiCredential) -> Result<(), NetError> {
        let mut s = self.inner.lock().unwrap();
        if let Some(e) = take_injected(&mut s) { return Err(e); }
        s.wifi_status = WifiStatus {
            ssid: Some(ssid.to_string()),
            signal: Some(70),
            security: Some(Security::Wpa2Psk),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn list_interfaces_default() {
        let m = MockFacade::new();
        let ifs = m.list_interfaces().await.unwrap();
        assert_eq!(ifs.len(), 2);
    }

    #[tokio::test]
    async fn set_dhcp_clears_static_fields() {
        let m = MockFacade::new();
        m.set_dhcp("eth0").await.unwrap();
        let cfg = m.get_ip_config("eth0").await.unwrap();
        assert!(matches!(cfg.method, Ipv4Method::Auto));
        assert!(cfg.addresses.is_empty());
        assert!(cfg.gateway.is_none());
    }

    #[tokio::test]
    async fn unknown_interface_returns_error() {
        let m = MockFacade::new();
        let err = m.set_dhcp("bogus0").await.unwrap_err();
        assert!(matches!(err, NetError::InterfaceNotFound(_)));
    }

    #[tokio::test]
    async fn injected_error_is_returned_once() {
        let m = MockFacade::new();
        m.inject_error(NetError::Timeout);
        let err = m.list_interfaces().await.unwrap_err();
        assert!(matches!(err, NetError::Timeout));
        // Subsequent calls succeed — injected error is one-shot.
        assert!(m.list_interfaces().await.is_ok());
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`** (gated on `mock` feature)

Replace `crates/server/src/lib.rs`:

```rust
//! netprov server library.

pub mod facade;
pub use facade::NetworkFacade;

#[cfg(feature = "mock")]
pub mod facade_mock;
#[cfg(feature = "mock")]
pub use facade_mock::MockFacade;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p netprov-server`
Expected: 4 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/facade_mock.rs crates/server/src/lib.rs
git commit -m "feat(server): add MockFacade for tests"
```

### Task 2.3: Static-IP validator

**Files:**
- Create: `crates/server/src/validate.rs`
- Modify: `crates/server/src/lib.rs`

Per spec §8.3.

- [ ] **Step 1: Write failing test in `crates/server/src/validate.rs`**

```rust
use ipnet::Ipv4Net;
use netprov_protocol::{NetError, StaticIpv4};
use std::net::Ipv4Addr;

pub fn validate_static_ipv4(cfg: &StaticIpv4) -> Result<(), NetError> {
    let addr = cfg.address.addr();
    let prefix = cfg.address.prefix_len();

    if !(1..=30).contains(&prefix) {
        return Err(NetError::InvalidArgument(format!(
            "prefix length {prefix} out of range (1..=30)"
        )));
    }
    if addr.is_loopback() {
        return Err(NetError::InvalidArgument("address is loopback".into()));
    }
    if addr.is_multicast() {
        return Err(NetError::InvalidArgument("address is multicast".into()));
    }
    if addr.is_broadcast() {
        return Err(NetError::InvalidArgument("address is broadcast".into()));
    }
    if addr.is_unspecified() {
        return Err(NetError::InvalidArgument("address is unspecified".into()));
    }
    if addr == cfg.address.broadcast() {
        return Err(NetError::InvalidArgument(
            "address equals subnet broadcast".into(),
        ));
    }
    if addr == cfg.address.network() {
        return Err(NetError::InvalidArgument(
            "address equals subnet network".into(),
        ));
    }
    if let Some(gw) = cfg.gateway {
        if !cfg.address.contains(&gw) {
            return Err(NetError::InvalidArgument(
                "gateway is outside subnet".into(),
            ));
        }
        if gw == addr {
            return Err(NetError::InvalidArgument(
                "gateway equals host address".into(),
            ));
        }
    }
    for dns in &cfg.dns {
        if dns.is_unspecified() || dns.is_multicast() || dns.is_broadcast() {
            return Err(NetError::InvalidArgument(
                "dns server has invalid address".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(addr: &str, gw: Option<&str>, dns: &[&str]) -> StaticIpv4 {
        StaticIpv4 {
            address: addr.parse().unwrap(),
            gateway: gw.map(|s| s.parse().unwrap()),
            dns: dns.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn valid_config_accepted() {
        assert!(validate_static_ipv4(&cfg("192.168.1.10/24", Some("192.168.1.1"), &["1.1.1.1"])).is_ok());
    }

    #[test]
    fn zero_prefix_rejected() {
        assert!(validate_static_ipv4(&cfg("10.0.0.1/0", None, &[])).is_err());
    }

    #[test]
    fn host_route_prefix_rejected() {
        assert!(validate_static_ipv4(&cfg("10.0.0.1/31", None, &[])).is_err());
    }

    #[test]
    fn loopback_rejected() {
        assert!(validate_static_ipv4(&cfg("127.0.0.2/8", None, &[])).is_err());
    }

    #[test]
    fn multicast_rejected() {
        assert!(validate_static_ipv4(&cfg("224.0.0.1/24", None, &[])).is_err());
    }

    #[test]
    fn subnet_broadcast_rejected() {
        assert!(validate_static_ipv4(&cfg("192.168.1.255/24", None, &[])).is_err());
    }

    #[test]
    fn subnet_network_rejected() {
        assert!(validate_static_ipv4(&cfg("192.168.1.0/24", None, &[])).is_err());
    }

    #[test]
    fn gateway_outside_subnet_rejected() {
        assert!(validate_static_ipv4(&cfg("192.168.1.10/24", Some("10.0.0.1"), &[])).is_err());
    }

    #[test]
    fn gateway_equals_host_rejected() {
        assert!(validate_static_ipv4(&cfg("192.168.1.10/24", Some("192.168.1.10"), &[])).is_err());
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Append:

```rust
pub mod validate;
pub use validate::validate_static_ipv4;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p netprov-server`
Expected: 13 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/validate.rs crates/server/src/lib.rs
git commit -m "feat(server): add static-IPv4 validator"
```

### Task 2.4: Rate limiter

**Files:**
- Create: `crates/server/src/rate_limit.rs`
- Modify: `crates/server/src/lib.rs`

Per spec §7.4.

- [ ] **Step 1: Write failing test in `crates/server/src/rate_limit.rs`**

```rust
//! Per-peer failed-auth rate limiter.
//!
//! Defaults from §7.4: 5 failures in 60s → 10 minute lockout.

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RateLimiterConfig {
    pub threshold: u32,
    pub window: Duration,
    pub lockout: Duration,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            threshold: 5,
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(600),
        }
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Instant { Instant::now() }
}

pub struct RateLimiter<C: Clock = SystemClock> {
    cfg: RateLimiterConfig,
    clock: C,
    state: std::sync::Mutex<HashMap<String, PeerState>>,
}

struct PeerState {
    failures: Vec<Instant>,
    locked_until: Option<Instant>,
}

pub enum CheckResult {
    Allowed,
    Locked { retry_after: Duration },
}

impl RateLimiter<SystemClock> {
    pub fn with_defaults() -> Self {
        Self::new(RateLimiterConfig::default(), SystemClock)
    }
}

impl<C: Clock> RateLimiter<C> {
    pub fn new(cfg: RateLimiterConfig, clock: C) -> Self {
        Self { cfg, clock, state: Default::default() }
    }

    pub fn check(&self, peer: &str) -> CheckResult {
        let now = self.clock.now();
        let mut map = self.state.lock().unwrap();
        let e = map.entry(peer.to_string()).or_insert(PeerState {
            failures: Vec::new(),
            locked_until: None,
        });
        if let Some(until) = e.locked_until {
            if now < until {
                return CheckResult::Locked { retry_after: until - now };
            }
            e.locked_until = None;
            e.failures.clear();
        }
        CheckResult::Allowed
    }

    /// Record a failed auth attempt. Returns `true` if this triggered lockout.
    pub fn record_failure(&self, peer: &str) -> bool {
        let now = self.clock.now();
        let mut map = self.state.lock().unwrap();
        let e = map.entry(peer.to_string()).or_insert(PeerState {
            failures: Vec::new(),
            locked_until: None,
        });
        // drop failures outside the window
        let cutoff = now.checked_sub(self.cfg.window).unwrap_or(now);
        e.failures.retain(|t| *t >= cutoff);
        e.failures.push(now);
        if e.failures.len() as u32 >= self.cfg.threshold {
            e.locked_until = Some(now + self.cfg.lockout);
            true
        } else {
            false
        }
    }

    /// Clear failure history for a peer on successful auth.
    pub fn record_success(&self, peer: &str) {
        self.state.lock().unwrap().remove(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct FakeClock { t: Cell<Instant> }
    impl FakeClock { fn new() -> Self { Self { t: Cell::new(Instant::now()) } } }
    impl FakeClock { fn advance(&self, d: Duration) { self.t.set(self.t.get() + d); } }
    unsafe impl Sync for FakeClock {} // FakeClock used single-threaded in tests
    impl Clock for FakeClock { fn now(&self) -> Instant { self.t.get() } }

    #[test]
    fn allows_under_threshold() {
        let r = RateLimiter::new(RateLimiterConfig::default(), FakeClock::new());
        for _ in 0..4 {
            assert!(matches!(r.check("A"), CheckResult::Allowed));
            assert!(!r.record_failure("A"));
        }
    }

    #[test]
    fn locks_on_threshold() {
        let clock = FakeClock::new();
        let r = RateLimiter::new(RateLimiterConfig::default(), clock);
        for i in 0..4 { assert!(!r.record_failure("A"), "fail {i}"); }
        assert!(r.record_failure("A")); // 5th failure triggers lockout
        assert!(matches!(r.check("A"), CheckResult::Locked { .. }));
    }

    #[test]
    fn success_clears_failures() {
        let r = RateLimiter::new(RateLimiterConfig::default(), FakeClock::new());
        r.record_failure("A");
        r.record_failure("A");
        r.record_success("A");
        for _ in 0..4 { assert!(!r.record_failure("A")); }
    }

    #[test]
    fn failures_expire_after_window() {
        let clock = FakeClock::new();
        let r = RateLimiter::new(
            RateLimiterConfig { threshold: 3, window: Duration::from_secs(10), lockout: Duration::from_secs(60) },
            clock,
        );
        r.record_failure("A");
        r.record_failure("A");
        // advance past window
        r.clock.advance(Duration::from_secs(20));
        assert!(!r.record_failure("A")); // only 1 failure in current window
    }

    #[test]
    fn lockout_clears_after_expiry() {
        let clock = FakeClock::new();
        let r = RateLimiter::new(
            RateLimiterConfig { threshold: 2, window: Duration::from_secs(60), lockout: Duration::from_secs(30) },
            clock,
        );
        r.record_failure("A");
        assert!(r.record_failure("A")); // locked
        r.clock.advance(Duration::from_secs(31));
        assert!(matches!(r.check("A"), CheckResult::Allowed));
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Append:

```rust
pub mod rate_limit;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p netprov-server`
Expected: 18 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/rate_limit.rs crates/server/src/lib.rs
git commit -m "feat(server): add per-peer rate limiter"
```

### Task 2.5: Session state machine

**Files:**
- Create: `crates/server/src/session.rs`
- Modify: `crates/server/src/lib.rs`

Per spec §7.3 (auth flow), §7.5 (request/response).

- [ ] **Step 1: Write failing test in `crates/server/src/session.rs`**

```rust
use crate::facade::NetworkFacade;
use crate::rate_limit::{CheckResult, RateLimiter};
use crate::validate::validate_static_ipv4;
use netprov_protocol::*;
use rand::RngCore;
use std::sync::Arc;

pub struct Session<F: NetworkFacade> {
    psk: Psk,
    peer_id: String, // e.g., BLE peer MAC; opaque identifier.
    facade: Arc<F>,
    rate_limiter: Arc<RateLimiter>,
    state: SessionAuthState,
}

enum SessionAuthState {
    Unauthenticated { pending_nonce: Option<Nonce> },
    Authenticated,
}

pub enum HandleIncoming {
    /// No response required (e.g., successful auth handshake progress).
    Ack,
    /// Send this response frame to the peer.
    Response(Response),
    /// Terminate the connection.
    Disconnect,
}

impl<F: NetworkFacade> Session<F> {
    pub fn new(psk: Psk, peer_id: String, facade: Arc<F>, rate_limiter: Arc<RateLimiter>) -> Self {
        Self {
            psk,
            peer_id,
            facade,
            rate_limiter,
            state: SessionAuthState::Unauthenticated { pending_nonce: None },
        }
    }

    /// Called when peer reads `ChallengeNonce`. Generates and returns a fresh
    /// nonce, invalidates any prior pending nonce.
    pub fn issue_nonce(&mut self) -> Nonce {
        let mut nonce: Nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        self.state = SessionAuthState::Unauthenticated {
            pending_nonce: Some(nonce),
        };
        nonce
    }

    /// Called when peer writes `AuthResponse`. Consumes the nonce regardless of
    /// outcome. Returns `true` if auth succeeded.
    pub fn submit_auth(&mut self, tag: &[u8]) -> bool {
        if matches!(self.rate_limiter.check(&self.peer_id), CheckResult::Locked { .. }) {
            return false;
        }
        let (tag_len_ok, nonce) = match &self.state {
            SessionAuthState::Unauthenticated { pending_nonce: Some(n) } => (true, *n),
            _ => (false, [0u8; NONCE_LEN]),
        };
        self.state = SessionAuthState::Unauthenticated { pending_nonce: None };
        if !tag_len_ok {
            return false;
        }
        if hmac_verify(&self.psk, &nonce, tag) {
            self.state = SessionAuthState::Authenticated;
            self.rate_limiter.record_success(&self.peer_id);
            true
        } else {
            self.rate_limiter.record_failure(&self.peer_id);
            false
        }
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self.state, SessionAuthState::Authenticated)
    }

    /// Dispatch an already-decoded `Request`. Returns a `Response` to send
    /// back over the transport.
    pub async fn handle_request(&self, req: Request) -> Response {
        if !self.is_authenticated() {
            return Response {
                request_id: req.request_id,
                result: Err(ProtocolError::NotAuthenticated),
            };
        }
        let request_id = req.request_id;
        let result = match req.op {
            Op::ListInterfaces => self.facade.list_interfaces().await
                .map(OpResult::Interfaces).map_err(Into::into),
            Op::GetIpConfig { iface } => self.facade.get_ip_config(&iface).await
                .map(OpResult::IpConfig).map_err(Into::into),
            Op::WifiStatus => self.facade.wifi_status().await
                .map(OpResult::WifiStatus).map_err(Into::into),
            Op::WifiScan => self.facade.scan_wifi().await
                .map(OpResult::WifiNetworks).map_err(Into::into),
            Op::SetDhcp { iface } => self.facade.set_dhcp(&iface).await
                .map(|_| OpResult::Ok).map_err(Into::into),
            Op::SetStaticIpv4 { iface, cfg } => {
                if let Err(e) = validate_static_ipv4(&cfg) {
                    Err(e.into())
                } else {
                    self.facade.set_static_ipv4(&iface, cfg).await
                        .map(|_| OpResult::Ok).map_err(Into::into)
                }
            }
            Op::ConnectWifi { ssid, credential } => self.facade.connect_wifi(&ssid, credential).await
                .map(|_| OpResult::Ok).map_err(Into::into),
        };
        Response { request_id, result }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facade_mock::MockFacade;

    fn fixture() -> (Psk, Session<MockFacade>) {
        let psk = [9u8; PSK_LEN];
        let s = Session::new(
            psk,
            "peer-A".into(),
            Arc::new(MockFacade::new()),
            Arc::new(RateLimiter::with_defaults()),
        );
        (psk, s)
    }

    #[tokio::test]
    async fn unauth_rejects_request() {
        let (_psk, s) = fixture();
        let r = Request { request_id: 1, op: Op::ListInterfaces };
        let resp = s.handle_request(r).await;
        assert!(matches!(resp.result, Err(ProtocolError::NotAuthenticated)));
    }

    #[tokio::test]
    async fn auth_flow_then_list() {
        let (psk, mut s) = fixture();
        let nonce = s.issue_nonce();
        let tag = hmac_compute(&psk, &nonce);
        assert!(s.submit_auth(&tag));
        let resp = s.handle_request(Request { request_id: 1, op: Op::ListInterfaces }).await;
        assert!(matches!(resp.result, Ok(OpResult::Interfaces(_))));
    }

    #[tokio::test]
    async fn wrong_tag_stays_unauth() {
        let (_psk, mut s) = fixture();
        s.issue_nonce();
        assert!(!s.submit_auth(&[0u8; TAG_LEN]));
        assert!(!s.is_authenticated());
    }

    #[tokio::test]
    async fn nonce_is_single_use() {
        let (psk, mut s) = fixture();
        let nonce = s.issue_nonce();
        let tag = hmac_compute(&psk, &nonce);
        // Wrong first attempt consumes the nonce.
        assert!(!s.submit_auth(&[0u8; TAG_LEN]));
        // Second attempt with the correct tag but stale nonce must fail.
        assert!(!s.submit_auth(&tag));
    }

    #[tokio::test]
    async fn static_ip_validation_runs() {
        let (psk, mut s) = fixture();
        let nonce = s.issue_nonce();
        let tag = hmac_compute(&psk, &nonce);
        s.submit_auth(&tag);
        let bad = StaticIpv4 {
            address: "224.0.0.1/24".parse().unwrap(),
            gateway: None,
            dns: vec![],
        };
        let resp = s.handle_request(Request {
            request_id: 2,
            op: Op::SetStaticIpv4 { iface: "eth0".into(), cfg: bad },
        }).await;
        assert!(matches!(resp.result, Err(ProtocolError::InvalidArgument { .. })));
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Append:

```rust
pub mod session;
pub use session::Session;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p netprov-server`
Expected: 23 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/session.rs crates/server/src/lib.rs
git commit -m "feat(server): add Session state machine (auth + dispatch)"
```

---

## Phase 3 — Key loading + dev-key warn

### Task 3.1: Commit a dev PSK + packaging/README

**Files:**
- Create: `packaging/dev-key.bin`, `packaging/README.md`

Per spec §9.4, §9.5.

- [ ] **Step 1: Generate the dev key**

Run:
```bash
mkdir -p packaging
head -c 32 /dev/urandom > packaging/dev-key.bin
```

Expected: 32-byte file.

- [ ] **Step 2: Verify size**

Run: `stat -c %s packaging/dev-key.bin`
Expected: `32`.

- [ ] **Step 3: Write `packaging/README.md`**

```markdown
# packaging/

Artifacts consumed at build/install time.

## `dev-key.bin`

**32-byte pre-shared key embedded in debug builds as a dev fallback.**
This key is committed to the repository and is therefore **PUBLIC**.
It is intended solely for local development and CI loopback tests.

The server logs a loud WARN loop at runtime when this key is in use
(see §9.4 of the design spec). In production, install a per-device key
via `netprovd keygen --install` and ensure `$NETPROV_PRODUCTION=1` is
set in the service environment, which disables the dev-key fallback.

## `netprovd.service`

Deferred to Part 2 of the implementation plan.
```

- [ ] **Step 4: Commit**

```bash
git add packaging/dev-key.bin packaging/README.md
git commit -m "chore: commit dev PSK and packaging README"
```

### Task 3.2: `build.rs` for embedded dev-key path + `load_key`

**Files:**
- Create: `crates/server/build.rs`, `crates/server/src/key.rs`
- Modify: `crates/server/src/lib.rs`

Per spec §9.3.

- [ ] **Step 1: Write `crates/server/build.rs`**

```rust
fn main() {
    // Recompile if the committed dev key changes.
    println!("cargo:rerun-if-changed=../../packaging/dev-key.bin");
}
```

- [ ] **Step 2: Write failing test in `crates/server/src/key.rs`**

```rust
use netprov_protocol::{Psk, PSK_LEN};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const DEV_KEY: &[u8] = include_bytes!("../../../packaging/dev-key.bin");

const _: () = {
    assert!(DEV_KEY.len() == PSK_LEN, "dev-key.bin must be exactly PSK_LEN bytes");
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    EnvPath(PathBuf),
    DefaultPath(PathBuf),
    EmbeddedDev,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("key path {path} not readable: {source}")]
    NotReadable { path: PathBuf, #[source] source: std::io::Error },
    #[error("key at {path} has insecure permissions (mode {mode:#o}); must be owner-only")]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("key at {path} has wrong length {got}, expected {expected}")]
    WrongLength { path: PathBuf, got: usize, expected: usize },
    #[error("production mode enabled but no key found")]
    NoKeyInProduction,
}

pub struct LoadOptions {
    pub env_path: Option<PathBuf>,
    pub default_path: PathBuf,
    pub production: bool,
}

pub struct LoadedKey {
    pub psk: Psk,
    pub source: KeySource,
}

pub fn load_key(opts: LoadOptions) -> Result<LoadedKey, KeyError> {
    if let Some(p) = &opts.env_path {
        return read_key_file(p).map(|psk| LoadedKey {
            psk,
            source: KeySource::EnvPath(p.clone()),
        });
    }
    match read_key_file(&opts.default_path) {
        Ok(psk) => Ok(LoadedKey { psk, source: KeySource::DefaultPath(opts.default_path.clone()) }),
        Err(KeyError::NotReadable { .. }) => {
            if opts.production {
                return Err(KeyError::NoKeyInProduction);
            }
            let mut psk = [0u8; PSK_LEN];
            psk.copy_from_slice(DEV_KEY);
            Ok(LoadedKey { psk, source: KeySource::EmbeddedDev })
        }
        Err(e) => Err(e),
    }
}

fn read_key_file(path: &Path) -> Result<Psk, KeyError> {
    let meta = std::fs::metadata(path).map_err(|e| KeyError::NotReadable {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(KeyError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    let bytes = std::fs::read(path).map_err(|e| KeyError::NotReadable {
        path: path.to_path_buf(),
        source: e,
    })?;
    if bytes.len() != PSK_LEN {
        return Err(KeyError::WrongLength {
            path: path.to_path_buf(),
            got: bytes.len(),
            expected: PSK_LEN,
        });
    }
    let mut psk = [0u8; PSK_LEN];
    psk.copy_from_slice(&bytes);
    Ok(psk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tempkey(bytes: &[u8], mode: u32) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        let mut perms = f.as_file().metadata().unwrap().permissions();
        perms.set_mode(mode);
        std::fs::set_permissions(f.path(), perms).unwrap();
        f
    }

    #[test]
    fn falls_back_to_embedded_dev_key_when_default_missing() {
        let loaded = load_key(LoadOptions {
            env_path: None,
            default_path: "/definitely/does/not/exist".into(),
            production: false,
        }).unwrap();
        assert_eq!(loaded.source, KeySource::EmbeddedDev);
        assert_eq!(loaded.psk.as_slice(), DEV_KEY);
    }

    #[test]
    fn production_mode_rejects_missing_key() {
        let e = load_key(LoadOptions {
            env_path: None,
            default_path: "/definitely/does/not/exist".into(),
            production: true,
        }).unwrap_err();
        assert!(matches!(e, KeyError::NoKeyInProduction));
    }

    #[test]
    fn insecure_permissions_rejected() {
        let f = tempkey(&[0u8; PSK_LEN], 0o644);
        let e = load_key(LoadOptions {
            env_path: None,
            default_path: f.path().to_path_buf(),
            production: false,
        }).unwrap_err();
        assert!(matches!(e, KeyError::InsecurePermissions { .. }));
    }

    #[test]
    fn wrong_length_rejected() {
        let f = tempkey(&[0u8; PSK_LEN - 1], 0o600);
        let e = load_key(LoadOptions {
            env_path: None,
            default_path: f.path().to_path_buf(),
            production: false,
        }).unwrap_err();
        assert!(matches!(e, KeyError::WrongLength { .. }));
    }

    #[test]
    fn valid_key_loads() {
        let bytes: [u8; PSK_LEN] = [0xab; PSK_LEN];
        let f = tempkey(&bytes, 0o600);
        let loaded = load_key(LoadOptions {
            env_path: None,
            default_path: f.path().to_path_buf(),
            production: false,
        }).unwrap();
        assert!(matches!(loaded.source, KeySource::DefaultPath(_)));
        assert_eq!(loaded.psk, bytes);
    }

    #[test]
    fn env_path_takes_precedence() {
        let bytes: [u8; PSK_LEN] = [0xcd; PSK_LEN];
        let f_env = tempkey(&bytes, 0o600);
        let f_default = tempkey(&[0x00; PSK_LEN], 0o600);
        let loaded = load_key(LoadOptions {
            env_path: Some(f_env.path().to_path_buf()),
            default_path: f_default.path().to_path_buf(),
            production: false,
        }).unwrap();
        assert!(matches!(loaded.source, KeySource::EnvPath(_)));
        assert_eq!(loaded.psk, bytes);
    }
}
```

- [ ] **Step 3: Add `tempfile` dev-dependency to `crates/server/Cargo.toml`**

In the `[dev-dependencies]` section, append:

```toml
tempfile = "3"
```

- [ ] **Step 4: Wire into `lib.rs`**

Append:

```rust
pub mod key;
pub use key::{load_key, KeySource, LoadOptions, LoadedKey, KeyError, DEV_KEY};
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p netprov-server`
Expected: 29 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/server/build.rs crates/server/src/key.rs crates/server/src/lib.rs crates/server/Cargo.toml
git commit -m "feat(server): load_key with env > path > embedded fallback"
```

### Task 3.3: Dev-key warn loop

**Files:**
- Create: `crates/server/src/logging.rs`
- Modify: `crates/server/src/lib.rs`

Per spec §9.4.

- [ ] **Step 1: Write `crates/server/src/logging.rs`**

```rust
use crate::key::KeySource;
use std::time::Duration;
use tokio::time;
use tracing::{info, warn};

pub const DEV_KEY_WARN_PERIOD: Duration = Duration::from_secs(60);
pub const DEV_KEY_WARN_MARKER: &str =
    "netprov: INSECURE: development key in use; run 'netprovd keygen --install' to install a production key";

pub fn log_startup_banner(source: &KeySource) {
    match source {
        KeySource::EnvPath(p) => info!(path = %p.display(), "PSK loaded from NETPROV_KEY_PATH"),
        KeySource::DefaultPath(p) => info!(path = %p.display(), "PSK loaded from default path"),
        KeySource::EmbeddedDev => warn!("PSK loaded from EMBEDDED DEV KEY — this server is INSECURE"),
    }
}

/// Spawn a task that emits a warning every DEV_KEY_WARN_PERIOD when the
/// embedded dev key is active. No-op for any other source.
pub fn spawn_dev_key_warn_loop(source: KeySource) -> Option<tokio::task::JoinHandle<()>> {
    if !matches!(source, KeySource::EmbeddedDev) {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut ticker = time::interval(DEV_KEY_WARN_PERIOD);
        // Skip the immediate first tick (banner already logged at startup).
        ticker.tick().await;
        loop {
            ticker.tick().await;
            warn!("{DEV_KEY_WARN_MARKER}");
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn warn_loop_is_none_for_nondev_sources() {
        assert!(spawn_dev_key_warn_loop(KeySource::DefaultPath("/tmp/k".into())).is_none());
        assert!(spawn_dev_key_warn_loop(KeySource::EnvPath("/tmp/k".into())).is_none());
    }

    #[tokio::test]
    async fn warn_loop_spawns_for_dev_key() {
        let h = spawn_dev_key_warn_loop(KeySource::EmbeddedDev).unwrap();
        assert!(!h.is_finished());
        h.abort();
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Append:

```rust
pub mod logging;
pub use logging::{log_startup_banner, spawn_dev_key_warn_loop};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p netprov-server`
Expected: 31 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/logging.rs crates/server/src/lib.rs
git commit -m "feat(server): dev-key startup banner + periodic warn loop"
```

---

## Phase 4 — Transport + client + loopback

### Task 4.1: Length-prefixed transport over `AsyncRead + AsyncWrite`

**Files:**
- Create: `crates/server/src/transport.rs`
- Modify: `crates/server/src/lib.rs`

Rationale: Part 1's loopback transport substitutes for BLE GATT framing. We use a **length-prefixed** wire format here (u32 BE length + body) that both the server and client speak. Part 2 replaces this with the §7.2 fragmentation-over-GATT transport. The `protocol::framing` module from Task 1.5 is not used on the loopback path — it's there for Part 2.

- [ ] **Step 1: Write `crates/server/src/transport.rs`**

```rust
//! Length-prefixed message transport over any AsyncRead + AsyncWrite.
//!
//! Wire format: `[u32 BE length][body]`. Max body size MAX_MESSAGE_SIZE
//! (§7.2 — 4 KiB). Part 2 will replace this with GATT-fragmented framing;
//! both transports share the same request/response semantics above.

use netprov_protocol::MAX_MESSAGE_SIZE;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("message too large: {0} bytes (max {MAX_MESSAGE_SIZE})")]
    TooLarge(usize),
}

pub async fn write_message<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    body: &[u8],
) -> Result<(), TransportError> {
    if body.len() > MAX_MESSAGE_SIZE {
        return Err(TransportError::TooLarge(body.len()));
    }
    let len = body.len() as u32;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_message<R: AsyncReadExt + Unpin>(
    r: &mut R,
) -> Result<Vec<u8>, TransportError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(TransportError::TooLarge(len));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let payload = vec![1u8, 2, 3, 4, 5];
        let t = tokio::spawn(async move {
            write_message(&mut a, &payload).await.unwrap();
        });
        let got = read_message(&mut b).await.unwrap();
        t.await.unwrap();
        assert_eq!(got, vec![1u8, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn rejects_oversize_write() {
        let (mut a, _b) = tokio::io::duplex(4096);
        let big = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let e = write_message(&mut a, &big).await.unwrap_err();
        assert!(matches!(e, TransportError::TooLarge(_)));
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Append:

```rust
pub mod transport;
pub use transport::{read_message, write_message, TransportError};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p netprov-server`
Expected: 33 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/transport.rs crates/server/src/lib.rs
git commit -m "feat(server): length-prefixed loopback transport"
```

### Task 4.2: Server run loop — auth + request dispatch over transport

**Files:**
- Create: `crates/server/src/server_loop.rs`
- Modify: `crates/server/src/lib.rs`

Rationale: the loopback server takes the place of the GATT handlers in Part 2. Wire format for the **auth handshake over loopback**: client sends `Request` with `op = Op::ListInterfaces` or any other op while unauthenticated, gets `NotAuthenticated`. Auth is out-of-band on loopback — we just piggyback it onto the transport with two dedicated message kinds.

To avoid leaking BLE concepts into loopback, we use a small session-control envelope:

```
Envelope = NonceRequest | NonceReply(Nonce) | AuthSubmit(Tag) | Req(Request) | Resp(Response)
```

- [ ] **Step 1: Extend `protocol::message` with `Envelope`**

Edit `crates/protocol/src/message.rs`, appending:

```rust
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
```

Run: `cargo test -p netprov-protocol`
Expected: still 22 passed (no new tests here — `Envelope` tested indirectly via server/client).

- [ ] **Step 2: Write `crates/server/src/server_loop.rs`**

```rust
use crate::facade::NetworkFacade;
use crate::rate_limit::{CheckResult, RateLimiter};
use crate::session::Session;
use crate::transport::{read_message, write_message, TransportError};
use netprov_protocol::*;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("decode: {0}")]
    Decode(#[from] CodecError),
}

pub struct ServerConfig {
    pub psk: Psk,
    pub peer_id: String,
}

pub async fn run_server<F, IO>(
    io: IO,
    cfg: ServerConfig,
    facade: Arc<F>,
    rate_limiter: Arc<RateLimiter>,
) -> Result<(), ServerError>
where
    F: NetworkFacade + 'static,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let (mut r, mut w) = tokio::io::split(io);
    let mut session = Session::new(cfg.psk, cfg.peer_id.clone(), facade, rate_limiter.clone());

    loop {
        let bytes = match read_message(&mut r).await {
            Ok(b) => b,
            Err(TransportError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("peer closed connection");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        let env: Envelope = decode(&bytes)?;

        let reply = match env {
            Envelope::NonceRequest => {
                if let CheckResult::Locked { retry_after } = rate_limiter.check(&cfg.peer_id) {
                    warn!(peer = %cfg.peer_id, retry_after_s = retry_after.as_secs(), "peer is locked out");
                    // Reply with AuthFail so the client stops; they won't know the timer.
                    Envelope::AuthFail
                } else {
                    let nonce = session.issue_nonce();
                    Envelope::NonceReply(nonce.to_vec())
                }
            }
            Envelope::AuthSubmit(tag) => {
                if session.submit_auth(&tag) {
                    info!(peer = %cfg.peer_id, "authenticated");
                    Envelope::AuthOk
                } else {
                    warn!(peer = %cfg.peer_id, "auth failed");
                    Envelope::AuthFail
                }
            }
            Envelope::Req(req) => {
                let resp = session.handle_request(req).await;
                Envelope::Resp(resp)
            }
            // Client should never send these server-origin envelopes.
            Envelope::NonceReply(_) | Envelope::AuthOk | Envelope::AuthFail | Envelope::Resp(_) => {
                warn!("client sent server-origin envelope; closing");
                return Ok(());
            }
        };

        let out = encode(&reply)?;
        write_message(&mut w, &out).await?;
    }
}
```

- [ ] **Step 3: Wire into `lib.rs`**

Append:

```rust
pub mod server_loop;
pub use server_loop::{run_server, ServerConfig, ServerError};
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo build -p netprov-server`
Expected: success.

- [ ] **Step 5: Commit**

```bash
git add crates/protocol/src/message.rs crates/server/src/server_loop.rs crates/server/src/lib.rs
git commit -m "feat(server): loopback run_server with envelope-based auth"
```

### Task 4.3: Client library — `Client<T>` with handshake + request/response

**Files:**
- Create: `crates/client/src/client.rs`
- Modify: `crates/client/src/lib.rs`, `crates/client/Cargo.toml`

- [ ] **Step 1: Add needed deps to `crates/client/Cargo.toml`**

Append `thiserror` to `[dependencies]`:
```toml
thiserror.workspace = true
```

Also add a path dep on the server's transport types — actually we'll inline a minimal transport module here so the client doesn't depend on the server. Adjust the plan: re-export `transport` from `netprov-protocol` so both can consume it. Do this re-export first:

Create `crates/protocol/src/transport.rs`:

```rust
//! Length-prefixed transport, shared by client and server.
//! Part 2 will add a GATT-fragmented transport; this one stays as the
//! loopback transport for tests.

use crate::MAX_MESSAGE_SIZE;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("message too large: {0} bytes (max {MAX_MESSAGE_SIZE})")]
    TooLarge(usize),
}

pub async fn write_message<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    body: &[u8],
) -> Result<(), TransportError> {
    if body.len() > MAX_MESSAGE_SIZE {
        return Err(TransportError::TooLarge(body.len()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_message<R: AsyncReadExt + Unpin>(
    r: &mut R,
) -> Result<Vec<u8>, TransportError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(TransportError::TooLarge(len));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}
```

Update `crates/protocol/Cargo.toml` to add `tokio`:

```toml
tokio = { workspace = true, features = ["io-util"] }
```

Add module to `crates/protocol/src/lib.rs`:

```rust
pub mod transport;
pub use transport::{read_message, write_message, TransportError};
```

Remove the duplicate `transport.rs` from the server crate:

```bash
git rm crates/server/src/transport.rs
```

Edit `crates/server/src/lib.rs` — remove the `pub mod transport;` and `pub use transport::...;` lines.

Edit `crates/server/src/server_loop.rs` — update imports: replace `use crate::transport::...` with `use netprov_protocol::{read_message, write_message, TransportError};`.

Verify: `cargo test -p netprov-server`
Expected: still 31 tests pass (transport's 2 tests moved — will re-add below in protocol).

Add equivalent tests to `crates/protocol/src/transport.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let payload = vec![1u8, 2, 3, 4, 5];
        let t = tokio::spawn(async move {
            write_message(&mut a, &payload).await.unwrap();
        });
        let got = read_message(&mut b).await.unwrap();
        t.await.unwrap();
        assert_eq!(got, vec![1u8, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn rejects_oversize_write() {
        let (mut a, _b) = tokio::io::duplex(4096);
        let big = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let e = write_message(&mut a, &big).await.unwrap_err();
        assert!(matches!(e, TransportError::TooLarge(_)));
    }
}
```

Add `tokio = { workspace = true, features = ["io-util", "macros", "rt"] }` to protocol's `[dev-dependencies]`:

```toml
[dev-dependencies]
proptest.workspace = true
tokio = { workspace = true, features = ["io-util", "macros", "rt"] }
```

Run: `cargo test -p netprov-protocol`
Expected: 24 passed.

- [ ] **Step 2: Write `crates/client/src/client.rs`**

```rust
use netprov_protocol::*;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("decode: {0}")]
    Decode(#[from] CodecError),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("authentication failed")]
    AuthFailed,
    #[error("unexpected server message: {0}")]
    UnexpectedMessage(&'static str),
    #[error("response id mismatch: expected {expected}, got {got}")]
    IdMismatch { expected: u16, got: u16 },
}

pub struct Client<IO> {
    r: tokio::io::ReadHalf<IO>,
    w: tokio::io::WriteHalf<IO>,
    psk: Psk,
    next_id: u16,
    authenticated: bool,
}

impl<IO: AsyncRead + AsyncWrite> Client<IO> {
    pub fn new(io: IO, psk: Psk) -> Self {
        let (r, w) = tokio::io::split(io);
        Self { r, w, psk, next_id: 1, authenticated: false }
    }

    pub async fn authenticate(&mut self) -> Result<(), ClientError> {
        self.send(Envelope::NonceRequest).await?;
        let nonce = match self.recv().await? {
            Envelope::NonceReply(bytes) => {
                if bytes.len() != NONCE_LEN {
                    return Err(ClientError::UnexpectedMessage("nonce length"));
                }
                let mut n = [0u8; NONCE_LEN];
                n.copy_from_slice(&bytes);
                n
            }
            Envelope::AuthFail => return Err(ClientError::AuthFailed),
            _ => return Err(ClientError::UnexpectedMessage("expected NonceReply")),
        };
        let tag = hmac_compute(&self.psk, &nonce);
        self.send(Envelope::AuthSubmit(tag.to_vec())).await?;
        match self.recv().await? {
            Envelope::AuthOk => {
                self.authenticated = true;
                Ok(())
            }
            Envelope::AuthFail => Err(ClientError::AuthFailed),
            _ => Err(ClientError::UnexpectedMessage("expected AuthOk/AuthFail")),
        }
    }

    pub async fn request(&mut self, op: Op) -> Result<OpResult, ClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.send(Envelope::Req(Request { request_id: id, op })).await?;
        match self.recv().await? {
            Envelope::Resp(resp) => {
                if resp.request_id != id {
                    return Err(ClientError::IdMismatch { expected: id, got: resp.request_id });
                }
                resp.result.map_err(Into::into)
            }
            _ => Err(ClientError::UnexpectedMessage("expected Resp")),
        }
    }

    async fn send(&mut self, env: Envelope) -> Result<(), ClientError> {
        let bytes = encode(&env)?;
        write_message(&mut self.w, &bytes).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Envelope, ClientError> {
        let bytes = read_message(&mut self.r).await?;
        Ok(decode(&bytes)?)
    }
}
```

- [ ] **Step 3: Wire into client `lib.rs`**

`crates/client/src/lib.rs`:

```rust
//! netprov client library.

pub mod client;
pub use client::{Client, ClientError};
```

- [ ] **Step 4: Verify compile**

Run: `cargo build -p netprov-client`
Expected: success.

- [ ] **Step 5: Commit**

```bash
git add crates/protocol/src/transport.rs crates/protocol/src/lib.rs crates/protocol/Cargo.toml \
        crates/server/src/server_loop.rs crates/server/src/lib.rs \
        crates/client/src/client.rs crates/client/src/lib.rs crates/client/Cargo.toml
git rm crates/server/src/transport.rs 2>/dev/null || true
git commit -m "feat: shared transport in protocol; client with handshake + request API"
```

### Task 4.4: Loopback integration test — all v1 ops

**Files:**
- Create: `tests/loopback.rs` (workspace-level integration test)
- Modify: workspace `Cargo.toml` — add integration test crate

Alternative: put the integration test inside `crates/server/tests/loopback.rs` so the `[dev-dependencies]` pull in the client. Simpler.

- [ ] **Step 1: Add client as dev-dependency of server**

Edit `crates/server/Cargo.toml` `[dev-dependencies]`:

```toml
netprov-client = { path = "../client" }
```

- [ ] **Step 2: Write `crates/server/tests/loopback.rs`**

```rust
//! End-to-end loopback tests: client ↔ server over tokio::io::duplex,
//! driving MockFacade. No BLE, no NetworkManager.

use netprov_client::Client;
use netprov_protocol::*;
use netprov_server::{run_server, MockFacade, RateLimiter, ServerConfig};
use std::sync::Arc;

fn spawn_pair(psk: Psk) -> Client<tokio::io::DuplexStream> {
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);
    let facade = Arc::new(MockFacade::new());
    let rl = Arc::new(RateLimiter::with_defaults());
    tokio::spawn(run_server(
        server_io,
        ServerConfig { psk, peer_id: "test-peer".into() },
        facade,
        rl,
    ));
    Client::new(client_io, psk)
}

#[tokio::test]
async fn authenticate_and_list_interfaces() {
    let psk = [7u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    c.authenticate().await.unwrap();
    let res = c.request(Op::ListInterfaces).await.unwrap();
    let ifs = match res { OpResult::Interfaces(v) => v, _ => panic!() };
    assert_eq!(ifs.len(), 2);
}

#[tokio::test]
async fn wrong_psk_fails_auth() {
    let server_psk = [1u8; PSK_LEN];
    let client_psk = [2u8; PSK_LEN];
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);
    tokio::spawn(run_server(
        server_io,
        ServerConfig { psk: server_psk, peer_id: "bad".into() },
        Arc::new(MockFacade::new()),
        Arc::new(RateLimiter::with_defaults()),
    ));
    let mut c = Client::new(client_io, client_psk);
    assert!(matches!(c.authenticate().await, Err(netprov_client::ClientError::AuthFailed)));
}

#[tokio::test]
async fn unauth_request_rejected() {
    let psk = [3u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    let err = c.request(Op::ListInterfaces).await.unwrap_err();
    assert!(matches!(err, netprov_client::ClientError::Protocol(ProtocolError::NotAuthenticated)));
}

#[tokio::test]
async fn get_ip_config_eth0() {
    let psk = [3u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    c.authenticate().await.unwrap();
    let res = c.request(Op::GetIpConfig { iface: "eth0".into() }).await.unwrap();
    match res {
        OpResult::IpConfig(cfg) => {
            assert!(!cfg.addresses.is_empty());
        }
        _ => panic!(),
    }
}

#[tokio::test]
async fn set_dhcp_then_read_back() {
    let psk = [3u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    c.authenticate().await.unwrap();
    c.request(Op::SetDhcp { iface: "eth0".into() }).await.unwrap();
    let res = c.request(Op::GetIpConfig { iface: "eth0".into() }).await.unwrap();
    match res {
        OpResult::IpConfig(cfg) => {
            assert!(matches!(cfg.method, Ipv4Method::Auto));
            assert!(cfg.addresses.is_empty());
        }
        _ => panic!(),
    }
}

#[tokio::test]
async fn set_static_ipv4_then_read_back() {
    let psk = [3u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    c.authenticate().await.unwrap();
    c.request(Op::SetStaticIpv4 {
        iface: "eth0".into(),
        cfg: StaticIpv4 {
            address: "192.168.2.42/24".parse().unwrap(),
            gateway: Some("192.168.2.1".parse().unwrap()),
            dns: vec!["1.1.1.1".parse().unwrap()],
        },
    }).await.unwrap();
    let res = c.request(Op::GetIpConfig { iface: "eth0".into() }).await.unwrap();
    match res {
        OpResult::IpConfig(cfg) => {
            assert!(matches!(cfg.method, Ipv4Method::Manual));
            assert_eq!(cfg.addresses[0].to_string(), "192.168.2.42/24");
        }
        _ => panic!(),
    }
}

#[tokio::test]
async fn static_ipv4_validation_rejects_multicast() {
    let psk = [3u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    c.authenticate().await.unwrap();
    let err = c.request(Op::SetStaticIpv4 {
        iface: "eth0".into(),
        cfg: StaticIpv4 {
            address: "224.0.0.1/24".parse().unwrap(),
            gateway: None,
            dns: vec![],
        },
    }).await.unwrap_err();
    assert!(matches!(err, netprov_client::ClientError::Protocol(ProtocolError::InvalidArgument { .. })));
}

#[tokio::test]
async fn wifi_scan_returns_networks() {
    let psk = [3u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    c.authenticate().await.unwrap();
    let res = c.request(Op::WifiScan).await.unwrap();
    match res {
        OpResult::WifiNetworks(nets) => assert!(!nets.is_empty()),
        _ => panic!(),
    }
}

#[tokio::test]
async fn connect_wifi_then_status_reflects_ssid() {
    let psk = [3u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    c.authenticate().await.unwrap();
    c.request(Op::ConnectWifi {
        ssid: "HomeWifi".into(),
        credential: WifiCredential::Wpa2Psk("super-secret".into()),
    }).await.unwrap();
    let res = c.request(Op::WifiStatus).await.unwrap();
    match res {
        OpResult::WifiStatus(st) => assert_eq!(st.ssid.as_deref(), Some("HomeWifi")),
        _ => panic!(),
    }
}
```

- [ ] **Step 3: Export `RateLimiter` from server crate for the test**

In `crates/server/src/lib.rs`, append:

```rust
pub use rate_limit::{RateLimiter, RateLimiterConfig, SystemClock};
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p netprov-server --test loopback`
Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/server/Cargo.toml crates/server/src/lib.rs crates/server/tests/loopback.rs
git commit -m "test: end-to-end loopback tests for all v1 ops"
```

---

## Phase 5 — Keygen subcommand + CLI

### Task 5.1: `netprovd keygen`

**Files:**
- Create: `crates/server/src/keygen.rs`
- Modify: `crates/server/src/main.rs`, `crates/server/src/lib.rs`

Per spec §9.5.

- [ ] **Step 1: Write `crates/server/src/keygen.rs`**

```rust
use base64::prelude::{Engine, BASE64_STANDARD};
use netprov_protocol::PSK_LEN;
use qrcode::{render::unicode::Dense1x2, QrCode};
use rand::RngCore;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("QR rendering failed: {0}")]
    Qr(String),
}

pub struct KeygenArgs {
    pub install: bool,
    pub install_path: PathBuf,
}

impl Default for KeygenArgs {
    fn default() -> Self {
        Self {
            install: false,
            install_path: "/etc/netprov/key".into(),
        }
    }
}

pub fn run_keygen(args: KeygenArgs, out: &mut dyn std::io::Write) -> Result<(), KeygenError> {
    let mut psk = [0u8; PSK_LEN];
    rand::thread_rng().fill_bytes(&mut psk);

    let b64 = BASE64_STANDARD.encode(psk);
    writeln!(out, "Generated PSK ({PSK_LEN} bytes, base64):")?;
    writeln!(out, "{b64}")?;
    writeln!(out)?;

    let qr = QrCode::new(b64.as_bytes()).map_err(|e| KeygenError::Qr(e.to_string()))?;
    let ascii = qr.render::<Dense1x2>().dark_color(Dense1x2::Dark).light_color(Dense1x2::Light).build();
    writeln!(out, "{ascii}")?;

    if args.install {
        if let Some(parent) = args.install_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&args.install_path)?;
        std::io::Write::write_all(&mut f, &psk)?;
        writeln!(out, "Installed to: {} (0600 root:root)", args.install_path.display())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn generates_and_prints() {
        let mut buf = Vec::new();
        run_keygen(KeygenArgs::default(), &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Generated PSK"));
    }

    #[test]
    fn install_writes_0600_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("k");
        let mut buf = Vec::new();
        run_keygen(KeygenArgs {
            install: true,
            install_path: path.clone(),
        }, &mut buf).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.len(), PSK_LEN as u64);
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Append:

```rust
pub mod keygen;
pub use keygen::{run_keygen, KeygenArgs, KeygenError};
```

- [ ] **Step 3: Wire the subcommand into `crates/server/src/main.rs`**

Replace `crates/server/src/main.rs`:

```rust
use clap::{Parser, Subcommand};
use netprov_server::keygen::{run_keygen, KeygenArgs};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "netprovd", about = "netprov daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new 32-byte PSK. Optionally install it to disk.
    Keygen {
        /// Write the generated key to the install path (default /etc/netprov/key).
        #[arg(long)]
        install: bool,
        /// Override the install path.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Cmd::Keygen { install, out }) => {
            let args = KeygenArgs {
                install,
                install_path: out.unwrap_or_else(|| "/etc/netprov/key".into()),
            };
            run_keygen(args, &mut std::io::stdout())?;
            Ok(())
        }
        None => {
            // Default: run the daemon. Loop integration lands in Part 2
            // (BLE wiring); for now, print a usage note.
            eprintln!("Part 1 build: BLE server not wired yet. Use `netprovd keygen`.");
            std::process::exit(1);
        }
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p netprov-server`
Expected: 33 passed (31 + 2 keygen).

- [ ] **Step 5: Run the keygen subcommand end-to-end**

Run: `cargo run -p netprov-server --bin netprovd -- keygen`
Expected: prints base64 PSK + QR code, does not write any file.

- [ ] **Step 6: Commit**

```bash
git add crates/server/src/keygen.rs crates/server/src/lib.rs crates/server/src/main.rs
git commit -m "feat(server): netprovd keygen subcommand with QR output"
```

### Task 5.2: Client CLI with subcommands for every v1 op

**Files:**
- Create: `crates/client/src/cli.rs`, `crates/client/src/commands.rs`
- Modify: `crates/client/src/main.rs`, `crates/client/src/lib.rs`

For Part 1, the CLI connects over **TCP loopback** (a natural stand-in for BLE at dev time). Part 2 swaps this for a BLE connector. The CLI therefore takes a `--endpoint host:port` arg in Part 1.

- [ ] **Step 1: Write `crates/client/src/cli.rs`**

```rust
use clap::{Parser, Subcommand};
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "netprov", about = "netprov client CLI")]
pub struct Cli {
    /// Path to the 32-byte PSK file.
    #[arg(long, short = 'k', env = "NETPROV_KEY_PATH", default_value = "/etc/netprov/key")]
    pub key_path: PathBuf,

    /// TCP endpoint for loopback transport (Part 1). Part 2 will default to
    /// BLE peer discovery.
    #[arg(long, env = "NETPROV_ENDPOINT", default_value = "127.0.0.1:9600")]
    pub endpoint: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// List network interfaces.
    List,
    /// Print IP config for an interface.
    Ip { iface: String },
    /// Print Wi-Fi status.
    WifiStatus,
    /// Scan for Wi-Fi networks.
    WifiScan,
    /// Connect to a Wi-Fi network.
    WifiConnect {
        ssid: String,
        #[arg(long)]
        psk: Option<String>,
        /// Security type: open | wpa2 | wpa3
        #[arg(long, default_value = "wpa2")]
        security: String,
    },
    /// Configure interface for DHCP.
    SetDhcp { iface: String },
    /// Configure interface for static IPv4.
    SetStatic {
        iface: String,
        #[arg(long)]
        address: Ipv4Net,
        #[arg(long)]
        gateway: Option<Ipv4Addr>,
        #[arg(long, value_delimiter = ',')]
        dns: Vec<Ipv4Addr>,
    },
}
```

- [ ] **Step 2: Write `crates/client/src/commands.rs`**

```rust
use crate::cli::Command;
use crate::client::Client;
use anyhow::{bail, Result};
use netprov_protocol::*;
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn dispatch<IO: AsyncRead + AsyncWrite>(c: &mut Client<IO>, cmd: Command) -> Result<()> {
    match cmd {
        Command::List => {
            let res = c.request(Op::ListInterfaces).await?;
            match res {
                OpResult::Interfaces(ifs) => {
                    for i in ifs {
                        println!("{:<10} {:<10} {:<18} {:?}",
                            i.name,
                            format!("{:?}", i.iface_type),
                            i.mac.unwrap_or_else(|| "-".into()),
                            i.state,
                        );
                    }
                }
                _ => bail!("unexpected result shape"),
            }
        }
        Command::Ip { iface } => {
            let res = c.request(Op::GetIpConfig { iface: iface.clone() }).await?;
            match res {
                OpResult::IpConfig(cfg) => {
                    println!("iface: {iface}");
                    println!("method: {:?}", cfg.method);
                    for a in &cfg.addresses { println!("  addr: {a}"); }
                    if let Some(gw) = cfg.gateway { println!("  gw:   {gw}"); }
                    for d in &cfg.dns { println!("  dns:  {d}"); }
                }
                _ => bail!("unexpected result shape"),
            }
        }
        Command::WifiStatus => {
            let res = c.request(Op::WifiStatus).await?;
            match res {
                OpResult::WifiStatus(st) => println!("{st:?}"),
                _ => bail!("unexpected result shape"),
            }
        }
        Command::WifiScan => {
            let res = c.request(Op::WifiScan).await?;
            match res {
                OpResult::WifiNetworks(nets) => {
                    for n in nets {
                        println!("{:<32} {:>3}% {:?} {}",
                            n.ssid,
                            n.signal.unwrap_or(0),
                            n.security,
                            n.bssid,
                        );
                    }
                }
                _ => bail!("unexpected result shape"),
            }
        }
        Command::WifiConnect { ssid, psk, security } => {
            let credential = match (security.as_str(), psk) {
                ("open", _) => WifiCredential::Open,
                ("wpa2", Some(p)) => WifiCredential::Wpa2Psk(p),
                ("wpa3", Some(p)) => WifiCredential::Wpa3(p),
                _ => bail!("unsupported combination of security and psk"),
            };
            c.request(Op::ConnectWifi { ssid, credential }).await?;
            println!("ok");
        }
        Command::SetDhcp { iface } => {
            c.request(Op::SetDhcp { iface }).await?;
            println!("ok");
        }
        Command::SetStatic { iface, address, gateway, dns } => {
            c.request(Op::SetStaticIpv4 {
                iface,
                cfg: StaticIpv4 { address, gateway, dns },
            }).await?;
            println!("ok");
        }
    }
    Ok(())
}
```

- [ ] **Step 3: Wire into `lib.rs`**

`crates/client/src/lib.rs`:

```rust
//! netprov client library.

pub mod cli;
pub mod client;
pub mod commands;
pub use client::{Client, ClientError};
```

- [ ] **Step 4: Wire `main.rs`**

`crates/client/src/main.rs`:

```rust
use anyhow::{Context, Result};
use clap::Parser;
use netprov_client::cli::Cli;
use netprov_client::{client::Client, commands::dispatch};
use netprov_protocol::PSK_LEN;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let key_bytes = std::fs::read(&cli.key_path)
        .with_context(|| format!("read key {}", cli.key_path.display()))?;
    if key_bytes.len() != PSK_LEN {
        anyhow::bail!("key length is {}, expected {}", key_bytes.len(), PSK_LEN);
    }
    let mut psk = [0u8; PSK_LEN];
    psk.copy_from_slice(&key_bytes);

    let sock = tokio::net::TcpStream::connect(&cli.endpoint).await
        .with_context(|| format!("connect {}", cli.endpoint))?;
    let mut client = Client::new(sock, psk);
    client.authenticate().await.context("authenticate")?;
    dispatch(&mut client, cli.command).await?;
    Ok(())
}
```

- [ ] **Step 5: Verify compile**

Run: `cargo build -p netprov-client`
Expected: success.

- [ ] **Step 6: Commit**

```bash
git add crates/client/src/cli.rs crates/client/src/commands.rs crates/client/src/lib.rs crates/client/src/main.rs
git commit -m "feat(client): CLI subcommands for all v1 ops (TCP loopback transport)"
```

### Task 5.3: Add a TCP-server test entry to the server binary

**Files:**
- Modify: `crates/server/src/main.rs`, `crates/server/src/lib.rs`

Purpose: give the binary a `serve` subcommand that listens on TCP for Part 1, so you can run `netprovd serve` on one terminal and `netprov list` on another, end-to-end, without BLE. Part 2 replaces this with BLE.

- [ ] **Step 1: Add `run_tcp_server` to the server library**

Append to `crates/server/src/server_loop.rs`:

```rust
use tokio::net::{TcpListener, ToSocketAddrs};

pub async fn run_tcp_server<F, A>(
    addr: A,
    psk: Psk,
    facade: Arc<F>,
    rate_limiter: Arc<RateLimiter>,
) -> anyhow::Result<()>
where
    F: NetworkFacade + 'static,
    A: ToSocketAddrs,
{
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %listener.local_addr()?, "netprov tcp loopback listener");
    loop {
        let (sock, peer) = listener.accept().await?;
        let facade = facade.clone();
        let rl = rate_limiter.clone();
        let peer_id = peer.to_string();
        tokio::spawn(async move {
            if let Err(e) = run_server(
                sock,
                ServerConfig { psk, peer_id: peer_id.clone() },
                facade,
                rl,
            ).await {
                warn!(peer = %peer_id, error = ?e, "session ended with error");
            }
        });
    }
}
```

Add `use anyhow;` via the workspace dep (already present).

- [ ] **Step 2: Add `serve` subcommand to `main.rs`**

Replace `crates/server/src/main.rs`:

```rust
use clap::{Parser, Subcommand};
use netprov_server::keygen::{run_keygen, KeygenArgs};
use netprov_server::logging::{log_startup_banner, spawn_dev_key_warn_loop};
use netprov_server::{load_key, LoadOptions, MockFacade, RateLimiter};
use netprov_server::server_loop::run_tcp_server;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "netprovd", about = "netprov daemon")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a PSK. Optionally install it.
    Keygen {
        #[arg(long)]
        install: bool,
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
    /// Run the loopback TCP server (Part 1 only). Uses MockFacade.
    Serve {
        /// TCP listen address.
        #[arg(long, default_value = "127.0.0.1:9600")]
        listen: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Cmd::Keygen { install, out } => {
            run_keygen(KeygenArgs {
                install,
                install_path: out.unwrap_or_else(|| "/etc/netprov/key".into()),
            }, &mut std::io::stdout())?;
        }
        Cmd::Serve { listen } => {
            let production = std::env::var("NETPROV_PRODUCTION").ok().as_deref() == Some("1");
            let env_path = std::env::var_os("NETPROV_KEY_PATH").map(PathBuf::from);
            let key = load_key(LoadOptions {
                env_path,
                default_path: "/etc/netprov/key".into(),
                production,
            })?;
            log_startup_banner(&key.source);
            let _warn_task = spawn_dev_key_warn_loop(key.source.clone());
            let facade = Arc::new(MockFacade::new());
            let rl = Arc::new(RateLimiter::with_defaults());
            run_tcp_server(&listen, key.psk, facade, rl).await?;
        }
    }
    Ok(())
}
```

- [ ] **Step 3: Verify build**

Run: `cargo build --workspace`
Expected: success.

- [ ] **Step 4: Smoke test end-to-end on localhost**

In one terminal:
```bash
cargo run -p netprov-server --bin netprovd -- serve --listen 127.0.0.1:9600
```
Expected: startup banner logged, "tcp loopback listener" message.

In another terminal (the dev key file does not exist at `/etc/netprov/key`, so the server uses embedded dev key; the client needs the same dev key file on disk):
```bash
cp packaging/dev-key.bin /tmp/netprov-devkey.bin
chmod 600 /tmp/netprov-devkey.bin
cargo run -p netprov-client --bin netprov -- --key-path /tmp/netprov-devkey.bin --endpoint 127.0.0.1:9600 list
```
Expected: prints two interfaces (eth0, wlan0).

Try one write:
```bash
cargo run -p netprov-client --bin netprov -- --key-path /tmp/netprov-devkey.bin --endpoint 127.0.0.1:9600 set-dhcp eth0
cargo run -p netprov-client --bin netprov -- --key-path /tmp/netprov-devkey.bin --endpoint 127.0.0.1:9600 ip eth0
```
Expected: `ok`, then an IpConfig with `method: Auto` and no addresses.

Stop the server with Ctrl-C.

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/main.rs crates/server/src/server_loop.rs
git commit -m "feat(server): serve subcommand with TCP loopback (Part 1 dev surface)"
```

---

## Phase 6 — `NmrsFacade` (opt-in `live-nm` feature)

All of Phase 6 is gated on `--features live-nm` and uses `#[ignore]` on tests that talk to the system. These tests are **not** part of the default `cargo test` run.

### Task 6.1: Confirm `nmrs` version and set up facade module skeleton

**Files:**
- Create: `crates/server/src/facade_nmrs.rs`
- Modify: `crates/server/Cargo.toml`, `crates/server/src/lib.rs`

- [ ] **Step 1: Verify the current `nmrs` crate version**

Run: `cargo search nmrs`
Expected: pick the latest stable version. Update `crates/server/Cargo.toml`:

```toml
nmrs = { version = "<pasted-from-cargo-search>", optional = true }
zbus = { version = "5", optional = true }
```

- [ ] **Step 2: Write the skeleton `crates/server/src/facade_nmrs.rs`**

```rust
//! Production NetworkFacade backed by nmrs + raw zbus.
//!
//! All operations are bound by a 30-second timeout per §8.3.

use crate::facade::NetworkFacade;
use async_trait::async_trait;
use netprov_protocol::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

pub const OP_TIMEOUT: Duration = Duration::from_secs(30);

pub struct NmrsFacade {
    write_guard: Arc<Mutex<()>>,
    // Fields populated in 6.2.
    _zbus: zbus::Connection,
    _nm: nmrs::NetworkManager,
}

impl NmrsFacade {
    pub async fn new() -> anyhow::Result<Self> {
        let zbus = zbus::Connection::system().await?;
        let nm = nmrs::NetworkManager::new().await?;
        Ok(Self {
            write_guard: Arc::new(Mutex::new(())),
            _zbus: zbus,
            _nm: nm,
        })
    }
}

#[async_trait]
impl NetworkFacade for NmrsFacade {
    async fn list_interfaces(&self) -> Result<Vec<Interface>, NetError> {
        Err(NetError::NotSupported)
    }
    async fn get_ip_config(&self, _iface: &str) -> Result<IpConfig, NetError> {
        Err(NetError::NotSupported)
    }
    async fn wifi_status(&self) -> Result<WifiStatus, NetError> {
        Err(NetError::NotSupported)
    }
    async fn scan_wifi(&self) -> Result<Vec<WifiNetwork>, NetError> {
        Err(NetError::NotSupported)
    }
    async fn set_dhcp(&self, _iface: &str) -> Result<(), NetError> {
        Err(NetError::NotSupported)
    }
    async fn set_static_ipv4(&self, _iface: &str, _cfg: StaticIpv4) -> Result<(), NetError> {
        Err(NetError::NotSupported)
    }
    async fn connect_wifi(&self, _ssid: &str, _cred: WifiCredential) -> Result<(), NetError> {
        Err(NetError::NotSupported)
    }
}
```

- [ ] **Step 3: Wire into `lib.rs`**

Append:

```rust
#[cfg(feature = "live-nm")]
pub mod facade_nmrs;
#[cfg(feature = "live-nm")]
pub use facade_nmrs::NmrsFacade;
```

- [ ] **Step 4: Verify build under `live-nm`**

Run: `cargo build -p netprov-server --features live-nm`
Expected: success.

- [ ] **Step 5: Commit**

```bash
git add crates/server/Cargo.toml crates/server/src/facade_nmrs.rs crates/server/src/lib.rs
git commit -m "feat(server): NmrsFacade skeleton under live-nm feature"
```

### Task 6.2: Implement `list_interfaces` via raw zbus

**Files:**
- Modify: `crates/server/src/facade_nmrs.rs`

Per spec §8.2.

- [ ] **Step 1: Add dependencies if needed**

Check that `futures-util` is usable via `tokio::time::timeout` — no extra crate needed for timeout itself.

- [ ] **Step 2: Replace the body of `list_interfaces`**

In `crates/server/src/facade_nmrs.rs`:

```rust
async fn list_interfaces(&self) -> Result<Vec<Interface>, NetError> {
    tokio::time::timeout(OP_TIMEOUT, async {
        let proxy = zbus::Proxy::new(
            &self._zbus,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        ).await.map_err(nm_err)?;
        let devices: Vec<zbus::zvariant::OwnedObjectPath> =
            proxy.call("GetDevices", &()).await.map_err(nm_err)?;
        let mut out = Vec::with_capacity(devices.len());
        for dev_path in devices {
            let dev = zbus::Proxy::new(
                &self._zbus,
                "org.freedesktop.NetworkManager",
                dev_path.as_str(),
                "org.freedesktop.NetworkManager.Device",
            ).await.map_err(nm_err)?;
            let name: String = dev.get_property("Interface").await.map_err(nm_err)?;
            let dev_type: u32 = dev.get_property("DeviceType").await.map_err(nm_err)?;
            let mac: Option<String> = dev.get_property("HwAddress").await.ok();
            let state: u32 = dev.get_property("State").await.map_err(nm_err)?;

            let iface_type = match dev_type {
                1 => IfaceType::Ethernet,   // NM_DEVICE_TYPE_ETHERNET
                2 => IfaceType::Wifi,       // NM_DEVICE_TYPE_WIFI
                14 => IfaceType::Loopback,  // NM_DEVICE_TYPE_LOOPBACK
                _ => IfaceType::Other,
            };
            if matches!(iface_type, IfaceType::Loopback) {
                continue;
            }
            let iface_state = match state {
                100 => IfaceState::Up,     // activated
                20..=30 => IfaceState::Down,
                _ => IfaceState::Unknown,
            };
            out.push(Interface {
                name,
                iface_type,
                mac,
                state: iface_state,
            });
        }
        Ok::<_, NetError>(out)
    }).await.map_err(|_| NetError::Timeout)?
}

fn nm_err<E: std::fmt::Display>(e: E) -> NetError {
    NetError::NetworkManager(e.to_string())
}
```

Move `fn nm_err` to module scope (not inside the trait impl block).

- [ ] **Step 3: Build**

Run: `cargo build -p netprov-server --features live-nm`
Expected: success.

- [ ] **Step 4: Add a live integration test**

At the bottom of `crates/server/src/facade_nmrs.rs`:

```rust
#[cfg(test)]
mod live_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires NetworkManager on system bus"]
    async fn list_interfaces_live() {
        let f = NmrsFacade::new().await.expect("connect NM");
        let ifs = f.list_interfaces().await.expect("list");
        assert!(ifs.iter().any(|i| matches!(i.iface_type, IfaceType::Ethernet | IfaceType::Wifi)),
            "expected at least one Ethernet or Wi-Fi interface, got {ifs:?}");
    }
}
```

- [ ] **Step 5: Run the test (only on a machine with NM)**

Run: `cargo test -p netprov-server --features live-nm --test facade_nmrs_live -- --ignored list_interfaces_live`

If running locally on a machine with NM:
Expected: 1 passed.

If running on a machine without NM: skip this step, document in commit message.

- [ ] **Step 6: Commit**

```bash
git add crates/server/src/facade_nmrs.rs
git commit -m "feat(server): NmrsFacade::list_interfaces via raw zbus

Validated manually on a dev box with NetworkManager; live-nm integration
test passes there. CI runs the default --features mock build only."
```

### Task 6.3: Implement `get_ip_config`

**Files:**
- Modify: `crates/server/src/facade_nmrs.rs`

- [ ] **Step 1: Replace `get_ip_config`**

```rust
async fn get_ip_config(&self, iface: &str) -> Result<IpConfig, NetError> {
    tokio::time::timeout(OP_TIMEOUT, async {
        let dev_path = find_device_path(&self._zbus, iface).await?;

        let dev = zbus::Proxy::new(
            &self._zbus,
            "org.freedesktop.NetworkManager",
            dev_path.as_str(),
            "org.freedesktop.NetworkManager.Device",
        ).await.map_err(nm_err)?;

        let ip4_path: zbus::zvariant::OwnedObjectPath =
            dev.get_property("Ip4Config").await.map_err(nm_err)?;

        let method = read_method(&self._zbus, &dev).await.unwrap_or(Ipv4Method::Auto);

        // "/" means no active config.
        if ip4_path.as_str() == "/" {
            return Ok(IpConfig { method, addresses: vec![], gateway: None, dns: vec![] });
        }
        let ip4 = zbus::Proxy::new(
            &self._zbus,
            "org.freedesktop.NetworkManager",
            ip4_path.as_str(),
            "org.freedesktop.NetworkManager.IP4Config",
        ).await.map_err(nm_err)?;

        // AddressData is a Vec<HashMap<String, Variant>>: {"address": "...", "prefix": u32}
        let addr_data: Vec<std::collections::HashMap<String, zbus::zvariant::OwnedValue>> =
            ip4.get_property("AddressData").await.map_err(nm_err)?;
        let mut addresses = Vec::new();
        for m in addr_data {
            let addr: String = m.get("address").and_then(|v| v.try_into().ok()).unwrap_or_default();
            let prefix: u32 = m.get("prefix").and_then(|v| v.try_into().ok()).unwrap_or(32);
            if let Ok(a) = format!("{addr}/{prefix}").parse() { addresses.push(a); }
        }

        let gw: String = ip4.get_property("Gateway").await.unwrap_or_default();
        let gateway = gw.parse().ok();

        let nameservers: Vec<u32> = ip4.get_property("Nameservers").await.unwrap_or_default();
        let dns = nameservers.into_iter()
            .map(|n| std::net::Ipv4Addr::from(n.to_le_bytes()))
            .collect();

        Ok::<_, NetError>(IpConfig { method, addresses, gateway, dns })
    }).await.map_err(|_| NetError::Timeout)?
}

async fn find_device_path(
    conn: &zbus::Connection,
    iface: &str,
) -> Result<zbus::zvariant::OwnedObjectPath, NetError> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
    ).await.map_err(nm_err)?;
    let path: zbus::zvariant::OwnedObjectPath =
        proxy.call("GetDeviceByIpIface", &(iface,)).await
            .map_err(|_| NetError::InterfaceNotFound(iface.to_string()))?;
    Ok(path)
}

async fn read_method(
    conn: &zbus::Connection,
    dev: &zbus::Proxy<'_>,
) -> Option<Ipv4Method> {
    // Get the active connection settings → ipv4.method
    let active: zbus::zvariant::OwnedObjectPath = dev.get_property("ActiveConnection").await.ok()?;
    if active.as_str() == "/" { return None; }
    let ac = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        active.as_str(),
        "org.freedesktop.NetworkManager.Connection.Active",
    ).await.ok()?;
    let conn_path: zbus::zvariant::OwnedObjectPath = ac.get_property("Connection").await.ok()?;
    let settings = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        conn_path.as_str(),
        "org.freedesktop.NetworkManager.Settings.Connection",
    ).await.ok()?;
    let s: std::collections::HashMap<
        String,
        std::collections::HashMap<String, zbus::zvariant::OwnedValue>
    > = settings.call("GetSettings", &()).await.ok()?;
    let m: String = s.get("ipv4")?.get("method")?.try_into().ok()?;
    match m.as_str() {
        "auto" => Some(Ipv4Method::Auto),
        "manual" => Some(Ipv4Method::Manual),
        _ => None,
    }
}
```

- [ ] **Step 2: Build**

Run: `cargo build -p netprov-server --features live-nm`
Expected: success.

- [ ] **Step 3: Add live test**

Append to `live_tests` mod:

```rust
#[tokio::test]
#[ignore = "requires NetworkManager with an active wired or wireless interface"]
async fn get_ip_config_live() {
    let f = NmrsFacade::new().await.unwrap();
    let ifs = f.list_interfaces().await.unwrap();
    let iface = ifs.first().expect("at least one interface");
    let cfg = f.get_ip_config(&iface.name).await.unwrap();
    println!("{cfg:?}");
}
```

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/facade_nmrs.rs
git commit -m "feat(server): NmrsFacade::get_ip_config"
```

### Task 6.4: Implement `wifi_status`, `scan_wifi`, `connect_wifi` via nmrs

**Files:**
- Modify: `crates/server/src/facade_nmrs.rs`

- [ ] **Step 1: Implement using `nmrs::NetworkManager` directly**

Consult the `nmrs` docs (see README snippet in §6 of the design spec) for the exact signatures of `list_networks`, `connect`, and whatever property/method exposes active Wi-Fi info. If a method is missing, fall back to raw zbus using the same patterns as Tasks 6.2 / 6.3.

Replacement blocks — fill in method calls per the current `nmrs` API. Keep the overall shape:

```rust
async fn wifi_status(&self) -> Result<WifiStatus, NetError> {
    tokio::time::timeout(OP_TIMEOUT, async {
        // If nmrs exposes an active-access-point getter, use it.
        // Otherwise: find the first Wi-Fi device via GetDevices,
        // read its ActiveAccessPoint object path, then read
        // Ssid (ay → UTF-8), Strength (u8), Flags/WpaFlags/RsnFlags → Security.
        Err::<WifiStatus, NetError>(NetError::NotSupported) // TODO fill in per nmrs API
    }).await.map_err(|_| NetError::Timeout)?
}
```

> **Fill-in guidance:** The engineer executing this task must consult the current `nmrs` docs (`cargo doc --open -p nmrs`) to pick the right calls. For each op below, the acceptance test is the live-gated integration test. If an API is missing from nmrs, use raw zbus with NM's Wi-Fi object interfaces (`org.freedesktop.NetworkManager.AccessPoint`, `.Device.Wireless`).

- [ ] **Step 2: Add live-gated tests**

```rust
#[tokio::test]
#[ignore = "requires Wi-Fi adapter"]
async fn wifi_scan_live() {
    let f = NmrsFacade::new().await.unwrap();
    let nets = f.scan_wifi().await.unwrap();
    println!("{nets:#?}");
}

#[tokio::test]
#[ignore = "requires Wi-Fi adapter with an active AP"]
async fn wifi_status_live() {
    let f = NmrsFacade::new().await.unwrap();
    let st = f.wifi_status().await.unwrap();
    println!("{st:?}");
}
```

`connect_wifi` live test deliberately omitted from the default test set — it actually changes system state. Add a `--features live-nm-destructive` gate for that case instead:

In `crates/server/Cargo.toml`:

```toml
[features]
live-nm-destructive = ["live-nm"]
```

Then:

```rust
#[cfg(feature = "live-nm-destructive")]
#[tokio::test]
#[ignore = "connects to a real Wi-Fi network; requires NETPROV_TEST_SSID + NETPROV_TEST_PSK env"]
async fn wifi_connect_live() {
    let f = NmrsFacade::new().await.unwrap();
    let ssid = std::env::var("NETPROV_TEST_SSID").unwrap();
    let psk = std::env::var("NETPROV_TEST_PSK").unwrap();
    f.connect_wifi(&ssid, WifiCredential::Wpa2Psk(psk)).await.unwrap();
}
```

- [ ] **Step 3: Commit after each op compiles**

```bash
git add crates/server/src/facade_nmrs.rs crates/server/Cargo.toml
git commit -m "feat(server): NmrsFacade wifi_status, scan_wifi, connect_wifi"
```

### Task 6.5: Implement `set_dhcp` and `set_static_ipv4`

**Files:**
- Modify: `crates/server/src/facade_nmrs.rs`

- [ ] **Step 1: Implement shared helper for applying `ipv4` settings**

Pattern, per spec §8.2 "re-activation requirement":

```rust
async fn apply_ipv4_settings(
    &self,
    iface: &str,
    method: &str,
    addresses: &[(std::net::Ipv4Addr, u32)],
    gateway: Option<std::net::Ipv4Addr>,
    dns: &[std::net::Ipv4Addr],
) -> Result<(), NetError> {
    let _guard = self.write_guard.lock().await;
    tokio::time::timeout(OP_TIMEOUT, async {
        let dev_path = find_device_path(&self._zbus, iface).await?;
        let dev = zbus::Proxy::new(
            &self._zbus,
            "org.freedesktop.NetworkManager",
            dev_path.as_str(),
            "org.freedesktop.NetworkManager.Device",
        ).await.map_err(nm_err)?;
        let active: zbus::zvariant::OwnedObjectPath = dev.get_property("ActiveConnection").await.map_err(nm_err)?;
        if active.as_str() == "/" {
            return Err(NetError::InvalidArgument(
                format!("interface {iface} has no active connection")
            ));
        }
        let ac = zbus::Proxy::new(
            &self._zbus,
            "org.freedesktop.NetworkManager",
            active.as_str(),
            "org.freedesktop.NetworkManager.Connection.Active",
        ).await.map_err(nm_err)?;
        let conn_path: zbus::zvariant::OwnedObjectPath = ac.get_property("Connection").await.map_err(nm_err)?;
        let settings = zbus::Proxy::new(
            &self._zbus,
            "org.freedesktop.NetworkManager",
            conn_path.as_str(),
            "org.freedesktop.NetworkManager.Settings.Connection",
        ).await.map_err(nm_err)?;

        let mut current: std::collections::HashMap<
            String,
            std::collections::HashMap<String, zbus::zvariant::OwnedValue>
        > = settings.call("GetSettings", &()).await.map_err(nm_err)?;

        let ipv4 = current.entry("ipv4".into()).or_default();
        ipv4.insert("method".into(), zbus::zvariant::Value::from(method).try_to_owned().unwrap());

        // addresses: aau is legacy; use "address-data" aa{sv}
        let addr_data: Vec<std::collections::HashMap<&str, zbus::zvariant::Value>> = addresses.iter()
            .map(|(a, p)| {
                let mut m = std::collections::HashMap::new();
                m.insert("address", zbus::zvariant::Value::from(a.to_string()));
                m.insert("prefix", zbus::zvariant::Value::from(*p));
                m
            }).collect();
        ipv4.insert("address-data".into(), zbus::zvariant::Value::from(addr_data).try_to_owned().unwrap());

        if let Some(gw) = gateway {
            ipv4.insert("gateway".into(), zbus::zvariant::Value::from(gw.to_string()).try_to_owned().unwrap());
        } else {
            ipv4.remove("gateway");
        }

        let dns_u32: Vec<u32> = dns.iter().map(|d| u32::from_le_bytes(d.octets())).collect();
        ipv4.insert("dns".into(), zbus::zvariant::Value::from(dns_u32).try_to_owned().unwrap());

        // If switching to auto, clear static fields entirely.
        if method == "auto" {
            ipv4.remove("address-data");
            ipv4.remove("gateway");
            ipv4.remove("dns");
        }

        settings.call::<_, _, ()>("Update", &(current,)).await.map_err(nm_err)?;

        // Re-activate — §8.2: "Update alone does not apply."
        let nm = zbus::Proxy::new(
            &self._zbus,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        ).await.map_err(nm_err)?;
        let _: zbus::zvariant::OwnedObjectPath = nm.call("ActivateConnection",
            &(conn_path, dev_path, zbus::zvariant::ObjectPath::try_from("/").unwrap())).await.map_err(nm_err)?;

        Ok(())
    }).await.map_err(|_| NetError::Timeout)?
}
```

(Implementation quirks — especially around the exact dict typing and `Value`/`OwnedValue` conversions — are what drives the live-test gate: this code is only validated against a real NM.)

- [ ] **Step 2: Wire `set_dhcp` and `set_static_ipv4` to the helper**

```rust
async fn set_dhcp(&self, iface: &str) -> Result<(), NetError> {
    self.apply_ipv4_settings(iface, "auto", &[], None, &[]).await
}

async fn set_static_ipv4(&self, iface: &str, cfg: StaticIpv4) -> Result<(), NetError> {
    let (a, p) = (cfg.address.addr(), cfg.address.prefix_len() as u32);
    self.apply_ipv4_settings(iface, "manual", &[(a, p)], cfg.gateway, &cfg.dns).await
}
```

- [ ] **Step 3: Add live-destructive tests**

```rust
#[cfg(feature = "live-nm-destructive")]
#[tokio::test]
#[ignore = "changes system IP config; set NETPROV_TEST_IFACE"]
async fn set_dhcp_live() {
    let f = NmrsFacade::new().await.unwrap();
    let iface = std::env::var("NETPROV_TEST_IFACE").unwrap();
    f.set_dhcp(&iface).await.unwrap();
    let cfg = f.get_ip_config(&iface).await.unwrap();
    assert!(matches!(cfg.method, Ipv4Method::Auto));
}
```

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/facade_nmrs.rs
git commit -m "feat(server): NmrsFacade set_dhcp + set_static_ipv4"
```

---

## Phase 7 — CI lint + test (no deb yet)

### Task 7.1: Add minimal GitHub Actions workflow

**Files:**
- Create: `.github/workflows/ci.yml`

Part 2 adds the deb + arm64 matrix. For Part 1 we just want PR gating.

- [ ] **Step 1: Write `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Cache cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock', '**/Cargo.toml') }}
      - name: fmt
        run: cargo fmt --all -- --check
      - name: clippy
        run: cargo clippy --workspace --all-targets -- -D warnings
      - name: test
        run: cargo test --workspace
```

- [ ] **Step 2: Run locally to catch anything the runner would flag**

Run:
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
Expected: all three pass. Fix any clippy warnings that surface.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: fmt + clippy + test on push/PR"
```

---

## Part 1 exit criteria

Before declaring Part 1 done:

- [ ] `cargo fmt --all -- --check` clean.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `cargo test --workspace` — all default-feature tests passing (est. ~40 tests).
- [ ] `cargo build --workspace --features live-nm` compiles.
- [ ] `cargo run -p netprov-server --bin netprovd -- keygen` prints a PSK + QR.
- [ ] Loopback smoke test (Task 5.3 Step 4) completes end-to-end.
- [ ] On a dev box with NetworkManager:
  - `cargo test -p netprov-server --features live-nm -- --ignored list_interfaces_live get_ip_config_live wifi_scan_live` passes for the three non-destructive ops (the engineer documents output and any `NotSupported` results observed).

When these pass, Part 2 (BLE wiring + systemd + deb) begins.

---

## Self-review (from the writing-plans skill)

**Spec coverage (by §):**

- §2 goals — ✓ Phases 0-6 cover all v1 ops; non-goals respected.
- §3 threat model — ✓ §7.3/§7.4 implemented in Phases 1-2.
- §4 architecture — ✓ three-layer split enforced by Task 2.1/2.2.
- §5 crate layout — ✓ Task 0.2.
- §6 library choices — ✓ all pinned in Cargo.toml (Task 0.1).
- §7 GATT protocol — **partially**: Phase 1 builds the envelope and framing logic; wiring to actual GATT characteristics is Part 2. Loopback transport substitutes in Part 1.
- §8 facade — ✓ Phases 2 and 6.
- §9.1 unit file, §9.6 deb — **deferred to Part 2**.
- §9.3 key loading — ✓ Task 3.2.
- §9.4 dev-key warn — ✓ Task 3.3.
- §9.5 keygen — ✓ Task 5.1.
- §9.7 CI — ✓ partial in Task 7.1; arm64 matrix + deb in Part 2.
- §10 testing — ✓ unit + session + loopback tiers in Phases 1-5; live-nm gated in Phase 6; live-ble in Part 2.

**Placeholder scan:** Task 0.2 step 3 has "0.1" placeholder for nmrs version, flagged explicitly with a note to verify at implementation time (Task 6.1 step 1 re-confirms). Task 6.4 contains a structural placeholder for the Wi-Fi ops — genuinely unavoidable because the exact `nmrs` method names depend on the current published version; the task explicitly calls this out and provides raw-zbus fallback guidance + an acceptance test. All other tasks contain complete code.

**Type consistency:** `NetError::InterfaceNotFound(String)` used consistently across `facade.rs`, `facade_mock.rs`, `facade_nmrs.rs`. `Psk` / `Nonce` / `Tag` aliases defined once in `auth.rs`, imported everywhere. `Envelope` defined once in `protocol/message.rs`, used by both server and client.

**Scope:** Part 1 produces working, testable software (end-to-end CLI over TCP loopback with `MockFacade`; `NmrsFacade` validated manually on a dev box). Part 2 adds BLE + packaging to reach a shippable deb.
