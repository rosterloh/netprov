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
            while !s.is_char_boundary(cut) {
                cut -= 1;
            }
            s.truncate(cut);
        }
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
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
                "string exceeds {BOUNDED_STRING_MAX} byte limit ({} bytes)",
                s.len()
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

impl std::fmt::Display for BoundedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
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
        let e = ProtocolError::RateLimited {
            retry_after_seconds: 60,
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&e, &mut bytes).unwrap();
        let back: ProtocolError = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(e, back);
    }
}
