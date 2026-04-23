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
