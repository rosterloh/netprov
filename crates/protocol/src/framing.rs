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
}
