//! Fragmented framing over small GATT writes/notifies.
//!
//! Each physical frame carries: `[u16 request_id BE][u16 seq BE][u8 flags][payload]`.
//! `flags` bit 0 is `FIN` (last fragment in the message).

pub const FRAME_HEADER_LEN: usize = 5;
pub const FRAME_FLAG_FIN: u8 = 0x01;
/// Upper bound on a single BLE notify/write value (Web Bluetooth ceiling).
/// Real ATT MTUs negotiated by a given connection are usually smaller than
/// this; callers should cap `fragment`'s `max_fragment` argument at the
/// negotiated MTU and use this constant only as the ceiling.
pub const MAX_FRAME_LEN: usize = 512;
pub const MAX_PAYLOAD_PER_FRAME: usize = MAX_FRAME_LEN - FRAME_HEADER_LEN;

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("frame too short ({0} bytes, need >= {FRAME_HEADER_LEN})")]
    TooShort(usize),
    #[error("reassembled message exceeds {limit} bytes")]
    MessageTooLarge { limit: usize },
    #[error("duplicate sequence number {seq} for request {request_id}")]
    DuplicateSeq { request_id: u16, seq: u16 },
    #[error("missing fragments for request {request_id} (have {got}, FIN at seq {fin_seq})")]
    MissingFragments {
        request_id: u16,
        got: usize,
        fin_seq: u16,
    },
    #[error("too many concurrent partial messages ({max})")]
    TooManyPartials { max: usize },
}

pub fn fragment(request_id: u16, payload: &[u8], max_fragment: usize) -> Vec<Vec<u8>> {
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
    /// Cap on distinct in-flight `request_id`s. The client is strictly
    /// request/response, so this is generous headroom, not a real limit —
    /// its purpose is to bound memory an unauthenticated or misbehaving
    /// peer can hold via never-completed fragment sequences.
    max_partials: usize,
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
        Self {
            max_message,
            max_partials: 4,
            state: Default::default(),
        }
    }

    /// Feed one parsed fragment. Returns `Some(message_bytes)` when a FIN is
    /// received and all prior seqs are present.
    pub fn push(&mut self, f: ParsedFrame<'_>) -> Result<Option<Vec<u8>>, FramingError> {
        if !self.state.contains_key(&f.request_id) && self.state.len() >= self.max_partials {
            return Err(FramingError::TooManyPartials {
                max: self.max_partials,
            });
        }
        let entry = self
            .state
            .entry(f.request_id)
            .or_insert_with(|| PartialMessage {
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

        // Contiguity guard: no fragment may carry a seq beyond the FIN. This
        // rejects a stray high-seq fragment (whether it arrives before or
        // after the FIN) and a FIN that lands below an already-buffered higher
        // seq. Without it, a bogus fragment can make `frags.len()` match the
        // expected count while the assembled bytes include data past FIN and
        // silently omit a real fragment. The message is unrecoverable once
        // this happens, so drop the partial to free its slot rather than let
        // it linger for the life of the connection.
        let effective_fin = if f.fin { Some(f.seq) } else { entry.fin_seq };
        if let Some(fin_seq) = effective_fin {
            let highest_buffered = entry.frags.keys().next_back().copied();
            if f.seq > fin_seq || highest_buffered.is_some_and(|h| h > fin_seq) {
                let got = entry.frags.len();
                self.state.remove(&f.request_id);
                return Err(FramingError::MissingFragments {
                    request_id: f.request_id,
                    got,
                    fin_seq,
                });
            }
        }

        entry.total_bytes += f.payload.len();
        if entry.total_bytes > self.max_message {
            self.state.remove(&f.request_id);
            return Err(FramingError::MessageTooLarge {
                limit: self.max_message,
            });
        }
        entry.frags.insert(f.seq, f.payload.to_vec());
        if f.fin {
            entry.fin_seq = Some(f.seq);
        }

        if let Some(fin_seq) = entry.fin_seq {
            let expected = (fin_seq as usize) + 1;
            if entry.frags.len() == expected {
                let mut out = Vec::with_capacity(entry.total_bytes);
                for frag in entry.frags.values() {
                    out.extend_from_slice(frag);
                }
                self.state.remove(&f.request_id);
                return Ok(Some(out));
            }
        }
        Ok(None)
    }

    /// Number of distinct `request_id`s with in-flight partial state.
    /// Exposed for tests asserting a rejected/dropped frame left no state
    /// behind.
    pub fn partial_count(&self) -> usize {
        self.state.len()
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
        assert!(matches!(
            parse_frame(b"abc"),
            Err(FramingError::TooShort(3))
        ));
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

    #[test]
    fn fifth_concurrent_partial_rejected() {
        let mut r = Reassembler::new(4096);
        // Open 4 partial messages (one unfinished fragment each) — all within
        // the default max_partials cap.
        for rid in 0..4u16 {
            let f = encode_frame(rid, 0, 0, b"partial");
            assert!(r.push(parse_frame(&f).unwrap()).unwrap().is_none());
        }
        // A 5th distinct request_id must be rejected before any state for it
        // is created.
        let f5 = encode_frame(4, 0, 0, b"partial");
        let err = r.push(parse_frame(&f5).unwrap()).unwrap_err();
        assert!(matches!(err, FramingError::TooManyPartials { max: 4 }));

        // Existing partials are unaffected and can still be completed.
        let fin = encode_frame(0, 1, FRAME_FLAG_FIN, b"!");
        let out = r.push(parse_frame(&fin).unwrap()).unwrap();
        assert_eq!(out.unwrap(), b"partial!");
    }

    #[test]
    fn stray_high_seq_before_fin_rejected() {
        // Repro from issue #12: a stray fragment with seq > fin_seq must not
        // be assembled into a "complete" message just because the count lines
        // up. Previously this yielded Ok(Some(b"AABBXX")).
        let mut r = Reassembler::new(4096);
        r.push(parse_frame(&encode_frame(1, 0, 0, b"AA")).unwrap())
            .unwrap();
        r.push(parse_frame(&encode_frame(1, 5, 0, b"XX")).unwrap())
            .unwrap(); // stray seq 5
        let err = r
            .push(parse_frame(&encode_frame(1, 2, FRAME_FLAG_FIN, b"BB")).unwrap())
            .unwrap_err();
        assert!(matches!(
            err,
            FramingError::MissingFragments { fin_seq: 2, .. }
        ));
        // The unrecoverable partial is dropped, freeing its slot.
        assert_eq!(r.partial_count(), 0);
    }

    #[test]
    fn stray_high_seq_after_fin_rejected() {
        // FIN establishes fin_seq=1; a later fragment with seq 5 must be
        // rejected rather than buffered.
        let mut r = Reassembler::new(4096);
        r.push(parse_frame(&encode_frame(1, 0, 0, b"AA")).unwrap())
            .unwrap();
        r.push(parse_frame(&encode_frame(1, 1, FRAME_FLAG_FIN, b"BB")).unwrap())
            .unwrap();
        // With seqs {0,1} and fin_seq=1 the message already completed above,
        // so start a fresh request to exercise the post-FIN stray path.
        let mut r = Reassembler::new(4096);
        r.push(parse_frame(&encode_frame(2, 0, 0, b"AA")).unwrap())
            .unwrap();
        r.push(parse_frame(&encode_frame(2, 2, FRAME_FLAG_FIN, b"CC")).unwrap())
            .unwrap(); // fin_seq=2, still missing seq 1
        let err = r
            .push(parse_frame(&encode_frame(2, 5, 0, b"XX")).unwrap())
            .unwrap_err();
        assert!(matches!(
            err,
            FramingError::MissingFragments { fin_seq: 2, .. }
        ));
        assert_eq!(r.partial_count(), 0);
    }

    #[test]
    fn fin_below_buffered_seq_rejected() {
        // Milder variant from issue #12: {seq 0, seq 5} then FIN at 1. The
        // buffered seq 5 is beyond the declared FIN, so reject instead of
        // letting the partial linger and permanently consume a slot.
        let mut r = Reassembler::new(4096);
        r.push(parse_frame(&encode_frame(1, 0, 0, b"AA")).unwrap())
            .unwrap();
        r.push(parse_frame(&encode_frame(1, 5, 0, b"XX")).unwrap())
            .unwrap();
        let err = r
            .push(parse_frame(&encode_frame(1, 1, FRAME_FLAG_FIN, b"BB")).unwrap())
            .unwrap_err();
        assert!(matches!(
            err,
            FramingError::MissingFragments { fin_seq: 1, .. }
        ));
        assert_eq!(r.partial_count(), 0);
    }

    #[test]
    fn out_of_order_valid_fragments_still_reassemble() {
        // Guard must not reject legitimate out-of-order delivery within range.
        let mut r = Reassembler::new(4096);
        assert!(
            r.push(parse_frame(&encode_frame(1, 2, FRAME_FLAG_FIN, b"CC")).unwrap())
                .unwrap()
                .is_none()
        );
        assert!(
            r.push(parse_frame(&encode_frame(1, 0, 0, b"AA")).unwrap())
                .unwrap()
                .is_none()
        );
        let out = r
            .push(parse_frame(&encode_frame(1, 1, 0, b"BB")).unwrap())
            .unwrap();
        assert_eq!(out.unwrap(), b"AABBCC");
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

        /// Reordered valid fragments must still reassemble to the exact
        /// original payload, and whatever the Reassembler declares "complete"
        /// must round-trip — never a corrupted concatenation.
        #[test]
        fn reordered_fragments_reassemble(
            rid in any::<u16>(),
            payload in proptest::collection::vec(any::<u8>(), 1..2000usize),
            mtu in 16usize..512,
            seed in any::<u64>(),
        ) {
            let mut frames = fragment(rid, &payload, mtu);
            // Deterministic Fisher–Yates shuffle driven by the proptest seed.
            let mut s = seed | 1;
            for i in (1..frames.len()).rev() {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                let j = (s as usize) % (i + 1);
                frames.swap(i, j);
            }
            let mut r = Reassembler::new(1 << 20);
            let mut out = None;
            for f in &frames {
                let parsed = parse_frame(f).unwrap();
                if let Some(msg) = r.push(parsed).unwrap() {
                    out = Some(msg);
                }
            }
            prop_assert_eq!(out.unwrap(), payload);
        }

        /// Injecting a stray fragment whose seq is beyond the FIN must never
        /// produce a "complete" message: either the injection is rejected, or
        /// the genuine fragments still assemble to the correct payload. The
        /// Reassembler must never return corrupt bytes.
        #[test]
        fn injected_high_seq_never_corrupts(
            payload in proptest::collection::vec(any::<u8>(), 2..500usize),
            mtu in 16usize..64,
            stray in proptest::collection::vec(any::<u8>(), 1..8usize),
        ) {
            let rid = 7u16;
            let frames = fragment(rid, &payload, mtu);
            // Only meaningful when the payload spans multiple fragments so the
            // FIN seq is > 0 and a "beyond FIN" seq exists.
            prop_assume!(frames.len() >= 2);
            let fin_seq = (frames.len() - 1) as u16;

            let mut r = Reassembler::new(1 << 20);
            // Feed everything except the FIN fragment.
            for f in &frames[..frames.len() - 1] {
                r.push(parse_frame(f).unwrap()).unwrap();
            }
            // Inject a stray fragment past the FIN seq.
            let stray_frame = encode_frame(rid, fin_seq + 3, 0, &stray);
            let _ = r.push(parse_frame(&stray_frame).unwrap());
            // Deliver the real FIN.
            let res = r.push(parse_frame(&frames[frames.len() - 1]).unwrap());
            // If it claims completion, the bytes must be exactly the payload;
            // rejecting the inconsistent state (Ok(None)/Err) is also fine.
            // The Reassembler must never return corrupt bytes.
            if let Ok(Some(msg)) = res {
                prop_assert_eq!(msg, payload.clone());
            }
        }
    }
}
