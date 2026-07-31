use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const PSK_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;
pub const TAG_LEN: usize = 32;

pub type Psk = [u8; PSK_LEN];
pub type Nonce = [u8; NONCE_LEN];
pub type Tag = [u8; TAG_LEN];

/// Wire layout of the `AuthResponse` write (and `Envelope::AuthSubmit`): the
/// client's nonce followed by its tag.
pub const AUTH_PAYLOAD_LEN: usize = NONCE_LEN + TAG_LEN;

pub fn auth_payload(client_nonce: &Nonce, tag: &Tag) -> [u8; AUTH_PAYLOAD_LEN] {
    let mut out = [0u8; AUTH_PAYLOAD_LEN];
    out[..NONCE_LEN].copy_from_slice(client_nonce);
    out[NONCE_LEN..].copy_from_slice(tag);
    out
}

/// Splits an `AuthResponse` payload. `None` if it is not exactly
/// [`AUTH_PAYLOAD_LEN`] bytes.
pub fn split_auth_payload(payload: &[u8]) -> Option<(Nonce, &[u8])> {
    if payload.len() != AUTH_PAYLOAD_LEN {
        return None;
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&payload[..NONCE_LEN]);
    Some((nonce, &payload[NONCE_LEN..]))
}

/// Domain separation labels. Both tags cover the same two nonces, so without
/// distinct labels a client tag could be replayed back as the server's proof
/// and an impersonator would pass verification without knowing the PSK.
const CLIENT_LABEL: &[u8] = b"netprov-auth-client-v2";
const SERVER_LABEL: &[u8] = b"netprov-auth-server-v2";

fn tag_with(label: &[u8], psk: &Psk, server_nonce: &Nonce, client_nonce: &Nonce) -> Tag {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(psk).expect("HMAC accepts any key len");
    mac.update(label);
    mac.update(server_nonce);
    mac.update(client_nonce);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&out);
    tag
}

/// The client's proof that it holds the PSK.
pub fn client_tag(psk: &Psk, server_nonce: &Nonce, client_nonce: &Nonce) -> Tag {
    tag_with(CLIENT_LABEL, psk, server_nonce, client_nonce)
}

/// The server's proof that it holds the PSK, sent only after the client's tag
/// verifies. This is what stops an impersonating peer — which cannot produce
/// it — from collecting the Wi-Fi credentials the client would send next.
pub fn server_tag(psk: &Psk, server_nonce: &Nonce, client_nonce: &Nonce) -> Tag {
    tag_with(SERVER_LABEL, psk, server_nonce, client_nonce)
}

fn verify(expected: Tag, candidate: &[u8]) -> bool {
    if candidate.len() != TAG_LEN {
        return false;
    }
    expected.ct_eq(candidate).into()
}

pub fn verify_client_tag(
    psk: &Psk,
    server_nonce: &Nonce,
    client_nonce: &Nonce,
    candidate: &[u8],
) -> bool {
    verify(client_tag(psk, server_nonce, client_nonce), candidate)
}

pub fn verify_server_tag(
    psk: &Psk,
    server_nonce: &Nonce,
    client_nonce: &Nonce,
    candidate: &[u8],
) -> bool {
    verify(server_tag(psk, server_nonce, client_nonce), candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: Nonce = [42u8; NONCE_LEN];
    const NC: Nonce = [99u8; NONCE_LEN];

    #[test]
    fn verify_accepts_correct_tags() {
        let psk = [7u8; PSK_LEN];
        assert!(verify_client_tag(
            &psk,
            &NS,
            &NC,
            &client_tag(&psk, &NS, &NC)
        ));
        assert!(verify_server_tag(
            &psk,
            &NS,
            &NC,
            &server_tag(&psk, &NS, &NC)
        ));
    }

    #[test]
    fn verify_rejects_wrong_psk() {
        let psk_a = [1u8; PSK_LEN];
        let psk_b = [2u8; PSK_LEN];
        assert!(!verify_client_tag(
            &psk_b,
            &NS,
            &NC,
            &client_tag(&psk_a, &NS, &NC)
        ));
        assert!(!verify_server_tag(
            &psk_b,
            &NS,
            &NC,
            &server_tag(&psk_a, &NS, &NC)
        ));
    }

    #[test]
    fn verify_rejects_wrong_length() {
        let psk = [0u8; PSK_LEN];
        assert!(!verify_client_tag(&psk, &NS, &NC, b"too short"));
        assert!(!verify_client_tag(&psk, &NS, &NC, &[0u8; TAG_LEN + 1]));
    }

    /// The whole point of the domain labels: neither side's proof is accepted
    /// as the other's, so a relaying impersonator cannot echo the client's tag
    /// back as the server's.
    #[test]
    fn tags_are_domain_separated() {
        let psk = [3u8; PSK_LEN];
        let client = client_tag(&psk, &NS, &NC);
        let server = server_tag(&psk, &NS, &NC);
        assert_ne!(client, server);
        assert!(!verify_server_tag(&psk, &NS, &NC, &client));
        assert!(!verify_client_tag(&psk, &NS, &NC, &server));
    }

    #[test]
    fn either_nonce_changes_both_tags() {
        let psk = [0u8; PSK_LEN];
        let other = [1u8; NONCE_LEN];
        assert_ne!(client_tag(&psk, &NS, &NC), client_tag(&psk, &other, &NC));
        assert_ne!(client_tag(&psk, &NS, &NC), client_tag(&psk, &NS, &other));
        assert_ne!(server_tag(&psk, &NS, &NC), server_tag(&psk, &other, &NC));
        assert_ne!(server_tag(&psk, &NS, &NC), server_tag(&psk, &NS, &other));
    }

    /// Swapping the two nonces must not collide, or a reflected handshake
    /// could pass.
    #[test]
    fn nonce_order_matters() {
        let psk = [5u8; PSK_LEN];
        assert_ne!(client_tag(&psk, &NS, &NC), client_tag(&psk, &NC, &NS));
    }
}
