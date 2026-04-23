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
