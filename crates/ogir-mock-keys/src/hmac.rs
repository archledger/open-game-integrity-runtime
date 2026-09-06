// SPDX-License-Identifier: Apache-2.0

//! Test-only HMAC-SHA256 (RFC 2104/4231 shape) for the OGIR mock substrate.
//!
//! Same test-only status as the parent crate: deterministic, dependency
//! free, and never a production authenticator (ADR-0016).

use crate::sha256::Sha256;

/// SHA-256 block size in bytes.
const BLOCK_SIZE: usize = 64;

/// Computes HMAC-SHA256(key, message) per RFC 2104.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut normalized = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        normalized[..32].copy_from_slice(&crate::sha256::sha256(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }

    let mut inner_key = [0u8; BLOCK_SIZE];
    let mut outer_key = [0u8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner_key[index] = normalized[index] ^ 0x36;
        outer_key[index] = normalized[index] ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(&inner_key);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&outer_key);
    outer.update(&inner_digest);
    outer.finalize()
}

/// Value-independent comparison over fixed-size tags.
///
/// A correctness obligation from ADR-0016, not a production timing claim.
pub fn fixed_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        let bytes = text.as_bytes();
        if !bytes.len().is_multiple_of(2) {
            panic!("odd hex length");
        }
        (0..bytes.len() / 2)
            .map(|index| {
                let high = (bytes[index * 2] as char).to_digit(16);
                let low = (bytes[index * 2 + 1] as char).to_digit(16);
                match (high, low) {
                    (Some(high), Some(low)) => (high * 16 + low) as u8,
                    _ => panic!("invalid hex digit"),
                }
            })
            .collect()
    }

    fn assert_vector(key: &[u8], message: &[u8], expected_hex: &str) {
        let tag = hmac_sha256(key, message);
        let actual: String = tag.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(actual, expected_hex);
    }

    #[test]
    fn rfc_4231_case_1() {
        assert_vector(
            &[0x0b; 20],
            b"Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        );
    }

    #[test]
    fn rfc_4231_case_2() {
        assert_vector(
            b"Jefe",
            b"what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        );
    }

    #[test]
    fn rfc_4231_case_3() {
        assert_vector(
            &[0xaa; 20],
            &[0xdd; 50],
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        );
    }

    #[test]
    fn rfc_4231_case_6_longer_than_block_key() {
        assert_vector(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        );
    }

    #[test]
    fn rfc_4231_case_7_longer_than_block_key_and_data() {
        assert_vector(
            &[0xaa; 131],
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        );
    }

    #[test]
    fn fixed_time_equal_distinguishes_and_accepts() {
        let left = [0u8; 32];
        let mut right = [0u8; 32];
        right[31] = 1;
        assert!(fixed_time_equal(&left, &left));
        assert!(!fixed_time_equal(&left, &right));
        let _ = unhex("00");
    }
}
