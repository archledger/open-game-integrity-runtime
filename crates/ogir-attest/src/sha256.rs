// SPDX-License-Identifier: Apache-2.0

//! Test-only SHA-256 (FIPS 180-4) for the OGIR mock substrate.
//!
//! This module exists so the mock protocol can authenticate and digest
//! without selecting a production crypto library (ADR-0016). It is
//! dependency-free and deterministic; it is not hardened, not
//! side-channel-resistant, and must never leave test-only code paths.

/// SHA-256 compression constants from FIPS 180-4 section 4.2.2.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Incremental SHA-256 state.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    total_length: u64,
}

impl std::fmt::Debug for Sha256 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Sha256([INTERNAL STATE])")
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Creates a hasher with the FIPS 180-4 initial state.
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            total_length: 0,
        }
    }

    /// Absorbs bytes; any length is accepted.
    pub fn update(&mut self, data: &[u8]) {
        self.total_length = self.total_length.wrapping_add(data.len() as u64);
        let mut offset = 0;
        if self.buffered > 0 {
            let take = std::cmp::min(64 - self.buffered, data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            offset = take;
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            self.compress(&block);
            offset += 64;
        }
        if offset < data.len() {
            let rest = data.len() - offset;
            self.buffer[..rest].copy_from_slice(&data[offset..]);
            self.buffered = rest;
        }
    }

    /// Pads, compresses the tail, and returns the big-endian digest.
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_length = self.total_length.wrapping_mul(8);
        self.update_padding(&bit_length);
        let mut digest = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn update_padding(&mut self, bit_length: &u64) {
        // The pending buffer plus 0x80 plus 8 length bytes must fill whole
        // blocks, so pad with zeros through the next 56-byte boundary.
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let zeroes = if self.buffered < 56 {
            56 - self.buffered
        } else {
            120 - self.buffered
        };
        let total = zeroes + 8;
        pad[zeroes..total].copy_from_slice(&bit_length.to_be_bytes());
        // Bypass update()'s length accounting for the padding itself.
        let mut offset = 0;
        while offset < total {
            let take = std::cmp::min(64 - self.buffered, total - offset);
            self.buffer[self.buffered..self.buffered + take]
                .copy_from_slice(&pad[offset..offset + take]);
            self.buffered += take;
            offset += take;
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for index in 0..16 {
            w[index] = u32::from_be_bytes([
                block[index * 4],
                block[index * 4 + 1],
                block[index * 4 + 2],
                block[index * 4 + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        let deltas = [a, b, c, d, e, f, g, h];
        for (word, delta) in self.state.iter_mut().zip(deltas) {
            *word = word.wrapping_add(delta);
        }
    }
}

/// One-shot SHA-256 over `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn fips_180_4_empty_message() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn fips_180_4_abc() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn fips_180_4_two_block_message() {
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn fips_180_4_one_million_a() {
        let chunk = [b'a'; 1000];
        let mut hasher = Sha256::new();
        for _ in 0..1000 {
            hasher.update(&chunk);
        }
        assert_eq!(
            hex(&hasher.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn incremental_matches_one_shot_at_block_boundaries() {
        let data = [7u8; 200];
        let mut incremental = Sha256::new();
        incremental.update(&data[..63]);
        incremental.update(&data[63..64]);
        incremental.update(&data[64..130]);
        incremental.update(&data[130..]);
        assert_eq!(incremental.finalize(), sha256(&data));
    }
}
