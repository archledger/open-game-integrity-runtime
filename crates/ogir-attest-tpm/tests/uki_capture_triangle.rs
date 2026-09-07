// SPDX-License-Identifier: Apache-2.0

//! The M4-028c UKI-capture triangle: the committed fixture from ONE
//! measured capture boot under the TCG2-enabled OVMF must satisfy all
//! three legs:
//!   1. LOG vs LIVE: ogir-bootlog's replay of the exported TCG2 event
//!      log equals the live PCR values read inside the guest for every
//!      captured SHA-256 bank;
//!   2. LOG vs QUOTE: the TPM2_Quote's attested pcrDigest equals
//!      SHA256(concatenation of the replayed PCR values) - the
//!      multi-bank generalization of `replay_agrees_with_quote` - and
//!      the quote covers exactly the validated banks and echoes the
//!      recorded capture nonce;
//!   3. SIGNATURE: the RSASSA-SHA256 signature over the TPMS_ATTEST
//!      bytes verifies against the captured AK modulus through the
//!      crate's QuoteVerifier (a fresh swtpm as the verification
//!      engine; verification reads no TPM state).
//!
//! The capture (image/boot-capture.sh) is a dev-host gate; this test
//! makes the committed evidence durably valid in CI.

mod common;

use std::collections::HashMap;

use common::SwtpmInstance;
use ogir_attest::sha256::sha256;
use ogir_attest_tpm::validation::QuoteVerifier;
use ogir_bootlog::parser::parse;
use ogir_bootlog::replay::Replay;

const EVENT_LOG: &[u8] = include_bytes!("fixtures/uki-tcg2/event-log.bin");
const PCRS_TEXT: &str = include_str!("fixtures/uki-tcg2/pcrs.txt");
const QUOTE_MSG: &[u8] = include_bytes!("fixtures/uki-tcg2/quote.msg");
const QUOTE_SIG: &[u8] = include_bytes!("fixtures/uki-tcg2/quote.sig");
const AK_MODULUS_HEX: &str = include_str!("fixtures/uki-tcg2/ak-modulus.hex");
const NONCE_HEX: &str = include_str!("fixtures/uki-tcg2/nonce.hex");

/// The banks the capture validates (image/capture-init.sh): every PCR
/// this OVMF measures plus the sd-stub UKI bank. PCR 8 stays zero on
/// the platform and PCR 10 carries non-replayable IMA churn, so both
/// are excluded by design everywhere in the capture.
const CAPTURE_SLOTS: &[u32] = &[0, 1, 2, 3, 4, 5, 6, 7, 9, 11];

/// TPMS_ATTEST (QUOTE variant) pieces needed for offline validation.
struct QuoteAttest {
    extra_data: Vec<u8>,
    pcr_digest: [u8; 32],
    /// SHA-256 selections as (algorithm, selected PCR indices).
    selections: Vec<(u16, Vec<u32>)>,
}

/// Minimal, fail-closed TPMS_ATTEST walk (TPM 2.0 Part 2): the fixed
/// header (magic, type), the two TPM2B fields (qualifiedSigner,
/// extraData), the fixed clockInfo and firmwareVersion, then the
/// QUOTE-specific TPML_PCR_SELECTION and the TPM2B pcrDigest.
fn parse_quote_attest(bytes: &[u8]) -> QuoteAttest {
    let mut c = Cursor::new(bytes);
    let magic = c.u32();
    assert_eq!(magic, 0xFF54_4347, "TPM_GENERATED magic");
    let attest_type = c.u16();
    assert_eq!(attest_type, 0x8018, "TPM_ST_ATTEST_QUOTE");
    let _qualified_signer = c.tpm2b();
    let extra_data = c.tpm2b();
    c.skip(8 + 4 + 4 + 1); // clockInfo: clock, resetCount, restartCount, safe
    c.skip(8); // firmwareVersion

    let count = c.u32();
    assert_eq!(count, 1, "the capture quote uses one SHA-256 selection");
    let mut selections = Vec::new();
    for _ in 0..count {
        let algorithm = c.u16();
        assert_eq!(algorithm, 0x000B, "TPM_ALG_SHA256");
        let size_of_select = c.u8();
        let select = c.take(size_of_select as usize);
        let slots: Vec<u32> = (0..size_of_select as u32 * 8)
            .filter(|bit| select[(*bit / 8) as usize] >> (bit % 8) & 1 == 1)
            .collect();
        selections.push((algorithm, slots));
    }
    let digest_bytes = c.tpm2b();
    let pcr_digest: [u8; 32] = digest_bytes
        .try_into()
        .unwrap_or_else(|_| panic!("pcrDigest is a SHA-256 digest"));
    assert_eq!(c.remaining(), 0, "the attestation is fully consumed");
    QuoteAttest {
        extra_data,
        pcr_digest,
        selections,
    }
}

/// A bounds-checked big-endian reader; every overrun fails the test.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, length: usize) -> &'a [u8] {
        let end = self.offset + length;
        assert!(
            end <= self.bytes.len(),
            "attestation truncated at a field boundary"
        );
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        slice
    }
    fn skip(&mut self, length: usize) {
        self.take(length);
    }
    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }
    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(
            self.take(2)
                .try_into()
                .unwrap_or_else(|_| panic!("two bytes")),
        )
    }
    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(
            self.take(4)
                .try_into()
                .unwrap_or_else(|_| panic!("four bytes")),
        )
    }
    fn tpm2b(&mut self) -> Vec<u8> {
        let length = self.u16() as usize;
        self.take(length).to_vec()
    }
    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}

fn decode_hex(text: &str) -> Vec<u8> {
    let clean: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&clean[i..i + 2], 16).unwrap_or_else(|_| panic!("hex digit at {i}"))
        })
        .collect()
}

/// Parses the tpm2 pcrread text output for the SHA-256 bank into
/// index-to-value pairs; any short or malformed line fails the test.
fn live_sha256_pcrs() -> HashMap<u32, [u8; 32]> {
    let mut in_sha256 = false;
    let mut values = HashMap::new();
    for line in PCRS_TEXT.lines() {
        if line.starts_with("  sha256:") {
            in_sha256 = true;
            continue;
        }
        if !in_sha256 {
            continue;
        }
        let Some((index_text, value_text)) = line.split_once(':') else {
            break;
        };
        let Ok(index) = index_text.trim().parse::<u32>() else {
            break; // the sha1: section header ends the sha256 bank
        };
        let value_text = value_text.trim();
        assert!(
            value_text.starts_with("0x") && value_text.len() == 66,
            "malformed pcrread line: {line:?}"
        );
        values.insert(
            index,
            decode_hex(&value_text[2..])
                .try_into()
                .unwrap_or_else(|_| panic!("32-byte SHA-256 PCR value for {index}")),
        );
    }
    values
}

/// Unwraps tpm2-tools' TPMT_SIGNATURE output (u16 algorithm tag, u16
/// hash algorithm, TPM2B length, then the raw signature) into the raw
/// RSA signature bytes the QuoteVerifier expects.
fn raw_signature(tpmt: &[u8]) -> Vec<u8> {
    let mut c = Cursor::new(tpmt);
    let algorithm = c.u16();
    assert_eq!(algorithm, 0x0014, "TPM_ALG_RSASSA");
    let hash = c.u16();
    assert_eq!(hash, 0x000B, "TPM_ALG_SHA256");
    let signature = c.tpm2b();
    assert_eq!(signature.len(), 256, "RSA-2048 signature");
    assert_eq!(c.remaining(), 0, "no trailing bytes");
    signature
}

#[test]
fn captured_uki_boot_triangle_holds() {
    // Parse the exported TCG2 event log and replay it.
    let log = parse(EVENT_LOG).unwrap_or_else(|e| panic!("{e:?}"));
    let replay = Replay::sha256(&log).unwrap_or_else(|e| panic!("{e:?}"));

    // Leg 1 - LOG vs LIVE: the replay equals the in-guest read for
    // every captured bank (PCR 11 included: the sd-stub UKI phase).
    replay
        .matches(&live_sha256_pcrs())
        .unwrap_or_else(|e| panic!("{e:?}"));

    // Leg 2 - LOG vs QUOTE: the attested digest is SHA256(concat of
    // the replayed values, ascending index within the selection).
    let attest = parse_quote_attest(QUOTE_MSG);
    assert_eq!(
        attest.extra_data,
        decode_hex(NONCE_HEX),
        "the quote must echo the recorded capture nonce"
    );
    let (algorithm, slots) = &attest.selections[0];
    assert_eq!(*algorithm, 0x000B);
    assert_eq!(
        slots, CAPTURE_SLOTS,
        "the quote must cover exactly the validated banks"
    );
    let concatenated: Vec<u8> = slots
        .iter()
        .flat_map(|index| {
            replay
                .pcr(*index)
                .unwrap_or_else(|| panic!("replayed PCR value for {index}"))
                .iter()
                .copied()
        })
        .collect();
    assert_eq!(
        sha256(&concatenated),
        attest.pcr_digest,
        "the quoted pcrDigest must equal the log replay's digest"
    );

    // Leg 3 - SIGNATURE: verify RSASSA-SHA256 over the raw TPMS_ATTEST
    // bytes with the captured AK modulus through the QuoteVerifier
    // (a fresh swtpm as the crypto engine; no TPM state involved).
    let instance = SwtpmInstance::start();
    let mut verifier =
        QuoteVerifier::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    verifier
        .verify_signature(
            &decode_hex(AK_MODULUS_HEX),
            &raw_signature(QUOTE_SIG),
            QUOTE_MSG,
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn tampered_quote_signature_rejects() {
    let instance = SwtpmInstance::start();
    let mut verifier =
        QuoteVerifier::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    let mut tampered = raw_signature(QUOTE_SIG);
    tampered[0] ^= 0xFF;
    assert!(
        verifier
            .verify_signature(&decode_hex(AK_MODULUS_HEX), &tampered, QUOTE_MSG)
            .is_err()
    );
}
