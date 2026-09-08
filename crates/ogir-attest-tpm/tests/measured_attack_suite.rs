// SPDX-License-Identifier: Apache-2.0

//! The M4 measured-boot attack suite: all ten roadmap attack-test
//! categories, each returning a deterministic non-allow result
//! against the committed M4-028c capture fixtures, the signed
//! M4-029 reference manifests, and (where a TPM leg is needed) real
//! swtpm. The suite consolidates the categories into one named
//! inventory in the M2-019/M3-025 pattern so the milestone record is
//! self-contained.
//!
//! The ten categories (docs/ROADMAP.md, M4 "Required attack tests"):
//!   1. Secure Boot disabled;
//!   2. modified UKI;
//!   3. modified initramfs or command line;
//!   4. user-enrolled custom key;
//!   5. unapproved kernel with valid signature;
//!   6. forged/truncated/reordered event log;
//!   7. event log that does not reproduce quoted PCRs;
//!   8. revoked boot component;
//!   9. firmware update producing an unknown profile;
//!   10. no TPM or cleared TPM.
//!
//! Mutations operate on the PARSED log structure (public events and
//! digests), so every mutation is exactly what it claims: a changed
//! measurement value, not parser confusion. The Secure Boot
//! ENFORCEMENT boot (the enrolled varstore and the firmware-side
//! rejection of a modified UKI) is the dev-host gate
//! image/enroll-test-key.sh + scripts/test-sb-boot.py, per ADR-0026.

mod common;

use std::collections::HashMap;

use common::SwtpmInstance;
use ogir_attest::sha256::sha256;
use ogir_attest_tpm::logbridge::replay_agrees_with_quote;
use ogir_attest_tpm::validation::QuoteVerifier;
use ogir_bootlog::BootlogError;
use ogir_bootlog::admission::{BootEvidence, admit_boot};
use ogir_bootlog::manifest::parse_manifest;
use ogir_bootlog::parser::{EventLog, parse};
use ogir_bootlog::replay::Replay;

const MANIFEST: &[u8] = include_bytes!("fixtures/manifest/manifest.txt");
const MANIFEST_REVOKED: &[u8] = include_bytes!("fixtures/manifest/manifest-revoked.txt");
const EVENT_LOG: &[u8] = include_bytes!("fixtures/uki-tcg2/event-log.bin");
const IMAGE_KEY_DER: &[u8] = include_bytes!("../../../image/keys/test-image-key.der");
const MANIFEST_ANCHOR_DER: &[u8] = include_bytes!("../../../image/keys/manifest-anchor-key.der");

const CAPTURE_SLOTS: &[u32] = &[0, 1, 2, 3, 4, 5, 6, 7, 9, 11];

fn decode_hex(text: &str) -> Vec<u8> {
    let clean: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&clean[i..i + 2], 16).unwrap_or_else(|_| panic!("hex digit at {i}"))
        })
        .collect()
}

fn replay_of(log: &EventLog) -> HashMap<u32, [u8; 32]> {
    let replay = Replay::sha256(log).unwrap_or_else(|e| panic!("{e:?}"));
    CAPTURE_SLOTS
        .iter()
        .map(|index| {
            (
                *index,
                replay
                    .pcr(*index)
                    .copied()
                    .unwrap_or_else(|| panic!("PCR {index} replayed")),
            )
        })
        .collect()
}

fn good_evidence() -> BootEvidence {
    let log = parse(EVENT_LOG).unwrap_or_else(|e| panic!("{e:?}"));
    BootEvidence {
        claimed_profile: "test-image-efi-capture-v1".to_string(),
        replay_values: replay_of(&log),
        secure_boot_enabled: true,
        component_root_fingerprint: Some(sha256(IMAGE_KEY_DER)),
    }
}

/// Flips one byte of the LAST sha256 digest event for `pcr` in the
/// parsed log - a structurally valid log for a boot whose `pcr`
/// channel measured something else.
fn flip_last_digest_bit(log: &mut EventLog, pcr: u32, bit: u8) {
    let position = log
        .events
        .iter()
        .rposition(|event| event.pcr_index == pcr)
        .unwrap_or_else(|| panic!("an event extending PCR {pcr}"));
    let event = &mut log.events[position];
    let (_, digest) = event
        .digests
        .iter_mut()
        .find(|(algorithm, _)| *algorithm == 0x000B)
        .unwrap_or_else(|| panic!("a sha256 digest for PCR {pcr}"));
    let last = digest.len() - 1;
    digest[last] ^= bit;
}

// Category 1: Secure Boot disabled.
#[test]
fn cat01_secure_boot_disabled_rejects() {
    let manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));
    let mut evidence = good_evidence();
    evidence.secure_boot_enabled = false;
    assert_eq!(
        admit_boot(&manifest, &evidence),
        Err(BootlogError::SecureBootDisabled)
    );
}

// Category 2: a modified UKI measures differently; the replay of the
// modified boot's log no longer reproduces the manifest's PCR 11
// expectation (the sd-stub UKI channel).
#[test]
fn cat02_modified_uki_measurement_rejects() {
    let manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));
    let mut log = parse(EVENT_LOG).unwrap_or_else(|e| panic!("{e:?}"));
    flip_last_digest_bit(&mut log, 11, 0x01);
    let mut evidence = good_evidence();
    evidence.replay_values = replay_of(&log);
    assert_eq!(
        admit_boot(&manifest, &evidence),
        Err(BootlogError::PcrMismatch)
    );
}

// Category 3: a modified initramfs or command line changes the same
// measured channel (both sections live inside the UKI sd-stub
// measures into PCR 11); a different bit of the same digest carries
// the distinct modification.
#[test]
fn cat03_modified_initrd_or_cmdline_rejects() {
    let manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));
    let mut log = parse(EVENT_LOG).unwrap_or_else(|e| panic!("{e:?}"));
    flip_last_digest_bit(&mut log, 11, 0x02);
    let mut evidence = good_evidence();
    evidence.replay_values = replay_of(&log);
    assert_eq!(
        admit_boot(&manifest, &evidence),
        Err(BootlogError::PcrMismatch)
    );
}

// Category 4: a user-enrolled custom key. The boot's components are
// signed by a DIFFERENT root (here: the manifest anchor's own DER -
// a real, committed, non-accepted key), which Secure Boot may happily
// accept on the user's machine but the manifest does not.
#[test]
fn cat04_user_enrolled_custom_key_rejects() {
    let manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));
    let mut evidence = good_evidence();
    evidence.component_root_fingerprint = Some(sha256(MANIFEST_ANCHOR_DER));
    assert_eq!(
        admit_boot(&manifest, &evidence),
        Err(BootlogError::SigningRootRejected)
    );
}

// Category 5: an unapproved kernel carrying a VALID signature from
// the accepted root. Signature and root checks pass; the different
// kernel measures differently, so the replay still mismatches.
#[test]
fn cat05_unapproved_kernel_valid_signature_rejects() {
    let manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));
    let mut evidence = good_evidence();
    let entry = evidence
        .replay_values
        .get_mut(&11)
        .unwrap_or_else(|| panic!("PCR 11 replayed"));
    entry[0] ^= 0x04;
    assert_eq!(
        admit_boot(&manifest, &evidence),
        Err(BootlogError::PcrMismatch)
    );
}

// Category 6: forged, truncated, and reordered event logs.
#[test]
fn cat06_forged_truncated_reordered_logs_reject() {
    // Forged: not a TCG2 Spec ID Event03 log at all.
    let forged = vec![0u8; 64];
    assert_eq!(parse(&forged), Err(BootlogError::NotTcg2));

    // Truncated: cut inside the final structure.
    let truncated = &EVENT_LOG[..EVENT_LOG.len() - 20];
    assert!(parse(truncated).is_err());

    // Reordered: a PCR 7 event (the Secure Boot configuration bank)
    // moved to the UKI phase's position. The log stays structurally
    // valid, but the extension order changed, so the replayed values
    // differ and admission mismatches.
    let manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));
    let mut log = parse(EVENT_LOG).unwrap_or_else(|e| panic!("{e:?}"));
    let pcr7 = log
        .events
        .iter()
        .rposition(|event| event.pcr_index == 7)
        .unwrap_or_else(|| panic!("a PCR 7 event"));
    let uki = log
        .events
        .iter()
        .rposition(|event| event.pcr_index == 11)
        .unwrap_or_else(|| panic!("a PCR 11 event"));
    log.events.swap(pcr7, uki);
    let mut evidence = good_evidence();
    evidence.replay_values = replay_of(&log);
    assert_eq!(
        admit_boot(&manifest, &evidence),
        Err(BootlogError::PcrMismatch)
    );
}

// Category 7: an event log that does not reproduce the quoted PCRs -
// the M4-027 bridge check against a live quote: the genuine log's
// PCR 7 bank is extended into a fresh swtpm and quoted; a log whose
// PCR 7 digest was mutated does not agree with that quote.
#[test]
fn cat07_log_does_not_reproduce_quote_rejects() {
    use ogir_attest::{AttestationBackend, QuoteRequest};
    use ogir_attest_tpm::logbridge::LogExtender;
    use ogir_attest_tpm::swtpm::SwtpmBackend;
    use tss_esapi::handles::PcrHandle;

    let instance = SwtpmInstance::start();
    let mut extender =
        LogExtender::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    let genuine = parse(EVENT_LOG).unwrap_or_else(|e| panic!("{e:?}"));
    extender
        .extend_log_bank(&genuine, 7, PcrHandle::Pcr16)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut backend =
        SwtpmBackend::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    let request = QuoteRequest {
        qualifying_data: b"m4-030-log-quote".to_vec(),
    };
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    let quoted = statement.qualifying_digest();

    // The genuine log agrees with its own quote.
    replay_agrees_with_quote(&genuine, 7, quoted)
        .unwrap_or_else(|e| panic!("the genuine log must agree: {e:?}"));

    // The mutated log does not.
    let mut mutated = parse(EVENT_LOG).unwrap_or_else(|e| panic!("{e:?}"));
    flip_last_digest_bit(&mut mutated, 7, 0x08);
    assert!(replay_agrees_with_quote(&mutated, 7, quoted).is_err());
}

// Category 8: a revoked boot component (the committed revocation
// fixture, revision 2).
#[test]
fn cat08_revoked_boot_component_rejects() {
    let v2 = parse_manifest(MANIFEST_REVOKED).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        v2.check_component("test-uki", "1"),
        Err(BootlogError::ComponentRevoked)
    );
}

// Category 9: a firmware update produces measurements the accepted
// profile never pinned: an UNSUPPORTED state, distinct from forgery.
#[test]
fn cat09_firmware_update_is_unsupported_not_attack() {
    let manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));

    // The firmware measurements changed (PCR 0 is the CRTM bank): a
    // mismatch - the reference data is stale, not the evidence fake.
    let mut log = parse(EVENT_LOG).unwrap_or_else(|e| panic!("{e:?}"));
    flip_last_digest_bit(&mut log, 0, 0x10);
    let mut evidence = good_evidence();
    evidence.replay_values = replay_of(&log);
    assert_eq!(
        admit_boot(&manifest, &evidence),
        Err(BootlogError::PcrMismatch)
    );

    // The updated firmware carries a new profile name: explicitly
    // distinguishable as unsupported, never as an attack verdict.
    let mut renamed = good_evidence();
    renamed.claimed_profile = "test-image-efi-capture-v2".to_string();
    assert_eq!(
        admit_boot(&manifest, &renamed),
        Err(BootlogError::UnsupportedProfile)
    );
}

// Category 10: no TPM (the backend is unreachable and fails closed)
// and a cleared TPM (measurements vanished; nothing matches).
#[test]
fn cat10_no_tpm_and_cleared_tpm_fail_closed() {
    // No TPM: a verifier connecting to a port with no listener fails
    // closed before any decision.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e:?}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e:?}"))
        .port();
    drop(listener);
    assert!(QuoteVerifier::connect("127.0.0.1", port).is_err());

    // Cleared TPM: a fresh swtpm with no boot measures zero banks;
    // admission against the manifest must mismatch, never allow.
    let _instance = SwtpmInstance::start();
    let manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));
    let mut evidence = good_evidence();
    evidence.replay_values = CAPTURE_SLOTS
        .iter()
        .map(|index| (*index, [0u8; 32]))
        .collect();
    assert_eq!(
        admit_boot(&manifest, &evidence),
        Err(BootlogError::PcrMismatch)
    );
}

// The M4 exit criterion as a direct negative: "Secure Boot enabled"
// alone is never sufficient - every other leg green but the
// measurements absent still rejects.
#[test]
fn exit_secure_boot_alone_is_never_sufficient() {
    let manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));
    let mut evidence = good_evidence();
    evidence.replay_values.clear();
    assert_eq!(
        admit_boot(&manifest, &evidence),
        Err(BootlogError::PcrMismatch)
    );
}

// The committed fixtures remain coherent under the suite's own use:
// the manifest verifies against the pinned anchor through a real
// swtpm (a re-statement of the M4-029 leg inside the milestone
// record).
#[test]
fn manifest_signature_verifies_for_the_record() {
    let manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));
    let instance = SwtpmInstance::start();
    let mut verifier =
        QuoteVerifier::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    ogir_attest_tpm::manifest::verify_reference_manifest_signature(
        &mut verifier,
        &decode_hex(include_str!("fixtures/manifest/anchor-modulus.hex")),
        &manifest,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
}
