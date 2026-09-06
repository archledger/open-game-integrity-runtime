// SPDX-License-Identifier: Apache-2.0

//! The measured-triangle integration suite (M4-027): the REAL host
//! event-log fixture, extended into a live swtpm PCR bank, quoted
//! through the M3 backend, and replayed by ogir-bootlog - all three
//! must agree exactly. The mismatching-log attack rejects.

mod common;

use common::SwtpmInstance;
use ogir_attest::{AssuranceClass, AttestationBackend, QuoteRequest};
use ogir_attest_tpm::logbridge::{BridgeError, LogExtender, replay_agrees_with_quote};
use ogir_attest_tpm::swtpm::SwtpmBackend;
use ogir_bootlog::parser::parse;
use tss_esapi::handles::PcrHandle;

const FIXTURE: &[u8] = include_bytes!("../../ogir-bootlog/tests/fixtures/host-lnl-efi.bin");

/// PCR 7 (secure-boot configuration) is the faithfully replayed bank
/// on this fixture; the events are re-extended into swtpm's PCR 16
/// (the bank the SwtpmBackend quotes).
const SOURCE_PCR: u32 = 7;
const TARGET: PcrHandle = PcrHandle::Pcr16;

#[test]
fn log_tpm_and_quote_agree_end_to_end() {
    let log = parse(FIXTURE).unwrap_or_else(|e| panic!("{e:?}"));
    let instance = SwtpmInstance::start();

    // Extend the log's PCR-7 event digests into the live PCR 16.
    let mut extender =
        LogExtender::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    extender
        .extend_log_bank(&log, SOURCE_PCR, TARGET)
        .unwrap_or_else(|e| panic!("{e:?}"));

    // Quote PCR 16 through the M3 backend.
    let mut backend =
        SwtpmBackend::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    let request = QuoteRequest {
        qualifying_data: b"m4-027-triangle".to_vec(),
    };
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(statement.assurance_class(), AssuranceClass::SoftwareTpm);

    // The quoted digest must validate against the log's replay.
    replay_agrees_with_quote(&log, SOURCE_PCR, statement.qualifying_digest())
        .unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn mismatching_log_rejects_against_the_quote() {
    let log = parse(FIXTURE).unwrap_or_else(|e| panic!("{e:?}"));
    let instance = SwtpmInstance::start();

    // Extend a DIFFERENT bank's events (PCR 2) into PCR 16, so the
    // quoted digest reflects PCR 2's history while we validate against
    // PCR 7's replay - the log-does-not-reproduce category.
    let mut extender =
        LogExtender::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    extender
        .extend_log_bank(&log, 2, TARGET)
        .unwrap_or_else(|e| panic!("{e:?}"));

    let mut backend =
        SwtpmBackend::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    let statement = backend
        .quote(&QuoteRequest {
            qualifying_data: b"m4-027-attack".to_vec(),
        })
        .unwrap_or_else(|e| panic!("{e:?}"));

    assert_eq!(
        replay_agrees_with_quote(&log, SOURCE_PCR, statement.qualifying_digest()),
        Err(BridgeError::LogQuoteMismatch)
    );
}

#[test]
fn truncated_log_cannot_validate() {
    let log = parse(&FIXTURE[..FIXTURE.len() / 2]);
    assert!(log.is_err());
}
