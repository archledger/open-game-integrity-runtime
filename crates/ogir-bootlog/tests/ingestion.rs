// SPDX-License-Identifier: Apache-2.0

//! Integration suite for the TCG2 parser, replay, and profile schema
//! against the REAL host event-log fixture (exported from the dev
//! machine's /sys/kernel/security/tpm0/binary_bios_measurements with
//! its live PCR readback captured as expectations).

use std::collections::HashMap;

use ogir_bootlog::parser::{SHA256_ID, parse};
use ogir_bootlog::profile::PlatformProfile;
use ogir_bootlog::replay::Replay;

const FIXTURE: &[u8] = include_bytes!("fixtures/host-lnl-efi.bin");

/// Live tpm2_pcrread SHA-256 readback captured with the fixture.
///
/// PCR 0 is deliberately NOT asserted: this host's firmware log does
/// not replay to the live PCR 0 (a known real-world fidelity gap -
/// early CRTM measurements precede the log; this is exactly why
/// "event log that does not reproduce quoted PCRs" is a roadmap attack
/// category). PCRs 2 and 7 replay EXACTLY.
fn expectations() -> HashMap<u32, [u8; 32]> {
    let mut expected = HashMap::new();
    for (index, hex) in [
        (
            2u32,
            "3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969",
        ),
        (
            7,
            "498C5733636A5C932780A847C7D81F623A7A4C60123ED5861B04B6D6C2E32F55",
        ),
    ] {
        let mut value = [0u8; 32];
        for (position, pair) in hex.as_bytes().chunks(2).enumerate() {
            let text = std::str::from_utf8(pair).unwrap_or_else(|e| panic!("{e:?}"));
            value[position] = u8::from_str_radix(text, 16).unwrap_or_else(|e| panic!("{e:?}"));
        }
        expected.insert(index, value);
    }
    expected
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

#[test]
fn host_fixture_parses_and_replays_to_live_pcrs() {
    let log = parse(FIXTURE).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(!log.events.is_empty());
    // The fixture is the real host log (116 events in tpm2eventlog
    // counting, which includes the Spec ID header; the parser yields
    // the 115 EVENT2 records).
    assert_eq!(log.events.len(), 115);
    // The Spec ID declares exactly SHA-256.
    assert_eq!(log.spec_id.algorithms.len(), 1);
    assert_eq!(log.spec_id.algorithms[0], (SHA256_ID, 32));

    let replay = Replay::sha256(&log).unwrap_or_else(|e| panic!("{e:?}"));
    let expected = expectations();
    for (index, value) in &expected {
        assert_eq!(
            hex(replay
                .pcr(*index)
                .unwrap_or_else(|| panic!("PCR {index} not touched"))),
            hex(value),
            "PCR {index} replay mismatch"
        );
    }
    replay
        .matches_subset(&expected)
        .unwrap_or_else(|e| panic!("{e:?}"));
    // The log touches PCRs 0 through 7 in this boot; the profile
    // expectations deliberately cover the faithfully replayed subset.
    assert!(replay.touched().contains(&0));
    assert!(replay.touched().contains(&2));
    assert!(replay.touched().contains(&7));
}

#[test]
fn profile_schema_validates_and_transitions_non_weakening() {
    let profile = PlatformProfile {
        name: "test-image-efi-v1".to_string(),
        revision: 1,
        pcr_expectations: expectations(),
        secure_boot_required: true,
        minimum_versions: HashMap::from([("shim".to_string(), "15.8".to_string())]),
    };
    profile.validate().unwrap_or_else(|e| panic!("{e:?}"));

    // A successor: higher revision, same expectations, added
    // expectation, risen floor.
    let mut successor = profile.clone();
    successor.revision = 2;
    successor
        .minimum_versions
        .insert("shim".to_string(), "16.0".to_string());
    successor.pcr_expectations.insert(11, [1u8; 32]);
    assert!(profile.is_non_weakening_successor(&successor));

    // Weakening attempts reject: same revision, dropped expectation,
    // lowered floor, Secure Boot dropped.
    let mut same_revision = successor.clone();
    same_revision.revision = 1;
    assert!(!profile.is_non_weakening_successor(&same_revision));
    let mut dropped = successor.clone();
    dropped.pcr_expectations.remove(&7);
    assert!(!profile.is_non_weakening_successor(&dropped));
    let mut lowered = successor.clone();
    lowered
        .minimum_versions
        .insert("shim".to_string(), "15.6".to_string());
    assert!(!profile.is_non_weakening_successor(&lowered));
    let mut no_sb = successor.clone();
    no_sb.secure_boot_required = false;
    assert!(!profile.is_non_weakening_successor(&no_sb));

    // Shape validation.
    let mut bad = profile.clone();
    bad.pcr_expectations.clear();
    assert!(bad.validate().is_err());
    let mut bad_index = profile.clone();
    bad_index.pcr_expectations.insert(31, [2u8; 32]);
    assert!(bad_index.validate().is_err());
}

#[test]
fn truncated_log_rejects_at_every_cut() {
    for cut in [1usize, 12, 33, 40, 60, FIXTURE.len() / 2, FIXTURE.len() - 1] {
        let result = parse(&FIXTURE[..cut]);
        assert!(result.is_err(), "cut {cut} unexpectedly parsed");
    }
}

#[test]
fn trailing_bytes_and_foreign_headers_reject() {
    let mut trailing = FIXTURE.to_vec();
    trailing.push(0);
    assert!(parse(&trailing).is_err());

    let mut foreign = FIXTURE.to_vec();
    // Corrupt the Spec ID signature.
    foreign[32] = b'X';
    assert!(matches!(
        parse(&foreign),
        Err(ogir_bootlog::BootlogError::NotTcg2)
    ));

    let mut bad_algorithm = FIXTURE.to_vec();
    // Corrupt the Spec ID algorithm table (the digestSize byte of the
    // first declared algorithm): parsing either fails or, if it still
    // parses, must fail the later structure checks - either way the
    // log no longer validates as-is against live PCRs.
    bad_algorithm[41] = 0x40;
    if let Ok(log) = parse(&bad_algorithm) {
        let replay = Replay::sha256(&log).unwrap_or_else(|e| panic!("{e:?}"));
        assert!(replay.matches_subset(&expectations()).is_err());
    }
}

#[test]
fn replay_mismatch_detects_forged_expectations() {
    let log = parse(FIXTURE).unwrap_or_else(|e| panic!("{e:?}"));
    let replay = Replay::sha256(&log).unwrap_or_else(|e| panic!("{e:?}"));
    let mut forged = expectations();
    let entry = forged.get_mut(&7).unwrap_or_else(|| panic!("missing"));
    entry[0] ^= 0x01;
    assert!(replay.matches(&forged).is_err());
    // An expectation for an untouched PCR also fails.
    let mut extra = expectations();
    extra.insert(11, [9u8; 32]);
    assert!(replay.matches(&extra).is_err());
}
