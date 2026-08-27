// SPDX-License-Identifier: Apache-2.0

use std::any::TypeId;
use std::collections::{HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};

use ogir_model::{Nonce, SESSION_PUBLIC_KEY_ID_LENGTH, SessionId, SessionPublicKeyId};

const EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH: usize = 32;
const PRIVATE_SENTINEL: [u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH] = [
    0x03, 0x17, 0x2b, 0x3f, 0x53, 0x67, 0x7b, 0x8f, 0xa3, 0xb7, 0xcb, 0xdf, 0xf3, 0x07, 0x1b, 0x2f,
    0x43, 0x57, 0x6b, 0x7f, 0x93, 0xa7, 0xbb, 0xcf, 0xe3, 0xf7, 0x0b, 0x1f, 0x33, 0x47, 0x5b, 0x6f,
];

fn value_hash(value: SessionPublicKeyId) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn exact_length_and_round_trip_are_fixed() {
    assert_eq!(
        SESSION_PUBLIC_KEY_ID_LENGTH,
        EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH
    );
    let identifier = SessionPublicKeyId::from_bytes(PRIVATE_SENTINEL);
    assert_eq!(identifier.as_bytes(), &PRIVATE_SENTINEL);
}

#[test]
fn every_fixed_whole_value_control_is_representable() {
    let mut alternating = [0_u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH];
    for (position, byte) in alternating.iter_mut().enumerate() {
        *byte = if position % 2 == 0 { 0x55 } else { 0xaa };
    }

    let mut ascending = [0_u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH];
    let mut descending = [0_u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH];
    for value in 0_u8..32 {
        ascending[usize::from(value)] = value;
        descending[usize::from(value)] = 31 - value;
    }

    for bytes in [
        [0_u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH],
        [u8::MAX; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH],
        alternating,
        ascending,
        descending,
    ] {
        assert_eq!(SessionPublicKeyId::from_bytes(bytes).as_bytes(), &bytes);
    }
}

#[test]
fn copy_equality_inequality_and_hashing_are_plain_value_semantics() {
    let first = SessionPublicKeyId::from_bytes(PRIVATE_SENTINEL);
    let same = first;
    let mut changed = PRIVATE_SENTINEL;
    changed[17] ^= 0xff;
    let different = SessionPublicKeyId::from_bytes(changed);

    assert_eq!(first, same);
    assert_ne!(first, different);
    assert_eq!(value_hash(first), value_hash(same));

    let mut values = HashSet::new();
    assert!(values.insert(first));
    assert!(!values.insert(same));
    assert!(values.insert(different));
    assert_eq!(values.len(), 2);
}

#[test]
fn all_8192_position_value_cases_round_trip_without_normalization() {
    let mut case_count = 0_usize;

    for position in 0..EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH {
        for value in u8::MIN..=u8::MAX {
            let mut bytes = PRIVATE_SENTINEL;
            bytes[position] = value;
            let identifier = SessionPublicKeyId::from_bytes(bytes);
            let copied = identifier;

            assert_eq!(identifier.as_bytes(), &bytes);
            assert_eq!(copied, identifier);
            assert_eq!(value_hash(copied), value_hash(identifier));
            assert_eq!(
                format!("{identifier:?}"),
                "SessionPublicKeyId([REDACTED; 32])"
            );
            case_count += 1;
        }
    }

    assert_eq!(case_count, 8_192);
}

#[test]
fn debug_is_exact_fixed_redaction_for_real_sentinel_bytes() {
    let identifier = SessionPublicKeyId::from_bytes(PRIVATE_SENTINEL);
    let diagnostic = format!("{identifier:?}");
    let raw = format!("{PRIVATE_SENTINEL:?}");

    assert_eq!(diagnostic, "SessionPublicKeyId([REDACTED; 32])");
    assert!(!diagnostic.contains(&raw));
    assert!(!diagnostic.contains("0x"));
}

#[test]
fn runtime_type_identity_is_distinct_from_nonce_and_session_id() {
    let identifier_type = TypeId::of::<SessionPublicKeyId>();
    assert_ne!(identifier_type, TypeId::of::<Nonce>());
    assert_ne!(identifier_type, TypeId::of::<SessionId>());
}

#[test]
fn public_api_surface_is_pinned_to_the_approved_non_authority_contract() {
    let source = include_str!("../src/lib.rs").replace("\r\n", "\n");
    assert_eq!(
        source
            .matches("pub const SESSION_PUBLIC_KEY_ID_LENGTH: usize = 32;")
            .count(),
        1
    );

    let start_marker = "#[derive(Clone, Copy, PartialEq, Eq, Hash)]\npub struct SessionPublicKeyId";
    let start = match source.find(start_marker) {
        Some(index) => index,
        None => panic!("approved SessionPublicKeyId declaration is missing"),
    };
    let tail = &source[start..];
    let end = match tail.find("/// A versioned protocol identifier.") {
        Some(index) => index,
        None => panic!("SessionPublicKeyId block has no stable end marker"),
    };
    let production = tail[..end]
        .lines()
        .filter(|line| !line.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(production.contains(
        "#[derive(Clone, Copy, PartialEq, Eq, Hash)]\n\
         pub struct SessionPublicKeyId([u8; SESSION_PUBLIC_KEY_ID_LENGTH]);"
    ));
    assert!(
        production
            .contains("pub const fn from_bytes(bytes: [u8; SESSION_PUBLIC_KEY_ID_LENGTH]) -> Self")
    );
    assert!(
        production.contains("pub const fn as_bytes(&self) -> &[u8; SESSION_PUBLIC_KEY_ID_LENGTH]")
    );
    assert_eq!(production.matches("pub const fn ").count(), 2);
    assert_eq!(production.matches("pub fn ").count(), 0);
    assert!(production.contains("formatter.write_str(\"SessionPublicKeyId([REDACTED; 32])\")"));

    for forbidden in [
        "pub struct SessionPublicKeyId(pub ",
        "pub type SessionPublicKeyId",
        "impl Default for SessionPublicKeyId",
        "impl fmt::Display for SessionPublicKeyId",
        "impl From<",
        "impl Into<",
        "impl TryFrom<",
        "impl TryInto<",
        "impl std::convert::From<",
        "impl std::convert::Into<",
        "impl std::convert::TryFrom<",
        "impl std::convert::TryInto<",
        "impl AsRef<",
        "impl std::str::FromStr",
        "Serialize",
        "Deserialize",
        "as_bytes_mut",
        "serialize",
        "generate",
        "is_valid",
        "authorize",
        "verified_attestation",
        "validated_permit",
        "proof_of_possession",
        "admit",
        "impl PartialOrd",
        "impl Ord",
        "Decision",
        "ReasonCode",
        "VerifiedAttestation",
        "Permit",
        "Proof",
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden public surface appeared: {forbidden:?}"
        );
    }
}
