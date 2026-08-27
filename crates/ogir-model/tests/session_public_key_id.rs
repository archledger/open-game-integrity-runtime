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
