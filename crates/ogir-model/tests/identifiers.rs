// SPDX-License-Identifier: Apache-2.0

use std::any::TypeId;
use std::fmt::Debug;
use std::num::NonZeroU64;

use ogir_model::{
    AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, EvidenceProfile, GameId,
    IdentifierError, MAX_IDENTIFIER_LENGTH, MatchId, Nonce, PolicyId, PolicyVersion,
    ProtocolVersion, PublisherChallenge, PublisherId, SessionId, UnixTime,
};

const EXPECTED_MAX_IDENTIFIER_LENGTH: usize = 128;

fn parse_identifier<T>(value: &str) -> T
where
    T: AsRef<str> + Debug,
    for<'a> T: TryFrom<&'a str, Error = IdentifierError>,
{
    match T::try_from(value) {
        Ok(identifier) => identifier,
        Err(error) => panic!("expected {value:?} to be valid, got {error:?}"),
    }
}

fn assert_valid_identifier<T>(value: &str)
where
    T: AsRef<str> + Debug,
    for<'a> T: TryFrom<&'a str, Error = IdentifierError>,
{
    let identifier = parse_identifier::<T>(value);
    assert_eq!(identifier.as_ref(), value);
}

fn reference_is_canonical(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > EXPECTED_MAX_IDENTIFIER_LENGTH {
        return false;
    }

    let mut previous_was_separator = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let is_atom = byte.is_ascii_lowercase() || byte.is_ascii_digit();
        let is_separator = matches!(byte, b'.' | b'-');
        if !is_atom && !is_separator {
            return false;
        }
        if is_separator && (index == 0 || index + 1 == bytes.len() || previous_was_separator) {
            return false;
        }
        previous_was_separator = is_separator;
    }

    true
}

#[test]
fn every_text_identifier_type_preserves_canonical_input() {
    assert_valid_identifier::<PublisherId>("example.publisher");
    assert_valid_identifier::<GameId>("example.game");
    assert_valid_identifier::<BuildId>("build-1");
    assert_valid_identifier::<AccountScope>("account-1");
    assert_valid_identifier::<MatchId>("match-1");
    assert_valid_identifier::<PolicyId>("research-v0");
    assert_valid_identifier::<SessionId>("session-1");
    assert_valid_identifier::<EvidenceProfile>("mock-v0");
}

#[test]
fn empty_and_overlong_identifiers_are_rejected_at_byte_boundaries() {
    assert_eq!(MAX_IDENTIFIER_LENGTH, EXPECTED_MAX_IDENTIFIER_LENGTH);
    assert_eq!(PublisherId::try_from(""), Err(IdentifierError::Empty));

    let maximum = "a".repeat(EXPECTED_MAX_IDENTIFIER_LENGTH);
    assert_valid_identifier::<PublisherId>(&maximum);

    let overlong = "a".repeat(EXPECTED_MAX_IDENTIFIER_LENGTH + 1);
    assert_eq!(
        PublisherId::try_from(overlong.as_str()),
        Err(IdentifierError::TooLong {
            maximum: EXPECTED_MAX_IDENTIFIER_LENGTH,
        })
    );
}

#[test]
fn noncanonical_characters_and_separator_confusion_are_rejected() {
    let cases = [
        ("Upper", IdentifierError::InvalidCharacter { index: 0 }),
        ("é", IdentifierError::InvalidCharacter { index: 0 }),
        ("a b", IdentifierError::InvalidCharacter { index: 1 }),
        ("a/b", IdentifierError::InvalidCharacter { index: 1 }),
        ("a:b", IdentifierError::InvalidCharacter { index: 1 }),
        ("a\\b", IdentifierError::InvalidCharacter { index: 1 }),
        ("a_b", IdentifierError::InvalidCharacter { index: 1 }),
        ("a\0b", IdentifierError::InvalidCharacter { index: 1 }),
        (".a", IdentifierError::InvalidSeparator { index: 0 }),
        ("a.", IdentifierError::InvalidSeparator { index: 1 }),
        ("a..b", IdentifierError::InvalidSeparator { index: 2 }),
        ("a.-b", IdentifierError::InvalidSeparator { index: 2 }),
    ];

    for (value, expected) in cases {
        assert_eq!(PublisherId::try_from(value), Err(expected), "{value:?}");
    }
}

#[test]
fn deterministic_arbitrary_strings_match_the_canonical_grammar() {
    const ALPHABET: [char; 13] = [
        'a', 'z', '0', '9', '.', '-', '_', '/', ':', '@', 'A', '\0', 'é',
    ];
    let mut state = 0x4f47_4952_4d31_3037_u64;

    for _ in 0..8_192 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let length = (state as usize) % (EXPECTED_MAX_IDENTIFIER_LENGTH + 13);
        let mut candidate = String::new();
        for _ in 0..length {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            candidate.push(ALPHABET[(state as usize) % ALPHABET.len()]);
        }

        let expected = reference_is_canonical(&candidate);
        let actual = PublisherId::try_from(candidate.as_str());
        assert_eq!(
            actual.is_ok(),
            expected,
            "candidate bytes: {:?}",
            candidate.as_bytes()
        );
        if let Ok(identifier) = actual {
            assert_eq!(identifier.as_ref(), candidate);
        }
    }
}

#[test]
fn every_ascii_byte_and_representative_unicode_scalar_matches_the_profile() {
    for byte in 0_u8..=127 {
        let candidate = format!("a{}b", char::from(byte));
        let expected =
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-');
        assert_eq!(
            PublisherId::try_from(candidate.as_str()).is_ok(),
            expected,
            "ASCII byte: {byte}"
        );
    }

    for character in ['é', 'α', 'а', '中', '\u{200b}', '\u{200d}'] {
        let candidate = format!("a{character}b");
        assert_eq!(
            PublisherId::try_from(candidate.as_str()),
            Err(IdentifierError::InvalidCharacter { index: 1 }),
            "Unicode scalar: U+{:04X}",
            u32::from(character)
        );
    }

    for first in ['.', '-'] {
        for second in ['.', '-'] {
            let candidate = format!("a{first}{second}b");
            assert_eq!(
                PublisherId::try_from(candidate.as_str()),
                Err(IdentifierError::InvalidSeparator { index: 2 }),
                "separator transition: {first}{second}"
            );
        }
    }
}

#[test]
fn every_identifier_type_has_a_distinct_runtime_type_identity() {
    let types = [
        ("PublisherId", TypeId::of::<PublisherId>()),
        ("GameId", TypeId::of::<GameId>()),
        ("BuildId", TypeId::of::<BuildId>()),
        ("AccountScope", TypeId::of::<AccountScope>()),
        ("MatchId", TypeId::of::<MatchId>()),
        ("PolicyId", TypeId::of::<PolicyId>()),
        ("SessionId", TypeId::of::<SessionId>()),
        ("EvidenceProfile", TypeId::of::<EvidenceProfile>()),
        ("PolicyVersion", TypeId::of::<PolicyVersion>()),
    ];

    for (index, (left_name, left_type)) in types.iter().enumerate() {
        for (right_name, right_type) in &types[index + 1..] {
            assert_ne!(
                left_type, right_type,
                "{left_name} and {right_name} must remain distinct"
            );
        }
    }
}

#[test]
fn privacy_sensitive_debug_output_is_redacted() {
    let publisher = parse_identifier::<PublisherId>("private.publisher");
    let game = parse_identifier::<GameId>("private.game");
    let build = parse_identifier::<BuildId>("private-build");
    let account = match AccountScope::try_from("private-account") {
        Ok(value) => value,
        Err(error) => panic!("valid account scope rejected: {error:?}"),
    };
    let match_id = match MatchId::try_from("private-match") {
        Ok(value) => value,
        Err(error) => panic!("valid match id rejected: {error:?}"),
    };
    let session = match SessionId::try_from("private-session") {
        Ok(value) => value,
        Err(error) => panic!("valid session id rejected: {error:?}"),
    };
    let policy = parse_identifier::<PolicyId>("private-policy");
    let policy_version = PolicyVersion::new(424_242);
    let maximum = match NonZeroU64::new(100) {
        Some(value) => ChallengeLifetime::new(value),
        None => panic!("fixture lifetime must be nonzero"),
    };
    let window =
        match ChallengeWindow::new(UnixTime::new(4_242_400), UnixTime::new(4_242_499), maximum) {
            Ok(value) => value,
            Err(error) => panic!("valid fixture window rejected: {error:?}"),
        };

    assert_eq!(format!("{publisher:?}"), "PublisherId([REDACTED])");
    assert_eq!(format!("{game:?}"), "GameId([REDACTED])");
    assert_eq!(format!("{build:?}"), "BuildId([REDACTED])");
    assert_eq!(format!("{account:?}"), "AccountScope([REDACTED])");
    assert_eq!(format!("{match_id:?}"), "MatchId([REDACTED])");
    assert_eq!(format!("{session:?}"), "SessionId([REDACTED])");
    assert_eq!(format!("{policy:?}"), "PolicyId([REDACTED])");
    assert_eq!(format!("{policy_version:?}"), "PolicyVersion([REDACTED])");
    assert_eq!(format!("{:?}", window.issued_at()), "UnixTime([REDACTED])");
    assert_eq!(format!("{window:?}"), "ChallengeWindow([REDACTED])");
}

#[test]
fn validation_errors_never_echo_hostile_input() {
    let hostile = "private/account";
    let error = match AccountScope::try_from(hostile) {
        Ok(_) => panic!("hostile identifier unexpectedly accepted"),
        Err(error) => error,
    };

    assert!(!format!("{error}").contains(hostile));
    assert!(!format!("{error:?}").contains(hostile));
}

#[test]
fn policy_version_preserves_its_numeric_value() {
    let version = PolicyVersion::new(0);
    assert_eq!(version.get(), 0);
}

#[test]
fn publisher_challenge_uses_typed_ids_and_redacts_complete_binding() {
    let maximum = match NonZeroU64::new(100) {
        Some(value) => ChallengeLifetime::new(value),
        None => panic!("fixture lifetime must be nonzero"),
    };
    let window = match ChallengeWindow::new(UnixTime::new(100), UnixTime::new(200), maximum) {
        Ok(value) => value,
        Err(error) => panic!("valid fixture window rejected: {error:?}"),
    };
    let challenge = PublisherChallenge {
        version: ProtocolVersion { major: 0, minor: 1 },
        publisher_id: parse_identifier::<PublisherId>("example.publisher"),
        game_id: parse_identifier::<GameId>("example.game"),
        build_id: parse_identifier::<BuildId>("build-1"),
        account_scope: parse_identifier::<AccountScope>("private-account"),
        match_id: parse_identifier::<MatchId>("private-match"),
        policy_id: parse_identifier::<PolicyId>("research-v0"),
        policy_version: PolicyVersion::new(1),
        nonce: Nonce::from_bytes([7; 32]),
        window,
    };

    assert_eq!(challenge.window.evaluate(UnixTime::new(150)), Ok(()));
    let debug = format!("{challenge:?}");
    assert_eq!(debug, "PublisherChallenge([REDACTED])");
}
