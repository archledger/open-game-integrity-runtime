// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! Pure domain types and invariants for OGIR.

use std::error::Error;
use std::fmt;

/// Protocol nonce length in bytes.
pub const NONCE_LENGTH: usize = 32;
/// Maximum length for externally visible identifiers.
pub const MAX_IDENTIFIER_LENGTH: usize = 128;

/// Failure to construct a canonical OGIR identifier.
///
/// Errors intentionally report only a byte position or public limit, never the
/// rejected value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierError {
    /// The identifier had no bytes.
    Empty,
    /// The identifier exceeded its byte-length limit.
    TooLong {
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// The identifier contained a byte outside lowercase ASCII, digits, `.`, and `-`.
    InvalidCharacter {
        /// Zero-based byte index of the first invalid byte.
        index: usize,
    },
    /// A separator was leading, trailing, or adjacent to another separator.
    InvalidSeparator {
        /// Zero-based byte index of the invalid separator.
        index: usize,
    },
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("identifier is empty"),
            Self::TooLong { maximum } => {
                write!(formatter, "identifier exceeds {maximum} bytes")
            }
            Self::InvalidCharacter { index } => {
                write!(formatter, "identifier has an invalid byte at index {index}")
            }
            Self::InvalidSeparator { index } => {
                write!(
                    formatter,
                    "identifier has an invalid separator at index {index}"
                )
            }
        }
    }
}

impl Error for IdentifierError {}

fn validate_canonical_identifier(value: &str) -> Result<(), IdentifierError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return Err(IdentifierError::Empty);
    }
    if bytes.len() > MAX_IDENTIFIER_LENGTH {
        return Err(IdentifierError::TooLong {
            maximum: MAX_IDENTIFIER_LENGTH,
        });
    }

    let mut previous_was_separator = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            previous_was_separator = false;
            continue;
        }

        if matches!(byte, b'.' | b'-') {
            if index == 0 || index + 1 == bytes.len() || previous_was_separator {
                return Err(IdentifierError::InvalidSeparator { index });
            }
            previous_was_separator = true;
            continue;
        }

        return Err(IdentifierError::InvalidCharacter { index });
    }

    Ok(())
}

macro_rules! define_identifier {
    ($(#[$metadata:meta])* $name:ident, redacted = $redacted:literal) => {
        $(#[$metadata])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Validates and copies a canonical identifier.
            pub fn new(value: &str) -> Result<Self, IdentifierError> {
                validate_canonical_identifier(value)?;
                Ok(Self(value.to_owned()))
            }

            /// Returns the canonical identifier text.
            #[must_use]
            pub const fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl TryFrom<&str> for $name {
            type Error = IdentifierError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl std::str::FromStr for $name {
            type Err = IdentifierError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                if $redacted {
                    formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
                } else {
                    formatter
                        .debug_tuple(stringify!($name))
                        .field(&self.0)
                        .finish()
                }
            }
        }
    };
}

define_identifier!(
    /// Publisher namespace selected by the relying party.
    PublisherId,
    redacted = false
);
define_identifier!(
    /// Game namespace within a publisher.
    GameId,
    redacted = false
);
define_identifier!(
    /// Exact game-build identifier.
    BuildId,
    redacted = false
);
define_identifier!(
    /// Publisher-scoped account binding.
    AccountScope,
    redacted = true
);
define_identifier!(
    /// Match or protected-session namespace from the relying party.
    MatchId,
    redacted = true
);
define_identifier!(
    /// Publisher policy identifier.
    PolicyId,
    redacted = false
);
define_identifier!(
    /// Locally established protected-session identifier.
    SessionId,
    redacted = true
);
define_identifier!(
    /// Attestation evidence-profile identifier.
    EvidenceProfile,
    redacted = false
);

/// Version of a publisher policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersion(u32);

impl PolicyVersion {
    /// Creates a typed policy version without assigning protocol semantics to zero.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric policy version.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for PolicyVersion {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

/// A fixed-size publisher challenge nonce.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce([u8; NONCE_LENGTH]);

impl Nonce {
    /// Creates a nonce from exactly 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Nonce([REDACTED; 32])")
    }
}

/// A versioned protocol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolVersion {
    /// Breaking protocol generation.
    pub major: u16,
    /// Backwards-compatible protocol revision.
    pub minor: u16,
}

/// A publisher-issued challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherChallenge {
    /// Protocol version selected by the publisher.
    pub version: ProtocolVersion,
    /// Publisher-scoped identifier.
    pub publisher_id: String,
    /// Game identifier.
    pub game_id: String,
    /// Exact game build identifier.
    pub build_id: String,
    /// Publisher-scoped account binding.
    pub account_scope: String,
    /// Match or protected-session identifier.
    pub match_id: String,
    /// Requested policy identifier.
    pub policy_id: String,
    /// Requested policy version.
    pub policy_version: u32,
    /// Fresh random challenge.
    pub nonce: Nonce,
    /// Challenge issue time as Unix seconds.
    pub issued_at_unix_seconds: u64,
    /// Challenge expiry as Unix seconds.
    pub expires_at_unix_seconds: u64,
}

impl PublisherChallenge {
    /// Validates local structural invariants. Signature and freshness checks belong to the verifier.
    pub fn validate_structure(&self) -> Result<(), ModelError> {
        validate_identifier("publisher_id", &self.publisher_id)?;
        validate_identifier("game_id", &self.game_id)?;
        validate_identifier("build_id", &self.build_id)?;
        validate_identifier("account_scope", &self.account_scope)?;
        validate_identifier("match_id", &self.match_id)?;
        validate_identifier("policy_id", &self.policy_id)?;

        if self.expires_at_unix_seconds <= self.issued_at_unix_seconds {
            return Err(ModelError::InvalidTimeWindow);
        }

        Ok(())
    }
}

/// High-level verifier decision. This type is produced only by verifier logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Requested protected mode is permitted.
    Allow,
    /// A lower-assurance mode may be offered.
    AllowRestricted,
    /// The requested policy was not satisfied.
    Deny,
    /// The platform or evidence profile is not supported.
    Unsupported,
    /// A transient failure may be retried.
    Retry,
}

/// Non-disciplinary result reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    /// No failure occurred.
    None,
    /// Input was malformed.
    Malformed,
    /// A protocol or profile version is unsupported.
    UnsupportedVersion,
    /// Challenge or result is not yet valid.
    NotYetValid,
    /// Challenge or result expired.
    Expired,
    /// A nonce or permit was reused.
    ReplayDetected,
    /// Caller or session identity did not match.
    SessionBindingMismatch,
    /// Evidence could not be validated.
    EvidenceInvalid,
    /// The requested policy was not satisfied.
    PolicyDenied,
    /// A component or key was revoked.
    Revoked,
    /// Required local service or hardware was unavailable.
    AttestationUnavailable,
    /// Required protected-session state was lost.
    ProtectedSessionLost,
}

/// Errors in pure model validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    /// An identifier was empty.
    EmptyIdentifier { field: &'static str },
    /// An identifier exceeded the configured maximum.
    IdentifierTooLong { field: &'static str },
    /// An identifier contained a disallowed byte.
    InvalidIdentifierCharacter { field: &'static str },
    /// Expiry was not after issue time.
    InvalidTimeWindow,
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentifier { field } => write!(formatter, "{field} is empty"),
            Self::IdentifierTooLong { field } => write!(formatter, "{field} is too long"),
            Self::InvalidIdentifierCharacter { field } => {
                write!(formatter, "{field} contains a disallowed character")
            }
            Self::InvalidTimeWindow => {
                formatter.write_str("challenge expiry must be after issue time")
            }
        }
    }
}

impl Error for ModelError {}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::EmptyIdentifier { field });
    }

    if value.len() > MAX_IDENTIFIER_LENGTH {
        return Err(ModelError::IdentifierTooLong { field });
    }

    let valid = value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    });

    if !valid {
        return Err(ModelError::InvalidIdentifierCharacter { field });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ModelError, Nonce, ProtocolVersion, PublisherChallenge};

    fn valid_challenge() -> PublisherChallenge {
        PublisherChallenge {
            version: ProtocolVersion { major: 0, minor: 1 },
            publisher_id: "example.publisher".to_owned(),
            game_id: "example.game".to_owned(),
            build_id: "build-1".to_owned(),
            account_scope: "account-123".to_owned(),
            match_id: "match-456".to_owned(),
            policy_id: "research-v0".to_owned(),
            policy_version: 1,
            nonce: Nonce::from_bytes([7; 32]),
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
        }
    }

    #[test]
    fn valid_challenge_passes_structure_validation() {
        assert_eq!(valid_challenge().validate_structure(), Ok(()));
    }

    #[test]
    fn invalid_time_window_is_rejected() {
        let mut challenge = valid_challenge();
        challenge.expires_at_unix_seconds = challenge.issued_at_unix_seconds;
        assert_eq!(
            challenge.validate_structure(),
            Err(ModelError::InvalidTimeWindow)
        );
    }

    #[test]
    fn debug_output_redacts_nonce_bytes() {
        let nonce = Nonce::from_bytes([0xAA; 32]);
        assert_eq!(format!("{nonce:?}"), "Nonce([REDACTED; 32])");
    }
}
