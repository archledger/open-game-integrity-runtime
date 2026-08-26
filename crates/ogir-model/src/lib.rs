// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! Pure domain types and invariants for OGIR.
//!
//! # Canonical identifier profile
//!
//! Text identifiers contain 1 to 128 UTF-8 bytes, but accepted bytes are
//! deliberately restricted to lowercase ASCII letters, ASCII digits, and the
//! `.` or `-` separators. A separator must occur between two alphanumeric
//! bytes; leading, trailing, and adjacent separators are rejected. Inputs are
//! never trimmed, case-folded, or otherwise normalized: noncanonical text is
//! rejected at construction and callers retain exactly one representation.
//!
//! Distinct newtypes follow the Rust API Guidelines' recommendations for
//! [static distinctions][newtype] and [boundary validation][validation]. The
//! deliberately narrow character profile avoids Unicode equivalence and
//! confusable-identifier behavior; Unicode UTS #39 permits implementations to
//! define a tighter application profile and document its exceptions.
//!
//! Authorization-binding and local-session identifiers redact their values
//! from [`Debug`](std::fmt::Debug). Code that genuinely needs canonical text
//! must request it explicitly through `as_str` or [`AsRef<str>`]; that explicit
//! access is functional trusted-core input and must not be copied to diagnostics.
//!
//! [newtype]: https://rust-lang.github.io/api-guidelines/type-safety.html#newtypes-provide-static-distinctions-c-newtype
//! [validation]: https://rust-lang.github.io/api-guidelines/dependability.html#functions-validate-their-arguments-c-validate
//! [Unicode UTS #39]: https://www.unicode.org/reports/tr39/#Identifier_Characters

use std::error::Error;
use std::fmt;

mod freshness;

pub use freshness::{
    ChallengeLifetime, ChallengeWindow, FreshnessError, FreshnessLimits, UnixTime,
};

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
    ///
    /// A publisher identifier cannot be substituted for another identifier type:
    ///
    /// ```compile_fail
    /// use ogir_model::{GameId, PublisherId};
    ///
    /// fn needs_game_id(_: GameId) {}
    ///
    /// let publisher_id = match PublisherId::try_from("example.publisher") {
    ///     Ok(value) => value,
    ///     Err(error) => panic!("unexpected error: {error}"),
    /// };
    /// needs_game_id(publisher_id);
    /// ```
    PublisherId,
    redacted = true
);
define_identifier!(
    /// Game namespace within a publisher.
    GameId,
    redacted = true
);
define_identifier!(
    /// Exact game-build identifier.
    BuildId,
    redacted = true
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
    redacted = true
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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersion(u32);

impl fmt::Debug for PolicyVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PolicyVersion([REDACTED])")
    }
}

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
#[derive(Clone, PartialEq, Eq)]
pub struct PublisherChallenge {
    /// Protocol version selected by the publisher.
    pub version: ProtocolVersion,
    /// Publisher-scoped identifier.
    pub publisher_id: PublisherId,
    /// Game identifier.
    pub game_id: GameId,
    /// Exact game build identifier.
    pub build_id: BuildId,
    /// Publisher-scoped account binding.
    pub account_scope: AccountScope,
    /// Match or protected-session identifier.
    pub match_id: MatchId,
    /// Requested policy identifier.
    pub policy_id: PolicyId,
    /// Requested policy version.
    pub policy_version: PolicyVersion,
    /// Fresh random challenge.
    pub nonce: Nonce,
    /// Validated challenge issue/expiry interval.
    pub window: ChallengeWindow,
}

impl fmt::Debug for PublisherChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublisherChallenge([REDACTED])")
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

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::num::NonZeroU64;

    use super::{
        AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, GameId, IdentifierError,
        MatchId, Nonce, PolicyId, PolicyVersion, ProtocolVersion, PublisherChallenge, PublisherId,
        UnixTime,
    };

    fn identifier<T>(value: &str) -> T
    where
        T: Debug,
        for<'a> T: TryFrom<&'a str, Error = IdentifierError>,
    {
        match T::try_from(value) {
            Ok(identifier) => identifier,
            Err(error) => panic!("valid fixture rejected: {error:?}"),
        }
    }

    fn valid_challenge() -> PublisherChallenge {
        let maximum = match NonZeroU64::new(100) {
            Some(value) => ChallengeLifetime::new(value),
            None => panic!("fixture lifetime must be nonzero"),
        };
        let window = match ChallengeWindow::new(UnixTime::new(100), UnixTime::new(200), maximum) {
            Ok(value) => value,
            Err(error) => panic!("valid fixture window rejected: {error:?}"),
        };
        PublisherChallenge {
            version: ProtocolVersion { major: 0, minor: 1 },
            publisher_id: identifier::<PublisherId>("example.publisher"),
            game_id: identifier::<GameId>("example.game"),
            build_id: identifier::<BuildId>("build-1"),
            account_scope: identifier::<AccountScope>("account-123"),
            match_id: identifier::<MatchId>("match-456"),
            policy_id: identifier::<PolicyId>("research-v0"),
            policy_version: PolicyVersion::new(1),
            nonce: Nonce::from_bytes([7; 32]),
            window,
        }
    }

    #[test]
    fn publisher_challenge_carries_a_validated_window() {
        assert_eq!(
            valid_challenge().window.evaluate(UnixTime::new(150)),
            Ok(())
        );
    }

    #[test]
    fn debug_output_redacts_nonce_bytes() {
        let nonce = Nonce::from_bytes([0xAA; 32]);
        assert_eq!(format!("{nonce:?}"), "Nonce([REDACTED; 32])");
    }
}
