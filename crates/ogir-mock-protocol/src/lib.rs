// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! TEST-ONLY transcript encoding, framing, and signed mock objects.
//!
//! This crate implements ADR-0015 for the M2 mock protocol. The encoding
//! is a parallel test-only format that production will never use; every
//! file carrying it is test-only. Objects are a fixed ASCII domain tag, a
//! canonical record sequence, and (for signed classes) a 32-byte
//! authenticator trailer. Validation of one class under another class's
//! tag fails before any record is read. Full contract:
//! [ADR-0015](../../docs/adr/0015-mock-binding-transcript-encoding.md).

pub mod admission;
pub mod attest;
pub mod frame;
pub mod objects;
pub mod policy;
pub mod renewal;
pub mod service;
pub mod transcript;

/// Test-only transcript encoding and verification failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptError {
    /// The bytes do not start with the expected domain tag.
    TagMismatch,
    /// Input ended inside the tag, a record header, or a record value.
    Truncated,
    /// A record id repeated within one object, including equal values.
    DuplicateField {
        /// The repeated field id.
        id: u16,
    },
    /// A record id outside the class's frozen registry (fail closed,
    /// including reserved extension ids in M2).
    UnknownField {
        /// The unregistered field id.
        id: u16,
    },
    /// Record ids were not strictly ascending.
    OutOfOrder {
        /// The first out-of-order field id.
        id: u16,
    },
    /// A record value failed its per-field length invariant.
    BadFieldLength {
        /// The field id whose value had an invalid length.
        id: u16,
    },
    /// A required field of the class was absent.
    MissingField {
        /// The absent field id.
        id: u16,
    },
    /// The whole object exceeds the bounded size.
    ObjectTooLarge,
    /// A semantic ordering invariant failed (issue before expiry, or
    /// collection start after snapshot-freeze end).
    InvalidWindow,
    /// The key id named no registered key.
    UnknownKey,
    /// The trailing authenticator did not verify.
    AuthenticationFailed,
    /// Frame-layer failures.
    Frame(FrameError),
}

impl std::fmt::Display for TranscriptError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TagMismatch => formatter.write_str("object does not carry the expected tag"),
            Self::Truncated => formatter.write_str("object ended mid-field"),
            Self::DuplicateField { id } => write!(formatter, "field {id:#06x} repeats"),
            Self::UnknownField { id } => write!(formatter, "field {id:#06x} is not registered"),
            Self::OutOfOrder { id } => write!(formatter, "field {id:#06x} breaks canonical order"),
            Self::BadFieldLength { id } => {
                write!(formatter, "field {id:#06x} has an invalid value length")
            }
            Self::MissingField { id } => write!(formatter, "required field {id:#06x} is absent"),
            Self::ObjectTooLarge => formatter.write_str("object exceeds the bounded size"),
            Self::InvalidWindow => formatter.write_str("temporal ordering invariant violated"),
            Self::UnknownKey => formatter.write_str("key id names no registered mock key"),
            Self::AuthenticationFailed => formatter.write_str("authenticator rejected"),
            Self::Frame(error) => write!(formatter, "frame rejected: {error}"),
        }
    }
}

impl std::error::Error for TranscriptError {}

/// Frame-layer rejection reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer bytes than the fixed frame header.
    TooSmall,
    /// The magic value is not `OGIR`.
    BadMagic,
    /// Reserved header bytes were nonzero.
    ReservedNotZero,
    /// The kind value maps to no allocated message kind.
    UnknownKind {
        /// The rejected raw kind value.
        kind: u16,
    },
    /// The payload exceeds the frame bound.
    PayloadTooLarge,
    /// The frame did not carry exactly header plus declared payload.
    LengthMismatch,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooSmall => formatter.write_str("frame is smaller than the fixed header"),
            Self::BadMagic => formatter.write_str("frame magic is not OGIR"),
            Self::ReservedNotZero => formatter.write_str("reserved frame bytes are nonzero"),
            Self::UnknownKind { kind } => {
                write!(formatter, "message kind {kind} is not allocated")
            }
            Self::PayloadTooLarge => formatter.write_str("payload exceeds the frame bound"),
            Self::LengthMismatch => {
                formatter.write_str("frame length does not match the declared payload")
            }
        }
    }
}

impl std::error::Error for FrameError {}

impl From<FrameError> for TranscriptError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}
