// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! Bounded protocol framing primitives.

use std::error::Error;
use std::fmt;

pub use ogir_model::{EvidenceProfile, ProtocolVersion};

/// Maximum accepted local frame size for the research protocol.
pub const MAX_FRAME_LENGTH: usize = 1024 * 1024;

/// Opaque experimental evidence envelope. The production encoding is not frozen.
///
/// Both the local agent and remote verifier depend on this protocol-owned type;
/// the verifier must not depend on implementation details of the local agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceBundle {
    /// Evidence profile identifier.
    pub profile_id: EvidenceProfile,
    /// Encoded payload owned by the selected attestation profile.
    pub payload: Vec<u8>,
}

/// Research protocol message kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageKind {
    /// Begin a protected-session request.
    BeginSession = 1,
    /// Request session renewal.
    RenewSession = 2,
    /// End a protected session.
    EndSession = 3,
    /// Return a bounded response.
    Response = 4,
}

/// A normalized frame header. Encoding is intentionally not frozen yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Protocol version.
    pub version: ProtocolVersion,
    /// Message kind.
    pub kind: MessageKind,
    /// Payload length in bytes.
    pub payload_length: usize,
}

impl FrameHeader {
    /// Validates the research frame's bounded-length invariant.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.payload_length > MAX_FRAME_LENGTH {
            return Err(ProtocolError::FrameTooLarge {
                length: self.payload_length,
                maximum: MAX_FRAME_LENGTH,
            });
        }

        Ok(())
    }
}

/// Protocol framing error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// The message exceeded the configured bound.
    FrameTooLarge { length: usize, maximum: usize },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { length, maximum } => {
                write!(formatter, "frame length {length} exceeds maximum {maximum}")
            }
        }
    }
}

impl Error for ProtocolError {}

#[cfg(test)]
mod tests {
    use super::{FrameHeader, MAX_FRAME_LENGTH, MessageKind, ProtocolError};
    use ogir_model::ProtocolVersion;

    #[test]
    fn maximum_sized_frame_is_accepted() {
        let header = FrameHeader {
            version: ProtocolVersion { major: 0, minor: 1 },
            kind: MessageKind::BeginSession,
            payload_length: MAX_FRAME_LENGTH,
        };
        assert_eq!(header.validate(), Ok(()));
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let header = FrameHeader {
            version: ProtocolVersion { major: 0, minor: 1 },
            kind: MessageKind::BeginSession,
            payload_length: MAX_FRAME_LENGTH + 1,
        };
        assert_eq!(
            header.validate(),
            Err(ProtocolError::FrameTooLarge {
                length: MAX_FRAME_LENGTH + 1,
                maximum: MAX_FRAME_LENGTH,
            })
        );
    }
}
