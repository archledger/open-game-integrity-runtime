// SPDX-License-Identifier: Apache-2.0

//! Test-only mock frame header (M2-017 layout per the M2-016 design).
//!
//! Fixed 16-byte header: magic `OGIR`, protocol major/minor (u16 each,
//! big-endian), message kind (u16), two reserved zero bytes, payload
//! length (u32). Unknown kinds reject before the payload is read; this is
//! the structural home of the protocol-downgrade attack surface. The wire
//! encoding stays test-only and unfrozen for production.

use ogir_model::ProtocolVersion;
use ogir_protocol::MessageKind;

use crate::{FrameError, TranscriptError};

/// Fixed mock frame header length in bytes.
pub const FRAME_HEADER_LENGTH: usize = 16;

/// Mock frame magic.
pub const FRAME_MAGIC: [u8; 4] = *b"OGIR";

/// Maximum mock payload, aligned with `MAX_FRAME_LENGTH`.
pub const MAX_PAYLOAD_LENGTH: usize = 1024 * 1024;

/// A parsed mock frame. Payload bytes stay opaque at this layer.
#[derive(Clone, PartialEq, Eq)]
pub struct MockFrame {
    /// Protocol version carried by the frame.
    pub version: ProtocolVersion,
    /// Allocated message kind.
    pub kind: MessageKind,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for MockFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MockFrame([PAYLOAD REDACTED])")
    }
}

/// Encodes header plus payload.
pub fn encode_frame(
    version: ProtocolVersion,
    kind: MessageKind,
    payload: &[u8],
) -> Result<Vec<u8>, TranscriptError> {
    if payload.len() > MAX_PAYLOAD_LENGTH {
        return Err(FrameError::PayloadTooLarge.into());
    }
    let mut bytes = Vec::with_capacity(FRAME_HEADER_LENGTH + payload.len());
    bytes.extend_from_slice(&FRAME_MAGIC);
    bytes.extend_from_slice(&version.major.to_be_bytes());
    bytes.extend_from_slice(&version.minor.to_be_bytes());
    bytes.extend_from_slice(&(kind as u16).to_be_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// Validates and parses a frame, rejecting unknown kinds before payload
/// interpretation.
pub fn parse_frame(bytes: &[u8]) -> Result<MockFrame, TranscriptError> {
    if bytes.len() < FRAME_HEADER_LENGTH {
        return Err(FrameError::TooSmall.into());
    }
    if bytes[..4] != FRAME_MAGIC {
        return Err(FrameError::BadMagic.into());
    }
    if bytes[10] != 0 || bytes[11] != 0 {
        return Err(FrameError::ReservedNotZero.into());
    }
    let kind = u16::from_be_bytes([bytes[8], bytes[9]]);
    let kind = match MessageKind::from_u16(kind) {
        Some(kind) => kind,
        None => return Err(FrameError::UnknownKind { kind }.into()),
    };
    let payload_length = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    if payload_length > MAX_PAYLOAD_LENGTH {
        return Err(FrameError::PayloadTooLarge.into());
    }
    if bytes.len() != FRAME_HEADER_LENGTH + payload_length {
        return Err(FrameError::LengthMismatch.into());
    }
    Ok(MockFrame {
        version: ProtocolVersion {
            major: u16::from_be_bytes([bytes[4], bytes[5]]),
            minor: u16::from_be_bytes([bytes[6], bytes[7]]),
        },
        kind,
        payload: bytes[FRAME_HEADER_LENGTH..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_for_every_mock_kind() {
        for kind in [
            MessageKind::BeginSession,
            MessageKind::RenewSession,
            MessageKind::EndSession,
            MessageKind::Response,
            MessageKind::MockChallenge,
            MessageKind::MockEvidence,
            MessageKind::MockPermit,
            MessageKind::MockProofOfPossession,
        ] {
            let version = ProtocolVersion { major: 0, minor: 1 };
            let bytes = encode_frame(version, kind, b"payload")
                .unwrap_or_else(|error| panic!("encode: {error:?}"));
            let frame = parse_frame(&bytes).unwrap_or_else(|error| panic!("parse: {error:?}"));
            assert_eq!(frame.version, version);
            assert_eq!(frame.kind, kind);
            assert_eq!(frame.payload, b"payload");
        }
    }

    #[test]
    fn bad_magic_truncated_reserved_and_length_rejected() {
        let version = ProtocolVersion { major: 0, minor: 1 };
        let bytes = encode_frame(version, MessageKind::MockPermit, b"abc")
            .unwrap_or_else(|error| panic!("encode: {error:?}"));
        assert_eq!(
            parse_frame(&bytes[..15]),
            Err(TranscriptError::Frame(FrameError::TooSmall))
        );
        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            parse_frame(&bad_magic),
            Err(TranscriptError::Frame(FrameError::BadMagic))
        );
        let mut reserved = bytes.clone();
        reserved[10] = 1;
        assert_eq!(
            parse_frame(&reserved),
            Err(TranscriptError::Frame(FrameError::ReservedNotZero))
        );
        assert_eq!(
            parse_frame(&bytes[..bytes.len() - 1]),
            Err(TranscriptError::Frame(FrameError::LengthMismatch))
        );
    }

    #[test]
    fn unknown_kind_rejected_before_payload_read() {
        let version = ProtocolVersion { major: 0, minor: 1 };
        let mut bytes = encode_frame(version, MessageKind::MockPermit, b"abc")
            .unwrap_or_else(|error| panic!("encode: {error:?}"));
        bytes[8] = 0x00;
        bytes[9] = 0x40; // kind 64: rejected until allocated
        assert_eq!(
            parse_frame(&bytes),
            Err(TranscriptError::Frame(FrameError::UnknownKind { kind: 64 }))
        );
        bytes[9] = 0x09; // kind 9: reserved for later mock work
        assert_eq!(
            parse_frame(&bytes),
            Err(TranscriptError::Frame(FrameError::UnknownKind { kind: 9 }))
        );
    }
}
