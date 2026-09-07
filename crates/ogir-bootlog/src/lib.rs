// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! Dependency-free TCG2 measured-boot ingestion (ADR-0023): the binary
//! TPM2 event-log parser, PCR replay, and the platform-profile schema.
//! Statements about measured state are candidate inputs, never
//! authority; a profile is reference data whose acceptance always
//! requires signed, reviewed updates (ADR-0014 transition rules apply).

use std::error::Error;
use std::fmt;

pub mod manifest;
pub mod parser;
pub mod profile;
pub mod replay;

/// Ingestion and replay failures. Deterministic, non-disciplinary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootlogError {
    /// The log ended inside a structure.
    Truncated,
    /// The log is not a TCG2 (Spec ID Event03) log.
    NotTcg2,
    /// A structure carried an unsupported or inconsistent value.
    Malformed(&'static str),
    /// Replay produced PCRs that do not match the expectations.
    PcrMismatch,
    /// The profile itself was invalid.
    InvalidProfile(&'static str),
    /// The manifest violated the canonical grammar (ADR-0025).
    InvalidManifest(&'static str),
    /// The checked boot component version is revoked.
    ComponentRevoked,
    /// The checked boot component is below its minimum version.
    BelowMinimumVersion,
    /// The checked boot component is not declared by the profile.
    UnknownComponent,
    /// The claimed profile is not the accepted one (reference data,
    /// never an attack verdict).
    UnsupportedProfile,
}

impl fmt::Display for BootlogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("event log ended inside a structure"),
            Self::NotTcg2 => formatter.write_str("not a TCG2 Spec ID Event03 log"),
            Self::Malformed(detail) => write!(formatter, "malformed event log: {detail}"),
            Self::PcrMismatch => formatter.write_str("replayed PCRs do not match expectations"),
            Self::InvalidProfile(detail) => write!(formatter, "invalid profile: {detail}"),
            Self::InvalidManifest(detail) => write!(formatter, "invalid manifest: {detail}"),
            Self::ComponentRevoked => formatter.write_str("boot component version is revoked"),
            Self::BelowMinimumVersion => {
                formatter.write_str("boot component is below its minimum version")
            }
            Self::UnknownComponent => formatter.write_str("boot component is not declared"),
            Self::UnsupportedProfile => {
                formatter.write_str("claimed profile is not the accepted one")
            }
        }
    }
}

impl Error for BootlogError {}
