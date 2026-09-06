// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! Dependency-free TCG2 measured-boot ingestion (ADR-0023): the binary
//! TPM2 event-log parser, PCR replay, and the platform-profile schema.
//! Statements about measured state are candidate inputs, never
//! authority; a profile is reference data whose acceptance always
//! requires signed, reviewed updates (ADR-0014 transition rules apply).

use std::error::Error;
use std::fmt;

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
}

impl fmt::Display for BootlogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("event log ended inside a structure"),
            Self::NotTcg2 => formatter.write_str("not a TCG2 Spec ID Event03 log"),
            Self::Malformed(detail) => write!(formatter, "malformed event log: {detail}"),
            Self::PcrMismatch => formatter.write_str("replayed PCRs do not match expectations"),
            Self::InvalidProfile(detail) => write!(formatter, "invalid profile: {detail}"),
        }
    }
}

impl Error for BootlogError {}
