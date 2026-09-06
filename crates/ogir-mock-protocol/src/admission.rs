// SPDX-License-Identifier: Apache-2.0

//! Test-only mock relying-party admission: the server side that admits
//! only a verifier-signed permit with a valid session-key proof of
//! possession. There is no local trusted boolean anywhere on the client
//! path; this is the M2 exit-criteria embodiment.

use std::collections::HashSet;

use ogir_mock_keys::keys::MockKeyDirectory;

use crate::TranscriptError;
use crate::objects::{MockPermit, verify_signed_permit};

/// Why admission failed. Non-disciplinary and deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    /// The transcript layer rejected the permit or the proof.
    Transcript(TranscriptError),
    /// The permit was signed by a key the relying party does not know.
    UnknownIssuer,
    /// Decision time was at or after the permit's exclusive expiry.
    PermitExpired,
    /// The session key bound to the permit is not registered here.
    UnknownSession,
    /// This exact permit was already used for an initial admission.
    PermitReplay,
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transcript(error) => write!(formatter, "transcript rejected: {error}"),
            Self::UnknownIssuer => formatter.write_str("permit issuer is not trusted here"),
            Self::PermitExpired => formatter.write_str("permit reached its exclusive expiry"),
            Self::UnknownSession => formatter.write_str("session key is not registered here"),
            Self::PermitReplay => formatter.write_str("permit was already admitted"),
        }
    }
}

impl std::error::Error for AdmissionError {}

impl From<TranscriptError> for AdmissionError {
    fn from(error: TranscriptError) -> Self {
        Self::Transcript(error)
    }
}

/// An admitted protected session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedSession {
    /// The verified permit.
    pub permit: MockPermit,
    /// The rechallenge nonce the proof carried.
    pub rechallenge_nonce: [u8; 32],
}

/// A mock relying party with its own view of trusted verifier keys and
/// registered session keys, tracking one-use initial admission per permit.
#[derive(Debug)]
pub struct MockRelyingParty {
    directory: MockKeyDirectory,
    admitted_permits: HashSet<Vec<u8>>,
}

impl MockRelyingParty {
    /// Creates a relying party from a key directory it trusts.
    pub fn new(directory: MockKeyDirectory) -> Self {
        Self {
            directory,
            admitted_permits: HashSet::new(),
        }
    }

    /// Attempts admission at decision time `now`: the permit must verify
    /// under a known verifier key, be unexpired, carry a session key
    /// registered here, and be accompanied by a proof of possession valid
    /// under that exact session key and those exact permit bytes. Initial
    /// admission is one-use per permit (ADR-0014: exact redelivery of a
    /// committed artifact is a separate idempotent path, not re-admission).
    pub fn admit(
        &mut self,
        now: u64,
        permit_bytes: &[u8],
        pop_bytes: &[u8],
    ) -> Result<AdmittedSession, AdmissionError> {
        let permit = verify_signed_permit(&self.directory, permit_bytes)
            .map_err(AdmissionError::Transcript)?;
        if now >= permit.expires_at {
            return Err(AdmissionError::PermitExpired);
        }
        let session_material = self
            .directory
            .session_material_by_handle(&permit.session_key_handle)
            .ok_or(AdmissionError::UnknownSession)?;
        let rechallenge_nonce =
            crate::objects::verify_pop_under_material(&session_material, permit_bytes, pop_bytes)
                .map_err(AdmissionError::Transcript)?;
        if !self.admitted_permits.insert(permit_bytes.to_vec()) {
            return Err(AdmissionError::PermitReplay);
        }
        Ok(AdmittedSession {
            permit,
            rechallenge_nonce,
        })
    }
}

/// Convenience: builds a proof the relying party can validate, using the
/// session key object directly (client side).
pub fn client_build_pop(
    session_key: &ogir_mock_keys::keys::MockSessionKey,
    permit_bytes: &[u8],
    rechallenge_nonce: &[u8; 32],
) -> Result<Vec<u8>, TranscriptError> {
    crate::objects::build_pop(session_key, permit_bytes, rechallenge_nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_error_maps_to_admission_error() {
        let error = AdmissionError::from(TranscriptError::UnknownKey);
        assert_eq!(
            error,
            AdmissionError::Transcript(TranscriptError::UnknownKey)
        );
        assert!(error.to_string().contains("transcript"));
    }
}
