// SPDX-License-Identifier: Apache-2.0

//! The labeled test backend: the M2 mock attester behind the production
//! [`AttestationBackend`] seam (ADR-0017). Assurance class is always
//! [`AssuranceClass::Test`]; statements are the mock HMAC quote over the
//! request's qualifying data.

use ogir_attest::{
    AssuranceClass, AttestationBackend, AttestationStatement, BackendError, QuoteRequest,
};
use ogir_mock_keys::keys::MockAttesterKey;
use ogir_mock_keys::sha256::sha256;

/// Qualifying-digest domain label for the mock backend (mock-namespace,
/// never reused by a real backend class).
const QUALIFYING_LABEL: &[u8] = b"ogir-attest/mock/qualifying/v1";

/// The test backend: deterministic, TPM-free, labeled `test`.
#[derive(Debug, Clone)]
pub struct MockAttestationBackend {
    attester: MockAttesterKey,
}

impl MockAttestationBackend {
    /// Creates a test backend from an explicit seed.
    pub fn from_seed(seed: &[u8]) -> Self {
        Self {
            attester: MockAttesterKey::from_seed(seed),
        }
    }

    /// The mock attester key, for evidence construction alongside quotes.
    pub fn attester_key(&self) -> &MockAttesterKey {
        &self.attester
    }
}

impl AttestationBackend for MockAttestationBackend {
    fn assurance_class(&self) -> AssuranceClass {
        AssuranceClass::Test
    }

    fn backend_id(&self) -> &str {
        "ogir-mock-attester-v1"
    }

    fn quote(&mut self, request: &QuoteRequest) -> Result<AttestationStatement, BackendError> {
        request.validate()?;
        let mut input = QUALIFYING_LABEL.to_vec();
        input.extend_from_slice(&request.qualifying_data);
        let mut digest = sha256(&input);
        // Fold the attester key into the digest so different backends
        // produce different bindings for the same request.
        let keyed = ogir_mock_keys::hmac::hmac_sha256(self.attester.id().as_bytes(), &digest);
        digest = keyed;
        let payload = self
            .attester
            .authenticate(&request.qualifying_data)
            .to_vec();
        AttestationStatement::new(
            AssuranceClass::Test,
            "ogir-mock-attester-v1",
            digest,
            payload,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ogir_attest::accept_class;

    #[test]
    fn test_backend_labels_and_binds_deterministically() {
        let mut backend = MockAttestationBackend::from_seed(b"m3-020");
        assert_eq!(backend.assurance_class(), AssuranceClass::Test);
        assert_eq!(backend.backend_id(), "ogir-mock-attester-v1");
        let request = QuoteRequest {
            qualifying_data: b"qualifying".to_vec(),
        };
        let first = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
        let second = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(first, second);
        assert_eq!(first.assurance_class(), AssuranceClass::Test);
        assert_eq!(first.backend_id(), "ogir-mock-attester-v1");
    }

    #[test]
    fn different_qualifying_data_yields_different_bindings() {
        let mut backend = MockAttestationBackend::from_seed(b"m3-020");
        let left = backend
            .quote(&QuoteRequest {
                qualifying_data: b"one".to_vec(),
            })
            .unwrap_or_else(|e| panic!("{e:?}"));
        let right = backend
            .quote(&QuoteRequest {
                qualifying_data: b"two".to_vec(),
            })
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_ne!(left.qualifying_digest(), right.qualifying_digest());
        assert_ne!(left.quote_payload(), right.quote_payload());
    }

    #[test]
    fn invalid_requests_fail_closed() {
        let mut backend = MockAttestationBackend::from_seed(b"m3-020");
        assert_eq!(
            backend
                .quote(&QuoteRequest {
                    qualifying_data: Vec::new()
                })
                .err(),
            Some(BackendError::InvalidRequest)
        );
    }

    #[test]
    fn hardware_expectation_rejects_test_statements() {
        let mut backend = MockAttestationBackend::from_seed(b"m3-020");
        let statement = backend
            .quote(&QuoteRequest {
                qualifying_data: b"q".to_vec(),
            })
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert!(accept_class(AssuranceClass::Test, statement.assurance_class()).is_ok());
        assert!(
            accept_class(
                AssuranceClass::HardwareFirmwareTpm,
                statement.assurance_class()
            )
            .is_err()
        );
        assert!(accept_class(AssuranceClass::SoftwareTpm, statement.assurance_class()).is_err());
    }
}
