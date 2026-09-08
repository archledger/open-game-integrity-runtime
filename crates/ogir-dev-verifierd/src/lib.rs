// SPDX-License-Identifier: Apache-2.0

//! The developer-mode verifier daemon (M6-036, ADR-0032): the
//! "local developer mode using test keys and simulated profiles"
//! deliverable. This crate composes the TEST substrate
//! (ADR-0016/0017: the mock protocol, deterministic test keys,
//! exact-context policy) into the production service shell
//! (ogir-verifier::{http, bjson, service}) and serves three routes
//! over bounded HTTP:
//!   POST /v1/challenge     - issue a test-signed challenge (the
//!                            service's expected context becomes
//!                            exactly the issued context)
//!   POST /v1/dev/evidence  - simulate a client answering it
//!   POST /v1/evidence      - process a submission (verdict JSON)
//! It is mock-tier by construction and never part of the
//! production graph; the authoritative backend that composes the
//! real M3/M5 chain arrives later and reuses the same shell.

use std::sync::Mutex;

use ogir_mock_keys::keys::{MockAttesterKey, MockKeyDirectory, MockSessionKey, MockVerifierKey};
use ogir_mock_protocol::objects::{
    MockChallenge, MockClaim, MockEvidence, Provenance, build_signed_challenge,
    build_signed_evidence,
};
use ogir_mock_protocol::policy::{ContextMatchPolicy, MockExpectedContext};
use ogir_mock_protocol::service::MockVerdict;
use ogir_mock_protocol::service::MockVerifierService;
use ogir_verifier::service::{
    ChallengeIssuer, ChallengeRequest, ChallengeResponse, EvidenceProcessor, EvidenceSimulator,
    PermitRenewer, RenewalRequest, RevocationAuthority, RevocationRequest, WireVerdict,
};

/// The challenge lifetime in developer mode (seconds).
pub const DEV_CHALLENGE_LIFETIME: u64 = 300;
/// The permit lifetime in developer mode (seconds).
pub const DEV_PERMIT_LIFETIME: u64 = 600;

/// The composed developer-mode backend. The verification service
/// is (re)built at each challenge issuance with the exact expected
/// context of that challenge, so the simulated flow exercises the
/// full verify-replay-policy-permit chain per challenge.
/// Debug omits key material by construction (the substrate types
/// redact themselves; this impl never prints the backend's fields).
impl std::fmt::Debug for DevBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DevBackend([TEST KEYS REDACTED])")
    }
}

pub struct DevBackend {
    verifier_key: MockVerifierKey,
    attester_key: MockAttesterKey,
    session_key: MockSessionKey,
    directory: MockKeyDirectory,
    service: Mutex<Option<MockVerifierService<ContextMatchPolicy>>>,
    /// Permit objects (exact bytes) revoked through /v1/revoke;
    /// honored at renewal and re-admission.
    revoked: Mutex<std::collections::HashSet<Vec<u8>>>,
}

impl DevBackend {
    /// Creates the backend with deterministic test keys.
    pub fn new() -> Self {
        let verifier_key = MockVerifierKey::from_seed(b"m6-036-dev-verifier");
        let attester_key = MockAttesterKey::from_seed(b"m6-036-dev-attester");
        let session_key = MockSessionKey::from_seed(b"m6-036-dev-session");
        let mut directory = MockKeyDirectory::new();
        directory.register_verifier(&verifier_key);
        directory.register_attester(&attester_key);
        Self {
            verifier_key,
            attester_key,
            session_key,
            directory,
            service: Mutex::new(None),
            revoked: Mutex::new(std::collections::HashSet::new()),
        }
    }

    fn rebuild_service(&self, expected: MockExpectedContext) {
        let policy = ContextMatchPolicy {
            expected,
            permit_id: "permit.dev".to_string(),
            session_id: "session.dev".to_string(),
            lifetime_seconds: DEV_PERMIT_LIFETIME,
        };
        // The signing key is deterministic from the seed, so the
        // reconstructed key equals the directory-registered one.
        let signing = MockVerifierKey::from_seed(b"m6-036-dev-verifier");
        let service = MockVerifierService::new(signing, policy, DEV_CHALLENGE_LIFETIME)
            .unwrap_or_else(|error| panic!("developer backend construction: {error:?}"));
        *self
            .service
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(service);
    }
}

impl Default for DevBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeIssuer for DevBackend {
    fn issue(&self, request: &ChallengeRequest, now: u64) -> Result<ChallengeResponse, String> {
        let mut nonce = [0u8; 32];
        nonce[0] = (now & 0xff) as u8;
        for (index, byte) in nonce.iter_mut().enumerate().skip(1) {
            *byte = (index as u8).wrapping_add((now & 0xff) as u8);
        }
        let challenge = MockChallenge {
            version: ogir_model::ProtocolVersion { major: 1, minor: 0 },
            publisher_id: request.publisher_id.clone(),
            game_id: request.game_id.clone(),
            build_id: request.build_id.clone(),
            account_scope: request.account_scope.clone(),
            match_id: request.match_id.clone(),
            policy_id: request.policy_id.clone(),
            policy_version: request.policy_version,
            nonce,
            issued_at: now,
            expires_at: now + DEV_CHALLENGE_LIFETIME,
            evidence_profile_id: "profile.base".to_string(),
            issuer_key_id: [0; 16],
        };
        let challenge_hex = build_signed_challenge(&challenge, &self.verifier_key)
            .map_err(|error| format!("challenge issuance: {error:?}"))?;

        self.rebuild_service(MockExpectedContext {
            publisher_id: request.publisher_id.clone(),
            game_id: request.game_id.clone(),
            build_id: request.build_id.clone(),
            account_scope: request.account_scope.clone(),
            match_id: request.match_id.clone(),
            policy_id: request.policy_id.clone(),
            policy_version: request.policy_version,
        });

        Ok(ChallengeResponse {
            challenge_hex,
            issued_at: challenge.issued_at,
            expires_at: challenge.expires_at,
        })
    }
}

impl EvidenceSimulator for DevBackend {
    fn simulate(&self, challenge_object: &[u8]) -> Result<Vec<u8>, String> {
        let evidence = MockEvidence {
            challenge_object: challenge_object.to_vec(),
            evidence_profile_id: "profile.base".to_string(),
            session_key_handle: *self.session_key.handle_bytes(),
            session_key_id: *self.session_key.id().as_bytes(),
            collection_authority_contract_id: "authority.dev".to_string(),
            epoch_relation: 1,
            collection_sequence: 1,
            collection_start: 1,
            snapshot_freeze_end: 2,
            base_claims: std::array::from_fn(|slot| MockClaim {
                provenance: match slot % 3 {
                    0 => Provenance::HardwareCertified,
                    1 => Provenance::MeasuredLogDerived,
                    _ => Provenance::TrustedAgentObserved,
                },
                identity: vec![slot as u8 + 1; 8],
            }),
            profile_claims: vec![MockClaim {
                provenance: Provenance::HardwareCertified,
                identity: vec![0xAA; 5],
            }],
            manifest_identities: vec![0x55; 16],
            attester_key_id: [0; 16],
        };
        build_signed_evidence(&evidence, &self.attester_key)
            .map_err(|error| format!("evidence simulation: {error:?}"))
    }
}

impl EvidenceProcessor for DevBackend {
    fn process(&self, now: u64, challenge_object: &[u8], evidence_object: &[u8]) -> WireVerdict {
        let guard = self
            .service
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(service) = guard.as_ref() else {
            return WireVerdict::from_reason("Malformed");
        };
        match service.process(now, challenge_object, evidence_object, &self.directory) {
            MockVerdict::Admit { permit_bytes, .. } => {
                // Revoked permits never re-admit.
                let revoked = self
                    .revoked
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if revoked.contains(&permit_bytes) {
                    return WireVerdict::from_reason("Revoked");
                }
                WireVerdict::allow(permit_bytes)
            }
            MockVerdict::Deny { reason } => WireVerdict::from_reason(&format!("{reason:?}")),
        }
    }
}

impl PermitRenewer for DevBackend {
    fn renew(&self, now: u64, request: &RenewalRequest) -> ogir_verifier::service::RenewalOutcome {
        // ADR-0014 posture for developer mode: renewal is fresh
        // evidence under a NEW challenge for the permit's context.
        // The permit must verify, be unexpired, and be unrevoked.
        let permit = match ogir_mock_protocol::objects::verify_signed_permit(
            &self.directory,
            &request.permit_hex,
        ) {
            Ok(permit) => permit,
            Err(_) => return Err(WireVerdict::from_reason("Malformed")),
        };
        if now >= permit.expires_at {
            return Err(WireVerdict::from_reason("Expired"));
        }
        {
            let revoked = self
                .revoked
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if revoked.contains(&request.permit_hex) {
                return Err(WireVerdict::from_reason("Revoked"));
            }
        }
        // Renewal issues a fresh challenge for the SAME policy
        // context, then processes the submitted evidence against
        // it exactly like an initial submission; evidence
        // embedding the OLD challenge denies as stale.
        let renewal_challenge = MockChallenge {
            version: ogir_model::ProtocolVersion { major: 1, minor: 0 },
            publisher_id: permit.policy_id.clone(),
            game_id: format!("renewal:{}", permit.session_id),
            build_id: "build.renewal".to_string(),
            account_scope: "account.renewal".to_string(),
            match_id: permit.session_id.clone(),
            policy_id: permit.policy_id.clone(),
            policy_version: permit.policy_version,
            nonce: permit.appraised_nonce,
            issued_at: now,
            expires_at: now + DEV_CHALLENGE_LIFETIME,
            evidence_profile_id: "profile.base".to_string(),
            issuer_key_id: [0; 16],
        };
        let challenge_object = match build_signed_challenge(&renewal_challenge, &self.verifier_key)
        {
            Ok(bytes) => bytes,
            Err(_) => return Err(WireVerdict::from_reason("TransientFailure")),
        };
        self.rebuild_service(MockExpectedContext {
            publisher_id: renewal_challenge.publisher_id.clone(),
            game_id: renewal_challenge.game_id.clone(),
            build_id: renewal_challenge.build_id.clone(),
            account_scope: renewal_challenge.account_scope.clone(),
            match_id: renewal_challenge.match_id.clone(),
            policy_id: renewal_challenge.policy_id.clone(),
            policy_version: renewal_challenge.policy_version,
        });
        let guard = self
            .service
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(service) = guard.as_ref() else {
            return Err(WireVerdict::from_reason("TransientFailure"));
        };
        match service.process(
            now,
            &challenge_object,
            &request.evidence_hex,
            &self.directory,
        ) {
            MockVerdict::Admit { permit_bytes, .. } => Ok(permit_bytes),
            MockVerdict::Deny { reason } => Err(WireVerdict::from_reason(&format!("{reason:?}"))),
        }
    }
}

impl RevocationAuthority for DevBackend {
    fn revoke(&self, request: &RevocationRequest) -> ogir_verifier::service::RevocationOutcome {
        // Any non-empty opaque artifact can be retired; parser
        // confusion is impossible because nothing is parsed - the
        // exact bytes become the denylist key.
        if request.target_hex.is_empty() {
            return Err(WireVerdict::from_reason("Malformed"));
        }
        self.revoked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(request.target_hex.clone());
        Ok(())
    }
}

/// Runs the developer-mode daemon on the given address until the
/// process is stopped. `now` comes from the caller for
/// determinism in tests.
pub fn run_dev_daemon(address: &str, now_source: impl Fn() -> u64) -> std::io::Result<()> {
    let backend = DevBackend::new();
    let listener = ogir_verifier::http::Listener::bind(address)?;
    ogir_verifier::service::serve_forever(
        listener,
        now_source,
        &backend,
        Some(&backend),
        &backend,
        &backend,
        &backend,
    )
    .map_err(|error| std::io::Error::other(format!("{error:?}")))
}
