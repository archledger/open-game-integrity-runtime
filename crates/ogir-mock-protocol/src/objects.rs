// SPDX-License-Identifier: Apache-2.0

//! Signed mock objects for the four M2 message classes (ADR-0015
//! registries, ADR-0016 authenticators). Objects are
//! `tag || records || authenticator(32)`; the authenticator covers the tag
//! and every record byte, so any field alteration fails closed.

use ogir_mock_keys::keys::{
    DirectoryError, KEY_ID_LENGTH, MockAttesterKey, MockKeyDirectory, MockSessionKey,
    MockVerifierKey,
};
use ogir_mock_keys::sha256::sha256;

use crate::TranscriptError;
use crate::transcript::{Schema, TAG_CHALLENGE, TAG_EVIDENCE, TAG_PERMIT, TAG_POP, encode, parse};

/// Maximum canonical text length, mirroring the model's limit.
const MAX_TEXT: usize = 128;

/// Nonce and session-handle length, mirroring the model's constants.
const FIXED_32: usize = 32;

/// Challenge registry (all fields required).
const CHALLENGE_SCHEMA: Schema = Schema {
    required: &[
        0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A, 0x000B,
        0x000C, 0x000D, 0x000E,
    ],
    optional: &[],
};

/// Evidence registry: eight required base claim slots, two optional
/// profile-specific slots, one required manifest-identities record.
const EVIDENCE_SCHEMA: Schema = Schema {
    required: &[
        0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x0010, 0x0011,
        0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017, 0x001A, 0x001B,
    ],
    optional: &[0x0018, 0x0019],
};

/// Permit registry (all fields required).
const PERMIT_SCHEMA: Schema = Schema {
    required: &[
        0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A, 0x000B,
    ],
    optional: &[],
};

/// Proof-of-possession registry (all fields required).
const POP_SCHEMA: Schema = Schema {
    required: &[0x0001, 0x0002],
    optional: &[],
};

/// Registered provenance classes (TRUST_MODEL producers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Provenance {
    /// Hardware-certified claim.
    HardwareCertified = 1,
    /// Measured-log-derived claim.
    MeasuredLogDerived = 2,
    /// Trusted-agent-observed claim.
    TrustedAgentObserved = 3,
}

impl Provenance {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::HardwareCertified),
            2 => Some(Self::MeasuredLogDerived),
            3 => Some(Self::TrustedAgentObserved),
            _ => None,
        }
    }
}

/// One mock claim: a provenance class plus opaque semantic identity.
#[derive(Clone, PartialEq, Eq)]
pub struct MockClaim {
    /// Registered provenance class for this claim.
    pub provenance: Provenance,
    /// Opaque semantic identity bytes (1 to 128).
    pub identity: Vec<u8>,
}

impl std::fmt::Debug for MockClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MockClaim([IDENTITY REDACTED])")
    }
}

/// A verified (or to-be-signed) mock challenge. Plain data by design:
/// mapping into `ogir_model::PublisherChallenge` is the caller's duty.
#[derive(Clone, PartialEq, Eq)]
pub struct MockChallenge {
    /// Protocol version.
    pub version: ogir_model::ProtocolVersion,
    /// Publisher-scoped identifier text.
    pub publisher_id: String,
    /// Game identifier text.
    pub game_id: String,
    /// Exact build identifier text.
    pub build_id: String,
    /// Publisher-scoped account binding text.
    pub account_scope: String,
    /// Match or protected-session identifier text.
    pub match_id: String,
    /// Policy identifier text.
    pub policy_id: String,
    /// Policy version.
    pub policy_version: u32,
    /// Fresh challenge nonce.
    pub nonce: [u8; 32],
    /// Window issue time.
    pub issued_at: u64,
    /// Exclusive window expiry.
    pub expires_at: u64,
    /// Requested evidence profile text.
    pub evidence_profile_id: String,
    /// Verifier test signing key id.
    pub issuer_key_id: [u8; KEY_ID_LENGTH],
}

impl std::fmt::Debug for MockChallenge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MockChallenge([NONCE AND KEY REDACTED])")
    }
}

/// A verified (or to-be-signed) mock evidence transcript.
#[derive(Clone, PartialEq, Eq)]
pub struct MockEvidence {
    /// The complete signed challenge object bytes, embedded verbatim.
    pub challenge_object: Vec<u8>,
    /// Evidence profile text.
    pub evidence_profile_id: String,
    /// Session public-key handle (32 bytes).
    pub session_key_handle: [u8; FIXED_32],
    /// Session key id association.
    pub session_key_id: [u8; KEY_ID_LENGTH],
    /// Collection authority contract text.
    pub collection_authority_contract_id: String,
    /// Protected epoch relation.
    pub epoch_relation: u64,
    /// Protected collection sequence.
    pub collection_sequence: u64,
    /// Protected collection start.
    pub collection_start: u64,
    /// Protected snapshot-freeze end.
    pub snapshot_freeze_end: u64,
    /// The eight Base claims, in registry slot order.
    pub base_claims: [MockClaim; 8],
    /// The profile's declared subset of the two profile-specific claims.
    pub profile_claims: Vec<MockClaim>,
    /// Semantic manifest and measurement identities.
    pub manifest_identities: Vec<u8>,
    /// Test attester key id.
    pub attester_key_id: [u8; KEY_ID_LENGTH],
}

impl std::fmt::Debug for MockEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MockEvidence([CLAIMS AND KEYS REDACTED])")
    }
}

/// A verified (or to-be-signed) mock permit.
#[derive(Clone, PartialEq, Eq)]
pub struct MockPermit {
    /// Protocol version.
    pub version: ogir_model::ProtocolVersion,
    /// Permit identifier text.
    pub permit_id: String,
    /// Session identifier text.
    pub session_id: String,
    /// Session public-key handle.
    pub session_key_handle: [u8; FIXED_32],
    /// Nonce of the appraised challenge.
    pub appraised_nonce: [u8; 32],
    /// Policy identifier text.
    pub policy_id: String,
    /// Policy version.
    pub policy_version: u32,
    /// Permit issue time.
    pub issued_at: u64,
    /// Exclusive permit expiry (finite, half-open, ADR-0014).
    pub expires_at: u64,
    /// Verifier test signing key id.
    pub issuer_key_id: [u8; KEY_ID_LENGTH],
}

impl std::fmt::Debug for MockPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MockPermit([NONCE AND KEY REDACTED])")
    }
}

fn text_record(id: u16, value: &str) -> Result<(u16, Vec<u8>), TranscriptError> {
    if value.is_empty() || value.len() > MAX_TEXT {
        return Err(TranscriptError::BadFieldLength { id });
    }
    Ok((id, value.as_bytes().to_vec()))
}

fn fixed_record<const N: usize>(id: u16, value: &[u8; N]) -> (u16, Vec<u8>) {
    (id, value.to_vec())
}

fn take_text(
    records: &crate::transcript::ParsedRecords,
    id: u16,
) -> Result<String, TranscriptError> {
    let bytes = records.require(id)?;
    if bytes.is_empty() || bytes.len() > MAX_TEXT {
        return Err(TranscriptError::BadFieldLength { id });
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => Ok(text.to_string()),
        Err(_) => Err(TranscriptError::BadFieldLength { id }),
    }
}

fn take_u16(records: &crate::transcript::ParsedRecords, id: u16) -> Result<u16, TranscriptError> {
    let bytes = records.require(id)?;
    let array: [u8; 2] = match bytes.try_into() {
        Ok(array) => array,
        Err(_) => return Err(TranscriptError::BadFieldLength { id }),
    };
    Ok(u16::from_be_bytes(array))
}

fn take_u32(records: &crate::transcript::ParsedRecords, id: u16) -> Result<u32, TranscriptError> {
    let bytes = records.require(id)?;
    let array: [u8; 4] = match bytes.try_into() {
        Ok(array) => array,
        Err(_) => return Err(TranscriptError::BadFieldLength { id }),
    };
    Ok(u32::from_be_bytes(array))
}

fn take_u64(records: &crate::transcript::ParsedRecords, id: u16) -> Result<u64, TranscriptError> {
    let bytes = records.require(id)?;
    let array: [u8; 8] = match bytes.try_into() {
        Ok(array) => array,
        Err(_) => return Err(TranscriptError::BadFieldLength { id }),
    };
    Ok(u64::from_be_bytes(array))
}

fn take_32(
    records: &crate::transcript::ParsedRecords,
    id: u16,
) -> Result<[u8; 32], TranscriptError> {
    let bytes = records.require(id)?;
    match bytes.try_into() {
        Ok(array) => Ok(array),
        Err(_) => Err(TranscriptError::BadFieldLength { id }),
    }
}

fn take_key_id(
    records: &crate::transcript::ParsedRecords,
    id: u16,
) -> Result<[u8; KEY_ID_LENGTH], TranscriptError> {
    let bytes = records.require(id)?;
    match bytes.try_into() {
        Ok(array) => Ok(array),
        Err(_) => Err(TranscriptError::BadFieldLength { id }),
    }
}

fn claim_record(id: u16, claim: &MockClaim) -> Result<(u16, Vec<u8>), TranscriptError> {
    if claim.identity.is_empty() || claim.identity.len() > MAX_TEXT {
        return Err(TranscriptError::BadFieldLength { id });
    }
    let mut value = Vec::with_capacity(1 + claim.identity.len());
    value.push(claim.provenance as u8);
    value.extend_from_slice(&claim.identity);
    Ok((id, value))
}

fn take_claim(
    records: &crate::transcript::ParsedRecords,
    id: u16,
) -> Result<MockClaim, TranscriptError> {
    let bytes = records.require(id)?;
    if bytes.len() < 2 || bytes.len() > 1 + MAX_TEXT {
        return Err(TranscriptError::BadFieldLength { id });
    }
    match Provenance::from_byte(bytes[0]) {
        Some(provenance) => Ok(MockClaim {
            provenance,
            identity: bytes[1..].to_vec(),
        }),
        None => Err(TranscriptError::BadFieldLength { id }),
    }
}

fn split_signed<'a>(
    tag: &str,
    bytes: &'a [u8],
) -> Result<(&'a [u8], &'a [u8; 32]), TranscriptError> {
    let minimum = tag.len() + 32;
    if bytes.len() < minimum {
        return Err(TranscriptError::Truncated);
    }
    let split = bytes.len() - 32;
    let (inner, authenticator) = bytes.split_at(split);
    let authenticator: &[u8; 32] = match authenticator.try_into() {
        Ok(array) => array,
        Err(_) => return Err(TranscriptError::Truncated),
    };
    Ok((inner, authenticator))
}

fn map_directory_error(error: DirectoryError) -> TranscriptError {
    match error {
        DirectoryError::UnknownKey => TranscriptError::UnknownKey,
        DirectoryError::AuthenticationFailed => TranscriptError::AuthenticationFailed,
    }
}

/// Builds the signed challenge object under `key`.
pub fn build_signed_challenge(
    challenge: &MockChallenge,
    key: &MockVerifierKey,
) -> Result<Vec<u8>, TranscriptError> {
    if challenge.issued_at >= challenge.expires_at {
        return Err(TranscriptError::InvalidWindow);
    }
    let records = vec![
        (0x0001, challenge.version.major.to_be_bytes().to_vec()),
        (0x0002, challenge.version.minor.to_be_bytes().to_vec()),
        text_record(0x0003, &challenge.publisher_id)?,
        text_record(0x0004, &challenge.game_id)?,
        text_record(0x0005, &challenge.build_id)?,
        text_record(0x0006, &challenge.account_scope)?,
        text_record(0x0007, &challenge.match_id)?,
        text_record(0x0008, &challenge.policy_id)?,
        (0x0009, challenge.policy_version.to_be_bytes().to_vec()),
        fixed_record(0x000A, &challenge.nonce),
        (0x000B, challenge.issued_at.to_be_bytes().to_vec()),
        (0x000C, challenge.expires_at.to_be_bytes().to_vec()),
        text_record(0x000D, &challenge.evidence_profile_id)?,
        fixed_record(0x000E, key.id().as_bytes()),
    ];
    let mut object = encode(TAG_CHALLENGE, &records)?;
    let authenticator = key.authenticate(&object);
    object.extend_from_slice(&authenticator);
    Ok(object)
}

/// Verifies and parses a signed challenge against the directory.
pub fn verify_signed_challenge(
    directory: &MockKeyDirectory,
    bytes: &[u8],
) -> Result<MockChallenge, TranscriptError> {
    let (inner, authenticator) = split_signed(TAG_CHALLENGE, bytes)?;
    let records = parse(TAG_CHALLENGE, inner, &CHALLENGE_SCHEMA)?;
    let issuer_key_id = take_key_id(&records, 0x000E)?;
    directory
        .verify_verifier(
            &ogir_mock_keys::keys::KeyId::from_bytes(issuer_key_id),
            inner,
            authenticator,
        )
        .map_err(map_directory_error)?;
    let issued_at = take_u64(&records, 0x000B)?;
    let expires_at = take_u64(&records, 0x000C)?;
    if issued_at >= expires_at {
        return Err(TranscriptError::InvalidWindow);
    }
    Ok(MockChallenge {
        version: ogir_model::ProtocolVersion {
            major: take_u16(&records, 0x0001)?,
            minor: take_u16(&records, 0x0002)?,
        },
        publisher_id: take_text(&records, 0x0003)?,
        game_id: take_text(&records, 0x0004)?,
        build_id: take_text(&records, 0x0005)?,
        account_scope: take_text(&records, 0x0006)?,
        match_id: take_text(&records, 0x0007)?,
        policy_id: take_text(&records, 0x0008)?,
        policy_version: take_u32(&records, 0x0009)?,
        nonce: take_32(&records, 0x000A)?,
        issued_at,
        expires_at,
        evidence_profile_id: take_text(&records, 0x000D)?,
        issuer_key_id,
    })
}

/// Builds the signed evidence transcript under `key`.
pub fn build_signed_evidence(
    evidence: &MockEvidence,
    key: &MockAttesterKey,
) -> Result<Vec<u8>, TranscriptError> {
    if evidence.collection_start > evidence.snapshot_freeze_end {
        return Err(TranscriptError::InvalidWindow);
    }
    if evidence.profile_claims.len() > 2 {
        return Err(TranscriptError::BadFieldLength { id: 0x0018 });
    }
    let mut records = vec![
        (0x0001, evidence.challenge_object.clone()),
        text_record(0x0002, &evidence.evidence_profile_id)?,
        fixed_record(0x0003, &evidence.session_key_handle),
        fixed_record(0x0004, &evidence.session_key_id),
        text_record(0x0005, &evidence.collection_authority_contract_id)?,
        (0x0006, evidence.epoch_relation.to_be_bytes().to_vec()),
        (0x0007, evidence.collection_sequence.to_be_bytes().to_vec()),
        (0x0008, evidence.collection_start.to_be_bytes().to_vec()),
        (0x0009, evidence.snapshot_freeze_end.to_be_bytes().to_vec()),
    ];
    for (slot, claim) in evidence.base_claims.iter().enumerate() {
        records.push(claim_record(0x0010 + slot as u16, claim)?);
    }
    for (slot, claim) in evidence.profile_claims.iter().enumerate() {
        records.push(claim_record(0x0018 + slot as u16, claim)?);
    }
    if evidence.manifest_identities.is_empty() || evidence.manifest_identities.len() > 256 {
        return Err(TranscriptError::BadFieldLength { id: 0x001A });
    }
    records.push((0x001A, evidence.manifest_identities.clone()));
    records.push(fixed_record(0x001B, key.id().as_bytes()));
    let mut object = encode(TAG_EVIDENCE, &records)?;
    let authenticator = key.authenticate(&object);
    object.extend_from_slice(&authenticator);
    Ok(object)
}

/// Verifies and parses a signed evidence transcript against the directory.
pub fn verify_signed_evidence(
    directory: &MockKeyDirectory,
    bytes: &[u8],
) -> Result<MockEvidence, TranscriptError> {
    let (inner, authenticator) = split_signed(TAG_EVIDENCE, bytes)?;
    let records = parse(TAG_EVIDENCE, inner, &EVIDENCE_SCHEMA)?;
    let attester_key_id = take_key_id(&records, 0x001B)?;
    directory
        .verify_attester(
            &ogir_mock_keys::keys::KeyId::from_bytes(attester_key_id),
            inner,
            authenticator,
        )
        .map_err(map_directory_error)?;
    let collection_start = take_u64(&records, 0x0008)?;
    let snapshot_freeze_end = take_u64(&records, 0x0009)?;
    if collection_start > snapshot_freeze_end {
        return Err(TranscriptError::InvalidWindow);
    }
    let mut base_claims = Vec::with_capacity(8);
    for slot in 0x0010..=0x0017 {
        base_claims.push(take_claim(&records, slot)?);
    }
    let base_claims: [MockClaim; 8] = match base_claims.try_into() {
        Ok(array) => array,
        Err(_) => return Err(TranscriptError::MissingField { id: 0x0010 }),
    };
    let mut profile_claims = Vec::new();
    for slot in [0x0018u16, 0x0019] {
        if records.get(slot).is_some() {
            profile_claims.push(take_claim(&records, slot)?);
        }
    }
    let challenge_object = records.require(0x0001)?.to_vec();
    if challenge_object.is_empty() {
        return Err(TranscriptError::BadFieldLength { id: 0x0001 });
    }
    let manifest_identities = records.require(0x001A)?.to_vec();
    if manifest_identities.is_empty() || manifest_identities.len() > 256 {
        return Err(TranscriptError::BadFieldLength { id: 0x001A });
    }
    Ok(MockEvidence {
        challenge_object,
        evidence_profile_id: take_text(&records, 0x0002)?,
        session_key_handle: take_32(&records, 0x0003)?,
        session_key_id: take_key_id(&records, 0x0004)?,
        collection_authority_contract_id: take_text(&records, 0x0005)?,
        epoch_relation: take_u64(&records, 0x0006)?,
        collection_sequence: take_u64(&records, 0x0007)?,
        collection_start,
        snapshot_freeze_end,
        base_claims,
        profile_claims,
        manifest_identities,
        attester_key_id,
    })
}

/// Builds the signed permit object under `key`.
pub fn build_signed_permit(
    permit: &MockPermit,
    key: &MockVerifierKey,
) -> Result<Vec<u8>, TranscriptError> {
    if permit.issued_at >= permit.expires_at {
        return Err(TranscriptError::InvalidWindow);
    }
    let records = vec![
        (0x0001, permit.version.major.to_be_bytes().to_vec()),
        (0x0002, permit.version.minor.to_be_bytes().to_vec()),
        text_record(0x0003, &permit.permit_id)?,
        text_record(0x0004, &permit.session_id)?,
        fixed_record(0x0005, &permit.session_key_handle),
        fixed_record(0x0006, &permit.appraised_nonce),
        text_record(0x0007, &permit.policy_id)?,
        (0x0008, permit.policy_version.to_be_bytes().to_vec()),
        (0x0009, permit.issued_at.to_be_bytes().to_vec()),
        (0x000A, permit.expires_at.to_be_bytes().to_vec()),
        fixed_record(0x000B, key.id().as_bytes()),
    ];
    let mut object = encode(TAG_PERMIT, &records)?;
    let authenticator = key.authenticate(&object);
    object.extend_from_slice(&authenticator);
    Ok(object)
}

/// Verifies and parses a signed permit against the directory.
pub fn verify_signed_permit(
    directory: &MockKeyDirectory,
    bytes: &[u8],
) -> Result<MockPermit, TranscriptError> {
    let (inner, authenticator) = split_signed(TAG_PERMIT, bytes)?;
    let records = parse(TAG_PERMIT, inner, &PERMIT_SCHEMA)?;
    let issuer_key_id = take_key_id(&records, 0x000B)?;
    directory
        .verify_verifier(
            &ogir_mock_keys::keys::KeyId::from_bytes(issuer_key_id),
            inner,
            authenticator,
        )
        .map_err(map_directory_error)?;
    let issued_at = take_u64(&records, 0x0009)?;
    let expires_at = take_u64(&records, 0x000A)?;
    if issued_at >= expires_at {
        return Err(TranscriptError::InvalidWindow);
    }
    Ok(MockPermit {
        version: ogir_model::ProtocolVersion {
            major: take_u16(&records, 0x0001)?,
            minor: take_u16(&records, 0x0002)?,
        },
        permit_id: take_text(&records, 0x0003)?,
        session_id: take_text(&records, 0x0004)?,
        session_key_handle: take_32(&records, 0x0005)?,
        appraised_nonce: take_32(&records, 0x0006)?,
        policy_id: take_text(&records, 0x0007)?,
        policy_version: take_u32(&records, 0x0008)?,
        issued_at,
        expires_at,
        issuer_key_id,
    })
}

/// Builds the session-key proof of possession over the exact permit bytes
/// and a verifier-issued single-use rechallenge nonce (ADR-0016 formula:
/// HMAC over `OGIR-MOCK-POP-1 || permit-bytes || rechallenge-nonce`).
pub fn build_pop(
    session_key: &MockSessionKey,
    permit_bytes: &[u8],
    rechallenge_nonce: &[u8; 32],
) -> Result<Vec<u8>, TranscriptError> {
    let permit_digest = sha256(permit_bytes);
    let records = vec![
        fixed_record(0x0001, &permit_digest),
        fixed_record(0x0002, rechallenge_nonce),
    ];
    let mut object = encode(TAG_POP, &records)?;
    let mut authenticator_input = TAG_POP.as_bytes().to_vec();
    authenticator_input.extend_from_slice(permit_bytes);
    authenticator_input.extend_from_slice(rechallenge_nonce);
    let authenticator = session_key.authenticate(&authenticator_input);
    object.extend_from_slice(&authenticator);
    Ok(object)
}

/// Verifies a proof of possession against the exact permit bytes. Returns
/// the rechallenge nonce carried by the proof.
pub fn verify_pop(
    session_key: &MockSessionKey,
    permit_bytes: &[u8],
    pop_bytes: &[u8],
) -> Result<[u8; 32], TranscriptError> {
    let (inner, authenticator) = split_signed(TAG_POP, pop_bytes)?;
    let records = parse(TAG_POP, inner, &POP_SCHEMA)?;
    let rechallenge_nonce = pop_common_checks(&records, permit_bytes)?;
    let expected = session_key.authenticate(&pop_input(permit_bytes, &rechallenge_nonce));
    if !ogir_mock_keys::hmac::fixed_time_equal(authenticator, &expected) {
        return Err(TranscriptError::AuthenticationFailed);
    }
    Ok(rechallenge_nonce)
}

/// Verifies a proof of possession under explicit session-key material
/// (the trusted mock channel's view of the actual key), using the same
/// canonical parse and the same ADR-0016 formula.
pub fn verify_pop_under_material(
    session_material: &[u8; 32],
    permit_bytes: &[u8],
    pop_bytes: &[u8],
) -> Result<[u8; 32], TranscriptError> {
    let (inner, authenticator) = split_signed(TAG_POP, pop_bytes)?;
    let records = parse(TAG_POP, inner, &POP_SCHEMA)?;
    let rechallenge_nonce = pop_common_checks(&records, permit_bytes)?;
    let expected = ogir_mock_keys::hmac::hmac_sha256(
        session_material,
        &pop_input(permit_bytes, &rechallenge_nonce),
    );
    if !ogir_mock_keys::hmac::fixed_time_equal(authenticator, &expected) {
        return Err(TranscriptError::AuthenticationFailed);
    }
    Ok(rechallenge_nonce)
}

fn pop_common_checks(
    records: &crate::transcript::ParsedRecords,
    permit_bytes: &[u8],
) -> Result<[u8; 32], TranscriptError> {
    let presented_digest = take_32(records, 0x0001)?;
    let expected_digest = sha256(permit_bytes);
    if !ogir_mock_keys::hmac::fixed_time_equal(&presented_digest, &expected_digest) {
        return Err(TranscriptError::AuthenticationFailed);
    }
    take_32(records, 0x0002)
}

fn pop_input(permit_bytes: &[u8], rechallenge_nonce: &[u8; 32]) -> Vec<u8> {
    let mut authenticator_input = TAG_POP.as_bytes().to_vec();
    authenticator_input.extend_from_slice(permit_bytes);
    authenticator_input.extend_from_slice(rechallenge_nonce);
    authenticator_input
}
