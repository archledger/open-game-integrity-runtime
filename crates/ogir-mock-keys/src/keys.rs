// SPDX-License-Identifier: Apache-2.0

//! Test-only ephemeral key classes and derivation (ADR-0016).
//!
//! Three key classes exist: a verifier test signing key, a test attester
//! key, and an ephemeral session key. All derive deterministically from an
//! explicit seed, live for the test process, carry the `OGIR-MOCK`
//! namespace in every key id, and never appear in diagnostics.

use crate::hmac::{fixed_time_equal, hmac_sha256};

/// Mock key-id length in bytes.
pub const KEY_ID_LENGTH: usize = 16;

/// Permanent test-only namespace prefix embedded in every key id.
pub const KEY_NAMESPACE: &[u8; 8] = b"OGIRMOCK";

/// Session-key handle length; matches the model's lookup-handle size.
pub const SESSION_HANDLE_LENGTH: usize = 32;

/// Derivation-domain labels; part of the reproducible-vector contract.
const VERIFIER_LABEL: &[u8] = b"ogir-mock-keys/verifier-signing/v1";
const ATTESTER_LABEL: &[u8] = b"ogir-mock-keys/attester/v1";
const SESSION_LABEL: &[u8] = b"ogir-mock-keys/session/v1";
const KEY_ID_LABEL: &[u8] = b"ogir-mock-keys/key-id/v1";
const HANDLE_LABEL: &[u8] = b"ogir-mock-keys/session-handle/v1";

/// A test-only key identifier: namespace prefix plus eight derived bytes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KeyId([u8; KEY_ID_LENGTH]);

impl KeyId {
    /// Returns the raw id bytes (namespace plus derivation).
    pub fn as_bytes(&self) -> &[u8; KEY_ID_LENGTH] {
        &self.0
    }

    /// Reconstructs an id from parsed record bytes.
    pub fn from_bytes(bytes: [u8; KEY_ID_LENGTH]) -> Self {
        Self(bytes)
    }

    fn from_material(material: &[u8; 32]) -> Self {
        let derived = hmac_sha256(material, KEY_ID_LABEL);
        let mut id = [0u8; KEY_ID_LENGTH];
        id[..8].copy_from_slice(KEY_NAMESPACE);
        id[8..].copy_from_slice(&derived[..8]);
        Self(id)
    }
}

impl std::fmt::Debug for KeyId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeyId([REDACTED])")
    }
}

fn derive_material(seed: &[u8], label: &[u8]) -> [u8; 32] {
    hmac_sha256(seed, label)
}

/// Verifier test signing key: issues signed mock challenges and permits.
#[derive(Clone)]
pub struct MockVerifierKey {
    id: KeyId,
    material: [u8; 32],
}

impl std::fmt::Debug for MockVerifierKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MockVerifierKey([REDACTED])")
    }
}

impl MockVerifierKey {
    /// Deterministically derives a verifier key from an explicit seed.
    pub fn from_seed(seed: &[u8]) -> Self {
        let material = derive_material(seed, VERIFIER_LABEL);
        Self {
            id: KeyId::from_material(&material),
            material,
        }
    }

    /// Returns the derived key id.
    pub fn id(&self) -> &KeyId {
        &self.id
    }

    /// Authenticates `message` under this key.
    pub fn authenticate(&self, message: &[u8]) -> [u8; 32] {
        hmac_sha256(&self.material, message)
    }

    /// Raw key material, for directory registration inside this crate only.
    pub(crate) fn signing_material(&self) -> [u8; 32] {
        self.material
    }
}

/// Test attester key: constructs signed mock evidence.
#[derive(Clone)]
pub struct MockAttesterKey {
    id: KeyId,
    material: [u8; 32],
}

impl std::fmt::Debug for MockAttesterKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MockAttesterKey([REDACTED])")
    }
}

impl MockAttesterKey {
    /// Deterministically derives an attester key from an explicit seed.
    pub fn from_seed(seed: &[u8]) -> Self {
        let material = derive_material(seed, ATTESTER_LABEL);
        Self {
            id: KeyId::from_material(&material),
            material,
        }
    }

    /// Returns the derived key id.
    pub fn id(&self) -> &KeyId {
        &self.id
    }

    /// Authenticates `message` under this key.
    pub fn authenticate(&self, message: &[u8]) -> [u8; 32] {
        hmac_sha256(&self.material, message)
    }

    /// Raw key material, for directory registration inside this crate only.
    pub(crate) fn signing_material(&self) -> [u8; 32] {
        self.material
    }
}

/// Ephemeral session key held only by the mock local key owner.
#[derive(Clone)]
pub struct MockSessionKey {
    id: KeyId,
    handle: [u8; SESSION_HANDLE_LENGTH],
    material: [u8; 32],
}

impl std::fmt::Debug for MockSessionKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MockSessionKey([REDACTED])")
    }
}

impl MockSessionKey {
    /// Deterministically derives a session key from an explicit seed.
    pub fn from_seed(seed: &[u8]) -> Self {
        let material = derive_material(seed, SESSION_LABEL);
        let handle = hmac_sha256(&material, HANDLE_LABEL);
        Self {
            id: KeyId::from_material(&material),
            handle,
            material,
        }
    }

    /// Returns the derived key id.
    pub fn id(&self) -> &KeyId {
        &self.id
    }

    /// Returns the 32-byte lookup-handle value for constructing the
    /// model crate's `SessionPublicKeyId` by the caller. Plain text by
    /// design: this crate has no model dependency to link against.
    pub fn handle_bytes(&self) -> &[u8; SESSION_HANDLE_LENGTH] {
        &self.handle
    }

    /// Authenticates `message` under this key.
    pub fn authenticate(&self, message: &[u8]) -> [u8; 32] {
        hmac_sha256(&self.material, message)
    }

    /// Raw key material, for directory registration inside this crate only.
    pub(crate) fn signing_material(&self) -> [u8; 32] {
        self.material
    }
}

/// Failure to find a key or authenticate under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryError {
    /// No key with the requested id is registered.
    UnknownKey,
    /// The presented authenticator does not match.
    AuthenticationFailed,
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownKey => formatter.write_str("mock key id is not registered"),
            Self::AuthenticationFailed => formatter.write_str("mock authentication failed"),
        }
    }
}

impl std::error::Error for DirectoryError {}

/// In-process registry of mock verifier and attester keys.
///
/// Models the ADR-0016 key-compromise boundary: wrong or unknown key ids
/// fail closed here, never as a cryptographic property of the symmetric
/// authenticator.
#[derive(Debug, Clone, Default)]
pub struct MockKeyDirectory {
    verifier_keys: Vec<(KeyId, [u8; 32])>,
    attester_keys: Vec<(KeyId, [u8; 32])>,
    session_keys: Vec<([u8; SESSION_HANDLE_LENGTH], [u8; 32])>,
}

impl MockKeyDirectory {
    /// Creates an empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a verifier test signing key.
    pub fn register_verifier(&mut self, key: &MockVerifierKey) {
        self.verifier_keys
            .push((key.id.clone(), key.signing_material()));
    }

    /// Registers a test attester key.
    pub fn register_attester(&mut self, key: &MockAttesterKey) {
        self.attester_keys
            .push((key.id.clone(), key.signing_material()));
    }

    /// Verifies an authenticator under a registered verifier key.
    pub fn verify_verifier(
        &self,
        key_id: &KeyId,
        message: &[u8],
        presented: &[u8; 32],
    ) -> Result<(), DirectoryError> {
        let material = self
            .verifier_keys
            .iter()
            .find(|(candidate, _)| candidate == key_id)
            .map(|(_, material)| *material);
        match material {
            Some(material) => {
                let expected = hmac_sha256(&material, message);
                if fixed_time_equal(&expected, presented) {
                    Ok(())
                } else {
                    Err(DirectoryError::AuthenticationFailed)
                }
            }
            None => Err(DirectoryError::UnknownKey),
        }
    }

    /// Registers an ephemeral session key for relying-party proof
    /// validation (the trusted mock channel for the actual key; ADR-0008
    /// handle semantics still apply: the handle alone grants nothing).
    pub fn register_session(&mut self, key: &MockSessionKey) {
        self.session_keys
            .push((*key.handle_bytes(), key.signing_material()));
    }

    /// Returns session-key material by lookup handle, if registered.
    pub fn session_material_by_handle(
        &self,
        handle: &[u8; SESSION_HANDLE_LENGTH],
    ) -> Option<[u8; 32]> {
        self.session_keys
            .iter()
            .find(|(candidate, _)| candidate == handle)
            .map(|(_, material)| *material)
    }

    /// Verifies an authenticator under a registered attester key.
    pub fn verify_attester(
        &self,
        key_id: &KeyId,
        message: &[u8],
        presented: &[u8; 32],
    ) -> Result<(), DirectoryError> {
        let material = self
            .attester_keys
            .iter()
            .find(|(candidate, _)| candidate == key_id)
            .map(|(_, material)| *material);
        match material {
            Some(material) => {
                let expected = hmac_sha256(&material, message);
                if fixed_time_equal(&expected, presented) {
                    Ok(())
                } else {
                    Err(DirectoryError::AuthenticationFailed)
                }
            }
            None => Err(DirectoryError::UnknownKey),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_seed_sensitive() {
        let left = MockVerifierKey::from_seed(b"seed-a");
        let right = MockVerifierKey::from_seed(b"seed-a");
        let other = MockVerifierKey::from_seed(b"seed-b");
        assert_eq!(left.id(), right.id());
        assert_eq!(left.authenticate(b"m"), right.authenticate(b"m"));
        assert_ne!(left.id(), other.id());
        assert_ne!(left.authenticate(b"m"), other.authenticate(b"m"));
    }

    #[test]
    fn key_classes_have_distinct_derivation_domains() {
        let seed = b"shared-seed";
        let verifier = MockVerifierKey::from_seed(seed);
        let attester = MockAttesterKey::from_seed(seed);
        let session = MockSessionKey::from_seed(seed);
        assert_ne!(verifier.id().as_bytes(), attester.id().as_bytes());
        assert_ne!(verifier.id().as_bytes(), session.id().as_bytes());
        assert_ne!(attester.id().as_bytes(), session.id().as_bytes());
    }

    #[test]
    fn key_ids_carry_the_mock_namespace() {
        let verifier = MockVerifierKey::from_seed(b"ns");
        assert_eq!(&verifier.id().as_bytes()[..8], KEY_NAMESPACE);
        let attester = MockAttesterKey::from_seed(b"ns");
        assert_eq!(&attester.id().as_bytes()[..8], KEY_NAMESPACE);
        let session = MockSessionKey::from_seed(b"ns");
        assert_eq!(&session.id().as_bytes()[..8], KEY_NAMESPACE);
    }

    #[test]
    fn session_handle_is_stable_and_full_length() {
        let left = MockSessionKey::from_seed(b"handle-seed");
        let right = MockSessionKey::from_seed(b"handle-seed");
        assert_eq!(left.handle_bytes(), right.handle_bytes());
        assert_eq!(left.handle_bytes().len(), SESSION_HANDLE_LENGTH);
    }

    #[test]
    fn directory_fails_closed_on_unknown_and_wrong_keys() {
        let known = MockVerifierKey::from_seed(b"known");
        let unknown = MockVerifierKey::from_seed(b"unknown");
        let mut directory = MockKeyDirectory::new();
        directory.register_verifier(&known);

        let message = b"message";
        let good = known.authenticate(message);
        let wrong = unknown.authenticate(message);
        assert_eq!(
            directory.verify_verifier(known.id(), message, &good),
            Ok(())
        );
        assert_eq!(
            directory.verify_verifier(unknown.id(), message, &wrong),
            Err(DirectoryError::UnknownKey)
        );
        assert_eq!(
            directory.verify_verifier(known.id(), message, &wrong),
            Err(DirectoryError::AuthenticationFailed)
        );
        let attester = MockAttesterKey::from_seed(b"attester");
        assert_eq!(
            directory.verify_attester(attester.id(), message, &attester.authenticate(message)),
            Err(DirectoryError::UnknownKey)
        );
    }

    #[test]
    fn debug_output_redacts_all_key_material() {
        let verifier = MockVerifierKey::from_seed(b"redact");
        let attester = MockAttesterKey::from_seed(b"redact");
        let session = MockSessionKey::from_seed(b"redact");
        assert_eq!(format!("{:?}", verifier), "MockVerifierKey([REDACTED])");
        assert_eq!(format!("{:?}", attester), "MockAttesterKey([REDACTED])");
        assert_eq!(format!("{:?}", session), "MockSessionKey([REDACTED])");
        assert_eq!(format!("{:?}", verifier.id()), "KeyId([REDACTED])");
    }
}
