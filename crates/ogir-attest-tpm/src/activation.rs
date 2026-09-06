// SPDX-License-Identifier: Apache-2.0

//! The EK-bound credential-activation enrollment prototype (ADR-0024;
//! roadmap spike 3). The verifier seals an enrollment token to the
//! client's EK public key and AK name with TPM2_MakeCredential; the
//! client recovers it with TPM2_ActivateCredential, proving possession
//! of BOTH the endorsement key and the attestation key in one
//! operation. The recovered token equals the issued token only for the
//! genuine key holder.
//!
//! Prototype scope: the flow demonstrates the EK/AK binding property
//! with locally-created keys on swtpm. Production enrollment adds
//! endorsement-authentication of the EK, nonce freshness in the token,
//! and registry integration; those remain specified-not-implemented.

use ogir_attest::BackendError;
use tss_esapi::Context;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    Digest, EncryptedSecret, HashScheme, IdObject, Name, PcrSelectionListBuilder, PcrSlot,
    PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaScheme, SymmetricDefinitionObject,
};

fn map_error(error: tss_esapi::Error) -> BackendError {
    match error {
        tss_esapi::Error::WrapperError(_) => BackendError::InvalidRequest,
        _ => BackendError::Internal,
    }
}

/// The client-side key pair for the activation flow: one EK-restricted
/// decryption primary and one AK restricted-signing primary, both under
/// the Endorsement hierarchy with empty password auth.
#[derive(Debug)]
pub struct ActivationKeys {
    pub context: Context,
    pub ek_handle: tss_esapi::handles::KeyHandle,
    pub ak_handle: tss_esapi::handles::KeyHandle,
}

/// The material the client sends to the verifier for MakeCredential.
#[derive(Debug, Clone)]
pub struct ActivationRequest {
    /// The marshaled EK public area.
    pub ek_public: Vec<u8>,
    /// The AK's TPM name.
    pub ak_name: Vec<u8>,
}

/// The verifier's sealed output.
#[derive(Debug, Clone)]
pub struct SealedCredential {
    pub credential_blob: Vec<u8>,
    pub secret: Vec<u8>,
}

fn ek_public() -> Result<tss_esapi::structures::Public, BackendError> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(false)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .map_err(map_error)?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_rsa_unique_identifier(PublicKeyRsa::try_from(Vec::new()).map_err(map_error)?)
        .with_object_attributes(attributes)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_256_CFB,
                RsaKeyBits::Rsa2048,
                tss_esapi::structures::RsaExponent::default(),
            )
            .build()
            .map_err(map_error)?,
        )
        .build()
        .map_err(map_error)
}

fn ak_public() -> Result<tss_esapi::structures::Public, BackendError> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(false)
        .with_restricted(true)
        .build()
        .map_err(map_error)?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_rsa_unique_identifier(PublicKeyRsa::try_from(Vec::new()).map_err(map_error)?)
        .with_object_attributes(attributes)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(tss_esapi::structures::RsaExponent::default())
                .with_is_signing_key(true)
                .with_is_decryption_key(false)
                .with_restricted(true)
                .build()
                .map_err(map_error)?,
        )
        .build()
        .map_err(map_error)
}

impl ActivationKeys {
    /// Connects to the client swtpm and creates the EK and AK primaries
    /// under the Endorsement hierarchy.
    pub fn create(host: &str, port: u16) -> Result<Self, BackendError> {
        use std::str::FromStr;
        let config =
            tss_esapi::tcti_ldr::NetworkTPMConfig::from_str(&format!("host={host},port={port}"))
                .map_err(map_error)?;
        let mut context =
            Context::new(tss_esapi::tcti_ldr::TctiNameConf::Swtpm(config)).map_err(map_error)?;
        context.set_sessions((
            Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
            None,
            None,
        ));
        let ek_handle = context
            .create_primary(Hierarchy::Endorsement, ek_public()?, None, None, None, None)
            .map_err(map_error)?
            .key_handle;
        let ak_handle = context
            .create_primary(Hierarchy::Endorsement, ak_public()?, None, None, None, None)
            .map_err(map_error)?
            .key_handle;
        Ok(Self {
            context,
            ek_handle,
            ak_handle,
        })
    }

    /// The activation request for the verifier: the marshaled EK public
    /// and the AK name.
    pub fn request(&mut self) -> Result<ActivationRequest, BackendError> {
        self.context.clear_sessions();
        let (ek_pub, _ek_name, _) = self
            .context
            .read_public(self.ek_handle)
            .map_err(map_error)?;
        let (_ak_pub, ak_name, _) = self
            .context
            .read_public(self.ak_handle)
            .map_err(map_error)?;
        let ek_public =
            tss_esapi::traits::Marshall::marshall(&ek_pub).map_err(|_| BackendError::Internal)?;
        Ok(ActivationRequest {
            ek_public,
            ak_name: ak_name.value().to_vec(),
        })
    }

    /// Recovers the credential, proving possession of both keys.
    pub fn activate(&mut self, sealed: &SealedCredential) -> Result<Vec<u8>, BackendError> {
        // ActivateCredential authorizes BOTH the AK (session 1) and the
        // EK (session 2); empty-password auth satisfies each.
        self.context.set_sessions((
            Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
            Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
            None,
        ));
        let credential = self
            .context
            .activate_credential(
                self.ak_handle,
                self.ek_handle,
                IdObject::try_from(sealed.credential_blob.clone()).map_err(map_error)?,
                EncryptedSecret::try_from(sealed.secret.clone()).map_err(map_error)?,
            )
            .map_err(map_error)?;
        Ok(credential.value().to_vec())
    }

    /// The AK modulus, for enrollment records.
    pub fn ak_modulus(&mut self) -> Result<Vec<u8>, BackendError> {
        self.context.clear_sessions();
        let (public, _name, _) = self
            .context
            .read_public(self.ak_handle)
            .map_err(map_error)?;
        match public {
            tss_esapi::structures::Public::Rsa { unique, .. } => Ok(unique.value().to_vec()),
            _ => Err(BackendError::Internal),
        }
    }
}

/// The verifier side: seals a token to the EK public and AK name.
pub fn seal_credential(
    verifier: &mut Context,
    request: &ActivationRequest,
    token: [u8; 32],
) -> Result<SealedCredential, BackendError> {
    let ek_public = tss_esapi::structures::PublicBuffer::try_from(request.ek_public.clone())
        .map_err(map_error)?;
    let public = tss_esapi::structures::Public::try_from(ek_public).map_err(map_error)?;
    let ek_handle = verifier
        .load_external_public(public, Hierarchy::Null)
        .map_err(map_error)?;
    let name = Name::try_from(request.ak_name.clone()).map_err(map_error)?;
    let (blob, secret) = verifier
        .make_credential(
            ek_handle,
            Digest::try_from(token.to_vec()).map_err(map_error)?,
            name,
        )
        .map_err(map_error)?;
    let _ = verifier.flush_context(ek_handle.into());
    Ok(SealedCredential {
        credential_blob: blob.value().to_vec(),
        secret: secret.value().to_vec(),
    })
}

/// A helper the verifier can use to establish its swtpm context.
pub fn verifier_context(host: &str, port: u16) -> Result<Context, BackendError> {
    use std::str::FromStr;
    let config =
        tss_esapi::tcti_ldr::NetworkTPMConfig::from_str(&format!("host={host},port={port}"))
            .map_err(map_error)?;
    Context::new(tss_esapi::tcti_ldr::TctiNameConf::Swtpm(config)).map_err(map_error)
}

/// Keeps the selected experimental PCR slot referenced so the module
/// compiles standalone in future extensions.
#[allow(dead_code)]
fn experimental_selection() -> Result<tss_esapi::structures::PcrSelectionList, BackendError> {
    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot16])
        .build()
        .map_err(map_error)
}
