// SPDX-License-Identifier: Apache-2.0

//! The software-TPM backend: a restricted-signing attestation key (AK)
//! created as a primary under the Owner hierarchy on a swtpm instance,
//! producing TPM 2.0 quotes over the selected experimental PCR with the
//! caller's qualifying data bound into the quote (ADR-0018).
//!
//! Statement contract v3 (ADR-0020): `qualifying_digest` is the TPM's
//! attested PCR digest (32 bytes; SHA-256 bank), and `quote_payload`
//! is a length-prefixed encoding of [echoed qualifying data, attested
//! PCR digest, RSA signature, AK public modulus, marshaled
//! TPMS_ATTEST bytes]. The modulus binds the statement to the enrolled
//! key; the raw bytes let the verifier check the RSA signature
//! cryptographically; the statement itself grants nothing.

use std::str::FromStr;

use ogir_attest::{
    AssuranceClass, AttestationBackend, AttestationStatement, BackendError, QuoteRequest,
};
use tss_esapi::Context;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    AttestInfo, Data, HashScheme, PcrSelectionListBuilder, PcrSlot, PublicBuilder,
    PublicRsaParametersBuilder, RsaScheme, SignatureScheme,
};
use tss_esapi::tcti_ldr::{NetworkTPMConfig, TctiNameConf};

/// The experimental PCR slot quoted by this backend (debug slot 16).
const EXPERIMENTAL_PCR: PcrSlot = PcrSlot::Slot16;

/// Stable backend identifier (public for validator backend checks).
pub const BACKEND_ID: &str = "swtpm-tpm2-v1";

fn map_tss_error(error: tss_esapi::Error) -> BackendError {
    // Fail closed: any TSS-layer condition maps to a diagnosable seam
    // error without carrying TPM state out of the backend.
    match error {
        tss_esapi::Error::WrapperError(_) => BackendError::InvalidRequest,
        _ => BackendError::Internal,
    }
}

/// Length-prefixed payload field encoding.
fn append_field(payload: &mut Vec<u8>, field: &[u8]) {
    let length = u32::try_from(field.len()).unwrap_or(u32::MAX);
    payload.extend_from_slice(&length.to_be_bytes());
    payload.extend_from_slice(field);
}

/// A software-TPM (swtpm) attestation backend.
#[derive(Debug)]
pub struct SwtpmBackend {
    context: Context,
    ak_handle: tss_esapi::handles::KeyHandle,
    ak_modulus: Vec<u8>,
}

impl SwtpmBackend {
    /// Connects to a running swtpm instance (for example
    /// `127.0.0.1:2321`) and creates the restricted-signing AK primary
    /// under the Owner hierarchy.
    pub fn connect(host: &str, port: u16) -> Result<Self, BackendError> {
        let config = NetworkTPMConfig::from_str(&format!("host={host},port={port}"))
            .map_err(map_tss_error)?;
        let tcti = TctiNameConf::Swtpm(config);
        let mut context = Context::new(tcti).map_err(map_tss_error)?;

        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .with_decrypt(false)
            .with_restricted(true)
            .build()
            .map_err(map_tss_error)?;
        let public = PublicBuilder::new()
            .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::Rsa)
            .with_rsa_unique_identifier(
                tss_esapi::structures::PublicKeyRsa::try_from(Vec::new()).map_err(map_tss_error)?,
            )
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
                    .map_err(map_tss_error)?,
            )
            .build()
            .map_err(map_tss_error)?;

        // CreatePrimary and Quote each require one authorization
        // session; the AK uses empty password auth, so a password
        // session satisfies both.
        context.set_sessions((
            Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
            None,
            None,
        ));
        let result = context
            .create_primary(Hierarchy::Owner, public, None, None, None, None)
            .map_err(map_tss_error)?;
        let ak_modulus = match result.out_public {
            tss_esapi::structures::Public::Rsa { unique, .. } => unique.value().to_vec(),
            _ => return Err(BackendError::Internal),
        };
        Ok(Self {
            context,
            ak_handle: result.key_handle,
            ak_modulus,
        })
    }

    /// The AK's public modulus, for enrollment records (ADR-0019).
    pub fn ak_modulus(&self) -> &[u8] {
        &self.ak_modulus
    }

    fn pcr_selection() -> Result<tss_esapi::structures::PcrSelectionList, BackendError> {
        PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[EXPERIMENTAL_PCR])
            .build()
            .map_err(map_tss_error)
    }
}

impl AttestationBackend for SwtpmBackend {
    fn assurance_class(&self) -> AssuranceClass {
        AssuranceClass::SoftwareTpm
    }

    fn backend_id(&self) -> &str {
        BACKEND_ID
    }

    fn quote(&mut self, request: &QuoteRequest) -> Result<AttestationStatement, BackendError> {
        request.validate()?;
        let qualifying = Data::try_from(request.qualifying_data.clone()).map_err(map_tss_error)?;
        // Restricted signing key: the scheme is fixed in the key
        // template, so the quote-time scheme is Null.
        let (attest, signature) = self
            .context
            .quote(
                self.ak_handle,
                qualifying,
                SignatureScheme::Null,
                Self::pcr_selection()?,
            )
            .map_err(map_tss_error)?;

        let pcr_digest: &[u8] = match attest.attested() {
            AttestInfo::Quote { info } => info.pcr_digest().value(),
            _ => return Err(BackendError::Internal),
        };
        let digest: [u8; 32] = match pcr_digest.try_into() {
            Ok(array) => array,
            Err(_) => return Err(BackendError::Internal),
        };
        let signature_bytes: Vec<u8> = match &signature {
            tss_esapi::structures::Signature::RsaSsa(rsa) => rsa.signature().value().to_vec(),
            _ => return Err(BackendError::Internal),
        };

        let attest_bytes = crate::marshal::marshal_attest(&attest)?;
        let mut payload = Vec::new();
        append_field(&mut payload, attest.extra_data().value());
        append_field(&mut payload, pcr_digest);
        append_field(&mut payload, &signature_bytes);
        append_field(&mut payload, &self.ak_modulus);
        append_field(&mut payload, &attest_bytes);
        AttestationStatement::new(AssuranceClass::SoftwareTpm, BACKEND_ID, digest, payload)
    }
}
