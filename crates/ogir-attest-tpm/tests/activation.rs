// SPDX-License-Identifier: Apache-2.0

//! Integration suite for the EK-bound credential-activation enrollment
//! prototype (ADR-0024): the full seal/activate round trip on real
//! swtpm, plus the EK/AK-confusion and foreign-client rejections.

mod common;

use common::SwtpmInstance;
use ogir_attest_tpm::activation::{ActivationKeys, seal_credential, verifier_context};

#[test]
fn credential_activates_for_the_genuine_key_holder() {
    let instance = SwtpmInstance::start();
    let mut keys = ActivationKeys::create("127.0.0.1", instance.port())
        .unwrap_or_else(|error| panic!("{error:?}"));
    let request = keys.request().unwrap_or_else(|error| panic!("{error:?}"));

    let mut verifier =
        verifier_context("127.0.0.1", instance.port()).unwrap_or_else(|error| panic!("{error:?}"));
    let token = [0xAB; 32];
    let sealed =
        seal_credential(&mut verifier, &request, token).unwrap_or_else(|error| panic!("{error:?}"));

    let recovered = keys
        .activate(&sealed)
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(recovered, token.to_vec());
    // The AK modulus is available for the enrollment record.
    assert_eq!(
        keys.ak_modulus().unwrap_or_else(|e| panic!("{e:?}")).len(),
        256
    );
}

#[test]
fn sealed_credential_rejects_a_foreign_client() {
    // Seal for client A's keys; client B cannot recover the token.
    let holder = SwtpmInstance::start();
    let mut keys_a = ActivationKeys::create("127.0.0.1", holder.port())
        .unwrap_or_else(|error| panic!("{error:?}"));
    let request = keys_a.request().unwrap_or_else(|error| panic!("{error:?}"));
    let mut verifier =
        verifier_context("127.0.0.1", holder.port()).unwrap_or_else(|error| panic!("{error:?}"));
    let sealed = seal_credential(&mut verifier, &request, [0xCD; 32])
        .unwrap_or_else(|error| panic!("{error:?}"));

    let stranger = SwtpmInstance::start();
    let mut keys_b = ActivationKeys::create("127.0.0.1", stranger.port())
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert!(keys_b.activate(&sealed).is_err());
}

#[test]
fn ek_ak_confusion_rejects() {
    // A request whose AK name does not match the activating key's name
    // fails the activation even with the correct EK.
    let instance = SwtpmInstance::start();
    let mut keys = ActivationKeys::create("127.0.0.1", instance.port())
        .unwrap_or_else(|error| panic!("{error:?}"));
    let mut request = keys.request().unwrap_or_else(|error| panic!("{error:?}"));
    // Corrupt the AK name: the credential is no longer bound to this
    // client's AK, so the TPM refuses to activate it.
    let last = request.ak_name.len() - 1;
    request.ak_name[last] ^= 0x01;

    let mut verifier =
        verifier_context("127.0.0.1", instance.port()).unwrap_or_else(|error| panic!("{error:?}"));
    let sealed = seal_credential(&mut verifier, &request, [0xEF; 32])
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert!(keys.activate(&sealed).is_err());
}
