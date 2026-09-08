// SPDX-License-Identifier: Apache-2.0
#![no_main]

/// Fuzz target (M6-038, ADR-0034): the strict flat-object JSON
/// codec must never panic, hang, or accept a malformed shape - any
/// input either decodes to flat members or fails closed with a
/// named error. Also asserts the round-trip invariant for inputs
/// that DO decode: re-encoding the members is bounded.

use libfuzzer_sys::fuzz_target;
use ogir_verifier::bjson::{decode_object, encode_object};

fuzz_target!(|data: &[u8]| {
    if let Ok(members) = decode_object(data) {
        // Decoding succeeded: the members must be well-formed and
        // bounded by construction; re-encoding must not explode.
        let borrowed: Vec<(&str, ogir_verifier::bjson::Value)> = members
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect();
        let encoded = encode_object(&borrowed);
        assert!(encoded.len() <= ogir_verifier::bjson::MAX_WIRE * 2);
    }
});
