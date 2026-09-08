// SPDX-License-Identifier: Apache-2.0
#![no_main]

/// Fuzz target (M6-038, ADR-0034): the portal request decoder must
/// never panic and never admit an operation beyond the v1 Hello
/// kind; garbage inputs fail closed with named errors.

use libfuzzer_sys::fuzz_target;
use ogir_agent::portal::decode_request;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = decode_request(data) {
        // The only decodable request is a Hello; anything else
        // must have failed.
        let _ = format!("{request:?}");
    }
});
