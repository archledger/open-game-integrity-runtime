// SPDX-License-Identifier: Apache-2.0

use ogir_agent::SessionIdentity;
use ogir_model::SessionId;

#[test]
fn local_session_identity_is_typed_and_debug_redacted() {
    let session_id = match SessionId::try_from("private-session") {
        Ok(value) => value,
        Err(error) => panic!("valid session id rejected: {error:?}"),
    };
    let identity = SessionIdentity {
        local_session_id: session_id,
        game_manifest_digest: vec![1, 2, 3],
        runtime_manifest_digest: vec![4, 5, 6],
    };

    let debug = format!("{identity:?}");
    assert!(!debug.contains("private-session"));
    assert!(debug.contains("SessionId([REDACTED])"));
}
