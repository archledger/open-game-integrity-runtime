// SPDX-License-Identifier: Apache-2.0

use ogir_model::EvidenceProfile;
use ogir_protocol::EvidenceBundle;

#[test]
fn evidence_bundle_requires_a_validated_profile() {
    let profile = match EvidenceProfile::try_from("mock-v0") {
        Ok(value) => value,
        Err(error) => panic!("valid evidence profile rejected: {error:?}"),
    };
    let evidence = EvidenceBundle {
        profile_id: profile,
        payload: Vec::new(),
    };

    assert_eq!(evidence.profile_id.as_str(), "mock-v0");
}

#[test]
fn evidence_bundle_debug_redacts_profile_and_payload() {
    let profile_sentinel = "private-profile-sentinel";
    let payload_sentinel = b"private-evidence-payload-sentinel";
    let profile = match EvidenceProfile::try_from(profile_sentinel) {
        Ok(value) => value,
        Err(error) => panic!("valid evidence profile rejected: {error:?}"),
    };
    let evidence = EvidenceBundle {
        profile_id: profile,
        payload: payload_sentinel.to_vec(),
    };

    let diagnostic = format!("{evidence:?}");
    assert!(
        diagnostic == "EvidenceBundle([REDACTED])",
        "private diagnostic mismatch"
    );
    assert!(!diagnostic.contains(profile_sentinel));
    assert!(!diagnostic.contains("private-evidence-payload-sentinel"));
}
