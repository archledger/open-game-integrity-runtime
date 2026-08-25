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
