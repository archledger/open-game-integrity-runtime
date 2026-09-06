// SPDX-License-Identifier: Apache-2.0

//! M2-019 conformance vectors: deterministic objects from fixed seeds,
//! checked byte for byte against frozen hex vectors and against a
//! deliberately independent second encoder (ADR-0015's validation
//! obligation: two constructions, identical bytes).

use ogir_mock_keys::keys::{MockAttesterKey, MockKeyDirectory, MockSessionKey, MockVerifierKey};
use ogir_mock_protocol::objects::{
    MockChallenge, MockClaim, MockEvidence, MockPermit, Provenance, build_pop,
    build_signed_challenge, build_signed_evidence, build_signed_permit, verify_signed_challenge,
    verify_signed_evidence, verify_signed_permit,
};
use ogir_mock_protocol::transcript::{TAG_CHALLENGE, TAG_EVIDENCE, TAG_PERMIT, TAG_POP};
use ogir_model::ProtocolVersion;

const CHALLENGE_HEX: &str = "4f4749522d4d4f434b2d4348414c4c454e47452d31000100000002000000020000000200010003000000067075622e636600040000000767616d652e63660005000000086275696c642e6366000600000007616363742e63660007000000086d617463682e6366000800000009706f6c6963792e636600090000000400000007000a00000020c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1000b0000000800000000000001f4000c000000080000000000000384000d0000000a70726f66696c652e6366000e000000104f4749524d4f434bead5bfe1e415397a3557337109cfdd60b9a7b2497987738044f6a9a11e7c3c6d9c93c8e92ef21759";
const EVIDENCE_HEX: &str = "4f4749522d4d4f434b2d45564944454e43452d310001000001084f4749522d4d4f434b2d4348414c4c454e47452d31000100000002000000020000000200010003000000067075622e636600040000000767616d652e63660005000000086275696c642e6366000600000007616363742e63660007000000086d617463682e6366000800000009706f6c6963792e636600090000000400000007000a00000020c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1000b0000000800000000000001f4000c000000080000000000000384000d0000000a70726f66696c652e6366000e000000104f4749524d4f434bead5bfe1e415397a3557337109cfdd60b9a7b2497987738044f6a9a11e7c3c6d9c93c8e92ef2175900020000000a70726f66696c652e6366000300000020866d4d9e51588f21d0a68dc15d7f2666e1d5ddbd0a3be9cf112ba571e580cd880004000000104f4749524d4f434ba640f2830f265c6300050000000c617574686f726974792e636600060000000800000000000000030007000000080000000000000005000800000008000000000000022600090000000800000000000002580010000000040101010100110000000401020202001200000004020303030013000000040204040400140000000403050505001500000004030606060016000000040307070700170000000403080808001800000003019a9a001a000000065e5e5e5e5e5e001b000000104f4749524d4f434b69b326050e0a4155975ca9cfa35a5615015abe137d5ce32249cd3af313a82fa3994635a9d3480057";
const PERMIT_HEX: &str = "4f4749522d4d4f434b2d5045524d49542d31000100000002000000020000000200010003000000097065726d69742e636600040000000a73657373696f6e2e6366000500000020866d4d9e51588f21d0a68dc15d7f2666e1d5ddbd0a3be9cf112ba571e580cd88000600000020c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1000700000009706f6c6963792e6366000800000004000000070009000000080000000000000258000a000000080000000000000320000b000000104f4749524d4f434bead5bfe1e415397a4608dda35685a0c041a9cbd9d9b25723869259f3c1aa8817e1f9367ff0250dc6";
const POP_HEX: &str = "4f4749522d4d4f434b2d504f502d31000100000020de783b4c1bbf5f0b44549e2613c40c1800eaa5fb012f783bf8ebb5b5fcbc31fe000200000020cfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcf09862a9c397c57fe671c638d39afaf57cc2e354cb78738a7987ebb1571a673b8";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The independent second encoder: no shared helpers with the crate's
/// `transcript::encode`; explicit big-endian pushes only.
struct IndependentEncoder {
    bytes: Vec<u8>,
}

impl IndependentEncoder {
    fn new(tag: &str) -> Self {
        Self {
            bytes: tag.as_bytes().to_vec(),
        }
    }

    fn field(&mut self, id: u16, value: &[u8]) {
        self.bytes.push((id >> 8) as u8);
        self.bytes.push((id & 0xFF) as u8);
        let length = value.len() as u32;
        self.bytes.push((length >> 24) as u8);
        self.bytes.push(((length >> 16) & 0xFF) as u8);
        self.bytes.push(((length >> 8) & 0xFF) as u8);
        self.bytes.push((length & 0xFF) as u8);
        self.bytes.extend_from_slice(value);
    }

    fn u16_field(&mut self, id: u16, value: u16) {
        self.field(id, &value.to_be_bytes());
    }

    fn u32_field(&mut self, id: u16, value: u32) {
        self.field(id, &value.to_be_bytes());
    }

    fn u64_field(&mut self, id: u16, value: u64) {
        self.field(id, &value.to_be_bytes());
    }

    fn text_field(&mut self, id: u16, value: &str) {
        self.field(id, value.as_bytes());
    }

    fn finish(mut self, authenticator: &[u8; 32]) -> Vec<u8> {
        self.bytes.extend_from_slice(authenticator);
        self.bytes
    }
}

/// Directory, three keys, and the four frozen objects, in that order.
type Fixture = (
    MockKeyDirectory,
    MockVerifierKey,
    MockAttesterKey,
    MockSessionKey,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

fn fixture() -> Fixture {
    let verifier = MockVerifierKey::from_seed(b"m2-019-conformance-verifier");
    let attester = MockAttesterKey::from_seed(b"m2-019-conformance-attester");
    let session = MockSessionKey::from_seed(b"m2-019-conformance-session");
    let mut directory = MockKeyDirectory::new();
    directory.register_verifier(&verifier);
    directory.register_attester(&attester);
    directory.register_session(&session);

    let challenge = MockChallenge {
        version: ProtocolVersion { major: 0, minor: 1 },
        publisher_id: "pub.cf".to_string(),
        game_id: "game.cf".to_string(),
        build_id: "build.cf".to_string(),
        account_scope: "acct.cf".to_string(),
        match_id: "match.cf".to_string(),
        policy_id: "policy.cf".to_string(),
        policy_version: 7,
        nonce: [0xC1; 32],
        issued_at: 500,
        expires_at: 900,
        evidence_profile_id: "profile.cf".to_string(),
        issuer_key_id: [0; 16],
    };
    let challenge_bytes =
        build_signed_challenge(&challenge, &verifier).unwrap_or_else(|e| panic!("{e:?}"));

    let evidence = MockEvidence {
        challenge_object: challenge_bytes.clone(),
        evidence_profile_id: "profile.cf".to_string(),
        session_key_handle: *session.handle_bytes(),
        session_key_id: *session.id().as_bytes(),
        collection_authority_contract_id: "authority.cf".to_string(),
        epoch_relation: 3,
        collection_sequence: 5,
        collection_start: 550,
        snapshot_freeze_end: 600,
        base_claims: std::array::from_fn(|slot| MockClaim {
            provenance: match slot {
                0 | 1 => Provenance::HardwareCertified,
                2 | 3 => Provenance::MeasuredLogDerived,
                _ => Provenance::TrustedAgentObserved,
            },
            identity: vec![slot as u8 + 1; 3],
        }),
        profile_claims: vec![MockClaim {
            provenance: Provenance::HardwareCertified,
            identity: vec![0x9A; 2],
        }],
        manifest_identities: vec![0x5E; 6],
        attester_key_id: [0; 16],
    };
    let evidence_bytes =
        build_signed_evidence(&evidence, &attester).unwrap_or_else(|e| panic!("{e:?}"));

    let permit = MockPermit {
        version: ProtocolVersion { major: 0, minor: 1 },
        permit_id: "permit.cf".to_string(),
        session_id: "session.cf".to_string(),
        session_key_handle: *session.handle_bytes(),
        appraised_nonce: [0xC1; 32],
        policy_id: "policy.cf".to_string(),
        policy_version: 7,
        issued_at: 600,
        expires_at: 800,
        issuer_key_id: [0; 16],
    };
    let permit_bytes = build_signed_permit(&permit, &verifier).unwrap_or_else(|e| panic!("{e:?}"));

    let pop_bytes =
        build_pop(&session, &permit_bytes, &[0xCF; 32]).unwrap_or_else(|e| panic!("{e:?}"));

    (
        directory,
        verifier,
        attester,
        session,
        challenge_bytes,
        evidence_bytes,
        permit_bytes,
        pop_bytes,
    )
}

#[test]
fn conformance_vectors_are_frozen_and_reproducible() {
    let (
        directory,
        _verifier,
        _attester,
        _session,
        challenge_bytes,
        evidence_bytes,
        permit_bytes,
        pop_bytes,
    ) = fixture();

    let values = [
        ("challenge", &challenge_bytes, CHALLENGE_HEX),
        ("evidence", &evidence_bytes, EVIDENCE_HEX),
        ("permit", &permit_bytes, PERMIT_HEX),
        ("pop", &pop_bytes, POP_HEX),
    ];
    let mut incomplete = false;
    for (name, bytes, frozen) in &values {
        let actual = hex(bytes);
        if *frozen == "PENDING" {
            println!("FROZEN {name} = {actual}");
            incomplete = true;
        } else {
            assert_eq!(&actual, frozen, "conformance drift for {name}");
        }
    }
    assert!(
        !incomplete,
        "vectors not frozen yet; run once and embed the printed hex"
    );

    // The frozen vectors must also verify as live objects.
    assert!(verify_signed_challenge(&directory, &challenge_bytes).is_ok());
    assert!(verify_signed_evidence(&directory, &evidence_bytes).is_ok());
    assert!(verify_signed_permit(&directory, &permit_bytes).is_ok());
}

#[test]
fn independent_second_encoder_agrees_byte_for_byte() {
    let (
        _directory,
        verifier,
        attester,
        session,
        challenge_bytes,
        evidence_bytes,
        permit_bytes,
        pop_bytes,
    ) = fixture();

    // Challenge, rebuilt by hand.
    let mut encoder = IndependentEncoder::new(TAG_CHALLENGE);
    encoder.u16_field(0x0001, 0);
    encoder.u16_field(0x0002, 1);
    encoder.text_field(0x0003, "pub.cf");
    encoder.text_field(0x0004, "game.cf");
    encoder.text_field(0x0005, "build.cf");
    encoder.text_field(0x0006, "acct.cf");
    encoder.text_field(0x0007, "match.cf");
    encoder.text_field(0x0008, "policy.cf");
    encoder.u32_field(0x0009, 7);
    encoder.field(0x000A, &[0xC1; 32]);
    encoder.u64_field(0x000B, 500);
    encoder.u64_field(0x000C, 900);
    encoder.text_field(0x000D, "profile.cf");
    encoder.field(0x000E, verifier.id().as_bytes());
    let split = challenge_bytes.len() - 32;
    let challenge_authenticator: [u8; 32] = challenge_bytes[split..]
        .try_into()
        .unwrap_or_else(|_| panic!("slice"));
    assert_eq!(encoder.finish(&challenge_authenticator), challenge_bytes);

    // Evidence, rebuilt by hand over the same inputs.
    let mut encoder = IndependentEncoder::new(TAG_EVIDENCE);
    encoder.field(0x0001, &challenge_bytes);
    encoder.text_field(0x0002, "profile.cf");
    encoder.field(0x0003, session.handle_bytes());
    encoder.field(0x0004, session.id().as_bytes());
    encoder.text_field(0x0005, "authority.cf");
    encoder.u64_field(0x0006, 3);
    encoder.u64_field(0x0007, 5);
    encoder.u64_field(0x0008, 550);
    encoder.u64_field(0x0009, 600);
    for slot in 0u16..8 {
        let provenance = match slot {
            0 | 1 => 1u8,
            2 | 3 => 2u8,
            _ => 3u8,
        };
        let mut value = vec![provenance];
        value.extend_from_slice(&[(slot as u8 + 1).to_be_bytes()[0]; 3]);
        encoder.field(0x0010 + slot, &value);
    }
    encoder.field(0x0018, &[&[1u8], &[0x9A; 2][..]].concat());
    encoder.field(0x001A, &[0x5E; 6]);
    encoder.field(0x001B, attester.id().as_bytes());
    let split = evidence_bytes.len() - 32;
    let evidence_authenticator: [u8; 32] = evidence_bytes[split..]
        .try_into()
        .unwrap_or_else(|_| panic!("slice"));
    assert_eq!(encoder.finish(&evidence_authenticator), evidence_bytes);

    // Permit, rebuilt by hand.
    let mut encoder = IndependentEncoder::new(TAG_PERMIT);
    encoder.u16_field(0x0001, 0);
    encoder.u16_field(0x0002, 1);
    encoder.text_field(0x0003, "permit.cf");
    encoder.text_field(0x0004, "session.cf");
    encoder.field(0x0005, session.handle_bytes());
    encoder.field(0x0006, &[0xC1; 32]);
    encoder.text_field(0x0007, "policy.cf");
    encoder.u32_field(0x0008, 7);
    encoder.u64_field(0x0009, 600);
    encoder.u64_field(0x000A, 800);
    encoder.field(0x000B, verifier.id().as_bytes());
    let split = permit_bytes.len() - 32;
    let permit_authenticator: [u8; 32] = permit_bytes[split..]
        .try_into()
        .unwrap_or_else(|_| panic!("slice"));
    assert_eq!(encoder.finish(&permit_authenticator), permit_bytes);

    // Proof of possession, rebuilt by hand.
    let permit_digest = ogir_mock_keys::sha256::sha256(&permit_bytes);
    let mut encoder = IndependentEncoder::new(TAG_POP);
    encoder.field(0x0001, &permit_digest);
    encoder.field(0x0002, &[0xCF; 32]);
    let split = pop_bytes.len() - 32;
    let pop_authenticator: [u8; 32] = pop_bytes[split..]
        .try_into()
        .unwrap_or_else(|_| panic!("slice"));
    assert_eq!(encoder.finish(&pop_authenticator), pop_bytes);
}
