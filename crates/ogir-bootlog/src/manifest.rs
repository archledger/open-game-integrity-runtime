// SPDX-License-Identifier: Apache-2.0

//! The signed reference manifest (ADR-0025): the static, reviewed
//! reference data for ONE platform profile. The manifest carries the
//! profile itself (ADR-0023 schema), the accepted component signing
//! roots, component version floors, and revocations, plus one
//! detached-by-position RSA signature over the exact payload bytes.
//!
//! This module owns structure and policy, never cryptography: the
//! signature is verified against a verifier-pinned anchor through the
//! TPM-backed verifier (`ogir_attest_tpm`), mirroring ADR-0020. The
//! anchor is configuration held by the verifier; a manifest can never
//! declare its own signer.

use std::cmp::Ordering;

use crate::BootlogError;
use crate::profile::PlatformProfile;

/// One accepted component signing root: a name plus the SHA-256
/// fingerprint of the root's DER-encoded certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningRoot {
    pub name: String,
    pub fingerprint: [u8; 32],
}

/// Which versions of a component a revocation covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokedVersion {
    /// Every version of the component.
    All,
    /// Exactly this version.
    Exact(String),
}

/// One revocation entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub component: String,
    pub version: RevokedVersion,
}

/// A parsed reference manifest. `payload_bytes` is the exact input
/// prefix the signature covers (every byte before the signature
/// line); verification must always check those bytes, never a
/// re-serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceManifest {
    pub manifest_version: u32,
    pub profile: PlatformProfile,
    pub signing_roots: Vec<SigningRoot>,
    pub revocations: Vec<Revocation>,
    pub payload_bytes: Vec<u8>,
    pub signature: [u8; 256],
}

impl ReferenceManifest {
    /// Whether `other` is an accepted non-weakening successor of this
    /// manifest: same profile, higher revision, the ADR-0023
    /// non-weakening profile relation (expectations carried forward,
    /// floors only rise, Secure Boot only tightens), no signing root
    /// ADDED (adding a root expands trust and needs a fresh reviewed
    /// acceptance, not a successor bump), and no revocation removed.
    pub fn is_non_weakening_successor(&self, other: &ReferenceManifest) -> bool {
        if other.manifest_version != self.manifest_version {
            return false;
        }
        if !self.profile.is_non_weakening_successor(&other.profile) {
            return false;
        }
        if other
            .signing_roots
            .iter()
            .any(|root| !self.signing_roots.contains(root))
        {
            return false;
        }
        if self
            .revocations
            .iter()
            .any(|revocation| !other.revocations.contains(revocation))
        {
            return false;
        }
        true
    }

    /// Checks a boot component's version against the floors and
    /// revocations. Fail-closed: an undeclared component is never
    /// accepted.
    pub fn check_component(&self, component: &str, version: &str) -> Result<(), BootlogError> {
        for revocation in &self.revocations {
            if revocation.component != component {
                continue;
            }
            let revoked = match &revocation.version {
                RevokedVersion::All => true,
                RevokedVersion::Exact(revoked_version) => {
                    cmp_version(version, revoked_version) == Ordering::Equal
                }
            };
            if revoked {
                return Err(BootlogError::ComponentRevoked);
            }
        }
        match self.profile.minimum_versions.get(component) {
            Some(floor) if cmp_version(version, floor) != Ordering::Less => Ok(()),
            Some(_) => Err(BootlogError::BelowMinimumVersion),
            None => Err(BootlogError::UnknownComponent),
        }
    }

    /// Whether a component signature root fingerprint is accepted by
    /// this manifest.
    pub fn accepts_signing_root(&self, fingerprint: &[u8; 32]) -> bool {
        self.signing_roots
            .iter()
            .any(|root| &root.fingerprint == fingerprint)
    }

    /// Whether an evidence bundle's claimed profile name matches this
    /// manifest's profile. A mismatch is UNSUPPORTED reference data,
    /// never evidence of an attack (ADR-0025: the two stay
    /// distinguishable).
    pub fn matches_profile(&self, claimed_name: &str) -> Result<(), BootlogError> {
        if claimed_name == self.profile.name {
            Ok(())
        } else {
            Err(BootlogError::UnsupportedProfile)
        }
    }
}

/// Compares two canonical version strings as dotted numeric segments
/// ("2026.05" < "2026.10", "2" < "10"). Both inputs must be canonical
/// versions (see [`validate_version`]); the parser guarantees it.
pub fn cmp_version(a: &str, b: &str) -> Ordering {
    let mut left = a.split('.');
    let mut right = b.split('.');
    loop {
        match (left.next(), right.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(left_segment), Some(right_segment)) => {
                // Segments are validated pure digits, bounded to 8
                // characters, so this fold cannot overflow u64.
                let value = |segment: &str| {
                    segment.bytes().fold(0u64, |accumulator, byte| {
                        accumulator * 10 + u64::from(byte - b'0')
                    })
                };
                match value(left_segment).cmp(&value(right_segment)) {
                    Ordering::Equal => continue,
                    ordering => return ordering,
                }
            }
        }
    }
}

/// Accepts only canonical versions: one to four segments of pure
/// ASCII digits (leading zeros allowed: real firmware pins look like
/// "2026.05"), separated by single dots, at most 64 characters.
/// Comparison is numeric per segment, so "05" and "5" are the same
/// version.
pub fn validate_version(text: &str) -> Result<(), BootlogError> {
    let invalid = || BootlogError::InvalidManifest("version field");
    if text.is_empty() || text.len() > 64 || text.starts_with('.') || text.ends_with('.') {
        return Err(invalid());
    }
    if text.split('.').count() > 4 {
        return Err(invalid());
    }
    for segment in text.split('.') {
        if segment.is_empty() || segment.len() > 8 {
            return Err(invalid());
        }
        if !segment.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Accepts only canonical component and root names: ASCII lowercase
/// letters, digits, and hyphens, starting with a letter or digit, at
/// most 64 characters.
fn validate_name(text: &str) -> Result<(), BootlogError> {
    let invalid = || BootlogError::InvalidManifest("name field");
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return Err(invalid());
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(invalid());
    }
    if !bytes[1..]
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(invalid());
    }
    Ok(())
}

/// One lowercase ASCII hex nibble.
fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Decodes exactly `N * 2` lowercase ASCII hex characters into a
/// fixed-size buffer.
fn decode_hex<const N: usize>(text: &str, detail: &'static str) -> Result<[u8; N], BootlogError> {
    let bytes = text.as_bytes();
    if bytes.len() != N * 2 {
        return Err(BootlogError::InvalidManifest(detail));
    }
    let mut output = [0u8; N];
    for index in 0..N {
        match (nibble(bytes[index * 2]), nibble(bytes[index * 2 + 1])) {
            (Some(high), Some(low)) => output[index] = (high << 4) | low,
            _ => return Err(BootlogError::InvalidManifest(detail)),
        }
    }
    Ok(output)
}

/// The parser's line shapes, in the one legal order. Repeatable list
/// fields must also arrive in strictly ascending order (by PCR index,
/// or by name bytes) and without duplicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Section {
    ManifestVersion,
    Profile,
    Revision,
    SecureBoot,
    PcrBank,
    PcrExpectation,
    MinimumVersion,
    SigningRoot,
    Revoked,
    Signature,
}

impl Section {
    fn from_field(field: &str) -> Option<Self> {
        Some(match field {
            "ogir-manifest-version" => Self::ManifestVersion,
            "profile" => Self::Profile,
            "revision" => Self::Revision,
            "secure-boot" => Self::SecureBoot,
            "pcr-bank" => Self::PcrBank,
            "pcr-expectation" => Self::PcrExpectation,
            "minimum-version" => Self::MinimumVersion,
            "signing-root" => Self::SigningRoot,
            "revoked" => Self::Revoked,
            "signature" => Self::Signature,
            _ => return None,
        })
    }
}

/// Parses the canonical manifest bytes. Every deviation fails closed:
/// non-ASCII bytes, CR, tabs, trailing whitespace, empty lines,
/// unknown fields, out-of-order sections, repeated singular fields,
/// unordered or repeated list entries, wrong hex widths, or any byte
/// after the signature line.
pub fn parse_manifest(bytes: &[u8]) -> Result<ReferenceManifest, BootlogError> {
    let text = std::str::from_utf8(bytes).map_err(|_| BootlogError::InvalidManifest("utf-8"))?;
    if text.bytes().any(|byte| !byte.is_ascii()) {
        return Err(BootlogError::InvalidManifest("non-ascii byte"));
    }
    if text.contains('\r') || text.contains('\t') {
        return Err(BootlogError::InvalidManifest("cr or tab"));
    }
    if !text.ends_with('\n') {
        return Err(BootlogError::InvalidManifest("missing final newline"));
    }

    // The signature line must be the last line; the payload is every
    // byte before it.
    let mut payload_end = None;
    let mut signature_value = None;
    for line in text.split_inclusive('\n') {
        if let Some(rest) = line.strip_prefix("signature: ") {
            let start = line.as_ptr() as usize - text.as_ptr() as usize;
            payload_end = Some(start);
            signature_value = Some(rest.trim_end_matches('\n'));
            if start + line.len() != text.len() {
                return Err(BootlogError::InvalidManifest("bytes after signature"));
            }
            break;
        }
    }
    let (Some(payload_end), Some(signature_value)) = (payload_end, signature_value) else {
        return Err(BootlogError::InvalidManifest("no signature line"));
    };
    let payload = &text[..payload_end];
    let signature = decode_hex::<256>(signature_value, "signature width")?;

    let mut seen_singular = [false; 5];
    let mut last_section = Section::ManifestVersion;
    let mut manifest_version: Option<u32> = None;
    let mut profile_name: Option<String> = None;
    let mut revision: Option<u64> = None;
    let mut secure_boot_required: Option<bool> = None;
    let mut pcr_expectations: Vec<(u32, [u8; 32])> = Vec::new();
    let mut minimum_versions: Vec<(String, String)> = Vec::new();
    let mut signing_roots: Vec<SigningRoot> = Vec::new();
    let mut revocations: Vec<Revocation> = Vec::new();

    for line in payload.split_inclusive('\n') {
        let body = line
            .strip_suffix('\n')
            .ok_or(BootlogError::InvalidManifest("line"))?;
        if body.is_empty() {
            return Err(BootlogError::InvalidManifest("empty line"));
        }
        if body.ends_with(' ') {
            return Err(BootlogError::InvalidManifest("trailing space"));
        }
        let (field, value) = body
            .split_once(": ")
            .ok_or(BootlogError::InvalidManifest("field syntax"))?;
        let section =
            Section::from_field(field).ok_or(BootlogError::InvalidManifest("unknown field"))?;

        // Sections may never go backwards; repeatable list sections
        // may repeat; singular sections exactly once.
        let singular_index = match section {
            Section::ManifestVersion => Some(0),
            Section::Profile => Some(1),
            Section::Revision => Some(2),
            Section::SecureBoot => Some(3),
            Section::PcrBank => Some(4),
            _ => None,
        };
        if let Some(index) = singular_index {
            if seen_singular[index] {
                return Err(BootlogError::InvalidManifest("repeated field"));
            }
            seen_singular[index] = true;
        }
        if section < last_section {
            return Err(BootlogError::InvalidManifest("section order"));
        }
        last_section = section;

        match section {
            Section::ManifestVersion => {
                if value != "1" {
                    return Err(BootlogError::InvalidManifest("manifest version"));
                }
                manifest_version = Some(1);
            }
            Section::Profile => {
                validate_name(value)?;
                profile_name = Some(value.to_string());
            }
            Section::Revision => {
                revision = Some(
                    value
                        .parse()
                        .map_err(|_| BootlogError::InvalidManifest("revision"))?,
                );
            }
            Section::SecureBoot => {
                secure_boot_required = Some(match value {
                    "required" => true,
                    "not-required" => false,
                    _ => return Err(BootlogError::InvalidManifest("secure-boot value")),
                });
            }
            Section::PcrBank => {
                if value != "sha256" {
                    return Err(BootlogError::InvalidManifest("pcr bank"));
                }
            }
            Section::PcrExpectation => {
                let (index_text, hex) = value
                    .split_once('=')
                    .ok_or(BootlogError::InvalidManifest("pcr expectation"))?;
                let index: u32 = index_text
                    .parse()
                    .map_err(|_| BootlogError::InvalidManifest("pcr index"))?;
                if index > 23 {
                    return Err(BootlogError::InvalidManifest("pcr index range"));
                }
                let expectation = decode_hex::<32>(hex, "pcr value")?;
                if pcr_expectations
                    .last()
                    .is_some_and(|&(last_index, _)| index <= last_index)
                {
                    return Err(BootlogError::InvalidManifest("pcr order"));
                }
                pcr_expectations.push((index, expectation));
            }
            Section::MinimumVersion => {
                let (component, version) = value
                    .split_once('=')
                    .ok_or(BootlogError::InvalidManifest("minimum version"))?;
                validate_name(component)?;
                validate_version(version)?;
                if minimum_versions.last().is_some_and(|(last_component, _)| {
                    component.as_bytes() <= last_component.as_bytes()
                }) {
                    return Err(BootlogError::InvalidManifest("minimum order"));
                }
                minimum_versions.push((component.to_string(), version.to_string()));
            }
            Section::SigningRoot => {
                let (name, hex) = value
                    .split_once('=')
                    .ok_or(BootlogError::InvalidManifest("signing root"))?;
                validate_name(name)?;
                let fingerprint = decode_hex::<32>(hex, "fingerprint")?;
                if signing_roots
                    .last()
                    .is_some_and(|last_root| name.as_bytes() <= last_root.name.as_bytes())
                {
                    return Err(BootlogError::InvalidManifest("root order"));
                }
                signing_roots.push(SigningRoot {
                    name: name.to_string(),
                    fingerprint,
                });
            }
            Section::Revoked => {
                let (component, version) = value
                    .split_once('=')
                    .ok_or(BootlogError::InvalidManifest("revocation"))?;
                validate_name(component)?;
                let revoked_version = if version == "all" {
                    RevokedVersion::All
                } else {
                    validate_version(version)?;
                    RevokedVersion::Exact(version.to_string())
                };
                if revocations
                    .last()
                    .is_some_and(|last| component.as_bytes() <= last.component.as_bytes())
                {
                    return Err(BootlogError::InvalidManifest("revocation order"));
                }
                revocations.push(Revocation {
                    component: component.to_string(),
                    version: revoked_version,
                });
            }
            Section::Signature => unreachable!("a signature line is never part of the payload"),
        }
    }

    let manifest_version = manifest_version.ok_or(BootlogError::InvalidManifest("no version"))?;
    let name = profile_name.ok_or(BootlogError::InvalidManifest("no profile"))?;
    let revision = revision.ok_or(BootlogError::InvalidManifest("no revision"))?;
    let secure_boot_required =
        secure_boot_required.ok_or(BootlogError::InvalidManifest("no secure-boot"))?;
    if pcr_expectations.is_empty() {
        return Err(BootlogError::InvalidManifest("no pcr expectations"));
    }
    if signing_roots.is_empty() {
        return Err(BootlogError::InvalidManifest("no signing roots"));
    }

    let profile = PlatformProfile {
        name,
        revision,
        pcr_expectations: pcr_expectations.into_iter().collect(),
        secure_boot_required,
        minimum_versions: minimum_versions.into_iter().collect(),
    };
    profile.validate()?;

    Ok(ReferenceManifest {
        manifest_version,
        profile,
        signing_roots,
        revocations,
        payload_bytes: payload.as_bytes().to_vec(),
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PCR_VALUE: &str = "00d5b9c7d21af5b8de9f4e6e6e6f2e5b4d3c2a190817161514131211100f0e0d";

    /// A minimal valid payload with room for a signature line.
    fn canonical_body() -> String {
        let mut text = String::new();
        text.push_str("ogir-manifest-version: 1\n");
        text.push_str("profile: test-image-efi-capture-v1\n");
        text.push_str("revision: 1\n");
        text.push_str("secure-boot: required\n");
        text.push_str("pcr-bank: sha256\n");
        text.push_str("pcr-expectation: 7=");
        text.push_str(PCR_VALUE);
        text.push('\n');
        text.push_str("minimum-version: uki=1\n");
        text.push_str("signing-root: image-key=ab");
        text.push_str(&"ab".repeat(31));
        text.push('\n');
        text
    }

    fn signed(body: &str) -> Vec<u8> {
        let mut bytes = body.as_bytes().to_vec();
        bytes.extend_from_slice(format!("signature: {}\n", "cd".repeat(256)).as_bytes());
        bytes
    }

    #[test]
    fn canonical_manifest_parses() {
        let manifest =
            parse_manifest(&signed(&canonical_body())).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(manifest.profile.name, "test-image-efi-capture-v1");
        assert_eq!(manifest.profile.revision, 1);
        assert!(manifest.profile.secure_boot_required);
        assert_eq!(manifest.signing_roots.len(), 1);
        // The payload is the exact prefix before the signature line.
        assert_eq!(manifest.payload_bytes, canonical_body().as_bytes());
        assert_eq!(manifest.signature, [0xcd; 256]);
    }

    #[test]
    fn version_ordering_is_numeric() {
        assert_eq!(cmp_version("2", "10"), Ordering::Less);
        assert_eq!(cmp_version("2026.05", "2026.10"), Ordering::Less);
        assert_eq!(cmp_version("2026.10", "2026.05"), Ordering::Greater);
        assert_eq!(cmp_version("1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(cmp_version("1.2", "1.2.0"), Ordering::Less);
    }

    #[test]
    fn version_validation_rejects_noncanonical_forms() {
        assert!(validate_version("1").is_ok());
        assert!(validate_version("2026.05").is_ok());
        assert!(validate_version("05").is_ok());
        assert_eq!(cmp_version("05", "5"), Ordering::Equal);
        for bad in ["", "1..2", "1.", ".1", "a1", "1a", "1.2.3.4.5", "123456789"] {
            assert!(validate_version(bad).is_err(), "{bad} must be invalid");
        }
    }

    #[test]
    fn missing_signature_rejects() {
        let error = parse_manifest(canonical_body().as_bytes())
            .err()
            .unwrap_or_else(|| panic!("an unsigned payload must reject"));
        assert_eq!(error, BootlogError::InvalidManifest("no signature line"));
    }

    #[test]
    fn bytes_after_signature_rejects() {
        let mut bytes = signed(&canonical_body());
        bytes.extend_from_slice(b"extra\n");
        assert!(parse_manifest(&bytes).is_err());
    }

    #[test]
    fn crlf_rejects() {
        let crlf = canonical_body().replace('\n', "\r\n");
        assert!(parse_manifest(signed(&crlf).as_slice()).is_err());
    }

    #[test]
    fn unknown_field_rejects() {
        let mut body = canonical_body();
        body.push_str("unexpected: 1\n");
        assert!(parse_manifest(&signed(&body)).is_err());
    }

    #[test]
    fn repeated_singular_field_rejects() {
        let mut body = canonical_body();
        body.push_str("revision: 2\n");
        assert!(parse_manifest(&signed(&body)).is_err());
    }

    #[test]
    fn out_of_order_sections_reject() {
        // revision before profile is out of order.
        let mut body = String::new();
        body.push_str("ogir-manifest-version: 1\n");
        body.push_str("revision: 1\n");
        body.push_str("profile: test-image-efi-capture-v1\n");
        body.push_str("secure-boot: required\n");
        body.push_str("pcr-bank: sha256\n");
        body.push_str("pcr-expectation: 7=");
        body.push_str(PCR_VALUE);
        body.push('\n');
        body.push_str("minimum-version: uki=1\n");
        body.push_str("signing-root: image-key=ab");
        body.push_str(&"ab".repeat(31));
        body.push('\n');
        assert!(parse_manifest(&signed(&body)).is_err());
    }

    #[test]
    fn unordered_pcr_expectations_reject() {
        let mut body = canonical_body();
        body.push_str("pcr-expectation: 3=");
        body.push_str(PCR_VALUE);
        body.push('\n');
        assert!(parse_manifest(&signed(&body)).is_err());
    }

    #[test]
    fn uppercase_hex_rejects() {
        let body = canonical_body().replace(
            PCR_VALUE,
            "00D5B9C7D21AF5B8DE9F4E6E6E6F2E5B4D3C2A190817161514131211100F0E0D",
        );
        assert!(parse_manifest(&signed(&body)).is_err());
    }

    #[test]
    fn wrong_signature_width_rejects() {
        let mut bytes = canonical_body().into_bytes();
        bytes.extend_from_slice(format!("signature: {}\n", "cd".repeat(128)).as_bytes());
        assert!(parse_manifest(&bytes).is_err());
    }

    #[test]
    fn missing_final_newline_rejects() {
        let mut bytes = signed(&canonical_body());
        bytes.pop();
        assert!(parse_manifest(&bytes).is_err());
    }

    #[test]
    fn revocation_all_and_exact_parse() {
        let mut body = canonical_body();
        body.push_str("revoked: capture-uki=all\n");
        body.push_str("revoked: uki=1\n");
        let manifest = parse_manifest(&signed(&body)).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            manifest.revocations,
            vec![
                Revocation {
                    component: "capture-uki".to_string(),
                    version: RevokedVersion::All,
                },
                Revocation {
                    component: "uki".to_string(),
                    version: RevokedVersion::Exact("1".to_string()),
                },
            ]
        );
    }

    #[test]
    fn check_component_distinguishes_reasons() {
        let mut body = canonical_body();
        body.push_str("revoked: uki=1\n");
        let manifest = parse_manifest(&signed(&body)).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            manifest.check_component("uki", "1"),
            Err(BootlogError::ComponentRevoked)
        );
        assert_eq!(manifest.check_component("uki", "2"), Ok(()));
        assert_eq!(
            manifest.check_component("uki", "0"),
            Err(BootlogError::BelowMinimumVersion)
        );
        assert_eq!(
            manifest.check_component("absent", "1"),
            Err(BootlogError::UnknownComponent)
        );
    }

    #[test]
    fn revocation_all_covers_every_version() {
        let mut body = canonical_body();
        body.push_str("revoked: uki=all\n");
        let manifest = parse_manifest(&signed(&body)).unwrap_or_else(|e| panic!("{e:?}"));
        for version in ["1", "2", "99"] {
            assert_eq!(
                manifest.check_component("uki", version),
                Err(BootlogError::ComponentRevoked)
            );
        }
    }

    #[test]
    fn successor_rules_hold() {
        let mut v2_body = canonical_body();
        v2_body = v2_body.replace("revision: 1", "revision: 2");
        v2_body = v2_body.replace("minimum-version: uki=1", "minimum-version: uki=2");
        v2_body.push_str("revoked: uki=1\n");
        let v1 = parse_manifest(&signed(&canonical_body())).unwrap_or_else(|e| panic!("{e:?}"));
        let v2 = parse_manifest(&signed(&v2_body)).unwrap_or_else(|e| panic!("{e:?}"));
        assert!(v1.is_non_weakening_successor(&v2));

        // Removing the revocation weakens.
        let v3 = parse_manifest(&signed(&v2_body.replace("revoked: uki=1\n", "")))
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert!(!v2.is_non_weakening_successor(&v3));

        // Floors compare numerically: 2 -> 10 is a rise that a
        // lexical string compare would wrongly reject.
        let v4 = parse_manifest(&signed(
            &v2_body
                .replace("revision: 2", "revision: 3")
                .replace("minimum-version: uki=2", "minimum-version: uki=10"),
        ))
        .unwrap_or_else(|e| panic!("{e:?}"));
        assert!(v2.is_non_weakening_successor(&v4));
        let v5 = parse_manifest(&signed(
            &v2_body
                .replace("revision: 2", "revision: 3")
                .replace("minimum-version: uki=2", "minimum-version: uki=1"),
        ))
        .unwrap_or_else(|e| panic!("{e:?}"));
        assert!(!v2.is_non_weakening_successor(&v5));

        // Adding a signing root expands trust and is never a
        // successor (inserted in the legal ascending order, before
        // the revocation block).
        let with_root = v2_body.replacen(
            "revoked: uki=1\n",
            &format!(
                "signing-root: other-key={}{}\nrevoked: uki=1\n",
                "cd",
                "cd".repeat(31)
            ),
            1,
        );
        let v6 = parse_manifest(&signed(&with_root)).unwrap_or_else(|e| panic!("{e:?}"));
        assert!(!v2.is_non_weakening_successor(&v6));
    }

    #[test]
    fn profile_mismatch_is_unsupported_not_attack() {
        let manifest =
            parse_manifest(&signed(&canonical_body())).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            manifest.matches_profile("test-image-efi-capture-v1"),
            Ok(())
        );
        assert_eq!(
            manifest.matches_profile("some-other-profile"),
            Err(BootlogError::UnsupportedProfile)
        );
    }
}
