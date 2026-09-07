# ADR-0025: The signed reference manifest and revocation fixtures

- Status: Accepted
- Date: 2026-09-07
- Owners: Initial maintainer
- Related issues: [Local M4-029 issue](../../planning/issues/029-reference-manifest.md)
- Supersedes: None
- Superseded by: None

## Context

M4's fourth exit criterion is that updating the accepted profile
requires signed, reviewed reference data. ADR-0023 delivered the
platform-profile schema and explicitly deferred authenticity to "the
manifest layer's duty in M4-029". The roadmap deliverables open at
M4-029: an accepted signing-root representation, a static signed
reference manifest for the test profile, revocation and
minimum-version fixtures, and user-facing explanations of accepted
and unsupported states. The M4-028c capture fixture (the committed
event log, live PCR read, and quote for one TCG2-OVMF boot of the
TEST-ONLY-signed capture UKI) is the measured truth the reference
data must pin.

## Decision drivers

- No hand-implemented cryptography (AI development policy); no new
  Rust dependencies (the signed inventory stays untouched).
- Reference data must be auditable byte for byte and fail closed on
  any deviation from one canonical form.
- An anchor cannot vouch for itself: the manifest's signer is pinned
  by the verifier, never declared by the manifest.
- Updates must be non-weakening (ADR-0014), and revocation must be
  expressible and enforceable with distinguishable reasons.
- Unsupported and attack-indicating states must remain
  distinguishable (an M4 exit criterion).

## Options considered

1. **Canonical JSON manifest with a detached signature file.**
   Rejected: JSON canonicalization is a known ambiguity hazard (an
   M1 lesson), and a two-file fixture invites desync.
2. **A machine-readable binary format.** Rejected for the same
   auditability reasons the event log itself stays binary only where
   the TCG spec forces it; reference data should be diffable in
   review.
3. **Line-oriented canonical text with the signature as the final
   line, verified through the TPM.** One self-contained artifact;
   the payload is the exact byte prefix before the signature line;
   verification reuses the audited RSASSA-SHA256 TPM path from
   ADR-0020 with zero new trust surface.

## Decision

Adopt option 3. `ogir-bootlog::manifest` defines the canonical
grammar (versioned header, profile identity, Secure Boot state, the
SHA-256 PCR bank expectations in ascending index order, component
minimum versions, accepted signing roots as SHA-256 fingerprints of
DER certificates, revocations, then one 256-byte RSASSA-SHA256
signature over the exact payload bytes) and fails closed on every
deviation: non-ASCII, CR, tabs, unknown fields, out-of-order or
repeated fields, wrong hex widths, or any byte after the signature.

Signature verification lives in `ogir-attest-tpm::manifest` and
delegates to the QuoteVerifier's TPM path against a verifier-PINNED
anchor modulus; the anchor is configuration, never manifest content.
The committed TEST-ONLY anchor key (same generation posture as
ADR-0016 and the M4-028a image keys, subject branded DO NOT TRUST)
signs both fixtures:

- `manifest.txt` (revision 1): the accepted capture profile. Its
  PCR expectations are generated from the committed M4-028c
  `pcrs.txt` (never hand-typed) and the durable test asserts they
  equal the event-log replay; its accepted signing root is the
  committed image key by DER fingerprint.
- `manifest-revoked.txt` (revision 2): the revocation fixture - a
  non-weakening successor that retires `test-uki` version 1 by
  revocation and raises its floor to 2.

Update semantics: a successor must rise in revision, carry every
expectation forward, raise floors only, tighten Secure Boot only,
persist every revocation, and add no signing root (adding a root or
changing an expectation is a fresh reviewed acceptance, not a
successor bump). Version floors compare as dotted-numeric segments
("2026.05" < "2026.10", "2" < "10"); ADR-0023's successor relation
now uses the same comparison, refining its lexical floor compare
(equal-or-rise semantics unchanged, "2" to "10" correctly reads as a
rise).

`docs/PROFILE_STATES.md` is the user-facing explanation: accepted,
unsupported (unknown profile, firmware update, below floor,
revoked, custom key, absent TPM), and attack-indicating (log that
does not reproduce the quote, forged log, tampered manifest or
quote, weakening update), with the reason each state reports and the
principle that unsupported is never a cheating accusation.

## Consequences

- The manifest layer closes M4 deliverables: signing-root
  representation, signed static manifest, revocation and
  minimum-version fixtures, and the explanations.
- The Secure Boot enforcement leg (an enrolled varstore boot) stays
  with the M4-030 attack categories, which consume these fixtures.
- Signing a new manifest revision is a dev-host act
  (`scripts/sign-reference-manifest.sh`); CI validates committed
  evidence only, exactly like the capture fixtures.
- Multiple simultaneously accepted profiles and manifest
  distribution remain deferred (post-M4 production concerns).

## Threat-model impact

The manifest is trusted reference data AFTER signature verification
against a pinned anchor; before that it is untrusted input. The
parser is dependency-free and fail-closed, so a hostile manifest
cannot reach policy code except as a named error. Revocation and
floor checks are fail-closed (undeclared components reject). No new
runtime trust boundary opens; the verification path is the already
audited TPM boundary.

## Privacy impact

None. The fixtures carry firmware and UKI measurements and TEST-ONLY
key material only; no user or publisher identity is involved.

## Dependency and license impact

No Rust dependency changes; the signed inventory is untouched. The
committed TEST-ONLY manifest anchor key follows the M4-028a
committed-key precedent (force-added past the key-ignore rules,
documented in `image/README.md`).

## Validation

Executed on the dev host: `ogir-bootlog` unit tests (18: grammar
negatives, version ordering, successor rules including the numeric
floor rise and the root-addition rejection), `ogir-attest-tpm`
`reference_manifest` suite (6/6: the manifest equals the capture
replay, the signature verifies through a real swtpm, tampered
payload and signature reject, the wrong anchor rejects, and the
revocation successor enforces with distinguishable reasons), and
`scripts/test-reference-manifest.py` (PASS, with a negative
out-of-order case rejecting). Full house gates in the slice record.

## Rollback

Revert the commit; the manifest module, fixtures, and documents
disappear together. `profile.rs` returns to its lexical floor
compare, whose behavior differs only for multi-digit segment rises
("2" to "10"), which the ADR-0023 tests never exercised.

## Primary sources

- ADR-0014 (renewal and revocation semantics), ADR-0016 (TEST-ONLY
  key posture), ADR-0020 (audited TPM verification path), ADR-0023
  (profile schema and successor relation), ADR-0024 (the capture
  fixture the manifest pins).
- The executed fixture generation and test runs on the dev host
  (2026-09-07): payloads generated from the committed `pcrs.txt`,
  signed with the committed anchor, verified through swtpm.
