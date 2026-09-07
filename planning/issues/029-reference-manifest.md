# M4-029: The signed reference manifest and revocation fixtures
<!-- labels: type: implementation,area: measured-boot,area: verifier,area: supply-chain,status: needs-review -->
<!-- milestone: M4 Measured Boot Profile -->


## Problem

M4's fourth exit criterion requires that updating the accepted
profile requires signed, reviewed reference data. ADR-0023 delivered
the profile schema and deferred authenticity to this slice. Open
roadmap deliverables: the accepted signing-root representation, the
static signed reference manifest, the revocation and minimum-version
fixture, and the user-facing explanation of accepted and unsupported
states.

## What this slice delivers

1. `ogir-bootlog::manifest` - the canonical line-oriented manifest
   grammar (ADR-0025), parsed fail-closed: exact field order,
   lowercase hex widths, ascending list entries, no repeats, no
   unknown fields, nothing after the signature line. The signature
   covers the exact payload byte prefix, never a re-serialization.
2. `ogir-attest-tpm::manifest` - signature verification through the
   audited TPM path against a verifier-PINNED anchor modulus; the
   anchor is configuration, never manifest content.
3. The committed TEST-ONLY manifest anchor key
   (`image/keys/generate-test-manifest-key.sh`, subject branded DO
   NOT TRUST) and `scripts/sign-reference-manifest.sh` for
   reproducible fixture signing.
4. The fixtures: `manifest.txt` (revision 1 - the accepted capture
   profile; PCR expectations GENERATED from the committed M4-028c
   pcrs.txt; the accepted signing root is the committed image key by
   DER fingerprint) and `manifest-revoked.txt` (revision 2 - a
   non-weakening successor retiring test-uki v1 by revocation with
   the floor raised to 2).
5. Update semantics: non-weakening successors only (revision rises,
   expectations carried forward, floors only rise - compared as
   dotted-numeric segments, refining ADR-0023's lexical compare;
   revocations persist; no signing root added; changed expectations
   and root rotations are fresh reviewed acceptances, not
   successors). Component checks report distinguishable reasons:
   ComponentRevoked, BelowMinimumVersion, UnknownComponent, and
   UnsupportedProfile stay separate from attack-indicating errors.
6. `docs/PROFILE_STATES.md` - the user-facing explanation of
   accepted, unsupported, and attack-indicating states and how to
   update the accepted profile.
7. `scripts/test-reference-manifest.py` - the fail-closed signing-
   time gate (grammar statics, modulus widths, fingerprint
   coherence with the committed image key).

## Executed evidence (dev host)

- ogir-bootlog unit tests: 18 passed (grammar negatives, version
  ordering, successor rules).
- ogir-attest-tpm reference_manifest suite: 6/6 - the manifest
  equals the capture replay, the signature verifies through a real
  swtpm, tampered payload/signature reject, the wrong anchor
  rejects, the revocation successor enforces with distinguishable
  reasons.
- scripts/test-reference-manifest.py PASS, including a negative
  out-of-order case that rejects.

## Security invariants

- No Rust dependency changes; the signed allowlist is untouched.
- No hand-implemented cryptography; verification is the ADR-0020
  TPM path.
- A manifest can never declare its own signer.
- All checks fail closed; undeclared components reject.

## Out of scope

- The Secure Boot enforcement boot (the enrolled varstore) and the
  ten M4 attack categories - M4-030, which consumes these fixtures.
- Multiple simultaneously accepted profiles and manifest
  distribution - post-M4 production concerns.
