# M4 exit audit: one measured Linux boot profile

Date: 2026-09-07
Agent: zcode
Scope: the four M4 exit criteria from docs/ROADMAP.md, audited
against delivered, merged work plus this slice's executed evidence.

## Criterion 1: the verifier reconstructs or validates measured state
against the quote

DELIVERED (M4-027, M4-028c; both on main). The ogir-bootlog parser
replays the TCG2 event log with exact TPM semantics; the logbridge
extends a log's bank into a live TPM and validates the quote against
the replay (the pcrDigest-is-hash-of-values semantics); the committed
capture fixture satisfies the full triangle - replay equals the
in-guest live read (PCR 11 included), the quoted digest equals
SHA256 of the concatenated replayed values, the nonce echoes, the
QuoteVerifier cryptographically verifies the signature, and tamper
rejects. Re-hosted inside the milestone inventory as category 7
against a live swtpm quote.

Verdict: satisfied, executed.

## Criterion 2: `Secure Boot enabled` alone is never treated as
sufficient

DELIVERED (this slice). Structural, not procedural:
ogir_bootlog::admission::admit_boot checks the profile identity,
then the Secure Boot state, then an EXPLICITLY ACCEPTED component
signing root (the custom-key distinction: a machine may enroll its
own key and boot its own UKI with Secure Boot happily enabled - the
root check rejects it), then every manifest PCR expectation - and no
leg alone admits. The direct negative is a suite test
(exit_secure_boot_alone_is_never_sufficient); categories 1, 4, and 5
each independently refuse to admit on their own leg. Live firmware
enforcement is also proven, both directions, under the enrolled
varstore (ADR-0026): the good UKI boots with the kernel reporting
lockdown from EFI Secure Boot mode; the modified UKI is rejected by
the firmware.

Verdict: satisfied, executed.

## Criterion 3: unsupported and malicious-looking states remain
distinguishable

DELIVERED (M4-029 + this slice). The reason taxonomy keeps the two
families separate all the way through: UnsupportedProfile,
BelowMinimumVersion, UnknownComponent, SecureBootDisabled, and
SigningRootRejected are reference-data states (consistent evidence
that does not match reviewed expectations), while PcrMismatch from a
mutated log, Truncated/NotTcg2 forgeries, the log-quote mismatch,
and SignatureInvalid for tampered manifests or quotes are
internal-inconsistency states. docs/PROFILE_STATES.md explains both
families and the never-an-accusion principle for users; category 9
asserts the firmware-update state reports as unsupported, never as
an attack verdict.

Verdict: satisfied, executed and documented.

## Criterion 4: updating the accepted profile requires signed,
reviewed reference data

DELIVERED (M4-029, on main). The reference manifest is canonical,
fail-closed parsed, and verified against a verifier-PINNED anchor
through the audited TPM path; successor updates must be
non-weakening (revision rises, expectations carried forward, floors
only rise numerically, revocations persist, no root added); anything
else - a changed expectation, an added root - is a fresh reviewed
acceptance, never a successor bump. Tampered payloads, tampered
signatures, and wrong anchors all reject.

Verdict: satisfied, executed.

## Deliverables coverage

| Roadmap deliverable | Status |
| --- | --- |
| Platform-profile schema | M4-026, merged |
| Measured-boot event-log ingestion | M4-026, merged |
| PCR replay/validation | M4-027, merged |
| UKI and boot-phase reference policy | M4-028a-c, merged |
| Accepted signing-root representation | M4-029, merged |
| Secure Boot and custom-key distinction | M4-029 + this slice (admission root check + live enforcement) |
| Static signed reference manifest | M4-029, merged |
| Revocation and minimum-version fixture | M4-029, merged |
| User-facing explanation of accepted and unsupported states | M4-029 (PROFILE_STATES.md), merged |
| Ten required attack tests | This slice: measured_attack_suite.rs 12/12 + the SB enforcement gate |

## Honest limitations (recorded, not gaps in the criteria)

- The proven profile is the EMULATED test image (QEMU + pinned
  TCG2 OVMF + swtpm); no physical-hardware profile has been measured.
- The committed manifest binds the CAPTURE profile; the plain test
  image has no committed measurement fixture (its boot is proven by
  the chassis and SB gates, not a triangle fixture).
- SB enforcement boots are dev-host gates; CI validates committed
  evidence and the Rust suites, never a live QEMU boot.
- Kernel-phase measurements beyond the UKI (IMA, module signatures)
  are out of the accepted profile by design (PCR 10 excluded,
  documented in the capture).

## Verdict

All four M4 exit criteria are satisfied by delivered, executed, and
reviewed work. With this slice merged, Milestone M4 is COMPLETE:
M0 through M4 are closed, and the roadmap's next milestone is M5
(Proton bridge and race-resistant caller binding).
