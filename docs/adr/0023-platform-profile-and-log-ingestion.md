# ADR-0023: Platform-profile schema and in-repo TCG2 log ingestion

- Status: Accepted
- Date: 2026-09-06
- Owners: Initial maintainer
- Related issues: [Local M4-026 issue](../../planning/issues/026-profile-schema-and-log-ingestion.md)
- Supersedes: None
- Superseded by: None

## Context

Milestone M4 must prove one narrow, documented Linux platform profile.
Its foundation is the platform-profile schema and measured-boot
event-log ingestion with PCR replay. The human accepted the M4 entry
recommendations (2026-09-06): the in-repo dependency-free parser (Q3),
the firmware/EFI-phase-first profile scope (Q2), and the QEMU/OVMF +
swtpm CI image strategy (Q1) - this decision delivers the
parser/schema slice those choices enable.

## Decision drivers

- No new external dependencies (the 53-crate signed inventory stays).
- The parser must be total: every malformed shape fails closed.
- Replay must reproduce TPM semantics exactly (locality-3 PCR 0
  initialization, EV_NO_ACTION exclusion) or say what it cannot do.
- Profile updates must carry the ADR-0014 non-weakening transition
  relation from day one.
- Real fixtures over synthetic ones wherever possible.

## Options considered

### A: In-repo dependency-free parser over the TCG2 format (selected)

A `Reader`-based total parser for the Spec ID header and
TCG_PCR_EVENT2 records, replay via the production SHA-256 (ADR-0020's
promotion), and a profile type with `is_non_weakening_successor`.

### B: A log-parsing dependency (e.g., a TCG event-log crate)

Rejected: extends the signed inventory for a format two fixed
structures define; the roadmap's own CI strategy needs deterministic
fixtures the in-repo parser provides anyway.

### C: Shell out to tpm2_eventlog

Rejected: a subprocess dependency in the trusted path, nondeterministic
output formats across versions, and unavailable in CI without the
toolchain.

## Decision

- New production crate `ogir-bootlog` (dependency-free except the
  in-workspace `ogir-attest` SHA-256): `parser` (Spec ID + EVENT2,
  all-little-endian, digest-count consistency against the declared
  algorithm table, trailing bytes reject), `replay` (SHA-256 bank:
  `new = SHA256(old || digest)`; EV_NO_ACTION never extends;
  StartupLocality 3 initializes PCR 0 at all-FF per the TCG PC Client
  Platform Firmware Profile; `matches` = exact bidirectional,
  `matches_subset` = expectations-only for deliberately partial
  profiles), and `profile` (name, revision, PCR expectations,
  secure-boot requirement, minimum versions; shape validation; the
  ADR-0014 successor relation).
- The REAL host fixture ships in-tree (the dev machine's 116-event
  log) with its live PCR readback as expectations; PCRs 2 and 7
  replay EXACTLY. PCR 0 is documented as a known firmware-log
  fidelity gap on this hardware (early CRTM measurements precede the
  log) - this is precisely the roadmap's "log that does not
  reproduce quoted PCRs" category, recorded rather than papered over.

## Consequences

M4's ingestion deliverable is done: profiles, parsing, and replay are
test-local and CI-friendly with zero new dependencies. Cost: the
parser covers the TCG2 ("crypto agile") format only (SHA-256 bank);
SHA-1/legacy TCG 1.2 logs and other banks are future extensions, and
PCR 0 fidelity on this firmware generation is explicitly not claimed.

## Threat-model impact

Enables the forged/truncated/reordered-log and log-vs-PCR attack
categories at the ingestion layer (the truncation and
foreign/corrupt-header rejections are tested). No production trust
boundary changes yet: ingestion output is candidate input.

## Privacy impact

None. The fixture is the developer machine's own firmware log
(firmware measurements, no user data); profiles carry expectations,
not identities.

## Dependency and license impact

None external. One new internal crate depending on `ogir-attest`.

## Validation

Five integration tests: the real-fixture parse (115 EVENT2 records,
SHA-256-only Spec ID) and exact replay to live PCRs 2 and 7 with the
documented PCR 0 gap; profile shape validation and the four
non-weakening-successor directions; truncation rejection at every cut;
trailing-byte and foreign-header rejection; forged-expectation and
touched-but-unexpected detection.

## Rollback

Revert the slice; the crate and fixture are removed; no other crate
depends on `ogir-bootlog` yet.

## Primary sources

- TCG PC Client Platform Firmware Profile (EVENT2 layout,
  StartupLocality semantics); TCG EFI Protocol Specification (Spec ID
  Event03).
- The dev host's live log and `tpm2_pcrread` readback (2026-09-06).
- ADR-0014 (transitions), ADR-0020 (the production SHA-256).
