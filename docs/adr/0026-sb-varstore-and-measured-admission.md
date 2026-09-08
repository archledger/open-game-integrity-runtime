# ADR-0026: The enrolled Secure Boot varstore and the measured-boot admission point

- Status: Accepted
- Date: 2026-09-07
- Owners: Initial maintainer
- Related issues: [Local M4-030 issue](../../planning/issues/030-attack-suite-and-exit-audit.md)
- Supersedes: None
- Superseded by: None

## Context

M4-028b proved the boot chassis and documented the Secure Boot
enrollment of the test key as deliberate future work; M4-028c proved
the measured capture without SB enforcement; M4-029 delivered the
signed reference manifest. M4-030 closes the milestone: the ten
roadmap attack categories, the SB-enrolled varstore its enforcement
categories need, and the exit audit. A verifier-side decision point
was also missing: the checks lived in tests, with no single
production function a caller could hand a boot's evidence to.

## Decision drivers

- The enrolled varstore must be reproducible from committed
  material, never a committed binary and never an interactive UEFI
  menu session.
- "Secure Boot enabled" alone must never admit a boot (an M4 exit
  criterion); the admission point makes that structural.
- Every attack category must produce a deterministic, named
  non-allow result.
- No hand-implemented cryptography, no new Rust dependencies.

## Options considered

1. **Enroll through the OVMF firmware menu or a KeyTool ISO.**
   Interactive; not reproducible in a gate. Rejected.
2. **Commit a pre-built enrolled varstore binary.** Opaque firmware
   state in git; the house pins inputs by hash and derives outputs.
   Rejected.
3. **Derive the varstore with virt-fw-vars from the fetched template
   plus the committed TEST-ONLY certificate.** Deterministic, one
   dev-host pip tool, and the exact key triple the chain already
   uses.
4. **Admission policy: keep composing checks in tests only.** Leaves
   no production decision point; the exit criterion reads as test
   scaffolding. Rejected.

## Decision

Adopt option 3 for the varstore and add a production admission point.

`image/enroll-test-key.sh` builds the enrolled varstore with
virt-fw-vars (`--set-pk-cert`, `--add-kek-cert`, `--add-db-cert`; PK
= KEK = db = the committed TEST-ONLY image key, everything else
empty, fixed owner GUID) and fails closed unless PK, KEK, and db are
all present in the written store. The store pairs with the pinned
TCG2-enabled `OVMF_CODE_4M.secboot.fd` from ADR-0024's fetch (the
package ships it; the 028c fetch now retains it).
`scripts/test-sb-boot.py` is the enforcement gate: the GOOD test UKI
boots under the enrolled store with the kernel reporting lockdown
from EFI Secure Boot mode, and a TAMPERED UKI (one flipped byte
inside the signed image) is rejected by the firmware with no command
line - the firmware-side leg of the modified-UKI category.

`ogir_bootlog::admission::admit_boot` is the production decision
point: profile identity, Secure Boot state, an EXPLICITLY ACCEPTED
component signing root (the custom-key distinction), then every
manifest PCR expectation reproduced exactly - in that order, with
three new distinguishable reasons (SecureBootDisabled,
SigningRootRejected, SigningRootNotValidated). No leg alone admits;
an unvalidated signing root fails closed.

`crates/ogir-attest-tpm/tests/measured_attack_suite.rs` hosts all ten
roadmap categories as the named milestone inventory (M2-019/M3-025
pattern): mutations operate on the parsed log structure so every
mutation is the measurement change it claims; the log-vs-quote
category runs against a live swtpm quote through the M4-027 bridge;
the no-TPM leg asserts the fail-closed connection error; the
cleared-TPM leg asserts zero banks never admit; and the
SB-alone-insufficient exit criterion is a direct negative. The
dev-host execution record (the two SB boots and the suite run) is in
the slice plan and the exit audit.

## Consequences

- The last deferred M4-028b deliverable (the enrolled varstore) is
  closed; SB enforcement is proven live, both directions.
- virt-firmware joins the dev-host tool list (ukify, sbsign, QEMU,
  swtpm, mtools); CI validates committed evidence only.
- The admission point is the seam future milestones (M5+ verifier
  integration) call into; it owns no crypto and adds no deps.
- Real-hardware enrollment, dbx revocation distribution, and
  Microsoft-key profiles remain out of scope (the accepted profile is
  the test image).

## Threat-model impact

The admission order closes the "Secure Boot enabled is enough"
bypass structurally: a machine may boot anything it likes under its
own keys; without an accepted root AND matching measurements it never
admits. The enrolled varstore is test tooling for the emulator; no
production trust boundary moves. The tampered-UKI rejection is
firmware-enforced evidence, recorded by the gate, not asserted.

## Privacy impact

None. The gate reads serial logs and firmware measurements of a
synthetic image; no user or publisher data.

## Dependency and license impact

No Rust dependency changes; the signed inventory is untouched.
virt-firmware (Python, GPLv2+) is a dev-host build tool, not a
linked or distributed dependency; its output (the varstore) is a
gitignored emulator input.

## Validation

Executed on the dev host: the enrolled varstore built and verified
(PK/KEK/db present; the first attempt using --enroll-cert alone left
db EMPTY and the boot was rejected - caught by the boot itself, fixed
by explicit triple enrollment, both events recorded); the good UKI
booted under SB enforcement with the kernel lockdown notice; the
tampered UKI's signature failed sbverify and the firmware rejected
the boot; the measured attack suite 12/12 (ten categories, the exit
criterion negative, and the manifest record leg) against real swtpm.
Full house gates in the slice record.

## Rollback

Revert the commit; the admission module, suite, gate, and enrollment
script disappear together. The derived varstore and tampered ESP are
gitignored build outputs.

## Primary sources

- UEFI Secure Boot certificate databases (PK/KEK/db/dbx) and the
  authenticated variable store format edk2 consumes.
- virt-firmware's virt-fw-vars enrollment semantics (--enroll-cert
  versus the explicit --set-pk-cert/--add-kek-cert/--add-db-cert
  triple, observed empirically on 2026-09-07).
- ADR-0024 (the pinned TCG2 OVMF pair and its secboot variant),
  ADR-0025 (the manifest the admission point consumes).
