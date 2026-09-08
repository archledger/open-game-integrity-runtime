# M4-030: The measured-boot attack suite, the enrolled varstore, and the M4 exit audit
<!-- labels: type: test,area: measured-boot,area: attack-lab,area: tpm,status: needs-review -->
<!-- milestone: M4 Measured Boot Profile -->


## Problem

M4's ten required attack tests are not yet hosted as a named
inventory, the Secure Boot enforcement boot (the test-key-enrolled
varstore deferred from M4-028b) is not delivered, and the milestone
cannot close without the exit audit of its four criteria.

## What this slice delivers

1. `ogir_bootlog::admission` - the production decision point:
   profile identity, Secure Boot state, an EXPLICITLY accepted
   component signing root, then every manifest PCR expectation; no
   leg alone admits; three new distinguishable reasons
   (SecureBootDisabled, SigningRootRejected, SigningRootNotValidated).
2. `crates/ogir-attest-tpm/tests/measured_attack_suite.rs` - all ten
   roadmap categories, 12/12 green against real swtpm and the
   committed M4-028c/M4-029 fixtures: Secure Boot disabled; modified
   UKI; modified initramfs/cmdline; user-enrolled custom key;
   unapproved kernel with valid signature; forged/truncated/
   reordered event log; log that does not reproduce the quoted PCRs
   (live, through the M4-027 bridge); revoked boot component;
   firmware update as an UNSUPPORTED state distinct from attack; no
   TPM and cleared TPM failing closed. Plus the exit-criterion
   negative: Secure Boot enabled alone never admits. Mutations are
   made on the PARSED log structure, so each is exactly the
   measurement change it claims.
3. `image/enroll-test-key.sh` - the deterministically derived
   TEST-ONLY-enrolled varstore (virt-fw-vars; PK = KEK = db = the
   committed image key; fails closed unless all three are present)
   and `scripts/test-sb-boot.py` - the enforcement gate: the good
   UKI boots under Secure Boot (kernel lockdown notice in the
   serial log) and a one-byte-modified UKI is rejected by the
   firmware (ADR-0026).
4. `docs/superpowers/audits/2026-09-07-m4-exit-audit.md` - the exit
   audit finding all four criteria satisfied by executed work, with
   the honest limitations recorded (the emulated profile; the
   manifest binds the capture profile; SB boots are dev-host gates).
5. ADR-0026 + index row; ROADMAP M4-030 boundary declaring M4
   COMPLETE on merge.

## Executed evidence (dev host)

- Measured attack suite: 12/12 passed (real swtpm; the no-TPM leg
  asserts the fail-closed connection error).
- The enrolled varstore: built deterministically; the first attempt
  using virt-fw-vars --enroll-cert alone left db EMPTY (the boot was
  rejected by Secure Boot - caught live); the explicit
  --set-pk-cert/--add-kek-cert/--add-db-cert triple fixed it; both
  events are recorded in ADR-0026.
- SB enforcement, both directions: the good test UKI boots under
  OVMF_CODE_4M.secboot.fd + the enrolled varstore with the serial
  log showing the known command line AND "Kernel is locked down
  from EFI Secure Boot mode"; the tampered UKI (one flipped byte,
  sbverify "Signature verification failed") is rejected by the
  firmware ("rejected probably by Secure Boot", no command line).

## Security invariants

- No Rust dependency changes; no hand-implemented cryptography.
- The admission point fails closed on every leg, including an
  unvalidated signing root.
- The varstore is a derived gitignored build input; virt-firmware
  is a dev-host tool, not a linked dependency.

## Out of scope

- Physical-hardware profiles; kernel-phase measurements beyond the
  UKI (IMA, module signatures); dbx-based revocation distribution;
  CI boots. Recorded as limitations in the exit audit.
