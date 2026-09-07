# M4-028c: The measured capture (TCG2 OVMF, UKI fixture export, PCR 11 triangle)

- Agent: zcode
- Date: 2026-09-07
- Status: Implemented (this issue documents the slice)
- ADR: [ADR-0024](../../docs/adr/0024-tcg2-ovmf-acquisition-and-measured-capture.md)

## Problem

M4's exit criterion - the verifier validates measured state against
the quote, through the UKI phase - needs captured evidence from ONE
measured boot: the firmware event log, the live PCR values, and a
TPM2 quote that a second party can verify. M4-028b proved the boot
chassis but was blocked: Fedora's OVMF performs no TPM2 measurements.

## What this slice delivers

1. `image/fetch-ovmf-tcg2.sh` - the pinned, hash-verified TCG2-enabled
   OVMF (Ubuntu `ovmf-generic_2026.05-2ubuntu2`); fails closed.
2. `image/capture-init.sh` + `image/cmdline.capture` +
   `image/boot-capture.sh` - the capture: a second TEST-ONLY-signed
   UKI with the capture init embedded (so sd-stub measures it into
   PCR 11 via the TCG2 protocol), an IDE scratch evidence disk (the
   guest ships no virtio modules; `ata_piix` is builtin), a
   magic-delimited evidence stream (the guest ships no `dd`/`wc`/
   `awk`), and the canonical `createek`/`createak` quote flow.
3. `scripts/test-measured-capture.py` - the capture-time fail-closed
   gate (artifacts present, Spec ID Event03, PCR 11 non-zero, nonce
   echo, clean report).
4. The committed fixture (`crates/ogir-attest-tpm/tests/fixtures/
   uki-tcg2/`) and the durable Rust triangle test
   (`uki_capture_triangle.rs`): replay vs live vs quoted digest, the
   QuoteVerifier signature check, and a tamper rejection.
5. A production parser fix the multi-bank log forced: the TCG EFI
   Spec ID `digestSize` field is u16, not u8 (single-bank logs
   escaped the bug because the table tail is ignored).

## Executed evidence (dev host)

- Fedora OVMF (the blocker, now empirically confirmed): PCRs 0-9, 11
  zero; no event log. PCR 10's activity is the kernel's IMA, not
  firmware.
- Ubuntu TCG2 OVMF: PCRs 0-7, 9 measured; event log published;
  PCR 11 = `0xDC0FC1A4...` (the sd-stub UKI phase).
- Triangle test: 2/2 green (the full triangle holds; tamper rejects).

## Security invariants

- No Rust dependency changes; the 53-crate allowlist is untouched.
- The OVMF pair is a pinned, hash-verified build input, never a
  committed binary; build outputs stay gitignored.
- The capture UKI is signed with the TEST-ONLY key (ADR-0016
  posture); the committed fixture is evidence, never trusted input.
- The parser fix tightens (never weakens) validation.

## Out of scope

- Secure Boot enrollment of the test key (the varstore) - belongs to
  the M4-030 attack categories needing SB enforcement.
- Wiring QEMU boots into CI (the capture is a dev-host gate; CI
  validates the committed evidence).
