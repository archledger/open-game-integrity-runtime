# M4-030 plan: the measured-boot attack suite, the enrolled varstore, and the M4 exit audit

Date: 2026-09-07
Agent: zcode
Authorization: standing publication+merge authorization (recorded
2026-09-07T17:20:00-04:00); all gates remain mandatory.

## Objective

Close Milestone M4: host the ten roadmap attack categories as a
named inventory, deliver the deferred Secure Boot enrolled varstore
with live enforcement evidence in both directions, and write the
exit audit of the four criteria.

## Steps

1. Worktree research/m4-030-attack-suite-and-exit-audit from 5d232b1.
2. Production admission point first (ogir_bootlog::admission): the
   exit criterion "SB alone never sufficient" becomes structural.
3. The enrolled varstore: pip --user virt-firmware; derive the
   store from the ADR-0024 template + committed key; boot under
   OVMF_CODE_4M.secboot.fd both ways (good UKI boots with lockdown
   notice; tampered UKI rejected).
4. The ten-category suite against the committed fixtures + real
   swtpm; mutations on the PARSED log (no byte-offset surgery).
5. ADR-0026, exit audit, ROADMAP boundary declaring M4 complete,
   planning issue, this plan, doc touch-ups.
6. House gates, signed commit, publication (issue + draft PR), CI,
   merge under the standing authorization, post-merge verification.

## Development notes

- virt-fw-vars --enroll-cert alone does NOT populate db (PK and KEK
  only); the boot under the enrolled store was rejected by Secure
  Boot and the --print inspection showed db missing. The explicit
  --set-pk-cert/--add-kek-cert/--add-db-cert triple is required;
  enroll-test-key.sh fails closed unless PK, KEK, and db all exist.
- Two QEMU boots cannot share one ESP image (write lock); run them
  sequentially and never leave a timed-out QEMU holding the lock
  (the first SB attempt's OVMF sat at the boot manager until the
  timeout, blocking the next boot).
- extend_log_bank takes tss_esapi::handles::PcrHandle, not a raw
  index; quote() takes &QuoteRequest.
- The closed-port helper for the no-TPM leg binds, reads the port,
  and drops the listener; QuoteVerifier::connect then fails closed
  with tcti connection errors - expected output, not a failure.

## Boundaries

In: admission module, attack suite, enrollment script + SB gate,
exit audit, ADR-0026, ROADMAP closure, docs.
Out: hardware profiles, kernel-phase measurements, dbx distribution,
CI boots (limitations recorded in the audit).
