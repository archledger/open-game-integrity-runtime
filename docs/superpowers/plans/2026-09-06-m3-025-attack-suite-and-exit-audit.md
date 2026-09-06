# Plan: M3-025 attack suite and exit audit

- Status: Executed in `research/m3-025-attack-suite-and-exit-audit`;
  all local gates green; awaiting human review, signed commit, and
  separately authorized publication.
- Date: 2026-09-06.
- Baseline: merged `3660cc14ceb7d4d56eee2c144720d57b87891997`.
- Authority: roadmap Milestone M3 exit criteria and attack categories;
  [local issue](../../../planning/issues/025-attack-suite-and-exit-audit.md);
  [exit audit](../../../docs/superpowers/audits/2026-09-06-m3-exit-audit.md).

## Tasks

1. The ten-category attack suite (tests/attack_suite.rs), consolidating
   the already-covered categories into one self-contained inventory and
   adding the four new ones (resource exhaustion with held-alive AKs,
   daemon-kill via the fixture's new `kill()`, stale quote, malformed
   structures).
2. The M3 exit-criteria audit with per-criterion evidence.
3. Roadmap M3 completion boundary; local issue; this plan.

## Test inventory (executed, all green)

- Ten attack categories, each deterministic non-allow: class confusion
  (software-as-hardware), unenrolled AK, wrong qualifying data, copied
  public AK with garbage signature, stale quote (old challenge's
  statement under a new challenge), resource exhaustion (64 held-alive
  AK backends exhaust the TPM; failures are Internal; the TPM is not
  corrupted), daemon killed during quote (backend fails closed),
  malformed structures (garbage attest bytes), EK/AK confusion
  (corrupted AK name rejects activation), cross-publisher AK reuse
  (registry guard rejects).

## Development notes

Exhaustion requires holding backends alive (tss-esapi flushes on
drop); a dropped Context's handles flush via the handle manager, so
sequential connects never exhaust. The post-exhaustion quote is
accepted either way (the TPM may evict to make room) - the
deterministic properties are fail-closed errors and no corruption.

## Deliberately not done

The fTPM hardware-class backend and endorsement EK authentication
(recorded as future work in the audit and the roadmap boundary, not M3
gaps).
