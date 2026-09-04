# M1-013 Abstract JSON Conformance Format Version 1 Registry Guide

## Authority

The sole normative machine-readable planning authority is the closed root index
`2026-09-02-m1-013-format-v1-registry.json` and its four hash-bound shards. This
document is explanatory only. It intentionally repeats no normative count, ID,
path, schema, domain, baseline, transform, action, expected outcome, coverage
projection, resource constructor, diagnostic, or focused result.

The accepted design and ADR-0012 remain the architectural authorities. The JSON
registry freezes their format-version-1 planning details without selecting a
runtime type, production parser or schema, wire representation, canonical
encoding, cryptographic mechanism, TPM mapping, persistence mechanism, or
production resource limit.

## Validation

Run both commands before relying on the registry or beginning any implementation
task:

```bash
python3 scripts/test-m1-013-plan-registry.py
python3 scripts/check-m1-013-plan-registry.py
```

The checker validates the registry without reading this guide or deriving
authority from the implementation plan. It fails closed on descriptor-relative
shard admission, inventory and hashes, typed schemas and canonical baselines,
manifest cross-authority references, candidate-only transforms, all literal
focused results and coverage arrays, resource constructors and limits, source
bindings, and the operation-budget contract. It emits only fixed diagnostics.
It validates validator AST shape and references but does not execute future
validator adapters or accept their expected outcomes as proof.

The checker pins the accepted root-index byte hash as an independent trust
anchor. This detects a coherent shard-and-index rewrite without duplicating the
registry's semantic tables in Python. Any approved normative registry change
therefore updates the JSON, its negative tests, and this one fingerprint.
Attack-command parity expectations are separate registry data keyed by validator
case; they are never embedded in executable transform ASTs.

The planning registry contains no aggregate operation total or per-case
operation vectors. Runtime implementation later derives and proves those values
under per-case TDD; a passing planning check is not that implementation evidence.
The resource-constructor product is a complete parameterized constructor domain,
not a requirement for one validator case per product. Validator cases may consume
only admitted products; the checker proves that every product is constructible.

## Change Control

Any normative format-v1 planning change must update the JSON first, add or
adjust a negative checker test, and pass the checker before dependent prose is
changed. Do not copy normative arrays or tables back into Markdown. Incompatible
corpus changes still require the versioning and superseding-ADR process required
by ADR-0012.

All authorization gates in the implementation plan remain in force. A passing
planning checker authorizes no issue, implementation, fixture creation, staging,
commit, sign-off, push, pull request, publication, or merge.
