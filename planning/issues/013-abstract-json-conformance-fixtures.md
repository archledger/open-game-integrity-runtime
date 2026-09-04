# M1-013: Define abstract JSON conformance fixtures
<!-- labels: type: test,area: model,area: verifier,area: session,area: attack-lab,area: privacy,risk: trusted-computing-base,risk: parser,risk: privacy,risk: compatibility,status: ready -->
<!-- milestone: M1 Domain Model -->

## Problem

M1-012 defines the semantic Evidence-binding transcript, and M1-012F defines
its challenge-anchored evidence-time authority and protected-session lifecycle.
The repository does not yet have one executable, representation-independent
corpus that proves those contracts agree across valid snapshots, invalid
single-change snapshots, and ordered lifecycle histories.

Without a closed corpus and independent oracles, a future implementation could
accept incomplete coverage, copy candidate values into expected state, validate
the same evidence under another context or purpose, miss a temporal rollback,
or report success after an earlier validation layer failed. Existing JSON test
consumers also need one bounded admission seam so parser hardening does not
silently change the attack-scenario validator's reviewed behavior.

This issue implements the approved test-only design in
`docs/superpowers/specs/2026-09-01-m1-013-abstract-json-conformance-fixtures-design.md`
and ADR-0012. The admitted root registry at
`docs/superpowers/plans/2026-09-02-m1-013-format-v1-registry.json` and its
hash-bound shards are the sole normative format-version-1 planning authority.
This issue does not copy their IDs, schemas, transforms, actions, limits,
expectations, coverage mappings, diagnostics, resource constructors, or focused
rows.

At drafting, this local issue was a proposal requiring exact human approval;
that approval alone did not authorize implementation or any Git/publication
action. Later approvals and current local progress are recorded in the
[implementation evidence](#m1-013-local-implementation-evidence) below.
Publication remains separately gated by the approved plan and project policy.

## Security invariants

- The corpus manifest is the only runtime fixture inventory and coverage
  authority; no file, executable table, or caller supplies a second expected
  result or hidden case registry.
- Repository JSON and paths remain hostile until the shared loader and corpus
  boundary admit them under the registry's finite test-tool limits.
- A manifest expectation is consumed only after the canonical manifest,
  inventory, path set, closed registries, counts, coverage, and executable-table
  bijection pass independently.
- Validation runs in the approved six-layer order and stops at the earliest
  failure. No later oracle can convert an earlier rejection into success.
- Candidate data never supplies its own reconstruction, coverage, appraisal, or
  lifecycle oracle. Trusted and registered oracle inputs remain logically
  separate and immutable during validation.
- Every negative fixture is reproducible from one valid same-kind baseline by
  exactly its registered single-change transform at the appropriate comparison
  layer.
- Claim-entry order is non-semantic after typed admission, but duplicate claim
  meanings remain observable and invalid. History action order and all other
  schema-declared array order remain semantic.
- Evidence-time sequence, interval, epoch, high-water, restart, rollback,
  concurrency, outage, renewal, and terminal-state rules remain those approved
  by M1-012F and ADR-0011.
- The shared loader remains consumer-neutral. The attack-scenario consumer
  preserves its reviewed limits and exits, its compatibility formatter preserves
  its diagnostics, and parity tests verify all three contracts exactly.
- New conformance diagnostics contain only fixed consumer, checkpoint, and
  error-class labels. They never expose fixture content, identifiers, paths,
  correlation values, proof material, or tracebacks.
- JSON is repository fixture notation only. Passing this corpus grants no
  runtime authorization and selects no production representation or security
  mechanism.

## Threats addressed

- Missing, extra, duplicate, misclassified, symlinked, out-of-root, raced, or
  unregistered manifest and fixture files.
- Duplicate object names, non-finite or out-of-policy numbers, invalid UTF-8,
  multiple documents, excessive structure, and other ambiguous or unbounded
  JSON inputs.
- Manifest-controlled expectations, hidden executable cases, incomplete
  coverage mappings, and disagreement between declared and executable cases.
- Candidate-to-oracle copying, producer-supplied pass labels, and self-fulfilling
  transcript, coverage, appraisal, or lifecycle checks.
- Challenge, context, profile, claim, provenance, manifest, measurement,
  key/handle, evidence-time, lifecycle, and protocol-purpose substitution.
- Required-claim omission, duplicate meaning, invented meaning, undeclared
  profile membership, cross-purpose reuse, and claim-order-dependent outcomes.
- Sequence reuse or decrease, interval overlap, epoch change, rollback, restart,
  non-atomic high-water behavior, stale facts, invalid renewal, and terminal
  session recovery without a new session.
- Resource exhaustion, validation-budget bypass, later-layer execution after an
  earlier failure, parser disagreement, and permissive fallback.
- Path, fixture, challenge, session, key, evidence, temporal, proof, or CI-command
  disclosure through errors, logs, assertions, or tracebacks.
- Compatibility regressions in the existing attack-scenario validator during
  migration to the shared loader.

The corpus tests these failure modes. It does not prove that a claim is true,
make a compromised trusted producer honest, resist every local or physical
attacker, authorize a protected match, or justify a disciplinary conclusion.

## In scope

- `lab/conformance/corpus.json` and the registered snapshot and history fixture
  files under `lab/conformance/`.
- One Python-standard-library bounded JSON loader shared by the new conformance
  consumer and the existing attack-scenario consumer.
- One abstract-conformance validator, command-line entry point, deterministic
  executable case table, and self-tests.
- Six ordered validation layers covering corpus boundary, JSON admission,
  fixture shape, independent transcript reconstruction, exact abstract
  coverage, and appraisal or lifecycle semantics.
- Positive fixtures, registered single-change negatives, loader probes,
  inventory mutations, attack-loader parity cases, and focused independent
  oracle invocations admitted by the planning registry.
- Finite per-file, structural, inventory, operation-budget, and aggregate-command
  bounds for repository test tooling.
- Exact parity tests around the existing attack-scenario validator before and
  after loader migration.
- Aggregate-gate integration and updates to architecture, threat model, test
  strategy, lab guidance, roadmap, ADR evidence, and this issue from observed
  implementation evidence.
- Adversarial, mutation, authority, privacy, lifecycle, resource, compatibility,
  and whole-branch review of the completed candidate.

## Out of scope

- Runtime transcript, evidence-time, appraisal, protected-result, permit,
  proof-of-possession, renewal-authorization, or admission types and behavior.
- A production JSON, CBOR, or other wire format; serializer; parser; schema;
  media type; framing; canonical encoding; field order; or numeric tag.
- Digest, signature, MAC, KDF, commitment, proof, key-generation algorithm, or
  literal cryptographic domain-separation label.
- TPM commands, object templates, PCR selection, quote layout, protected-clock
  mapping, or physical-TPM forwarding.
- Production persistence, replay or high-water storage, replication, backup,
  recovery, migration, retention enforcement, or secure deletion.
- Production byte, depth, width, numeric, time, file-count, processing, or
  operation-budget limits. Repository test-tool values do not become protocol
  endorsements.
- Networking, telemetry, privileged operations, Wine ABI work, BPF/LSM work,
  new Rust runtime modules, or `unsafe` code.
- New dependencies, lockfile changes, packages, crates, feature flags, generated
  dependency artifacts, or license boundaries.
- Production parser fuzzing or differential validation between two production
  implementations; M2 owns that work after a representation is approved.

## Trust boundaries

- Repository paths and bytes cross into the shared loader as hostile input. Only
  files admitted relative to the approved repository root under the consumer's
  fixed limits may become parsed values.
- The validated manifest selects fixture files and expectations. Neither a
  directory listing, fixture field, caller-supplied kind, nor executable table
  may bypass or replace that authority.
- Candidate fixture semantics cross into independent transcript, coverage,
  appraisal, and lifecycle oracles. Candidate fields never become trusted oracle
  inputs merely because JSON shape validation succeeded.
- Validator results cross into CI diagnostics. The new consumer exports only
  fixed labels, while the existing attack consumer retains its reviewed safe
  compatibility formatter.
- Test-only conformance results do not cross into publisher authorization,
  protected-result issuance, permit issuance, signing, TPM, persistence, or
  production network boundaries.

## Primary sources

- [RFC 8259 Section 4](https://www.rfc-editor.org/rfc/rfc8259.html#section-4)
  for object-name uniqueness interoperability.
- [RFC 8259 Section 6](https://www.rfc-editor.org/rfc/rfc8259.html#section-6)
  for interoperable number behavior.
- [RFC 8259 Section 8.1](https://www.rfc-editor.org/rfc/rfc8259.html#section-8.1)
  for UTF-8 JSON text outside a closed ecosystem.
- [RFC 8259 Section 9](https://www.rfc-editor.org/rfc/rfc8259.html#section-9)
  for parser limits on accepted text, nesting, number range, and string length.
- [JSON Schema Draft 2020-12 Core](https://json-schema.org/draft/2020-12/json-schema-core)
  and [Validation](https://json-schema.org/draft/2020-12/json-schema-validation)
  for the vocabulary used by fixture-envelope assertions. The six-layer order
  is an OGIR design decision, not a JSON Schema requirement.
- [Python 3.14 `json`](https://docs.python.org/3.14/library/json.html) for the
  standard decoder behavior and hooks used to reject repeated names and
  non-finite values.
- [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) and
  [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html) for RATS roles,
  Evidence and Attestation Result separation, freshness, profile-governed
  claims, and proof-of-possession separation.
- [ADR-0010](../../docs/adr/0010-semantic-evidence-binding-transcript.md),
  [ADR-0011](../../docs/adr/0011-challenge-anchored-evidence-time.md), and
  [ADR-0012](../../docs/adr/0012-abstract-json-conformance-corpus.md).
- [Approved M1-013 design](../../docs/superpowers/specs/2026-09-01-m1-013-abstract-json-conformance-fixtures-design.md)
  and [approved implementation plan](../../docs/superpowers/plans/2026-09-02-m1-013-abstract-json-conformance-fixtures.md).
- `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`,
  `docs/ARCHITECTURE.md`, `docs/TEST_STRATEGY.md`, `docs/PRIVACY_MODEL.md`,
  `lab/README.md`, `docs/ROADMAP.md`, and `docs/AI_DEVELOPMENT_POLICY.md`.

No unresolved design question may be guessed during implementation. A proposed
change to the admitted registry, approved interfaces, authority split, trust
boundary, production deferrals, dependencies, or external state is a blocker
until separately reviewed and approved.

## Required interfaces

### Planning authority

`scripts/check-m1-013-plan-registry.py` must admit the closed root registry and
all hash-bound shards before Task 13 implementation work or verification. Task
13 test tooling reads the admitted JSON values; it must not parse the Markdown
plan or recreate the normative tables in Python or prose.

### Shared loader seam

`scripts/bounded_json.py` owns consumer-neutral hostile-file admission. It
receives an internally resolved registered file, a fixed trusted diagnostic
label, and the consumer's admitted limits. It does not receive or infer snapshot,
history, attack-scenario, transcript, appraisal, or lifecycle semantics.

The loader admits only a stable regular non-symlink file beneath the approved
repository root, performs a bounded read, decodes strict UTF-8, accepts one JSON
document plus trailing JSON whitespace, rejects duplicate object names and
disallowed numeric tokens, and walks the complete value under finite structural
bounds. Failure returns no partial value and exposes only the consumer's fixed
safe diagnostic contract.

### Abstract-conformance consumer

`scripts/abstract_conformance.py` owns corpus admission, the executable
baseline/transform table, six-layer validation, independent oracles, operation
charging, and self-test orchestration. `scripts/check-abstract-conformance.py`
is its thin aggregate command. Executable builders and transforms contain no
second copy of expected checkpoints, dispositions, or coverage authority.

The consumer validates layer 1 before using manifest expectations. Layers 2-6
then run in fixed order for each admitted fixture: JSON admission, envelope and
kind shape, independent transcript reconstruction, abstract coverage, and
appraisal or lifecycle semantics. Focused oracle tests rebuild prerequisites
and invoke each semantic oracle independently rather than trusting the normal
pipeline's earlier result.

### Corpus

`lab/conformance/corpus.json` is the sole runtime manifest, inventory, case, and
coverage authority. Registered snapshots are self-contained candidate transcript
instances with separate trusted oracle inputs. Registered histories are ordered
candidate observations and lifecycle actions with separate initial and expected
states. Baseline and mutation metadata remain in the manifest, not fixture
content.

### Attack-scenario compatibility

`scripts/check-attack-scenario-traceability.py` changes only at the JSON/file
admission seam. Its accepted and rejected inputs, limits, command-line exits,
safe messages, and bounded numeric locations remain unchanged and are frozen by
pre-migration parity tests.

## Positive tests

- The canonical registry, manifest, exact on-disk inventory, executable table,
  coverage mapping, and every registered valid fixture pass their expected
  checkpoints.
- Valid initial-appraisal and same-session-renewal snapshots reconstruct from
  independent trusted inputs, cover the complete semantic transcript, and reach
  the expected coarse appraisal disposition.
- Valid histories exercise initial collection, renewal, permitted sequence gaps,
  non-overlapping intervals, current-state revalidation, atomic temporal
  high-water, profile continuity, recoverable outage, terminal deletion, and
  new-session recovery as registered.
- Reordering admitted claim entries leaves typed semantic outcomes unchanged
  while preserving duplicate occurrences for rejection.
- Every registered focused row runs each semantic oracle independently with
  freshly rebuilt prerequisites and the admitted expected result.
- The operation budget admits the canonical cases under runtime-derived counters
  and rejects no case merely because another validation consumed budget in a
  prior fresh scope.
- The existing attack-scenario validator produces the exact frozen outputs and
  exits before and after migration to the shared loader.
- The aggregate command runs conformance validation under its finite outer
  timeout and remains part of the normal repository gate.

## Negative tests

- Every registered corpus mutation, loader probe, attack-loader parity transform,
  snapshot mutation, and history mutation with a rejecting expectation fails at
  its declared earliest checkpoint and coarse disposition.
- Missing, extra, duplicate, reordered where order is normative, misclassified,
  symlinked, non-regular, escaped, replaced, or raced registry and corpus files
  fail closed before fixture expectations are consumed.
- Invalid UTF-8, duplicate names, multiple JSON documents, non-finite or
  disallowed numeric tokens, excessive bytes or structure, and unstable files
  return no partial value and only fixed diagnostics.
- A hidden executable case, a missing implementation tuple, changed baseline,
  transform mismatch, invalid reference, count mismatch, orphan fixture, or
  incomplete coverage mapping rejects the corpus at layer 1.
- Each negative fixture reproduces exactly from its named valid baseline by one
  registered transform. Any second candidate change or oracle mutation fails
  the one-change proof.
- Omitted, duplicated, invented, substituted, mis-scoped, mis-provenanced, or
  cross-purpose transcript semantics fail at the earliest applicable layer.
- Sequence reuse/decrease, overlap, epoch or source change, rollback, restart,
  stale state, invalid high-water handling, concurrent advancement, and invalid
  renewal follow the registered fail-closed lifecycle outcome.
- A later claim or policy rejection cannot undo an already validated temporal
  observation, while invalid or unauthenticated coverage cannot advance temporal
  state.
- Exceeding any admitted resource or operation bound fails closed. Charging
  occurs before work, and the outer timeout prevents an unbounded aggregate run.
- Hostile labels and content containing paths, control characters, CI commands,
  identifiers, keys, challenge, evidence, proof, or temporal values cannot alter
  or expand diagnostic output.
- Loader migration cannot broaden or narrow the existing attack-scenario
  validator's accepted inputs, limits, messages, locations, or exits.

## Fuzz/property tests

- Use deterministic property-style tests with the existing Python standard
  library for manifest inventory bijection, path containment, claim-order
  independence, duplicate preservation, and value-independent diagnostics.
- Generate admitted claim reorderings and require identical semantic results;
  introduce one duplicate meaning and require rejection.
- Generate bounded valid and invalid resource shapes around each admitted limit
  and require exact boundary behavior with no partial result.
- Generate lifecycle histories within the admitted action vocabulary and require
  strict sequence increase, interval non-overlap, monotonic high-water, terminal
  finality, and oracle-state immutability.
- Physically apply and restore every named mutation from the implementation plan
  and record the expected detector, observed first cause, exit, and restoration
  hash.

No new property-testing or fuzzing dependency is approved. Byte fuzzing and
decoder differential tests for a production representation remain deferred to
M2.

## Privacy impact

The public repository fixtures use synthetic values only. They must not contain
real player identity, publisher secrets, private keys, production attestation
material, stable device identity, host paths, personal activity, biometric data,
or confidential policy material.

Fixture candidates and oracle inputs still model correlation-sensitive challenge,
context, manifest, key/handle, evidence-time, session, claim, provenance, and
high-water values. Ordinary diagnostics, logs, errors, assertions, traces, and
CI annotations expose none of those values. New conformance output is limited
to fixed consumer, checkpoint, and error-class labels. The existing attack
consumer retains only its reviewed safe messages and bounded numeric locations.

Parsed values and temporary corpus copies live only for one validator invocation.
This issue adds no runtime retention, telemetry, backup, replication, network
transfer, or secure-erasure claim. Any future production storage or transport
requires separate finite retention, access-control, deletion, confidentiality,
and anti-rollback decisions.

## Dependency impact

Implementation uses the Python standard library and existing repository tooling.
It adds no dependency, lockfile change, generated dependency artifact, package,
crate, feature flag, `unsafe` code, cryptographic primitive, TPM library,
production TCB component, or license boundary. Any proposal requiring one is
out of scope and needs separate approval.

## Acceptance criteria

- The exact local issue is approved before implementation begins, and later
  implementation and publication actions receive their own explicit approvals.
- The planning checker admits the root registry and all hash-bound shards; the
  implementation consumes admitted JSON rather than duplicating normative data.
- The canonical manifest is the sole runtime inventory, validator-case, expected-
  result, and coverage authority, with a proven bijection to executable builders
  and transforms and no hidden cases.
- The complete registered snapshot and history corpus exists with exact inventory
  and one reproducible baseline/transform relation for every negative fixture.
- The shared bounded loader rejects every registered hostile-file, JSON, numeric,
  structural, path, stability, and resource case without returning a partial
  value or attacker-controlled diagnostic text.
- All six validation layers execute in order and stop at the earliest failure.
- Transcript reconstruction, abstract coverage, and appraisal or lifecycle
  oracles use separate trusted inputs and pass their registered independent
  focused invocations.
- Claim-entry order is non-semantic after typed admission, duplicate meanings
  remain observable, and all history and schema-declared ordered arrays preserve
  their approved semantics.
- Evidence-time lifecycle behavior, temporal high-water, concurrency, renewal,
  outage, restart, rollback, terminal deletion, and new-session recovery agree
  with M1-012F and ADR-0011.
- Runtime-derived operation counters prove each case's budget behavior without a
  second planning-registry total, and the aggregate command has a finite timeout.
- New diagnostics are value-independent and redacted; attack-scenario diagnostics,
  limits, accepted inputs, outputs, and exits preserve exact reviewed parity.
- Every admitted positive, negative, focused, resource, diagnostic, inventory,
  loader, parity, and mutation case passes its required test and restoration
  checks.
- Architecture, threat model, test strategy, lab guidance, roadmap, ADR evidence,
  and this issue agree with the observed implementation and reference the
  registry rather than copying its normative arrays.
- Normal and release repository gates, planning checks, Python compilation,
  conformance self-tests, attack-scenario tests, aggregate timeout proof, diff
  checks, and required independent reviews pass on the frozen candidate.
- No production representation, parser, serializer, schema, cryptography, TPM
  mapping, persistence mechanism, production limit, dependency, privilege,
  admission path, or external GitHub mutation enters scope.
- A human reviewer understands and approves every changed line before DCO
  certification, commit, publication, or merge.

## M1-013 local implementation evidence

This exact local issue and subsequent local implementation through Task 9 were
approved by the human. Tasks 2–8 are accepted for continued local development;
all implementation changes remain uncommitted. The original issue problem and
acceptance criteria describe the task's starting gap and completion contract,
not a claim that all final gates have already run.

The test-only shared loader, real snapshot/history corpus, independent
six-layer oracles, exact attack compatibility, focused validation, deterministic
accounting, and bounded aggregate commands are implemented. The
[admitted JSON planning registry](../../docs/superpowers/plans/2026-09-02-m1-013-format-v1-registry.json)
remains the format authority, and the admitted
[corpus manifest](../../lab/conformance/corpus.json) remains execution inventory
and coverage authority. The
[test strategy](../../docs/TEST_STRATEGY.md#m1-013-local-implementation-evidence)
records observed counts, source/test links, and accepted Task 8 results.

Task 9 updates implementation evidence.

This uncommitted test-only candidate is prepared for Task 10 final local
verification and freeze. The freeze handoff will identify the exact candidate
and completed checks. Human line review, DCO certification, and separately
authorized Task 11 commit and publication remain pending.
No live issue, remote branch, pull request, or publication has been created for M1-013.
JSON remains fixture notation only; production representation, cryptography,
TPM mapping, persistence, privilege, permit, and admission remain out of scope.
