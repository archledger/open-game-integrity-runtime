# M1-013 Abstract JSON conformance fixtures design

- Status: Approved for implementation planning
- Date: 2026-09-01
- Decision owner: Initial maintainer
- Related roadmap task: M1-013, define abstract JSON conformance fixtures
- Related issue: Not yet created; an approved canonical issue is required before implementation
- Related decision: [ADR-0012](../../adr/0012-abstract-json-conformance-corpus.md)
- Base: `origin/main` at `9a04b055d9e978b5e4ff01adce72f0915c122532`

## Summary

Task 13 will add a test-only JSON corpus that makes the semantic contracts from
ADR-0010 and ADR-0011 executable without choosing a production transcript or
wire representation. The corpus has two fixture kinds:

- **snapshots** describe one candidate Evidence-binding transcript instance;
- **histories** describe ordered observations and actions for one protected-
  session lifecycle, including deliberately invalid transitions.

One `corpus.json` manifest is the sole fixture registry and count authority. A
single hardened bounded JSON loader is shared by the new abstract-conformance
validator and the existing attack-scenario validator. The migration of the
existing validator is behavior-preserving: its accepted inputs, limits, fixed
diagnostics, and exit behavior remain unchanged.

Validation is fail-closed through six ordered layers: corpus boundary and
inventory; JSON admission; fixture envelope and kind shape; independent
transcript reconstruction; abstract coverage; and appraisal or lifecycle
semantics. Each fixture declares one expected earliest layer and one expected
coarse disposition in the manifest. A failure at one layer prevents all later
layers from running for that fixture.

JSON is only the repository fixture notation. Task 13 does not choose a Rust
type, production serializer or parser, signed encoding, canonical bytes,
cryptographic mechanism, TPM mapping, persistence mechanism, or production
numeric limit. Those remain M2/M3 decisions under ADR-0010 and ADR-0011.

## Conversation-level approval record

On 2026-09-01, the decision owner approved these architectural directions:

- use separate snapshot and history fixture kinds;
- use one shared hardened bounded JSON loader seam;
- preserve existing attack-scenario validator behavior during migration;
- validate through six ordered fail-closed layers with stage-separated oracles;
- use claim-entry arrays so negative fixtures can preserve duplicate meanings;
- use a versioned `corpus.json` manifest with exact inventory and counts; and
- keep production runtime, wire, cryptographic, TPM, persistence, and numeric-
  limit choices out of Task 13.

This record did not claim approval of the exact written files. The design and
ADR remained Proposed until the decision owner reviewed the complete candidate.

## Exact written approval record

On 2026-09-02, the decision owner approved without requested changes the exact
three-file candidate represented by temporary-index tree
`f3326ab93724b583b72601b4c50627ce624c1120` and binary patch SHA-256
`8c8c4d912a20a107a8fdead0bd15ba18471a4ab4ca37dce7f968caa425ff8d99`.
This approval authorizes recording the design/ADR decision and writing the
implementation plan only. It does not authorize creating the Task 13 issue,
executing the plan, implementing fixtures or validators, committing, signing,
pushing, opening a pull request, or changing GitHub state.

## Security requirement

Task 13 makes parser disagreement, transcript underbinding, lifecycle rollback,
and fail-open fixture handling observable before production representation work.
It preserves these repository authorities:

- untrusted parsing is explicitly bounded;
- duplicate or ambiguous security-critical fields are rejected;
- unknown critical semantics and malformed input fail closed;
- the verifier reconstructs expected transcript semantics independently;
- claim truth, claim provenance, abstract coverage, and lifecycle continuity are
  separate judgments;
- failure remains coarse and non-disciplinary; and
- new conformance diagnostics disclose no fixture path, host path, claim value,
  challenge value, key/handle value, temporal value, or raw parser input.

## Trust boundaries

Task 13 touches four test-only trust boundaries:

1. **Repository-controlled bytes to JSON admission.** Pull-request content is
   hostile until the bounded loader accepts it.
2. **Manifest to fixture selection.** Only a validated manifest entry may select
   a fixture path, kind, mutation, expected layer, and disposition; only the
   validated top-level coverage mapping may associate requirements with cases.
3. **Candidate semantics to independent oracles.** Candidate fields never
   define their own expected transcript, coverage result, appraisal result, or
   lifecycle transition.
4. **Validator to CI diagnostics.** The new conformance consumer exposes only
   fixed consumer, layer, and error-class labels. The existing attack-scenario
   compatibility formatter preserves its reviewed safe messages and bounded
   numeric locations; neither consumer emits attacker-controlled strings.

No runtime authorization, publisher-verifier authority, signing authority,
privilege boundary, TPM boundary, or production network boundary is added.

## Scope

### In scope for Task 13 implementation

- a canonical issue containing the full AI-task sections required by
  `docs/AI_DEVELOPMENT_POLICY.md`;
- `lab/conformance/corpus.json` format version 1;
- snapshot fixtures under `lab/conformance/snapshots/`;
- history fixtures under `lab/conformance/histories/`;
- one shared standard-library bounded JSON loader module;
- one abstract-conformance validator and self-tests;
- a parity-preserving migration of the attack-scenario validator to the shared
  loader;
- exact positive, single-cause negative, inventory, loader, diagnostic, and
  stage-oracle tests;
- aggregate-gate integration; and
- architecture, threat-model, test-strategy, lab, ADR, and roadmap updates.

### Out of scope

- runtime transcript types or verifier implementation;
- a production wire format, serializer, parser, schema, or canonical encoding;
- digest, signature, MAC, proof, or literal domain-separation labels;
- cryptographic or TPM mechanism selection;
- production persistence, backup, recovery, or migration mechanisms;
- production resource-limit values;
- protected Attestation Result, permit, proof-of-possession, renewal-
  authorization, or admission implementation; and
- any new dependency or `unsafe` code.

Task 13 must choose finite limits for repository test tooling. Those values do
not become production protocol limits.

## Corpus model

### Snapshot fixtures

A snapshot fixture represents one candidate Evidence-binding transcript
instance plus the minimum independent expected inputs needed by the semantic
oracles. It is self-contained and has no references to another fixture.

Snapshots cover:

- valid initial appraisal and valid same-session renewal instances;
- Base-only and registered profile-specific claim sets;
- each registered provenance class;
- every single-change negative row in `docs/TEST_STRATEGY.md`;
- every shape and domain exclusion in `docs/TEST_STRATEGY.md`; and
- current-state revalidation of cached or boot-origin facts.

Claims are represented as an array of explicit claim entries. The array is a
fixture notation that preserves duplicate occurrences for negative tests. Claim
entry order is non-semantic: reordering an otherwise identical set cannot
change the oracle result. Exactly-once meaning, declared membership, value, and
provenance are judged independently. This choice does not prescribe a future
wire representation.

### History fixtures

A history fixture represents an ordered sequence of observations and actions
for one candidate protected-session lifecycle. It may contain valid or invalid
transitions. Strict sequence increase and interval non-overlap are acceptance
rules for conforming histories, not prerequisites for being a history fixture.

Histories cover every row in the evidence-time authority matrix in
`docs/TEST_STRATEGY.md`, including:

- valid initial collection and renewal;
- strictly increasing sequences with allowed gaps;
- sequence reuse or decrease;
- epoch/source change, restart, rollback, and discontinuity;
- concurrent or overlapping collection and compare-and-advance races;
- effective duration and exact challenge-expiry boundaries;
- stale snapshot or unrevalidated cached facts;
- time-domain and context substitution;
- temporary outage with intact recoverable state;
- missing, corrupt, contradictory, or rolled-back high-water;
- high-water advancement before later claim or policy rejection;
- non-advancement from invalid or unauthenticated coverage;
- profile transition continuity;
- terminal deletion and new-session recovery; and
- value-independent redacted diagnostics.

Each history observation is one independent candidate transcript instance.
Initial appraisal and each renewal therefore remain separate transcripts even
though the history records their same-session relationship.

The format-version-1 logical history-action vocabulary is closed to collection
open, snapshot freeze, drop, submit, validate, claim rejection, policy
rejection, renewal, concurrent submit, outage, rollback, restart, terminal end,
and deletion. The implementation plan freezes the literal JSON labels and the
required pre/post-state fields for each action before code is written. Adding a
new action after that freeze requires a reviewed format-version change.

## Authoritative manifest and inventory

`lab/conformance/corpus.json` is the only inventory and coverage authority.
Format version 1 contains exactly these top-level members:

- `format_version`, exactly the lexical JSON integer token `1` (not `1.0` or a
  boolean);
- `counts`, exact snapshot, history, and total counts;
- `fixtures`, the complete ordered registry of fixture entries;
- `validator_cases`, the complete ordered executable registry of non-file
  corpus, loader, and attack-parity self-tests; and
- `coverage`, the complete closed mapping from requirement tags to one or more
  fixture or validator-case IDs.

Each fixture entry contains only:

- a globally unique bounded ASCII identifier;
- one kind from the closed set `snapshot` or `history`;
- one normalized repository-relative path beneath the matching kind directory;
- `baseline`, either `null` for a valid baseline or the ID of one valid fixture
  of the same kind;
- `mutation`, either `null` for a valid baseline or one member of the closed
  single-change mutation registry;
- one expected earliest validation layer from layer 2 through layer 6, or the
  layer-6 success endpoint for a conforming fixture;
- one expected coarse disposition.

Each validator-case entry contains exactly a bounded ASCII ID, one operation
kind from `corpus-mutation`, `loader-probe`, or `attack-loader-parity`, one ID
from the closed self-test baseline registry, one registered deterministic
transform, one expected checkpoint from `layer-1`, `layer-2`, or `attack-parity`,
and one expected coarse disposition. Layer-1 cases appear only in this registry.
The implementation must prove a bijection between these manifest tuples and the
executable baseline/transform table: no tuple lacks one implementation and no
hidden executable case exists. That table contains baseline builders and
transform implementations only; it does not duplicate expected checkpoints,
dispositions, or coverage. The top-level `coverage` mapping is the only
requirement-to-case relation; every mapped ID names one registered fixture or
validator case, and no entry stores a second copy of its tags.

IDs match `[a-z0-9]+(?:-[a-z0-9]+)*` and contain at most 128 ASCII bytes. Each
path component matches `[a-z0-9]+(?:[._-][a-z0-9]+)*` and contains at most 128
ASCII bytes; the complete path contains at most 512 ASCII bytes. Paths use `/`,
contain no empty, `.`, or `..` component, begin with the directory for their
declared kind, and end in `.json`. The validator compares these ASCII bytes
exactly and performs no case folding or Unicode/platform normalization.

The validator derives kind and expectations from the manifest entry. No caller-
supplied kind selector is authoritative. The validator rejects a missing,
extra, duplicate, misclassified, non-regular, symlinked, out-of-root, or
unregistered path. It recomputes all three counts from validated entries and
the exact on-disk inventory; any disagreement fails the corpus before fixture
validation. There is no second registry and no invisible orphan fixture.

Manifest order is deterministic for review output but has no protocol meaning.
The approved implementation plan freezes the exact format-version-1 fixture
schemas, history-action enum, mutation registry, coverage mapping, candidate-
comparison rules, validator-case operation/baseline/transform registries, and
counts before code is written.
After that freeze, removing or changing a required member requires format
version 2 and a superseding ADR; compatible optional additions still require
review and explicit unknown-critical behavior.

Layer-1 corpus-boundary failures cannot be fixture entries inside the canonical
manifest they invalidate. Using fixed validator rules and no manifest-derived
expectation, the harness first completes layer 1 for the unmodified canonical
manifest, exact inventory, and executable-table bijection. Only after that
success may it register the manifest's validator-case expectations and exercise
each single-cause temporary mutation against a separate copy of the valid
corpus. The expected checkpoint and disposition come from the validated
canonical `validator_cases` entry, not from the invalid manifest mutation or the
executable table.

## Fixture oracle separation

Every admitted fixture has logically separate candidate and oracle sections.
The candidate section contains the transcript, abstract coverage statement, or
history presented for validation. The oracle section contains independently
supplied authenticated/registered/resolved inputs and expected state needed to
derive the correct result. Candidate fields never populate oracle fields.

For abstract coverage, the candidate lists the semantic meanings it claims to
cover together with their exact abstract values and relationships. Layer 5
compares that duplicate-preserving coverage statement with every component,
value, provenance relation, key/handle association, evidence-time relation,
semantic identity, and purpose in the complete layer-4 reconstructed
transcript. This models completeness, substitution, omission, duplication, and
cross-purpose reuse without selecting proof bytes, an algorithm, or a
cryptographic mechanism.

Negative fixtures name one valid baseline and one mutation in the manifest. The
one-change proof is layer-specific and the implementation plan freezes every
deterministic mutation transform:

- a layer-2 test applies one registered byte-level transform to baseline bytes
  and requires exact equality with the committed rejected bytes;
- a layer-3 test admits both JSON documents, applies one registered JSON-value
  transform to the complete baseline fixture document, and requires structural
  equality with the malformed fixture before schema normalization; and
- a layer-4, layer-5, or layer-6 test compares typed candidate sections after
  shape admission and allows only the leaf or relationship named by the
  registered semantic mutation.

For layer-3 JSON-value comparison, only object-member order is ignored; every
array retains its literal order because the malformed document may not yet have
a trusted kind schema. For typed layer-4 through layer-6 comparisons, object
member order and claim-entry order are ignored, while history-action order and
every other schema-declared array order are preserved. In both forms integers
compare by exact mathematical value, strings compare code point for code point,
and no text is trimmed, case-folded, or normalized. Oracle sections and top-
level manifest coverage mappings are excluded only from typed layer-4 through
layer-6 comparisons. A layer-5 candidate coverage statement is candidate data
and therefore remains in that comparison. Fixture files remain self-contained;
baseline and mutation are manifest metadata used only by the test oracle.

## Shared bounded JSON loader

Every repository consumer covered by Task 13 reads JSON through one shared
loader seam. The seam receives an internally resolved registered file and a
fixed trusted diagnostic label. It does not receive or infer snapshot/history
semantics.

The seam:

- accepts only a regular non-symlink file within the approved repository root;
- reads at most the configured test-tool byte limit;
- decodes strict UTF-8;
- accepts exactly one JSON document and only trailing JSON whitespace;
- rejects duplicate object names;
- rejects `NaN`, positive/negative infinity, and numeric tokens outside the
  configured finite parser bounds;
- bounds nesting depth, object fields, array items, key/string length, numeric-
  token length, and total nodes;
- never returns a partial value; and
- emits a fixed error class without raw paths, filenames, keys, values, control
  characters, CI commands, or tracebacks.

The initial implementation preserves the existing attack-scenario consumer's
exact limits and public behavior. The new conformance consumer receives
separately named finite repository-tool limits and a finite corpus-file count.
The implementation plan must freeze those values and prove each bound with a
single-cause negative test. These are test-harness limits, not production
protocol endorsements.

For the new conformance consumer, the implementation plan also freezes a
deterministic validation-operation budget counted across decoded nodes, schema
assertions, claim comparisons, history actions, and oracle comparisons.
Exceeding the budget fails closed. Its aggregate command has a finite outer
wall-clock timeout so standard-library parser or platform behavior cannot evade
the operation budget indefinitely. The existing attack-scenario consumer gains
no new timeout or operation-budget rejection; its current finite structural
bounds and exit behavior remain the parity contract.

## Six ordered validation layers

Every fixture declares the earliest layer expected to stop. The validator runs
layers in order and stops at the first failure. A fixture cannot expect or emit
a later-layer finding after an earlier layer fails.

Layer 1 is proven by validator self-tests because a failed corpus cannot safely
supply its own expected result. Canonical manifest entries cover layers 2-6 and
the conforming layer-6 endpoint.

### Layer 1: corpus boundary and inventory

Bootstrap the manifest through the shared loader under separately frozen
manifest limits, then validate its format version, closed registries, unique IDs
and paths, normalized containment, regular non-symlink files, exact inventory,
exact counts, and executable-table bijection without consuming manifest-derived
expectations. Manifest UTF-8, one-document, duplicate-name, numeric, or
resource-admission failure is therefore layer 1, not layer 2, and its expected
result in self-tests comes from a validator case registered only after the
unmodified canonical corpus passes layer 1. Failure disposition is `Malformed`.

### Layer 2: JSON admission

Apply the shared loader's UTF-8, one-document, duplicate-name, finite-number,
and resource-limit rules to registered fixture files. A valid RFC 8259 document
may still be rejected by a project resource or interoperability rule. Failure
disposition is `Malformed`.

### Layer 3: fixture envelope and kind shape

Validate only the reviewed format-version-1 envelope, candidate/oracle section
shapes, vocabulary, required fields, closed enums, claim-entry array shape,
history action shape, cardinality of semantic meanings, profile-declared claim
membership, and unknown-critical handling. Missing, duplicate, aliased,
invented, contradictory, or known-but-undeclared semantic meanings are
`Malformed` here. Unknown critical semantics are `Unsupported`. No accepted
claim value, provenance judgment, current-subject judgment, or lifecycle
transition is appraised here.

### Layer 4: independent transcript reconstruction

Build the expected semantic transcript independently from authenticated,
registered, resolved, and candidate inputs, then compare semantic equality.
Check complete challenge fields, profile contract, actual key and handle
association, evidence time, exact claims, provenance, semantic identities, and
purpose/domain exclusions. Candidate-provided expected values are never used as
the oracle. Authenticated challenge/`ExpectedContext`, actual-key/handle,
publisher, or protected-session association disagreement is
`ContextBindingMismatch`. Every other post-shape reconstruction inequality is
`EvidenceInvalid`.

### Layer 5: abstract coverage

Independently determine whether the fixture's abstract evidence mechanism
covers every exact reconstructed component, value, and relationship. Coverage
success does not prove claim truth or policy acceptance. Coverage failure is
`EvidenceInvalid` and cannot be masked by later appraisal. Task 13 models the
semantic coverage result only; it chooses no cryptographic proof or algorithm.

### Layer 6: appraisal or lifecycle semantics

For snapshots, appraise already-declared claim value, provenance, and current
live-subject semantics on coverage-valid inputs. For histories, apply the
independent lifecycle oracle to sequence, epoch, interval, high-water, outage,
restart, rollback, concurrency, advancement ordering, later claim/policy
appraisal, and terminal deletion. A valid temporal observation advances high-
water before a later `PolicyDenied`; invalid or unauthenticated coverage never
advances it. Outcomes use only the closed coarse vocabulary below.

The layer 4 reconstruction oracle, layer 5 coverage oracle, and layer 6
appraisal/lifecycle oracle use separate derivations and focused test baselines.
The required pipeline may pass an accepted result forward, but one oracle may
not call another to obtain its expected result or copy an expectation from the
candidate section.

Normal validation stops at the earliest failing layer. Separately, focused
oracle tests invoke layers 4, 5, and 6 against each registered single-change
semantic mutation with the prerequisites supplied by its valid baseline. These
tests prove reconstruction inequality, exact abstract-coverage rejection, and
independent appraisal behavior for the same mutation without weakening the
normal fail-closed pipeline.

## Violation-to-layer contract

| Isolated case | Earliest layer | Disposition |
| --- | --- | --- |
| Manifest admission/path/count/inventory failure | 1 self-test | `Malformed` |
| Fixture UTF-8, document, duplicate-name, numeric, or resource admission failure | 2 | `Malformed` |
| Invalid envelope or missing/duplicate/aliased/invented/known-but-undeclared semantic meaning | 3 | `Malformed` |
| Unknown critical semantic | 3 | `Unsupported` |
| Challenge/`ExpectedContext`, actual-key/handle, publisher, or protected-session association mismatch | 4 | `ContextBindingMismatch` |
| Any other post-shape reconstructed transcript inequality | 4 | `EvidenceInvalid` |
| Exact component/value/relationship absent, substituted, duplicated, or cross-purpose in abstract coverage | 5 | `EvidenceInvalid` |
| Covered claim/provenance/current-subject appraisal failure | 6 | `EvidenceInvalid` |
| Exact challenge expiry | 6 | `Expired` |
| Intact-state temporary authority outage | 6 | `AttestationUnavailable` |
| Epoch/sequence/interval/restart/rollback/high-water continuity loss | 6 | `ProtectedSessionLost` |
| Valid temporal advance followed by policy rejection | 6 | `PolicyDenied`; high-water remains advanced |
| All six layers conform | 6 success | `Conform` |

No validator may choose a disposition dynamically from attacker-controlled
fixture text.

## Coarse expected dispositions

Format version 1 permits exactly these abstract dispositions:

- `Conform`;
- `Malformed`;
- `Unsupported`;
- `ContextBindingMismatch`;
- `EvidenceInvalid`;
- `Expired`;
- `AttestationUnavailable`;
- `ProtectedSessionLost`; and
- `PolicyDenied`.

They preserve the M1-011/M1-012 coarse non-disciplinary mappings without
creating new runtime enums. The implementation issue must map every fixture to
exactly one earliest layer and one disposition. No fixture may encode an allow
fallback, cheating accusation, ban, raw failure detail, or client repair.

## Required coverage registry

Coverage tags are closed and machine checked. The implementation issue must
freeze the complete tag registry and map every current row in these project
authorities to at least one fixture or validator case:

- positive reconstruction;
- single-change negative matrix;
- shape and domain exclusions;
- evidence-time authority matrix;
- parser/resource bounds;
- manifest/inventory failures;
- diagnostic redaction; and
- attack-scenario loader parity.

Every negative fixture is reproduced by one registered layer-appropriate
mutation of its manifest-named valid baseline. The top-level mapping may associate multiple requirement
tags with one fixture or validator case only when one unchanged input
legitimately covers multiple requirements; each case still has one expected
earliest layer and disposition. Missing or duplicate coverage, unknown tags,
and mappings to an unregistered fixture or validator case fail the aggregate
gate.

No fixture count is invented in this design. The implementation plan derives
the exact count from the frozen row-to-fixture inventory, records the count in
the manifest, and verifies it mechanically.

## Consumer parity

Task 13 adds a new abstract-conformance validator and migrates the existing
attack-scenario validator to the shared loader. For the existing consumer:

- accepted and rejected inputs remain identical;
- all existing numeric limits remain identical;
- reviewed safe diagnostics, including bounded numeric locations, remain
  identical through a compatibility formatter;
- self-test assertions and aggregate-gate exit behavior remain identical; and
- scenario schema and semantic validation remain outside the shared loader.

Stage/layer classification is internal to the new validator and does not alter
the existing attack-scenario validator's public output.

## Security and privacy review

The corpus contains synthetic public test values only. It must contain no real
attestation identity, private/session key, player/account data, confidential
publisher material, host path, secret, or biometric data.

The new conformance diagnostics use fixed consumer, layer, and error-class
labels. They do not print manifest IDs, fixture paths, filenames, host paths,
JSON keys or values, challenge/context/key/time/proof material, control
characters, CI annotation commands, or tracebacks. Self-tests inject absolute
paths, control characters, and CI-command text and require value-independent
output. The existing attack-scenario compatibility formatter may continue to
emit its reviewed bounded line/column numbers and fixed safe messages; it may
not expose new raw values or paths.

The design adds no runtime retention. Repository fixtures remain public source
artifacts; temporary parsed values live only for one validator invocation.

## Dependency and license impact

Task 13 uses the Python standard library and existing repository tooling. It
adds no dependency, lockfile change, trusted runtime component, unsafe code,
cryptographic primitive, TPM library, or license boundary. Any implementation
proposal that needs a new dependency requires separate approval.

## Validation strategy

The implementation plan must use negative tests first and must prove:

- each loader rejection independently;
- every manifest/inventory mismatch independently;
- every fixture-envelope failure independently;
- earliest-layer fail-closed behavior;
- independent reconstruction, coverage, and appraisal/lifecycle oracles;
- claim-order independence and duplicate-meaning preservation;
- every required coverage tag and exact fixture count;
- redacted diagnostics under hostile labels and content;
- attack-scenario validator parity; and
- the complete repository normal and release gates where applicable.

Byte fuzzing of a production parser remains M2 work. Task 13 must consider
property tests for manifest inventory and claim-order independence, but it must
not add a dependency without separate approval.

## Acceptance criteria

The implementation is complete only when:

1. a canonical Task 13 issue is approved;
2. the format-version-1 manifest is the sole exact inventory authority;
3. snapshots and histories cover every frozen required row and tag;
4. every fixture has one expected earliest layer and disposition;
5. all six layers stop at the earliest failure;
6. the three semantic oracles remain independent;
7. the shared loader is bounded, new conformance diagnostics are value-
   independent, and legacy attack diagnostics preserve their reviewed output;
8. attack-scenario behavior is proven unchanged;
9. no production representation, parser, crypto, TPM, persistence, or numeric
   limit is selected;
10. architecture, threat, test, lab, roadmap, and ADR documentation agree;
11. all repository gates pass; and
12. a human reviewer understands and approves every changed line.

## Rollback

Before publication, deleting the uncommitted Task 13 files and restoring the
ADR index returns the worktree to merged `origin/main` at `9a04b055`.

After acceptance, changing the corpus kinds, six-layer order, manifest
authority, claim-array semantics, loader parity boundary, or deferred production
boundary requires a superseding ADR and a versioned corpus migration. Disabling
the Task 13 aggregate gate is not an acceptable rollback because it would make
the corpus non-authoritative.

## Primary sources

- [RFC 8259 Section 4](https://www.rfc-editor.org/rfc/rfc8259.html#section-4)
  describes object-name uniqueness interoperability.
- [RFC 8259 Section 6](https://www.rfc-editor.org/rfc/rfc8259.html#section-6)
  describes interoperable number limits.
- [RFC 8259 Section 8.1](https://www.rfc-editor.org/rfc/rfc8259.html#section-8.1)
  requires UTF-8 for exchanged JSON text outside a closed ecosystem.
- [RFC 8259 Section 9](https://www.rfc-editor.org/rfc/rfc8259.html#section-9)
  permits parsers to set limits on size, nesting, number range, and string
  length.
- [JSON Schema Draft 2020-12 core](https://json-schema.org/draft/2020-12/json-schema-core)
  and [validation](https://json-schema.org/draft/2020-12/json-schema-validation)
  define the schema vocabulary used for fixture-envelope assertions. OGIR's
  six-layer ordering is a project decision, not a JSON Schema requirement.
- [Python 3.14 `json`](https://docs.python.org/3.14/library/json.html)
  documents the default decoder's acceptance of repeated object names and
  non-finite numeric values and the hooks used to reject them.
- [ADR-0010](../../adr/0010-semantic-evidence-binding-transcript.md),
  [ADR-0011](../../adr/0011-challenge-anchored-evidence-time.md),
  `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`,
  `docs/ARCHITECTURE.md`, and `docs/TEST_STRATEGY.md` are project authorities.

## Current accepted-design state

- Conversation-level architecture and the exact written design/ADR are approved
  for implementation planning.
- No Task 13 issue, plan execution, fixture, validator, commit, push, or remote
  mutation was authorized by the written-candidate approval.
- The implementation plan and its machine-validated planning registry are
  written candidates pending exact human approval. Their existence authorizes
  no implementation, issue, commit, publication, or remote mutation.
- Implementation still requires the canonical issue and the plan's explicit
  execution authorization.
