# ADR-0012: Define one abstract JSON conformance corpus and validation pipeline

- Status: Accepted
- Date: 2026-09-01
- Owners: Initial maintainer
- Related issues: Not yet created; this accepted design must be linked to the canonical M1-013 issue before implementation
- Supersedes: None
- Superseded by: None

## Context

ADR-0010 defines one closed semantic Evidence-binding transcript but deliberately
selects no representation or cryptographic mechanism. ADR-0011 defines its
challenge-anchored protected collection interval and lifecycle semantics but
deliberately selects no runtime type, parser, persistence mechanism, TPM
mapping, or production numeric limit.

Roadmap Task 13 must make those contracts executable before M2 chooses a
production representation. The repository already has a bounded standard-
library JSON validator for attack scenarios, but independent loaders would
create parser disagreement, limit drift, and diagnostic drift. A fixture format
must also preserve duplicate claim meanings for negative tests without making
claim order semantically significant, and histories must represent invalid as
well as valid lifecycle transitions.

One durable decision is needed for the test-only corpus boundary: fixture kinds,
inventory authority, shared loader, ordered validation pipeline, oracle
separation, diagnostics, and the production decisions that remain deferred.

## Decision drivers

- Parser disagreement between repository consumers is release-blocking.
- Pull-request-controlled JSON requires finite byte, nesting, collection,
  string, number, node, and file-count limits.
- Duplicate and ambiguous security-critical meanings must fail closed.
- Candidate transcript data cannot define its own expected transcript,
  coverage, appraisal, or lifecycle result.
- Reconstruction, abstract coverage, claim/provenance appraisal, and temporal
  lifecycle continuity must remain independently testable.
- Negative fixtures must preserve duplicate claim occurrences while valid claim
  semantics remain order-independent.
- New conformance diagnostics must remain context-free and value-independent;
  legacy attack-scenario diagnostics retain reviewed compatibility behavior.
- Task 13 may define concrete repository test notation and test-tool limits but
  must not choose production representation, parsing, cryptography, TPM,
  persistence, or numeric limits.
- The existing attack-scenario validator must retain its accepted inputs,
  limits, diagnostics, and exit behavior.

## Options considered

### One corpus, one manifest, one shared consumer-neutral loader, and six ordered layers

Selected. Snapshots and histories share one authoritative versioned manifest
and one consumer- and fixture-kind-neutral bounded loader. Six ordered layers stop at the earliest
failure. Reconstruction, abstract coverage, and appraisal/lifecycle remain
separate oracles.

### One undifferentiated fixture kind

Rejected. It obscures whether a case is one transcript instance or a lifecycle
transition and makes lifecycle coverage difficult to inventory exactly.

### Require every history to be strictly increasing

Rejected. Strict increase is a positive acceptance rule. Making it a shape rule
would make reused/decreased sequence, rollback, and overlap histories
unrepresentable.

### Separate manifest and fixture registry

Rejected. Two authorities can disagree and can silently make unregistered files
invisible. One manifest contains the complete registry and mechanically checked
counts.

### Per-consumer JSON loaders

Rejected. Shared prose does not prevent code, limit, duplicate-key, numeric, or
diagnostic drift. One loader seam is required.

### Let the loader accept a caller-selected fixture kind

Rejected. A caller-selected kind becomes a classification authority and cannot
serve the attack-scenario consumer. The loader remains consumer-neutral; the
validated manifest selects conformance kind and later semantic validation.

### JSON objects keyed by claim name

Rejected for fixture claim collections. Duplicate meanings would be collapsed
or rejected before the semantic negative case can be represented. An array of
explicit claim entries preserves duplicate occurrences. Entry order remains
non-semantic.

### One structural stage followed by one semantic stage

Rejected as too coarse. It conflates corpus inventory, JSON admission, fixture
shape, independent reconstruction, abstract coverage, and appraisal/lifecycle
semantics. It also invites one failure to mask another oracle.

### Report every possible later failure after an earlier failure

Rejected. Running semantic checks on unadmitted or malformed input violates
fail-closed ordering and makes diagnostics depend on invalid partial values.
Only the earliest failing layer is reported.

### Defer all parsers and limits to M2

Rejected. Production parser and limit choices remain deferred, but Task 13
cannot safely ingest repository-controlled JSON or preserve existing validator
behavior without bounded test-only tooling.

### Freeze production representation in Task 13

Rejected. JSON is fixture notation only. Production types, canonical encoding,
cryptographic coverage, TPM mapping, persistence, and numeric limits require
separate M2/M3 decisions.

## Decision

On 2026-09-02, the decision owner accepted this exact ADR as part of approved
temporary-index tree `f3326ab93724b583b72601b4c50627ce624c1120`, binary
patch SHA-256
`8c8c4d912a20a107a8fdead0bd15ba18471a4ab4ca37dce7f968caa425ff8d99`.
Acceptance authorizes implementation planning only; issue creation, plan
execution, implementation, commit/sign-off, and publication remain separately
gated.

Task 13 defines one test-only abstract JSON conformance corpus under
`lab/conformance/`. It has exactly two fixture kinds:

- a **snapshot** is one self-contained candidate transcript instance;
- a **history** is an ordered sequence of observations and actions for one
  candidate protected-session lifecycle and may intentionally violate
  continuity rules.

Claims are encoded as arrays of explicit entries so duplicate meanings remain
representable. Claim-entry order has no semantic meaning. Histories are ordered;
valid histories require the ADR-0011 sequence/interval rules, while negative
histories isolate one violation.

The logical history actions are collection open, snapshot freeze, drop, submit,
validate, claim rejection, policy rejection, renewal, concurrent submit,
outage, rollback, restart, terminal end, and deletion. The approved
implementation plan freezes their literal JSON labels and required pre/post-
state fields before code is written.

`lab/conformance/corpus.json` format version 1 is the sole inventory and coverage
authority. It contains exactly `format_version`, `counts`, `fixtures`,
`validator_cases`, and `coverage`. `format_version` is the lexical JSON integer
token `1`. Counts cover snapshots, histories, and total fixtures. Fixture
entries have one bounded ASCII ID, kind, normalized in-root path, valid-baseline
ID or `null`, registered single-change mutation or `null`, expected earliest
layer from layer 2 through layer 6 (or the conforming layer-6 endpoint), and
expected coarse disposition. Validator-case entries form the executable non-file
self-test registry: each names an operation kind (`corpus-mutation`,
`loader-probe`, or `attack-loader-parity`), a closed-registry baseline, a deterministic
transform, an expected checkpoint, and an expected coarse disposition. The
implementation proves a bijection between those tuples and its executable
baseline/transform table. That table contains implementations only and does not
duplicate expected checkpoints, dispositions, or coverage. The top-level
coverage mapping is the only
requirement-to-case relation and names registered fixture or validator-case IDs.

IDs use the project's bounded kebab-case grammar. Every path component uses only
bounded ASCII lowercase letters, digits, `.`, `_`, or `-`, starts and ends
alphanumeric, and has no adjacent separator. Paths use `/`, contain no empty,
`.`, or `..` component, begin with their kind directory, and end in `.json`.
The validator compares path bytes exactly with no case folding or normalization.
The validator rejects every missing, extra, duplicate,
misclassified, non-regular, symlinked, out-of-root, or unregistered path and
every count disagreement. Kind comes from the validated manifest, never an
independent caller selector.

Layer-1 corpus-boundary failures are single-cause validator self-tests derived
from temporary mutations of a valid corpus. Using fixed rules and no manifest-
derived expectation, the harness first completes layer 1 for the unmodified
canonical manifest, inventory, and executable-table bijection. Only then may it
register the validated case expectations and run a separate invalid copy. Such
cases cannot be authoritative fixture entries in the invalid manifest whose
failure they test.

One shared standard-library bounded JSON loader serves both the new abstract-
conformance validator and the existing attack-scenario validator. It is
consumer- and fixture-kind-neutral and enforces regular non-symlink files, approved-root
containment, finite bytes, strict UTF-8, one document, duplicate-name rejection,
finite bounded numeric tokens, nesting, object, array, key/string, and total-
node limits. It never returns a partial value. Manifest admission is a layer-1
bootstrap under separately frozen limits; layer 2 applies admission rules only
to registered fixture files. The new conformance validator adds a deterministic
operation budget and finite outer wall-clock timeout. The attack-scenario
migration adds no rejection and preserves exact existing
limits, accepted/rejected inputs, reviewed safe messages and bounded numeric
locations, and exit behavior through a compatibility formatter. The new
conformance formatter uses only fixed consumer/layer/error-class labels.

The abstract-conformance validator applies six layers in order and stops at the
first failure:

1. manifest JSON bootstrap, corpus boundary, and inventory;
2. JSON admission;
3. fixture envelope and kind shape;
4. independent transcript reconstruction;
5. abstract coverage; and
6. claim/provenance appraisal for snapshots or lifecycle semantics for
   histories.

Layer 3 maps an invalid envelope and missing, duplicate, invented, aliased,
contradictory, or known-but-undeclared profile semantics to `Malformed`, and
unknown critical semantics to `Unsupported`. Layer 4 maps
challenge/`ExpectedContext`, actual-key/handle,
publisher, or protected-session association disagreement to
`ContextBindingMismatch`; every other post-shape reconstruction inequality is
`EvidenceInvalid`. Layer 5 exact-coverage failure is `EvidenceInvalid`. Layer 6
uses the remaining coarse lifecycle/appraisal dispositions below.

Every admitted fixture has logically separate candidate and oracle sections.
The candidate presents transcript, abstract coverage, or history data; the
oracle supplies the independent authenticated/registered/resolved inputs and
expected state used to derive the correct result. For abstract coverage, the
candidate lists every claimed covered component with its exact abstract value
and relationships; layer 5 compares this duplicate-preserving statement with
the complete layer-4 reconstruction without choosing cryptographic proof.

Each negative fixture names one valid same-kind baseline and one registered
mutation. Layer-2 cases must equal one deterministic registered byte transform
of baseline bytes. Layer-3 cases must equal one deterministic registered JSON-
value transform of the complete baseline fixture before schema normalization.
Layer-4 through layer-6 cases use one registered typed semantic leaf or
relationship transform after shape admission. The layer-3 transform covers the
complete fixture document, including
envelope and oracle sections; only object-member order is ignored and all arrays
remain literal. Typed comparisons ignore object-member and claim-entry order,
preserve history-action and other schema-declared array order, compare integers
mathematically and strings code point for code point, and perform no trimming,
case folding, or normalization. Oracle sections and the top-level coverage
mapping are excluded only from typed comparisons, while a layer-5 candidate
coverage statement remains candidate data.

Every fixture declares one expected earliest layer and one disposition. Layer 4
reconstruction, layer 5 coverage, and layer 6 appraisal/lifecycle use separate
derivations and focused test baselines. A pipeline may pass an accepted result
forward, but one oracle may not call another to obtain its expected result or
copy an expectation from candidate data. A failed earlier layer prevents all
later layers from running in the normal pipeline. Focused oracle tests separately
invoke reconstruction, coverage, and appraisal/lifecycle against every
registered semantic mutation using its valid-baseline prerequisites, proving
the three independent assertions required by the test strategy.

The closed format-version-1 dispositions are `Conform`, `Malformed`,
`Unsupported`, `ContextBindingMismatch`, `EvidenceInvalid`, `Expired`,
`AttestationUnavailable`, `ProtectedSessionLost`, and `PolicyDenied`. They are
abstract fixture labels mapped to existing coarse non-disciplinary semantics,
not new runtime enums. `PolicyDenied` covers the history case where a valid
temporal observation advances high-water before later policy rejection.

The manifest coverage registry maps every current positive-reconstruction row,
single-change negative row, shape/domain exclusion, evidence-time authority
row, parser/resource bound, inventory failure, diagnostic-redaction case, and
attack-loader parity case to at least one fixture or validator self-test. Exact
counts are derived and frozen in the implementation plan; this ADR invents no
count.

JSON remains repository fixture notation only. This ADR selects no runtime
transcript type, production serializer/parser/schema, canonical bytes,
algorithm, signature/MAC/proof, literal domain label, TPM mapping, persistence,
backup/recovery mechanism, production limit, protected result, permit,
proof-of-possession, renewal-authorization, or admission implementation.

## Consequences

Positive consequences:

- The corpus makes ADR-0010/0011 semantics executable before production wire
  work.
- One manifest makes inventory and count drift fail closed.
- One loader prevents parser, limit, and diagnostic disagreement between
  repository consumers.
- Six ordered layers identify the earliest failure without evaluating partial
  invalid values.
- Independent reconstruction, coverage, and appraisal/lifecycle oracles prevent
  one success from substituting for another.
- Claim arrays preserve duplicate negative cases without imposing claim order.
- Existing attack-scenario behavior remains stable.

Negative consequences:

- The manifest, fixture files, coverage registry, and derived counts must change
  together.
- The shared loader becomes common test infrastructure and requires stronger
  regression coverage than either ad hoc loader.
- The corpus is not a production interoperability format and cannot directly
  prove a later wire implementation correct.
- Exact repository-tool limits must be reviewed and maintained separately from
  future production limits.

Follow-up obligations:

- Create and approve the canonical M1-013 issue before implementation.
- Write a negative-first implementation plan that freezes exact fixture counts,
  coverage mapping, schemas, history-action enum, mutation registry, candidate-
  comparison rules, validator-case operation/baseline/transform registries,
  new-consumer operation/wall-clock budgets, and test-tool limits.
- Update architecture, threat model, test strategy, lab documentation, roadmap,
  and the ADR index with the implementation.
- Require a superseding ADR and corpus version change for an incompatible
  corpus contract.

## Threat-model impact

Affected attacker classes are A1/A6 for malicious repository-controlled
fixtures or validator changes and A5 for faulty verifier-oracle design. A8
privacy risk applies if diagnostics disclose paths or transcript values.

Affected assets are conformance-test integrity, evidence-binding transcript
meaning, evidence-time continuity semantics, CI availability, and confidential
diagnostic values. Affected test-only boundaries are repository bytes to loader,
manifest to fixture selection, candidate values to independent oracles, and
validator failures to CI output.

The decision narrows parser disagreement, resource exhaustion, duplicate-name
ambiguity, orphan-fixture omission, candidate-as-oracle confusion, later-stage
masking, and diagnostic injection/disclosure. It adds no runtime authorization
or privilege path.

Residual risks remain: a jointly wrong fixture and oracle can agree; static
fixtures cannot prove every arbitrary history; a future production parser can
disagree with the test notation; and a compromised maintainer or CI runner can
alter both corpus and validator. Independent review, later differential/fuzz
work, exact inventory gates, and M2/M3 representation decisions remain
necessary.

## Privacy impact

The corpus uses synthetic public test values only. Real attestation identities,
private/session keys, player/account data, confidential publisher material,
host paths, secrets, and biometric data are prohibited.

The new conformance diagnostics contain fixed consumer, layer, and error-class
labels only. They do not print manifest IDs, fixture paths, filenames, host
paths, JSON keys or values, challenge/context/key/time/proof material, control
characters, CI annotation commands, or tracebacks. Self-tests must inject those
values and prove value-independent output. The existing attack-scenario
compatibility formatter may retain its reviewed bounded line/column numbers and
fixed safe messages, but may expose no new raw values or paths.

No runtime retention changes. Parsed values exist only for one validator
invocation; public fixtures remain ordinary reviewed repository source.

## Dependency and license impact

The decision uses the Python standard library and existing repository tooling.
It adds no dependency, lockfile change, runtime TCB component, unsafe code,
cryptographic primitive, TPM library, or license boundary. Any dependency
proposal requires separate purpose, maintenance, security, and license review.

## Validation

The implementation must prove, with negative tests first:

- every loader rejection and resource bound independently;
- every manifest and on-disk inventory mismatch independently;
- every fixture-envelope and unknown-critical failure independently;
- exact earliest-layer fail-closed behavior;
- independent reconstruction, coverage, and appraisal/lifecycle oracles;
- focused reconstruction, exact-coverage, and appraisal checks for every
  registered single-change semantic mutation;
- claim-order independence and duplicate-meaning preservation;
- every frozen coverage tag and exact fixture count;
- fixed redacted diagnostics under hostile paths, labels, and values;
- parity of the existing attack-scenario consumer; and
- all repository normal/release documentation, formatting, lint, and test gates.

The implementation plan must map every row in the existing transcript and
evidence-time matrices to a fixture or validator self-test. Byte fuzzing of a
production parser remains M2 work. Property testing for manifest inventory and
claim-order independence must be considered without adding an unapproved
dependency.

## Rollback

Before acceptance, deleting the proposed Task 13 design/ADR and restoring the
index returns the branch to merged `origin/main` at `9a04b055`.

After acceptance, changing the two kinds, manifest authority, claim-array
semantics, six-layer order, shared-loader parity contract, disposition
vocabulary, or deferred-production boundary requires a superseding ADR and a
versioned corpus migration. Disabling the aggregate conformance gate is not an
acceptable rollback.

## Primary sources

- [RFC 8259 Section 4](https://www.rfc-editor.org/rfc/rfc8259.html#section-4)
  describes object-name uniqueness interoperability.
- [RFC 8259 Section 6](https://www.rfc-editor.org/rfc/rfc8259.html#section-6)
  describes interoperable number limits.
- [RFC 8259 Section 8.1](https://www.rfc-editor.org/rfc/rfc8259.html#section-8.1)
  requires UTF-8 for exchanged JSON text outside a closed ecosystem.
- [RFC 8259 Section 9](https://www.rfc-editor.org/rfc/rfc8259.html#section-9)
  permits parser limits on size, nesting, number range, and string length.
- [JSON Schema Draft 2020-12 core](https://json-schema.org/draft/2020-12/json-schema-core)
  and [validation](https://json-schema.org/draft/2020-12/json-schema-validation)
  define schema vocabulary used for fixture-envelope assertions. The six-layer
  order is an OGIR decision, not a JSON Schema requirement.
- [Python 3.14 `json`](https://docs.python.org/3.14/library/json.html)
  documents default repeated-name/non-finite acceptance and rejection hooks.
- [ADR-0010](0010-semantic-evidence-binding-transcript.md),
  [ADR-0011](0011-challenge-anchored-evidence-time.md), the
  [M1-013 design](../superpowers/specs/2026-09-01-m1-013-abstract-json-conformance-fixtures-design.md),
  security invariants, architecture, threat model, test strategy, and AI
  development policy are project authorities.
