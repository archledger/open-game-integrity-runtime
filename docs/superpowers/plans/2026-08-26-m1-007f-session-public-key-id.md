# M1-007F Session Public-Key Lookup Handle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one fixed-width, redacted, non-authoritative `SessionPublicKeyId` domain newtype whose public surface, value behavior, privacy boundary, and future per-session lifecycle are completely specified and mechanically proved.

**Architecture:** Keep the implementation entirely in the existing pure `ogir-model` crate: one public length constant, one private-field `[u8; 32]` newtype, two infallible byte methods, fixed redacted `Debug`, and plain copy/equality/hash semantics. A dedicated integration test exhausts every byte position/value and pins the production surface; single-cause compile-fail doctests prohibit type confusion and convenience/authority interfaces. ADR-0008 and existing architecture, roadmap, trust, privacy, and test documents record the future owner/consumer obligations without adding key generation, proof of possession, result, permit, or admission behavior.

**Tech Stack:** Rust 1.98.0, edition 2024, Rust standard library only (`TypeId`, `HashSet`, `DefaultHasher` in tests), existing `ogir-model` workspace crate, Cargo tests/doctests/Clippy/rustdoc, Bash/Git disposable mutation worktrees, the existing repository/ADR/DCO gates, and GitHub CLI for guarded issue/PR workflow.

**Spec:** `docs/superpowers/specs/2026-08-26-m1-007f-session-public-key-id-design.md`

## Global Constraints

- Before every task, read the approved spec plus the task-relevant sections of `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/AI_DEVELOPMENT_POLICY.md`, and ADR-0006/ADR-0007.
- Work only in `/home/wisbfime/Open Game Intergrity Runtime  - Github Project/open-game-integrity-runtime-m1-007f` on `research/m1-007f-session-public-key-id`; preserve every other worktree, branch, backup ref, and bundle.
- The approved base is exact merged main `9269b570ce83be01c1309469ff85fb79d4fa0c3d`. If local or remote main changes before execution, stop and review/rebase the plan rather than silently applying it to a new base.
- `SESSION_PUBLIC_KEY_ID_LENGTH` is exactly `32`; `SessionPublicKeyId` stores exactly `[u8; SESSION_PUBLIC_KEY_ID_LENGTH]` in one private tuple field.
- Expose only `from_bytes([u8; 32]) -> Self` and `as_bytes(&self) -> &[u8; 32]`; both are `pub const fn` and `#[must_use]`.
- Derive only `Clone`, `Copy`, `PartialEq`, `Eq`, and `Hash`; implement `Debug` manually as exactly `SessionPublicKeyId([REDACTED; 32])`.
- Accept every 32-byte array, including all-zero and all-`0xff`; do not normalize, reserve, reject, generate, hash, or reinterpret any value.
- The handle is constructible/copyable non-authoritative data. Construction, equality, hashing, or byte access must never create a decision, verified-attestation capability, validated permit, proof-of-possession result, or admission authority.
- Add no `Default`, `Display`, ordering, `From`, `Into`, `TryFrom`, `AsRef`, `FromStr`, string, serialization, mutable accessor, generator, validity predicate, authority conversion, or lifecycle method.
- Do not change `LocalSession`, verifier flow, protocol/evidence/result/permit types, applications, SDK/FFI, workflows, scenario schema/corpus, or any production crate except `ogir-model`.
- Add no production dependency, feature, crate, manifest, lockfile, build script, parser, serializer, network, persistence, async, I/O, RNG, cryptographic primitive, key material, TPM operation, `unsafe`, C, FFI, privileged behavior, production key, or signing operation. Repository tests/reviews and guarded GitHub workflow remain non-product evidence operations.
- Future lifecycle is normative documentation only: one future trusted key/handle belongs to one publisher and `SessionId`, persists through renewal of that session, becomes invalid at `Ended`/`Invalidated`, and is never reused across sessions or publishers. The bare copied value does not enforce or erase that lifetime.
- Explicit `as_bytes` access is a trusted functional boundary, not an approved diagnostic sink. No default formatting may expose any full or partial byte, prefix, suffix, hash, pointer, or dynamic content.
- Write the missing-type test first and observe the exact RED compiler failure before production implementation. A zero-test success or wrong-cause failure is not evidence.
- The fixed runtime matrix executes exactly `32 × 256 = 8,192` position/value cases and separately exercises all-zero, all-`0xff`, alternating, ascending, and descending whole-value controls.
- Use one compile-fail block per forbidden boundary so one compiler error cannot mask another. Every imported type must resolve before the intended length/type/privacy/trait/method error.
- The structural test pins actual non-doc production code after CRLF normalization; it supplements doctests because a private supporting type or unrelated compiler error can otherwise make a negative proof vacuous.
- The minimum nine approved mutation categories are expanded into 19 single-cause probes so constructor/accessor semantics, raw/partial diagnostics, each forbidden convenience interface, and each named authority shortcut fail independently. This strengthens proof without changing scope or authority.
- Add no attack scenario: this pure vocabulary slice accepts no runtime threat and implements no threat control. Cross-session substitution, relay, replay, proof, permit, and admission scenarios remain with the later behavior-owning issues.
- Append `docs/LESSONS_LEARNED.md` only if implementation or review confirms a concrete mistaken assumption with a durable prevention rule; do not add a ceremonial entry.
- After every material change, refresh `/home/wisbfime/Agent Shared Memory/project-open-game-integrity-runtime.md` and its `index.md` row with exact SHA, tests, external state/rollback, lessons, and resumption action.
- Keep every commit unsigned until the user certifies one exact frozen range. Never add `Signed-off-by: archledger <archledger236@gmail.com>`. The only permitted eventual trailer is `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>` after exact human certification.
- Do not infer DCO certification, line-by-line review, responsibility acceptance, publication, or merge authority from written-spec approval, plan approval, or execution permission.
- Do not push, rewrite commit metadata, create a PR, change the live issue to `needs-review`, mark human-only PR fields, merge, delete a branch, dismiss an alert, or remove a retained worktree before the task that explicitly authorizes and guards that action.

## File and Responsibility Map

**Create:**

- `crates/ogir-model/tests/session_public_key_id.rs` — exact value semantics, complete 8,192-case matrix, fixed whole-value controls, type distinction, diagnostic privacy, and structural public-surface proof.
- `docs/adr/0008-session-public-key-id-is-not-authority.md` — durable non-authority, lifecycle, privacy, and deferred-consumer decision.

**Modify:**

- `crates/ogir-model/src/lib.rs` — length constant, private newtype, exact methods, fixed `Debug`, positive rustdoc, and single-cause compile-fail boundaries.
- `docs/ARCHITECTURE.md` — identifier trust-source row and explicit lookup-handle producer/consumer/non-authority contract.
- `docs/ROADMAP.md` — mark the missing identifier follow-up as M1-007F while preserving task 11 for result/reason taxonomy.
- `docs/TRUST_MODEL.md` — reject client-supplied/key-ID authority and name future trusted owner/verifier/relying-party duties.
- `docs/PRIVACY_MODEL.md` — treat the handle as correlation-sensitive and scope it to one publisher/session with renewal-only reuse.
- `docs/TEST_STRATEGY.md` — exact seven runtime tests, 19 doctests added by this slice, 8,192-case matrix, structural proof, and 19-probe mutation table.
- `docs/adr/index.md` — exact Accepted ADR-0008 row.
- `planning/issues/007f-session-public-key-id.md` — time-bounded implementation evidence and `status: needs-review` only after all proof/review gates pass.
- `docs/LESSONS_LEARNED.md` — conditional append-only entry only for a confirmed new implementation/review mistake.

**External/ignored evidence only:**

- One live GitHub issue with the exact local body/taxonomy; one eventual remote feature branch and non-draft PR; never a merge in this plan.
- `.superpowers/sdd/2026-08-26-m1-007f-session-public-key-id/mutation-report.md` and `pr-body.md` — ignored exact-head evidence, never committed.
- `/home/wisbfime/Open Game Intergrity Runtime  - Github Project/backups/ogir-m1-007f-pre-dco-${m1_007f_backup_stamp}.bundle` plus sibling SHA-256 manifest — retained rollback evidence after human DCO certification; the variable is resolved from the exact UTC command in Task 6 before file creation.

**Intentionally unchanged:**

- `crates/ogir-agent/**`, `crates/ogir-verifier/**`, `crates/ogir-protocol/**`, `apps/**`, `sdk/**`, `lab/scenarios/**`, `.github/workflows/**`, every `Cargo.toml`, `Cargo.lock`, and `rust-toolchain.toml`.
- `docs/THREAT_MODEL.md` and `docs/PROTOCOL.md` because this issue adds neither a runtime threat control nor a wire field. A concrete review finding may change that only through explicit scope review.

---

### Task 1: Guardedly Create the Reviewed Ready Issue and Freeze Preconditions

**Files:**

- Read: `planning/issues/007f-session-public-key-id.md`
- Read: `scripts/create-initial-issues.sh`
- External: one GitHub issue only; no repository file change

**Interfaces:**

- Consumes: the approved issue body at local `status: ready`, the exact approved plan commit recorded in Shared Memory, and remote main `9269b570ce83be01c1309469ff85fb79d4fa0c3d`.
- Produces: one open live issue titled `M1-007F: Define the session public-key lookup handle` with byte-identical body, exact canonical labels, milestone `M1 Domain Model`, and a discovered decimal issue number.

- [ ] **Step 1: Revalidate local and remote preconditions without mutation**

Run each command separately:

```bash
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
git ls-remote origin refs/heads/main
git ls-remote --heads origin refs/heads/research/m1-007f-session-public-key-id
gh issue list --repo archledger/open-game-integrity-runtime --state all --limit 500 --json number,title,state,url
gh pr list --repo archledger/open-game-integrity-runtime --state all --head research/m1-007f-session-public-key-id --json number,state,url
sha256sum planning/issues/007f-session-public-key-id.md
```

Then resolve the exact-title count:

```bash
m1_007f_title='M1-007F: Define the session public-key lookup handle'
m1_007f_existing_count="$(gh issue list --repo archledger/open-game-integrity-runtime --state all --limit 500 --json title --jq '[.[] | select(.title == "M1-007F: Define the session public-key lookup handle")] | length')"
test "${m1_007f_existing_count}" -eq 0
```

Expected: clean approved-plan head; origin/main and live remote main both equal `9269b570ce83be01c1309469ff85fb79d4fa0c3d`; no remote feature branch or PR; zero exact-title issues; local issue SHA-256 `156c1521dc29af0da508dc6cbcf897b15d4d7a99c096f2b21497d9b99a4ac781`.

If main, plan head, body hash, issue title count, branch, or PR state differs, stop without writing GitHub and review the changed state.

- [ ] **Step 2: Create exactly the reviewed ready issue**

Run:

```bash
m1_007f_issue_url="$(gh issue create \
  --repo archledger/open-game-integrity-runtime \
  --title 'M1-007F: Define the session public-key lookup handle' \
  --body-file planning/issues/007f-session-public-key-id.md \
  --milestone 'M1 Domain Model' \
  --label 'type: implementation' \
  --label 'area: model' \
  --label 'area: privacy' \
  --label 'risk: trusted-computing-base' \
  --label 'risk: privacy' \
  --label 'status: ready')"
printf '%s\n' "${m1_007f_issue_url}"
```

Expected: exactly one GitHub issue URL ending in a decimal issue number. Do not guess or hard-code the number.

- [ ] **Step 3: Read back exact body bytes and metadata**

Run:

```bash
m1_007f_issue_number="$(gh issue list --repo archledger/open-game-integrity-runtime --state all --limit 500 --json number,title --jq '.[] | select(.title == "M1-007F: Define the session public-key lookup handle") | .number')"
m1_007f_issue_count="$(gh issue list --repo archledger/open-game-integrity-runtime --state all --limit 500 --json title --jq '[.[] | select(.title == "M1-007F: Define the session public-key lookup handle")] | length')"
test "${m1_007f_issue_count}" -eq 1
test -n "${m1_007f_issue_number}"
m1_007f_local_body="$(base64 -w0 planning/issues/007f-session-public-key-id.md)"
m1_007f_live_body="$(gh issue view "${m1_007f_issue_number}" --repo archledger/open-game-integrity-runtime --json body --jq '.body | @base64')"
test "${m1_007f_live_body}" = "${m1_007f_local_body}"
gh issue view "${m1_007f_issue_number}" --repo archledger/open-game-integrity-runtime --json number,title,state,milestone,labels,url
```

Require:

```text
state: OPEN
milestone: M1 Domain Model
labels (sorted): area: model,area: privacy,risk: privacy,risk: trusted-computing-base,status: ready,type: implementation
```

If body bytes or metadata differ, do not continue to code. Preserve the returned issue number and correct only the exact mismatch through a separately reviewed guarded edit.

- [ ] **Step 4: Record external state and rollback**

Refresh Shared Memory with exact issue number/URL, local/live body hash, labels, milestone, local HEAD, remote main, and absence of remote branch/PR. Before implementation, rollback is closing only this new issue after explicit authorization; never delete or rewrite unrelated issues. No repository commit is created in this task.

---

### Task 2: Add the Fixed-Width Value Type Test-First

**Files:**

- Create: `crates/ogir-model/tests/session_public_key_id.rs`
- Modify: `crates/ogir-model/src/lib.rs:40,267-290`

**Interfaces:**

- Consumes: existing root-level `fmt`, `Nonce`, `SessionId`, Rust fixed arrays, and pure `ogir-model` conventions.
- Produces: `SESSION_PUBLIC_KEY_ID_LENGTH: usize = 32` and `SessionPublicKeyId` with exact `from_bytes`/`as_bytes`, copy/equality/hash semantics, and fixed redacted `Debug`.

- [ ] **Step 1: Create the complete runtime test file before production code**

Create `crates/ogir-model/tests/session_public_key_id.rs` with:

```rust
// SPDX-License-Identifier: Apache-2.0

use std::any::TypeId;
use std::collections::{HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};

use ogir_model::{Nonce, SESSION_PUBLIC_KEY_ID_LENGTH, SessionId, SessionPublicKeyId};

const EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH: usize = 32;
const PRIVATE_SENTINEL: [u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH] = [
    0x03, 0x17, 0x2b, 0x3f, 0x53, 0x67, 0x7b, 0x8f, 0xa3, 0xb7, 0xcb, 0xdf, 0xf3, 0x07, 0x1b, 0x2f,
    0x43, 0x57, 0x6b, 0x7f, 0x93, 0xa7, 0xbb, 0xcf, 0xe3, 0xf7, 0x0b, 0x1f, 0x33, 0x47, 0x5b, 0x6f,
];

fn value_hash(value: SessionPublicKeyId) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn exact_length_and_round_trip_are_fixed() {
    assert_eq!(
        SESSION_PUBLIC_KEY_ID_LENGTH,
        EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH
    );
    let identifier = SessionPublicKeyId::from_bytes(PRIVATE_SENTINEL);
    assert_eq!(identifier.as_bytes(), &PRIVATE_SENTINEL);
}

#[test]
fn every_fixed_whole_value_control_is_representable() {
    let mut alternating = [0_u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH];
    for (position, byte) in alternating.iter_mut().enumerate() {
        *byte = if position % 2 == 0 { 0x55 } else { 0xaa };
    }

    let mut ascending = [0_u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH];
    let mut descending = [0_u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH];
    for value in 0_u8..32 {
        ascending[usize::from(value)] = value;
        descending[usize::from(value)] = 31 - value;
    }

    for bytes in [
        [0_u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH],
        [u8::MAX; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH],
        alternating,
        ascending,
        descending,
    ] {
        assert_eq!(SessionPublicKeyId::from_bytes(bytes).as_bytes(), &bytes);
    }
}

#[test]
fn copy_equality_inequality_and_hashing_are_plain_value_semantics() {
    let first = SessionPublicKeyId::from_bytes(PRIVATE_SENTINEL);
    let same = first;
    let mut changed = PRIVATE_SENTINEL;
    changed[17] ^= 0xff;
    let different = SessionPublicKeyId::from_bytes(changed);

    assert_eq!(first, same);
    assert_ne!(first, different);
    assert_eq!(value_hash(first), value_hash(same));

    let mut values = HashSet::new();
    assert!(values.insert(first));
    assert!(!values.insert(same));
    assert!(values.insert(different));
    assert_eq!(values.len(), 2);
}

#[test]
fn all_8192_position_value_cases_round_trip_without_normalization() {
    let mut case_count = 0_usize;

    for position in 0..EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH {
        for value in u8::MIN..=u8::MAX {
            let mut bytes = PRIVATE_SENTINEL;
            bytes[position] = value;
            let identifier = SessionPublicKeyId::from_bytes(bytes);
            let copied = identifier;

            assert_eq!(identifier.as_bytes(), &bytes);
            assert_eq!(copied, identifier);
            assert_eq!(value_hash(copied), value_hash(identifier));
            assert_eq!(
                format!("{identifier:?}"),
                "SessionPublicKeyId([REDACTED; 32])"
            );
            case_count += 1;
        }
    }

    assert_eq!(case_count, 8_192);
}

#[test]
fn debug_is_exact_fixed_redaction_for_real_sentinel_bytes() {
    let identifier = SessionPublicKeyId::from_bytes(PRIVATE_SENTINEL);
    let diagnostic = format!("{identifier:?}");
    let raw = format!("{PRIVATE_SENTINEL:?}");

    assert_eq!(diagnostic, "SessionPublicKeyId([REDACTED; 32])");
    assert!(!diagnostic.contains(&raw));
    assert!(!diagnostic.contains("0x"));
}

#[test]
fn runtime_type_identity_is_distinct_from_nonce_and_session_id() {
    let identifier_type = TypeId::of::<SessionPublicKeyId>();
    assert_ne!(identifier_type, TypeId::of::<Nonce>());
    assert_ne!(identifier_type, TypeId::of::<SessionId>());
}
```

- [ ] **Step 2: Run the targeted test and verify the required RED state**

Run:

```bash
cargo test -p ogir-model --test session_public_key_id
```

Expected: nonzero compile failure E0432 for unresolved imports `SessionPublicKeyId` and `SESSION_PUBLIC_KEY_ID_LENGTH`. Confirm Cargo attempted this exact integration target; a failure in another crate or a zero-test result is not RED evidence.

- [ ] **Step 3: Add the minimal constant and production type**

Immediately after `NONCE_LENGTH`, add:

```rust
/// Session public-key lookup-handle length in bytes.
pub const SESSION_PUBLIC_KEY_ID_LENGTH: usize = 32;
```

Immediately after `impl fmt::Debug for Nonce`, add:

```rust
/// Opaque lookup handle for a future ephemeral protected-session public key.
///
/// This value is non-authoritative: construction, equality, hashing, and byte
/// access do not prove key possession and do not authorize a protected session.
/// A future trusted key owner and relying party must enforce publisher/session
/// scope, lifetime, key resolution, and fresh proof of possession.
///
/// ```
/// use ogir_model::{SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// let bytes = [0x5a; SESSION_PUBLIC_KEY_ID_LENGTH];
/// let identifier = SessionPublicKeyId::from_bytes(bytes);
/// assert_eq!(identifier.as_bytes(), &bytes);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionPublicKeyId([u8; SESSION_PUBLIC_KEY_ID_LENGTH]);

impl SessionPublicKeyId {
    /// Creates a lookup handle from every exactly sized byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SESSION_PUBLIC_KEY_ID_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the exact lookup-handle bytes without normalization.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_PUBLIC_KEY_ID_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for SessionPublicKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionPublicKeyId([REDACTED; 32])")
    }
}
```

Do not add a module, error type, validation branch, conversion, or use the value in another model object.

- [ ] **Step 4: Run focused GREEN and quality gates**

Run:

```bash
cargo fmt --all
cargo fmt --all --check
cargo test -p ogir-model --test session_public_key_id
cargo test -p ogir-model --all-features
cargo test -p ogir-model --doc
cargo clippy -p ogir-model --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p ogir-model --no-deps
git diff --check
```

Expected: six new integration tests pass, the one new positive rustdoc passes, all inherited model tests/doctests pass, Clippy/rustdoc emit no warning, and the diff contains only the production type plus its dedicated test.

- [ ] **Step 5: Stage, inspect, and commit the value slice unsigned**

```bash
git add crates/ogir-model/src/lib.rs crates/ogir-model/tests/session_public_key_id.rs
git diff --cached --check
git diff --cached --stat
git diff --cached
git commit -m "feat: add session public-key lookup handle"
```

Refresh Shared Memory with the RED error, exact GREEN counts, commit SHA/tree, paths, no external change, and next proof task.

---

### Task 3: Pin Every Forbidden Public and Authority Boundary

**Files:**

- Modify: `crates/ogir-model/src/lib.rs` (`SessionPublicKeyId` rustdoc only)
- Modify: `crates/ogir-model/tests/session_public_key_id.rs`

**Interfaces:**

- Consumes: Task 2's exact constant/type/method/Debug implementation.
- Produces: one positive and eighteen single-cause compile-fail doctests for the new type plus one structural integration test that pins the non-doc production surface.

- [ ] **Step 1: Add separate compile-fail blocks to the type rustdoc**

Insert the following after the positive `SessionPublicKeyId` example and before the derive. Preserve each as its own block; do not combine failures.

```rust
///
/// # Compile-time boundaries
///
/// The private tuple field cannot be constructed directly:
///
/// ```compile_fail
/// use ogir_model::{SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// let _identifier = SessionPublicKeyId([0; SESSION_PUBLIC_KEY_ID_LENGTH]);
/// ```
///
/// Arrays shorter than 32 bytes are rejected by the type system:
///
/// ```compile_fail
/// use ogir_model::SessionPublicKeyId;
///
/// let _identifier = SessionPublicKeyId::from_bytes([0; 31]);
/// ```
///
/// Arrays longer than 32 bytes are rejected independently:
///
/// ```compile_fail
/// use ogir_model::SessionPublicKeyId;
///
/// let _identifier = SessionPublicKeyId::from_bytes([0; 33]);
/// ```
///
/// A lookup handle cannot substitute for a challenge nonce:
///
/// ```compile_fail
/// use ogir_model::{Nonce, SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// fn needs_nonce(_: Nonce) {}
/// let identifier = SessionPublicKeyId::from_bytes([0; SESSION_PUBLIC_KEY_ID_LENGTH]);
/// needs_nonce(identifier);
/// ```
///
/// A lookup handle cannot substitute for a trusted local session identity:
///
/// ```compile_fail
/// use ogir_model::{SessionId, SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// fn needs_session_id(_: SessionId) {}
/// let identifier = SessionPublicKeyId::from_bytes([0; SESSION_PUBLIC_KEY_ID_LENGTH]);
/// needs_session_id(identifier);
/// ```
///
/// No `Default` value implies a generated or reserved handle:
///
/// ```compile_fail
/// use ogir_model::SessionPublicKeyId;
///
/// let _identifier = SessionPublicKeyId::default();
/// ```
///
/// `Display` is intentionally absent:
///
/// ```compile_fail
/// use ogir_model::{SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// let identifier = SessionPublicKeyId::from_bytes([0; SESSION_PUBLIC_KEY_ID_LENGTH]);
/// let _display = format!("{identifier}");
/// ```
///
/// String parsing is intentionally absent:
///
/// ```compile_fail
/// use ogir_model::SessionPublicKeyId;
///
/// let _identifier = "not-a-wire-format".parse::<SessionPublicKeyId>();
/// ```
///
/// Raw arrays do not convert implicitly into the distinct type:
///
/// ```compile_fail
/// use ogir_model::{SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// let _identifier: SessionPublicKeyId = [0; SESSION_PUBLIC_KEY_ID_LENGTH].into();
/// ```
///
/// Generic byte-reference conversion is intentionally absent:
///
/// ```compile_fail
/// use ogir_model::{SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// fn needs_implicit_bytes<T: AsRef<[u8; SESSION_PUBLIC_KEY_ID_LENGTH]>>(_: T) {}
/// let identifier = SessionPublicKeyId::from_bytes([0; SESSION_PUBLIC_KEY_ID_LENGTH]);
/// needs_implicit_bytes(identifier);
/// ```
///
/// Callers cannot mutate the stored bytes through an accessor:
///
/// ```compile_fail
/// use ogir_model::{SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// let mut identifier = SessionPublicKeyId::from_bytes([0; SESSION_PUBLIC_KEY_ID_LENGTH]);
/// identifier.as_bytes_mut()[0] = 1;
/// ```
///
/// Serialization remains outside this pure vocabulary slice:
///
/// ```compile_fail
/// use ogir_model::{SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// let identifier = SessionPublicKeyId::from_bytes([0; SESSION_PUBLIC_KEY_ID_LENGTH]);
/// let _wire = identifier.serialize();
/// ```
///
/// The value has no authority-like validity predicate:
///
/// ```compile_fail
/// use ogir_model::{SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// let identifier = SessionPublicKeyId::from_bytes([0; SESSION_PUBLIC_KEY_ID_LENGTH]);
/// let _valid = identifier.is_valid();
/// ```
///
/// A lookup handle cannot convert into a verifier decision:
///
/// ```compile_fail
/// use ogir_model::{Decision, SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// let identifier = SessionPublicKeyId::from_bytes([0; SESSION_PUBLIC_KEY_ID_LENGTH]);
/// let _decision: Decision = identifier.into();
/// ```
///
/// The handle cannot fabricate a verified-attestation capability:
///
/// ```compile_fail
/// use ogir_model::{SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// let identifier = SessionPublicKeyId::from_bytes([0; SESSION_PUBLIC_KEY_ID_LENGTH]);
/// let _verified = identifier.verified_attestation();
/// ```
///
/// The handle cannot fabricate a validated permit:
///
/// ```compile_fail
/// use ogir_model::{SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// let identifier = SessionPublicKeyId::from_bytes([0; SESSION_PUBLIC_KEY_ID_LENGTH]);
/// let _permit = identifier.validated_permit();
/// ```
///
/// The handle cannot claim proof of possession:
///
/// ```compile_fail
/// use ogir_model::{SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// let identifier = SessionPublicKeyId::from_bytes([0; SESSION_PUBLIC_KEY_ID_LENGTH]);
/// let _proof = identifier.proof_of_possession();
/// ```
///
/// The handle cannot authorize admission:
///
/// ```compile_fail
/// use ogir_model::{SessionPublicKeyId, SESSION_PUBLIC_KEY_ID_LENGTH};
///
/// let identifier = SessionPublicKeyId::from_bytes([0; SESSION_PUBLIC_KEY_ID_LENGTH]);
/// identifier.admit();
/// ```
```

Expected intended compiler boundaries, in order: private tuple constructor; E0308 for 31; E0308 for 33; E0308 for `Nonce`; E0308 for `SessionId`; missing `Default`; missing `Display`; missing `FromStr`; missing `From<[u8; 32]>`; missing `AsRef`; missing mutable method; missing serialization method; missing validity method; missing `Into<Decision>`; and four independent missing verified-attestation, validated-permit, proof-of-possession, and admission methods.

- [ ] **Step 2: Add the structural API test**

Append to `crates/ogir-model/tests/session_public_key_id.rs`:

```rust
#[test]
fn public_api_surface_is_pinned_to_the_approved_non_authority_contract() {
    let source = include_str!("../src/lib.rs").replace("\r\n", "\n");
    assert_eq!(
        source
            .matches("pub const SESSION_PUBLIC_KEY_ID_LENGTH: usize = 32;")
            .count(),
        1
    );

    let start_marker = "#[derive(Clone, Copy, PartialEq, Eq, Hash)]\npub struct SessionPublicKeyId";
    let start = match source.find(start_marker) {
        Some(index) => index,
        None => panic!("approved SessionPublicKeyId declaration is missing"),
    };
    let tail = &source[start..];
    let end = match tail.find("/// A versioned protocol identifier.") {
        Some(index) => index,
        None => panic!("SessionPublicKeyId block has no stable end marker"),
    };
    let production = tail[..end]
        .lines()
        .filter(|line| !line.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(production.contains(
        "#[derive(Clone, Copy, PartialEq, Eq, Hash)]\n\
         pub struct SessionPublicKeyId([u8; SESSION_PUBLIC_KEY_ID_LENGTH]);"
    ));
    assert!(
        production
            .contains("pub const fn from_bytes(bytes: [u8; SESSION_PUBLIC_KEY_ID_LENGTH]) -> Self")
    );
    assert!(
        production.contains("pub const fn as_bytes(&self) -> &[u8; SESSION_PUBLIC_KEY_ID_LENGTH]")
    );
    assert_eq!(production.matches("pub const fn ").count(), 2);
    assert_eq!(production.matches("pub fn ").count(), 0);
    assert!(production.contains("formatter.write_str(\"SessionPublicKeyId([REDACTED; 32])\")"));

    for forbidden in [
        "pub struct SessionPublicKeyId(pub ",
        "pub type SessionPublicKeyId",
        "impl Default for SessionPublicKeyId",
        "impl fmt::Display for SessionPublicKeyId",
        "impl From<",
        "impl Into<",
        "impl TryFrom<",
        "impl TryInto<",
        "impl std::convert::From<",
        "impl std::convert::Into<",
        "impl std::convert::TryFrom<",
        "impl std::convert::TryInto<",
        "impl AsRef<",
        "impl std::str::FromStr",
        "Serialize",
        "Deserialize",
        "as_bytes_mut",
        "serialize",
        "generate",
        "is_valid",
        "authorize",
        "verified_attestation",
        "validated_permit",
        "proof_of_possession",
        "admit",
        "impl PartialOrd",
        "impl Ord",
        "Decision",
        "ReasonCode",
        "VerifiedAttestation",
        "Permit",
        "Proof",
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden public surface appeared: {forbidden:?}"
        );
    }
}
```

If rustfmt changes the multi-line exact declaration assertion, update the expected string to the actual approved rustfmt output before accepting GREEN; do not weaken the assertion to a broad name search.

- [ ] **Step 3: Run the complete public-boundary proof**

Run:

```bash
cargo fmt --all
cargo fmt --all --check
cargo test -p ogir-model --test session_public_key_id public_api_surface_is_pinned_to_the_approved_non_authority_contract -- --exact
cargo test -p ogir-model --test session_public_key_id
cargo test -p ogir-model --doc
cargo clippy -p ogir-model --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p ogir-model --no-deps
git diff --check
```

Expected: the focused command reports `running 1 test` and `1 passed`; seven integration tests pass; `ogir-model` reports its inherited doctest plus one new positive and eighteen new compile-fail blocks (20 model doctests total); Clippy/rustdoc/diff checks pass. Inspect that each compile-fail block imports a real public type and contains only its intended invalid operation.

- [ ] **Step 4: Run explicit source-surface positive and negative controls**

Run:

```bash
rg -n 'pub const SESSION_PUBLIC_KEY_ID_LENGTH: usize = 32;' crates/ogir-model/src/lib.rs
rg -n 'pub struct SessionPublicKeyId\(\[u8; SESSION_PUBLIC_KEY_ID_LENGTH\]\);' crates/ogir-model/src/lib.rs
rg -n 'SessionPublicKeyId\(\[REDACTED; 32\]\)' crates/ogir-model/src/lib.rs crates/ogir-model/tests/session_public_key_id.rs
```

Then require no production declaration of a forbidden surface:

```bash
! rg -n 'impl (Default|fmt::Display|From<|TryFrom<|AsRef<|std::str::FromStr).*SessionPublicKeyId|pub (const )?fn (as_bytes_mut|serialize|generate|is_valid|authorize)' crates/ogir-model/src/lib.rs
```

Expected: every positive control matches the exact production/test declaration and the negative control exits successfully because no forbidden implementation exists.

- [ ] **Step 5: Commit the proof slice unsigned**

```bash
git add crates/ogir-model/src/lib.rs crates/ogir-model/tests/session_public_key_id.rs
git diff --cached --check
git diff --cached
git commit -m "test: pin session public-key handle boundaries"
```

Refresh Shared Memory with exact doctest/runtime counts, commit SHA/tree, proof limitations, and next documentation task.

---

### Task 4: Record ADR-0008 and Align Architecture, Roadmap, Trust, Privacy, and Tests

**Files:**

- Create: `docs/adr/0008-session-public-key-id-is-not-authority.md`
- Modify: `docs/adr/index.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/ROADMAP.md`
- Modify: `docs/TRUST_MODEL.md`
- Modify: `docs/PRIVACY_MODEL.md`
- Modify: `docs/TEST_STRATEGY.md`
- Conditional modify: `docs/LESSONS_LEARNED.md` only for a concrete new lesson

**Interfaces:**

- Consumes: Tasks 2-3's exact production/test contract and the approved issue/design sources.
- Produces: one Accepted ADR and consistent durable documentation that distinguishes a lookup handle from key commitment, proof, result, permit, or admission authority.

- [ ] **Step 1: Create complete ADR-0008**

Create `docs/adr/0008-session-public-key-id-is-not-authority.md` with every required section populated. Use this exact decision content; expand only with factual execution evidence, never with new authority or crypto semantics:

```markdown
# ADR-0008: Session public-key identifiers are not authority

- Status: Accepted
- Date: 2026-08-26
- Owners: Initial maintainer
- Related issues: [M1-007F](../../planning/issues/007f-session-public-key-id.md)
- Supersedes: None
- Superseded by: None

## Context

The M1 roadmap names `SessionPublicKeyId`, but the first identifier slice did
not define it. Later signed results and permits need a bounded way to refer to
one ephemeral protected-session public key. A raw byte array, generic string,
key encoding, thumbprint, or freely constructible composite can blur the line
between a key-selection hint and actual proof or authorization.

The result, permit, wire format, key algorithm, key-owning adapter, and
proof-of-possession validator do not exist yet. This decision therefore adds
only pure domain vocabulary and records the obligations of those future
owners and consumers.

## Decision drivers

- Preserve server-side authorization and proof-of-possession invariants.
- Prevent accidental interchange with `Nonce` or `SessionId`.
- Fix representation width without selecting a key or digest algorithm.
- Keep the model allocation-free, parser-free, serialization-neutral, and
  dependency-free.
- Redact a correlation-sensitive value from default diagnostics.
- Make the complete public and non-public surface mechanically reviewable.
- Preserve roadmap M1-011 for result and reason-code taxonomy.

## Options considered

### Fixed 32-byte opaque newtype

Selected. A private-field `[u8; 32]` newtype gives compile-time width and type
distinction without allocation, parsing, hashing, or cryptographic meaning.

### Variable-length bytes or canonical text

Rejected. Either choice introduces allocation, parsing, bounds, normalization,
or encoding policy before the M2 wire-profile gate.

### Public-key bytes, key thumbprint, or digest

Rejected. These choices require an algorithm and canonical key representation
and would imply a key commitment that byte equality alone does not provide.

### Composite session binding or `LocalSession` integration

Rejected. A freely constructible tuple would still be non-authoritative, while
changing the lifecycle graph before a real key-owning adapter exists would
claim enforcement the current pure model cannot provide.

### Premature proof or admission capability

Rejected. The future relying party must validate a fresh proof over the actual
resolved key and complete signed context. The local model cannot mint that
authority for itself.

## Decision

`ogir-model` defines `SESSION_PUBLIC_KEY_ID_LENGTH` as 32 and exposes
`SessionPublicKeyId` with one private `[u8; 32]` field. It derives only `Clone`,
`Copy`, `PartialEq`, `Eq`, and `Hash`; accepts every exactly sized array through
`from_bytes`; returns exact bytes only through `as_bytes`; and formats only as
`SessionPublicKeyId([REDACTED; 32])` through `Debug`.

The value is a non-authoritative application-specific lookup handle.
Construction, copying, equality, hashing, or byte access proves neither key
identity nor possession and cannot authorize a transition, result, permit, or
admission. No `Default`, `Display`, string, conversion, serialization, mutable,
generation, validity, proof, permit, or authority interface is included.

A future trusted local key owner creates one ephemeral key and handle for one
publisher and protected `SessionId`. The same key/handle may persist only
through renewal of that session. Terminal end/invalidation makes future use
invalid, and another session or publisher receives a new key/handle. Future
verifier/result code validates exact key binding; the relying party resolves
the actual key and validates fresh replay-resistant proof before admission.
The copyable M1 value does not enforce or erase this lifecycle.

## Consequences

The domain receives a small unambiguous type that prevents accidental
`Nonce`/`SessionId` interchange and keeps crypto/wire decisions deferred. The
cost is an OGIR-specific 32-byte profile and explicit mapping work in a future
protocol implementation.

Collisions and malicious/reused values remain possible. Future producers and
consumers must handle them through exact context, actual key resolution, signed
binding, freshness, and proof rather than assuming identifier uniqueness.

## Threat-model impact

No runtime threat is accepted or mitigated by this vocabulary-only decision,
so no attack scenario is added. It prevents design/API confusion but does not
yet stop A1 cross-session substitution, relay, replay, or missing proof. Those
threats remain owned by the future result, permit, and proof-validation paths.
A compromised future trusted local key owner remains A4 residual risk; a
compromised verifier or relying party remains A5 risk. Either can mishandle a
lookup handle despite the pure type contract.

## Privacy impact

The handle is not secret but can correlate activity when reused. Future scope
is therefore one publisher and one protected session, with reuse only for that
session's renewal. `Debug` fully redacts the value, `Display` is absent, and
`as_bytes` is a trusted functional interface rather than an approved logging
sink. M1-007F adds no wire disclosure or retention mechanism and makes no
secure-erasure claim.

## Dependency and license impact

The implementation uses only Rust fixed arrays and standard-library traits in
the existing Apache-2.0 `ogir-model` crate. It adds no dependency, feature,
crate, manifest, lockfile, parser, serializer, I/O, `unsafe`, or license-boundary
change.

## Validation

Validation requires seven dedicated runtime/structural tests, exactly 8,192
position/value cases, fixed whole-value controls, one positive and eighteen
single-cause compile-fail doctests added by this slice, exact diagnostic
sentinels, and all 19 disposable mutation probes. Full/release gates and fresh
model/API plus privacy/standards reviews must pass before issue evidence moves
to `needs-review`. No test may infer authority from constructibility or byte
equality.

## Rollback

Before publication, reverting the isolated feature commits is safe. After
merge, removing or changing the public type requires a deprecation/migration
issue. Any change to non-authority, lifecycle, privacy, or future consumer
obligations requires an ADR update or superseding ADR plus matching tests and
documentation.

Exposing raw diagnostics, adding implicit authority, reusing the handle
globally, or inferring a hash/key algorithm from its width is not an acceptable
rollback.

## Primary sources

- [Approved M1-007F design](../superpowers/specs/2026-08-26-m1-007f-session-public-key-id-design.md)
  defines the project-specific representation and authority boundary.
- [RFC 9052 section 3.1](https://www.rfc-editor.org/rfc/rfc9052.html#section-3.1)
  defines COSE `kid` as a non-unique, structurally opaque lookup hint rather
  than a security-critical field.
- [RFC 8747](https://www.rfc-editor.org/rfc/rfc8747.html) separates key-ID
  lookup from actual PoP validation and records collision, freshness, audience,
  segregation, and correlation obligations.
- [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html) distinguishes an EAT
  used alongside a PoP application from the PoP transaction itself.
- [Rust 1.98 visibility and privacy](https://doc.rust-lang.org/1.98.0/reference/visibility-and-privacy.html),
  [Rust 1.98 arrays](https://doc.rust-lang.org/1.98.0/std/primitive.array.html),
  and the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
  define the private-field, fixed-array, and newtype behavior used here.
```

- [ ] **Step 2: Add ADR-0008 to the authoritative index**

Append this exact row to `docs/adr/index.md`:

```markdown
| [ADR-0008](0008-session-public-key-id-is-not-authority.md) | Accepted | A session public-key identifier is a non-authoritative lookup handle; actual key binding and proof remain later boundaries. | None | None |
```

Run the focused ADR gates immediately:

```bash
./scripts/test-adr-index.sh
./scripts/check-adr-index.sh
```

Expected: all ADR fixtures pass and the real checker reports 8 decision records.

- [ ] **Step 3: Add the architecture trust-source and handle contract**

Add this row to the identifier trust-source table in `docs/ARCHITECTURE.md`:

```markdown
| `SessionPublicKeyId` | Future trusted local key owner; later verifier/result and relying-party consumers | A fixed representation-only lookup handle. The client is never authoritative; byte equality is not key commitment, proof, permit, or admission. |
```

Immediately before `### Challenge freshness authority`, add:

```markdown
### Session public-key lookup handle

`SessionPublicKeyId` is exactly 32 opaque bytes with private storage, explicit
byte access, copy/equality/hash data semantics, and fixed redacted diagnostics.
Every 32-byte value is representable. Its width selects no public-key encoding,
hash, signature algorithm, RNG, or uniqueness guarantee.

A future trusted local key owner creates one ephemeral key and handle for one
publisher and protected `SessionId`, retains it only through renewal of that
session, and invalidates/releases key state at terminal end. A new session or
publisher receives a new key/handle. The verifier must appraise the actual key
under the same complete attempt, and the relying party must resolve that key
and validate fresh transcript-bound proof before admission. The bare handle
cannot enforce lifetime and never substitutes for `VerifiedAttestation`, a
signed result, permit, or proof-of-possession capability.
```

- [ ] **Step 4: Clarify the roadmap without consuming M1-011**

Immediately after the M1 domain-type list, add:

```markdown
`SessionPublicKeyId` is completed as M1-007F, a bounded identifier follow-up to
task 7. It is a non-authoritative lookup handle only. Task 11 remains the
separate result/reason-code taxonomy that later consumes a key reference under
the complete signed context.
```

Add these bullets to the M1 `## Tests` list:

```markdown
- session public-key handle length/type distinction and all 8,192 byte-position/value cases are exact;
- constructible/copyable key handles expose no result, permit, proof, or admission authority;
- session public-key handle diagnostics fully redact the complete value;
```

Change only roadmap issue 7's sentence to:

```markdown
7. Define identifier validation rules; use M1-007F for the missing fixed-width session public-key handle.
```

Leave item 11 exactly `Define result and reason-code taxonomy.`

- [ ] **Step 5: Align trust and privacy models**

Add to `Publisher trusts` in `docs/TRUST_MODEL.md`:

```markdown
- session-key binding only after verifier appraisal and relying-party validation of the actual key and fresh proof;
```

Add to `Publisher does not trust`:

```markdown
- a client-supplied or byte-equal `SessionPublicKeyId` as key commitment, proof of possession, permit, or admission authority;
```

Add to `Player trusts`:

```markdown
- a future session key and lookup handle are scoped to one publisher/protected session, with reuse only for that session's renewal;
```

Add to `OGIR maintainers must not control`:

```markdown
- a stable session-key handle reused as a cross-session or cross-publisher correlation identity;
```

In `docs/PRIVACY_MODEL.md`, add to allowed information classes:

```markdown
- opaque session public-key lookup handle scoped to one publisher and protected session;
```

Add to disallowed information classes:

```markdown
- session-key or key-handle reuse as a stable cross-session/cross-publisher correlation identifier;
```

Add to controls:

```markdown
- a fresh future key/handle for every new session or publisher, with renewal-only reuse inside one session;
- fixed `SessionPublicKeyId` Debug redaction and explicit byte access treated as a trusted functional boundary;
```

- [ ] **Step 6: Record the exact test and mutation contract**

Under `### Unit tests` in `docs/TEST_STRATEGY.md`, add:

```markdown
#### Session public-key lookup handle

M1-007F runs seven dedicated runtime/structural tests. Six value/privacy tests
cover exact 32-byte round trip, all-zero/all-`0xff`/alternating/ascending/
descending controls, copy/equality/inequality/hash behavior, a non-vacuous
private diagnostic sentinel, and runtime type distinction from `Nonce` and
`SessionId`. The finite matrix executes exactly 32 positions × 256 byte values
= 8,192 cases without normalization or rejection. A CRLF-normalized structural
test pins the exact private tuple field, derive list, two public methods, fixed
Debug implementation, and absence of convenience or authority interfaces.

One positive rustdoc and eighteen separate compile-fail doctests added by this
slice cover direct field construction, 31/33-byte arrays, `Nonce`/`SessionId`
substitution, `Default`, `Display`, string parsing, implicit array conversion,
`AsRef`, mutable access, serialization, validity, decision conversion, and
independent verified-attestation, validated-permit, proof-of-possession, and
admission shortcuts.
Each block imports a real public type before its one intended failure.
```

Under `### Mutation tests`, before `### Security-scanning regressions`, add:

```markdown
The M1-007F minimum mutation contract is expanded to 19 isolated probes so no
combined convenience-interface or diagnostic mutation can mask another:

| Group | Probe IDs | Exact mutation | Required detector |
| --- | --- | --- | --- |
| Width (2) | `L01`, `L02` | Change the public length constant to 31 or 33. | Exact constant/runtime compile contract |
| Field privacy (1) | `F01` | Make the tuple field public. | Structural test plus private-constructor doctest |
| Byte preservation (2) | `A01`, `A02` | Normalize one constructor byte; return a promoted zero array from `as_bytes`. | Round-trip and 8,192-case matrix |
| Diagnostics (2) | `D01`, `D02` | Format all raw bytes; append one real byte to the redaction marker. | Exact sentinel Debug tests and matrix |
| Convenience interfaces (6) | `T01`-`T06` | Add `Default`, `Display`, `From<[u8; 32]>`, `FromStr`, `AsRef<[u8; 32]>`, or `serialize`. | Matching single-cause doctest plus structural test |
| Authority shortcuts (5) | `K01`-`K05` | Add `is_valid`, `verified_attestation`, `validated_permit`, `proof_of_possession`, or `admit`. | Matching single-cause doctest plus structural test |
| Type distinction (1) | `N01` | Replace the newtype with a `Nonce` alias while preserving compilation. | TypeId, Debug, and structural tests |

Every probe runs from one frozen exact head in a disposable worktree, executes
the named detector, and fails for the intended cause. Syntax failure, zero-test
success, an unrelated compiler failure, or a grouped mutation is not evidence.
No parser fuzz target or attack scenario is added because this type accepts one
compile-time fixed array and implements no runtime threat control.
```

- [ ] **Step 7: Decide factually whether a lessons entry exists**

Review implementation/review notes. If no new mistaken assumption was confirmed, leave `docs/LESSONS_LEARNED.md` byte-identical and record `not applicable: no new confirmed defect` in the task report. If a concrete new defect was confirmed, append one entry with Context, Mistaken assumption, Observed failure, Security or quality impact, Permanent regression test, New prevention rule, and Documentation or agent-policy updates. Never manufacture a lesson to satisfy a checklist.

- [ ] **Step 8: Verify and commit the documentation slice unsigned**

Run:

```bash
./scripts/test-adr-index.sh
./scripts/check-adr-index.sh
git diff --check
./scripts/check.sh
cargo test --workspace --all-features --release
```

Then inspect and commit exactly the created/modified documentation paths:

```bash
git add docs/adr/0008-session-public-key-id-is-not-authority.md docs/adr/index.md docs/ARCHITECTURE.md docs/ROADMAP.md docs/TRUST_MODEL.md docs/PRIVACY_MODEL.md docs/TEST_STRATEGY.md
git diff --cached --check
git diff --cached --stat
git diff --cached
git commit -m "docs: record session public-key handle contract"
```

Add `docs/LESSONS_LEARNED.md` to the commit only if Step 7 produced a concrete entry. Expected after commit: eight ADRs, 14 unchanged scenarios, no threat/protocol/manifest/runtime file outside `ogir-model`, and a clean worktree. Refresh Shared Memory.

---

### Task 5: Prove All 19 Mutations, Obtain Fresh Reviews, and Move the Issue to `needs-review`

**Files:**

- Modify only if a probe/reviewer exposes a real gap: `crates/ogir-model/src/lib.rs`, `crates/ogir-model/tests/session_public_key_id.rs`, and directly affected Task 4 documentation
- Modify after all proof/review gates: `planning/issues/007f-session-public-key-id.md`
- Conditional modify: `docs/LESSONS_LEARNED.md` only for a confirmed new mistake
- External after the evidence commit: exact live M1-007F issue body/status label only

**Interfaces:**

- Consumes: clean Task 4 head, exact live `status: ready` issue, all production/tests/docs, and no remote feature branch/PR.
- Produces: 19/19 intended-cause mutation evidence, full/release green exact head, clean independent model/API and privacy/standards reviews, one unsigned implementation-evidence commit, and exact live `status: needs-review` synchronization.

- [ ] **Step 1: Freeze the clean pre-mutation head and complete baseline**

Run:

```bash
git status --short --branch
m1_007f_mutation_head="$(git rev-parse HEAD)"
printf '%s\n' "${m1_007f_mutation_head}"
git rev-parse origin/main
git worktree list --porcelain
git fsck --no-dangling
./scripts/check.sh
cargo test --workspace --all-features --release
```

Require: clean primary worktree; no mutation worktree; origin/main still exact approved base; normal and optimized gates pass; actual counts include seven M1-007F runtime/structural tests, one positive plus eighteen new M1-007F compile-fail doctests, 14 unchanged scenarios, and eight ADRs. Record actual repository totals rather than relying only on expected totals (if no unrelated change exists, 93 runtime/integration tests and 80 doctests).

- [ ] **Step 2: Create the ignored exact-head mutation report**

Create and verify the ignored evidence directory:

```bash
mkdir -p .superpowers/sdd/2026-08-26-m1-007f-session-public-key-id
git check-ignore -v .superpowers/sdd/2026-08-26-m1-007f-session-public-key-id/mutation-report.md
```

Require the repository-local exclude rule to match `.superpowers/`; if it does not, stop rather than create untracked evidence. Then use `apply_patch` to create `.superpowers/sdd/2026-08-26-m1-007f-session-public-key-id/mutation-report.md`. Include one row per probe with: ID, exact base head, mutated path/declaration, exact focused command, observed exit, expected test count, intended assertion/compiler cause, and cleanup result. Do not record credentials, raw environment values, or unrelated output.

The report begins with:

```markdown
# M1-007F mutation report

- Frozen head: the exact 40-hex Task 5 head printed above
- Primary worktree: unchanged throughout
- Rule: every row must execute its named detector and fail for the intended cause

| ID | Mutation | Focused command | Expected execution | Intended failure | Cleanup |
| --- | --- | --- | --- | --- | --- |
```

Replace the prose description of the frozen head with the actual printed 40-hex SHA before running probes; this is evidence, not a committed project document.

- [ ] **Step 3: Use one disposable detached worktree per probe**

For each probe, resolve an explicit fresh temporary path:

```bash
m1_007f_probe_id='L01'
m1_007f_probe_root="$(mktemp -d)"
m1_007f_probe_path="${m1_007f_probe_root}/${m1_007f_probe_id}"
git worktree add --detach "${m1_007f_probe_path}" "${m1_007f_mutation_head}"
```

Apply only the named semantic mutation with `apply_patch` inside that detached worktree. Run the exact detector from the table below and require nonzero exit for the intended assertion/compiler reason. Confirm output reports `running 1 test` for focused integration tests or identifies the named compile-fail block for doctests.

After recording the row, clean only the resolved probe path:

```bash
git worktree remove --force "${m1_007f_probe_path}"
rmdir "${m1_007f_probe_root}"
git rev-parse HEAD
git status --short --branch
```

Never use a workspace root, home directory, unresolved glob, or unresolved variable as a deletion/removal target.

The exact 19 probes are:

| ID | Apply this one semantic mutation | Exact focused detector and intended cause |
| --- | --- | --- |
| `L01` | Change only `SESSION_PUBLIC_KEY_ID_LENGTH: usize = 32` to `31`. | `cargo test -p ogir-model --test session_public_key_id exact_length_and_round_trip_are_fixed -- --exact`; nonzero compile/assertion caused by the exact width contract, not unrelated syntax. |
| `L02` | Change only the length constant to `33`. | Same focused command; independent width-contract failure. |
| `F01` | Change the declaration to `pub struct SessionPublicKeyId(pub [u8; SESSION_PUBLIC_KEY_ID_LENGTH]);`. | `cargo test -p ogir-model --test session_public_key_id public_api_surface_is_pinned_to_the_approved_non_authority_contract -- --exact`; `running 1 test`, structural private-field assertion fails. Also confirm `cargo test -p ogir-model --doc` rejects the now-compiling private-constructor block. |
| `A01` | In `from_bytes`, copy into `let mut normalized = bytes; normalized[0] = 0; Self(normalized)`. | `cargo test -p ogir-model --test session_public_key_id all_8192_position_value_cases_round_trip_without_normalization -- --exact`; `running 1 test`, exact round-trip fails. |
| `A02` | Make `as_bytes` return the promoted `&[0; SESSION_PUBLIC_KEY_ID_LENGTH]`. | Same 8,192-case focused detector; exact returned bytes fail. |
| `D01` | Replace fixed Debug with `formatter.debug_tuple("SessionPublicKeyId").field(&self.0).finish()`. | `cargo test -p ogir-model --test session_public_key_id debug_is_exact_fixed_redaction_for_real_sentinel_bytes -- --exact`; exact marker/sentinel test fails. |
| `D02` | Append the real first byte with `write!(formatter, "SessionPublicKeyId([REDACTED; 32]):{:02x}", self.0[0])`. | Same focused diagnostic detector; partial disclosure fails. A label-only change with no real byte is not acceptable mutation evidence. |
| `T01` | Add `Default` to the derive list. | `cargo test -p ogir-model --doc`; the dedicated `SessionPublicKeyId::default()` compile-fail block unexpectedly compiles, so rustdoc reports failure. |
| `T02` | Add `impl fmt::Display for SessionPublicKeyId` that writes the redaction marker. | `cargo test -p ogir-model --doc`; the dedicated Display block unexpectedly compiles. |
| `T03` | Add `impl From<[u8; SESSION_PUBLIC_KEY_ID_LENGTH]> for SessionPublicKeyId` delegating to `from_bytes`. | `cargo test -p ogir-model --doc`; the implicit-array-conversion block unexpectedly compiles. |
| `T04` | Add `impl std::str::FromStr for SessionPublicKeyId` with `type Err = std::convert::Infallible` and an `Ok(Self::from_bytes([0; SESSION_PUBLIC_KEY_ID_LENGTH]))` result. | `cargo test -p ogir-model --doc`; the string-parse block unexpectedly compiles. |
| `T05` | Add `impl AsRef<[u8; SESSION_PUBLIC_KEY_ID_LENGTH]> for SessionPublicKeyId` returning `as_bytes()`. | `cargo test -p ogir-model --doc`; the generic AsRef block unexpectedly compiles. |
| `T06` | Add `pub const fn serialize(&self) -> [u8; SESSION_PUBLIC_KEY_ID_LENGTH] { self.0 }`. | `cargo test -p ogir-model --doc`; the serialization-method block unexpectedly compiles. Independently run the structural test and require its forbidden-surface assertion to fail. |
| `K01` | Add `pub const fn is_valid(&self) -> bool { true }`. | `cargo test -p ogir-model --doc`; the authority-like validity block unexpectedly compiles. Independently run the structural test and require its forbidden-surface assertion to fail. |
| `K02` | Add `pub const fn verified_attestation(&self) {}`. | `cargo test -p ogir-model --doc`; only the verified-attestation shortcut block unexpectedly compiles. |
| `K03` | Add `pub const fn validated_permit(&self) {}`. | `cargo test -p ogir-model --doc`; only the validated-permit shortcut block unexpectedly compiles. |
| `K04` | Add `pub const fn proof_of_possession(&self) {}`. | `cargo test -p ogir-model --doc`; only the proof-of-possession shortcut block unexpectedly compiles. |
| `K05` | Add `pub const fn admit(&self) {}`. | `cargo test -p ogir-model --doc`; only the admission shortcut block unexpectedly compiles. |
| `N01` | Replace the newtype with `pub type SessionPublicKeyId = Nonce;` and remove only its now-invalid inherent/Debug impls so the alias compiles. | `cargo test -p ogir-model --test session_public_key_id runtime_type_identity_is_distinct_from_nonce_and_session_id -- --exact`; `running 1 test`, TypeId equality fails. Also run Debug and structural focused tests and require intended failures. |

Count assertion: `2 + 1 + 2 + 2 + 6 + 5 + 1 = 19`.

- [ ] **Step 4: Handle any surviving or wrong-cause probe test-first**

If any probe passes, executes zero tests, or fails for a syntax/unrelated compiler cause:

1. remove its disposable worktree;
2. return to the clean primary worktree;
3. add one focused regression that passes on correct code;
4. run the mutation again in a fresh detached worktree and require the intended failure;
5. commit only the regression and any minimal real correction unsigned;
6. refresh `m1_007f_mutation_head`; and
7. restart all 19 probes at the new exact head.

Never copy mutated source into the primary worktree. Record the invalidated earlier round append-only in the ignored report.

- [ ] **Step 5: Prove cleanup and run complete exact-head gates**

Run:

```bash
git status --short --branch
git rev-parse HEAD
git worktree list --porcelain
git fsck --no-dangling
git diff --check
git diff --exit-code 9269b570ce83be01c1309469ff85fb79d4fa0c3d..HEAD -- crates/ogir-agent crates/ogir-verifier crates/ogir-protocol apps sdk lab/scenarios .github/workflows docs/THREAT_MODEL.md docs/PROTOCOL.md Cargo.toml Cargo.lock rust-toolchain.toml
./scripts/check.sh
cargo test --workspace --all-features --release
```

Require: clean primary branch; no mutation worktrees/branches; mutation report has 19/19 intended-cause kills at one exact head; normal and release gates pass; no Cargo/agent/verifier/protocol/scenario/workflow drift. Record actual runtime/doctest/scenario/ADR counts.

- [ ] **Step 6: Obtain separate fresh model/API and privacy/standards reviews**

Prepare this exact review package:

```text
base: 9269b570ce83be01c1309469ff85fb79d4fa0c3d
head: exact current unsigned HEAD
issue: planning/issues/007f-session-public-key-id.md
spec: docs/superpowers/specs/2026-08-26-m1-007f-session-public-key-id-design.md
plan: docs/superpowers/plans/2026-08-26-m1-007f-session-public-key-id.md
mutation report: exact 19/19 IDs, commands, execution counts, intended causes, and cleanup
```

Use the `requesting-code-review` workflow with two independent fresh-context axes:

- Model/API reviewer: width/representation, exact public/non-public surface, compile-fail non-vacuity, value/hash semantics, type distinction, no authority shortcut, no dependency or cross-crate scope.
- Privacy/standards reviewer: RFC 9052/8747/9711 attribution, per-publisher/session correlation boundary, complete Debug redaction, trusted byte-access wording, lifecycle/deferred-consumer honesty, ADR/docs consistency, no unsupported security claim.

Require each reviewer to report only concrete Critical/Important/Minor findings, uncertainties, spec equivalence, and readiness Yes/No. Fix every finding test-first, rerun affected/all mutations and full/release gates, and obtain fresh review until both axes say Yes with no unresolved finding. AI review is evidence for the human, never approval.

- [ ] **Step 7: Add exact time-bounded implementation evidence locally**

Before editing, capture the current live issue body/metadata and prove it still equals the committed ready source. Then use `apply_patch` on `planning/issues/007f-session-public-key-id.md` to:

- change only `status: ready` to `status: needs-review` in the metadata comment;
- append `## Implementation evidence` containing the exact base, unsigned head/tree, commit count and timestamp;
- record actual normal/release commands and counts, exactly 8,192 matrix cases, seven runtime/structural test names, positive/compile-fail doctest counts, 19/19 mutation IDs and intended-cause result, exact diagnostics/type/surface proof, eight ADRs, 14 unchanged scenarios, and both review verdicts;
- state that agent/verifier/protocol/apps/manifests/lockfile/scenario corpus remained byte-identical to base where required;
- state that no runtime threat, scenario, key generation, key resolution, PoP, result, permit, admission, crypto, wire, I/O, dependency, or `unsafe` behavior was added;
- state explicitly that every feature commit was unsigned at this recorded checkpoint and DCO/publication/human line-by-line review remained pending; and
- avoid any production-readiness, uniqueness, secure-erasure, or cheating-detection claim.

Run:

```bash
git diff --check
./scripts/check.sh
cargo test --workspace --all-features --release
git add planning/issues/007f-session-public-key-id.md
git diff --cached --check
git diff --cached
git commit -m "docs: record M1-007F implementation evidence"
```

Expected: one unsigned evidence/status commit on a clean head.

- [ ] **Step 8: Guardedly synchronize only the live issue body/status label**

Resolve the exact issue number by title. Preconditions: one exact title; live body equals the captured prior ready body; issue remains OPEN; milestone is `M1 Domain Model`; labels equal exact ready taxonomy; no duplicate title.

Then run:

```bash
gh issue edit "${m1_007f_issue_number}" \
  --repo archledger/open-game-integrity-runtime \
  --body-file planning/issues/007f-session-public-key-id.md \
  --remove-label 'status: ready' \
  --add-label 'status: needs-review'
```

Read back body base64 and full metadata. Require byte-identical local/live body, unchanged state/milestone/non-status labels, and exactly `status: needs-review`. Refresh Shared Memory with exact live evidence and rollback: restore the prior reviewed body/label only through another guarded edit after explicit authorization.

---

### Task 6: Freeze DCO, Publish Non-Force, and Hand Off for Human Review

**Files:**

- Read only: complete repository and exact unsigned history
- Create outside repository: immutable backup ref/bundle/hash manifest
- Create ignored only: `.superpowers/sdd/2026-08-26-m1-007f-session-public-key-id/pr-body.md`
- External: remote feature branch and one non-draft PR; no merge

**Interfaces:**

- Consumes: clean independently reviewed unsigned branch, exact live `needs-review` issue, and a new human DCO certification for the exact frozen M1-007F range.
- Produces: metadata-only DCO-clean equivalent history, retained rollback bundle, non-force remote branch, green reviewable PR, and explicit human line-by-line/merge handoff.

- [ ] **Step 1: Freeze and print the exact unsigned certification range**

Run:

```bash
git status --short --branch
m1_007f_base='9269b570ce83be01c1309469ff85fb79d4fa0c3d'
m1_007f_unsigned_tip="$(git rev-parse HEAD)"
git rev-list --reverse "${m1_007f_base}..${m1_007f_unsigned_tip}"
git log --reverse --format='commit=%H%ncommitter=%cn <%ce>%nsubject=%s%ntrailers=%(trailers:key=Signed-off-by,valueonly)%n---' "${m1_007f_base}..${m1_007f_unsigned_tip}"
./scripts/check-dco.sh "${m1_007f_base}" "${m1_007f_unsigned_tip}"
```

Expected: clean branch, exact immutable commit list, no existing/forbidden trailer, and DCO exit 1 only because every new commit lacks the matching trailer.

Stop and generate the exact certification request from the resolved values:

```bash
printf '%s\n' \
  "I certify that I authored or otherwise have the right to submit every commit" \
  "in the exact range ${m1_007f_base}..${m1_007f_unsigned_tip}" \
  "under DCO 1.1, and I authorize adding exactly:" \
  "Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>" \
  "to those commits."
```

Show the resolved output verbatim to the user; require both values to be full 40-hex OIDs and never show an unresolved variable. Never infer certification from this plan, written-spec approval, execution approval, GitHub identity, or any prior M0/M1 range.

- [ ] **Step 2: After exact certification, create immutable rollback evidence**

Verify committer identity before rewriting:

```bash
git config user.name
git config user.email
```

Require exactly `Wisbendji Fimerlus` and `archledger236@gmail.com`. Then run with the certified frozen tip:

```bash
test -d "/home/wisbfime/Open Game Intergrity Runtime  - Github Project/backups"
m1_007f_backup_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
m1_007f_backup_ref="refs/backup/pre-m1-007f-dco/${m1_007f_backup_stamp}/tip"
m1_007f_backup_bundle="/home/wisbfime/Open Game Intergrity Runtime  - Github Project/backups/ogir-m1-007f-pre-dco-${m1_007f_backup_stamp}.bundle"
git update-ref "${m1_007f_backup_ref}" "${m1_007f_unsigned_tip}"
git bundle create "${m1_007f_backup_bundle}" "${m1_007f_backup_ref}"
git bundle verify "${m1_007f_backup_bundle}"
sha256sum "${m1_007f_backup_bundle}"
git fsck --no-dangling
```

Use `apply_patch` to write the exact SHA-256 and explicit bundle path to sibling `${m1_007f_backup_bundle}.sha256`, then run `sha256sum -c` on it. Record the ref, bundle, hash, certified range, and exact restore command

```bash
git fetch "${m1_007f_backup_bundle}" "${m1_007f_backup_ref}:${m1_007f_backup_ref}"
```

in Shared Memory. Never delete this ref/bundle during the task.

- [ ] **Step 3: Rewrite metadata only and prove complete equivalence**

Run:

```bash
git rebase --force-rebase --exec 'git commit --amend --no-edit --signoff' "${m1_007f_base}"
m1_007f_signed_tip="$(git rev-parse HEAD)"
./scripts/check-dco.sh "${m1_007f_base}" "${m1_007f_signed_tip}"
git log --reverse --format='%T%x09%an%x09%ae%x09%aI%x09%s' "${m1_007f_base}..${m1_007f_backup_ref}"
git log --reverse --format='%T%x09%an%x09%ae%x09%aI%x09%s' "${m1_007f_base}..${m1_007f_signed_tip}"
git range-diff "${m1_007f_base}..${m1_007f_backup_ref}" "${m1_007f_base}..${m1_007f_signed_tip}"
git log --format='%(trailers:key=Signed-off-by,valueonly)' "${m1_007f_base}..${m1_007f_signed_tip}"
git status --short --branch
```

Require identical commit count/order/tree/author/email/author-date/subject; only commit IDs, committer metadata, and one exact authorized trailer per commit may differ. Reject duplicate trailers and `Signed-off-by: archledger <archledger236@gmail.com>`.

- [ ] **Step 4: Re-run all gates and obtain fresh rewritten-SHA review**

Run:

```bash
./scripts/check.sh
cargo test --workspace --all-features --release
git diff "${m1_007f_base}..${m1_007f_signed_tip}" --check
git fsck --no-dangling
git status --short --branch
```

Use the `requesting-code-review` workflow with a fresh reviewer comparing the certified unsigned backup tip to the signed tip and reviewing the whole signed range against issue/spec/plan. Publication requires tree/spec equivalence Yes, DCO equivalence Yes, readiness Yes, and no Critical/Important/Minor finding.

- [ ] **Step 5: Guardedly publish the feature branch without force**

Immediately before push:

```bash
m1_007f_issue_number="$(gh issue list --repo archledger/open-game-integrity-runtime --state all --limit 500 --json number,title --jq '.[] | select(.title == "M1-007F: Define the session public-key lookup handle") | .number')"
test -n "${m1_007f_issue_number}"
git ls-remote origin refs/heads/main
git ls-remote --heads origin refs/heads/research/m1-007f-session-public-key-id
gh pr list --repo archledger/open-game-integrity-runtime --state all --head research/m1-007f-session-public-key-id --json number,state,url
gh issue view "${m1_007f_issue_number}" --repo archledger/open-game-integrity-runtime --json state,milestone,labels,url
```

Require remote main still exact `9269b570ce83be01c1309469ff85fb79d4fa0c3d`, no remote feature branch/PR, and exact open `needs-review` issue. Then:

```bash
git push -u origin research/m1-007f-session-public-key-id
git ls-remote --heads origin refs/heads/research/m1-007f-session-public-key-id
```

No force flag is permitted. Require the remote feature ref to equal `m1_007f_signed_tip` exactly.

- [ ] **Step 6: Create and verify one non-draft PR**

Use `apply_patch` to create ignored `.superpowers/sdd/2026-08-26-m1-007f-session-public-key-id/pr-body.md` from `.github/pull_request_template.md`. Fill every section with exact final evidence and the decimal issue number discovered in Task 1.

Before writing it, require:

```bash
git check-ignore -v .superpowers/sdd/2026-08-26-m1-007f-session-public-key-id/pr-body.md
```

If the path is not ignored, stop without creating the PR body.

Required facts:

```text
Problem: M1 lacks the typed session public-key lookup handle required by the roadmap; raw or convenience representations could blur lookup and authority.
Invariants: 1-5, 36-37, 47-48.
In scope: one fixed-width ogir-model newtype, tests/mutations, ADR and trust/privacy/test traceability.
Out of scope: key material/generation/storage, crypto/hash/RNG, serialization/wire, LocalSession/verifier/protocol/result/permit/PoP/admission, I/O/dependencies/unsafe.
Primary sources: RFC 9052 section 3.1, RFC 8747, RFC 9711, Rust 1.98 visibility/arrays, Rust API Guidelines.
Trust boundaries: None checked for runtime behavior; documentation records future local-owner/verifier/relying-party obligations.
Verification: exact final normal/release commands/counts, 8,192 cases, 19/19 mutations, dual clean reviews.
Fuzz/property/race: finite 8,192-case matrix; no parser/fuzz/race surface added.
Privacy: per-publisher/session correlation limit, fixed Debug redaction, explicit byte access as trusted functional boundary.
Dependencies: none added/changed; Apache-2.0 boundary unchanged.
AI-Assisted: yes
AI-System: OpenAI Codex
AI-Use: research | implementation | tests | review | docs
Human-Reviewed-Every-Line: no
Primary-Sources-Verified: yes
Closes followed by `#` and the exact decimal M1-007F issue number.
Contributor certification: DCO checkbox checked after exact range verification; responsibility checkbox remains unchecked.
```

Create and resolve the PR:

```bash
m1_007f_pr_url="$(gh pr create \
  --repo archledger/open-game-integrity-runtime \
  --base main \
  --head research/m1-007f-session-public-key-id \
  --title 'M1-007F: Define the session public-key lookup handle' \
  --body-file .superpowers/sdd/2026-08-26-m1-007f-session-public-key-id/pr-body.md)"
m1_007f_pr_number="$(gh pr list --repo archledger/open-game-integrity-runtime --state open --head research/m1-007f-session-public-key-id --json number --jq '.[0].number // empty')"
test -n "${m1_007f_pr_number}"
printf '%s\n' "${m1_007f_pr_url}"
```

Read back PR head/base/body/state/draft/mergeability/commits. Require exact signed head, base `main`, non-draft OPEN state, exact closing linkage and AI disclosure, DCO certification checked, and human line-by-line/responsibility still `no`/unchecked.

- [ ] **Step 7: Watch remote checks and hand off; never merge autonomously**

Run:

```bash
gh pr checks --repo archledger/open-game-integrity-runtime --watch "${m1_007f_pr_number}"
gh pr view "${m1_007f_pr_number}" --repo archledger/open-game-integrity-runtime --json state,isDraft,mergeable,mergeStateStatus,reviews,comments,commits,url
gh api "repos/archledger/open-game-integrity-runtime/pulls/${m1_007f_pr_number}/comments"
gh api "repos/archledger/open-game-integrity-runtime/code-scanning/alerts?state=open&pr=${m1_007f_pr_number}"
```

Resolve only evidence-backed findings through new test-first unsigned commits followed by their own exact human DCO certification and safe publication. Never dismiss or exclude a real alert to obtain green checks.

When checks/reviews are clean, refresh Shared Memory and hand the exact PR URL/head to the user. Stop for explicit line-by-line review, responsibility acceptance, and merge authorization. Do not mark those human-only fields, merge, delete the branch, or remove retained worktrees/backups without explicit user direction.

---

## Approved-Spec Coverage Map

| Approved requirement | Implemented/proved by |
| --- | --- |
| Exact 32-byte private representation and every value accepted | Task 2 runtime tests/implementation; mutations `L01`, `L02`, `A01`, `A02` |
| No runtime error or reserved-value policy | Task 2 infallible fixed-array API and whole-value controls; Task 4 ADR |
| Only `from_bytes` and `as_bytes`; exact derive list | Tasks 2-3 structural test; `T01`-`T06` |
| Fixed complete Debug redaction with real sentinel | Tasks 2-3; `D01`, `D02` |
| Copy/equality/inequality/hash data semantics | Task 2 value/hash tests |
| Distinct from `Nonce` and `SessionId` | Tasks 2-3 compile/runtime proof; `N01` |
| No Default/Display/string/AsRef/conversion/serialization/mutable surface | Task 3 separate doctests/structural proof; `T01`-`T06` |
| No validity, result, permit, PoP, or admission authority | Task 3 authority doctests/structural proof; `K01`-`K05`; Tasks 4-5 review |
| Exactly 8,192 position/value cases plus fixed controls | Task 2 matrix/control tests; `A01`, `A02` |
| No parser/fuzzer/dependency/unsafe/cross-crate implementation | Global constraints, Tasks 2-5 file/range gates |
| Future per-publisher/session lifecycle and renewal-only reuse | Task 4 architecture/trust/privacy/ADR; privacy/standards review |
| Collision/key-resolution/freshness/PoP deferred honestly | Task 4 ADR/docs; Task 5 standards review |
| No new runtime threat or attack scenario | Global constraints; Task 4 threat rationale; Task 5 unchanged-scenario proof |
| ADR-0008 and architecture/roadmap/trust/privacy/test traceability | Task 4 |
| Minimum mutation categories and intended-cause cleanup | Task 5's expanded 19/19 campaign |
| Full/release and fresh independent review | Task 5, repeated after any correction; Task 6 after DCO rewrite |
| Live issue/PR exactness and non-disciplinary claims | Tasks 1, 5, and 6 |
| Human range-specific DCO and line-by-line merge authority | Task 6 only |

## Plan Self-Review Checklist

- [x] Every approved issue/design requirement maps to an exact task and executable detector.
- [x] File map matches every create/modify path; intentionally unchanged paths are guarded.
- [x] Public constant/type/method names and signatures are identical in spec, plan, runtime tests, doctests, docs, and mutations.
- [x] Runtime arithmetic is seven tests and `32 × 256 = 8,192`; mutation arithmetic is `2 + 1 + 2 + 2 + 6 + 5 + 1 = 19`.
- [x] Every negative doctest has one intended failure after all imports/types resolve.
- [x] Every mutation names one semantic change, one focused command, expected execution count, intended failure, and cleanup.
- [x] No production-code task adds crypto, key material, wire semantics, parser, dependency, I/O, `unsafe`, authority capability, or cross-crate runtime integration; test/review/GitHub workflow I/O remains outside the shipped model.
- [x] RFC 9052 lookup-hint, RFC 8747 collision/freshness/correlation, and RFC 9711 EAT/PoP claims remain attributed to the correct sources.
- [x] No unresolved marker, unanswered question, generic error-handling instruction, or fabricated count/result remains.
- [x] Human-only gates remain explicit: plan execution, DCO range/trailer, line-by-line review, responsibility, merge, branch/worktree cleanup.

## Execution Handoff

After this plan is committed and explicitly approved, choose one execution mode:

1. **Subagent-Driven (recommended):** invoke `subagent-driven-development`; dispatch a fresh implementer per task and run task/spec review between tasks.
2. **Inline Execution:** invoke `executing-plans`; execute the tasks in this worktree with the listed checkpoints and stop conditions.

Neither option begins until the user explicitly approves this exact committed plan and chooses execution. Both stop again at Task 6's exact DCO certification and human-only merge gates.
