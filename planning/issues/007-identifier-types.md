# M1-007: Define strongly typed identifiers and validation rules
<!-- labels: type: implementation,area: model,risk: parser,status: ready -->
<!-- milestone: M1 Domain Model -->

## Problem

Security-sensitive identifiers are currently plain strings. Cross-field confusion, Unicode ambiguity, unbounded allocation, and accidental context reuse must be prevented before serialization work.

## Security invariants

- Publisher, game, build, account scope, match, policy, and session identifiers cannot be interchanged accidentally.
- Every externally supplied identifier is bounded and canonically validated.
- Debug output does not leak account-scoped identifiers by default.

## In scope

- Introduce distinct newtypes for each identifier.
- Specify allowed character set, byte-length bounds, normalization policy, and redacted debug behavior.
- Provide fallible constructors and property tests.
- Update the scaffold without adding serialization dependencies.

## Out of scope

- Choosing wire encoding.
- Internationalized display names.
- Mapping Steam App IDs or publisher account formats.

## Primary sources

- Rust API Guidelines: https://rust-lang.github.io/api-guidelines/
- Unicode security considerations, if Unicode is proposed: https://www.unicode.org/reports/tr36/

## Required tests

- Empty, overlong, control-character, separator-confusion, and noncanonical inputs fail.
- Each newtype cannot be passed where another identifier type is required.
- Debug output redacts account scope and other privacy-sensitive fields.
- Property tests cover arbitrary byte/string inputs.

## Acceptance criteria

- No security-sensitive challenge identifier remains a raw public `String`.
- Validation rules are documented in the protocol model.
- No external dependency is added without a separate ADR.
