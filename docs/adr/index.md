# ADR decision index

This is the authoritative inventory of durable OGIR decisions. A decision
remains here when it is superseded or rejected so its context and alternatives
stay traceable.

## Status definitions

- **Proposed:** under review and not yet authoritative.
- **Accepted:** authoritative for its stated scope.
- **Superseded:** replaced by another ADR; retained as history.
- **Rejected:** considered and explicitly not selected; retained as history.
- **Experimental:** approved only for bounded research and not yet an accepted
  architecture commitment.

## Decision records

| ADR | Status | Decision | Supersedes | Superseded by |
| --- | --- | --- | --- | --- |
| [ADR-0001](0001-rust-primary-language.md) | Accepted | Rust is the primary trusted-core language. | None | None |
| [ADR-0002](0002-apache-2-core.md) | Accepted | Apache-2.0 is the default core license with explicit Wine and BPF boundaries. | None | None |
| [ADR-0003](0003-separate-compatibility-and-attestation.md) | Accepted | Virtual TPM compatibility remains separate from physical platform attestation. | None | None |
| [ADR-0004](0004-server-side-authorization.md) | Accepted | Only a publisher-controlled verifier authorizes protected sessions. | None | None |
| [ADR-0005](0005-verifier-authoritative-challenge-freshness.md) | Accepted | Publisher-verifier time and durable single-use nonce state define challenge freshness. | None | None |
| [ADR-0006](0006-local-session-lifecycle-capabilities.md) | Accepted | A private checked runtime graph and session-bound capabilities govern local lifecycle and cleanup. | None | None |
| [ADR-0007](0007-verifier-flow-capabilities.md) | Accepted | One attempt-bound checked graph is the only path to verifier appraisal authority. | None | None |
| [ADR-0008](0008-session-public-key-id-is-not-authority.md) | Accepted | A session public-key identifier is a non-authoritative lookup handle; actual key binding and proof remain later boundaries. | None | None |
| [ADR-0009](0009-capability-gated-appraisal-results.md) | Accepted | Unsigned Appraisal Results preserve exact context, claim-free phase-eligible failures, and one-use allow construction. | None | None |
| [ADR-0010](0010-semantic-evidence-binding-transcript.md) | Accepted | Evidence mechanisms cover one closed semantic transcript reconstructed independently by the verifier while EvidenceBundle remains external. | None | None |
| [ADR-0011](0011-challenge-anchored-evidence-time.md) | Accepted | Evidence time is one challenge-anchored protected collection interval with scoped epoch and monotonic same-session continuity. | None | None |
| [ADR-0012](0012-abstract-json-conformance-corpus.md) | Accepted | One abstract JSON corpus uses snapshot/history fixtures, one authoritative manifest, one shared bounded loader, and six ordered fail-closed validation layers while production representation remains deferred. | None | None |
