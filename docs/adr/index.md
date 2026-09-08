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
| [ADR-0013](0013-isolated-mock-replay-cache.md) | Accepted | An opt-in bounded volatile mock replay cache remains isolated from durable freshness authority and production recovery. | None | None |
| [ADR-0014](0014-renewal-revocation-semantics.md) | Accepted | Renewal uses fresh evidence and one coherent session owner; finite authorization and authenticated revocation freshness bound protected use. | None | None |
| [ADR-0015](0015-mock-binding-transcript-encoding.md) | Accepted | A test-only transcript encoding uses fixed domain tags and fail-closed canonical record rules with frozen per-class field registries. | None | None |
| [ADR-0016](0016-test-only-ephemeral-key-hierarchy.md) | Accepted | An in-repo test-only ephemeral software key hierarchy authenticates the mock protocol without selecting production crypto libraries. | None | None |
| [ADR-0017](0017-attestation-backend-boundary.md) | Accepted | A dependency-free AttestationBackend seam holds the trait, three disjoint assurance classes, and a strict-equality class gate; the mock attester is the labeled test backend. | None | None |
| [ADR-0018](0018-tss-esapi-dependency-and-swtpm-backend.md) | Accepted | Upstream tss-esapi 7.7.0 becomes the first external production dependency behind a signed cargo-deny allowlist, with the swtpm software-TPM backend issuing real quotes behind the seam. | None | None |
| [ADR-0019](0019-enrollment-records-and-quote-validation.md) | Accepted | Publisher-scoped AK enrollment records with one-modulus-one-scope enforcement and semantic quote validation (contract v2); cryptographic signature verification deferred behind the unsafe-policy blocker. | None | None |
| [ADR-0020](0020-audited-unsafe-marshaling-and-cryptographic-verification.md) | Accepted | One audited unsafe marshaling block (the only workspace exception, gate-enforced) plus production SHA-256 and verifier-side cryptographic quote verification close the copied-public-AK exposure. | None | None |
| [ADR-0021](0021-publisher-scoped-identity-and-privacy.md) | Accepted | Attestation identity is per publisher scope with scope-unique keys; cross-publisher linkability is structurally absent and intra-scope linkability is documented. | None | None |
| [ADR-0022](0022-recovery-after-tpm-state-loss.md) | Accepted | TPM state loss fails closed everywhere; recovery is always explicit re-enrollment, with per-cause event records and no key migration. | None | None |
| [ADR-0023](0023-platform-profile-and-log-ingestion.md) | Accepted | A dependency-free TCG2 event-log parser, PCR replay with exact TPM semantics, and the platform-profile schema with the ADR-0014 successor relation; the real host fixture replays exactly to live PCRs 2 and 7 with the PCR 0 fidelity gap documented. | None | None |
| [ADR-0024](0024-tcg2-ovmf-acquisition-and-measured-capture.md) | Accepted | The measured-boot capture uses a pinned hash-verified TCG2-enabled Ubuntu OVMF (Fedora's ships no TCG2), a second TEST-ONLY-signed capture UKI measured into PCR 11 by sd-stub, and an in-guest evidence export validated durably by the Rust replay/live/quote triangle. | None | None |
| [ADR-0025](0025-signed-reference-manifest.md) | Accepted | A canonical line-oriented signed reference manifest (profile, PCR expectations, signing-root fingerprints, floors, revocations) verified through the audited TPM path against a verifier-pinned anchor, with non-weakening successor updates and distinguishable unsupported states. | None | None |
| [ADR-0026](0026-sb-varstore-and-measured-admission.md) | Accepted | A deterministically derived TEST-ONLY-enrolled Secure Boot varstore (virt-fw-vars, PK=KEK=db) proves firmware enforcement both ways, and the production admission point makes Secure Boot alone structurally insufficient (identity, SB state, accepted root, then measurements). | None | None |
| [ADR-0027](0027-local-portal-and-peer-cred-shim.md) | Accepted | The unprivileged same-UID local portal authenticates every connection by kernel SO_PEERCRED through ogir-agent's single audited unsafe block (gate-enforced with ADR-0020's), serves only normalized bounded length-prefixed messages, and fails closed on floods, oversized and malformed input. | None | None |
| [ADR-0028](0028-race-resistant-caller-binding.md) | Accepted | Caller binding pairs the kernel start time from procfs with a pinned pidfd (open at bind, signal-0 liveness probes, Drop-closed) so PID reuse, exit-during-binding, and stale credentials fail closed; the audited shims consolidate under one gate-enforced allow attribute. | None | None |
| [ADR-0029](0029-ogir-client-prototype.md) | Accepted | The ogir-client prototype ships as a native mingw PE ABI surface plus a winegcc unixlib carrying real spec-bound ms_abi exports and initialized dispatch tables, proven live against the portal with the wine process's kernel credentials observed and pinned; the WoW64 leg fails closed by design. | None | None |
| [ADR-0030](0030-wine-transport-and-correlation.md) | Accepted | The transport is proven under mainline wine (per-prefix PE deployment) and real GE-Proton (compat prefix), with redacted correlation deriving prefix/loader digests, bounded ancestry, and cgroup structure from the PINNED caller - distinguishing deployments without learning paths. | None | None |
| [ADR-0031](0031-runtime-manifest-and-m5-suite.md) | Accepted | The runtime manifest derives executable/module digests and the mount-namespace anchor from the PINNED process's procfs, and the thirteen-category M5 attack suite closes the milestone with the exit audit finding criteria 1/2/4 satisfied and the fuzz remainder recorded for M6. | None | None |
| [ADR-0032](0032-verifier-service-shell.md) | Accepted | The verifier service shell ships as a bounded in-repo HTTP/1.1 endpoint with a strict flat-object JSON codec and trait-injected semantics (no new dependencies, no TLS by design), and the developer-mode daemon composes the mock substrate into it as a gate-enforced mock-tier crate. | None | None |
| [ADR-0033](0033-lifecycle-and-structured-results.md) | Accepted | The verdict becomes a structured shape (allow/restricted/unsupported/retry/deny with stable taxonomy reason codes and retry guidance), and /v1/renew (fresh-evidence ADR-0014 renewal) and /v1/revoke (parser-proof exact-bytes denylisting) complete the five-route lifecycle. | None | None |
| [ADR-0034](0034-stable-sdk-and-fuzzing.md) | Accepted | The v1 SDK freezes (version macros, the five verdict families, the structured ogir_result, ogir_abi_version, eight exports pinned by a fail-closed surface gate), the header-only C++ wrapper mirrors it with unknown families failing closed, and three fuzz targets close the recorded codec/router remainder. | None | None |
| [ADR-0035](0035-sample-backend-and-conformance-kit.md) | Accepted | The standalone Python conformance kit fail-closed checks the five-step flow, lifecycle, freshness, and wire bounds over plain HTTP (15 checks; self-test in CI), the sample backend demonstrates the five steps with the publisher's policy table in view, and the no-ban/casual-fallback contract is documented. | None | None |
