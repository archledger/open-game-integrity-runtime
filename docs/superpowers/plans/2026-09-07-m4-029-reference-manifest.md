# M4-029 plan: the signed reference manifest and revocation fixtures

Date: 2026-09-07
Agent: zcode
Authorization: standing publication+merge authorization (recorded
2026-09-07T17:20:00-04:00); all gates remain mandatory.

## Objective

Close M4's reference-data deliverables (ADR-0025): the accepted
signing-root representation, the static signed reference manifest,
the revocation and minimum-version fixture, and the user-facing
explanation of accepted and unsupported states.

## Steps

1. Worktree research/m4-029-reference-manifest from b6b9f41.
2. Grammar-first design: line-oriented canonical text, signature as
   the final line, payload = exact byte prefix. Negative tests
   before fixtures.
3. ogir-bootlog::manifest: parser, version comparator (dotted
   numeric), successor policy, component checks with distinguishable
   reasons; BootlogError extended.
4. ogir-attest-tpm::manifest: verification delegation to the
   QuoteVerifier TPM path with the pinned anchor.
5. TEST-ONLY anchor key + signing script + fixtures GENERATED from
   the committed pcrs.txt (never hand-typed; the first hand-typed
   attempt shipped a 65-character PCR value and failed its own
   gate - lesson recorded).
6. Integration suite against real swtpm; python signing-time gate.
7. docs/PROFILE_STATES.md, ADR-0025 + index row, ROADMAP boundary,
   this plan, the planning issue.
8. House gates, signed commit, publication (issue + draft PR), CI,
   merge under the standing authorization, post-merge verification.

## Development notes

- decode_hex must accept digits as hex (an is_ascii_lowercase guard
  on '0' rejected every digit pair; caught in review before commit).
- A successor fixture must actually raise the revision: an early
  unit-test construction compared a same-revision pair and the
  assertion failed for the wrong reason.
- The payload/signature split uses pointer arithmetic on the first
  signature-prefixed line; everything after it must be empty.
- Signing: openssl dgst -sha256 -sign (RSASSA-PKCS1-v1_5-SHA256),
  exactly what the TPM verify path checks; exponent 65537 both ends.

## Boundaries

In: manifest module both crates, anchor key + signing script,
fixtures, states doc, ADR-0025, gates.
Out: SB enforcement boot and the ten attack categories (M4-030),
multi-profile registries, manifest distribution.
