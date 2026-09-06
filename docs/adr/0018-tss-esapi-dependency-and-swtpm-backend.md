# ADR-0018: The tss-esapi dependency and the swtpm software-TPM backend

- Status: Accepted
- Date: 2026-09-06
- Owners: Initial maintainer
- Related issues: [Local M3-021 issue](../../planning/issues/021-swtpm-backend.md); [M3 entry scoping](../superpowers/plans/2026-09-06-m3-021-swtpm-backend.md)
- Supersedes: None
- Superseded by: None

## Context

Milestone M3 replaces the mock attester with TPM-backed quotes. The
approved M3 entry scoping (recommendations R1-R4, accepted 2026-09-06)
selected upstream crates.io `tss-esapi` 7.7.0 as the TSS binding, direct
usage without a Keylime adaptation, an OGIR-native enrollment prototype
in a later slice, and swtpm as the CI software-TPM fixture. Until now
the workspace admitted zero external crates; this decision is the first
external production dependency and therefore a signed policy event.

## Decision drivers

- A real TPM 2.0 backend behind the ADR-0017 seam with no raw TPM
  command escaping the backend crate.
- A dependency route with the cleanest supply chain for OGIR.
- CI must exercise real TPM semantics deterministically.
- The workspace's `cargo-deny` allowlist must remain an explicit,
  human-signed inventory, not a rubber stamp.

## Options considered

### A: Upstream crates.io `tss-esapi` 7.7.0 (selected)

Latest stable upstream (2026-04-24; 8.0 is alpha with feature-only
changes). The irlume project's 2026-08-20 audit already verified the
crate family at 7.x against the same tpm2-tss 4.1.3 userland this
workspace uses: FFI signatures exact against `tss2_esys.h`, fail-closed
error mapping, green swtpm integration suite. The crates.io route
carries no fork delta to track; the irlume fork's changes are
irlume-specific.

### B: The audited irlume fork pin `7567f604`

Rejected for OGIR: the delta is irlume-specific, the fork adds a
patch surface OGIR would own for no benefit, and crates.io gives a
cleaner provenance story.

### C: Raw FFI against tpm2-tss directly

Rejected: reimplements the audited safe wrapper the community and this
workspace already trust, expanding review burden and risk.

## Decision

- `crates/ogir-attest-tpm` (production) depends on upstream
  `tss-esapi` 7.7.0 with the `generate-bindings` feature (bindgen at
  build time against the system tpm2-tss; build environments require
  `libclang` and `tpm2-tss` development packages).
- `deny.toml` becomes the signed inventory: every crate in the normal
  and build dependency graphs (53 after platform-target additions) is
  enumerated in `[bans] allow` with this ADR cited; the license set
  grows to the permissive SPDX list (Apache-2.0, MIT, ISC, BSD-3-Clause,
  Unicode-3.0, Unlicense, Zlib, Apache-2.0 WITH LLVM-exception). The
  list never grows without an ADR.
- The software-TPM backend (`swtpm::SwtpmBackend`, assurance class
  `software-tpm`, id `swtpm-tpm2-v1`) creates a restricted-signing
  attestation key as a primary under the Owner hierarchy (RSA 2048,
  RSASSA-SHA256, fixedTPM/fixedParent) and produces real `TPM2_Quote`
  calls over experimental PCR slot 16 with the caller's qualifying data
  in the quote. A password session (empty auth) authorizes the
  hierarchy and key operations. The statement contract: qualifying
  digest = the TPM's attested SHA-256 PCR digest; payload =
  length-prefixed [echoed qualifying data, PCR digest, RSA signature].
- CI installs `libclang-dev`, `libtss2-dev`, and `swtpm` and runs the
  real-quote integration suite; the development host (LNL PTT fTPM,
  tpm2-tss 4.1.3, swtpm 0.10.2) runs the same suite locally.
- Development lessons recorded: swtpm needs `--flags
  not-need-init,startup-clear` or the TPM rejects commands with
  TPM_RC_INITIALIZE; ESYS commands requiring authorization
  (CreatePrimary, Quote) fail with TSS2_BASE_RC_BAD_VALUE unless a
  password session is set; the swtpm TCTI handshake needs both the
  server and ctrl ports listening.

## Consequences

The backend is genuinely backend-agnostic: the mock (test class) and
swtpm (software class) implement one seam, and M3-023's fTPM backend
will join them. Costs: the build environment now requires libclang and
tss2 development packages; the deny allowlist needs an ADR-backed
amendment for any transitive change; verifier-side quote validation
(cryptographic) is deliberately not in this slice and arrives with
enrollment in M3-022.

## Threat-model impact

The class gate now guards real TPM material: a software-TPM statement
can never satisfy a hardware expectation. No raw TPM command escapes
`ogir-attest-tpm`. The TPM-era attack categories (quote forgery,
unenrolled AK, copied public AK) are hosted starting with M3-022/024.

## Privacy impact

None beyond ADR-0017: statements redact payloads; the backend exposes no
key material through OGIR APIs.

## Dependency and license impact

The first external production dependency tree: 51 unique crates in the
normal+build graph (plus r-efi and windows-link for platform targets),
all enumerated in `deny.toml` under this ADR. `cargo deny check`
passes in full (advisories, bans, licenses, sources).

## Validation

Five integration tests against real per-test swtpm instances: real
quote with qualifying-data echo and 32-byte SHA-256 PCR digest,
256-byte RSA-2048 signature; distinct qualifying data yields distinct
payloads; software statements rejected under hardware and test
expectations; invalid requests fail closed; unreachable instances fail
closed. Full workspace suite and all house gates green.

## Rollback

Revert the slice commit; remove `ogir-attest-tpm` from the workspace
and the 53-entry allowlist; `deny.toml` returns to the zero-external
policy. ADR-0017's seam is unaffected.

## Primary sources

- tss-esapi 7.7.0 and tss-esapi-sys sources (crates.io), inspected
  directly: `quote`, `create_primary`, builders, TCTI configs.
- The irlume audit record (workspace shared memory,
  `project-rust-tss-esapi.md`), 2026-08-20/2026-08-29.
- Approved M3 entry scoping, recommendations R1-R4 (2026-09-06).
- TPM 2.0 Library Part 3 commands (Quote, CreatePrimary semantics);
  swtpm 0.10 flag documentation.
