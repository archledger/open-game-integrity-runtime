## Problem

<!-- What exact problem does this pull request solve? -->

## Security requirement and invariants

<!-- Link the relevant invariant numbers and threats. -->

## Scope

### In scope

-

### Out of scope

-

## Primary sources

<!-- Official specifications, documentation, or upstream source. -->

-

## Changes

-

## Trust boundaries affected

- [ ] None
- [ ] Windows/Proton bridge
- [ ] Local IPC
- [ ] Privileged service
- [ ] TPM/evidence
- [ ] Verifier/relying party
- [ ] Reference/revocation
- [ ] Build/release supply chain

## Verification

### Commands run

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
```

### Positive tests

-

### Negative/adversarial tests

-

### Fuzz/property/race impact

-

## Privacy and logging impact

- [ ] No new disclosed claim
- [ ] No new log field
- [ ] Privacy model updated
- [ ] Redaction tests updated

## Dependency and license impact

- [ ] No dependency added or changed
- [ ] Dependency review documented
- [ ] SPDX/license boundary reviewed

## Documentation

- [ ] Architecture updated or not applicable
- [ ] Threat model updated or not applicable
- [ ] ADR added/updated or not applicable
- [ ] Protocol updated or not applicable
- [ ] Lessons learned updated or not applicable

## AI assistance

- AI-Assisted: yes/no
- AI-System:
- AI-Use:
- Human-Reviewed-Every-Line: yes/no
- Primary-Sources-Verified: yes/no

## Residual risks and limitations

-

## Contributor certification

- [ ] My commits include a `Signed-off-by` trailer.
- [ ] I understand and accept responsibility for the submitted code and documentation.
