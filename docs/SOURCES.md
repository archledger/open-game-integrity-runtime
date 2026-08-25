# Primary technical sources

OGIR design and implementation work should cite primary specifications and
upstream documentation. This file is a starting index, not permission to skip
version checks or source review.

## Remote attestation and evidence

- IETF RFC 9334 — Remote ATtestation procedureS (RATS) Architecture:
  https://www.rfc-editor.org/rfc/rfc9334.html
- IETF RFC 9711 — The Entity Attestation Token (EAT):
  https://www.rfc-editor.org/rfc/rfc9711.html
- IETF RFC 9782 — EAT and attestation media types:
  https://www.rfc-editor.org/rfc/rfc9782.html
- Trusted Computing Group specifications:
  https://trustedcomputinggroup.org/resource/tpm-library-specification/

## Linux integrity and measured boot

- Linux IMA documentation:
  https://docs.kernel.org/security/IMA-templates.html
- Linux fs-verity documentation:
  https://docs.kernel.org/filesystems/fsverity.html
- Linux module-signing documentation:
  https://docs.kernel.org/admin-guide/module-signing.html
- Linux lockdown documentation:
  https://docs.kernel.org/security/lockdown.html
- Linux BPF LSM documentation:
  https://docs.kernel.org/bpf/prog_lsm.html
- systemd-stub:
  https://www.freedesktop.org/software/systemd/man/latest/systemd-stub.html
- systemd-measure:
  https://www.freedesktop.org/software/systemd/man/latest/systemd-measure.html
- Keylime documentation and source:
  https://keylime.readthedocs.io/
  https://github.com/keylime/keylime

## Wine and Proton boundary

- Wine Unixlib interface:
  https://github.com/wine-mirror/wine/blob/master/include/wine/unixlib.h
- Wine TBS implementation and exports:
  https://github.com/wine-mirror/wine/tree/master/dlls/tbs
- Valve Proton developer documentation:
  https://partner.steamgames.com/doc/steamhardware/proton

## Rust and supply-chain tooling

- Rust toolchain override file:
  https://rust-lang.github.io/rustup/overrides.html#the-toolchain-file
- Cargo manifest reference:
  https://doc.rust-lang.org/cargo/reference/manifest.html
- Clippy:
  https://doc.rust-lang.org/clippy/
- cargo-fuzz:
  https://github.com/rust-fuzz/cargo-fuzz
- cargo-deny:
  https://github.com/EmbarkStudios/cargo-deny
- SLSA build provenance:
  https://slsa.dev/spec/v1.2/provenance
- OpenSSF OSPS Baseline:
  https://baseline.openssf.org/
- OpenSSF Best Practices Badge:
  https://www.bestpractices.dev/

## GitHub hardening

- Secure use reference for GitHub Actions:
  https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
- Repository rulesets:
  https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets
- Secret scanning and push protection:
  https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning
- CodeQL default setup:
  https://docs.github.com/en/code-security/code-scanning/enabling-code-scanning/configuring-default-setup-for-code-scanning
