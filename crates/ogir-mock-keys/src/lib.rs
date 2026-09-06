// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! TEST-ONLY ephemeral software keys for the OGIR mock protocol.
//!
//! This crate implements ADR-0016. Its SHA-256 and HMAC authenticator are
//! symmetric, offer no non-repudiation, confidentiality, or side-channel
//! resistance, and are **not production cryptography**. Key ids carry the
//! permanent `OGIR-MOCK` namespace and are never reusable as production
//! identity. No production crate may depend on this crate; mock protocol
//! code that needs keys lives in separate test-only crates or binaries.
//! Every obligation here traces to
//! [ADR-0016](../../docs/adr/0016-test-only-ephemeral-key-hierarchy.md).

pub mod hmac;
pub mod keys;
pub use ogir_attest::sha256;
