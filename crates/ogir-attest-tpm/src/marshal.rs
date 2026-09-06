// SPDX-License-Identifier: Apache-2.0

//! The audited marshaling boundary (ADR-0020). This module contains the
//! workspace's ONLY permitted `unsafe` block: a single call to
//! `Tss2_MU_TPMS_ATTEST_Marshal` that serializes a parsed, safe
//! `Attest` structure back into the exact bytes the TPM signed. The
//! crate-level lint posture is `unsafe_code = "deny"` (not forbid)
//! solely to admit this one `#[allow]`; every other workspace crate
//! keeps the absolute forbid. The isolation gate asserts the lint
//! tables mirror the workspace except for this key.

use ogir_attest::BackendError;
use tss_esapi::structures::Attest;
use tss_esapi_sys::{TPMS_ATTEST, Tss2_MU_TPMS_ATTEST_Marshal};

/// Marshals an `Attest` into the signed TPMS_ATTEST bytes.
pub(crate) fn marshal_attest(attest: &Attest) -> Result<Vec<u8>, BackendError> {
    let tss_attest: TPMS_ATTEST = attest.clone().into();
    // TPMS_ATTEST is a fixed C struct (~1 KiB with the RSA buffer); a
    // 2 KiB buffer is ample, and the marshal call reports insufficient
    // space as an RC rather than overflowing.
    let mut buffer = vec![0u8; 2048];
    let mut offset = 0u64;
    let rc = marshal_into(
        &tss_attest,
        buffer.as_mut_ptr(),
        buffer.len() as u64,
        &mut offset,
    );
    if rc != 0 {
        return Err(BackendError::Internal);
    }
    buffer.truncate(offset as usize);
    Ok(buffer)
}

/// The single audited unsafe block (ADR-0020).
///
/// Safety argument: `tss_attest` is a fully-initialized value produced
/// by the safe `From` conversion; `buffer` is a live, correctly-sized
/// allocation of `buffer.len()` bytes; `offset` starts at zero and the
/// TSS2 MU layer never advances it past the buffer size; the function
/// writes only within `[0, offset)` on success and returns a nonzero
/// TSS2_RC on any inconsistency. No pointers escape.
#[allow(unsafe_code)]
fn marshal_into(
    tss_attest: &TPMS_ATTEST,
    buffer: *mut u8,
    buffer_size: u64,
    offset: &mut u64,
) -> u32 {
    // SAFETY: see the function-level safety argument above.
    unsafe { Tss2_MU_TPMS_ATTEST_Marshal(tss_attest, buffer, buffer_size, offset as *mut u64) }
}
