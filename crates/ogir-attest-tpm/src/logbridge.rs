// SPDX-License-Identifier: Apache-2.0

//! The log-quote bridge (M4-027): connects `ogir-bootlog`'s replay to
//! the live TPM and the M3 quote chain. The measured triangle - event
//! log, TPM PCR bank, and quoted digest - must agree exactly; a log
//! whose replay disagrees with the quote is the roadmap's
//! log-does-not-reproduce attack category and rejects here.

use ogir_attest::BackendError;
use ogir_bootlog::parser::{EventLog, SHA256_ID};
use ogir_bootlog::replay::Replay;
use tss_esapi::Context;
use tss_esapi::handles::PcrHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Digest, DigestValues};

/// Failure modes of the bridge. Deterministic, non-disciplinary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// The TPM rejected an extend or the connection failed.
    Tpm(BackendError),
    /// The replayed log value disagrees with the quoted digest.
    LogQuoteMismatch,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tpm(error) => write!(formatter, "TPM operation failed: {error:?}"),
            Self::LogQuoteMismatch => {
                formatter.write_str("log replay disagrees with the quoted PCR digest")
            }
        }
    }
}

impl std::error::Error for BridgeError {}

/// A connection to a swtpm instance for extending log digests.
#[derive(Debug)]
pub struct LogExtender {
    context: Context,
}

impl LogExtender {
    /// Connects to the swtpm instance at `host:port`.
    pub fn connect(host: &str, port: u16) -> Result<Self, BridgeError> {
        use std::str::FromStr;
        let config =
            tss_esapi::tcti_ldr::NetworkTPMConfig::from_str(&format!("host={host},port={port}"))
                .map_err(|_| BridgeError::Tpm(BackendError::InvalidRequest))?;
        let mut context = Context::new(tss_esapi::tcti_ldr::TctiNameConf::Swtpm(config))
            .map_err(|_| BridgeError::Tpm(BackendError::Internal))?;
        // PCR_Extend authorizes the (empty-auth) PCR handle through
        // session 1; a password session satisfies it.
        context.set_sessions((
            Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
            None,
            None,
        ));
        Ok(Self { context })
    }

    /// Reads the live SHA-256 value of a PCR (test/diagnostic aid).
    #[allow(dead_code)]
    pub fn read_pcr(
        &mut self,
        slot: tss_esapi::structures::PcrSlot,
    ) -> Result<[u8; 32], BridgeError> {
        use tss_esapi::interface_types::algorithm::HashingAlgorithm;
        use tss_esapi::structures::PcrSelectionListBuilder;
        let selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[slot])
            .build()
            .map_err(|_| BridgeError::Tpm(BackendError::Internal))?;
        self.context.clear_sessions();
        let (_counter, _selection, digests) = self
            .context
            .pcr_read(selection)
            .map_err(|_| BridgeError::Tpm(BackendError::Internal))?;
        // A single-algorithm single-PCR selection yields exactly one
        // digest in the returned list.
        match digests.value().first() {
            Some(digest) if digest.value().len() == 32 => match digest.value().try_into() {
                Ok(array) => Ok(array),
                Err(_) => Err(BridgeError::Tpm(BackendError::Internal)),
            },
            _ => Err(BridgeError::Tpm(BackendError::Internal)),
        }
    }

    /// Extends one digest into a live PCR (SHA-256 bank).
    pub fn extend(&mut self, pcr: PcrHandle, digest: [u8; 32]) -> Result<(), BridgeError> {
        let mut values = DigestValues::new();
        values.set(
            HashingAlgorithm::Sha256,
            Digest::try_from(digest.to_vec())
                .map_err(|_| BridgeError::Tpm(BackendError::InvalidRequest))?,
        );
        self.context
            .pcr_extend(pcr, values)
            .map_err(|_| BridgeError::Tpm(BackendError::Internal))
    }

    /// Extends every SHA-256 digest the log attributes to
    /// `source_pcr` into the live `target` PCR, in log order -
    /// reproducing exactly the extension sequence the replay computes
    /// for the source bank.
    pub fn extend_log_bank(
        &mut self,
        log: &EventLog,
        source_pcr: u32,
        target: PcrHandle,
    ) -> Result<(), BridgeError> {
        const NO_ACTION: u32 = 0x0000_0003;
        for event in &log.events {
            if event.event_type == NO_ACTION || event.pcr_index != source_pcr {
                continue;
            }
            if let Some(digest) = event.sha256_digest().filter(|d| d.len() == 32) {
                let digest: [u8; 32] = match digest.try_into() {
                    Ok(array) => array,
                    Err(_) => continue,
                };
                self.extend(target, digest)?;
            }
        }
        let _ = SHA256_ID;
        Ok(())
    }
}

/// The triangle check: the log's replayed value for `source_pcr` must
/// equal the digest the TPM quoted for the bank the events were
/// extended into. This is the M4 exit criterion "the verifier
/// reconstructs or validates measured state against the quote" for the
/// log-fidelity subset the replay covers.
pub fn replay_agrees_with_quote(
    log: &EventLog,
    source_pcr: u32,
    quoted_digest: &[u8; 32],
) -> Result<(), BridgeError> {
    let replay = Replay::sha256(log).map_err(|_| BridgeError::Tpm(BackendError::Internal))?;
    // TPM2_Quote's pcrDigest is the hash of the concatenated selected
    // PCR VALUES (TPM2 Part 3), so a single-bank quote carries
    // SHA256(pcr_value), not the PCR value itself: the verifier
    // reconstructs the value from the log, hashes it, and compares.
    match replay.pcr(source_pcr) {
        Some(replayed) if &ogir_attest::sha256::sha256(replayed) == quoted_digest => Ok(()),
        _ => Err(BridgeError::LogQuoteMismatch),
    }
}
