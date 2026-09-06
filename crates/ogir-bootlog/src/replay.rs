// SPDX-License-Identifier: Apache-2.0

//! PCR replay: recompute the TPM's PCR values from a parsed event log
//! by extending each event's SHA-256 digest in log order, exactly as
//! the TPM would have. `new PCR = SHA256(old PCR || event digest)`.

use std::collections::HashMap;

use crate::BootlogError;
use crate::parser::EventLog;

/// The replayed SHA-256 values for every PCR the log touches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    values: HashMap<u32, [u8; 32]>,
}

impl Replay {
    /// Replays the log's SHA-256 digests.
    pub fn sha256(log: &EventLog) -> Result<Self, BootlogError> {
        let mut values: HashMap<u32, [u8; 32]> = HashMap::new();
        // A StartupLocality EV_NO_ACTION event carrying locality 3
        // means the firmware ran first and PCR 0 starts at all-FF
        // rather than zero (TCG PC Client Platform Firmware Profile).
        let mut pcr0_initial = [0u8; 32];
        const NO_ACTION: u32 = 0x0000_0003;
        const LOCALITY_MARKER: &[u8; 15] = b"StartupLocality";
        for event in &log.events {
            // EV_NO_ACTION events never extend a PCR: the TPM ignores
            // them for extension, but the locality marker changes
            // PCR 0's starting value.
            if event.event_type == NO_ACTION {
                if event.event.len() == LOCALITY_MARKER.len() + 1
                    && &event.event[..LOCALITY_MARKER.len()] == LOCALITY_MARKER
                    && event.event[LOCALITY_MARKER.len()] == 3
                {
                    pcr0_initial = [0xFF; 32];
                }
                continue;
            }
            let digest = match event.sha256_digest() {
                Some(digest) if digest.len() == 32 => digest,
                Some(_) => return Err(BootlogError::Malformed("sha256 digest size")),
                // Events without a SHA-256 digest (e.g. SHA-1-only
                // legacy entries) do not extend the SHA-256 bank.
                None => continue,
            };
            let initial = if event.pcr_index == 0 {
                pcr0_initial
            } else {
                [0u8; 32]
            };
            let entry = values.entry(event.pcr_index).or_insert(initial);
            let mut input = Vec::with_capacity(64);
            input.extend_from_slice(entry);
            input.extend_from_slice(digest);
            *entry = ogir_attest::sha256::sha256(&input);
        }
        Ok(Self { values })
    }

    /// The replayed SHA-256 value for a PCR, if the log touched it.
    pub fn pcr(&self, index: u32) -> Option<&[u8; 32]> {
        // Direct reference through the map entry; the array is stored
        // by value so a stable reference exists for the borrow.
        self.values.get(&index).map(|value| value as &[u8; 32])
    }

    /// The PCRs the log touched.
    pub fn touched(&self) -> Vec<u32> {
        let mut indices: Vec<u32> = self.values.keys().copied().collect();
        indices.sort_unstable();
        indices
    }

    /// Compares against expected values; every expectation must match
    /// and every touched PCR must be expected (no unexplained state).
    pub fn matches(&self, expected: &HashMap<u32, [u8; 32]>) -> Result<(), BootlogError> {
        for (index, value) in &self.values {
            match expected.get(index) {
                Some(expected_value) if expected_value == value => {}
                _ => return Err(BootlogError::PcrMismatch),
            }
        }
        for index in expected.keys() {
            if !self.values.contains_key(index) {
                return Err(BootlogError::PcrMismatch);
            }
        }
        Ok(())
    }

    /// Partial comparison: every expectation must match and be
    /// touched, but touched PCRs WITHOUT expectations are permitted -
    /// for profiles that deliberately cover a subset (e.g. skipping
    /// PCR 0 where firmware-log fidelity is known-imperfect).
    pub fn matches_subset(&self, expected: &HashMap<u32, [u8; 32]>) -> Result<(), BootlogError> {
        for (index, value) in expected {
            match self.values.get(index) {
                Some(actual) if actual == value => {}
                _ => return Err(BootlogError::PcrMismatch),
            }
        }
        Ok(())
    }
}
