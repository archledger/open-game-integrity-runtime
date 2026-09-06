// SPDX-License-Identifier: Apache-2.0

//! The TCG2 ("crypto agile") binary event-log parser: the Spec ID
//! header event (TCG_EfiSpecIDEvent) followed by TCG_PCR_EVENT2
//! records. The parser is total: every malformed shape fails closed
//! with a deterministic error, and trailing bytes reject.

use crate::BootlogError;

/// One parsed TCG_PCR_EVENT2 record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The PCR the event extends.
    pub pcr_index: u32,
    /// The TCG event type (e.g. EV_POST_CODE, EV_EFI_VARIABLE_DRIVER_CONFIG).
    pub event_type: u32,
    /// The digests the event extends, one per algorithm.
    pub digests: Vec<(u16, Vec<u8>)>,
    /// The raw event payload.
    pub event: Vec<u8>,
}

impl Event {
    /// The SHA-256 digest of this event, if present.
    pub fn sha256_digest(&self) -> Option<&[u8]> {
        self.digests
            .iter()
            .find(|(algorithm, _)| *algorithm == SHA256_ID)
            .map(|(_, digest)| digest.as_slice())
    }
}

/// The TPM_ECC_HASH algorithm identifier for SHA-256 (TPM_ALG_SHA256).
pub const SHA256_ID: u16 = 0x000B;

/// The parsed Spec ID header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecId {
    /// The number of digest algorithms the log uses.
    pub algorithm_count: u32,
    /// (algorithmId, digestSize) for each.
    pub algorithms: Vec<(u16, u8)>,
}

/// A fully parsed event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventLog {
    /// The Spec ID header.
    pub spec_id: SpecId,
    /// The events, in log order.
    pub events: Vec<Event>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BootlogError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(BootlogError::Truncated)?;
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, BootlogError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, BootlogError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, BootlogError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Parses a TCG2 binary event log.
///
/// Layout (all little-endian): the first record is the legacy-sized
/// header of the Spec ID event (pcrIndex u32, eventType u32, a
/// 20-byte SHA-1 digest, eventDataSize u32, and the vendor/data area
/// starting with the "Spec ID Event03\\0" signature), whose tail carries
/// the numberOfAlgorithms and (algorithmId u16, digestSize u8) pairs.
/// Every subsequent record is TCG_PCR_EVENT2: pcrIndex u32, eventType
/// u32, digestCount u32, then per digest algorithmId u16 + the
/// digestSize bytes declared by the Spec ID, then eventSize u32 and
/// the event bytes.
pub fn parse(bytes: &[u8]) -> Result<EventLog, BootlogError> {
    let mut reader = Reader::new(bytes);

    // Spec ID event: legacy header.
    let pcr_index = reader.u32()?;
    let event_type = reader.u32()?;
    let _sha1_digest = reader.take(20)?;
    let event_size = reader.u32()? as usize;
    let body = reader.take(event_size)?;

    const NO_ACTION: u32 = 0x0000_0003;
    if pcr_index != 0 || event_type != NO_ACTION {
        return Err(BootlogError::NotTcg2);
    }
    const SIGNATURE: &[u8; 16] = b"Spec ID Event03\0";
    if body.len() < SIGNATURE.len() || &body[..SIGNATURE.len()] != SIGNATURE {
        return Err(BootlogError::NotTcg2);
    }

    // TCG_EfiSpecIDEventStruct tail: platformClass u32, specVersionMinor
    // u8, specVersionMajor u8, errata u8, uintnSize u8,
    // numberOfAlgorithms u32, then the algorithm sizes.
    let mut tail = Reader::new(&body[SIGNATURE.len()..]);
    let _platform_class = tail.u32()?;
    let _minor = tail.u8()?;
    let _major = tail.u8()?;
    let _errata = tail.u8()?;
    let _uintn_size = tail.u8()?;
    let algorithm_count = tail.u32()?;
    if algorithm_count == 0 || algorithm_count > 16 {
        return Err(BootlogError::Malformed("algorithm count out of range"));
    }
    let mut algorithms = Vec::with_capacity(algorithm_count as usize);
    for _ in 0..algorithm_count {
        let algorithm_id = tail.u16()?;
        let digest_size = tail.u8()?;
        if digest_size == 0 || digest_size > 64 {
            return Err(BootlogError::Malformed("digest size out of range"));
        }
        algorithms.push((algorithm_id, digest_size));
    }
    // The remaining vendorInfo length byte plus vendor bytes are
    // present in some logs; remaining tail is ignored deliberately
    // (the parser needs only the algorithm table).

    let spec_id = SpecId {
        algorithm_count,
        algorithms,
    };

    let mut events = Vec::new();
    while !reader.done() {
        let pcr_index = reader.u32()?;
        let event_type = reader.u32()?;
        let digest_count = reader.u32()?;
        if digest_count == 0 || digest_count > algorithm_count {
            return Err(BootlogError::Malformed(
                "digest count inconsistent with Spec ID",
            ));
        }
        let mut digests = Vec::with_capacity(digest_count as usize);
        for _ in 0..digest_count {
            let algorithm_id = reader.u16()?;
            let digest_size = spec_id
                .algorithms
                .iter()
                .find(|(id, _)| *id == algorithm_id)
                .map(|(_, size)| *size)
                .ok_or(BootlogError::Malformed(
                    "digest algorithm not declared in Spec ID",
                ))?;
            let digest = reader.take(digest_size as usize)?.to_vec();
            digests.push((algorithm_id, digest));
        }
        let event_size = reader.u32()? as usize;
        let event = reader.take(event_size)?.to_vec();
        events.push(Event {
            pcr_index,
            event_type,
            digests,
            event,
        });
    }

    Ok(EventLog { spec_id, events })
}
