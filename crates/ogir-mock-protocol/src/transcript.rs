// SPDX-License-Identifier: Apache-2.0

//! ADR-0015 record encoding: fixed domain tags plus canonical, strictly
//! ascending, unique, length-prefixed records with fail-closed parsing.

use crate::TranscriptError;

/// ADR-0015 domain tags. The `MOCK` component is permanent.
pub const TAG_CHALLENGE: &str = "OGIR-MOCK-CHALLENGE-1";
/// Evidence-binding transcript tag.
pub const TAG_EVIDENCE: &str = "OGIR-MOCK-EVIDENCE-1";
/// Short-lived test permit tag.
pub const TAG_PERMIT: &str = "OGIR-MOCK-PERMIT-1";
/// Session-key proof-of-possession tag.
pub const TAG_POP: &str = "OGIR-MOCK-POP-1";
/// Authenticated test revocation-view tag (registered, no registry).
pub const TAG_REVOKE: &str = "OGIR-MOCK-REVOKE-1";

/// Bounded object size, aligned with the protocol frame bound.
pub const MAX_OBJECT_LENGTH: usize = 1024 * 1024;

/// A field registry for one object class: required and optional ids.
///
/// Unknown ids, including the reserved extension range, are rejected in M2.
#[derive(Debug, Clone, Copy)]
pub struct Schema {
    /// Field ids that must be present, in canonical order.
    pub required: &'static [u16],
    /// Field ids that may be present, in canonical order.
    pub optional: &'static [u16],
}

/// Encodes `tag` plus the records in the given order.
///
/// Records must already be strictly ascending by id; the function enforces
/// uniqueness and order, making the encoding canonical by construction.
pub fn encode(tag: &str, records: &[(u16, Vec<u8>)]) -> Result<Vec<u8>, TranscriptError> {
    let mut bytes = Vec::with_capacity(tag.len() + records.len() * 8);
    bytes.extend_from_slice(tag.as_bytes());
    let mut previous: Option<u16> = None;
    for (id, value) in records {
        match previous {
            Some(previous_id) if *id == previous_id => {
                return Err(TranscriptError::DuplicateField { id: *id });
            }
            Some(previous_id) if *id < previous_id => {
                return Err(TranscriptError::OutOfOrder { id: *id });
            }
            _ => {}
        }
        if bytes.len() + 6 + value.len() > MAX_OBJECT_LENGTH {
            return Err(TranscriptError::ObjectTooLarge);
        }
        bytes.extend_from_slice(&id.to_be_bytes());
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value);
        previous = Some(*id);
    }
    Ok(bytes)
}

/// A parsed object: the records of one class, accessed by field id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRecords {
    values: Vec<(u16, Vec<u8>)>,
}

impl ParsedRecords {
    /// Returns the record value for `id`, if the object carried it.
    pub fn get(&self, id: u16) -> Option<&[u8]> {
        self.values
            .iter()
            .find(|(candidate, _)| *candidate == id)
            .map(|(_, value)| value.as_slice())
    }

    /// Requires a field's presence, mapping absence to `MissingField`.
    pub fn require(&self, id: u16) -> Result<&[u8], TranscriptError> {
        match self.get(id) {
            Some(value) => Ok(value),
            None => Err(TranscriptError::MissingField { id }),
        }
    }

    /// Re-encodes the parsed records; canonical parse/re-encode equality.
    pub fn reencode(&self, tag: &str) -> Result<Vec<u8>, TranscriptError> {
        encode(tag, &self.values)
    }
}

/// Parses `tag` plus the record sequence under `schema`.
///
/// Fails closed on duplicate, out-of-order, unknown (including reserved
/// extension), oversized, truncated, or trailing input, and on missing
/// required fields. Field-value length invariants are the caller's next
/// check via [`ParsedRecords::require`].
pub fn parse(tag: &str, bytes: &[u8], schema: &Schema) -> Result<ParsedRecords, TranscriptError> {
    let tag_bytes = tag.as_bytes();
    if bytes.len() < tag_bytes.len() {
        return Err(TranscriptError::Truncated);
    }
    if &bytes[..tag_bytes.len()] != tag_bytes {
        return Err(TranscriptError::TagMismatch);
    }
    if bytes.len() > MAX_OBJECT_LENGTH {
        return Err(TranscriptError::ObjectTooLarge);
    }

    let mut values: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut offset = tag_bytes.len();
    let mut previous: Option<u16> = None;
    while offset < bytes.len() {
        if offset + 6 > bytes.len() {
            return Err(TranscriptError::Truncated);
        }
        let id = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let length = u32::from_be_bytes([
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
        ]) as usize;
        let value_start = offset + 6;
        let value_end = match value_start.checked_add(length) {
            Some(end) if end <= bytes.len() => end,
            Some(_) => return Err(TranscriptError::Truncated),
            None => return Err(TranscriptError::Truncated),
        };
        if length > MAX_OBJECT_LENGTH {
            return Err(TranscriptError::ObjectTooLarge);
        }
        let known = schema.required.contains(&id) || schema.optional.contains(&id);
        if !known {
            return Err(TranscriptError::UnknownField { id });
        }
        match previous {
            Some(previous_id) if id == previous_id => {
                return Err(TranscriptError::DuplicateField { id });
            }
            Some(previous_id) if id < previous_id => {
                return Err(TranscriptError::OutOfOrder { id });
            }
            _ => {}
        }
        values.push((id, bytes[value_start..value_end].to_vec()));
        previous = Some(id);
        offset = value_end;
    }
    for id in schema.required {
        if !values.iter().any(|(candidate, _)| candidate == id) {
            return Err(TranscriptError::MissingField { id: *id });
        }
    }
    Ok(ParsedRecords { values })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: Schema = Schema {
        required: &[0x0001, 0x0002],
        optional: &[0x0003],
    };

    #[test]
    fn encode_parse_roundtrip() {
        let records = vec![
            (0x0001, vec![1, 2, 3]),
            (0x0002, vec![]),
            (0x0003, vec![9; 40]),
        ];
        let bytes =
            encode(TAG_PERMIT, &records).unwrap_or_else(|error| panic!("encode: {error:?}"));
        assert_eq!(&bytes[..TAG_PERMIT.len()], TAG_PERMIT.as_bytes());
        let parsed =
            parse(TAG_PERMIT, &bytes, &SCHEMA).unwrap_or_else(|error| panic!("parse: {error:?}"));
        assert_eq!(parsed.get(0x0001), Some(&[1u8, 2, 3][..]));
        assert_eq!(parsed.get(0x0002), Some(&[][..]));
        assert_eq!(parsed.get(0x0003), Some(&[9u8; 40][..]));
        assert_eq!(
            parsed
                .reencode(TAG_PERMIT)
                .unwrap_or_else(|error| panic!("reencode: {error:?}")),
            bytes
        );
    }

    #[test]
    fn duplicate_id_rejected_at_encode_and_parse() {
        let bad = vec![(0x0002, vec![1]), (0x0002, vec![1])];
        assert_eq!(
            encode(TAG_POP, &bad),
            Err(TranscriptError::DuplicateField { id: 0x0002 })
        );
        let mut bytes = TAG_POP.as_bytes().to_vec();
        for (id, value) in [(0x0002u16, vec![1u8]), (0x0002u16, vec![1u8])] {
            bytes.extend_from_slice(&id.to_be_bytes());
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&value);
        }
        assert_eq!(
            parse(TAG_POP, &bytes, &SCHEMA),
            Err(TranscriptError::DuplicateField { id: 0x0002 })
        );
    }

    #[test]
    fn out_of_order_rejected() {
        let bad = vec![(0x0003, vec![1]), (0x0001, vec![1])];
        assert_eq!(
            encode(TAG_EVIDENCE, &bad),
            Err(TranscriptError::OutOfOrder { id: 0x0001 })
        );
    }

    #[test]
    fn unknown_and_extension_ids_rejected() {
        let bytes = encode(TAG_EVIDENCE, &[(0x0001, vec![]), (0x7FFF, vec![])])
            .unwrap_or_else(|error| panic!("encode: {error:?}"));
        assert_eq!(
            parse(TAG_EVIDENCE, &bytes, &SCHEMA),
            Err(TranscriptError::UnknownField { id: 0x7FFF })
        );
        let bytes = encode(TAG_EVIDENCE, &[(0x0001, vec![]), (0x8001, vec![])])
            .unwrap_or_else(|error| panic!("encode: {error:?}"));
        assert_eq!(
            parse(TAG_EVIDENCE, &bytes, &SCHEMA),
            Err(TranscriptError::UnknownField { id: 0x8001 })
        );
    }

    #[test]
    fn missing_required_and_trailing_rejected() {
        let bytes = encode(TAG_PERMIT, &[(0x0002, vec![])])
            .unwrap_or_else(|error| panic!("encode: {error:?}"));
        assert_eq!(
            parse(TAG_PERMIT, &bytes, &SCHEMA),
            Err(TranscriptError::MissingField { id: 0x0001 })
        );
        let mut trailing = encode(TAG_PERMIT, &[(0x0001, vec![]), (0x0002, vec![])])
            .unwrap_or_else(|error| panic!("encode: {error:?}"));
        trailing.push(0);
        assert_eq!(
            parse(TAG_PERMIT, &trailing, &SCHEMA),
            Err(TranscriptError::Truncated)
        );
    }

    #[test]
    fn truncated_record_header_and_value_rejected() {
        let full = encode(TAG_POP, &[(0x0001, vec![7; 10])])
            .unwrap_or_else(|error| panic!("encode: {error:?}"));
        for cut in [1usize, 4, 7, 12] {
            let bytes = &full[..full.len() - cut];
            match parse(TAG_POP, bytes, &SCHEMA) {
                Err(TranscriptError::Truncated | TranscriptError::MissingField { .. }) => {}
                other => panic!("unexpected result for cut {cut}: {other:?}"),
            }
        }
    }

    #[test]
    fn wrong_tag_rejected_before_any_record_is_read() {
        let bytes = encode(TAG_CHALLENGE, &[(0x0001, vec![]), (0x0002, vec![])])
            .unwrap_or_else(|error| panic!("encode: {error:?}"));
        for tag in [TAG_EVIDENCE, TAG_PERMIT, TAG_POP, TAG_REVOKE] {
            assert_eq!(
                parse(tag, &bytes, &SCHEMA),
                Err(TranscriptError::TagMismatch)
            );
        }
    }
}
