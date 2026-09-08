// SPDX-License-Identifier: Apache-2.0

//! The strict bounded JSON codec for the verifier wire protocol
//! (ADR-0032). This is deliberately NOT a general JSON library: the
//! protocol carries flat objects of strings and byte-hex fields
//! only, and the decoder enforces that shape with fixed limits -
//! total length, nesting depth of exactly one object, no numbers,
//! no floats, no duplicates, no trailing garbage. Malformed input
//! fails closed into a named error.

/// Decoder/encoder failures. Deterministic, non-disciplinary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    /// The input exceeded the fixed size ceiling.
    TooLarge,
    /// The input is not a flat object of the allowed member kinds.
    Malformed(&'static str),
    /// A required member was absent or duplicated.
    Member(&'static str),
    /// A value violated its field's own bound.
    Value(&'static str),
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => formatter.write_str("request body exceeds the protocol ceiling"),
            Self::Malformed(detail) => write!(formatter, "malformed protocol object: {detail}"),
            Self::Member(detail) => write!(formatter, "protocol member error: {detail}"),
            Self::Value(detail) => write!(formatter, "protocol value error: {detail}"),
        }
    }
}

impl std::error::Error for JsonError {}

/// The hard ceiling for any encoded object on the wire.
pub const MAX_WIRE: usize = 64 * 1024;
/// The member-count ceiling for any object.
pub const MAX_MEMBERS: usize = 32;
/// The string-value length ceiling (bytes, UTF-8).
pub const MAX_STRING: usize = 512;
/// The hex-value length ceiling (characters; two per byte).
pub const MAX_HEX: usize = 8192;

/// A decoded protocol value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Hex(Vec<u8>),
}

/// Decodes one flat JSON object into ordered (key, value) pairs.
/// The only permitted shapes are `"key":"string"` and
/// `"key":"<lowercase hex>"` for keys ending in `_hex`.
pub fn decode_object(bytes: &[u8]) -> Result<Vec<(String, Value)>, JsonError> {
    if bytes.len() > MAX_WIRE {
        return Err(JsonError::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| JsonError::Malformed("utf-8"))?;
    let text = text.trim_start();
    let text = text
        .strip_prefix('{')
        .ok_or(JsonError::Malformed("not an object"))?;
    let text = text
        .strip_suffix('}')
        .ok_or(JsonError::Malformed("unterminated object"))?;
    let text = text.trim();

    let mut members = Vec::new();
    if text.is_empty() {
        return Ok(members);
    }
    let mut rest = text;
    loop {
        rest = rest.trim_start();
        let (key, after_key) =
            parse_string(rest, MAX_STRING).ok_or(JsonError::Malformed("member key"))?;
        let after_key = after_key
            .trim_start()
            .strip_prefix(':')
            .ok_or(JsonError::Malformed("separator"))?;
        let after_colon = after_key.trim_start();
        let value_limit = if key.ends_with("_hex") {
            MAX_HEX
        } else {
            MAX_STRING
        };
        let (raw_value, after_value) =
            parse_string(after_colon, value_limit).ok_or(JsonError::Malformed("member value"))?;
        let value = if key.ends_with("_hex") {
            if raw_value.len() > MAX_HEX || raw_value.len() % 2 != 0 {
                return Err(JsonError::Value("hex length"));
            }
            let mut decoded = Vec::with_capacity(raw_value.len() / 2);
            let value_bytes = raw_value.as_bytes();
            for pair in value_bytes.chunks(2) {
                let high = nibble(pair[0]).ok_or(JsonError::Value("hex digit"))?;
                let low = nibble(pair[1]).ok_or(JsonError::Value("hex digit"))?;
                decoded.push((high << 4) | low);
            }
            Value::Hex(decoded)
        } else {
            Value::Str(raw_value)
        };
        if members
            .iter()
            .any(|(existing, _): &(String, Value)| existing == &key)
        {
            return Err(JsonError::Member("duplicate"));
        }
        members.push((key, value));
        if members.len() > MAX_MEMBERS {
            return Err(JsonError::Member("too many"));
        }
        rest = after_value.trim_start();
        if let Some(tail) = rest.strip_prefix(',') {
            rest = tail;
            continue;
        }
        if rest.is_empty() {
            break;
        }
        return Err(JsonError::Malformed("trailing content"));
    }
    Ok(members)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Parses one JSON string literal starting at `text`; returns the
/// decoded content and the remainder. Escapes other than `\\` and
/// `\"` are rejected; control characters are rejected.
fn parse_string(text: &str, limit: usize) -> Option<(String, &str)> {
    let rest = text.strip_prefix('"')?;
    let mut output = String::new();
    let mut escaped = false;
    for (index, character) in rest.char_indices() {
        if escaped {
            match character {
                '\\' | '"' => {
                    output.push(character);
                    escaped = false;
                }
                _ => return None,
            }
            continue;
        }
        match character {
            '"' => {
                if output.len() > limit {
                    return None;
                }
                return Some((output, &rest[index + 1..]));
            }
            '\\' => escaped = true,
            '\u{00}'..='\u{1f}' => return None,
            _ => output.push(character),
        }
    }
    None
}

/// Encodes one flat object of string/hex members.
pub fn encode_object(members: &[(&str, Value)]) -> String {
    let mut output = String::from("{");
    for (index, (key, value)) in members.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push('"');
        output.push_str(&escape(key));
        output.push_str("\":\"");
        match value {
            Value::Str(text) => output.push_str(&escape(text)),
            Value::Hex(bytes) => {
                for byte in bytes {
                    output.push_str(&format!("{byte:02x}"));
                }
            }
        }
        output.push('"');
    }
    output.push('}');
    output
}

fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Extracts exactly one string member.
pub fn require_str<'a>(members: &'a [(String, Value)], key: &str) -> Result<&'a str, JsonError> {
    for (existing, value) in members {
        if existing == key {
            return match value {
                Value::Str(text) => Ok(text),
                Value::Hex(_) => Err(JsonError::Value("wrong member kind")),
            };
        }
    }
    Err(JsonError::Member("missing member"))
}

/// Extracts exactly one hex member.
pub fn require_hex<'a>(members: &'a [(String, Value)], key: &str) -> Result<&'a [u8], JsonError> {
    for (existing, value) in members {
        if existing == key {
            return match value {
                Value::Hex(bytes) => Ok(bytes),
                Value::Str(_) => Err(JsonError::Value("wrong member kind")),
            };
        }
    }
    Err(JsonError::Member("missing member"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_flat_objects() {
        let members = vec![
            (
                "publisher_id".to_string(),
                Value::Str("pub.example".to_string()),
            ),
            (
                "challenge_hex".to_string(),
                Value::Hex(vec![0xde, 0xad, 0xbe, 0xef]),
            ),
        ];
        let encoded = encode_object(&[
            ("publisher_id", Value::Str("pub.example".to_string())),
            ("challenge_hex", Value::Hex(vec![0xde, 0xad, 0xbe, 0xef])),
        ]);
        let decoded = decode_object(encoded.as_bytes()).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(decoded, members);
    }

    #[test]
    fn escapes_are_symmetric() {
        let encoded = encode_object(&[("note", Value::Str("a \"quoted\" \\ path".to_string()))]);
        let decoded = decode_object(encoded.as_bytes()).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(decoded[0].1, Value::Str("a \"quoted\" \\ path".to_string()));
    }

    #[test]
    fn rejects_numbers_arrays_and_nesting() {
        for bad in [
            "{\"a\":1}",
            "{\"a\":[1,2]}",
            "{\"a\":{\"b\":\"c\"}}",
            "{\"a\":true}",
            "{\"a\":\"x\",}",
            "{a:\"x\"}",
            "{\"a\":\"x\" trailing}",
            "{\"a\":\"x\"",
            "",
            "[]",
        ] {
            assert!(decode_object(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn rejects_duplicates_and_enforces_hex_shape() {
        assert_eq!(
            decode_object(b"{\"a\":\"x\",\"a\":\"y\"}"),
            Err(JsonError::Member("duplicate"))
        );
        assert!(decode_object(b"{\"k_hex\":\"zz\"}").is_err());
        assert!(decode_object(b"{\"k_hex\":\"abc\"}").is_err());
        assert_eq!(
            decode_object(b"{\"k_hex\":\"0a0b\"}").unwrap_or_else(|e| panic!("{e:?}"))[0].1,
            Value::Hex(vec![0x0a, 0x0b])
        );
    }

    #[test]
    fn rejects_control_characters_and_bad_escapes() {
        assert!(decode_object(b"{\"a\":\"line\nbreak\"}").is_err());
        assert!(decode_object(b"{\"a\":\"tab\\there\"}").is_err());
    }

    #[test]
    fn oversized_inputs_reject() {
        let big = format!("{{\"a\":\"{}\"}}", "x".repeat(MAX_STRING + 1));
        assert!(decode_object(big.as_bytes()).is_err());
        let huge = vec![b'{'; MAX_WIRE + 1];
        assert_eq!(decode_object(&huge), Err(JsonError::TooLarge));
    }

    #[test]
    fn accessors_require_the_right_kind() {
        let members =
            decode_object(b"{\"s\":\"v\",\"h_hex\":\"01\"}").unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(require_str(&members, "s"), Ok("v"));
        assert_eq!(require_hex(&members, "h_hex"), Ok(&[0x01][..]));
        assert_eq!(
            require_str(&members, "h_hex"),
            Err(JsonError::Value("wrong member kind"))
        );
        assert_eq!(
            require_hex(&members, "s"),
            Err(JsonError::Value("wrong member kind"))
        );
        assert_eq!(
            require_str(&members, "absent"),
            Err(JsonError::Member("missing member"))
        );
    }
}
