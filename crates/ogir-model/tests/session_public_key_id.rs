// SPDX-License-Identifier: Apache-2.0

use std::any::TypeId;
use std::collections::{HashSet, hash_map::DefaultHasher};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ogir_model::{Nonce, SESSION_PUBLIC_KEY_ID_LENGTH, SessionId, SessionPublicKeyId};

const EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH: usize = 32;
const SESSION_PUBLIC_KEY_ID_NAME: &str = "SessionPublicKeyId";
const PRIVATE_SENTINEL: [u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH] = [
    0x03, 0x17, 0x2b, 0x3f, 0x53, 0x67, 0x7b, 0x8f, 0xa3, 0xb7, 0xcb, 0xdf, 0xf3, 0x07, 0x1b, 0x2f,
    0x43, 0x57, 0x6b, 0x7f, 0x93, 0xa7, 0xbb, 0xcf, 0xe3, 0xf7, 0x0b, 0x1f, 0x33, 0x47, 0x5b, 0x6f,
];
const EXPECTED_CRATE_INNER_ATTRIBUTE_TOKENS: &[&str] =
    &["#", "!", "[", "forbid", "(", "unsafe_code", ")", "]"];
const EXPECTED_SESSION_PUBLIC_KEY_ID_STRUCT_TOKENS: &[&str] = &[
    "#",
    "[",
    "derive",
    "(",
    "Clone",
    ",",
    "Copy",
    ",",
    "PartialEq",
    ",",
    "Eq",
    ",",
    "Hash",
    ")",
    "]",
    "pub",
    "struct",
    "SessionPublicKeyId",
    "(",
    "[",
    "u8",
    ";",
    "SESSION_PUBLIC_KEY_ID_LENGTH",
    "]",
    ")",
    ";",
];
const EXPECTED_SESSION_PUBLIC_KEY_ID_IMPL_TOKENS: &[&str] = &[
    "impl",
    "SessionPublicKeyId",
    "{",
    "#",
    "[",
    "must_use",
    "]",
    "pub",
    "const",
    "fn",
    "from_bytes",
    "(",
    "bytes",
    ":",
    "[",
    "u8",
    ";",
    "SESSION_PUBLIC_KEY_ID_LENGTH",
    "]",
    ")",
    "-",
    ">",
    "Self",
    "{",
    "Self",
    "(",
    "bytes",
    ")",
    "}",
    "#",
    "[",
    "must_use",
    "]",
    "pub",
    "const",
    "fn",
    "as_bytes",
    "(",
    "&",
    "self",
    ")",
    "-",
    ">",
    "&",
    "[",
    "u8",
    ";",
    "SESSION_PUBLIC_KEY_ID_LENGTH",
    "]",
    "{",
    "&",
    "self",
    ".",
    "0",
    "}",
    "}",
];
const EXPECTED_SESSION_PUBLIC_KEY_ID_DEBUG_TOKENS: &[&str] = &[
    "impl",
    "fmt",
    ":",
    ":",
    "Debug",
    "for",
    "SessionPublicKeyId",
    "{",
    "fn",
    "fmt",
    "(",
    "&",
    "self",
    ",",
    "formatter",
    ":",
    "&",
    "mut",
    "fmt",
    ":",
    ":",
    "Formatter",
    "<",
    "'_",
    ">",
    ")",
    "-",
    ">",
    "fmt",
    ":",
    ":",
    "Result",
    "{",
    "formatter",
    ".",
    "write_str",
    "(",
    ")",
    "}",
    "}",
];

static NEXT_SOURCE_TREE_ID: AtomicU64 = AtomicU64::new(0);

struct TemporarySourceTree {
    root: PathBuf,
}

impl TemporarySourceTree {
    fn new() -> Self {
        let sequence = NEXT_SOURCE_TREE_ID.fetch_add(1, Ordering::Relaxed);
        let cargo_temp_root = fs::canonicalize(env!("CARGO_TARGET_TMPDIR"))
            .unwrap_or_else(|error| panic!("cannot canonicalize Cargo test directory: {error}"));
        let root = cargo_temp_root.join(format!(
            "ogir-model-source-inventory-{}-{sequence}",
            std::process::id()
        ));
        if let Err(error) = fs::create_dir(&root) {
            panic!("cannot create temporary source root: {error}");
        }
        let mut tree = Self { root };
        tree.root = canonical_descendant(&cargo_temp_root, &tree.root);
        tree
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn write(&self, relative: &str) {
        let relative = Path::new(relative);
        let components = relative.components().collect::<Vec<_>>();
        assert!(
            !components.is_empty()
                && components
                    .iter()
                    .all(|component| matches!(component, Component::Normal(_))),
            "temporary source path must contain only normal relative components"
        );
        let root_metadata = fs::symlink_metadata(&self.root)
            .unwrap_or_else(|error| panic!("cannot inspect temporary source root: {error}"));
        assert!(
            !root_metadata.file_type().is_symlink(),
            "temporary source root must not be a symlink"
        );
        assert!(
            root_metadata.is_dir(),
            "temporary source root must be a directory"
        );

        let (file_name, parent_components) = components
            .split_last()
            .unwrap_or_else(|| panic!("temporary source path has no file name"));
        let mut parent = self.root.clone();
        for component in parent_components {
            let candidate = parent.join(component.as_os_str());
            match fs::symlink_metadata(&candidate) {
                Ok(metadata) => {
                    assert!(
                        !metadata.file_type().is_symlink(),
                        "temporary source parent must not be a symlink"
                    );
                    assert!(
                        metadata.is_dir(),
                        "temporary source parent must be a directory"
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if let Err(error) = fs::create_dir(&candidate) {
                        panic!("cannot create temporary source parent: {error}");
                    }
                }
                Err(error) => panic!("cannot inspect temporary source parent: {error}"),
            }
            parent = canonical_descendant(&self.root, &candidate);
        }

        let path = parent.join(file_name.as_os_str());
        let path = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                assert!(
                    !metadata.file_type().is_symlink(),
                    "temporary source file must not be a symlink"
                );
                canonical_descendant(&self.root, &path)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => path,
            Err(error) => panic!("cannot inspect temporary source file: {error}"),
        };
        if let Err(error) = fs::write(&path, "// test fixture\n") {
            panic!("cannot write temporary source: {error}");
        }
    }
}

impl Drop for TemporarySourceTree {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.root) {
            panic!("cannot remove temporary source tree: {error}");
        }
    }
}

fn canonical_descendant(canonical_root: &Path, candidate: &Path) -> PathBuf {
    let canonical_candidate = fs::canonicalize(candidate)
        .unwrap_or_else(|error| panic!("cannot canonicalize source candidate: {error}"));
    assert!(
        canonical_candidate.starts_with(canonical_root),
        "canonical source candidate is outside the approved root"
    );
    canonical_candidate
}

fn rust_source_paths(root: &Path) -> Vec<PathBuf> {
    fn visit(root: &Path, directory: &Path, paths: &mut Vec<PathBuf>) {
        let directory = canonical_descendant(root, directory);
        let entries = fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("cannot read approved source directory: {error}"));

        for entry in entries {
            let entry =
                entry.unwrap_or_else(|error| panic!("cannot read source directory entry: {error}"));
            let file_type = entry
                .file_type()
                .unwrap_or_else(|error| panic!("cannot inspect source directory entry: {error}"));
            assert!(
                !file_type.is_symlink(),
                "model source inventory must not follow symlinks"
            );
            let entry_path = entry.path();

            if file_type.is_dir() {
                let directory = canonical_descendant(root, &entry_path);
                visit(root, &directory, paths);
            } else if file_type.is_file()
                && entry_path.extension().and_then(|value| value.to_str()) == Some("rs")
            {
                paths.push(canonical_descendant(root, &entry_path));
            }
        }
    }

    let root = fs::canonicalize(root)
        .unwrap_or_else(|error| panic!("cannot canonicalize source inventory root: {error}"));
    let mut paths = Vec::new();
    visit(&root, &root, &mut paths);
    paths.sort();
    paths
}

fn normalized_source(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
        .replace("\r\n", "\n")
}

fn model_source_texts() -> Vec<(PathBuf, String)> {
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    rust_source_paths(&source_root)
        .into_iter()
        .map(|path| {
            let source = normalized_source(&path);
            (path, source)
        })
        .collect()
}

fn raw_string_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut cursor = start;
    if matches!(bytes.get(cursor), Some(b'b' | b'c')) {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;

    let mut hashes = 0;
    while bytes.get(cursor) == Some(&b'#') {
        hashes += 1;
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    cursor += 1;

    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            let hashes_end = cursor + 1 + hashes;
            if hashes_end <= bytes.len()
                && bytes[cursor + 1..hashes_end]
                    .iter()
                    .all(|byte| *byte == b'#')
            {
                return Some(hashes_end);
            }
        }
        cursor += 1;
    }

    panic!("unterminated raw string beginning at byte {start}")
}

fn quoted_string_end(source: &str, quote: usize) -> usize {
    let bytes = source.as_bytes();
    let mut cursor = quote + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => cursor += 2,
            b'"' => return cursor + 1,
            _ => cursor += 1,
        }
    }
    panic!("unterminated string beginning at byte {quote}")
}

fn char_literal_end(source: &str, quote: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut cursor = quote + 1;
    let first = *bytes.get(cursor)?;

    if first == b'\\' {
        cursor += 1;
        match *bytes.get(cursor)? {
            b'x' => cursor += 3,
            b'u' => {
                cursor += 1;
                if bytes.get(cursor) != Some(&b'{') {
                    return None;
                }
                cursor += 1;
                while bytes.get(cursor) != Some(&b'}') {
                    cursor += 1;
                    if cursor >= bytes.len() {
                        return None;
                    }
                }
                cursor += 1;
            }
            _ => cursor += 1,
        }
    } else {
        let character = source[cursor..].chars().next()?;
        if matches!(character, '\'' | '\n' | '\r') {
            return None;
        }
        cursor += character.len_utf8();
    }

    (bytes.get(cursor) == Some(&b'\'')).then_some(cursor + 1)
}

fn is_rust_pattern_white_space(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'
            ..='\u{000d}'
                | '\u{0020}'
                | '\u{0085}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
    )
}

fn is_identifier_start(character: char) -> bool {
    !is_rust_pattern_white_space(character)
        && (character == '_' || character.is_ascii_alphabetic() || !character.is_ascii())
}

fn is_identifier_continue(character: char) -> bool {
    !is_rust_pattern_white_space(character)
        && (character == '_' || character.is_ascii_alphanumeric() || !character.is_ascii())
}

fn identifier_end(source: &str, start: usize) -> Option<usize> {
    let character = source.get(start..)?.chars().next()?;
    if !is_identifier_start(character) {
        return None;
    }

    let mut cursor = start + character.len_utf8();
    while cursor < source.len() {
        let next = source[cursor..].chars().next()?;
        if !is_identifier_continue(next) {
            break;
        }
        cursor += next.len_utf8();
    }
    Some(cursor)
}

fn normalize_identifier_for_target_comparison(identifier: &str) -> String {
    // Rust compares identifiers after NFC normalization. For this all-ASCII
    // target, UnicodeData's only singleton canonical decomposition to any
    // target code point is U+212A KELVIN SIGN -> U+004B LATIN CAPITAL LETTER K.
    // Compatibility-only K forms (for example U+FF2B) must remain distinct.
    identifier
        .chars()
        .map(|character| {
            if character == '\u{212a}' {
                'K'
            } else {
                character
            }
        })
        .collect()
}

fn literal_suffix_end(source: &str, literal_end: usize) -> usize {
    identifier_end(source, literal_end).unwrap_or(literal_end)
}

fn numeric_digit_run_end(bytes: &[u8], start: usize, radix: u8) -> usize {
    let mut cursor = start;
    while let Some(byte) = bytes.get(cursor) {
        let is_digit = match radix {
            2 => matches!(byte, b'0' | b'1'),
            8 => matches!(byte, b'0'..=b'7'),
            10 => byte.is_ascii_digit(),
            16 => byte.is_ascii_hexdigit(),
            _ => panic!("unsupported numeric literal radix {radix}"),
        };
        if !is_digit && *byte != b'_' {
            break;
        }
        cursor += 1;
    }
    cursor
}

fn decimal_exponent_end(bytes: &[u8], start: usize) -> Option<usize> {
    if !matches!(bytes.get(start), Some(b'e' | b'E')) {
        return None;
    }

    let mut cursor = start + 1;
    if matches!(bytes.get(cursor), Some(b'+' | b'-')) {
        cursor += 1;
    }
    let digits_start = cursor;
    cursor = numeric_digit_run_end(bytes, cursor, 10);
    bytes[digits_start..cursor]
        .iter()
        .any(u8::is_ascii_digit)
        .then_some(cursor)
}

fn trailing_float_dot_is_literal(source: &str, dot: usize) -> bool {
    source
        .get(dot + 1..)
        .and_then(|tail| tail.chars().next())
        .is_none_or(|next| next != '.' && next != '_' && !is_identifier_start(next))
}

fn numeric_literal_end(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let radix = if bytes.get(start) == Some(&b'0') {
        match bytes.get(start + 1) {
            Some(b'b') => Some(2),
            Some(b'o') => Some(8),
            Some(b'x') => Some(16),
            _ => None,
        }
    } else {
        None
    };

    if let Some(radix) = radix {
        let digits_end = numeric_digit_run_end(bytes, start + 2, radix);
        return literal_suffix_end(source, digits_end);
    }

    let mut cursor = numeric_digit_run_end(bytes, start, 10);
    if bytes.get(cursor) == Some(&b'.') {
        if bytes.get(cursor + 1).is_some_and(u8::is_ascii_digit) {
            cursor = numeric_digit_run_end(bytes, cursor + 1, 10);
            if let Some(exponent_end) = decimal_exponent_end(bytes, cursor) {
                cursor = exponent_end;
            }
            return literal_suffix_end(source, cursor);
        }
        if trailing_float_dot_is_literal(source, cursor) {
            return cursor + 1;
        }
    }

    if let Some(exponent_end) = decimal_exponent_end(bytes, cursor) {
        cursor = exponent_end;
    }
    literal_suffix_end(source, cursor)
}

fn raw_identifier(source: &str, start: usize) -> Option<(usize, String)> {
    if !source.as_bytes().get(start..)?.starts_with(b"r#") {
        return None;
    }
    let identifier_start = start + 2;
    let end = identifier_end(source, identifier_start)?;
    let normalized = normalize_identifier_for_target_comparison(&source[identifier_start..end]);
    let token = if matches!(
        normalized.as_str(),
        SESSION_PUBLIC_KEY_ID_NAME | "cfg_attr" | "include" | "path"
    ) {
        normalized
    } else {
        format!("r#{normalized}")
    };
    Some((end, token))
}

fn lifetime_or_label(source: &str, quote: usize) -> Option<(usize, String)> {
    let identifier_start = quote + 1;
    if source
        .as_bytes()
        .get(identifier_start..)?
        .starts_with(b"r#")
    {
        let raw_start = identifier_start + 2;
        let end = identifier_end(source, raw_start)?;
        return Some((end, source[quote..end].to_owned()));
    }

    let end = identifier_end(source, identifier_start)?;
    Some((end, source[quote..end].to_owned()))
}

fn rust_tokens(source: &str) -> Vec<String> {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0;

    while cursor < bytes.len() {
        let character = source[cursor..]
            .chars()
            .next()
            .unwrap_or_else(|| panic!("token cursor {cursor} is not on a character boundary"));
        if is_rust_pattern_white_space(character) {
            cursor += character.len_utf8();
            continue;
        }
        if bytes[cursor..].starts_with(b"//") {
            cursor += 2;
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
            continue;
        }
        if bytes[cursor..].starts_with(b"/*") {
            cursor += 2;
            let mut depth = 1_usize;
            while depth > 0 {
                if cursor >= bytes.len() {
                    panic!("unterminated block comment")
                }
                if bytes[cursor..].starts_with(b"/*") {
                    depth += 1;
                    cursor += 2;
                } else if bytes[cursor..].starts_with(b"*/") {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            continue;
        }
        if let Some(end) = raw_string_end(source, cursor) {
            cursor = literal_suffix_end(source, end);
            continue;
        }
        if bytes[cursor] == b'"' {
            cursor = literal_suffix_end(source, quoted_string_end(source, cursor));
            continue;
        }
        if matches!(bytes.get(cursor), Some(b'b' | b'c')) && bytes.get(cursor + 1) == Some(&b'"') {
            cursor = literal_suffix_end(source, quoted_string_end(source, cursor + 1));
            continue;
        }
        if bytes[cursor] == b'b' && bytes.get(cursor + 1) == Some(&b'\'') {
            let end = char_literal_end(source, cursor + 1)
                .unwrap_or_else(|| panic!("invalid byte character at byte {cursor}"));
            cursor = literal_suffix_end(source, end);
            continue;
        }
        if bytes[cursor] == b'\'' {
            if let Some(end) = char_literal_end(source, cursor) {
                cursor = literal_suffix_end(source, end);
            } else if let Some((end, lifetime)) = lifetime_or_label(source, cursor) {
                tokens.push(lifetime);
                cursor = end;
            } else {
                tokens.push("'".to_owned());
                cursor += 1;
            }
            continue;
        }
        if let Some((end, identifier)) = raw_identifier(source, cursor) {
            tokens.push(identifier);
            cursor = end;
            continue;
        }
        if is_identifier_start(character) {
            let end = identifier_end(source, cursor)
                .unwrap_or_else(|| panic!("identifier at byte {cursor} has no end"));
            tokens.push(normalize_identifier_for_target_comparison(
                &source[cursor..end],
            ));
            cursor = end;
            continue;
        }
        if bytes[cursor].is_ascii_digit() {
            let start = cursor;
            cursor = numeric_literal_end(source, cursor);
            tokens.push(source[start..cursor].to_owned());
            continue;
        }

        tokens.push(character.to_string());
        cursor += character.len_utf8();
    }

    tokens
}

fn matching_delimiter(tokens: &[String], open: usize) -> Option<usize> {
    if !matches!(tokens.get(open).map(String::as_str), Some("(" | "[" | "{")) {
        return None;
    }

    let mut expected_closes = Vec::new();
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token.as_str() {
            "(" => expected_closes.push(")"),
            "[" => expected_closes.push("]"),
            "{" => expected_closes.push("}"),
            ")" | "]" | "}" => {
                if expected_closes.pop() != Some(token.as_str()) {
                    return None;
                }
                if expected_closes.is_empty() {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn matching_square_bracket(tokens: &[String], open: usize) -> Option<usize> {
    (tokens.get(open).map(String::as_str) == Some("["))
        .then(|| matching_delimiter(tokens, open))
        .flatten()
}

fn delimiter_depths(tokens: &[String]) -> Result<Vec<usize>, String> {
    let mut expected_closes = Vec::new();
    let mut depths = Vec::with_capacity(tokens.len());

    for token in tokens {
        depths.push(expected_closes.len());
        match token.as_str() {
            "(" => expected_closes.push(")"),
            "[" => expected_closes.push("]"),
            "{" => expected_closes.push("}"),
            ")" | "]" | "}" if expected_closes.pop() != Some(token.as_str()) => {
                return Err(format!("mismatched delimiter before token {token}"));
            }
            ")" | "]" | "}" => {}
            _ => {}
        }
    }

    if expected_closes.is_empty() {
        Ok(depths)
    } else {
        Err(format!(
            "unclosed delimiter(s) expecting {expected_closes:?}"
        ))
    }
}

fn macro_token_tree_ranges(tokens: &[String]) -> Result<Vec<(usize, usize)>, String> {
    let mut ranges = Vec::new();

    for (bang, token) in tokens.iter().enumerate() {
        let macro_name = tokens.get(bang.wrapping_sub(1)).map(String::as_str);
        if token != "!"
            || macro_name == Some("#")
            || !macro_name.is_some_and(|name| name.chars().next().is_some_and(is_identifier_start))
        {
            continue;
        }

        let direct_open = bang + 1;
        let rules_open = bang + 2;
        let open = if matches!(
            tokens.get(direct_open).map(String::as_str),
            Some("(" | "[" | "{")
        ) {
            direct_open
        } else if macro_name == Some("macro_rules")
            && matches!(
                tokens.get(rules_open).map(String::as_str),
                Some("(" | "[" | "{")
            )
        {
            rules_open
        } else {
            continue;
        };

        let close = matching_delimiter(tokens, open)
            .ok_or_else(|| format!("macro token tree beginning at token {open} is unbalanced"))?;
        ranges.push((open, close));
    }

    Ok(ranges)
}

fn token_is_inside_ranges(index: usize, ranges: &[(usize, usize)]) -> bool {
    ranges
        .iter()
        .any(|(open, close)| *open < index && index < *close)
}

fn macro_definition_token_tree_ranges(
    tokens: &[String],
    macro_ranges: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    macro_ranges
        .iter()
        .copied()
        .filter(|(open, _)| {
            let Some(definition_start) = open.checked_sub(3) else {
                return false;
            };
            tokens.get(definition_start).map(String::as_str) == Some("macro_rules")
                && tokens.get(definition_start + 1).map(String::as_str) == Some("!")
                && tokens
                    .get(definition_start + 2)
                    .is_some_and(|name| name.chars().next().is_some_and(is_identifier_start))
                && !token_is_inside_ranges(definition_start, macro_ranges)
        })
        .collect()
}

fn token_is_macro_definition_metavariable(
    tokens: &[String],
    index: usize,
    macro_definition_ranges: &[(usize, usize)],
) -> bool {
    index > 0 && tokens[index - 1] == "$" && token_is_inside_ranges(index, macro_definition_ranges)
}

fn use_item_ranges(
    tokens: &[String],
    depths: &[usize],
    macro_ranges: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();

    for (start, token) in tokens.iter().enumerate() {
        if token != "use" || token_is_inside_ranges(start, macro_ranges) {
            continue;
        }
        let depth = depths[start];
        if let Some(end) = tokens
            .iter()
            .enumerate()
            .skip(start + 1)
            .find_map(|(index, token)| (token == ";" && depths[index] == depth).then_some(index))
        {
            ranges.push((start, end));
        }
    }

    ranges
}

fn token_is_inside_or_at_ranges(index: usize, ranges: &[(usize, usize)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| *start <= index && index <= *end)
}

fn skip_outer_attributes(tokens: &[String], mut cursor: usize) -> Option<usize> {
    while tokens.get(cursor).map(String::as_str) == Some("#")
        && tokens.get(cursor + 1).map(String::as_str) == Some("[")
    {
        cursor = matching_square_bracket(tokens, cursor + 1)? + 1;
    }
    Some(cursor)
}

fn skip_visibility(tokens: &[String], mut cursor: usize) -> Option<usize> {
    if tokens.get(cursor).map(String::as_str) != Some("pub") {
        return Some(cursor);
    }
    cursor += 1;
    if tokens.get(cursor).map(String::as_str) == Some("(") {
        cursor = matching_delimiter(tokens, cursor)? + 1;
    }
    Some(cursor)
}

fn top_level_meta_segments(tokens: &[String]) -> Vec<&[String]> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut depth = 0_usize;

    for (index, token) in tokens.iter().enumerate() {
        match token.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => depth = depth.saturating_sub(1),
            "," if depth == 0 => {
                segments.push(&tokens[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    segments.push(&tokens[start..]);
    segments
}

fn meta_item_can_emit_path_attribute(tokens: &[String]) -> bool {
    if tokens.first().map(String::as_str) == Some("path")
        && tokens.get(1).map(String::as_str) == Some("=")
    {
        return true;
    }
    if tokens.first().map(String::as_str) != Some("cfg_attr")
        || tokens.get(1).map(String::as_str) != Some("(")
    {
        return false;
    }
    let Some(close) = matching_delimiter(tokens, 1) else {
        return false;
    };
    if close + 1 != tokens.len() {
        return false;
    }

    top_level_meta_segments(&tokens[2..close])
        .into_iter()
        .skip(1)
        .any(meta_item_can_emit_path_attribute)
}

fn path_attribute_is_attached_to_module(tokens: &[String], attribute_close: usize) -> bool {
    let after_attributes = match skip_outer_attributes(tokens, attribute_close + 1) {
        Some(cursor) => cursor,
        None => return false,
    };
    let after_visibility = match skip_visibility(tokens, after_attributes) {
        Some(cursor) => cursor,
        None => return false,
    };
    tokens.get(after_visibility).map(String::as_str) == Some("mod")
}

fn validate_no_unscanned_item_sources(path: &Path, tokens: &[String]) -> Result<(), String> {
    // `include` is reserved only where it can name a macro or a namespace-
    // ambiguous import; ordinary functions and bindings remain valid. `path`
    // is reserved inside macro token trees because declarative expansion can
    // turn either a concrete token or a metavariable named `$path` into the
    // module-loading attribute. Outside macros, only a path meta-item attached
    // to `mod` is rejected.
    let depths = delimiter_depths(tokens)
        .map_err(|error| format!("cannot classify tokens in {}: {error}", path.display()))?;
    let macro_ranges = macro_token_tree_ranges(tokens)
        .map_err(|error| format!("cannot classify macros in {}: {error}", path.display()))?;
    let macro_definition_ranges = macro_definition_token_tree_ranges(tokens, &macro_ranges);
    let use_ranges = use_item_ranges(tokens, &depths, &macro_ranges);

    for (index, token) in tokens.iter().enumerate() {
        if token == "trait"
            && !token_is_macro_definition_metavariable(tokens, index, &macro_definition_ranges)
        {
            return Err(format!(
                "local trait declarations are forbidden by the exact SessionPublicKeyId surface policy in {}",
                path.display()
            ));
        }

        if token == "include"
            && (tokens.get(index + 1).map(String::as_str) == Some("!")
                || token_is_inside_or_at_ranges(index, &use_ranges)
                || (token_is_inside_ranges(index, &macro_ranges)
                    && !token_is_macro_definition_metavariable(
                        tokens,
                        index,
                        &macro_definition_ranges,
                    )))
        {
            return Err(format!(
                "unscanned item-source mechanism include macro/import identity is forbidden in {}",
                path.display()
            ));
        }

        if token == "path"
            && (tokens.get(index + 1).map(String::as_str) == Some("!")
                || token_is_inside_ranges(index, &macro_ranges))
        {
            return Err(format!(
                "unscanned item-source mechanism reserves path spelling in macro/meta context in {}",
                path.display()
            ));
        }
    }

    let mut cursor = 0;
    while cursor < tokens.len() {
        if tokens[cursor] != "#" {
            cursor += 1;
            continue;
        }

        let mut open = cursor + 1;
        if tokens.get(open).map(String::as_str) == Some("!") {
            open += 1;
        }
        if tokens.get(open).map(String::as_str) != Some("[") {
            cursor += 1;
            continue;
        }

        let close = matching_square_bracket(tokens, open).ok_or_else(|| {
            format!(
                "unbalanced attribute while checking item-source mechanisms in {}",
                path.display()
            )
        })?;
        if meta_item_can_emit_path_attribute(&tokens[open + 1..close])
            && path_attribute_is_attached_to_module(tokens, close)
        {
            return Err(format!(
                "unscanned item-source mechanism path meta-item is forbidden in {}",
                path.display()
            ));
        }
        cursor = close + 1;
    }

    Ok(())
}

fn attached_attributes_start(tokens: &[String], item_start: usize) -> usize {
    let mut start = item_start;
    while start > 0 && tokens[start - 1] == "]" {
        let mut cursor = start - 1;
        let mut depth = 1_usize;
        while cursor > 0 && depth > 0 {
            cursor -= 1;
            match tokens[cursor].as_str() {
                "]" => depth += 1,
                "[" => depth -= 1,
                _ => {}
            }
        }
        if depth != 0 || cursor == 0 || tokens[cursor - 1] != "#" {
            break;
        }
        start = cursor - 1;
    }
    start
}

fn semicolon_item_end(tokens: &[String], start: usize) -> Option<usize> {
    let mut delimiters = Vec::new();
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token.as_str() {
            "(" | "[" | "{" => delimiters.push(token.as_str()),
            ")" => {
                if delimiters.pop() != Some("(") {
                    return None;
                }
            }
            "]" => {
                if delimiters.pop() != Some("[") {
                    return None;
                }
            }
            "}" => {
                if delimiters.pop() != Some("{") {
                    return None;
                }
            }
            ";" if delimiters.is_empty() => return Some(index + 1),
            _ => {}
        }
    }
    None
}

fn braced_item_end(tokens: &[String], start: usize) -> Option<usize> {
    let brace = tokens
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, token)| (token == "{").then_some(index))?;
    let mut depth = 0_usize;
    for (index, token) in tokens.iter().enumerate().skip(brace) {
        match token.as_str() {
            "{" => depth += 1,
            "}" => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn exact_tokens_match(actual: &[String], expected: &[&str]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == expected)
}

fn root_token_sequence_starts(
    tokens: &[String],
    depths: &[usize],
    sequence: &[&str],
) -> Vec<usize> {
    tokens
        .windows(sequence.len())
        .enumerate()
        .filter(|(start, window)| {
            depths[*start] == 0
                && window
                    .iter()
                    .zip(sequence)
                    .all(|(actual, expected)| actual == expected)
        })
        .map(|(start, _)| start)
        .collect()
}

fn attribute_ranges(tokens: &[String]) -> Result<Vec<(usize, usize)>, String> {
    let mut ranges = Vec::new();
    let mut cursor = 0;

    while cursor < tokens.len() {
        if tokens[cursor] != "#" {
            cursor += 1;
            continue;
        }
        let mut open = cursor + 1;
        if tokens.get(open).map(String::as_str) == Some("!") {
            open += 1;
        }
        if tokens.get(open).map(String::as_str) != Some("[") {
            cursor += 1;
            continue;
        }
        let close = matching_square_bracket(tokens, open)
            .ok_or_else(|| format!("attribute beginning at token {cursor} is unbalanced"))?;
        ranges.push((cursor, close));
        cursor = close + 1;
    }

    Ok(ranges)
}

fn validate_crate_inner_attribute_surface(
    tokens: &[String],
    depths: &[usize],
) -> Result<(), String> {
    let mut inner_attributes = Vec::new();

    for (start, token) in tokens.iter().enumerate() {
        if token != "#"
            || depths[start] != 0
            || tokens.get(start + 1).map(String::as_str) != Some("!")
            || tokens.get(start + 2).map(String::as_str) != Some("[")
        {
            continue;
        }
        let close = matching_square_bracket(tokens, start + 2)
            .ok_or_else(|| "crate inner attribute is unbalanced".to_owned())?;
        inner_attributes.push(&tokens[start..=close]);
    }

    if inner_attributes.len() != 1
        || !exact_tokens_match(inner_attributes[0], EXPECTED_CRATE_INNER_ATTRIBUTE_TOKENS)
    {
        return Err(format!(
            "crate inner attribute inventory must contain only #![forbid(unsafe_code)]; found {inner_attributes:?}"
        ));
    }

    Ok(())
}

fn token_is_macro_definition_name(
    tokens: &[String],
    index: usize,
    macro_definition_ranges: &[(usize, usize)],
) -> bool {
    index >= 2
        && tokens[index - 2] == "macro_rules"
        && tokens[index - 1] == "!"
        && macro_definition_ranges
            .iter()
            .any(|(open, _)| index + 1 == *open)
}

fn token_is_in_braced_item_header(
    tokens: &[String],
    depths: &[usize],
    macro_ranges: &[(usize, usize)],
    index: usize,
    keyword: &str,
) -> bool {
    tokens
        .iter()
        .enumerate()
        .take(index)
        .filter(|(start, token)| {
            token.as_str() == keyword && !token_is_inside_ranges(*start, macro_ranges)
        })
        .any(|(start, _)| {
            let depth = depths[start];
            tokens
                .iter()
                .enumerate()
                .skip(start + 1)
                .find_map(|(cursor, token)| {
                    (token == "{" && depths[cursor] == depth).then_some(cursor)
                })
                .is_some_and(|body| index < body)
        })
}

fn token_is_in_type_item(
    tokens: &[String],
    depths: &[usize],
    macro_ranges: &[(usize, usize)],
    index: usize,
) -> bool {
    tokens
        .iter()
        .enumerate()
        .take(index)
        .filter(|(start, token)| {
            token.as_str() == "type" && !token_is_inside_ranges(*start, macro_ranges)
        })
        .any(|(start, _)| {
            let depth = depths[start];
            tokens
                .iter()
                .enumerate()
                .skip(start + 1)
                .find_map(|(cursor, token)| {
                    (token == ";" && depths[cursor] == depth).then_some(cursor)
                })
                .is_some_and(|end| index < end)
        })
}

#[derive(Clone, Copy)]
struct TargetValueBinding {
    name_index: usize,
    available_after: usize,
    scope: Option<(usize, usize)>,
}

fn brace_scope_ranges(tokens: &[String]) -> Vec<(usize, usize)> {
    tokens
        .iter()
        .enumerate()
        .filter_map(|(open, token)| {
            (token == "{")
                .then(|| matching_delimiter(tokens, open).map(|close| (open, close)))
                .flatten()
        })
        .collect()
}

fn innermost_brace_scope(scopes: &[(usize, usize)], index: usize) -> Option<(usize, usize)> {
    scopes
        .iter()
        .copied()
        .filter(|(open, close)| *open < index && index < *close)
        .min_by_key(|(open, close)| close - open)
}

fn simple_value_declaration_kind(tokens: &[String], index: usize) -> Option<&'static str> {
    match tokens.get(index.wrapping_sub(1)).map(String::as_str) {
        Some("fn" | "const" | "static") => Some("item"),
        Some("let") => Some("let"),
        Some("mut") if index >= 2 && tokens.get(index - 2).map(String::as_str) == Some("let") => {
            Some("let")
        }
        _ => None,
    }
}

fn target_value_bindings(
    tokens: &[String],
    depths: &[usize],
    macro_ranges: &[(usize, usize)],
) -> Vec<TargetValueBinding> {
    let scopes = brace_scope_ranges(tokens);
    let mut bindings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        if token != SESSION_PUBLIC_KEY_ID_NAME || token_is_inside_ranges(index, macro_ranges) {
            continue;
        }
        let Some(kind) = simple_value_declaration_kind(tokens, index) else {
            continue;
        };
        let available_after = if kind == "item" {
            0
        } else {
            let depth = depths[index];
            match tokens
                .iter()
                .enumerate()
                .skip(index + 1)
                .find_map(|(cursor, token)| {
                    (token == ";" && depths[cursor] == depth).then_some(cursor)
                }) {
                Some(semicolon) => semicolon,
                None => index,
            }
        };
        bindings.push(TargetValueBinding {
            name_index: index,
            available_after,
            scope: innermost_brace_scope(&scopes, index),
        });
    }

    bindings
}

fn target_is_shadowed_value_use(bindings: &[TargetValueBinding], index: usize) -> bool {
    bindings.iter().any(|binding| {
        index > binding.available_after
            && binding
                .scope
                .is_none_or(|(open, close)| open < index && index < close)
    })
}

fn target_use_reservation_reason(
    tokens: &[String],
    depths: &[usize],
    macro_ranges: &[(usize, usize)],
    macro_definition_ranges: &[(usize, usize)],
    attribute_ranges: &[(usize, usize)],
    value_bindings: &[TargetValueBinding],
    index: usize,
) -> Option<&'static str> {
    // The proof can recognize harmless macro declaration/metavariable names
    // and simple fn/const/static/let value bindings with lexical scope. Every
    // concrete macro use and every ambiguous unshadowed spelling stays
    // reserved: it might be the tuple constructor, a constructor pattern, or
    // a type/associated-item path even when inference hides the return type.
    if token_is_macro_definition_name(tokens, index, macro_definition_ranges) {
        return None;
    }
    if token_is_macro_definition_metavariable(tokens, index, macro_definition_ranges) {
        return None;
    }
    if token_is_inside_ranges(index, macro_ranges)
        || tokens.get(index + 1).map(String::as_str) == Some("!")
    {
        return Some("concrete target spelling in macro expansion context");
    }
    if token_is_inside_or_at_ranges(index, attribute_ranges) {
        return Some("target spelling in attribute expansion context");
    }
    if tokens.get(index + 1).map(String::as_str) == Some(":") {
        return Some("associated item or type path");
    }
    if token_is_in_braced_item_header(tokens, depths, macro_ranges, index, "impl") {
        return Some("noncanonical impl header");
    }
    if token_is_in_type_item(tokens, depths, macro_ranges, index) {
        return Some("type alias or associated type item");
    }
    if matches!(
        tokens.get(index.wrapping_sub(1)).map(String::as_str),
        Some("struct" | "enum" | "union" | "mod")
    ) {
        return Some("noncanonical type-namespace declaration");
    }
    if tokens.get(index.wrapping_sub(1)).map(String::as_str) != Some("fn")
        && token_is_in_braced_item_header(tokens, depths, macro_ranges, index, "fn")
    {
        return Some("function signature type use");
    }
    if matches!(
        tokens.get(index.wrapping_sub(1)).map(String::as_str),
        Some(":" | "as" | "for")
    ) {
        return Some("type-path context");
    }
    if value_bindings
        .iter()
        .any(|binding| binding.name_index == index)
        || target_is_shadowed_value_use(value_bindings, index)
    {
        return None;
    }

    Some("ambiguous unshadowed value/type spelling")
}

fn validate_session_public_key_id_token_surface(
    sources: &[(PathBuf, String)],
) -> Result<(), String> {
    let declaration = ["pub", "struct", "SessionPublicKeyId", "("];
    let inherent_impl = ["impl", "SessionPublicKeyId", "{"];
    let debug_impl = [
        "impl",
        "fmt",
        ":",
        ":",
        "Debug",
        "for",
        "SessionPublicKeyId",
        "{",
    ];
    let mut tokenized_sources = Vec::new();
    let mut primary_index = None;

    for (path, source) in sources {
        let tokens = rust_tokens(source);
        validate_no_unscanned_item_sources(path, &tokens)?;
        if path.ends_with("src/lib.rs") && primary_index.replace(tokenized_sources.len()).is_some()
        {
            return Err("model source inventory contains multiple src/lib.rs files".to_owned());
        }
        tokenized_sources.push((path, tokens));
    }

    let primary_index = match primary_index {
        Some(index) => index,
        None => return Err("model source inventory omitted src/lib.rs".to_owned()),
    };
    let primary_tokens = &tokenized_sources[primary_index].1;
    let primary_depths = delimiter_depths(primary_tokens)
        .map_err(|error| format!("cannot classify primary source tokens: {error}"))?;
    validate_crate_inner_attribute_surface(primary_tokens, &primary_depths)?;

    let declaration_roots =
        root_token_sequence_starts(primary_tokens, &primary_depths, &declaration);
    let inherent_roots =
        root_token_sequence_starts(primary_tokens, &primary_depths, &inherent_impl);
    let debug_roots = root_token_sequence_starts(primary_tokens, &primary_depths, &debug_impl);
    if declaration_roots.len() != 1 || inherent_roots.len() != 1 || debug_roots.len() != 1 {
        return Err(format!(
            "SessionPublicKeyId token inventory requires its three canonical anchors to be direct root production items; found {} declaration, {} inherent impl, and {} Debug impl root anchor(s)",
            declaration_roots.len(),
            inherent_roots.len(),
            debug_roots.len()
        ));
    }

    let canonical_target_indices = [
        declaration_roots[0] + 2,
        inherent_roots[0] + 1,
        debug_roots[0] + 6,
    ];
    let mut reserved_uses = Vec::new();
    for (source_index, (path, tokens)) in tokenized_sources.iter().enumerate() {
        let depths = delimiter_depths(tokens)
            .map_err(|error| format!("cannot classify {}: {error}", path.display()))?;
        let macro_ranges = macro_token_tree_ranges(tokens)
            .map_err(|error| format!("cannot classify macros in {}: {error}", path.display()))?;
        let macro_definition_ranges = macro_definition_token_tree_ranges(tokens, &macro_ranges);
        let attributes = attribute_ranges(tokens).map_err(|error| {
            format!("cannot classify attributes in {}: {error}", path.display())
        })?;
        let value_bindings = target_value_bindings(tokens, &depths, &macro_ranges);

        for (index, token) in tokens.iter().enumerate() {
            if token != SESSION_PUBLIC_KEY_ID_NAME
                || (source_index == primary_index && canonical_target_indices.contains(&index))
            {
                continue;
            }
            if let Some(reason) = target_use_reservation_reason(
                tokens,
                &depths,
                &macro_ranges,
                &macro_definition_ranges,
                &attributes,
                &value_bindings,
                index,
            ) {
                let start = index.saturating_sub(5);
                let end = usize::min(index + 6, tokens.len());
                reserved_uses.push(format!(
                    "{} ({reason}): {}",
                    path.display(),
                    tokens[start..end].join(" ")
                ));
            }
        }
    }
    if !reserved_uses.is_empty() {
        return Err(format!(
            "SessionPublicKeyId token inventory permits only the three canonical type anchors, harmless value-namespace roles, macro declaration names, and macro metavariables; reserved use(s): {reserved_uses:?}"
        ));
    }

    let declaration_start = attached_attributes_start(primary_tokens, declaration_roots[0]);
    let declaration_end = match semicolon_item_end(primary_tokens, declaration_start) {
        Some(end) => end,
        None => return Err("struct exact token sequence has no valid item end".to_owned()),
    };
    let actual_declaration = &primary_tokens[declaration_start..declaration_end];
    if !exact_tokens_match(
        actual_declaration,
        EXPECTED_SESSION_PUBLIC_KEY_ID_STRUCT_TOKENS,
    ) {
        return Err(format!(
            "struct exact token sequence mismatch; expected {:?}, found {actual_declaration:?}",
            EXPECTED_SESSION_PUBLIC_KEY_ID_STRUCT_TOKENS
        ));
    }

    let inherent_start = attached_attributes_start(primary_tokens, inherent_roots[0]);
    let inherent_end = match braced_item_end(primary_tokens, inherent_start) {
        Some(end) => end,
        None => return Err("inherent impl exact token sequence has no valid item end".to_owned()),
    };
    let actual_inherent = &primary_tokens[inherent_start..inherent_end];
    if !exact_tokens_match(actual_inherent, EXPECTED_SESSION_PUBLIC_KEY_ID_IMPL_TOKENS) {
        return Err(format!(
            "inherent impl exact token sequence mismatch; expected {:?}, found {actual_inherent:?}",
            EXPECTED_SESSION_PUBLIC_KEY_ID_IMPL_TOKENS
        ));
    }

    let debug_start = attached_attributes_start(primary_tokens, debug_roots[0]);
    let debug_end = match braced_item_end(primary_tokens, debug_start) {
        Some(end) => end,
        None => return Err("Debug impl exact token sequence has no valid item end".to_owned()),
    };
    let actual_debug = &primary_tokens[debug_start..debug_end];
    if !exact_tokens_match(actual_debug, EXPECTED_SESSION_PUBLIC_KEY_ID_DEBUG_TOKENS) {
        return Err(format!(
            "Debug impl exact token sequence mismatch; expected {:?}, found {actual_debug:?}",
            EXPECTED_SESSION_PUBLIC_KEY_ID_DEBUG_TOKENS
        ));
    }

    Ok(())
}

fn value_hash(value: SessionPublicKeyId) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn exact_length_and_round_trip_are_fixed() {
    assert_eq!(
        SESSION_PUBLIC_KEY_ID_LENGTH,
        EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH
    );
    let identifier = SessionPublicKeyId::from_bytes(PRIVATE_SENTINEL);
    assert_eq!(identifier.as_bytes(), &PRIVATE_SENTINEL);
}

#[test]
fn every_fixed_whole_value_control_is_representable() {
    let mut alternating = [0_u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH];
    for (position, byte) in alternating.iter_mut().enumerate() {
        *byte = if position % 2 == 0 { 0x55 } else { 0xaa };
    }

    let mut ascending = [0_u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH];
    let mut descending = [0_u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH];
    for value in 0_u8..32 {
        ascending[usize::from(value)] = value;
        descending[usize::from(value)] = 31 - value;
    }

    for bytes in [
        [0_u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH],
        [u8::MAX; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH],
        alternating,
        ascending,
        descending,
    ] {
        assert_eq!(SessionPublicKeyId::from_bytes(bytes).as_bytes(), &bytes);
    }
}

#[test]
fn copy_equality_inequality_and_hashing_are_plain_value_semantics() {
    let first = SessionPublicKeyId::from_bytes(PRIVATE_SENTINEL);
    let same = first;
    let mut changed = PRIVATE_SENTINEL;
    changed[17] ^= 0xff;
    let different = SessionPublicKeyId::from_bytes(changed);

    assert_eq!(first, same);
    assert_ne!(first, different);
    assert_eq!(value_hash(first), value_hash(same));

    let mut values = HashSet::new();
    assert!(values.insert(first));
    assert!(!values.insert(same));
    assert!(values.insert(different));
    assert_eq!(values.len(), 2);
}

#[test]
fn all_8192_position_value_cases_round_trip_without_normalization() {
    let mut case_count = 0_usize;

    for position in 0..EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH {
        for value in u8::MIN..=u8::MAX {
            let mut bytes = PRIVATE_SENTINEL;
            bytes[position] = value;
            let identifier = SessionPublicKeyId::from_bytes(bytes);
            let copied = identifier;

            assert_eq!(identifier.as_bytes(), &bytes);
            assert_eq!(copied, identifier);
            assert_eq!(value_hash(copied), value_hash(identifier));
            assert_eq!(
                format!("{identifier:?}"),
                "SessionPublicKeyId([REDACTED; 32])"
            );
            case_count += 1;
        }
    }

    assert_eq!(case_count, 8_192);
}

#[test]
fn debug_is_exact_fixed_redaction_for_real_sentinel_bytes() {
    let identifier = SessionPublicKeyId::from_bytes(PRIVATE_SENTINEL);
    let diagnostic = format!("{identifier:?}");
    let raw = format!("{PRIVATE_SENTINEL:?}");

    assert_eq!(diagnostic, "SessionPublicKeyId([REDACTED; 32])");
    assert!(!diagnostic.contains(&raw));
    assert!(!diagnostic.contains("0x"));
}

#[test]
fn runtime_type_identity_is_distinct_from_nonce_and_session_id() {
    let identifier_type = TypeId::of::<SessionPublicKeyId>();
    assert_ne!(identifier_type, TypeId::of::<Nonce>());
    assert_ne!(identifier_type, TypeId::of::<SessionId>());
}

#[test]
fn rust_source_inventory_recurses_into_future_nested_modules() {
    let tree = TemporarySourceTree::new();
    tree.write("lib.rs");
    tree.write("flat.rs");
    tree.write("nested/deeper/module.rs");
    tree.write("nested/deeper/extra.inc");
    tree.write("nested/ignored.txt");

    let relative_paths = rust_source_paths(tree.path())
        .into_iter()
        .map(|path| match path.strip_prefix(tree.path()) {
            Ok(relative) => relative.to_path_buf(),
            Err(error) => panic!(
                "collected source {} escaped {}: {error}",
                path.display(),
                tree.path().display()
            ),
        })
        .collect::<Vec<_>>();

    assert_eq!(
        relative_paths,
        [
            PathBuf::from("flat.rs"),
            PathBuf::from("lib.rs"),
            PathBuf::from("nested/deeper/module.rs"),
        ]
    );
}

#[test]
fn temporary_source_tree_rejects_non_normal_write_before_access() {
    let tree = TemporarySourceTree::new();
    let outside_tree = TemporarySourceTree::new();
    let outside_name = outside_tree
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| panic!("temporary source tree name is not valid UTF-8"));
    let escaped_path = outside_tree.path().join("escaped.rs");
    let relative = format!("../{outside_name}/escaped.rs");

    let rejection = std::panic::catch_unwind(|| tree.write(&relative));

    assert!(
        rejection.is_err() && !escaped_path.exists(),
        "non-normal source path was not rejected before write access: rejected={}, outside_exists={}",
        rejection.is_err(),
        escaped_path.exists()
    );
}

#[test]
fn temporary_source_tree_rejects_parent_symlink_before_creating_outside_directory() {
    let tree = TemporarySourceTree::new();
    let outside_tree = TemporarySourceTree::new();
    std::os::unix::fs::symlink(outside_tree.path(), tree.path().join("nested"))
        .unwrap_or_else(|error| panic!("cannot create parent-symlink fixture: {error}"));
    let outside_directory = outside_tree.path().join("new");

    let rejection = std::panic::catch_unwind(|| tree.write("nested/new/file.rs"));

    assert!(
        rejection.is_err() && !outside_directory.exists(),
        "parent symlink was not rejected before directory creation: rejected={}, outside_exists={}",
        rejection.is_err(),
        outside_directory.exists()
    );
}

#[test]
fn temporary_source_tree_rejects_final_symlink_before_modifying_outside_file() {
    let tree = TemporarySourceTree::new();
    let outside_tree = TemporarySourceTree::new();
    let outside_file = outside_tree.path().join("outside.rs");
    let original = "outside sentinel\n";
    fs::write(&outside_file, original)
        .unwrap_or_else(|error| panic!("cannot create outside-file fixture: {error}"));
    std::os::unix::fs::symlink(&outside_file, tree.path().join("file.rs"))
        .unwrap_or_else(|error| panic!("cannot create final-symlink fixture: {error}"));

    let rejection = std::panic::catch_unwind(|| tree.write("file.rs"));
    let outside_contents = fs::read_to_string(&outside_file)
        .unwrap_or_else(|error| panic!("cannot read outside-file fixture: {error}"));

    assert!(
        rejection.is_err() && outside_contents == original,
        "final symlink was not rejected before write: rejected={}, outside_modified={}",
        rejection.is_err(),
        outside_contents != original
    );
}

#[test]
fn temporary_source_tree_rejects_replaced_root_symlink_before_writing_outside_tree() {
    let tree = TemporarySourceTree::new();
    let outside_tree = TemporarySourceTree::new();
    fs::remove_dir(tree.path())
        .unwrap_or_else(|error| panic!("cannot remove owned-root fixture: {error}"));
    std::os::unix::fs::symlink(outside_tree.path(), tree.path())
        .unwrap_or_else(|error| panic!("cannot create root-symlink fixture: {error}"));
    let outside_file = outside_tree.path().join("new/file.rs");

    let rejection = std::panic::catch_unwind(|| tree.write("new/file.rs"));

    assert!(
        rejection.is_err() && !outside_file.exists(),
        "replaced root symlink was not rejected before outside write: rejected={}, outside_exists={}",
        rejection.is_err(),
        outside_file.exists()
    );
}

#[test]
fn canonical_descendant_rejects_path_from_another_owned_tree() {
    let tree = TemporarySourceTree::new();
    let outside_tree = TemporarySourceTree::new();

    let rejection =
        std::panic::catch_unwind(|| canonical_descendant(tree.path(), outside_tree.path()));

    assert!(
        rejection.is_err(),
        "canonical source path outside the approved root was accepted"
    );
}

#[test]
fn rust_lexer_ignores_comments_and_literals_but_preserves_real_tokens() {
    let source = r####"
// impl SessionPublicKeyId { line comment decoy }
/* outer impl SessionPublicKeyId {
   /* nested impl SessionPublicKeyId { block comment decoy } */
} */
"impl SessionPublicKeyId { normal string decoy }"
b"impl SessionPublicKeyId { byte string decoy }"
r###"impl SessionPublicKeyId { raw string decoy }"###
br##"impl SessionPublicKeyId { raw byte string decoy }"##
'i'
b'i'
impl/**/ SessionPublicKeyId {}
"####;

    assert_eq!(
        rust_tokens(source),
        ["impl", "SessionPublicKeyId", "{", "}"]
    );
    assert_eq!(
        rust_tokens("fn borrow<'a>(value: &'a str) {}"),
        [
            "fn", "borrow", "<", "'a", ">", "(", "value", ":", "&", "'a", "str", ")", "{", "}",
        ]
    );
    assert_eq!(
        rust_tokens("struct SessionPublicKeyIdé;"),
        ["struct", "SessionPublicKeyIdé", ";"]
    );
}

#[test]
fn target_identifier_matching_follows_rust_nfc_without_compatibility_folding() {
    assert_eq!(
        rust_tokens("impl SessionPublicKeyId {}"),
        ["impl", "SessionPublicKeyId", "{", "}"],
        "U+212A KELVIN SIGN is canonically equivalent to ASCII K under Rust NFC"
    );
    assert_eq!(
        rust_tokens("impl r#SessionPublicKeyId {}"),
        ["impl", "SessionPublicKeyId", "{", "}"],
        "raw identifiers obey the same NFC comparison"
    );

    for distinct in [
        "SessionPublicＫeyId",
        "SessionPublicKeyIdé",
        "SessionPublicKeyIde\u{0301}",
        "SessionPublicKeyIdé",
    ] {
        assert_ne!(
            rust_tokens(distinct),
            ["SessionPublicKeyId"],
            "compatibility forms and Unicode suffixes must remain distinct: {distinct}"
        );
    }
}

#[test]
fn rust_lexer_strips_the_optional_leading_source_bom() {
    assert_eq!(
        rust_tokens("\u{feff}include!(\"extra.inc\");"),
        ["include", "!", "(", ")", ";"],
        "rustc strips a leading UTF-8 BOM before tokenization"
    );
}

#[test]
fn valid_literal_suffixes_are_consumed_with_the_literal_token() {
    let tokens = rust_tokens(
        r####"
macro_rules! discard_literals { ($($literal:literal),* $(,)?) => {}; }
discard_literals!(
    "normal"SessionPublicKeyId,
    b"byte"SessionPublicKeyId,
    c"c"SessionPublicKeyId,
    r"raw"SessionPublicKeyId,
    br"raw-byte"SessionPublicKeyId,
    cr"raw-c"SessionPublicKeyId,
    'x'SessionPublicKeyId,
    b'x'SessionPublicKeyId,
    1SessionPublicKeyId,
    "kelvin"SessionPublicKeyId,
);
"####,
    );

    assert_eq!(
        tokens
            .iter()
            .filter(|token| token.as_str() == "SessionPublicKeyId")
            .count(),
        0,
        "a literal suffix is part of the literal token, not a target identifier: {tokens:?}"
    );
}

#[test]
fn numeric_literal_tokens_stop_before_ranges_and_field_access() {
    for (source, expected) in [
        (
            "1..SessionPublicKeyId",
            vec!["1", ".", ".", "SessionPublicKeyId"],
        ),
        (
            "1..=SessionPublicKeyId",
            vec!["1", ".", ".", "=", "SessionPublicKeyId"],
        ),
        ("1.SessionPublicKeyId", vec!["1", ".", "SessionPublicKeyId"]),
        ("1._field", vec!["1", ".", "_field"]),
        (
            "1.0..SessionPublicKeyId",
            vec!["1.0", ".", ".", "SessionPublicKeyId"],
        ),
        (
            "1.0e+2f64..SessionPublicKeyId",
            vec!["1.0e+2f64", ".", ".", "SessionPublicKeyId"],
        ),
        (
            "1e2..SessionPublicKeyId",
            vec!["1e2", ".", ".", "SessionPublicKeyId"],
        ),
        (
            "1E+2..SessionPublicKeyId",
            vec!["1E+2", ".", ".", "SessionPublicKeyId"],
        ),
        (
            "0b101..SessionPublicKeyId",
            vec!["0b101", ".", ".", "SessionPublicKeyId"],
        ),
        (
            "0o71..SessionPublicKeyId",
            vec!["0o71", ".", ".", "SessionPublicKeyId"],
        ),
        (
            "0x2f..SessionPublicKeyId",
            vec!["0x2f", ".", ".", "SessionPublicKeyId"],
        ),
        (
            "1u8..SessionPublicKeyId",
            vec!["1u8", ".", ".", "SessionPublicKeyId"],
        ),
        (
            "0x2fu8..SessionPublicKeyId",
            vec!["0x2fu8", ".", ".", "SessionPublicKeyId"],
        ),
        ("1.éclair", vec!["1", ".", "éclair"]),
    ] {
        assert_eq!(rust_tokens(source), expected, "numeric boundary: {source}");
    }
}

#[test]
fn numeric_literal_tokens_preserve_suffixes_and_float_dot_rules() {
    assert_eq!(
        rust_tokens("1u8 1_0usize 0b101u8 0o71i16 0x2fu32 1.0f64 1e2f32 1E+2f64"),
        [
            "1u8", "1_0usize", "0b101u8", "0o71i16", "0x2fu32", "1.0f64", "1e2f32", "1E+2f64",
        ]
    );
    assert_eq!(rust_tokens("2."), ["2."]);
    assert_eq!(rust_tokens("2.f64"), ["2", ".", "f64"]);
    assert_eq!(rust_tokens("2.0f64"), ["2.0f64"]);
}

#[test]
fn numeric_range_macros_cannot_hide_source_policy_tokens() {
    let mut bypasses = Vec::new();
    for (label, extra_source, expected_diagnostic) in [
        (
            "target type",
            "macro_rules! attach { ($number:literal .. $target:ty) => { impl $target { fn hidden(&self) {} } }; } attach!(1..SessionPublicKeyId);",
            "SessionPublicKeyId token inventory",
        ),
        (
            "path meta-item",
            "macro_rules! load { ($number:literal .. $attribute:ident) => { #[$attribute = \"extra.inc\"] mod injected; }; } load!(1..path);",
            "unscanned item-source mechanism",
        ),
        (
            "include identity",
            "macro_rules! load { ($number:literal .. $name:ident) => { $name!(\"extra.inc\"); }; } load!(1..include);",
            "unscanned item-source mechanism",
        ),
        (
            "trait keyword",
            "macro_rules! declare { ($number:literal .. $keyword:ident) => { $keyword AdmitExt { fn admit(&self) {} } impl<T> AdmitExt for T {} }; } declare!(1..trait);",
            "local trait declarations are forbidden",
        ),
    ] {
        let mut sources = model_source_texts();
        sources.push((
            PathBuf::from("numeric_range_macro.rs"),
            extra_source.to_owned(),
        ));
        match validate_session_public_key_id_token_surface(&sources) {
            Ok(()) => bypasses.push(label),
            Err(error) => assert!(
                error.contains(expected_diagnostic),
                "{label} failed for an unrelated reason: {error}"
            ),
        }
    }
    assert!(
        bypasses.is_empty(),
        "numeric-range macro inputs bypassed source policy: {bypasses:?}"
    );
}

#[test]
fn rust_lexer_uses_exact_rust_pattern_white_space() {
    let pattern_white_space = [
        '\u{0009}', '\u{000a}', '\u{000b}', '\u{000c}', '\u{000d}', '\u{0020}', '\u{0085}',
        '\u{200e}', '\u{200f}', '\u{2028}', '\u{2029}',
    ];

    for separator in pattern_white_space {
        assert_eq!(
            rust_tokens(&format!("impl{separator}SessionPublicKeyId {{}}")),
            ["impl", "SessionPublicKeyId", "{", "}"],
            "Rust Pattern_White_Space U+{:04X} did not separate tokens",
            u32::from(separator)
        );
    }

    for non_separator in ['\u{0008}', '\u{000e}', '\u{00a0}', '\u{200b}', '\u{202a}'] {
        assert_ne!(
            rust_tokens(&format!("impl{non_separator}SessionPublicKeyId {{}}")),
            ["impl", "SessionPublicKeyId", "{", "}"],
            "non-Pattern_White_Space U+{:04X} separated tokens",
            u32::from(non_separator)
        );
    }
}

#[test]
fn rust_lexer_distinguishes_ordinary_and_raw_lifetimes_and_labels() {
    assert_eq!(
        rust_tokens("r#SessionPublicKeyId r#cfg_attr r#include r#path"),
        ["SessionPublicKeyId", "cfg_attr", "include", "path"],
        "raw identifiers must normalize before surface and source-injection checks"
    );
    assert_eq!(
        rust_tokens("fn r#trait() {}"),
        ["fn", "r#trait", "(", ")", "{", "}"],
        "unrelated raw keywords must retain raw-identifier identity"
    );

    let tokens = rust_tokens(
        "fn borrow<'SessionPublicKeyId, 'r#SessionPublicKeyId>(\
         first: &'SessionPublicKeyId str, second: &'r#SessionPublicKeyId str) {\
         'SessionPublicKeyId: loop { break 'SessionPublicKeyId; }\
         'r#SessionPublicKeyId: loop { break 'r#SessionPublicKeyId; } }",
    );

    assert_eq!(
        tokens
            .iter()
            .filter(|token| token.as_str() == "SessionPublicKeyId")
            .count(),
        0,
        "lifetime or label names must not count as type-identifier uses: {tokens:?}"
    );
    assert_eq!(
        tokens
            .iter()
            .filter(|token| token.as_str() == "'SessionPublicKeyId")
            .count(),
        4
    );
    assert_eq!(
        tokens
            .iter()
            .filter(|token| token.as_str() == "'r#SessionPublicKeyId")
            .count(),
        4
    );
}

#[test]
fn pattern_white_space_cannot_hide_session_key_surface() {
    for (label, extra_source, expected_diagnostic) in [
        (
            "U+200E-separated inherent impl",
            "impl\u{200e}SessionPublicKeyId { pub const fn hidden(&self) {} }",
            "SessionPublicKeyId token inventory",
        ),
        (
            "U+200E-separated extra derive",
            "#[derive(PartialOrd, Ord)]\u{200e}\n\
             #[derive(Clone, Copy, PartialEq, Eq, Hash)]\n\
             pub struct SessionPublicKeyId([u8; SESSION_PUBLIC_KEY_ID_LENGTH]);",
            "struct exact token sequence",
        ),
    ] {
        let mut sources = model_source_texts();
        if label.contains("derive") {
            let (_, lib_source) = sources
                .iter_mut()
                .find(|(path, _)| path.ends_with("src/lib.rs"))
                .unwrap_or_else(|| panic!("{label}: model source inventory omitted src/lib.rs"));
            let canonical = "#[derive(Clone, Copy, PartialEq, Eq, Hash)]\n\
                             pub struct SessionPublicKeyId([u8; SESSION_PUBLIC_KEY_ID_LENGTH]);";
            let mutated = lib_source.replacen(canonical, extra_source, 1);
            assert_ne!(
                mutated, *lib_source,
                "{label}: mutation needle did not match the current source"
            );
            *lib_source = mutated;
        } else {
            sources.push((PathBuf::from("extra.rs"), extra_source.to_owned()));
        }

        let error = match validate_session_public_key_id_token_surface(&sources) {
            Ok(()) => panic!("{label} bypassed the source-token proof"),
            Err(error) => error,
        };
        assert!(
            error.contains(expected_diagnostic),
            "{label} failed for an unrelated reason: {error}"
        );
    }
}

#[test]
fn unscanned_item_source_mechanisms_fail_closed_across_token_forms() {
    for (label, extra_source) in [
        ("direct include", "include!(\"extra.inc\");"),
        ("qualified include", "std::include!(\"extra.inc\");"),
        ("raw include", "r#include!(\"extra.inc\");"),
        (
            "aliased include",
            "use std::include as inject_items; inject_items!(\"extra.inc\");",
        ),
        ("direct path", "#[path = \"extra.inc\"] mod injected_path;"),
        (
            "raw path",
            "#[r#path = \"extra.inc\"] mod injected_raw_path;",
        ),
        (
            "nested cfg_attr path",
            "#[cfg_attr(all(), path = \"extra.inc\")] mod injected_cfg_path;",
        ),
        (
            "nested cfg_attr raw path",
            "#[cfg_attr(all(), r#path = \"extra.inc\")] mod injected_cfg_raw_path;",
        ),
        (
            "raw cfg_attr and raw path",
            "#[r#cfg_attr(all(), r#path = \"extra.inc\")] mod injected_raw_cfg_attr_path;",
        ),
    ] {
        let mut sources = model_source_texts();
        sources.push((PathBuf::from("extra.rs"), extra_source.to_owned()));

        let error = match validate_session_public_key_id_token_surface(&sources) {
            Ok(()) => panic!("{label} bypassed the unscanned item-source guard"),
            Err(error) => error,
        };
        assert!(
            error.contains("unscanned item-source mechanism"),
            "{label} failed for an unrelated reason: {error}"
        );
    }
}

#[test]
fn macro_source_selection_is_rejected_before_expansion() {
    for (label, extra_source) in [
        (
            "macro passes path meta-item",
            "macro_rules! select_source { ($attribute:meta) => { #[$attribute] mod injected; }; }\n\
             select_source!(path = \"extra.inc\");",
        ),
        (
            "macro hardcodes path attribute",
            "macro_rules! select_source { () => { #[path = \"extra.inc\"] mod injected; }; }\n\
             select_source!();",
        ),
        (
            "macro metavariable reserves path spelling",
            "macro_rules! forward { ($path:meta) => {}; } forward!(doc = \"safe\");",
        ),
        (
            "macro forwards include identity",
            "macro_rules! invoke { ($name:ident) => { $name!(\"extra.inc\"); }; }\n\
             invoke!(include);",
        ),
        (
            "nested imported include alias",
            "use std::{include as inject_items}; inject_items!(\"extra.inc\");",
        ),
        (
            "chained imported include alias",
            "use std::include as first; use first as second; second!(\"extra.inc\");",
        ),
        ("leading BOM include", "\u{feff}include!(\"extra.inc\");"),
    ] {
        let mut sources = model_source_texts();
        sources.push((PathBuf::from("extra.rs"), extra_source.to_owned()));

        let error = match validate_session_public_key_id_token_surface(&sources) {
            Ok(()) => panic!("{label} bypassed the source-selection policy"),
            Err(error) => error,
        };
        assert!(
            error.contains("unscanned item-source mechanism"),
            "{label} failed for an unrelated reason: {error}"
        );
    }
}

#[test]
fn local_trait_declarations_are_forbidden_but_trait_decoys_are_ignored() {
    let mut blanket_sources = model_source_texts();
    blanket_sources.push((
        PathBuf::from("blanket.rs"),
        "pub trait AdmitExt { fn admit(&self) {} } impl<T> AdmitExt for T {}".to_owned(),
    ));
    let error = match validate_session_public_key_id_token_surface(&blanket_sources) {
        Ok(()) => panic!("a local blanket extension trait bypassed the exact surface proof"),
        Err(error) => error,
    };
    assert!(
        error.contains("local trait declarations are forbidden"),
        "blanket extension trait failed for an unrelated reason: {error}"
    );

    let mut decoy_sources = model_source_texts();
    decoy_sources.push((
        PathBuf::from("trait_decoys.rs"),
        r####"
// pub trait CommentDecoy {}
const _NORMAL: &str = "pub trait NormalStringDecoy {}";
const _RAW: &str = r#"pub trait RawStringDecoy {}"#;
fn r#trait() {}
macro_rules! keyword_metavariable { ($trait:ident) => {}; }
keyword_metavariable!(ordinary_name);
"####
            .to_owned(),
    ));
    assert_eq!(
        validate_session_public_key_id_token_surface(&decoy_sources),
        Ok(())
    );

    let mut concrete_keyword_sources = model_source_texts();
    concrete_keyword_sources.push((
        PathBuf::from("trait_macro_input.rs"),
        "macro_rules! discard { ($token:ident) => {}; } discard!(trait);".to_owned(),
    ));
    let error = match validate_session_public_key_id_token_surface(&concrete_keyword_sources) {
        Ok(()) => panic!("a concrete trait keyword in macro input bypassed the trait policy"),
        Err(error) => error,
    };
    assert!(
        error.contains("local trait declarations are forbidden"),
        "concrete trait macro input failed for an unrelated reason: {error}"
    );
}

#[test]
fn ordinary_modules_and_similar_tokens_do_not_trigger_item_source_guard() {
    let mut sources = model_source_texts();
    sources.push((
        PathBuf::from("ordinary.rs"),
        r####"
mod ordinary;
const _INCLUDE_TEXT: &str = "include!(\"extra.inc\")";
const _PATH_TEXT: &str = "#[path = \"extra.inc\"]";
const INCLUDE_EXTRA: &str = include_str!("ordinary.rs");
const INCLUDE_BYTES_EXTRA: &[u8] = include_bytes!("ordinary.rs");
fn ordinary_path() { let path = "ordinary"; let _ = path; }
#[doc = "path = ordinary"]
struct Ordinary;
"####
            .to_owned(),
    ));

    assert_eq!(
        validate_session_public_key_id_token_surface(&sources),
        Ok(())
    );
}

#[test]
fn ordinary_include_path_and_target_value_roles_do_not_trigger_surface_guards() {
    let mut sources = model_source_texts();
    sources.push((
        PathBuf::from("ordinary_roles.rs"),
        r####"
#[allow(dead_code, non_snake_case)]
mod ordinary_roles {
    fn include(path: usize) -> usize { path }
    fn path(include: usize) -> usize { include }
    fn SessionPublicKeyId(path: usize) -> usize { path }

    fn use_names() {
        let include = include(1);
        let path = path(include);
        let SessionPublicKeyId = SessionPublicKeyId(path);
        let _ = SessionPublicKeyId;
        let _not_path = !(path == 0);
    }
}

#[cfg_attr(any(), path = "missing.inc")]
struct InertPathMetadata;

#[cfg_attr(any(), doc(path = "not-a-source-path"))]
mod NestedNonLoadingPathMetadata {}
"####
            .to_owned(),
    ));

    assert_eq!(
        validate_session_public_key_id_token_surface(&sources),
        Ok(())
    );
}

#[test]
fn macro_metavariables_and_macro_namespace_names_are_not_target_type_uses() {
    let mut sources = model_source_texts();
    sources.push((
        PathBuf::from("macro_roles.rs"),
        r####"
macro_rules! SessionPublicKeyId { () => {}; }
macro_rules! harmless_metavariable {
    ($SessionPublicKeyId:ident) => {
        const _: &str = stringify!($SessionPublicKeyId);
    };
}
harmless_metavariable!(ordinary_name);
"####
            .to_owned(),
    ));

    assert_eq!(
        validate_session_public_key_id_token_surface(&sources),
        Ok(())
    );

    let mut concrete_sources = model_source_texts();
    concrete_sources.push((
        PathBuf::from("concrete_macro.rs"),
        "macro_rules! observe { ($value:ident) => {}; } observe!(SessionPublicKeyId);".to_owned(),
    ));
    let error = match validate_session_public_key_id_token_surface(&concrete_sources) {
        Ok(()) => panic!("concrete target spelling in macro input bypassed the reservation"),
        Err(error) => error,
    };
    assert!(
        error.contains("SessionPublicKeyId token inventory"),
        "concrete macro spelling failed for an unrelated reason: {error}"
    );
}

#[test]
fn dollar_prefixed_macro_invocation_tokens_remain_concrete_source() {
    let mut bypasses = Vec::new();
    for (label, invocation, expected_diagnostic) in [
        (
            "target type",
            "macro_rules! discard { ($dollar:tt $value:ty) => {}; } \
             discard!($ SessionPublicKeyId);",
            "SessionPublicKeyId token inventory",
        ),
        (
            "include identity",
            "macro_rules! discard { ($dollar:tt $value:ident) => {}; } \
             discard!($ include);",
            "unscanned item-source mechanism",
        ),
        (
            "trait keyword",
            "macro_rules! discard { ($dollar:tt $value:ident) => {}; } \
             discard!($ trait);",
            "local trait declarations are forbidden",
        ),
        (
            "path spelling control",
            "macro_rules! discard { ($dollar:tt $value:ident) => {}; } \
             discard!($ path);",
            "unscanned item-source mechanism",
        ),
    ] {
        let mut sources = model_source_texts();
        sources.push((PathBuf::from("dollar_invocation.rs"), invocation.to_owned()));

        match validate_session_public_key_id_token_surface(&sources) {
            Ok(()) => bypasses.push(label),
            Err(error) => assert!(
                error.contains(expected_diagnostic),
                "{label} failed for an unrelated reason: {error}"
            ),
        }
    }

    assert!(
        bypasses.is_empty(),
        "dollar-prefixed concrete macro invocation tokens bypassed source policy: {bypasses:?}"
    );
}

#[test]
fn genuine_macro_definition_metavariables_remain_exempt() {
    let mut sources = model_source_texts();
    sources.push((
        PathBuf::from("definition_metavariables.rs"),
        r####"
macro_rules! stringify_definition_metavariables {
    ($SessionPublicKeyId:ident, $include:ident, $trait:ident) => {
        const _: &str = concat!(
            stringify!($SessionPublicKeyId),
            stringify!($include),
            stringify!($trait),
        );
    };
}
stringify_definition_metavariables!(ordinary_target, ordinary_include, ordinary_trait);
"####
            .to_owned(),
    ));

    assert_eq!(
        validate_session_public_key_id_token_surface(&sources),
        Ok(())
    );
}

#[test]
fn macro_definition_name_exemption_requires_a_genuine_definition_range() {
    let mut genuine_sources = model_source_texts();
    genuine_sources.push((
        PathBuf::from("genuine_definition_names.rs"),
        "macro_rules! SessionPublicKeyId { () => {}; } \
         mod nested { macro_rules! SessionPublicKeyId { () => {}; } }"
            .to_owned(),
    ));
    assert_eq!(
        validate_session_public_key_id_token_surface(&genuine_sources),
        Ok(())
    );

    let mut concrete_sources = model_source_texts();
    concrete_sources.push((
        PathBuf::from("concrete_nested_definition_tokens.rs"),
        "macro_rules! outer { \
             (macro_rules ! $name:ident { $($rest:tt)* }) => { \
                 impl $name { fn added(&self) -> bool { true } } \
             }; \
         } \
         outer!(macro_rules! SessionPublicKeyId {});"
            .to_owned(),
    ));
    let error = match validate_session_public_key_id_token_surface(&concrete_sources) {
        Ok(()) => panic!(
            "a concrete macro invocation token sequence received the definition-name exemption"
        ),
        Err(error) => error,
    };
    assert!(
        error.contains("SessionPublicKeyId token inventory"),
        "concrete macro definition-like input failed for an unrelated reason: {error}"
    );
}

#[test]
fn concrete_constructor_and_associated_path_uses_are_reserved() {
    for (label, extra_source) in [
        (
            "associated constructor",
            "pub fn make(bytes: [u8; 32]) -> impl Copy { \
             SessionPublicKeyId::from_bytes(bytes) }",
        ),
        (
            "tuple constructor",
            "pub fn make(bytes: [u8; 32]) -> impl Copy { SessionPublicKeyId(bytes) }",
        ),
        (
            "bare tuple constructor value",
            "pub fn constructor_value() { let _ = SessionPublicKeyId; }",
        ),
        (
            "tuple constructor pattern",
            "pub fn destructure(value: SessionPublicKeyId) { \
             let SessionPublicKeyId(_bytes) = value; }",
        ),
    ] {
        let mut sources = model_source_texts();
        sources.push((PathBuf::from("constructor_use.rs"), extra_source.to_owned()));

        let error = match validate_session_public_key_id_token_surface(&sources) {
            Ok(()) => panic!("{label} bypassed the concrete target-use reservation"),
            Err(error) => error,
        };
        assert!(
            error.contains("SessionPublicKeyId token inventory"),
            "{label} failed for an unrelated reason: {error}"
        );
    }
}

#[test]
fn global_token_surface_ignores_comment_and_literal_decoys() {
    let mut sources = model_source_texts();
    sources.push((
        PathBuf::from("decoys.rs"),
        r####"
// impl SessionPublicKeyId { line comment decoy }
/*! outer block doc with impl SessionPublicKeyId {
    /* nested block with impl SessionPublicKeyId { } */
} */
const _NORMAL: &str = "impl SessionPublicKeyId { normal string decoy }";
const _RAW: &str = r###"impl SessionPublicKeyId { raw string decoy }"###;
const _BYTES: &[u8] = b"impl SessionPublicKeyId { byte string decoy }";
const _RAW_BYTES: &[u8] = br##"impl SessionPublicKeyId { raw bytes decoy }"##;
const _CHAR: char = 'i';
const _BYTE_CHAR: u8 = b'i';
"####
            .to_owned(),
    ));

    assert_eq!(
        validate_session_public_key_id_token_surface(&sources),
        Ok(())
    );
}

#[test]
fn global_token_surface_rejects_noncanonical_type_uses() {
    for (label, extra_source, expected_diagnostic) in [
        (
            "comment-separated inherent impl",
            "impl/**/ SessionPublicKeyId { pub fn mystery_power(&self) {} }",
            "SessionPublicKeyId token inventory",
        ),
        (
            "generic trait impl",
            "trait Extra<T> {} impl<T> Extra<T> for crate::SessionPublicKeyId {}",
            "local trait declarations are forbidden",
        ),
        (
            "type alias",
            "type Handle = crate::SessionPublicKeyId;",
            "SessionPublicKeyId token inventory",
        ),
        (
            "macro integration",
            "macro_rules! integrate { ($type:ty) => {} } integrate!(SessionPublicKeyId);",
            "SessionPublicKeyId token inventory",
        ),
        (
            "NFC-equivalent Kelvin-sign inherent impl",
            "impl SessionPublicKeyId { pub fn kelvin_extra(&self) {} }",
            "SessionPublicKeyId token inventory",
        ),
    ] {
        let mut sources = model_source_texts();
        sources.push((PathBuf::from("extra.rs"), extra_source.to_owned()));

        let error = match validate_session_public_key_id_token_surface(&sources) {
            Ok(()) => panic!("{label} bypassed the global token proof"),
            Err(error) => error,
        };
        assert!(
            error.contains(expected_diagnostic),
            "{label} failed for an unrelated reason: {error}"
        );
    }
}

#[test]
fn exact_token_regions_reject_extra_attributes_items_and_macros() {
    for (label, needle, replacement, expected_diagnostic) in [
        (
            "extra derive attribute",
            "#[derive(Clone, Copy, PartialEq, Eq, Hash)]\npub struct SessionPublicKeyId",
            "#[derive(PartialOrd, Ord)]\n#[derive(Clone, Copy, PartialEq, Eq, Hash)]\npub struct SessionPublicKeyId",
            "struct exact token sequence",
        ),
        (
            "target-specific attribute on struct",
            "#[derive(Clone, Copy, PartialEq, Eq, Hash)]\npub struct SessionPublicKeyId",
            "#[cfg(target_pointer_width = \"64\")]\n#[derive(Clone, Copy, PartialEq, Eq, Hash)]\npub struct SessionPublicKeyId",
            "struct exact token sequence",
        ),
        (
            "associated const",
            "        &self.0\n    }\n}\n\nimpl fmt::Debug for SessionPublicKeyId",
            "        &self.0\n    }\n\n    pub const ZERO: Self = Self([0; SESSION_PUBLIC_KEY_ID_LENGTH]);\n}\n\nimpl fmt::Debug for SessionPublicKeyId",
            "inherent impl exact token sequence",
        ),
        (
            "surface-generating macro",
            "        &self.0\n    }\n}\n\nimpl fmt::Debug for SessionPublicKeyId",
            "        &self.0\n    }\n\n    extra_surface!();\n}\n\nimpl fmt::Debug for SessionPublicKeyId",
            "inherent impl exact token sequence",
        ),
        (
            "target-specific attribute on inherent impl",
            "impl SessionPublicKeyId {",
            "#[cfg(target_pointer_width = \"64\")]\nimpl SessionPublicKeyId {",
            "inherent impl exact token sequence",
        ),
        (
            "target-specific cfg_attr on Debug impl",
            "impl fmt::Debug for SessionPublicKeyId {",
            "#[cfg_attr(target_os = \"linux\", allow(dead_code))]\nimpl fmt::Debug for SessionPublicKeyId {",
            "Debug impl exact token sequence",
        ),
    ] {
        let mut sources = model_source_texts();
        let (_, lib_source) = sources
            .iter_mut()
            .find(|(path, _)| path.ends_with("src/lib.rs"))
            .unwrap_or_else(|| panic!("{label}: model source inventory omitted src/lib.rs"));
        let mutated = lib_source.replacen(needle, replacement, 1);
        assert_ne!(
            mutated, *lib_source,
            "{label}: mutation needle did not match the current source"
        );
        *lib_source = mutated;

        let error = match validate_session_public_key_id_token_surface(&sources) {
            Ok(()) => panic!("{label} bypassed the exact token proof"),
            Err(error) => error,
        };
        assert!(
            error.contains(expected_diagnostic),
            "{label} failed for an unrelated reason: {error}"
        );
    }
}

#[test]
fn canonical_items_must_be_direct_root_items_and_crate_inner_attrs_are_pinned() {
    let mut nested_sources = model_source_texts();
    let (_, nested_lib) = nested_sources
        .iter_mut()
        .find(|(path, _)| path.ends_with("src/lib.rs"))
        .unwrap_or_else(|| panic!("model source inventory omitted src/lib.rs"));
    let start = nested_lib
        .find("#[derive(Clone, Copy, PartialEq, Eq, Hash)]\npub struct SessionPublicKeyId")
        .unwrap_or_else(|| panic!("approved declaration marker is missing"));
    let end = nested_lib[start..]
        .find("/// A versioned protocol identifier.")
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("approved declaration end marker is missing"));
    let canonical_block = nested_lib[start..end].to_owned();
    nested_lib.replace_range(
        start..end,
        &format!("mod nested {{\nuse super::*;\n{canonical_block}\n}}\n\n"),
    );
    let error = match validate_session_public_key_id_token_surface(&nested_sources) {
        Ok(()) => panic!("canonical items nested in a module bypassed the root-item rule"),
        Err(error) => error,
    };
    assert!(
        error.contains("direct root production item"),
        "nested canonical items failed for an unrelated reason: {error}"
    );

    let mut macro_sources = model_source_texts();
    let (_, macro_lib) = macro_sources
        .iter_mut()
        .find(|(path, _)| path.ends_with("src/lib.rs"))
        .unwrap_or_else(|| panic!("model source inventory omitted src/lib.rs"));
    let start = macro_lib
        .find("#[derive(Clone, Copy, PartialEq, Eq, Hash)]\npub struct SessionPublicKeyId")
        .unwrap_or_else(|| panic!("approved declaration marker is missing"));
    let end = macro_lib[start..]
        .find("/// A versioned protocol identifier.")
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("approved declaration end marker is missing"));
    let canonical_block = macro_lib[start..end].to_owned();
    macro_lib.replace_range(
        start..end,
        &format!(
            "macro_rules! define_session_key {{ () => {{ {canonical_block} }}; }}\n\
             define_session_key!();\n\n"
        ),
    );
    let error = match validate_session_public_key_id_token_surface(&macro_sources) {
        Ok(()) => panic!("canonical items in a macro token tree bypassed the root-item rule"),
        Err(error) => error,
    };
    assert!(
        error.contains("direct root production item")
            || error.contains("SessionPublicKeyId token inventory"),
        "macro-nested canonical items failed for an unrelated reason: {error}"
    );

    let mut cfg_sources = model_source_texts();
    let (_, cfg_lib) = cfg_sources
        .iter_mut()
        .find(|(path, _)| path.ends_with("src/lib.rs"))
        .unwrap_or_else(|| panic!("model source inventory omitted src/lib.rs"));
    let mutated = cfg_lib.replacen(
        "#![forbid(unsafe_code)]",
        "#![forbid(unsafe_code)]\n#![cfg(target_pointer_width = \"64\")]",
        1,
    );
    assert_ne!(
        mutated, *cfg_lib,
        "crate inner-attribute needle did not match"
    );
    *cfg_lib = mutated;
    let error = match validate_session_public_key_id_token_surface(&cfg_sources) {
        Ok(()) => panic!("an extra crate-wide cfg attribute bypassed the source proof"),
        Err(error) => error,
    };
    assert!(
        error.contains("crate inner attribute"),
        "crate-wide cfg failed for an unrelated reason: {error}"
    );
}

#[test]
fn public_api_surface_is_pinned_to_the_approved_non_authority_contract() {
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let source_paths = rust_source_paths(&source_root);
    let lib_path = source_root.join("lib.rs");
    assert!(
        source_paths.binary_search(&lib_path).is_ok(),
        "model Rust source inventory omitted lib.rs"
    );

    let source = normalized_source(&lib_path);
    assert_eq!(
        source
            .matches("pub const SESSION_PUBLIC_KEY_ID_LENGTH: usize = 32;")
            .count(),
        1
    );

    let start_marker = "#[derive(Clone, Copy, PartialEq, Eq, Hash)]\npub struct SessionPublicKeyId";
    let start = match source.find(start_marker) {
        Some(index) => index,
        None => panic!("approved SessionPublicKeyId declaration is missing"),
    };
    let tail = &source[start..];
    let end = match tail.find("/// A versioned protocol identifier.") {
        Some(index) => index,
        None => panic!("SessionPublicKeyId block has no stable end marker"),
    };
    let production = tail[..end]
        .lines()
        .filter(|line| !line.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(production.contains(
        "#[derive(Clone, Copy, PartialEq, Eq, Hash)]\n\
         pub struct SessionPublicKeyId([u8; SESSION_PUBLIC_KEY_ID_LENGTH]);"
    ));
    assert!(
        production
            .contains("pub const fn from_bytes(bytes: [u8; SESSION_PUBLIC_KEY_ID_LENGTH]) -> Self")
    );
    assert!(
        production.contains("pub const fn as_bytes(&self) -> &[u8; SESSION_PUBLIC_KEY_ID_LENGTH]")
    );
    assert!(production.contains("formatter.write_str(\"SessionPublicKeyId([REDACTED; 32])\")"));

    let production_tokens = rust_tokens(&production);
    let function_names = production_tokens
        .windows(2)
        .filter(|window| window[0] == "fn")
        .map(|window| window[1].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        function_names,
        ["from_bytes", "as_bytes", "fmt"],
        "the primary SessionPublicKeyId block must contain exactly its two methods and Debug::fmt"
    );
    assert!(
        !production_tokens.iter().any(|token| token == "!"),
        "the primary SessionPublicKeyId block must not invoke a surface-generating macro"
    );

    let sources = model_source_texts();
    if let Err(error) = validate_session_public_key_id_token_surface(&sources) {
        panic!("{error}");
    }
}
