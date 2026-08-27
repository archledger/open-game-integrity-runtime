// SPDX-License-Identifier: Apache-2.0

use std::any::TypeId;
use std::collections::{HashSet, hash_map::DefaultHasher};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ogir_model::{Nonce, SESSION_PUBLIC_KEY_ID_LENGTH, SessionId, SessionPublicKeyId};

const EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH: usize = 32;
const PRIVATE_SENTINEL: [u8; EXPECTED_SESSION_PUBLIC_KEY_ID_LENGTH] = [
    0x03, 0x17, 0x2b, 0x3f, 0x53, 0x67, 0x7b, 0x8f, 0xa3, 0xb7, 0xcb, 0xdf, 0xf3, 0x07, 0x1b, 0x2f,
    0x43, 0x57, 0x6b, 0x7f, 0x93, 0xa7, 0xbb, 0xcf, 0xe3, 0xf7, 0x0b, 0x1f, 0x33, 0x47, 0x5b, 0x6f,
];
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
    "'",
    "_",
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
        let root = std::env::temp_dir().join(format!(
            "ogir-model-source-inventory-{}-{sequence}",
            std::process::id()
        ));
        if let Err(error) = fs::create_dir(&root) {
            panic!(
                "cannot create temporary source root {}: {error}",
                root.display()
            );
        }
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn write(&self, relative: &str) {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent()
            && let Err(error) = fs::create_dir_all(parent)
        {
            panic!(
                "cannot create temporary source parent {}: {error}",
                parent.display()
            );
        }
        if let Err(error) = fs::write(&path, "// test fixture\n") {
            panic!("cannot write temporary source {}: {error}", path.display());
        }
    }
}

impl Drop for TemporarySourceTree {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.root) {
            panic!(
                "cannot remove temporary source tree {}: {error}",
                self.root.display()
            );
        }
    }
}

fn rust_source_paths(root: &Path) -> Vec<PathBuf> {
    fn visit(directory: &Path, paths: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()));

        for entry in entries {
            let entry = entry.unwrap_or_else(|error| {
                panic!(
                    "cannot read an entry below {}: {error}",
                    directory.display()
                )
            });
            let file_type = entry.file_type().unwrap_or_else(|error| {
                panic!("cannot inspect {}: {error}", entry.path().display())
            });
            assert!(
                !file_type.is_symlink(),
                "model source inventory must not follow symlink: {}",
                entry.path().display()
            );

            if file_type.is_dir() {
                visit(&entry.path(), paths);
            } else if file_type.is_file()
                && entry.path().extension().and_then(|value| value.to_str()) == Some("rs")
            {
                paths.push(entry.path());
            }
        }
    }

    let mut paths = Vec::new();
    visit(root, &mut paths);
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

fn is_identifier_start(character: char) -> bool {
    character == '_' || character.is_ascii_alphabetic() || !character.is_ascii()
}

fn is_identifier_continue(character: char) -> bool {
    character == '_' || character.is_ascii_alphanumeric() || !character.is_ascii()
}

fn rust_tokens(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0;

    while cursor < bytes.len() {
        if bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
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
            cursor = end;
            continue;
        }
        if bytes[cursor] == b'"' {
            cursor = quoted_string_end(source, cursor);
            continue;
        }
        if matches!(bytes.get(cursor), Some(b'b' | b'c')) && bytes.get(cursor + 1) == Some(&b'"') {
            cursor = quoted_string_end(source, cursor + 1);
            continue;
        }
        if bytes[cursor] == b'b' && bytes.get(cursor + 1) == Some(&b'\'') {
            cursor = char_literal_end(source, cursor + 1)
                .unwrap_or_else(|| panic!("invalid byte character at byte {cursor}"));
            continue;
        }
        if bytes[cursor] == b'\'' {
            if let Some(end) = char_literal_end(source, cursor) {
                cursor = end;
            } else {
                tokens.push("'".to_owned());
                cursor += 1;
            }
            continue;
        }
        let character = source[cursor..]
            .chars()
            .next()
            .unwrap_or_else(|| panic!("token cursor {cursor} is not on a character boundary"));
        if is_identifier_start(character) {
            let start = cursor;
            cursor += character.len_utf8();
            while cursor < bytes.len() {
                let next = source[cursor..].chars().next().unwrap_or_else(|| {
                    panic!("identifier cursor {cursor} is not on a character boundary")
                });
                if !is_identifier_continue(next) {
                    break;
                }
                cursor += next.len_utf8();
            }
            tokens.push(source[start..cursor].to_owned());
            continue;
        }
        if bytes[cursor].is_ascii_digit() {
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || matches!(bytes[cursor], b'_' | b'.'))
            {
                cursor += 1;
            }
            tokens.push(source[start..cursor].to_owned());
            continue;
        }

        tokens.push(character.to_string());
        cursor += character.len_utf8();
    }

    tokens
}

fn token_sequence_count(tokens: &[String], sequence: &[&str]) -> usize {
    tokens
        .windows(sequence.len())
        .filter(|window| {
            window
                .iter()
                .zip(sequence)
                .all(|(actual, expected)| actual == expected)
        })
        .count()
}

fn token_sequence_start(tokens: &[String], sequence: &[&str]) -> Option<usize> {
    tokens.windows(sequence.len()).position(|window| {
        window
            .iter()
            .zip(sequence)
            .all(|(actual, expected)| actual == expected)
    })
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
    let mut uses = Vec::new();
    let mut declaration_count = 0;
    let mut inherent_count = 0;
    let mut debug_count = 0;
    let mut primary_tokens = None;

    for (path, source) in sources {
        let tokens = rust_tokens(source);
        declaration_count += token_sequence_count(&tokens, &declaration);
        inherent_count += token_sequence_count(&tokens, &inherent_impl);
        debug_count += token_sequence_count(&tokens, &debug_impl);

        for (index, token) in tokens.iter().enumerate() {
            if token == "SessionPublicKeyId" {
                let start = index.saturating_sub(5);
                let end = usize::min(index + 6, tokens.len());
                uses.push(format!(
                    "{}: {}",
                    path.display(),
                    tokens[start..end].join(" ")
                ));
            }
        }
        if path.ends_with("src/lib.rs") && primary_tokens.replace(tokens).is_some() {
            return Err("model source inventory contains multiple src/lib.rs files".to_owned());
        }
    }

    if uses.len() != 3 || declaration_count != 1 || inherent_count != 1 || debug_count != 1 {
        return Err(format!(
            "SessionPublicKeyId token inventory must contain exactly one private declaration, one inherent impl, and one Debug impl; found {} use(s), {declaration_count} declaration(s), {inherent_count} inherent impl(s), and {debug_count} Debug impl(s): {uses:?}",
            uses.len()
        ));
    }

    let primary_tokens = match primary_tokens {
        Some(tokens) => tokens,
        None => return Err("model source inventory omitted src/lib.rs".to_owned()),
    };

    let declaration_start = match token_sequence_start(&primary_tokens, &declaration) {
        Some(start) => attached_attributes_start(&primary_tokens, start),
        None => return Err("struct exact token sequence has no declaration anchor".to_owned()),
    };
    let declaration_end = match semicolon_item_end(&primary_tokens, declaration_start) {
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

    let inherent_start = match token_sequence_start(&primary_tokens, &inherent_impl) {
        Some(start) => start,
        None => return Err("inherent impl exact token sequence has no anchor".to_owned()),
    };
    let inherent_end = match braced_item_end(&primary_tokens, inherent_start) {
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

    let debug_start = match token_sequence_start(&primary_tokens, &debug_impl) {
        Some(start) => start,
        None => return Err("Debug impl exact token sequence has no anchor".to_owned()),
    };
    let debug_end = match braced_item_end(&primary_tokens, debug_start) {
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
            "fn", "borrow", "<", "'", "a", ">", "(", "value", ":", "&", "'", "a", "str", ")", "{",
            "}",
        ]
    );
    assert_eq!(
        rust_tokens("struct SessionPublicKeyIdé;"),
        ["struct", "SessionPublicKeyIdé", ";"]
    );
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
    for (label, extra_source) in [
        (
            "comment-separated inherent impl",
            "impl/**/ SessionPublicKeyId { pub fn mystery_power(&self) {} }",
        ),
        (
            "generic trait impl",
            "trait Extra<T> {} impl<T> Extra<T> for crate::SessionPublicKeyId {}",
        ),
        ("type alias", "type Handle = crate::SessionPublicKeyId;"),
        (
            "macro integration",
            "macro_rules! integrate { ($type:ty) => {} } integrate!(SessionPublicKeyId);",
        ),
    ] {
        let mut sources = model_source_texts();
        sources.push((PathBuf::from("extra.rs"), extra_source.to_owned()));

        let error = match validate_session_public_key_id_token_surface(&sources) {
            Ok(()) => panic!("{label} bypassed the global token proof"),
            Err(error) => error,
        };
        assert!(
            error.contains("SessionPublicKeyId token inventory"),
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
