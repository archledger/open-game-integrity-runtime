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

fn non_doc_source(source: &str) -> String {
    source
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("///") && !trimmed.starts_with("//!")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn session_public_key_id_impl_headers(source: &str) -> Vec<String> {
    let compact = source.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut headers = Vec::new();
    let mut offset = 0;

    while let Some(relative_start) = compact[offset..].find("impl ") {
        let start = offset + relative_start;
        let tail = &compact[start..];
        let relative_end = tail
            .find('{')
            .unwrap_or_else(|| panic!("impl header has no body: {tail}"));
        let end = start + relative_end + 1;
        let header = &compact[start..end];
        if header.contains("SessionPublicKeyId") {
            headers.push(header.to_owned());
        }
        offset = end;
    }

    headers
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
    assert_eq!(production.matches("pub const fn ").count(), 2);
    assert_eq!(production.matches("pub fn ").count(), 0);
    assert!(production.contains("formatter.write_str(\"SessionPublicKeyId([REDACTED; 32])\")"));

    for forbidden in [
        "pub struct SessionPublicKeyId(pub ",
        "pub type SessionPublicKeyId",
        "impl Default for SessionPublicKeyId",
        "impl fmt::Display for SessionPublicKeyId",
        "impl From<",
        "impl Into<",
        "impl TryFrom<",
        "impl TryInto<",
        "impl std::convert::From<",
        "impl std::convert::Into<",
        "impl std::convert::TryFrom<",
        "impl std::convert::TryInto<",
        "impl AsRef<",
        "impl std::str::FromStr",
        "Serialize",
        "Deserialize",
        "as_bytes_mut",
        "serialize",
        "generate",
        "is_valid",
        "authorize",
        "verified_attestation",
        "validated_permit",
        "proof_of_possession",
        "admit",
        "impl PartialOrd",
        "impl Ord",
        "Decision",
        "ReasonCode",
        "VerifiedAttestation",
        "Permit",
        "Proof",
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden public surface appeared: {forbidden:?}"
        );
    }

    let all_production = source_paths
        .iter()
        .map(|path| non_doc_source(&normalized_source(path)))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        all_production
            .matches("pub struct SessionPublicKeyId([u8; SESSION_PUBLIC_KEY_ID_LENGTH]);")
            .count(),
        1,
        "the private SessionPublicKeyId declaration must appear exactly once across model sources"
    );
    assert_eq!(
        session_public_key_id_impl_headers(&all_production),
        [
            "impl SessionPublicKeyId {",
            "impl fmt::Debug for SessionPublicKeyId {",
        ],
        "SessionPublicKeyId must have exactly one inherent impl and its one allowed Debug impl"
    );

    for line in all_production.lines() {
        assert!(
            !(line.contains("type ") && line.contains("SessionPublicKeyId")),
            "SessionPublicKeyId type alias appeared outside documentation: {line:?}"
        );
        assert!(
            !line.contains("SessionPublicKeyId as "),
            "SessionPublicKeyId alias import appeared outside documentation: {line:?}"
        );
    }

    let compact_all_production = all_production
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for forbidden_method in [
        "fn as_bytes_mut",
        "fn serialize",
        "fn generate",
        "fn is_valid",
        "fn authorize",
        "fn verified_attestation",
        "fn validated_permit",
        "fn proof_of_possession",
        "fn admit",
    ] {
        assert!(
            !compact_all_production.contains(forbidden_method),
            "forbidden global SessionPublicKeyId authority surface appeared: {forbidden_method:?}"
        );
    }
}
