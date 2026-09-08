// SPDX-License-Identifier: Apache-2.0

//! Wine context correlation (M5-034, ADR-0030): given a PINNED
//! caller (ADR-0028), derive which wine deployment it belongs to -
//! the prefix, the wineserver, the process tree, and the cgroup -
//! from procfs. Everything read is REDACTED by construction: the
//! correlation record carries digests and structural facts only,
//! never environment values, command lines, or paths verbatim.

use std::collections::BTreeMap;

use crate::binding::CallerBinding;

/// The redacted wine context of a pinned caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WineContext {
    /// Whether the pinned process carries a WINEPREFIX variable.
    pub has_wineprefix: bool,
    /// SHA-256 of the WINEPREFIX VALUE (never the value itself):
    /// stable correlation without exposing the user's paths.
    pub wineprefix_digest: Option<[u8; 32]>,
    /// SHA-256 of the WINELOADER/WINESERVER variable values when
    /// present (same redaction rule).
    pub loader_digests: BTreeMap<String, [u8; 32]>,
    /// Depth of the process tree above the pinned process (0 when
    /// the parent is not observable). Bounded; no identities.
    pub ancestry_depth: u32,
    /// The pinned process's cgroup PATH DIGEST and its controller
    /// list, structural only.
    pub cgroup_controllers: Vec<String>,
    pub cgroup_path_digest: Option<[u8; 32]>,
}

/// Correlation failures. Deterministic, non-disciplinary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrelationError {
    /// procfs was unreadable for the pinned process.
    Unreadable,
}

impl std::fmt::Display for CorrelationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable => formatter.write_str("the pinned process's procfs was unreadable"),
        }
    }
}

impl std::error::Error for CorrelationError {}

/// The wine-relevant environment KEYS the correlation reads (values
/// are always reduced to digests).
const WINE_KEYS: &[&str] = &["WINEPREFIX", "WINELOADER", "WINESERVER", "WINEDEBUG"];

const MAX_ANCESTRY: u32 = 64;

fn sha256_hex_digest(bytes: &[u8]) -> [u8; 32] {
    // The workspace's production SHA-256 (ogir-attest).
    ogir_attest::sha256::sha256(bytes)
}

/// Reads the redacted wine context of a pinned caller. The caller
/// must still be pinned (the binding's own liveness is the gate for
/// using any of this).
pub fn correlate(binding: &CallerBinding) -> Result<WineContext, CorrelationError> {
    let pid = binding.pid();
    // A transient read failure of a live process's environ (observed
    // on loaded CI runners) is not an unreadable process: retry a
    // bounded budget first.
    let mut environ = None;
    for attempt in 0..10 {
        if let Ok(bytes) = std::fs::read(format!("/proc/{pid}/environ")) {
            environ = Some(bytes);
            break;
        }
        if attempt < 9 {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    let environ = environ.ok_or(CorrelationError::Unreadable)?;

    let mut values: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in environ.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        if let Some((key, value)) = split_env(entry)
            && WINE_KEYS.contains(&key.as_str())
        {
            values.insert(key, value.to_vec());
        }
    }

    let has_wineprefix = values.contains_key("WINEPREFIX");
    let wineprefix_digest = values
        .get("WINEPREFIX")
        .map(|value| sha256_hex_digest(value));
    let loader_digests = values
        .iter()
        .filter(|(key, _)| key.as_str() != "WINEPREFIX")
        .map(|(key, value)| (key.clone(), sha256_hex_digest(value)))
        .collect();

    let ancestry_depth = ancestry_depth(pid);
    let (cgroup_controllers, cgroup_path_digest) = read_cgroup(pid);

    Ok(WineContext {
        has_wineprefix,
        wineprefix_digest,
        loader_digests,
        ancestry_depth,
        cgroup_controllers,
        cgroup_path_digest,
    })
}

fn split_env(entry: &[u8]) -> Option<(String, Vec<u8>)> {
    let position = entry.iter().position(|byte| *byte == b'=')?;
    let key = String::from_utf8(entry[..position].to_vec()).ok()?;
    if key.is_empty() {
        return None;
    }
    Some((key, entry[position + 1..].to_vec()))
}

/// How many observable ancestors the process has, bounded. Reads
/// only ppid fields - never command lines.
fn ancestry_depth(pid: u32) -> u32 {
    let mut current = pid;
    let mut depth = 0u32;
    for _ in 0..MAX_ANCESTRY {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{current}/stat")) else {
            break;
        };
        let Some((_comm, after_comm)) = stat.rsplit_once(')') else {
            break;
        };
        // Field 4 (ppid) is the second field after the parenthesis.
        let Some(ppid_text) = after_comm.split_whitespace().nth(1) else {
            break;
        };
        let Ok(ppid) = ppid_text.parse::<u32>() else {
            break;
        };
        if ppid == 0 || ppid == 1 || ppid == current {
            break;
        }
        current = ppid;
        depth += 1;
    }
    depth
}

fn read_cgroup(pid: u32) -> (Vec<String>, Option<[u8; 32]>) {
    let Ok(cgroup) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
        return (Vec::new(), None);
    };
    // Unified (v2) lines: `0::/path`; v1 lines: `controller:/path`.
    // Keep controller names (structural) and digest the path.
    let mut controllers = Vec::new();
    let mut path_digest = None;
    for line in cgroup.lines() {
        let Some((hierarchy, path)) = line.split_once(':') else {
            continue;
        };
        if !hierarchy.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if !hierarchy.is_empty() {
            controllers.push(hierarchy.to_string());
        } else if path_digest.is_none() && path != "/" {
            path_digest = Some(sha256_hex_digest(path.as_bytes()));
        }
    }
    (controllers, path_digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal::PeerCredentials;

    fn pinned_self() -> CallerBinding {
        CallerBinding::pin(&PeerCredentials {
            pid: std::process::id(),
            uid: 0,
            gid: 0,
        })
        .unwrap_or_else(|e| panic!("{e:?}"))
    }

    #[test]
    fn correlates_the_current_process_redacted() {
        let binding = pinned_self();
        let context = correlate(&binding).unwrap_or_else(|e| panic!("{e:?}"));
        // This test process has no WINEPREFIX unless inherited.
        if std::env::var("WINEPREFIX").is_err() {
            assert!(!context.has_wineprefix);
            assert_eq!(context.wineprefix_digest, None);
        } else {
            assert!(context.has_wineprefix);
            assert!(context.wineprefix_digest.is_some());
        }
        assert!(context.ancestry_depth <= MAX_ANCESTRY);
    }

    #[test]
    fn digests_are_stable_and_not_the_raw_value() {
        let digest = sha256_hex_digest(b"/home/user/.wine");
        assert_eq!(digest, sha256_hex_digest(b"/home/user/.wine"));
        assert_ne!(digest, sha256_hex_digest(b"/home/user/.wine2"));
        // Not the raw bytes.
        assert_ne!(&digest[..], b"/home/user/.wine");
    }

    #[test]
    fn env_splitting_rejects_malformed_entries() {
        assert_eq!(
            split_env(b"WINEPREFIX=/a/b"),
            Some(("WINEPREFIX".to_string(), b"/a/b".to_vec()))
        );
        assert_eq!(split_env(b"NOVALUE"), None);
        assert_eq!(split_env(b"=x"), None);
    }

    #[test]
    fn a_dead_process_is_unreadable() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .unwrap_or_else(|e| panic!("{e:?}"));
        let pid = child.id();
        let _ = child.wait();
        // Pinning fails for the dead process, so correlation cannot
        // even start: the record type requires a live pin.
        let outcome = CallerBinding::pin(&PeerCredentials {
            pid,
            uid: 0,
            gid: 0,
        });
        assert!(outcome.is_err());
    }
}
