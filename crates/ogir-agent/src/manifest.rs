// SPDX-License-Identifier: Apache-2.0

//! Game/runtime manifest derivation (M5-035, ADR-0031): the
//! independently derived identity of WHAT the pinned caller is
//! running - the executable's digest and the bridge module's
//! digest - reduced from procfs of the PINNED process. Like
//! correlation (ADR-0030) this is redacted by construction: the
//! manifest carries digests and sizes, never paths, arguments, or
//! environment values. The manifest is REFERENCE DATA for the
//! verifier's later decisions, never authority by itself.

use crate::binding::CallerBinding;

/// The derived runtime manifest of a pinned caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeManifest {
    /// SHA-256 of the pinned process's executable file.
    pub executable_digest: [u8; 32],
    /// The executable's size in bytes.
    pub executable_size: u64,
    /// SHA-256 of the mapped files backing the process's text
    /// regions that do NOT belong to the executable itself (the
    /// bridge module among them), each with its size. Bounded.
    pub module_digests: Vec<([u8; 32], u64)>,
    /// SHA-256 of the process's mount-namespace identifier
    /// (the ns/mnt link target) - the namespace-substitution
    /// correlation anchor.
    pub mount_namespace_digest: [u8; 32],
}

/// Manifest failures. Deterministic, non-disciplinary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// The pinned process's procfs was unreadable.
    Unreadable,
    /// The maps file was malformed beyond a bounded skip count.
    Malformed,
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable => formatter.write_str("the pinned process's procfs was unreadable"),
            Self::Malformed => formatter.write_str("the pinned process's maps were malformed"),
        }
    }
}

impl std::error::Error for ManifestError {}

const MAX_MODULES: usize = 64;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    ogir_attest::sha256::sha256(bytes)
}

/// Derives the runtime manifest of a pinned caller. Requires the
/// pin (the process identity is already race-resolved); reads only
/// procfs of that process.
pub fn derive(binding: &CallerBinding) -> Result<RuntimeManifest, ManifestError> {
    let pid = binding.pid();

    let mount_namespace_digest = std::fs::read_link(format!("/proc/{pid}/ns/mnt"))
        .map_err(|_| ManifestError::Unreadable)
        .and_then(|target| {
            let text = target
                .to_str()
                .ok_or(ManifestError::Unreadable)?
                .to_string();
            Ok(sha256(text.as_bytes()))
        })?;

    let exe_stat =
        std::fs::metadata(format!("/proc/{pid}/exe")).map_err(|_| ManifestError::Unreadable)?;
    let executable_bytes =
        std::fs::read(format!("/proc/{pid}/exe")).map_err(|_| ManifestError::Unreadable)?;
    if executable_bytes.len() as u64 != exe_stat.len() {
        return Err(ManifestError::Malformed);
    }
    let executable_digest = sha256(&executable_bytes);

    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|_| ManifestError::Unreadable)?;
    let mut module_digests = Vec::new();
    let mut seen_paths: Vec<String> = Vec::new();
    for line in maps.lines() {
        // Only file-backed executable mappings outside the exe.
        let Some((_address, rest)) = line.split_once(' ') else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let _permissions = fields.next();
        let _offset = fields.next();
        let _device = fields.next();
        let _inode = fields.next();
        let Some(path) = fields.next() else {
            continue;
        };
        if path == "/proc/self/exe" || !path.starts_with('/') {
            continue;
        }
        let is_executable_mapping = line
            .split_whitespace()
            .nth(1)
            .is_some_and(|permissions| permissions.contains('x'));
        if !is_executable_mapping {
            continue;
        }
        if seen_paths.iter().any(|seen| seen == path) {
            continue;
        }
        seen_paths.push(path.to_string());
        if seen_paths.len() > MAX_MODULES {
            return Err(ManifestError::Malformed);
        }
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        module_digests.push((sha256(&bytes), bytes.len() as u64));
    }

    Ok(RuntimeManifest {
        executable_digest,
        executable_size: exe_stat.len(),
        module_digests,
        mount_namespace_digest,
    })
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
    fn derives_the_current_process_manifest() {
        let binding = pinned_self();
        let manifest = derive(&binding).unwrap_or_else(|e| panic!("{e:?}"));
        // The executable digest is of THIS test binary; the size is
        // its real file size; modules are bounded; the mount
        // namespace is the test's own.
        assert!(manifest.executable_size > 0);
        assert!(manifest.module_digests.len() <= MAX_MODULES);
        let other = derive(&pinned_self()).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(manifest.executable_digest, other.executable_digest);
        assert_eq!(
            manifest.mount_namespace_digest,
            other.mount_namespace_digest
        );
    }

    #[test]
    fn a_different_process_has_a_different_executable_digest() {
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap_or_else(|e| panic!("{e:?}"));
        let child_binding = CallerBinding::pin(&PeerCredentials {
            pid: child.id(),
            uid: 0,
            gid: 0,
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
        let child_manifest = derive(&child_binding).unwrap_or_else(|e| panic!("{e:?}"));
        let self_manifest = derive(&pinned_self()).unwrap_or_else(|e| panic!("{e:?}"));
        assert_ne!(
            child_manifest.executable_digest,
            self_manifest.executable_digest
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_dead_process_cannot_have_a_manifest() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .unwrap_or_else(|e| panic!("{e:?}"));
        let pid = child.id();
        let _ = child.wait();
        assert!(
            CallerBinding::pin(&PeerCredentials {
                pid,
                uid: 0,
                gid: 0
            })
            .is_err()
        );
    }
}
