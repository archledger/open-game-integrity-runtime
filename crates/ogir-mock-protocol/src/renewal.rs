// SPDX-License-Identifier: Apache-2.0

//! Test-only renewal fencing per ADR-0014: one logical session owner, at
//! most one committed successor per predecessor, idempotent exact
//! redelivery of the committed artifact, and no authorization from a
//! pending request. The owner tracks bytes and fencing only; callers
//! verify signatures before installation.

/// Why a renewal transition failed. Non-disciplinary and deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalError {
    /// A pending renewal already exists for the current permit.
    PendingExists,
    /// The presented predecessor is not the currently installed permit.
    PredecessorNotCurrent,
    /// A different successor was already committed for this predecessor.
    DifferentSuccessorForPredecessor,
}

impl std::fmt::Display for RenewalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PendingExists => formatter.write_str("a pending renewal already exists"),
            Self::PredecessorNotCurrent => {
                formatter.write_str("predecessor is not the installed permit")
            }
            Self::DifferentSuccessorForPredecessor => {
                formatter.write_str("predecessor already fenced to a different successor")
            }
        }
    }
}

impl std::error::Error for RenewalError {}

/// The outcome of an installation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// A new successor was fenced and installed.
    New,
    /// The exact committed pair was redelivered; acknowledged idempotently
    /// with no re-authorization.
    IdempotentRedelivery,
}

/// One logical session-authorization owner for an exact
/// publisher/protected-session context (ADR-0014 obligation, mock form).
#[derive(Debug, Clone)]
pub struct MockSessionOwner {
    current: Vec<u8>,
    generation: u64,
    pending: Option<Vec<u8>>,
    committed: Vec<(Vec<u8>, Vec<u8>)>,
}

impl MockSessionOwner {
    /// Creates an owner over the initially installed permit bytes.
    pub fn new(current: Vec<u8>) -> Self {
        Self {
            current,
            generation: 0,
            pending: None,
            committed: Vec::new(),
        }
    }

    /// The currently installed permit bytes.
    pub fn current(&self) -> &[u8] {
        &self.current
    }

    /// The installed generation; zero until a successor commits.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The pending successor, if any. Pending grants nothing.
    pub fn pending(&self) -> Option<&[u8]> {
        self.pending.as_deref()
    }

    /// Stages one pending renewal against the current permit. At most one
    /// pending successor may exist; a pending request never installs.
    pub fn stage_pending(
        &mut self,
        predecessor: &[u8],
        successor: &[u8],
    ) -> Result<(), RenewalError> {
        if self.pending.is_some() {
            return Err(RenewalError::PendingExists);
        }
        if predecessor != self.current.as_slice() {
            return Err(RenewalError::PredecessorNotCurrent);
        }
        self.pending = Some(successor.to_vec());
        Ok(())
    }

    /// Installs a successor fenced against its exact live predecessor.
    /// At most one successor commits per predecessor; exact redelivery of
    /// the committed pair is idempotent; any different successor for an
    /// already-fenced predecessor rejects.
    pub fn install_successor(
        &mut self,
        predecessor: &[u8],
        successor: &[u8],
    ) -> Result<InstallOutcome, RenewalError> {
        if let Some((_committed_predecessor, committed_successor)) = self
            .committed
            .iter()
            .find(|(committed, _)| committed.as_slice() == predecessor)
        {
            if committed_successor.as_slice() == successor {
                return Ok(InstallOutcome::IdempotentRedelivery);
            }
            return Err(RenewalError::DifferentSuccessorForPredecessor);
        }
        if predecessor != self.current.as_slice() {
            return Err(RenewalError::PredecessorNotCurrent);
        }
        self.committed
            .push((predecessor.to_vec(), successor.to_vec()));
        self.current = successor.to_vec();
        self.generation += 1;
        if self.pending.as_deref() == Some(successor) {
            self.pending = None;
        }
        Ok(InstallOutcome::New)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_successor_commits_then_idempotent_redelivery() {
        let mut owner = MockSessionOwner::new(vec![1]);
        assert_eq!(owner.install_successor(&[1], &[2]), Ok(InstallOutcome::New));
        assert_eq!(owner.generation(), 1);
        assert_eq!(owner.current(), &[2]);
        assert_eq!(
            owner.install_successor(&[1], &[2]),
            Ok(InstallOutcome::IdempotentRedelivery)
        );
        assert_eq!(owner.generation(), 1);
    }

    #[test]
    fn different_successor_for_fenced_predecessor_rejects() {
        let mut owner = MockSessionOwner::new(vec![1]);
        assert_eq!(owner.install_successor(&[1], &[2]), Ok(InstallOutcome::New));
        assert_eq!(
            owner.install_successor(&[1], &[3]),
            Err(RenewalError::DifferentSuccessorForPredecessor)
        );
        assert_eq!(owner.current(), &[2]);
    }

    #[test]
    fn stale_predecessor_rejects_and_pending_is_unique() {
        let mut owner = MockSessionOwner::new(vec![1]);
        assert_eq!(owner.stage_pending(&[1], &[2]), Ok(()));
        assert_eq!(
            owner.stage_pending(&[1], &[3]),
            Err(RenewalError::PendingExists)
        );
        assert_eq!(
            owner.install_successor(&[0], &[3]),
            Err(RenewalError::PredecessorNotCurrent)
        );
        assert_eq!(owner.install_successor(&[1], &[2]), Ok(InstallOutcome::New));
        assert_eq!(owner.pending(), None);
        assert_eq!(
            owner.stage_pending(&[9], &[3]),
            Err(RenewalError::PredecessorNotCurrent)
        );
    }

    #[test]
    fn pending_grants_nothing_it_is_not_the_current_permit() {
        let mut owner = MockSessionOwner::new(vec![1]);
        assert_eq!(owner.stage_pending(&[1], &[2]), Ok(()));
        assert_eq!(owner.pending(), Some(&[2][..]));
        assert_eq!(owner.current(), &[1]);
        assert_eq!(owner.generation(), 0);
    }
}
