// SPDX-License-Identifier: Apache-2.0

//! The integrity-change event stream (M7-043, ADR-0039): bounded,
//! redacted, per-session events for the changes the observation
// can actually see - the process exiting, the manifest drifting
// (a component changed), the cgroup moving (a deployment change),
// and the tree restructuring (a parent changed). Events are the
// REDACTED layer only (ADR-0037): digests, pids, start times.
//! RENEWAL INVALIDATION: any event after a permit's issuance means
//! the observed world changed - renewal must re-verify rather than
//! extend. NO ENFORCEMENT CLAIM: events report; M8 decides.

/// The event kinds (wire-stable spellings).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// The observed process exited.
    ProcessExited,
    /// The runtime manifest changed (executable or module set).
    ManifestDrift,
    /// The cgroup path digest changed (a deployment move).
    CgroupMoved,
    /// The process tree changed (a parent's pid/start differ).
    TreeChanged,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcessExited => "process-exited",
            Self::ManifestDrift => "manifest-drift",
            Self::CgroupMoved => "cgroup-moved",
            Self::TreeChanged => "tree-changed",
        }
    }
}

/// One integrity-change event: the kind, the session identity
/// digest, a monotonic sequence number, and the BEFORE/AFTER state
/// digests (never the observations themselves).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityEvent {
    pub kind: EventKind,
    pub session: [u8; 32],
    pub sequence: u64,
    pub before: [u8; 32],
    pub after: [u8; 32],
}

/// The bounded per-session event log. Oldest events drop when the
/// bound is hit (the log is a rolling diagnostic, not a ledger).
#[derive(Debug)]
pub struct EventLog {
    session: [u8; 32],
    events: std::collections::VecDeque<IntegrityEvent>,
    sequence: u64,
    bound: usize,
}

/// The default per-session bound (the portal framing scale).
pub const DEFAULT_EVENT_BOUND: usize = 64;

/// Event-stream failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventError {
    /// The event belongs to a different session.
    WrongSession,
}

impl std::fmt::Display for EventError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongSession => formatter.write_str("event belongs to a different session"),
        }
    }
}

impl std::error::Error for EventError {}

impl EventLog {
    pub fn new(session: [u8; 32]) -> Self {
        Self::with_bound(session, DEFAULT_EVENT_BOUND)
    }

    pub fn with_bound(session: [u8; 32], bound: usize) -> Self {
        Self {
            session,
            events: std::collections::VecDeque::new(),
            sequence: 0,
            bound: bound.max(1),
        }
    }

    /// Records one change. The kind is the CALLER's diagnosis (the
    /// diff helpers below); this function only sequences and bounds.
    pub fn record(
        &mut self,
        kind: EventKind,
        before: [u8; 32],
        after: [u8; 32],
    ) -> Result<u64, EventError> {
        self.sequence += 1;
        let sequence = self.sequence;
        self.events.push_back(IntegrityEvent {
            kind,
            session: self.session,
            sequence,
            before,
            after,
        });
        while self.events.len() > self.bound {
            self.events.pop_front();
        }
        Ok(sequence)
    }

    /// The events in sequence order (a snapshot copy).
    pub fn events(&self) -> Vec<IntegrityEvent> {
        self.events.iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Whether any event occurred at or after `sequence` - the
    /// RENEWAL INVALIDATION check: a permit issued at sequence S
    /// cannot renew through a stream that moved past S.
    pub fn changed_since(&self, sequence: u64) -> bool {
        self.sequence > sequence
    }
}

/// Diagnoses the change between two observations of the SAME
/// session (identity-checked by the caller): the kind of the first
/// difference, in a fixed precedence (exit > manifest > cgroup >
/// tree). None means no drift.
pub fn diagnose(
    before: &crate::observation::ObservedSession,
    after: &crate::observation::ObservedSession,
) -> Option<EventKind> {
    if before.identity.pid != after.identity.pid {
        // Different processes are not drift; callers refresh with
        // identity checks. Defensive: treat as tree change.
        return Some(EventKind::TreeChanged);
    }
    if before.state != after.state {
        // Narrow the diagnosis for the wire.
        if before.manifest != after.manifest {
            return Some(EventKind::ManifestDrift);
        }
        if before.context.cgroup_path_digest != after.context.cgroup_path_digest {
            return Some(EventKind::CgroupMoved);
        }
        if before.tree != after.tree {
            return Some(EventKind::TreeChanged);
        }
        return Some(EventKind::ManifestDrift);
    }
    None
}

/// The renewal-decision contract: a permit issued at event sequence
/// S may renew only when the stream is unchanged since S AND the
/// session still observes identically. Any event invalidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalDecision {
    /// The stream is quiet: renewal may proceed to full
    /// re-verification (this is the gate, not the grant).
    MayReverify,
    /// Events occurred since the permit: renewal must RE-ESTABLISH,
    /// not extend.
    MustReestablish,
}

/// The renewal gate over an event log.
pub fn renewal_gate(log: &EventLog, permit_sequence: u64) -> RenewalDecision {
    if log.changed_since(permit_sequence) {
        RenewalDecision::MustReestablish
    } else {
        RenewalDecision::MayReverify
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_log_sequences_and_bounds() {
        let mut log = EventLog::with_bound([1u8; 32], 4);
        for index in 0..10 {
            let sequence = log
                .record(EventKind::ManifestDrift, [index; 32], [index + 1; 32])
                .unwrap_or_else(|e| panic!("{e:?}"));
            assert_eq!(sequence, index as u64 + 1);
        }
        assert_eq!(log.len(), 4, "the bound drops the oldest");
        let events = log.events();
        assert_eq!(events[0].sequence, 7, "the oldest surviving");
        assert_eq!(events[3].sequence, 10, "the newest");
        assert_eq!(events[0].session, [1u8; 32]);
    }

    #[test]
    fn changed_since_is_the_renewal_gate() {
        let mut log = EventLog::new([2u8; 32]);
        assert_eq!(renewal_gate(&log, 0), RenewalDecision::MayReverify);
        log.record(EventKind::ProcessExited, [0; 32], [1; 32])
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(renewal_gate(&log, 0), RenewalDecision::MustReestablish);
        // A permit issued AFTER the event renews until the next one.
        assert_eq!(renewal_gate(&log, 1), RenewalDecision::MayReverify);
        log.record(EventKind::CgroupMoved, [1; 32], [2; 32])
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(renewal_gate(&log, 1), RenewalDecision::MustReestablish);
    }

    #[test]
    fn empty_logs_are_quiet() {
        let log = EventLog::new([3u8; 32]);
        assert!(log.is_empty());
        assert!(!log.changed_since(0));
    }

    #[test]
    fn the_wire_spellings_are_stable() {
        assert_eq!(EventKind::ProcessExited.as_str(), "process-exited");
        assert_eq!(EventKind::ManifestDrift.as_str(), "manifest-drift");
        assert_eq!(EventKind::CgroupMoved.as_str(), "cgroup-moved");
        assert_eq!(EventKind::TreeChanged.as_str(), "tree-changed");
    }
}
