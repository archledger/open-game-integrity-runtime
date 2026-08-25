# M1-009: Implement the local protected-session state machine
<!-- labels: type: implementation,area: model,area: session,risk: trusted-computing-base,status: ready -->
<!-- milestone: M1 Domain Model -->

## Problem

A session must not skip caller binding, policy preparation, evidence creation, permit receipt, or cleanup gates. Ad hoc booleans make invalid transitions difficult to detect.

## Security invariants

- Evidence cannot be created before caller binding and session preparation.
- A session cannot become active without a verifier-issued permit.
- Ended or invalidated sessions cannot renew or reactivate.
- Cleanup is required from every terminal path.

## In scope

- Implement a pure, deterministic state machine with typed transition methods.
- Define terminal states and structured transition errors.
- Add model/property tests for all valid and invalid transitions.
- Keep I/O, async, TPM, and process operations outside the state machine.

## Out of scope

- Cgroup creation.
- TPM evidence.
- Network transport.
- Actual policy enforcement.

## Required tests

- Enumerate every allowed transition.
- Attempt every one-step invalid transition.
- Random action sequences never reach Active without the required gates.
- End/invalidated states remain terminal.
- Error debug output contains no challenge or account secret.

## Acceptance criteria

- The state graph matches `docs/ROADMAP.md` and `docs/ARCHITECTURE.md`.
- Public APIs make skipped gates unrepresentable or return deterministic errors.
- State-machine crate remains dependency-light and side-effect free.
