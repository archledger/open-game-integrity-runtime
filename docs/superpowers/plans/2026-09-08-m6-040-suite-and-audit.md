# M6-040 plan: the attack suite and the M6 exit audit

Date: 2026-09-08
Agent: zcode
Authorization: standing publication+merge authorization; all gates
mandatory.

## Objective

Close Milestone M6: consolidate the ten attack categories into the
house inventory over the real stack, then audit the three exit
criteria.

## Steps

1. Worktree research/m6-040-suite-and-audit from 2691fec.
2. The suite: real TCP, serve_one with the full backend, the
   threaded-server pattern from M6-037; re-host the focused legs.
3. The exit audit against the three criteria with honest
   limitations.
4. ADR-0036, index row, the M6-closing ROADMAP boundary, planning
   issue, plan.
5. House gates, signed commit, publication, CI, merge,
   post-merge verification; then the issue dispositions.

## Development notes

- std's TcpListener exposes local_addr (not local_address), and
  accept() returns (stream, address) - destructure.
- The threaded server must serve EXACTLY the connections the test
  makes: count EVERY post() (issue_and_answer alone costs two);
  a short count surfaces as a client ConnectionRefused panic, not
  a logic failure.
- cat03's corrupted-signature challenge goes through the
  simulator too (it signs whatever it receives) - the BACKEND's
  challenge validation is the rejection point.

## Boundaries

In: the suite, the audit, ADR-0036, docs.
Out: M7+; the production-side end-to-end.
