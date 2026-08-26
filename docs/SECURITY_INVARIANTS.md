# Security invariants

These invariants are release-blocking. A change that weakens one requires a public architecture decision, threat-model update, explicit versioning, and new adversarial tests.

## Authorization

1. A local boolean, DLL return value, file, registry key, environment variable, or process claim can never authorize a protected match.
2. Only a publisher-controlled verifier may produce an accepted Attestation Result.
3. Every permit is short-lived and bound to one publisher, game, build, account scope, policy, match, and session public key.
4. Every protected-session admission requires proof of possession of the bound private session key.
5. A challenge, evidence bundle, Attestation Result, or permit cannot validate for a different session.
6. Revoked or below-minimum protocol, policy, agent, verifier, platform, game, or runtime versions fail closed for the requested protected mode.

## Freshness and replay

7. The publisher-controlled issuer generates a fresh cryptographically random nonce and durably registers its challenge before returning it.
8. A challenge is eligible only during its exact publisher-verifier window `[issued_at, expires_at)`, and only the ordered verifier context/claim path can create the single freshness capability for `(PublisherId, Nonce)` in any context.
9. Every authoritative time observation durably advances/checks the verifier-time high-water mark before later window or context rejection; the floor and issued/consumed replay state survive restart, while rollback, missing/corrupt/unavailable state, or capacity exhaustion fails closed without stateless fallback or unexpired-record eviction.
10. Evidence and permits have explicit issued-at and expiry values; renewal requires a fresh challenge and cannot silently downgrade policy.

## Caller and session identity

11. Caller-controlled PID, path, App ID, build ID, prefix, and environment values are never authoritative.
12. The portal derives caller identity from kernel-provided credentials and race-resistant process handles.
13. The attested game/runtime/session manifest is independently derived by trusted local components.
14. Process identity includes a start-time or equivalent anti-reuse property.
15. Session policy applies only to the intended game process tree and is removed at session end.

## TPM and evidence

16. Games cannot submit arbitrary commands to the physical TPM.
17. Raw Windows TPM compatibility terminates at an isolated virtual TPM.
18. The TPM Endorsement Key is not exposed as a universal game identifier.
19. Publisher-scoped attestation identities are used where practical.
20. Hardware-certified, measured-log-derived, and trusted-agent-observed claims are distinguished.
21. The daemon never signs caller-supplied security claims without independently deriving or verifying them.
22. Evidence logs are validated against TPM-certified rolling state; a log file is never trusted by itself.

## Parsing and protocol

23. Every untrusted parser has fixed limits for total bytes, nesting, fields, strings, collections, and processing time.
24. Signed encodings are canonical and reject duplicate or ambiguous security-critical fields.
25. Unknown critical fields fail closed.
26. Malformed input can never produce an allow result.
27. Parser disagreement between conforming implementations is release-blocking.
28. No raw Windows pointer or unchecked length crosses the Wine/Unix boundary.

## Privilege

29. The Windows bridge and portal run without system privilege.
30. The privileged service has a minimal fixed operation set and no plugin, scripting, shell, arbitrary-file, arbitrary-BPF, or arbitrary-command interface.
31. Privileged operations are authorized against the authenticated caller, signed challenge, and selected local policy.
32. Safe Rust is the default; new `unsafe` or C code requires explicit isolation and review.
33. A game cannot install, replace, downgrade, or configure the trusted daemon silently.

## Privacy

34. A publisher request cannot expand the fixed evidence claim vocabulary.
35. Unrelated process lists, personal files, browser/chat activity, and biometric material are outside the protocol.
36. Stable identifiers are scoped to the publisher where possible.
37. Logs and default diagnostics redact secrets, home paths, raw evidence identities, session keys, and complete challenge/replay bindings and timing; explicit value access remains confined to trusted functional code.
38. Evidence and verifier authorization-state retention are minimal and declared; replay records end at challenge expiry and issuance-rate events end with their enforcement window unless a separately approved finite retention purpose applies.

## Failure and enforcement

39. Attestation failure is not automatically evidence of cheating.
40. Unsupported, revoked, unavailable, transient, and policy-denied outcomes remain distinguishable.
41. Loss of required enforcement prevents permit renewal.
42. The server does not trust a local notification that enforcement remains active; continued authorization depends on fresh evidence.
43. Session restrictions cannot persist beyond the protected session except for explicit system policy already controlled by the user.

## Supply chain

44. Release artifacts are traceable to reviewed source and build instructions.
45. CI workflows use least privilege and immutable action references.
46. One compromised maintainer, online key, or CI credential must not be able to replace every trust root in a mature release process.
47. Every confirmed security defect receives a permanent regression test.
48. AI-generated or AI-assisted output receives the same provenance, review, test, and licensing scrutiny as human-written code.
