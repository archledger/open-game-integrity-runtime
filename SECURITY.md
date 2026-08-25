# Security policy

## Experimental status

OGIR is experimental research software and must not be used to authorize production ranked matches, issue player bans, protect production signing keys, or make claims of complete cheat prevention.

## Reporting a vulnerability

Do **not** open a public issue for a suspected vulnerability.

Use GitHub's private vulnerability reporting or a private draft security advisory for this repository. Include:

- affected commit or release;
- attacker prerequisites;
- precise reproduction steps;
- expected and observed behavior;
- security invariant violated;
- proof-of-concept material that is safe to share;
- suggested mitigations, when known.

Do not include real player data, production publisher credentials, TPM endorsement secrets, or unrelated personal information.

## Initial response policy

Until a formal security response team exists, maintainers will triage privately, preserve reporter attribution preferences, avoid public disclosure before a fix is available, and add a permanent regression test for every confirmed defect.

## No automatic player enforcement

An OGIR failure or vulnerability report must never directly trigger a player ban. Security triage, attestation eligibility, and disciplinary decisions are separate processes.
