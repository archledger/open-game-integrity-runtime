# Privacy model

OGIR applies data minimization at the protocol boundary.

## Allowed information classes

- publisher/game/build/match identifiers already known to the publisher;
- selected integrity policy identifier;
- accepted profile identifiers and digests;
- TPM-backed freshness and measurement evidence;
- publisher-scoped attestation identity;
- game/runtime/session manifest digests;
- structured policy outcomes;
- short-lived session public key.

## Disallowed information classes

- complete system process list;
- names of unrelated applications;
- browser, chat, document, or home-directory content;
- unrelated file paths;
- raw biometric samples or templates;
- universal cross-publisher device identifier;
- raw TPM Endorsement Key as a game identifier;
- arbitrary publisher-selected host queries;
- persistent global monitoring after the game session.

## Controls

- fixed claim schema;
- local maximum-disclosure policy;
- publisher-scoped Attestation Keys;
- hashed or abstracted accepted-profile results where possible;
- redacted local logging;
- short retention periods;
- user-visible policy before protected mode;
- session-scoped enforcement and cleanup;
- privacy tests that fail when forbidden fields appear.
