# OGIR domain glossary

This glossary defines domain language only. It does not describe modules, wire
encodings, cryptographic algorithms, implementation status, or delivery order.

## Appraisal Result

The verifier's unsigned semantic outcome for one relying-party-selected
context. It contains either accepted claims for an allowed outcome or one
coarse non-disciplinary reason for an unsuccessful outcome. It is not an
Attestation Result, permit, proof of possession, or protected-session admission.

## Attestation Result

The verifier-protected output consumed by a relying party. A trusted issuer
creates it only after independently establishing the appraisal outcome, then
binds that outcome to the appraised evidence, verifier identity, validity, and
integrity protection required by the selected protocol profile.

## Accepted claims

Claims that the verifier has appraised and is prepared to place in an allowed
outcome. Unsuccessful outcomes contain no accepted claims.

## Decision

The coarse outcome class: allow, allow restricted, deny, unsupported, or retry.
A Decision is a report and grants no authority.

## Reason code

Exactly one coarse, structured, non-disciplinary explanation attached to an
unsuccessful Appraisal Result. Allowed outcomes have no reason code. A reason
code contains no free text, raw evidence, or accusation of cheating.

## Verified Attestation

A proof that every verifier appraisal gate completed for one exact attempt. It
is not a protected Attestation Result or admission decision.

## Expected context

The publisher, game, build, account scope, match, and policy selected by the
relying party independently of client evidence. The same selected policy binds
both full and restricted allowed classes; restricted mode cannot substitute a
different policy after appraisal begins.

## Session public-key lookup handle

A non-authoritative reference to an ephemeral protected-session public key.
The relying party must resolve the actual key and validate fresh
transcript-bound proof of possession before admission.
