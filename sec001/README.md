# CALIBRE SECURITY SEC-001 — Owner-Bound Authorization Handoff

## Purpose

This is the first CALIBRE security-semantics experiment after freezing the performance-tuning phase.

The experiment asks whether the user key that signs a spend is actually bound to the owner recorded in the monetary input cells, and whether an upstream authorization decision can be handed to the fast state-only core through an exact transaction certificate.

## Tested path

1. Monetary cells store an Ed25519 owner public key.
2. A user signs a canonical spend message containing network/domain, transaction id, every input id+generation, output id, recipient, amount and expiry.
3. The authorization tier checks that every active input cell is owned by the signing key, checks the user signature and checks value conservation.
4. A trusted authorization certifier signs a BLAKE3 commitment to the exact authorized transaction and claimed user.
5. The state-only core verifies the trusted certificate, rechecks active input existence/generation/value conservation, consumes the input cells and creates the recipient output.

## Positive and negative cases

- Valid Alice-owned spend to Bob: must pass.
- Mallory signing Alice-owned cells: must fail.
- Recipient changed after Alice signs: must fail.
- Amount changed after Alice signs: must fail.
- Valid certificate replayed on a modified transaction: must fail.
- Certificate from an untrusted certifier: must fail.
- Replaying the same valid certificate after the cells were already consumed: must fail locally.

## Deliberate attack case

SEC-001 also demonstrates the current trust boundary: if the single certifier trusted by the fast core is itself malicious, it can sign a transaction that never passed user-ownership verification, and the core cannot distinguish that lie from an honest upstream authorization result.

This attack is EXPECTED to succeed in SEC-001 and is recorded as `ATTACK CONFIRMED`. It is not a regression in the local state engine; it proves that a production CALIBRE design cannot rely on one trusted authorization certifier.

The next security experiment must replace that single trust point with a Byzantine-resilient threshold/quorum authorization certificate and test conflicting/forged certificate safety.

## Claim discipline

SEC-001 does **not** prove distributed Byzantine safety, finality, crash persistence, WAN security or post-quantum security. It is an ownership-binding and certificate-handoff experiment only.
