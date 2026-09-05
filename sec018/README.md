# CALIBRE SECURITY SEC-018 — Attested Monotonic Generation Protocol Gate

SEC-017 demonstrated that deleting a named TPM key can reject fresh open-by-name attempts while a cross-process handle opened before deletion remains capable of signing a new nonce. SEC-018 tests the protocol rule needed so that possession of that old signing capability is not enough to create an accepted freshness share.

This version is deliberately a **non-destructive model**, not a live TPM NV claim. It does not define, increment, certify, or delete a TPM NV index. It models the exact evidence that a later isolated-vTPM or sacrificial-hardware experiment must obtain from `TPM2_NV_Increment` and `TPM2_NV_Certify`.

## Candidate rule

Every accepted freshness share must contain both:

1. a committee signing-key signature over the exact epoch, monetary state, generation, and client nonce; and
2. a pinned-attestation-key signature over the exact NV-index Name, current monotonic generation, and a qualifying-data digest binding the same epoch, state, generation, and client nonce.

The verifier rejects the combined share unless the attested NV generation equals the claimed monetary-state generation and the NV Name and attestation key match values pinned for that validator.

## Configuration

- N = 7, Q = 5
- retired generation 70; active generation 71
- seven separate OS processes over real TCP loopback on one physical host
- nodes 0..4 model honest devices whose monotonic generation advanced to 71
- nodes 5..6 model Byzantine devices left at generation 70
- all seven old signing handles remain deliberately usable after retirement
- deterministic Ed25519 keys stand in for committee keys and pinned TPM attestation keys
- no blockchain, blocks, DAG, or universal transaction order

## Attacks tested

1. Before retirement, generation-70 state obtains 7/7 valid combined shares.
2. After retirement, all seven retained old handles still sign generation-70 state, but five honest devices attest generation 71. Only the two Byzantine generation-70 devices produce acceptable combined shares: 2/7, below quorum.
3. Five honest current devices produce 5/7 valid generation-71 combined shares.
4. An old certificate replayed under a new client nonce is rejected.
5. A generation-71 attestation cannot be mixed with a generation-70 monetary signature.
6. A proof under the wrong NV-index Name is rejected.
7. Restoring generation-70 application state does not decrease the modeled monotonic generation and remains below quorum.
8. If three honest pinned attestation keys are compromised, their forged generation-70 proofs plus the two Byzantine shares form 5/7. This is the expected trust-boundary attack witness.

## Required interpretation

A successful run may say:

`OLD PRE-OPENED SIGNING HANDLES WITHOUT MATCHING CURRENT-GENERATION ATTESTATION: REJECTED BELOW 5/7 IN TESTED MODEL`

It must also say:

`LIVE TPM NV MONOTONICITY / NV_CERTIFY / AK PROPERTIES: NOT TESTED`

and:

`THREE PINNED ATTESTATION KEYS COMPROMISED: 5/7 STALE ATTACK CONFIRMED`

## Safety and claim limits

This experiment proves only the protocol acceptance logic and adversarial threshold arithmetic. Its attestation signatures are software Ed25519 model signatures. It does not prove TPM NV command availability, true monotonic persistence, `TPM2_NV_Certify` parsing, attestation-key `fixedTPM`/`fixedParent` attributes, hardware key non-exportability, resistance to TPM clear or NV undefine/redefine, power-loss atomicity, or same-device rollback resistance.

The next live stage must use an isolated vTPM/VHD or sacrificial test machine. It must pin both the attestation-key identity and NV-index Name, bind the client nonce through `qualifyingData`, verify the returned TPM attestation structure and signature, and avoid the user's PCR7/BitLocker-bound daily-use TPM.

No TPM clear, PCR write, NV write, hierarchy change, Secure Boot change, BitLocker change, or existing-key operation is performed by SEC-018 v0.18.0.

## Standards basis

- TCG TPM 2.0 Library Part 3, section 31.2 defines an NV counter as monotonic and updateable only through `TPM2_NV_Increment`.
- TCG TPM 2.0 Library Part 3, section 31.16 defines `TPM2_NV_Certify`, including caller-supplied `qualifyingData`, the NV index being certified, the returned attestation structure, and its signature.

SEC-018 models those semantics but does not claim to execute either TPM command.
