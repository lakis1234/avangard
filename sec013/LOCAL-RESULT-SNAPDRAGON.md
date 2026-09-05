# CALIBRE SECURITY SEC-013 — LOCAL SNAPDRAGON ARM64 RESULT

Platform: Windows 11 ARM64 / Snapdragon X Plus development machine
Experiment: `calibre-sec013 v0.13.0`

## Local result

- Unit tests: 5/5 PASS
- Old committee epoch 12: N=7, Q=5
- New committee epoch 13: N=7, Q=5
- Old/new key sets: deliberately disjoint / zero membership overlap
- Seven old + seven new OS certifier processes over real TCP loopback
- Finalized old-epoch input handoff: new committee activates 5/7; conflicting successor gets 0 honest votes — PASS
- Locked old-epoch state handoff: inherited digest 5/7; conflicting digest 0 honest votes — PASS
- f<=2 conflicting old handoff: first certificate 5/7; conflicting certificate only 4/7; restarted honest signer remembers prior handoff choice — PASS
- Insufficient old handoff 4/7: new honest activation shares 0 — PASS
- Wrong target-epoch handoff: cryptographically valid old certificate rejected by epoch-13 new committee — PASS
- New activation split 3/7: no activation QC; after heal same handoff reaches 5/7 and inherited state continues — PASS
- New committee process restart: durable activation survives; inherited digest accepted and conflict rejected — PASS
- f=3 boundary: two conflicting old-committee 5-of-7 handoff certificates produced — ATTACK CONFIRMED / EXPECTED

## Decision

`ZERO-OVERLAP OLD->NEW COMMITTEE HANDOFF WITH 5/7 OLD CERT + 5/7 NEW ACTIVATION: PASS IN TESTED LOCAL SCENARIOS`

`FINALIZED MONETARY INPUT CANNOT BE REVIVED BY NEW COMMITTEE: PASS`

`INHERITED OLD-EPOCH QC LOCK CONSTRAINS NEW-EPOCH VOTES TO SAME DIGEST: PASS`

`F<=2 CONFLICTING HANDOFF CERTIFICATE SAFETY + OLD-SIGNER RESTART MEMORY: PASS`

`INSUFFICIENT / WRONG-EPOCH HANDOFF REJECTION: PASS`

`NEW-COMMITTEE ACTIVATION PAUSES BELOW QUORUM AND RECOVERS AFTER HEAL: PASS`

`F=3 OLD-COMMITTEE HANDOFF SAFETY: FAIL AT EXPECTED 5-OF-7 QUORUM BOUNDARY / ATTACK CONFIRMED`

## Claim limits

This is a local multi-process TCP experiment, not a formal proof of dynamic reconfiguration. Physical multi-machine/WAN behavior, arbitrary asynchronous reconfiguration liveness, multi-epoch long-range replay resistance, production membership selection, Sybil resistance, power-loss durability, malicious storage snapshot rollback resistance, and production finality remain unproven.
