# CALIBRE SECURITY SEC-013 — CI RESULT

GitHub Actions workflow run: `33941873296`
Commit: `31fabc0fbc9ede6e595d8cb48c340bb7482abfc7`
Platform: GitHub Actions Windows Server 2025

## Configuration

- old committee epoch 12: N=7, Q=5
- new committee epoch 13: N=7, Q=5
- target Byzantine bound f<=2
- old and new committee key sets deliberately disjoint
- seven old + seven new OS certifier processes
- real TCP loopback sockets
- durable old handoff choice and durable new activation choice with `sync_all()` before signatures
- 5-of-7 old handoff certificate + 5-of-7 new activation certificate
- no blockchain, blocks, DAG, or universal transaction order

## Results

- Unit tests: 5/5 PASS
- Finalized old-epoch input handoff: new committee activates 5/7; conflicting successor receives 0 honest new-committee votes
- Locked old-epoch handoff: inherited digest receives 5/7 honest new votes; conflicting digest receives 0 honest votes
- f<=2 conflicting old handoff: first handoff reaches 5/7; conflicting handoff reaches only 4/7
- old honest signer crash/restart preserves prior handoff choice
- insufficient 4/7 old handoff receives 0 honest new activation shares
- cryptographically valid handoff to wrong target epoch is rejected by epoch-13 honest new nodes
- new activation split 3/7 does not activate; after heal the same handoff reaches 5/7 and inherited state continues
- new honest activation survives process crash/restart
- f=3 old-committee boundary: two conflicting 5-of-7 handoff certificates produced, attack confirmed as expected

## Decision

`ZERO-OVERLAP OLD->NEW COMMITTEE HANDOFF WITH 5/7 OLD CERT + 5/7 NEW ACTIVATION: PASS IN TESTED SCENARIOS`

`FINALIZED MONETARY INPUT CANNOT BE REVIVED BY NEW COMMITTEE: PASS`

`INHERITED OLD-EPOCH QC LOCK CONSTRAINS NEW-EPOCH VOTES TO SAME DIGEST: PASS`

`F<=2 CONFLICTING HANDOFF CERTIFICATE SAFETY + OLD-SIGNER RESTART MEMORY: PASS`

`INSUFFICIENT / WRONG-EPOCH HANDOFF REJECTION: PASS`

`NEW-COMMITTEE ACTIVATION PAUSES BELOW QUORUM AND RECOVERS AFTER HEAL: PASS`

`F=3 OLD-COMMITTEE HANDOFF SAFETY: FAIL AT EXPECTED 5-OF-7 QUORUM BOUNDARY / ATTACK CONFIRMED`

## Claim limits

This is a local multi-process TCP experiment, not a formal proof of dynamic reconfiguration. It does not prove physical multi-machine/WAN behavior, arbitrary asynchronous reconfiguration liveness, production membership selection, Sybil resistance, power-loss durability, malicious storage snapshot rollback resistance, or production finality.
