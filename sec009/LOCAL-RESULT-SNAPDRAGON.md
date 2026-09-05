# CALIBRE SECURITY SEC-009 — LOCAL SNAPDRAGON ARM64 RESULT

Platform: Windows 11 ARM64 / Snapdragon X Plus development machine
Experiment: `calibre-sec009 v0.9.0`

## Local result

- Unit tests: 4/4 PASS
- Seven separate certifier OS processes over real `127.0.0.1` TCP
- Round 0 tentative split: A=3/7, B=2/7, no QC, no permanent safety lock
- Round 1 deterministic conflict-local proposer: PREVOTE QC 5/7 + PRECOMMIT QC 5/7, deadlock resolved
- Higher-round Byzantine conflicting proposal without valid justification: honest votes 0, Byzantine votes 2, no quorum
- Partial PRECOMMIT lock (3 honest) followed by QC-carrying round change: next round finalizes 5/7
- 4/3 logical partition: no QC; after heal a new conflict-local round finalizes 5/7
- f=3 boundary: two conflicting 5/7 PRECOMMIT QCs created under Byzantine equivocation, attack confirmed as expected

## Decision

`SEC-008 3/2 FIRST-SEEN DEADLOCK RESOLVED BY CONFLICT-LOCAL ROUND CHANGE: PASS IN TESTED LOCAL SCHEDULE`

`FIRST-SEEN PREVOTE IS TENTATIVE; SAFETY LOCK REQUIRES 5-OF-7 PREVOTE QC: IMPLEMENTED`

`FINALITY REQUIRES 5-OF-7 PRECOMMIT QC AFTER VALID PREVOTE QC: IMPLEMENTED`

`LOCKED HONEST NODES REJECT CONFLICTING HIGHER-ROUND PROPOSAL WITHOUT VALID HIGHER JUSTIFICATION: PASS`

`PARTIAL LOCK + QC-CARRYING ROUND CHANGE RECOVERS LIVENESS: PASS`

`4/3 PARTITION SAFETY + POST-HEAL LIVENESS RECOVERY: PASS IN TESTED SCHEDULE`

`F=3 SAFETY: FAIL AT EXPECTED 5-OF-7 QUORUM BOUNDARY / ATTACK CONFIRMED`

No blockchain, blocks, DAG, or universal transaction order is used by this experiment. Coordination is scoped to a single conflicting monetary input/generation.

## Claim limits

This is still one physical host with seven OS processes and TCP loopback. It is not a formal Byzantine consensus proof and does not prove arbitrary asynchronous-network liveness, physical multi-machine/WAN operation, kernel-level packet loss, power-loss durability, malicious storage rollback resistance, committee rotation, Sybil resistance, or production finality.
