# CALIBRE SECURITY SEC-009 — CI RESULT

GitHub Actions workflow run: `33939951448`
Commit: `baf6970f689abda828036e351737a6b227123813`
Platform: GitHub Actions Windows Server 2025

## Configuration

- N = 7
- Q = 5
- target Byzantine bound f <= 2
- seven separate certifier OS processes
- real TCP loopback sockets
- real Ed25519 user, proposal, PREVOTE, and PRECOMMIT signatures
- 96-byte checksummed durable lock records with `sync_all()` before an honest PRECOMMIT share
- conflict-local round numbers and deterministic per-conflict proposer schedule
- no blockchain, blocks, DAG, or universal transaction order

## Results

- Unit tests: 4/4 PASS
- Reconstructed 3/2 tentative PREVOTE split: A=3/7, B=2/7, no QC and therefore no safety lock
- Later conflict-local round: 5/7 PREVOTE QC + 5/7 PRECOMMIT QC, deadlock resolved
- Conflicting higher-round Byzantine proposal without valid justification: honest votes 0, Byzantine votes 2, cannot reach quorum
- Partial lock case: three honest PRECOMMIT locks followed by a QC-carrying later round finalizes 5/7
- Logical 4/3 partition: no QC; after heal a new conflict-local round finalizes 5/7
- f=3 boundary: two conflicting 5/7 PRECOMMIT QCs produced under Byzantine equivocation, attack confirmed as expected

## Decision

`SEC-008 3/2 FIRST-SEEN DEADLOCK RESOLVED BY CONFLICT-LOCAL ROUND CHANGE: PASS IN TESTED SCHEDULE`

`FIRST-SEEN PREVOTE IS TENTATIVE; SAFETY LOCK REQUIRES 5-OF-7 PREVOTE QC: IMPLEMENTED`

`FINALITY REQUIRES 5-OF-7 PRECOMMIT QC AFTER NODES HAVE SEEN A VALID PREVOTE QC: IMPLEMENTED`

`LOCKED HONEST NODES REJECT CONFLICTING HIGHER-ROUND PROPOSAL WITHOUT VALID HIGHER JUSTIFICATION: PASS`

`F=3 SAFETY: FAIL AT EXPECTED 5-OF-7 QUORUM BOUNDARY / ATTACK CONFIRMED`

## Claim limits

This is a protocol candidate and tested state machine, not a formal Byzantine consensus proof. The initial 3/2 split is deliberately reconstructed by the test harness as conflicting tentative proposals/votes to reproduce SEC-008's deadlock condition; it should not be interpreted as proof that an honest proposer would equivocate. Physical multi-machine/WAN operation, arbitrary asynchronous-network liveness, kernel-level network faults, power-loss durability, malicious storage rollback resistance, committee rotation, Sybil resistance, and production finality remain unproven.
