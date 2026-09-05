# CALIBRE SECURITY SEC-010 — CI RESULT

GitHub Actions workflow run: `33940490361`
Commit: `6e6db40f81ef50914ed3cb9406b013d592d93697`
Platform: GitHub Actions Windows Server 2025

## Configuration

- N = 7
- Q = 5
- target Byzantine bound f <= 2
- seven separate OS certifier processes over real TCP loopback
- 250 randomized conflict trials
- deterministic conflict-local leader rotation covering all seven leaders within seven rounds
- real Ed25519 user/proposal/PREVOTE/PRECOMMIT signatures
- durable same-round PREVOTE and PRECOMMIT records with checksummed WAL and `sync_all()`
- PRECOMMIT records also persist the current safety lock
- no blockchain, blocks, DAG, or universal transaction order

## Results

- Unit tests: 5/5 PASS
- Reconstructed Byzantine-leader 3/2 tentative splits: 250/250
- Trials finalized after network heal: 250/250
- Dual-finality violations with f <= 2: 0
- Permanent deadlocks after a full honest-leader rotation: 0
- Actual scheduler drops: 939
- Duplicate delivery attempts: 845
- Honest process crash/restarts: 84
- Byzantine leader equivocation rounds: 58
- Byzantine leader withhold rounds: 53
- Invalid/unjustified conflicting proposals attempted: 52
- Post-finality conflicting Byzantine proposals without valid justification remained below quorum in all trials

## Decision

`CONFLICT-LOCAL ROUND-CHANGE SAFETY WITH f<=2: PASS IN TESTED RANDOMIZED SCHEDULES (0 DUAL FINALITY)`

`POST-HEAL LIVENESS WITH ROTATING CONFLICT-LOCAL LEADERS: PASS IN TESTED SCHEDULES (250/250 FINALIZED)`

`DURABLE SAME-ROUND PREVOTE/PRECOMMIT RECORDING ACROSS PROCESS RESTART: EXERCISED IN CAMPAIGN`

`POST-FINALITY CONFLICTING BYZANTINE PROPOSAL WITHOUT JUSTIFY QC: REJECTED BELOW QUORUM IN ALL TRIALS`

## Claim limits

This is a randomized local multi-process TCP experiment, not a formal Byzantine consensus proof. It does not prove arbitrary asynchronous-network liveness, physical multi-machine/WAN behavior, kernel-level network faults, power-loss durability, malicious storage rollback resistance, committee rotation, Sybil resistance, or production consensus/finality.
