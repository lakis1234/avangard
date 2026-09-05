# CALIBRE SECURITY SEC-010 — LOCAL SNAPDRAGON ARM64 RESULT

Platform: Windows 11 ARM64 / Snapdragon X Plus development machine
Experiment: `calibre-sec010 v0.10.0`

## Local result

- Unit tests: 5/5 PASS
- Trials: 1000
- Reconstructed Byzantine-leader 3/2 tentative splits: 1000/1000
- Trials finalized after network heal: 1000/1000
- Dual-finality violations with f <= 2: 0
- Permanent deadlocks after full honest-leader rotation: 0
- Actual scheduler drops: 3876
- Duplicate delivery attempts: 3545
- Honest process crash/restarts: 289
- Byzantine leader equivocation rounds: 186
- Byzantine leader withhold rounds: 204
- Invalid/unjustified conflict proposals attempted: 246
- Total post-heal rounds to finality: 1000

## Decision

`CONFLICT-LOCAL ROUND-CHANGE SAFETY WITH f<=2: PASS IN TESTED RANDOMIZED SCHEDULES (0 DUAL FINALITY)`

`POST-HEAL LIVENESS WITH ROTATING CONFLICT-LOCAL LEADERS: PASS IN TESTED SCHEDULES (1000/1000 FINALIZED)`

`DURABLE SAME-ROUND PREVOTE/PRECOMMIT RECORDING ACROSS PROCESS RESTART: EXERCISED IN CAMPAIGN`

`POST-FINALITY CONFLICTING BYZANTINE PROPOSAL WITHOUT JUSTIFY QC: REJECTED BELOW QUORUM IN ALL TRIALS`

## What this establishes

This local campaign demonstrates that the SEC-009/010 conflict-local round-change candidate removed the permanent first-seen-lock deadlock seen in SEC-008.2 for the tested randomized schedules while preserving the tested f<=2 conflicting-successor safety property. It also exercised real TCP loopback, seven separate OS certifier processes, real Ed25519 user/proposal/PREVOTE/PRECOMMIT signatures, scheduler-level drops and duplicates, Byzantine proposer behavior, and repeated process crash/restart.

## Claim limits

This is not a formal Byzantine consensus proof and not a production cryptocurrency network result. It does not prove arbitrary asynchronous-network liveness, physical multi-machine/WAN behavior, kernel-level packet faults, power-loss or disk-controller durability, malicious storage rollback resistance, committee rotation, Sybil resistance, or production finality.
