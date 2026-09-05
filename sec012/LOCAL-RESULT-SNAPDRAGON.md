# CALIBRE SECURITY SEC-012 — LOCAL SNAPDRAGON ARM64 RESULT

Platform: Windows 11 ARM64 / Snapdragon X Plus development machine
Experiment: `calibre-sec012 v0.12.0`

## Local result

- Unit tests: 6/6 PASS
- N = 7, Q = 5, target f <= 2
- Bounded adversarial rounds: 3
- Healed-network leader rotation bound: <= 7 rounds
- Unique terminal states across all leader offsets: 12,359
- State transitions explored: 301,543
- PREVOTE-QC branches explored: 6,290
- No-QC / delay-withhold branches explored: 5,913
- Partial honest QC-lock delivery branches: 283,050
- Full five-honest QC-lock delivery branches: 6,290
- PRECOMMIT finality branches explored: 100,640
- Conflicting dual-finality states found with f <= 2: 0
- Post-heal recovery failures from checked terminal states: 0
- Maximum healed-network rounds to an honest leader that can finalize: 3
- f = 3 dual 5-of-7 boundary witness: EXISTS / EXPECTED

## Decision

`BOUNDED EXHAUSTIVE f<=2 CONFLICT-SAFETY CHECK: PASS WITHIN MODELED ROUND/STATE BOUND`

`POST-HEAL CONFLICT-LOCAL LEADER-ROTATION RECOVERY: PASS FROM ALL MODELED TERMINAL STATES`

`F=3 SAFETY BOUNDARY: DUAL 5-OF-7 CERTIFICATES MATHEMATICALLY REACHABLE / EXPECTED`

## What this establishes

The local Snapdragon run reproduces the SEC-012 bounded state-space result: within the modeled three adversarial conflict-local rounds plus healed leader rotation, no conflicting dual-finality state was reachable under the f<=2 assumptions, and every modeled terminal state recovered after healing.

## Claim limits

This is a bounded model, not an unbounded formal Byzantine consensus proof. Signatures are abstracted as unforgeable and durable same-round non-equivocation / QC-lock persistence are imported from earlier experimentally tested mechanisms. Physical multi-machine/WAN behavior, arbitrary asynchronous-network liveness, power-loss durability, malicious storage rollback resistance, committee/epoch rotation, Sybil resistance, and production finality remain unproven.
