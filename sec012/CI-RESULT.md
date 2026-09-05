# CALIBRE SECURITY SEC-012 — CI RESULT

GitHub Actions workflow run: `33941497727`
Commit: `b7938d8da9bb735266ad15bcec316a267cde0dd9`
Platform: GitHub Actions Windows Server 2025

## Configuration

- N = 7
- Q = 5
- target Byzantine bound f <= 2
- five honest + two Byzantine certifiers
- 3 bounded adversarial conflict-local rounds
- then <=7 healed-network conflict-local leader-rotation rounds
- signatures abstracted as unforgeable
- durable same-round non-equivocation and QC-lock persistence imported from SEC-011
- no blockchain, blocks, DAG, or universal transaction order

## Results

- Unit tests: 6/6 PASS
- Unique terminal states across all seven leader offsets: 12,359
- State transitions explored: 301,543
- PREVOTE-QC branches explored: 6,290
- No-QC / delay-withhold branches explored: 5,913
- Partial honest QC-lock delivery branches: 283,050
- Full five-honest QC-lock delivery branches: 6,290
- PRECOMMIT finality branches explored: 100,640
- Conflicting dual-finality states found with f <= 2: 0
- Post-heal recovery failures from checked terminal states: 0
- Maximum healed-network rounds to an honest leader that can finalize: 3
- f=3 two-conflicting-5-of-7 boundary witness exists: YES

## Decision

`BOUNDED EXHAUSTIVE f<=2 CONFLICT-SAFETY CHECK: PASS WITHIN MODELED ROUND/STATE BOUND`

`POST-HEAL CONFLICT-LOCAL LEADER-ROTATION RECOVERY: PASS FROM ALL MODELED TERMINAL STATES`

`F=3 SAFETY BOUNDARY: DUAL 5-OF-7 CERTIFICATES MATHEMATICALLY REACHABLE / EXPECTED`

## Claim limits

This is a bounded state-space model, not an unbounded formal Byzantine consensus proof. Cryptographic signatures, process persistence ordering, and same-round durable non-equivocation are abstracted based on mechanisms already exercised in earlier experiments. Physical multi-machine/WAN behavior, arbitrary asynchronous-network liveness, kernel-level packet faults, power-loss durability, malicious storage rollback resistance, committee rotation, Sybil resistance, and production finality remain unproven.
