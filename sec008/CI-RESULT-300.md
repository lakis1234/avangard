# CALIBRE SECURITY SEC-008 — CI RESULT

GitHub Actions workflow run: `33937777873`
Commit: `48c3f4b282408f6367f595548e907ca6a725389c`
Platform: GitHub Actions `windows-latest` / Windows Server 2025

## Configuration

- N = 7
- Q = 5
- target f <= 2
- certifiers 0 and 1 Byzantine
- certifiers 2..6 honest
- 300 randomized trials
- seed `14128301678598393857`
- seven separate OS processes
- real TCP loopback sockets
- durable local conflict WALs
- real Ed25519 user and certifier signatures

## Deterministic witnesses

- Two Byzantine nodes unavailable; five honest nodes finalize one successor: `PASS (5/7)`.
- Honest lock split 3/2 plus two Byzantine withholders: `A=3/7`, `B=2/7`; neither successor can finalize after network healing. `CONFLICT-LIVENESS DEADLOCK ATTACK CONFIRMED`.

## Randomized campaign

- Trials: 300
- Dual-finality safety violations with f <= 2: 0
- Trials with exactly one successor reaching >= 5/7: 132
- Trials deadlocked below 5/7 after honest-network heal: 168
- Injected application-layer message drops: 370
- Injected duplicate deliveries: 495
- Honest process crash/restarts: 6
- Restarts preserving conflicting-successor rejection: 6

## Decision

`RANDOMIZED REAL-TCP LOOPBACK CONFLICT SAFETY WITH f<=2: PASS IN TESTED SCHEDULES`

`DURABLE HONEST LOCK SURVIVES REPEATED PROCESS CRASH/RESTART: PASS`

`CONFLICT LIVENESS UNDER BYZANTINE WITHHOLDING + HONEST 3/2 SPLIT: FAIL / DEADLOCK ATTACK CONFIRMED`

The next required protocol mechanism is a conflict-local canonical-winner / round-change rule that allows honest certifiers to converge after a split while preserving safety and without imposing a universal order on unrelated transactions.

## Claim limits

This is not physical multi-machine or WAN testing. Message drops are injected at the application scheduling layer, not with a kernel-level network emulator. Arbitrary asynchronous-network liveness, power-loss durability, committee rotation, Sybil resistance, and production finality remain unproven.
