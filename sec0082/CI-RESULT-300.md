# CALIBRE SECURITY SEC-008.2 — CI RESULT

GitHub Actions workflow run: `33938965936`
Commit: `85fa5b081074a28127c65f67dc6a1c8eb87cf46f`
Platform: GitHub Actions `windows-latest` / Windows Server 2025

## Configuration

- N = 7
- Q = 5
- target f <= 2
- certifiers 0 and 1 Byzantine
- certifiers 2..6 honest
- trials = 300
- seed = `14128301678598524929`
- seven separate OS processes
- real TCP loopback sockets
- 96-byte checksummed WAL records
- `sync_all()` before honest share
- actual application-scheduler drops where no TCP request is sent

## Results

- Unit tests: 5/5 PASS
- Baseline with two Byzantine nodes unavailable: 5/7 honest finalization PASS
- Deterministic honest 3/2 split + two Byzantine withholders: liveness deadlock CONFIRMED
- Dual-finality safety violations with f <= 2: 0
- Trials with one successor reaching >=5/7 after heal: 139
- Trials deadlocked below 5/7 after heal: 161
- Actual application-scheduler message drops: 383
- Initial deliveries actually sent: 1117
- Duplicate delivery attempts: 382
- Honest process crash/restarts: 6
- Restart durability checks passed: 6/6

## Decision

`HARDENED CHECKSUMMED WAL PROCESS-RESTART DURABILITY: PASS IN TESTED CAMPAIGN`

`ACTUAL APPLICATION-LAYER DROP INJECTION: PASS / CONFIRMED`

`RANDOMIZED REAL-TCP LOOPBACK CONFLICT SAFETY WITH f<=2: PASS IN TESTED SCHEDULES (0 DUAL CERTIFICATES)`

`CONFLICT LIVENESS WITH PERMANENT FIRST-SEEN LOCKS: FAIL / DEADLOCKS CONFIRMED`

The next protocol mechanism must be a conflict-local round-change / canonical-winner rule that lets honest certifiers converge after a split without imposing a universal transaction order on unrelated payments.

## Claim limits

This is not physical multi-machine or WAN testing. It does not prove kernel-level packet-loss behavior, arbitrary asynchronous-network liveness, power-loss or disk-controller durability, malicious storage snapshot rollback resistance, committee rotation, Sybil resistance, or production finality.
