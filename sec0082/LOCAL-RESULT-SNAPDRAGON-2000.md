# CALIBRE SECURITY SEC-008.2 — LOCAL SNAPDRAGON ARM64 RESULT

Platform: Windows 11 ARM64 / Snapdragon X Plus development machine
Experiment: `calibre-sec0082 v0.8.2`

## Local result

- Unit tests: 5/5 PASS
- Trials: 2000
- Dual-finality safety violations with f <= 2: 0
- Trials with one successor reaching >=5/7 after heal: 902
- Trials deadlocked below 5/7 after heal: 1098
- Actual application-scheduler message drops (no TCP request sent): 2570
- Initial deliveries actually sent: 7430
- Duplicate delivery attempts: 2494
- Honest process crash/restarts: 40
- Restart durability checks passed: 40/40

## Decision

`HARDENED CHECKSUMMED WAL PROCESS-RESTART DURABILITY: PASS IN TESTED CAMPAIGN`

`ACTUAL APPLICATION-LAYER DROP INJECTION: PASS / CONFIRMED`

`RANDOMIZED REAL-TCP LOOPBACK CONFLICT SAFETY WITH f<=2: PASS IN TESTED SCHEDULES (0 DUAL CERTIFICATES)`

`CONFLICT LIVENESS WITH PERMANENT FIRST-SEEN LOCKS: FAIL / DEADLOCKS CONFIRMED`

The 2000-trial local campaign confirms that the current permanent first-seen lock rule is safe in the tested schedules but not live: 1098/2000 trials remained below quorum after the network healed. The next protocol mechanism must be conflict-local round change / safe locking / canonical winner selection, without imposing a universal order on unrelated transactions.

## Claim limits

This is one physical host with seven OS processes and real TCP loopback. It is not physical multi-machine or WAN testing. Kernel-level packet loss, arbitrary asynchronous-network liveness, power-loss/disk-controller durability, malicious storage snapshot rollback resistance, committee rotation, Sybil resistance, and production finality remain unproven.
