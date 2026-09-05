# CALIBRE SECURITY SEC-008.1 — LOCAL SNAPDRAGON ARM64 RESULT

Platform: Windows 11 ARM64 / Snapdragon X Plus development machine
Rust: 1.98.1-compatible toolchain
Experiment: `calibre-sec0081 v0.8.1`

## Local result

- Unit tests: 4/4 PASS
- Unique durable lock trials: 2500
- Controller-side checksummed WAL verifications before restart: 2500/2500
- Process crash/restarts: 50
- Restarts preserving same-digest acceptance plus conflicting-digest rejection: 50/50
- Explicit trial-1000 / node-4 reproduction checkpoint: PASS
- Earlier SEC-008 trial-1000 durable-lock abort reproduced under hardened WAL: NO

## Decision

`HARDENED CHECKSUMMED WAL SYNC-BEFORE-SHARE: PASS IN TESTED PROCESS-RESTART CAMPAIGN`

`DURABLE LOCK REPLAY AFTER PROCESS KILL/RESTART: PASS`

This closes the specific SEC-008 process-restart anomaly as **not reproduced under the hardened checksummed WAL implementation**. It does not prove power-loss or disk-controller durability, and it does not prove resistance to malicious storage snapshot rollback.

## Next experiment

SEC-008.2 should rerun the randomized seven-process conflict campaign using the hardened WAL and actual application-layer message-drop injection, while preserving the known 3/2 honest-lock liveness-deadlock attack as an expected protocol limitation to be solved by a later conflict-local round-change/canonical-winner mechanism.
