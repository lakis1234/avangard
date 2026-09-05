# CALIBRE SECURITY SEC-011 — CI RESULT

GitHub Actions workflow run: `33941097240`
Commit: `cc9ce3c6adbb7349094069aa47288f78584d4e2c`
Platform: GitHub Actions Windows Server 2025

## Configuration

- N = 7
- Q = 5
- seven separate certifier OS processes
- real TCP loopback sockets
- real Ed25519 user and certifier vote signatures
- durable same-round PREVOTE/PRECOMMIT records
- PRECOMMIT record also carries the current QC safety lock
- 104-byte checksummed WAL with `sync_all()` before vote reply
- no blockchain, blocks, DAG, or universal transaction order

## Results

- Unit tests: 4/4 PASS
- Baseline 5-of-7 PREVOTE QC + PRECOMMIT QC: PASS
- Crash before WAL persistence and before vote escape: no phantom lock; restart can choose a fresh successor: PASS
- Crash after `sync_all()` but before PREVOTE reply: durable same-round vote present; same digest replayed; conflicting same-round vote rejected after restart: PASS
- Normal PREVOTE reply followed by process kill/restart: conflicting same-round vote remained rejected: PASS
- Crash after `sync_all()` but before PRECOMMIT reply: durable QC lock survived restart; same digest remained admissible; unjustified higher-round conflict rejected: PASS
- End-to-end PREVOTE crash-after-sync + restart and PRECOMMIT crash-after-sync + restart: 5-of-7 finality recovered: PASS
- Torn WAL and checksum-mutated WAL: fail-closed on reopen: PASS

## Decision

`DURABLE SAME-ROUND PREVOTE BEFORE REPLY: PASS IN TESTED CRASH WINDOWS`

`DURABLE PRECOMMIT/QC LOCK BEFORE REPLY: PASS IN TESTED CRASH WINDOWS`

`CRASH AFTER sync_all() BEFORE REPLY PRESERVES VOTE/LOCK ACROSS PROCESS RESTART: PASS`

`END-TO-END FINALITY RECOVERS AFTER INJECTED PREVOTE + PRECOMMIT CRASH WINDOWS: PASS`

## Claim limits

This demonstrates process-crash ordering and software-WAL replay in the tested Windows environment. It does not prove sudden power-loss or disk-controller flush semantics, malicious storage snapshot rollback resistance, physical multi-machine/WAN behavior, arbitrary asynchronous-network liveness, or a formal Byzantine consensus theorem.
