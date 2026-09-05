# CALIBRE SECURITY SEC-011 — LOCAL SNAPDRAGON ARM64 RESULT

Platform: Windows 11 ARM64 / Snapdragon X development machine
Experiment: `calibre-sec011 v0.11.0`

## Local result

- Unit tests: 4/4 PASS
- Baseline 5-of-7 PREVOTE QC + PRECOMMIT QC: PASS
- Crash before WAL persistence and before vote escape: no phantom lock; restart may choose a fresh successor: PASS
- Crash after `sync_all()` but before PREVOTE reply: durable same-round vote present; same digest replayed; conflicting same-round PREVOTE rejected: PASS
- PREVOTE reply escaped, then process kill/restart: conflicting same-round PREVOTE still rejected: PASS
- Crash after `sync_all()` but before PRECOMMIT reply: durable QC lock survived; same digest accepted; unjustified conflicting successor rejected: PASS
- End-to-end PREVOTE crash-after-sync + restart, then PRECOMMIT crash-after-sync + restart: 5-of-7 finality recovered: PASS
- Torn WAL + checksum-mutated WAL: fail-closed on reopen: PASS

## Decision

`DURABLE SAME-ROUND PREVOTE BEFORE REPLY: PASS IN TESTED CRASH WINDOWS`

`DURABLE PRECOMMIT/QC LOCK BEFORE REPLY: PASS IN TESTED CRASH WINDOWS`

`CRASH AFTER sync_all() BEFORE REPLY PRESERVES VOTE/LOCK ACROSS PROCESS RESTART: PASS`

`ESCAPED VOTE THEN PROCESS KILL/RESTART DOES NOT ENABLE SAME-ROUND EQUIVOCATION: PASS`

`END-TO-END FINALITY RECOVERS AFTER INJECTED PREVOTE + PRECOMMIT CRASH WINDOWS: PASS`

`TORN/CORRUPT SOFTWARE WAL FAIL-CLOSED: PASS`

## What this establishes

This local Windows ARM64 run demonstrates the intended safety ordering around vote emission: safety-critical same-round vote state and QC-lock state are durably persisted and synchronized before the corresponding externally observable vote reply. In the tested process-crash windows, restart did not erase or contradict already durable voting state, and end-to-end 5-of-7 finality recovered after injected PREVOTE and PRECOMMIT crash windows.

## Claim limits

This is process-crash durability in the tested Windows software/WAL environment. It does not prove sudden physical power-loss or disk-controller flush semantics, malicious storage snapshot rollback resistance, physical multi-machine/WAN behavior, arbitrary asynchronous-network liveness, committee rotation, Sybil resistance, or a formal Byzantine consensus theorem.
