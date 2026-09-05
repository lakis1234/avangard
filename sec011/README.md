# CALIBRE SECURITY SEC-011

## Crash-window durability / durable vote replay / QC-lock safety

SEC-011 attacks the critical process-crash windows inside the conflict-local SEC-009/010 candidate.

Configuration:

- N = 7
- Q = 5
- seven separate certifier OS processes
- real TCP loopback sockets
- real Ed25519 user and certifier vote signatures
- same-round PREVOTE and PRECOMMIT choices persisted before a vote reply is returned
- PRECOMMIT persistence also acts as the current conflict safety lock
- 104-byte checksummed WAL records with `sync_all()` before vote transmission
- no blockchain, blocks, DAG, or universal transaction order

The runtime injects and checks:

1. crash before persistence and before a vote escapes: no phantom durable lock may appear;
2. crash after `sync_all()` but before a PREVOTE reply: durable same-round choice must survive restart;
3. normal PREVOTE reply followed by process kill/restart: a conflicting same-round PREVOTE must remain rejected;
4. crash after `sync_all()` but before a PRECOMMIT reply: durable QC lock must survive restart;
5. after the PRECOMMIT restart, same-digest continuation must remain possible while an unjustified conflicting higher-round PREVOTE is rejected;
6. end-to-end PREVOTE and PRECOMMIT crash-after-sync windows followed by restart must still recover a 5-of-7 finality QC;
7. torn and checksum-mutated WAL files must fail closed.

A PASS demonstrates process-crash ordering around software durability in the tested Windows/loopback environment. It does not prove sudden power-loss or disk-controller cache semantics, malicious storage snapshot rollback resistance, physical multi-machine/WAN behavior, or a formal Byzantine consensus theorem.
