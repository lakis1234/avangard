# CALIBRE SECURITY SEC-007

## Real TCP loopback multi-process conflict safety + partition liveness

SEC-007 moves the CALIBRE conflict-finality experiment from in-process committee simulation to seven separate OS child processes communicating over real TCP loopback sockets.

The experiment keeps the SEC-002/003 safety model:

- committee N = 7
- authorization threshold Q = 5
- target Byzantine bound f <= 2
- owner-bound user Ed25519 authorization
- honest certifier one-digest-per-input-generation rule
- durable local conflict WAL written and synced before an honest certifier share is returned
- five unique real Ed25519 certifier shares required by the core

The controller deliberately tests:

- two unavailable nodes while the remaining five honest nodes finalize a valid spend
- duplicate message/share delivery
- conflicting Alice-signed successors delivered in different orders with explicit delays
- two Byzantine certifiers double-signing both conflicts
- process kill/restart of an honest certifier with durable lock recovery
- a logical 4/3 network partition where neither side can reach quorum
- partition healing and liveness recovery
- the expected f = 3 boundary where two conflicting 5-of-7 certificates can form

## Claim discipline

A successful run may be labelled:

`MEASURED LOCAL MULTI-PROCESS TCP CONFLICT-SAFETY/LIVENESS PASS FOR TESTED 5-OF-7, f<=2 SCHEDULES`

It is **not** a physical multi-machine or WAN result. All seven certifiers run as separate processes on one host and communicate through `127.0.0.1` TCP sockets. It does not prove arbitrary asynchronous-network safety/liveness, power-loss durability, randomized packet-loss robustness, Sybil resistance, committee rotation, or production consensus/finality.

No blockchain, blocks, DAG, or universal transaction ordering is used by this experiment. Coordination is conflict-scoped to the same monetary input generations.
