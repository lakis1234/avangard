# CALIBRE SECURITY SEC-008

## Randomized multi-process TCP fault campaign

SEC-008 extends SEC-007 from a handful of hand-selected schedules into a repeatable randomized fault campaign over seven separate certifier OS processes communicating through real TCP loopback sockets.

Security model:

- committee `N = 7`
- authorization threshold `Q = 5`
- target Byzantine bound `f <= 2`
- certifiers 0 and 1 are Byzantine in the campaign
- certifiers 2..6 are honest
- owner-bound user Ed25519 authorization
- unique real Ed25519 certifier shares
- honest certifiers durably persist a one-digest-per-input-generation lock before returning a share

Fault campaign injects:

- randomized honest-node first-seen conflict ordering
- application-layer message-drop injection
- duplicate request/share delivery
- small randomized delays
- Byzantine sign-A / sign-B / sign-both / withhold behavior
- repeated abrupt honest-process crash/restart with the same durable WAL
- network-heal retries to all honest nodes

SEC-008 deliberately contains two deterministic witnesses before the randomized campaign:

1. **Baseline liveness:** with both Byzantine nodes unavailable, all five honest nodes see the same transaction and produce a valid 5-of-7 certificate.
2. **Conflict-liveness deadlock:** three honest nodes permanently lock successor A, two permanently lock successor B, and both Byzantine nodes withhold. Neither successor can reach 5-of-7 even after network healing.

The second result is expected to expose the limitation of the current permanent one-digest locking rule: quorum intersection preserves safety for `f <= 2`, but safety alone does not guarantee progress after honest nodes split across conflicting successors.

A successful SEC-008 campaign therefore has a deliberately mixed result:

`RANDOMIZED TCP CONFLICT SAFETY PASS FOR TESTED f<=2 SCHEDULES; CONFLICT-LIVENESS DEADLOCK ATTACK CONFIRMED`

This is a useful protocol result, not a failed experiment. It identifies the next required mechanism: a **conflict-local canonical winner / round-change protocol** that can make honest certifiers converge on one successor without imposing a global order on unrelated payments.

## Claim limits

This experiment uses real TCP but only `127.0.0.1` on one physical host. Message loss is injected at the application scheduling layer rather than by a kernel/network emulator. It does not prove arbitrary asynchronous-network liveness, physical multi-machine behavior, WAN behavior, power-loss durability, Sybil resistance, committee rotation, or production finality.

No blockchain, blocks, DAG, or universal transaction ordering is used.
