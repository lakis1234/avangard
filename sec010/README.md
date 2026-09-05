# CALIBRE SECURITY SEC-010

## Randomized conflict-local round-change safety/liveness campaign

SEC-010 stress-tests the SEC-009 conflict-local PREVOTE/PRECOMMIT candidate across many unique monetary conflicts.

Configuration:

- N = 7
- Q = 5
- target Byzantine bound f <= 2
- seven separate OS certifier processes
- real TCP loopback sockets
- real Ed25519 user, proposal, PREVOTE, and PRECOMMIT signatures
- deterministic conflict-local leader rotation covering all seven leaders within seven rounds
- durable same-round PREVOTE and PRECOMMIT records with BLAKE3 checksums and `sync_all()` before honest vote release
- PRECOMMIT records also carry the durable safety lock

The campaign reconstructs an initial Byzantine-leader 3/2 tentative split, then injects randomized Byzantine proposer equivocation/withholding, unjustified conflicting proposals, scheduler message drops, duplicate deliveries, bounded delay, partial QCs, and honest process crash/restart. After the randomized fault window, the network is healed and Byzantine nodes may remain silent; the conflict-local rotating leader schedule must allow an honest leader to drive the conflict to a 5-of-7 PREVOTE QC and 5-of-7 PRECOMMIT QC.

After finality, the harness deliberately submits a conflicting proposal from a Byzantine leader without a valid higher-round justification. Honest locked nodes must keep the conflict below quorum.

## Pass criteria

- zero conflicting PRECOMMIT QCs in the tested f <= 2 schedules
- every tested conflict finalizes after network healing within one full seven-leader rotation
- no post-finality conflicting PREVOTE QC can form without a valid safe justification
- crash/restart does not permit an honest process to issue a conflicting same-round vote

## Claim discipline

A successful result may be labelled:

`RANDOMIZED LOCAL MULTI-PROCESS TCP CONFLICT-LOCAL ROUND-CHANGE SAFETY/LIVENESS PASS IN TESTED f<=2 SCHEDULES`

It is not a formal Byzantine consensus proof and not a physical multi-machine/WAN result. Arbitrary asynchronous-network liveness, kernel-level network faults, full power-loss durability, malicious storage rollback resistance, committee rotation, Sybil resistance, and production finality remain unproven.

No blockchain, blocks, DAG, or universal transaction order is used. Round numbers, proposer rotation, QCs, locks, and finality are scoped only to one conflicting monetary input/generation at a time.
