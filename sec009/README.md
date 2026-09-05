# CALIBRE SECURITY SEC-009

## Conflict-local round change / QC locking / deadlock recovery

SEC-008.2 demonstrated that permanent first-seen locks preserve conflicting-successor safety in the tested `N=7, Q=5, f<=2` schedules but can deadlock liveness after an honest 3/2 split. SEC-009 changes the lock semantics.

### Protocol candidate

For one conflicting monetary input generation only:

1. A first-seen `PREVOTE` is tentative. It is not a permanent safety lock.
2. A valid `PREVOTE QC` requires five unique real Ed25519 certifier votes for the same digest, input generation, and conflict-local round.
3. An honest certifier persists a durable safety lock only when it receives a valid 5-of-7 PREVOTE QC and is about to issue its PRECOMMIT.
4. Final authorization requires a 5-of-7 `PRECOMMIT QC`. Thus finality requires certifiers to have seen a valid prepare/prevote quorum before they can contribute to finality.
5. If a round fails to reach quorum, the conflict advances to a new local round. A deterministic per-conflict proposer is derived from `(input id, generation, round)`.
6. A locked honest certifier rejects a conflicting proposal unless it carries a valid higher-round justification QC satisfying the lock rule.
7. Unrelated monetary inputs do not share this round number or proposer schedule. There is no universal transaction order in this experiment.

### Scenarios

- Reproduce SEC-008's honest 3/2 split as tentative prevotes, then recover in a later conflict-local round.
- Finalize via a 5-of-7 PREVOTE QC followed by a 5-of-7 PRECOMMIT QC.
- Attempt a conflicting higher-round Byzantine proposal after final locking.
- Form a PREVOTE QC but deliver PRECOMMIT to only three honest nodes, then recover in a later round carrying the prior QC.
- Logical 4/3 partition where no quorum is possible, followed by post-heal round-change finalization.
- Expected `f=3` boundary where three Byzantine voters plus two honest voters on each side can form two conflicting 5-of-7 PRECOMMIT QCs under equivocation.

### Claim discipline

A successful SEC-009 run demonstrates a **candidate conflict-local round-change state machine** resolving the specific permanent-first-seen 3/2 deadlock in the tested schedules while preserving the tested `f<=2` safety boundary.

It is not yet a formal proof, arbitrary asynchronous-network liveness proof, physical multi-machine/WAN result, committee-rotation mechanism, Sybil-resistance mechanism, or production consensus implementation.
