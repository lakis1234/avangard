# CALIBRE SECURITY SEC-014

## Multi-generation monetary lineage across zero-overlap committee rotations

SEC-014 extends SEC-013 from one committee handoff to a multi-generation monetary lineage that crosses two complete committee replacements.

The experiment uses three disjoint 7-node committees (epochs 20, 21, and 22), each with a 5-of-7 threshold. Twenty-one separate OS child processes communicate through real TCP loopback sockets.

The test advances one monetary state through several generations:

`Alice-state g0 -> Bob-state g1 -> Carol-state g2 -> Dave-state g3 -> Eve-state g4`

The focus is not wallet authorization itself (owner-bound authorization was tested earlier). Here the state digests stand in for already-authorized monetary successors so that SEC-014 can isolate lineage continuity, generation fencing, and epoch-transition safety.

Each honest committee member:

- signs at most one successor per `(coin_id, generation)`;
- persists that choice before releasing the signature;
- signs only a handoff to the immediately next epoch;
- durably retires a handed-off generation before releasing the handoff share;
- new committees activate only from a valid 5-of-7 predecessor handoff certificate addressed to their exact epoch;
- persist activated state before releasing an activation share.

The controller tests:

- normal multi-generation finalization across epochs 20 -> 21 -> 22;
- an old committee trying to finalize another successor after issuing a valid handoff;
- a 4-of-7 insufficient handoff;
- an attempted skipped-epoch handoff (20 -> 22);
- replay of an epoch-20->21 handoff against the epoch-22 committee;
- stale generation replay after several generations have advanced;
- process restart after activation/current-state persistence;
- the expected f=3 quorum boundary, where two conflicting 5-of-7 handoff certificates can be constructed.

## Claim discipline

A successful run may be labelled:

`LOCAL MULTI-PROCESS TCP MULTI-GENERATION / MULTI-EPOCH MONETARY LINEAGE PASS IN TESTED 5-OF-7, f<=2 SCENARIOS`

It does not prove a production dynamic-membership protocol, long-range security for offline clients, arbitrary asynchronous reconfiguration liveness, physical WAN operation, Sybil resistance, power-loss durability, or malicious storage rollback resistance.

No blockchain, blocks, DAG, or universal transaction ordering is used. The experiment does maintain a per-monetary-state generation/epoch lineage; that is local succession state, not a universal ledger ordering unrelated payments.
