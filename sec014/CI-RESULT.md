# CALIBRE SECURITY SEC-014 — CI RESULT

GitHub Actions workflow run: `33942470488`
Commit: `03fe0a662fe19cf52ae8bb3bc050fd9daa7faa85`
Platform: GitHub Actions Windows Server 2025

## Configuration

- three disjoint committees: epochs 20, 21, 22
- each committee N=7, Q=5
- target Byzantine bound f<=2
- 21 separate OS certifier processes over real TCP loopback
- durable per-generation successor choice, handoff retirement, activation state, and current-state replay
- old/new epoch signing-key domains are disjoint
- no blockchain, blocks, DAG, or universal transaction ordering
- per-monetary-state generation/epoch lineage is used

## Results

- Unit tests: 5/5 PASS
- generation 0->1 / epoch 20: Alice-state -> Bob-state finalizes
- insufficient 20->21 handoff 4/7: honest epoch-21 activation shares = 0
- skipped-epoch handoff 20->22: only 2/7 Byzantine shares, no quorum
- old epoch-20 post-handoff conflicting successor: 4/7, cannot finalize
- epoch 21 direct-predecessor activation: 5/7 PASS
- generation 1->2 / epoch 21: Bob-state -> Carol-state finalizes
- stale 20->21 handoff replay against epoch 22: honest activation shares = 0
- epoch 22 accepts direct 21->22 predecessor handoff: 5/7 PASS
- generation 2->3 / epoch 22: Carol-state -> Dave-state finalizes
- honest epoch-22 process restart followed by generation 3->4 Dave-state -> Eve-state: PASS
- stale generation-0 replay after generation 4: honest shares = 0; total 2/7
- restarted old epoch-20 honest handoff signer remembers retirement; post-handoff conflict remains 4/7
- f=3 boundary: two cryptographic conflicting 5/7 handoff certificates constructed, expected attack witness confirmed

## Decision

`MULTI-GENERATION MONETARY LINEAGE g0->g4 ACROSS EPOCHS 20->21->22: PASS IN TESTED LOCAL SCENARIO`

`ZERO-OVERLAP DIRECT-PREDECESSOR MULTI-EPOCH HANDOFF CONTINUITY: PASS`

`OLD COMMITTEE POST-HANDOFF SUCCESSOR FENCING WITH f<=2: PASS IN TESTED SCENARIO`

`INSUFFICIENT 4/7 + SKIPPED-EPOCH + STALE-HANDOFF REPLAY REJECTION: PASS`

`STALE MONETARY GENERATION REPLAY AFTER MULTIPLE SUCCESSORS: PASS`

`PROCESS-RESTART PERSISTENCE OF CURRENT STATE + OLD RETIREMENT: PASS`

`F=3 HANDOFF SAFETY BOUNDARY: TWO 5/7 CERTIFICATES REACHABLE / EXPECTED`

## Claim limits

Owner authorization is abstracted as pre-authorized state digests in this experiment; owner-bound user signatures were tested separately in earlier security work. This is still one physical host using TCP loopback, not a WAN or physical multi-machine deployment. Offline-client long-range bootstrap, arbitrary asynchronous reconfiguration liveness, production membership selection, Sybil resistance, power-loss durability, malicious storage rollback resistance, and production finality remain unproven.
