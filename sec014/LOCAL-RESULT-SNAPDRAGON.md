# CALIBRE SECURITY SEC-014 — LOCAL SNAPDRAGON ARM64 RESULT

Platform: Windows 11 ARM64 / Snapdragon X Plus development machine
Experiment: `calibre-sec014 v0.14.0`

## Local result

- Unit tests: 5/5 PASS
- Epochs 20 -> 21 -> 22, each N=7 Q=5
- 21 separate OS certifier processes over real TCP loopback
- Generation 0->1 / epoch 20: Alice-state -> Bob-state finalizes — PASS
- Insufficient 20->21 handoff 4/7: honest epoch-21 activation = 0 — PASS
- Skipped-epoch 20->22 handoff: only 2/7, no quorum — PASS
- Old epoch-20 post-handoff conflict: 4/7 < 5 — PASS
- Epoch-21 direct-predecessor activation: 5/7 — PASS
- Generation 1->2 / epoch 21: Bob-state -> Carol-state finalizes — PASS
- Stale 20->21 handoff replay against epoch 22: honest activation = 0 — PASS
- Epoch-22 direct 21->22 activation: 5/7 — PASS
- Generation 2->3 / epoch 22: Carol-state -> Dave-state finalizes — PASS
- Honest epoch-22 restart + generation 3->4 Dave-state -> Eve-state — PASS
- Stale generation-0 replay after generation 4: honest=0, total=2/7 — PASS
- Restarted epoch-20 honest handoff signer remembers retirement; conflicting old certificate remains 4/7 — PASS
- f=3 boundary: two conflicting cryptographic 5/7 handoff certificates — ATTACK WITNESS CONFIRMED / EXPECTED

## Decision

`MULTI-GENERATION MONETARY LINEAGE g0->g4 ACROSS EPOCHS 20->21->22: PASS IN TESTED LOCAL SCENARIO`

`ZERO-OVERLAP DIRECT-PREDECESSOR MULTI-EPOCH HANDOFF CONTINUITY: PASS`

`OLD COMMITTEE POST-HANDOFF SUCCESSOR FENCING WITH f<=2: PASS IN TESTED SCENARIO`

`INSUFFICIENT 4/7 + SKIPPED-EPOCH + STALE-HANDOFF REPLAY REJECTION: PASS`

`STALE MONETARY GENERATION REPLAY AFTER MULTIPLE SUCCESSORS: PASS`

`PROCESS-RESTART PERSISTENCE OF CURRENT STATE + OLD RETIREMENT: PASS`

`F=3 HANDOFF SAFETY BOUNDARY: TWO 5/7 CERTIFICATES REACHABLE / EXPECTED`

## Claim limits

Owner authorization is abstracted as pre-authorized state digests in SEC-014. This is one physical Windows ARM64 host using TCP loopback, not physical multi-machine/WAN. Offline-client long-range bootstrap, arbitrary asynchronous reconfiguration liveness, production membership selection, Sybil resistance, power-loss durability, malicious storage rollback resistance, and production finality remain unproven.
