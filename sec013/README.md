# CALIBRE SECURITY SEC-013

## Cross-epoch committee handoff / monetary unicity across rotation

SEC-013 attacks a major remaining safety gap: committee rotation. The old and new committees deliberately use disjoint signing-key sets to test whether monetary conflict state can cross an epoch boundary without relying on committee-member overlap.

Model:

- old committee epoch 12: N=7, Q=5
- new committee epoch 13: N=7, Q=5
- target Byzantine bound f<=2 per committee
- five old-committee signatures form a handoff certificate over the exact input, epoch transition, status, round, and digest
- five new-committee signatures form an activation certificate over the exact old handoff hash
- honest old certifiers durably choose one handoff state per input/epoch transition before signing
- honest new certifiers durably choose one handoff certificate before issuing an activation share
- new-epoch voting requires a valid old handoff certificate and a valid 5-of-7 new activation certificate
- finalized old-epoch inputs are treated as consumed and cannot be revived
- locked old-epoch state constrains new-epoch voting to the inherited digest

The experiment tests finalized-state transfer, locked-state transfer, f<=2 conflicting handoff safety, old-signer restart persistence, insufficient old certificates, wrong target epochs, partial new activation and recovery after heal, new-signer restart persistence, and the expected f=3 old-committee quorum boundary.

No blockchain, blocks, DAG, or universal transaction order is used. The handoff is scoped to the affected monetary input state.

## Claim discipline

A successful run may be labelled:

`MEASURED LOCAL MULTI-PROCESS CROSS-EPOCH COMMITTEE-HANDOFF PASS IN TESTED N=7 Q=5 f<=2 SCENARIOS`

It is not physical multi-machine/WAN testing, not a formal proof of reconfiguration safety, and not a production membership/Sybil-resistance mechanism. The f=3 dual-handoff boundary is expected for a 5-of-7 committee and is explicitly attacked.
