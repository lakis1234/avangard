# CALIBRE SECURITY SEC-016 — Retired-Key Ratchet / Later Compromise Attack

SEC-016 attacks the remaining long-range weakness exposed by SEC-015: a retired committee may be safe immediately after handoff, yet an attacker who compromises retired signing keys years later could manufacture a fresh stale-currentness response.

This experiment does **not** claim a complete forward-secure signature construction. It tests a narrower candidate: each honest retired signer advances its secret through a one-way BLAKE3 ratchet and durably stores only the advanced secret before acknowledging retirement. The old epoch freshness public key is cached by the client. Later compromise of the current retired-node secret state should therefore not recreate the old signing key.

## Configuration

- Old committee epoch 50
- N = 7, Q = 5
- Seven separate OS signer processes over real TCP loopback
- Nodes 0..4 retire honestly and ratchet their secret state
- Nodes 5..6 model Byzantine members that retain old keys
- State files are checksummed and `sync_all()` is used before retirement acknowledgement
- Initial per-node secrets are generated from the operating-system CSPRNG, not deterministically embedded in the executable

## Tested cases

1. Before retirement, the old committee can produce a valid 5/7 freshness quorum.
2. Five honest signers ratchet forward and retire; two Byzantine signers retain old key material.
3. The retired committee can no longer answer a fresh old-epoch currentness challenge with 5/7.
4. Restart of an honest retired signer preserves the ratcheted state.
5. The controller simulates later compromise of **all current on-disk node secret states**. The five honest advanced secrets do not reproduce signatures valid under their old public keys; only the two Byzantine retained old keys remain valid.
6. A deliberately saved **pre-retirement secret snapshot** from three honest nodes plus the two Byzantine retained old secrets forms a 5/7 stale freshness response. This is an expected attack witness.

## Interpretation

A successful run may be labelled:

`LATER COMPROMISE OF CURRENT RETIRED-NODE SECRET STATE: OLD 5/7 FRESHNESS NOT RECREATED IN TESTED ONE-WAY RATCHET MODEL`

But the experiment must also report:

`PRE-RETIREMENT SECRET SNAPSHOT / EXFILTRATION: ATTACK CONFIRMED`

The distinction is essential. A software ratchet can make *later* compromise of the advanced state less dangerous under the one-way-hash and erasure assumptions, but it cannot retroactively protect old secrets that an attacker copied before retirement.

## Claim limits

This is not a formally proven forward-secure signature scheme, not proof of physical key erasure, and not protection against SSD forensic remnants or malicious pre-retirement disk snapshots. Power-loss durability, hardware-backed erasure, physical multi-machine/WAN operation, permissionless committee selection, and Sybil resistance remain outside this experiment.

No blockchain, blocks, DAG, or universal transaction order is used.
