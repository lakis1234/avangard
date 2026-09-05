# CALIBRE SECURITY SEC-015 — Offline Client Long-Range / Stale-Prefix Bootstrap

SEC-015 attacks a problem created by deliberately not relying on a universal historical blockchain: a client that has been offline can be shown a cryptographically valid but stale certificate prefix and may not know that a later committee handoff exists.

The experiment uses three disjoint committee key domains (epochs 30, 31, 32), each with N=7 and Q=5. Twenty-one OS processes communicate over real TCP loopback on one physical host. Nodes 0 and 1 are Byzantine in the f<=2 scenarios.

## Attack

A naive offline client validates a legitimate prefix ending at epoch 31 / generation 2. The real protocol has already advanced through a valid 31->32 handoff, but the attacker simply omits that later certificate. No signature forgery is required. Certificate validity alone therefore does not establish *currentness*.

## Candidate tested

The terminal committee claimed by a bootstrap proof must answer a fresh client-generated 32-byte nonce with at least 5 unique signatures over:

`epoch || monetary-state || client-nonce`

Honest signers that have durably retired the state during a handoff refuse to answer freshness challenges for that state. A stale committee therefore cannot reach 5/7 under the tested f<=2 retirement pattern, while the active current committee can.

The nonce prevents replay of an old freshness certificate. If fewer than 5 current nodes are reachable, the client fails closed rather than accepting a stale state.

## Important limits

This is a candidate currentness mechanism, not a complete solution to long-range security. It requires live reachability to a 5/7 active-committee quorum. If three or more retired committee keys later become Byzantine/compromised, the stale committee can again manufacture a 5/7 freshness response in the tested threshold configuration. Forward-secure signing/key erasure or another long-term old-key-compromise defense remains open.

No global blockchain, blocks, DAG, or universal transaction order is used.
