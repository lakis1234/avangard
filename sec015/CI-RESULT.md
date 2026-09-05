# CALIBRE SECURITY SEC-015 — CI RESULT

GitHub Actions workflow run: `33944327158`
Commit: `1cbb6b196e95657dd373f8e0368a049eb170d7b3`
Platform: GitHub Actions Windows Server 2025

## Configuration

- epochs 30 -> 31 -> 32
- each committee N=7, Q=5
- nodes 0 and 1 Byzantine in the f<=2 scenarios
- 21 separate OS processes over real TCP loopback
- durable transfer, retirement, and activation state with checksummed WAL + `sync_all()`
- client freshness challenge signs exact epoch + monetary state + client nonce
- no blockchain, blocks, DAG, or universal transaction order

## Results

- Unit tests: 5/5 PASS
- Naive certificate-only offline bootstrap accepted a cryptographically valid stale prefix ending at epoch 31 / generation 2: LONG-RANGE CURRENTNESS ATTACK CONFIRMED
- Stale epoch-31 committee after valid 31->32 handoff answered a fresh client nonce with only 4/7 shares: below quorum
- Old 5/7 freshness certificate replayed against a new nonce failed signature verification
- Restarted retired honest epoch-31 signer remembered retirement and rejected the new freshness challenge
- Current epoch-32 five honest nodes produced a valid 5/7 freshness certificate for exact epoch + state + nonce
- Only 3/7 current honest nodes reachable: no freshness quorum; client fails closed / liveness pauses
- f=3 / three old keys compromised boundary: 3 Byzantine old keys + 2 non-retired honest signers can form a stale 5/7 freshness response: ATTACK WITNESS CONFIRMED

## Decision

`CERTIFICATE-ONLY OFFLINE CURRENTNESS: FAIL / STALE VALID PREFIX ATTACK CONFIRMED`

`LIVE CLIENT-NONCE 5-OF-7 CURRENT-STATE FRESHNESS CHALLENGE WITH f<=2: PASS IN TESTED HANDOFF SCENARIO`

`RETIRED COMMITTEE CANNOT ANSWER NEW 5/7 FRESHNESS CHALLENGE WITH f<=2 IN TESTED SCENARIO: PASS`

`OLD FRESHNESS RESPONSE REPLAY ACROSS CLIENT NONCES: REJECTED`

`RETIRED-SIGNER PROCESS RESTART MEMORY: PASS`

`TOTAL ECLIPSE / <5 CURRENT NODES REACHABLE: CLIENT FAILS CLOSED; LIVENESS NOT GUARANTEED`

`F=3 OR LATER COMPROMISE OF >=3 RETIRED COMMITTEE KEYS: STALE-FRESHNESS SAFETY FAILS AT EXPECTED BOUNDARY`

## Claim limits

This is a candidate currentness mechanism, not a complete long-range-security theorem. It requires live reachability to a 5/7 active-committee quorum and continued protection/retirement of old committee keys. It does not solve later compromise of >=3 retired keys, arbitrary network eclipse liveness, physical multi-machine/WAN behavior, production membership discovery, Sybil resistance, power-loss durability, or malicious storage rollback.
