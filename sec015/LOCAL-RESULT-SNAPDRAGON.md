# CALIBRE SECURITY SEC-015 — LOCAL SNAPDRAGON ARM64 RESULT

Platform: Windows 11 ARM64 / Snapdragon X Plus development machine
Experiment: `calibre-sec015 v0.15.0`

## Local result

- Unit tests: 5/5 PASS
- Epochs 30 -> 31 -> 32, each committee N=7, Q=5
- 21 separate OS processes over real TCP loopback on one physical host
- Naive certificate-only offline bootstrap accepted a cryptographically valid stale epoch-31 / generation-2 prefix: LONG-RANGE CURRENTNESS ATTACK CONFIRMED
- Stale epoch-31 committee after valid 31->32 handoff answered a fresh client nonce with only 4/7 shares: stale prefix rejected / fail-closed
- Replay of an old 5/7 freshness certificate against a new client nonce failed signature verification
- Restarted retired epoch-31 honest signer remembered retirement and rejected the new freshness challenge
- Current epoch-32 five honest nodes produced a valid 5/7 freshness certificate over exact epoch + state + nonce
- Only 3/7 current honest nodes reachable: no freshness QC; client pauses rather than accepting stale state
- f=3 / three old keys compromised boundary: 3 Byzantine old keys + 2 non-retired honest signers can form a stale 5/7 freshness response — ATTACK WITNESS CONFIRMED

## Decision

`CERTIFICATE-ONLY OFFLINE CURRENTNESS: FAIL / STALE VALID PREFIX ATTACK CONFIRMED`

`LIVE CLIENT-NONCE 5-OF-7 CURRENT-STATE FRESHNESS CHALLENGE WITH f<=2: PASS IN TESTED HANDOFF SCENARIO`

`RETIRED COMMITTEE CANNOT ANSWER NEW 5/7 FRESHNESS CHALLENGE WITH f<=2 IN TESTED SCENARIO: PASS`

`OLD FRESHNESS RESPONSE REPLAY ACROSS CLIENT NONCES: REJECTED`

`RETIRED-SIGNER PROCESS RESTART MEMORY: PASS`

`TOTAL ECLIPSE / <5 CURRENT NODES REACHABLE: CLIENT FAILS CLOSED; LIVENESS NOT GUARANTEED`

`F=3 OR LATER COMPROMISE OF >=3 RETIRED COMMITTEE KEYS: STALE-FRESHNESS SAFETY FAILS AT EXPECTED BOUNDARY`

## Claim limits

This is a candidate currentness mechanism, not a complete long-range-security theorem. It still requires live reachability to a 5/7 active-committee quorum and continued protection/retirement of old committee keys. Later compromise of >=3 retired signing keys remains a demonstrated attack boundary. Physical multi-machine/WAN behavior, arbitrary network-eclipse liveness, production membership discovery, Sybil resistance, power-loss durability, malicious storage rollback, and production finality remain unproven.
