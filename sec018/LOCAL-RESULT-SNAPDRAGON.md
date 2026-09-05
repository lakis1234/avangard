# CALIBRE SECURITY SEC-018 v0.18.0 — LOCAL SNAPDRAGON RESULT

Date: 2026-09-05  
Platform: Windows ARM64 / Snapdragon  
Visual Studio Build Tools: 2022 v17.14.25  
Rust dependency resolution: locked for Rust 1.98.1

## Configuration

- N = 7, Q = 5
- retired generation 70; active generation 71
- seven separate OS processes over real TCP loopback on one physical host
- all seven old monetary-signing handles deliberately remain usable after retirement
- nodes 0..4 model honest devices advanced to generation 71
- nodes 5..6 model Byzantine devices remaining at generation 70
- no blockchain, blocks, DAG, or universal transaction order
- software protocol model only; no live TPM NV operation

## Results

- Locked release unit tests: 7/7 PASS
- Abstract monotonic rule: 70 -> 71 accepted; 71 -> 70 rejected
- Pre-retirement generation-70 combined freshness: 7/7
- Post-retirement raw old-handle signatures remained available: 7/7, preserving the SEC-017 attack capability
- Post-retirement old state with matching generation attestation: 2/7, below quorum
- Current generation-71 combined freshness: 5/7, quorum accepted
- Old NV proof plus monetary signature replay under a new client nonce: 0/7, rejected
- Old monetary signature mixed with current generation-71 attestation: rejected
- Wrong or redefined NV-index Name: rejected by pinned-name check
- Restored generation-70 application state while five honest modeled NV generations remained 71: 2/7, below quorum
- Three compromised pinned attestation keys plus two Byzantine generation-70 devices: 5/7 stale quorum attack witness confirmed

## Decision

`EXPERIMENT_EXECUTION=PASS`

`OLD_PREOPENED_SIGNING_HANDLES_WITHOUT_MATCHING_GENERATION_ATTESTATION=REJECTED_2_OF_7_IN_TESTED_MODEL`

`CURRENT_GENERATION_COMBINED_FRESHNESS=ACCEPTED_5_OF_7_IN_TESTED_MODEL`

`OLD_NONCE_BOUND_ATTESTATION_REPLAY=REJECTED`

`APPLICATION_STATE_ROLLBACK_WITHOUT_MODELED_NV_ROLLBACK=REJECTED_2_OF_7`

`THREE_PINNED_ATTESTATION_KEYS_COMPROMISED=STALE_5_OF_7_ATTACK_CONFIRMED`

## Claim limits

This local run validates the software acceptance rule, process isolation, TCP transport, signature binding, and 5-of-7 threshold behavior on one Windows ARM64 host. It does not execute or prove live TPM NV monotonicity, `TPM2_NV_Increment`, `TPM2_NV_Certify`, pinned attestation-key hardware attributes, hardware non-exportability, TPM-clear resistance, NV undefine/redefine resistance, physical erasure, power-loss atomicity, independent physical validators, or WAN behavior.

No TPM clear, PCR write, NV operation, hierarchy change, Secure Boot change, BitLocker change, or existing-key operation was performed.
