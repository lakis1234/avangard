# CALIBRE SECURITY SEC-018 v0.18.0 — CI RESULT

GitHub Actions workflow run: `33971066860`  
Head commit: `62a850040bbd25b9cfb217bd7a6a53f676e8c06a`  
Platform: Microsoft Windows Server 2025 (`windows-2025-vs2026`)  
Rust: `rustc 1.98.1 (48a229cea 2026-09-01)`

## Results

- Locked release unit tests: 7/7 PASS
- Locked release adversarial executable: PASS
- Windows ARM64 locked release type-check: PASS
- Seven separate OS processes communicated over real TCP loopback
- Pre-retirement generation-70 combined freshness: 7/7
- After five modeled monotonic advances to generation 71, all seven retained old signing handles still answered, but only the two Byzantine generation-70 devices produced matching combined shares: 2/7, below quorum
- Current generation-71 combined freshness: 5/7, quorum accepted
- Old combined certificate replay under a new client nonce: 0/7
- Old monetary signature mixed with generation-71 attestation: rejected
- Wrong/redefined NV-index Name: rejected by pinned-name check
- Restored generation-70 application state while five honest modeled NV generations remained 71: 2/7, below quorum
- Three deliberately compromised pinned attestation keys plus two Byzantine generation-70 devices: 5/7 stale quorum attack witness confirmed

## Decision

`EXPERIMENT_EXECUTION=PASS`

`OLD_PREOPENED_SIGNING_HANDLES_WITHOUT_MATCHING_GENERATION_ATTESTATION=REJECTED_2_OF_7_IN_TESTED_MODEL`

`CURRENT_GENERATION_COMBINED_FRESHNESS=ACCEPTED_5_OF_7_IN_TESTED_MODEL`

`OLD_NONCE_BOUND_ATTESTATION_REPLAY=REJECTED`

`APPLICATION_STATE_ROLLBACK_WITHOUT_MODELED_NV_ROLLBACK=REJECTED_2_OF_7`

`THREE_PINNED_ATTESTATION_KEYS_COMPROMISED=STALE_5_OF_7_ATTACK_CONFIRMED`

## Claim limits

This CI result validates the software acceptance rule and threshold arithmetic. It does not use a TPM and does not prove live TPM NV monotonicity, `TPM2_NV_Certify`, attestation-key attributes, hardware non-exportability, TPM-clear resistance, NV undefine/redefine resistance, power-loss durability, or physical multi-machine/WAN behavior.

No TPM clear, PCR write, NV operation, hierarchy change, Secure Boot change, BitLocker change, existing-key operation, blockchain, block, DAG, or universal transaction order was used.
