# CALIBRE SECURITY SEC-019 v0.19.0 — CI RESULT

GitHub Actions workflow run: `33972643453`  
Tested head commit: `6ca917a5226f27d5025e911e7782df206cef319b`  
Platform: GitHub-hosted Ubuntu 24.04 runner  
Software TPM: `swtpm 0.7.3` / `libtpms 0.9.3`  
TPM tools: `tpm2-tools 5.6`  
OpenSSL: `3.0.13`  
Python: `3.12.3`

## Results

- Strict `TPMS_ATTEST` parser unit tests: 5/5 PASS.
- Simulator attestation key reported `restricted`, `sign`, `fixedtpm`, `fixedparent`, and `sensitivedataorigin`: PASS in the isolated software TPM.
- Generation-1 `TPM2_NV_Certify`: RSA signature, TPM generated magic, `TPM_ST_ATTEST_NV` type, exact client nonce, pinned NV Name, zero offset, eight-byte contents, and counter value all verified.
- Simulator restart followed by `TPM2_NV_Increment`: generation 1 -> 2, PASS.
- Generation-2 fresh certification: all signature and content bindings verified.
- Generation-1 attestation presented for the generation-2 nonce/value: rejected.
- Identical same-handle, same-Name undefine/redefine followed by first increment: generation 2 -> 3, so it did not reset the counter in the uninterrupted simulator lifetime.
- Full file-backed `swtpm` state snapshot restored from generation 3 to generation 1: rollback succeeded, and the restored simulator produced a valid fresh generation-1 certification under the same persistent attestation key and pinned NV Name. Attack witness confirmed.
- Public evidence artifact: `sec019-public-attestation-evidence`, artifact ID `9971379284`, ZIP SHA-256 `e457338c12f9e2ad98d967ee957e27e38b5f0a054dd8f38e4314c9518fe44057`.

## Decision

`ACTUAL_TPM2_NV_INCREMENT_COMMAND_PATH=PASS_IN_ISOLATED_SWT_TPM`

`ACTUAL_TPM2_NV_CERTIFY_SIGNATURE_NONCE_NAME_VALUE_BINDING=PASS_IN_ISOLATED_SWT_TPM`

`PERSISTENT_COUNTER_ACROSS_SWT_TPM_RESTART=PASS_1_TO_2`

`IDENTICAL_SAME_NAME_NV_REDEFINE_DOES_NOT_RESET_COUNTER=PASS_2_TO_3`

`OLD_ATTESTATION_REPLAY_FOR_NEW_NONCE_AND_GENERATION=REJECTED`

`FULL_SWT_TPM_HOST_STATE_SNAPSHOT_ROLLBACK=STALE_GENERATION_1_FRESHLY_CERTIFIED_ATTACK_CONFIRMED`

## Claim limits

This proves the actual TPM2 tool/command integration and strict verifier behavior against the tested file-backed simulator. It does not prove physical TPM monotonicity, physical anti-rollback, power-loss durability, TPM-clear resistance, firmware resistance, vendor AK certificates, or the 5-of-7 result on seven physical machines.

No physical TPM, PCR, NV index, hierarchy, Secure Boot setting, BitLocker setting, or existing key was accessed. No blockchain, block, DAG, or universal transaction order was used.
