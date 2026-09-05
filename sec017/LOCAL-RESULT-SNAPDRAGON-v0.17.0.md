# CALIBRE SECURITY SEC-017 v0.17.0 — LOCAL SNAPDRAGON RESULT

Platform: Windows ARM64 on one physical Snapdragon host
TPM preflight: TPM 2.0 present, initialized, storage-ready, attestation-ready, PCR7-bound, not locked out

## Results reached

- Locked model tests: 5/5 PASS
- Platform provider reported `NCRYPT_IMPL_HARDWARE_FLAG`: PASS (`0x00000001`)
- Platform provider ECDSA P-256 support: PASS
- Unique current-user key creation, finalization, signing-only usage, public export, cross-process open, baseline signing, and mutated-transcript rejection: PASS
- ECC-private export probe returned `0x8009000A` (`NTE_BAD_TYPE`): format unsupported, so ordinary private-export containment was INCONCLUSIVE in v0.17.0

## Deletion failure

The first independent `NCryptDeleteKey` call returned `0x80090009` (`NTE_BAD_FLAGS`). The emergency exact-name cleanup used the same provider-rejected flag and returned the same status. Therefore:

- named-key retirement was **not applied**;
- the post-delete nonce and held-handle attack stage was **not reached**;
- SEC-017 v0.17.0 produced **no deletion/revocation safety conclusion**;
- the single printed disposable key name may remain in the current-user Platform provider until exact-name recovery cleanup succeeds.

## Remediation

SEC-017 v0.17.1 calls `NCryptDeleteKey` with flags zero, adds a guarded `--cleanup-exact` mode, and probes several standard private-export formats while distinguishing policy denial from unsupported formats. No TPM clear, PCR/NV write, hierarchy change, BitLocker change, existing-key enumeration, or machine-key operation is used.
