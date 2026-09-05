# CALIBRE SECURITY SEC-017 — TPM Platform Key Containment / Pre-Opened Handle

SEC-017 is the first live Windows hardware-key follow-up to the pre-retirement software-secret snapshot attack demonstrated by SEC-016. It deliberately tests a narrow boundary before adding TPM NV generation policy or claiming committee-level protection.

The experiment creates exactly one uniquely named, current-user ECDSA P-256 key through the **Microsoft Platform Crypto Provider** on one physical host. It requires the provider to report `NCRYPT_IMPL_HARDWARE_FLAG`, forbids a software fallback, sets signing-only usage, leaves the default export policy unchanged, and requires the queried policy to be zero before continuing. A provider hardware flag does not identify whether the TPM is discrete, firmware-based, or integrated. It then tests:

1. TPM-provider ECDSA P-256 support.
2. Public-key export and ordinary ECC private-key export rejection.
3. A cross-process handle opened before retirement and a valid baseline freshness signature.
4. `NCryptDeleteKey` through a separately opened deletion handle.
5. Fresh open-by-name attempts while the attacker's old handle is live and again after it closes.
6. A never-before-seen client nonce delivered to the attack process only after deletion.
7. Whether the key name recovered from a checksummed CALIBRE application snapshot (containing only that name and public blob) resolves after deletion. Snapshot restoration itself is not described as recreating a key.

The pre-opened-handle outcome is intentionally empirical. Microsoft's documented `NCryptDeleteKey` contract says that it deletes the key and frees the handle passed to it; it does not promise that every other handle already open in another process is immediately revoked.

## Safety boundary

This live test:

- creates one unique current-user key and deletes only that exact name;
- never uses machine-key scope or overwrite;
- never calls TPM clear or initialization;
- never writes PCRs or TPM NV indexes;
- never changes hierarchy authorization, Secure Boot, BitLocker, or PPI state;
- never enumerates or deletes existing keys;
- never copies or edits the Windows CNG provider's internal key files.

The live mode requires this explicit acknowledgement:

```powershell
$env:CALIBRE_TPM_KEY_ACK="CREATE_DELETE_ONE_DISPOSABLE_KEY"
```

The crate pins Rust 1.98.1, matching the Windows ARM64 toolchain used for the surrounding CALIBRE experiments. GitHub CI compiles the Windows CNG path on a hosted x64 runner and runs the non-hardware model tests; the Snapdragon ARM64 build and TPM behavior are established only by the local command and its recorded output.

If execution is interrupted after key creation, the program prints the exact unique key name. Normal and error exits attempt cleanup using only that exact name.

## Interpretation

An ordinary private export denial demonstrates protection through that CNG export route. It does **not** prove that no opaque TPM-wrapped provider blob exists, that a same-TPM disk rollback cannot restore such a blob, or that physical key remnants are erased.

If the already-open attacker handle signs the post-delete fresh nonce, SEC-017 records a key-capability attack witness. If it is rejected, the result applies only to the tested provider and machine; cross-handle revocation is not treated as a general theorem.

This stage does not test a 5-of-7 committee and cannot close SEC-016's full long-range boundary. The protocol candidate after SEC-017 is a TPM monotonic generation plus fresh, client-nonce-bound NV certification under a pinned attestation key. Destructive disk rollback and sudden-power-loss testing belong on isolated vTPM/VHD or sacrificial hardware, not on this PCR7/BitLocker-bound computer.

## Claim limits

The following remain unproven: TPM key attestation and `fixedTPM`/`fixedParent` verification, same-TPM provider-blob rollback resistance, fresh TPM NV certification, physical erasure, power-loss atomicity, independent physical validators, WAN behavior, permissionless selection, and Sybil resistance.

No blockchain, blocks, DAG, or universal transaction order is used.
