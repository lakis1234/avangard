# CALIBRE SEC-017 v0.17.1 — Snapdragon Windows TPM Live Result

Date: 2026-09-05  
Scope: one Windows ARM64 Snapdragon host, one current-user disposable ECDSA P-256 key, Microsoft Platform Crypto Provider  
Evidence status: user-executed live output; not an independent multi-machine reproduction

## Host preflight

- TPM present: yes
- TPM version: 2.0
- Manufacturer identifier: `MSFT`
- Manufacturer version: `9.0.1.77`
- Initialized and ready for storage/attestation: yes
- Provider hardware implementation flag: `0x00000001`
- BitLocker PCR7 binding: bound
- Vulnerable firmware reported by Windows: no

The provider flag establishes that the selected KSP reports hardware implementation. It does not identify whether the TPM is discrete, firmware-based, or integrated.

## Deterministic checks

- Rust unit tests: 6 passed, 0 failed
- Exact cleanup-name validation: pass
- Freshness transcript binds key name and nonce: pass
- Snapshot mutation detection and public-only round trip: pass

## Live findings

| Probe | Observed result | Classification |
|---|---|---|
| Exact recovery of the v0.17.0 key name | Already absent | Safe; no old named key was found |
| TPM ECDSA P-256 key creation/finalization/signing | Pass | Hardware-provider signing path worked |
| Public-key export | 72-byte public blob | Pass |
| ECC private blob size query | `NTE_BAD_TYPE (0x8009000A)` | Format unsupported; not proof of policy denial |
| Generic private blob size query | `NTE_BAD_TYPE (0x8009000A)` | Format unsupported; not proof of policy denial |
| PKCS #8 private blob size query | `NTE_BAD_TYPE (0x8009000A)` | Format unsupported; not proof of policy denial |
| Opaque provider blob size query | `NTE_BAD_FLAGS (0x80090009)` | Inconclusive; not proof of denial or availability |
| Mutated-transcript replay | Rejected | Pass |
| Independent named-key deletion | Success | Pass |
| Fresh open by name while another process retained a handle | `NTE_BAD_KEYSET (0x80090016)` | Rejected |
| Previously opened cross-process handle after deletion | Produced a valid signature for a new nonce | **Attack witness confirmed** |
| Fresh open after the held process exited | `NTE_BAD_KEYSET (0x80090016)` | Rejected |
| Restored application snapshot resolves to a live key | No | Pass only for this public-only application snapshot |
| Post-test exact-name cleanup | No owned named key remained | Pass |

## Security conclusion

The run establishes an important negative result on this machine:

> Deleting the persisted TPM key name prevents new opens but does not revoke a handle that another process opened before deletion.

The held process signed a never-before-seen post-deletion nonce, and the signature verified under the retired public key. This is a real stale-signer witness, not a replay of an old signature.

Therefore CALIBRE must not treat `NCryptDeleteKey` by itself as immediate cryptographic retirement. An attacker that obtained or retained an already-open handle can continue using that retired key for at least the lifetime demonstrated by this process.

## What this proves for CALIBRE

- Hardware-backed key creation and signing worked through the selected Windows Platform KSP.
- Application snapshots containing only the key name and public material did not recreate the deleted named key.
- Named-key deletion blocked future opens in the tested provider.
- Named-key deletion did **not** stop an already-open signing handle.
- The current SEC-015/SEC-016 retirement design needs a verifier-enforced generation mechanism in addition to key deletion or software ratcheting.

## What is not yet proven

- Raw private-key non-exportability across every provider-specific route
- Opaque provider-blob export or same-TPM restore behavior
- Full-disk rollback resistance
- TPM key attestation properties such as `fixedTPM` and `fixedParent`
- TPM NV monotonic generation and client-nonce-bound certification
- Protocol rejection of the valid old-key signature
- Five-of-seven stale-quorum safety across separate physical TPMs
- Physical key erasure, reboot behavior, suspend behavior, crash atomicity, or power-loss semantics

## Required architectural consequence

A CALIBRE freshness share must eventually bind at least:

`protocol domain || committee generation || state digest || client nonce || signer identity`

and the verifier must reject an old signing key even when that key can still perform raw TPM operations. The next security stage should first test whether a non-rollbackable hardware generation and attestation can be bound to the client nonce and signer identity. Only after that single-node primitive passes should it be evaluated across a physical 5-of-7 committee.

## Safety record

No TPM clear, PCR change, NV change, hierarchy change, BitLocker change, machine-key operation, or modification of an existing key was performed. The disposable key name from this run did not remain openable after the held process closed.
