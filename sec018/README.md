# CALIBRE SECURITY SEC-018 — Generation-Bound Gate Against a Retained TPM Handle

SEC-018 follows the live SEC-017 finding that deleting a named Microsoft Platform Crypto Provider key did not revoke a different process's already-open handle. It asks the protocol question that SEC-017 deliberately left unanswered:

> Can a raw signature that is still cryptographically valid under a retired TPM key be rejected by CALIBRE because the signer generation and public-key set are no longer active?

The Windows experiment creates exactly two uniquely named, current-user ECDSA P-256 signing keys through the Microsoft Platform Crypto Provider:

- generation 60: the old key, opened by a separate process before retirement;
- generation 61: the active replacement key.

The CALIBRE share transcript binds the protocol domain, generation, validator identity, state identity, active key id, active keyset hash, state root, and a fresh client nonce. The verifier performs exact active-view checks before verifying the signature under the public key registered for that active generation.

## Attacks and controls

The controller performs these steps:

1. Accepts a valid generation-60 share before retirement as a baseline.
2. Deletes the named old key while a separate process retains a pre-opened handle.
3. Gives that process a never-before-seen nonce after deletion and confirms that its raw signature remains valid under the old public key on the tested provider.
4. Applies the generation-61 CALIBRE gate and requires rejection of the truthful old-generation share.
5. Makes the old handle sign a transcript relabelled as generation 61 and requires rejection under the registered generation-61 public key.
6. Attempts to substitute the old key id into the active generation and requires rejection.
7. Requires a fresh generation-61 share to pass and a replay to a different client nonce to fail.
8. Restores the checksummed generation-60 application view and confirms the remaining long-range boundary: a verifier that trusts the rolled-back view accepts the old share.

The last attack is intentional. SEC-018 proves only that the generation gate works when the verifier has the correct active view. It does not claim that local application storage is non-rollbackable or that an offline client can discover currentness from an old certificate alone.

## Safety boundary

The live experiment:

- creates exactly two unique current-user keys and deletes only those exact names;
- verifies each public key before exact-name cleanup during the same run;
- never uses machine-key scope or overwrite;
- never calls TPM clear or initialization;
- never writes or defines TPM NV indexes;
- never changes PCRs, hierarchy authorization, Secure Boot, BitLocker, or PPI state;
- never enumerates or deletes existing keys;
- never copies or edits the Windows provider's internal key files.

The live mode requires this explicit acknowledgement:

```powershell
$env:CALIBRE_TPM_KEY_ACK="CREATE_DELETE_TWO_DISPOSABLE_KEYS"
```

If the run is interrupted after either key is created, the program prints both exact generated names. Each can be recovered separately with:

```powershell
cargo run --release --locked -- --cleanup-exact "CALIBRE_SEC018_OLD_<exact-generated-suffix>"
cargo run --release --locked -- --cleanup-exact "CALIBRE_SEC018_ACTIVE_<exact-generated-suffix>"
```

Recovery accepts only the complete generated SEC-018 naming format, opens current-user Platform KSP scope without enumeration, and deletes only the supplied exact name.

## Correct interpretation

A successful live run establishes all of the following on the tested host:

- a pre-opened retired TPM handle can still create a raw signature after named-key deletion;
- that raw old share is rejected against the correct active generation view;
- changing the generation label does not turn the old key into an active member;
- substituting the old key id is rejected;
- the active key can answer the fresh nonce;
- replaying the response to a different nonce is rejected;
- rolling the verifier's local generation view back re-enables the long-range attack.

This is a conditional protocol result, not a complete currentness solution. A checksum detects accidental mutation but cannot prevent an attacker from restoring an intact old snapshot.

## Claim limits

SEC-018 does not test TPM key attestation, `fixedTPM`/`fixedParent`, TPM NV monotonic state, same-TPM provider-blob rollback, power-loss atomicity, physical key erasure, five-of-seven quorum safety, multiple physical machines, WAN behavior, formal security, post-quantum signatures, permissionless validator selection, or Sybil resistance.

The next hardware stage, SEC-019, must investigate a fresh non-rollbackable active-generation anchor separately. TPM NV mutation must not be silently added to this test because even a disposable counter changes persistent hardware state.

No blockchain, block, DAG, transaction ledger, or universal transaction order is used.
