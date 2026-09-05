# CALIBRE SECURITY SEC-018 v0.18.0 — CI Result

GitHub Actions workflow run: `33988320474`  
Commit: `75783c90a7978124df8d6dc48043ba26d2fd4ca3`  
Platform: GitHub-hosted `windows-latest`  
Rust: `rustc 1.98.1 (48a229cea 2026-09-01)`  
Cargo: `cargo 1.98.1 (797e8a9bc 2026-08-05)`

## Results

- Locked release model tests: 10/10 PASS
- Generation-view snapshot integrity and semantic consistency tests: PASS
- Generation, key-id, and nonce rejection gates: PASS
- Full share-transcript field-binding test: PASS
- Native Windows release build of the CNG live path: PASS
- Locked `aarch64-pc-windows-msvc` release type-check: PASS
- Resolved dependency lockfile artifact: preserved

## Execution boundary

CI compiled the complete Windows live controller and ran only the deterministic model tests. It did not invoke the controller, create or delete Platform KSP keys, or interact with TPM hardware.

The live path remains gated by:

```text
CALIBRE_TPM_KEY_ACK=CREATE_DELETE_TWO_DISPOSABLE_KEYS
```

## Claim limits

This CI result establishes compilation and model behavior. It does not establish the Snapdragon provider's two-key runtime behavior, post-delete retained-handle signing, protocol rejection of a real old-key signature, TPM attestation, non-rollbackable currentness, TPM NV behavior, physical erasure, power-loss atomicity, or five-of-seven committee safety.
