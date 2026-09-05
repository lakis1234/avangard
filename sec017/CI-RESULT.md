# CALIBRE SECURITY SEC-017 v0.17.1 — CI RESULT

GitHub Actions workflow run: `33966113815`
Commit: `81a0d9c322983cebda244444571aec6c18ee8508`
Platform: Microsoft Windows Server 2025 (`windows-2025-vs2026`)
Rust: `rustc 1.98.1 (48a229cea 2026-09-01)`
Cargo: `cargo 1.98.1 (797e8a9bc 2026-08-05)`

## Results

- Locked release model tests: 6/6 PASS
- Native hosted-Windows release build of the CNG code path: PASS
- Locked `aarch64-pc-windows-msvc` release type-check: PASS
- Corrected zero-flag deletion calls, generated-name validation, and exact-name recovery mode compiled: PASS
- Expanded standard-private and opaque-provider export size-query classification compiled: PASS

## Execution boundary

CI did **not** run the live controller or recovery controller and did not create or delete a TPM key. Both live paths remain gated by `CALIBRE_TPM_KEY_ACK=CREATE_DELETE_ONE_DISPOSABLE_KEY` and must be measured on the target Snapdragon Windows host.

## Claim limits

This CI result establishes compilation and deterministic model-test behavior. It does not establish TPM availability, Platform Crypto Provider behavior, key non-exportability, deletion semantics, pre-opened-handle revocation, same-TPM rollback resistance, physical erasure, or committee-level safety.
