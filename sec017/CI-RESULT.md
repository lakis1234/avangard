# CALIBRE SECURITY SEC-017 — CI RESULT

GitHub Actions workflow run: `33964539233`
Commit: `e43c0d41800086c26af78dafe0bf500ec2076e31`
Platform: Microsoft Windows Server 2025 (`windows-2025-vs2026`)
Rust: `rustc 1.98.1 (48a229cea 2026-09-01)`
Cargo: `cargo 1.98.1 (797e8a9bc 2026-08-05)`

## Results

- Locked release model tests: 5/5 PASS
- Native hosted-Windows release build of the CNG code path: PASS
- Locked `aarch64-pc-windows-msvc` release type-check: PASS
- Locked-run `Cargo.lock` artifact matched the committed lockfile after CRLF normalization

## Execution boundary

CI did **not** run the live controller and did not create or delete a TPM key. The live mode remains gated by `CALIBRE_TPM_KEY_ACK=CREATE_DELETE_ONE_DISPOSABLE_KEY` and must be measured on the target Snapdragon Windows host.

## Claim limits

This CI result establishes compilation and deterministic model-test behavior. It does not establish TPM availability, Platform Crypto Provider behavior, key non-exportability, deletion semantics, pre-opened-handle revocation, same-TPM rollback resistance, physical erasure, or committee-level safety.
