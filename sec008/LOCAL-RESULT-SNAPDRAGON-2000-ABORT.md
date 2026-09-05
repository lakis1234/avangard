# CALIBRE SECURITY SEC-008 — LOCAL SNAPDRAGON RESULT

Platform: Windows ARM64 / Snapdragon X / Rust 1.98.1
Requested campaign: 2000 trials
Seed: `14128276799733366785`

## Result before abort

- 4/4 unit tests: PASS
- baseline five-honest-node finalization with two Byzantine nodes unavailable: PASS (5/7)
- deterministic honest 3/2 conflict split with two Byzantine withholders: conflict-liveness deadlock attack CONFIRMED
- global blockchain / universal transaction order: NOT USED

## Abort

The campaign stopped at trial 1000 with:

`SEC-008 ERROR: restart lost honest durable lock at trial 1000 node 4`

Therefore this local 2000-trial run is **NOT a completed SEC-008 PASS**. It did not report a dual-finality violation before the abort, but the campaign ended before a full safety summary could be produced.

## Required interpretation

Treat the failure as a durability/harness finding until isolated. Do not assume either that Windows lost a correctly synced production lock or that the error is harmless. The next experiment, SEC-008.1, isolates WAL persistence and restart replay with a stronger checksummed record format, direct controller-side WAL verification before and after process restart, and repeated crash/restart cycles including an explicit trial-1000 checkpoint.
