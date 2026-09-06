# CALIBRE INTEGRATION-001

INTEGRATION-001 begins assembling CALIBRE's previously isolated monetary and quorum mechanisms into one executable local experiment.

The current package implements **Phase A**, a bounded local integration run. The larger crash, partition, rotation, and offline-freshness campaign in [`PASS-MATRIX.md`](PASS-MATRIX.md) is **Phase B and is not implemented**. A successful Phase A run must never be reported as completion of the full 31-gate campaign.

## Exact scope

The Phase A target combines:

- canonical owner authorization;
- a value-conserving `100 CALIBRE -> 60 recipient + 39 change + 1 fee` transfer;
- seven validator identities with a five-share certificate threshold;
- up to two Byzantine validators in the tested adversarial scenarios;
- concurrent conflicting successors of one input;
- independent transfers over unrelated inputs;
- software-only test keys;
- deterministic laboratory salts and keys for repeatable evidence, not production randomness;
- machine-readable evidence when requested.

The exact gate definitions and decision rules are in [`PASS-MATRIX.md`](PASS-MATRIX.md).

The B10 opposing-QC probe is explicitly a synthetic white-box state-machine injection: the controller uses deterministic test fixture keys to construct a valid QC that the observed 3/2 network split did not produce. Evidence counts it separately from live transaction finality chains and never presents it as an adversary-obtained certificate.

## What "no blockchain" means here

The tested path has:

- no blocks;
- no block producer;
- no longest/heaviest-chain fork-choice rule;
- no blockchain height used to accept a payment;
- no universal transaction sequence shared by every independent payment.

CALIBRE still requires order where order is logically necessary:

- each monetary object has a causal predecessor and generation;
- conflicting successors of the same input require a unique choice;
- later committee generations will form an ordered control-plane lineage;
- validators may use local persistent state or a write-ahead journal.

Those local and causal orderings are not a universal ordering of all transactions. Because persistent distributed state can be called a ledger in a broad sense, this experiment supports the narrower claim **"no blockchain and no universal transaction order for independent payments"**, not an undefined absolute claim of "no ledger."

## What "no TPM" means here

INTEGRATION-001 uses software test keys. It does not:

- create, open, delete, or export a TPM key;
- use Windows TBS or the Microsoft Platform Crypto Provider;
- define, read, increment, or remove a TPM NV index;
- modify PCRs, BitLocker, TPM ownership, hierarchy authorization, or firmware state;
- require a TPM acknowledgement environment variable or administrator access.

TPM experiments SEC-017 and SEC-018 are not dependencies of this integration package. Hardware key protection may be evaluated later as optional validator hardening, not as CALIBRE's protocol identity.

## Run modes

Run all compile-time/unit/model tests:

```bash
cd integration001
cargo test --release --locked
```

Run the default live Phase A integration:

```bash
cd integration001
cargo run --release --locked
```

The default uses the full implemented audit batch of 128 unrelated payments and performs two clean, isolated executions before reporting repeatability or a final Phase A decision.

Run Phase A and request a machine-readable evidence file:

```bash
cd integration001
cargo run --release --locked -- --evidence integration001-phase-a-evidence.json
```

Run the maximum implemented unrelated-payment benchmark count and save evidence:

```bash
cd integration001
cargo run --release --locked -- --bench-count 128 --evidence integration001-phase-a-evidence.json
```

`--bench-count` accepts a value from `1` through `128`. The requested count and the count actually completed must both appear in the result/evidence. An invalid or out-of-range value must fail rather than silently changing the audit configuration.

Counts below 128 are diagnostic runs. They report `B11=NOT_RUN_AT_AUDIT_COUNT` and make the overall Phase A result `INCONCLUSIVE`; only the default/full `128` setting can produce the Phase A `PASS` headline.

`--evidence <path>` writes the implemented Phase A evidence. Creating an evidence file does not imply the evidence is complete or that any unimplemented Phase B gate ran.

## Run-mode claim boundaries

| Invocation | Permitted conclusion |
|---|---|
| `cargo test --release --locked` | Unit/model tests passed or failed. It is not a live-integration result. |
| Default `cargo run` | Phase A live result only. |
| `cargo run ... --evidence <path>` | Phase A live result plus a machine-readable record of implemented measurements. |
| `cargo run ... --bench-count 128` | Phase A live result including the largest implemented unrelated-payment batch. It is not a scalability or WAN benchmark. |
| Any requested Phase B/campaign mode | `NOT IMPLEMENTED`; it must fail closed or be rejected. There is currently no Phase B command. |

No output is allowed to infer that crash/restart, exhaustive partitions, committee rotation, or offline freshness passed merely because earlier SEC experiments tested related mechanisms separately.

## Phase A result language

The strongest valid successful headline is:

```text
CALIBRE INTEGRATION-001 PHASE A: PASS
CALIBRE INTEGRATION-001 FULL CAMPAIGN: NOT IMPLEMENTED / NOT RUN
```

Any unauthorized certificate, two conflicting certified successor intents for one input/version, value-creation error, or duplicate/non-member quorum inflation is a hard failure. Multiple valid signer-subset QCs for the same intent are equivalent evidence, not conflicting successors.

An equivocating owner may cause its own input to produce no certificate. This is a safe result if both conflicting intents are not certified, but it must be printed as:

```text
SAFETY PASS / EQUIVOCATION LIVENESS NOT GUARANTEED
```

It must not be described as full liveness.

## Phase B remains future work

Phase B must be implemented and executed before a full INTEGRATION-001 decision. It includes:

- 15 exact crash-window cases across five honest validators;
- restart recovery and conflict refusal;
- all 35 placements of a 4/3 partition;
- all 21 placements of a 5/2 partition;
- delayed-message healing;
- atomic old-to-new committee freeze/handoff/activation;
- payment-versus-rotation races;
- retired-committee restart behavior;
- spending an inherited state after rotation;
- stale-prefix, fresh-nonce, replay, and fewer-than-five offline-client cases;
- full CPU, RSS, network, persistence, recovery, rotation, state-growth, and latency-percentile evidence.

Until those gates exist and run, the full campaign status is `NOT_IMPLEMENTED / NOT_RUN`.

## What a successful Phase A run does not establish

It does not establish physical multi-machine behavior, WAN performance, formal correctness, data availability, decentralization, Sybil resistance, economics, malicious disk-rollback protection, key erasure, more-than-two-Byzantine safety, post-quantum security, privacy, smart contracts, interoperability, horizontal scalability, production readiness, or a fastest-protocol claim.

Use [`PASS-MATRIX.md`](PASS-MATRIX.md) as the controlling audit document whenever the executable output and a prose summary appear to differ.
