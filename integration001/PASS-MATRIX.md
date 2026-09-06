# CALIBRE INTEGRATION-001 — Audit-Ready Pass Matrix

Status: two-phase verification specification
Protocol scope: single-input monetary successors, `N=7`, `Q=5`, `f<=2`
Excluded dependencies: blockchain, universal transaction ordering, TPM or other trusted hardware

## 1. Claim-control rule

INTEGRATION-001 has two intentionally separate phases.

- **Phase A — implemented local integration:** the mandatory gates exercised by the current package's unit/model tests and default live run.
- **Phase B — extended fault campaign:** crash-window injection, exhaustive network partitions, atomic committee rotation, and offline-freshness attacks. Phase B is a specification for later implementation. It is **not implemented**, and no current output may mark a Phase B gate `PASS`.

The words `INTEGRATION-001 FULL PASS` are forbidden unless every mandatory Phase A and Phase B gate has real execution evidence. Compilation, unit tests, a Phase A live run, or an evidence file cannot substitute for a Phase B campaign.

Allowed statuses are:

| Status | Meaning |
|---|---|
| `PASS` | The exact gate ran, its fault/precondition was observed, and every stated criterion held. |
| `FAIL` | The gate ran and at least one mandatory safety or liveness criterion was violated. |
| `INCONCLUSIVE` | The run started, but the required injection, observation, or evidence was missing or ambiguous. |
| `NOT_RUN` | An implemented gate was not executed in this run. |
| `NOT_IMPLEMENTED` | The mechanism or campaign does not exist in the current package. It can never be counted as `PASS`. |
| `EXPECTED_BOUNDARY` | A documented out-of-scope limitation was reproduced. This is not a security pass. |

## 2. System and trust assumptions

The experiment models a CALIBRE monetary state as a uniquely identified, versioned object containing an asset identifier, value, owner public key, and predecessor/state digest. A transfer consumes one current state and creates deterministic successor states.

The active committee contains seven distinct validator identities and requires five distinct valid shares for a certificate. The quorum-intersection lower bound is:

```text
2Q - N = (2 * 5) - 7 = 3
```

Therefore, two 5-of-7 quorums intersect in at least three validators. With at most two Byzantine validators, their intersection contains at least one honest validator. Safety additionally depends on that honest validator never authorizing two conflicting successors and durably preserving the relevant lock before releasing its share.

The following are trusted or assumed for this experiment:

- the initial network identifier and committee manifest are authentic;
- at most two of the seven active validators are Byzantine;
- owner and honest-validator private keys are not stolen;
- the signature and hash primitives are not broken;
- random challenges and transaction salts are unpredictable where required;
- honest processes execute the tested binary and their stable storage is not maliciously rolled back or edited;
- eventual liveness is required only after at least five protocol-following validators can communicate;
- Phase A processes on one host are adequate only as local implementation evidence, not independent physical failure domains.

Phase A deliberately uses deterministic fixture keys and salts so its clean rerun can be compared exactly. The unpredictability assumption applies to any future production deployment and to Phase B freshness challenges; Phase A does not claim to test a production RNG.

## 3. Adversary capabilities

Within the test boundary, the adversary may:

- control two validator processes and make them equivocate, forge protocol claims using only their own valid keys, sign selectively, stay silent, retain old software keys, or collude;
- make an owner intentionally authorize two mutually conflicting spends of the same input;
- deliver the two conflicts to honest validators in different orders;
- delay, reorder, duplicate, replay, or drop messages;
- create tested 4/3 and 5/2 partitions and later heal them;
- kill and restart honest validator processes at instrumented persistence boundaries;
- present a client with a genuine but stale certificate prefix;
- replay a genuine old freshness response against a new challenge;
- submit certificates containing duplicate signers, non-members, wrong generations, wrong committees, or altered contents.

The adversary is not assumed able to:

- forge an honest signature or break the cryptographic primitives;
- control three or more active validators;
- compromise the host kernel, RNG, compiler, or all loopback processes at once;
- roll back or maliciously rewrite honest stable storage;
- extract honest keys or accumulate five retired-committee keys;
- permanently eclipse the client while still demanding successful progress.

## 4. Mandatory protocol bindings

An owner authorization must bind a canonical representation of at least:

```text
CALIBRE transfer domain and version
network identifier
committee identifier/generation used for authorization
input object identifier and version/generation
input state digest
complete ordered output/effect description
protocol fee
transaction salt or equivalent replay-binding value
```

Every validator share must additionally bind the exact committee identity, committee generation, protocol phase/round where applicable, and the full owner-authorized intent digest.

The conflict lock must be scoped at least to:

```text
(asset_id, input_id, input_version_or_generation)
```

and must select the complete transaction/intent digest. If a share is visible outside an honest process, the corresponding lock must already be recoverable after restart.

A freshness response must bind:

```text
CALIBRE_FRESHNESS_V1
network_id
committee_id and generation
subject/input identifier
exact subject state digest
fresh client nonce
```

No shared mutable fee object may silently serialize otherwise unrelated payments. Independent fee cells, sharding, or another separately verified commutative mechanism is required for a later production claim.

## 5. Safety and liveness separation

Safety must hold during arbitrary delay, reordering, duplication, Byzantine equivocation, Byzantine withholding, and the tested partitions, provided `f<=2` and honest stable storage is not rolled back.

Liveness is conditional. A valid, non-conflicting transfer must progress after eventual communication among at least five honest validators. A malicious owner that signs two concurrent successors may self-stall its input. If five honest first-seen locks split 3/2 and both Byzantine validators withhold, neither conflict reaches five shares.

Consequently:

```text
two certified successors                       = hard safety failure
zero certified successors after owner equivocation = allowed safety result
zero certified successors for a normal transfer
  after five honest validators can communicate = liveness failure
```

Guaranteed resolution of an equivocating input requires a safe per-object round/view-change protocol; a permanent first-seen lock alone proves at-most-one finality, not exact-one progress. Such a protocol would still be conflict-local and need not impose a universal transaction order.

## 6. Phase A — implemented mandatory gates

Phase A is the only phase the current default live run may claim. A valid Phase A report must identify every Phase A row below and attach machine-readable evidence when the evidence mode is used.

| ID | Scenario | Strict `PASS` condition |
|---|---|---|
| B01 | Topology preflight | Seven distinct validator identities, threshold five, exactly two configured Byzantine identities where the scenario requires them, clean state, protocol version, test seed, and run configuration are recorded. |
| B02 | Quorum validation | Five distinct active members are accepted. Four shares, duplicate identities, non-members, wrong committee, wrong generation, altered payload, and invalid signatures are rejected. |
| B03 | Normal payment | Alice's input value `100` creates Bob `60`, Alice change `39`, and protocol fee `1`, with exactly one certified successor intent backed by a valid 5-of-7 PREVOTE-to-PRECOMMIT chain. Multiple valid signer-subset QCs for that same intent do not count as conflicting successors. |
| B04 | Owner authorization | Unsigned, wrong-owner, or malformed authorizations can obtain at most the two Byzantine shares and never form a certificate. |
| B05 | Signed-field mutation | Mutating recipient, amount, fee, input identity, input generation, asset, network, committee generation, or any output/effect invalidates the owner authorization. |
| B06 | Monetary conservation | The accepted successor outputs plus fee equal the consumed value exactly. Checked arithmetic prevents overflow; no losing-conflict output, hidden mint, negative-equivalent value, or duplicate fee exists. |
| B07 | Duplicate submission | Repeating the identical authorized intent is idempotent: it cannot create a second spend, a second fee, a different successor, or inflate certificate weight. |
| B08 | Equivocating-owner boundary | An owner signs two valid conflicting intents. The result contains zero or one certified successor intent, never two conflicting certified intents. Zero is reported as `SAFETY_PASS / EQUIVOCATION_LIVENESS_NOT_GUARANTEED`, not as full liveness. |
| B09 | Exhaustive quorum/conflict model | All `2^5 * 4^2 = 512` abstract cases are evaluated: each of five honest signers first selects A or B, while each Byzantine signer selects A, B, both, or neither. No case certifies both conflicting intents. |
| B10 | Live concurrent conflict | Real concurrent delivery gives the same input two valid owner-authorized successors. Honest validators never issue conflicting PRECOMMITs or violate a durable PRECOMMIT lock; at most one conflicting successor intent is certified; outputs of the loser do not become live. Multiple signer-subset QCs for the same intent are allowed. Any controller-constructed QC using honest fixture keys is labeled as a synthetic white-box state-machine injection, not as an adversary-obtained QC. A validator may change an uncertified PREVOTE in a later round, so this gate must not claim otherwise. Any claim that all 32 honest first-arrival patterns ran must be supported by 32 separately identified outcomes. |
| B11 | Unrelated payment batch | Up to 128 distinct input objects are submitted concurrently. At the audit setting `--bench-count 128`, all 128 valid, non-conflicting transfers finalize when five honest validators are available, with zero cross-input conflict. |
| B12 | Schedule independence | The same independent transfer set is executed under each schedule actually implemented and reported. The final live-state multiset and monetary totals match. Forward, reverse, and five seeded shuffles remain Phase B-quality evidence unless all seven schedules are present. |
| B13 | No acceptance-critical universal order | Transaction/certificate validity does not depend on a block hash, block height, longest-chain/fork-choice rule, global transaction sequence, completion-order-derived identifier, or shared mutable global fee state. Per-object generation and committee generation are allowed and must be reported separately. |
| B29 | No TPM or blockchain dependency | The package performs no TPM, TBS, CNG Platform KSP, PCR, NV, BitLocker, secure-element, block-production, or chain-selection operation. Software test keys and ordinary process/filesystem state are used. |
| B30-A | Phase A evidence and metrics | The run configuration, executed Phase-A gate/scenario counts, accepted/rejected counts, certificate counts, conservation totals, benchmark count, elapsed time/throughput reported by the implementation, and all mandatory safety decisions are present and internally consistent. Unit-test execution is reported separately by `cargo test`; the live binary must not invent that result. Missing required evidence makes the affected result `INCONCLUSIVE`, not `PASS`. |
| B31-A | Phase A cleanup and repeatability | All child processes terminate and test-owned temporary state is removed or isolated. A clean rerun produces the same safety decisions. Byte-identical timing or signatures are not required unless the implementation claims determinism. |

### Phase A decision

```text
PHASE_A_PASS =
    every implemented mandatory Phase A row executed and passed
    AND no unauthorized certificate
    AND no two conflicting successor intents are certified for the same input/version
    AND no monetary conservation violation
    AND no missing or ambiguous required evidence

PHASE_A_INCONCLUSIVE =
    no hard failure was observed
    BUT any mandatory Phase A gate did not actually execute,
    its required injection was not observed, or its evidence is incomplete

PHASE_A_FAIL =
    any mandatory Phase A safety property is violated
    OR a normal non-conflicting transfer fails to progress after
       five honest validators are available under the tested healthy schedule
```

A Phase A pass must be printed and documented only as:

```text
CALIBRE INTEGRATION-001 PHASE A: PASS
CALIBRE INTEGRATION-001 FULL CAMPAIGN: NOT IMPLEMENTED / NOT RUN
```

## 7. Phase B — campaign gates not implemented

Every row in this section is presently `NOT_IMPLEMENTED`. These gates describe the finite campaign needed before a full INTEGRATION-001 result can exist.

| ID | Scenario | Strict `PASS` condition |
|---|---|---|
| B14 | Crash-window persistence | For each of five honest validators, force termination at three hooks—before durable lock, after durable lock/before reply, and after reply—for 15 identified executions. No externally visible share may lack a recoverable lock. A crash that misses its exact hook is `INCONCLUSIVE`. |
| B15 | Restart conflict refusal | After every post-persistence restart, the validator can replay or validate its same choice but refuses a conflicting intent. A pre-persistence crash emitted no external share and may safely make a new choice. |
| B16 | Exhaustive 4/3 partitions | Exercise all `C(7,3)=35` three-node-minority placements. Neither side can form a five-share certificate before healing. After healing, a normal transfer progresses and conflicting transfers produce at most one certificate. |
| B17 | Exhaustive 5/2 partitions | Exercise all `C(7,2)=21` two-node-minority placements. The minority never certifies. A side with five responsive valid signers may certify. Once healed, every honest node converges on any certified successor. |
| B18 | Delayed-message healing | Old, duplicated, reordered, and selectively delayed votes delivered after healing cannot create a second successor, regress state, or inflate quorum weight. |
| B19 | Atomic committee rotation | A valid old 5-of-7 freeze/handoff certificate and a new 5-of-7 activation certificate bind the identical old generation, direct successor generation, old/new manifests, state frontier/commitment, and rotation nonce. Generation advances exactly once. |
| B20 | Invalid/competing rotation | A wrong predecessor, skipped generation, modified manifest, modified frontier, replayed handoff, and competing handoff are all rejected. |
| B21 | Rotation/payment race | A payment excluded from a certified freeze frontier and that freeze cannot both become effective. A payment certified before freeze is included in the handoff and remains spendable afterward. Honest successor voting and an excluding freeze choice are mutually exclusive and durable. |
| B22 | Retired committee | After handoff and restart, five honest old validators remain retired and refuse new old-generation shares. At most two retained Byzantine old-key shares are obtainable. |
| B23 | Post-rotation spend | Bob spends the state received under the previous committee through the new committee using the exact verified handoff lineage. A conflicting or unhanded state is rejected. |
| B24 | Stale certificate-only bootstrap | A genuine old prefix is recognized as valid historical evidence but is explicitly rejected as proof of currentness. The client does not silently treat the terminal certificate in the supplied prefix as current. |
| B25 | Live current freshness | A CSPRNG-generated fresh client nonce and exact subject state obtain five distinct valid responses from the active committee and are accepted. |
| B26 | Retired-committee freshness | For a never-before-seen nonce, a retired committee can provide at most the two Byzantine old-key responses and cannot prove currentness. |
| B27 | Freshness replay and substitution | A genuine response for another nonce, subject state, network, committee, or generation is rejected. |
| B28 | Eclipse/fewer-than-five fail-closed behavior | With fewer than five current members reachable, the client enters an explicit paused/no-freshness state. It neither accepts stale state nor claims liveness. |
| B30-B | Campaign evidence and metrics | Raw per-scenario evidence includes seeds, validator identities, fault hooks, partition membership, message schedule, accepted/rejected counts, finality p50/p95/p99/max, throughput, CPU, peak RSS, TCP bytes/messages, durable-write latency, restart time, partition-heal time, rotation time, certificate size, and state/journal growth. One warm-up and five measured runs are distinguished. |
| B31-B | Campaign cleanup and repeatability | No campaign process remains; all test-owned state is isolated; every deterministic safety outcome repeats from a clean start. Cleanup failure is not hidden by a successful safety assertion. |

### Required rotation state machine for Phase B

Old and new committees may be disjoint, so same-committee quorum intersection alone cannot protect the boundary. Phase B requires an atomic freeze/handoff:

1. An old validator durably enters `FROZEN(rotation_id, frontier)` before releasing its freeze share.
2. A validator that signed the freeze may not sign an old-generation payment excluded from that frontier.
3. Five old shares certify the exact direct-successor handoff.
4. Five new validators acknowledge the exact same handoff before activation.
5. The new committee accepts only states included in, or validly derived from, that handoff.
6. Honest old validators persist `RETIRED` across restart.

The freeze orders a committee-control transition relative to affected state. It does not establish a universal order among independent payments.

### Full-campaign decision

```text
INTEGRATION001_FULL_PASS =
    PHASE_A_PASS
    AND every Phase B row B14..B28, B30-B, and B31-B
        is implemented, executed, evidenced, and PASS
    AND no hard-failure condition occurs anywhere

INTEGRATION001_FULL_PASS is FALSE when Phase B is NOT_IMPLEMENTED or NOT_RUN.
```

The following are unconditional hard failures in either phase:

```text
any unauthorized 5-of-7 certificate
any two conflicting successor intents certified for one input/version
any accepted state transition that violates monetary conservation
any duplicate/non-member share increasing quorum weight
any acknowledged honest vote missing after an in-scope restart
any stale committee/state accepted as current under an executed freshness gate
any altered handoff or non-direct committee generation accepted
```

## 8. Required metrics and claim limits

Phase A records only metrics that the implemented harness actually measures. A missing CPU, RSS, network-byte, fsync, recovery, or percentile measurement must be printed as `NOT_MEASURED`; it must never be synthesized or inferred.

Phase B's eventual campaign should use one unmeasured warm-up followed by five measured seeded runs. It must report raw data and p50/p95/p99/max latency, not only averages.

INTEGRATION-001 sets no promotional TPS threshold. The correctness suite passes by preserving invariants and completing the healthy-path batch. A single-host loopback throughput result cannot establish WAN performance, decentralization, physical scalability, or that CALIBRE is the fastest protocol.

## 9. What a Phase A pass proves

Within the compiled implementation, exact run configuration, and one-host local-process model, Phase A can prove only that:

- the tested owner authorization and exact-field binding reject the listed mutations;
- the tested 5-of-7 certificate verifier counts distinct active validator identities;
- the normal `100 -> 60 + 39 + 1 fee` transition conserves value;
- the tested conflict schedules preserve at-most-one certified successor under `f<=2`;
- the tested unrelated input objects can be handled without an acceptance-critical universal transaction sequence;
- the implemented software-key path requires no TPM or trusted hardware;
- the exact reported batch and timing observations occurred on that machine;
- Phase A's implemented mechanisms execute together rather than only as isolated historical experiments.

## 10. What a Phase A pass does not prove

It does not prove:

- any Phase B crash, partition, rotation, or offline-freshness gate;
- physical multi-machine, WAN, cross-country, or independent-failure-domain behavior;
- correctness under every asynchronous schedule or a formal safety/liveness theorem;
- guaranteed progress for an owner-signed double spend;
- safety with three Byzantine validators or more;
- malicious storage rollback, physical key erasure, host compromise, or accumulated retired-key compromise;
- permissionless membership, Sybil resistance, staking, slashing, rewards, or sustainable economics;
- data availability, archival recovery, or new-node synchronization;
- multi-input atomicity unless separately implemented and tested;
- smart contracts, shared-state programmability, privacy, bridges, or interoperability;
- post-quantum security or production key management;
- denial-of-service or resource-exhaustion resistance;
- production throughput, horizontal scalability, or a fastest-protocol claim;
- patentability, novelty, regulatory compliance, or deployment readiness.

It also does not prove absolute "ledgerlessness." Validators still require persistent current-state and consumed/conflict information. The precise defensible claim is:

> The tested path uses no blockchain and no universal transaction order for independent payments.

Per-object causal generations, conflict-local rounds, ordered committee generations, local write-ahead journals, and an unordered state-set commitment are compatible with that claim because none universally sequences every transaction.

## 11. Closest existing system concepts

No cited system is an exact match for the proposed complete CALIBRE combination.

| System or concept | Closest similarity | Important difference from this CALIBRE target |
|---|---|---|
| [FastPay](https://arxiv.org/abs/2003.11506) | Distributed authorities, Byzantine faults, payment certificates, and Byzantine Consistent Broadcast instead of full consensus for every payment. | FastPay is a pre-funded settlement design with its own account/certificate rules; it is not this exact state-cell, rotation, and offline-freshness construction. |
| [Sui owned-object fast path](https://docs.sui.io/develop/objects/versioning) | Versioned owned objects; validators reject conflicts against the same object version; eligible owned-object transfers can bypass consensus. | Sui is an on-chain L1 with consensus paths and checkpoints elsewhere in the system. |
| [R3 Corda notaries](https://docs.r3.com/en/platform/corda/4.8/enterprise/key-concepts-notaries.html) | A uniqueness service signs only when input states have not already been consumed, directly addressing double-spend prevention. | Corda is an enterprise DLT/notary architecture, not this native public monetary protocol or fixed lifecycle. |
| PBFT/HotStuff/Tendermint-style quorum intersection | `N=3f+1`, `Q=2f+1`, honest intersection, locking, and Byzantine safety concepts. | These systems conventionally agree on an ordered log or blocks; CALIBRE's target applies agreement to conflict-local successors and committee control metadata. |
| [CometBFT light-client model](https://github.com/cometbft/cometbft/blob/main/spec/light-client/README.md) | Starts from trusted validator state and verifies signed validator-set/state evolution with explicit safety and liveness assumptions. | It verifies blockchain headers and uses a different time/trust model; CALIBRE's proposed freshness challenge is nonce-bound and has no block-history requirement. |
| Bitcoin UTXO | Owner authorization and unique consumption of a referenced output. | Bitcoin resolves conflicts through globally ordered blocks and chain selection. |

The strongest accurate comparison is component-level: FastPay and Sui for low-ordering payment paths, Corda for input uniqueness, Byzantine quorum protocols for intersection safety, and light-client work for evolving validator trust. Passing Phase A would not establish superiority over any of them.

## 12. Audit checklist for every result file

Every claimed result must answer all of the following:

- Which commit and binary produced the output?
- Was this `cargo test`, the default Phase A live run, or a future Phase B campaign?
- Which exact B-rows executed?
- Were the required faults actually injected and observed?
- Which rows are `NOT_RUN` or `NOT_IMPLEMENTED`?
- Were there zero unauthorized certificates and zero pairs of conflicting certified successor intents?
- Did value conservation hold exactly?
- Did any liveness statement rely on Byzantine cooperation?
- Which metrics were measured, and which were `NOT_MEASURED`?
- Did all child processes and test-owned state clean up?
- Does the headline say `PHASE A` rather than falsely saying `FULL PASS`?

If any answer is absent, the strongest allowed outcome is `INCONCLUSIVE` for the affected claim.
