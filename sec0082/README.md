# CALIBRE SECURITY SEC-008.2

## Hardened randomized TCP fault campaign

SEC-008.2 combines the hardened checksummed WAL discipline from SEC-008.1 with the seven-process randomized conflict campaign from SEC-008.

It is designed to answer four separate questions without hiding failures behind one aggregate PASS label:

1. **Safety:** under the declared N=7, Q=5, f<=2 model, can two conflicting successors both obtain valid 5-of-7 certificates in the tested randomized schedules?
2. **Durability:** after an honest certifier has durably locked one digest and returned a share, does a process kill/restart preserve same-digest acceptance and conflicting-digest rejection?
3. **Fault injection correctness:** are message drops real at the application scheduler layer (the TCP request is actually not sent), rather than merely counted?
4. **Liveness:** after the network heals, can permanent first-seen locks still leave the five honest certifiers split 3/2 so that neither successor reaches 5-of-7?

## Mechanisms

- seven independent OS child processes
- real TCP loopback sockets on 127.0.0.1
- owner-bound real Ed25519 user authorization
- real Ed25519 certifier shares
- five unique shares required for authorization
- certifiers 0 and 1 Byzantine
- certifiers 2..6 honest
- honest one-digest-per-input-generation rule
- 96-byte WAL records: magic + epoch + input id + generation + digest + BLAKE3 checksum
- WAL append followed by `sync_all()` before an honest certifier returns its share
- randomized delivery order
- actual application-scheduler message drops where no TCP request is sent
- duplicate delivery attempts
- bounded delays
- Byzantine sign-A / sign-B / sign-both / withhold choices
- periodic honest process kill/restart
- explicit healed-network phase where all honest nodes receive both conflicts

## Expected current-protocol result

The current permanent first-seen locking rule is expected to preserve safety for tested f<=2 schedules but **not** guarantee liveness. A 3/2 honest split plus Byzantine withholding can permanently strand both successors below quorum even after connectivity is restored.

A successful experiment therefore does **not** mean every sub-property passes. The expected decision is:

- randomized conflict safety: PASS in tested schedules if dual certificates remain zero
- hardened process-restart durability: PASS if every scheduled restart preserves the prior lock
- real application-layer drop injection: PASS if requests are genuinely skipped
- conflict liveness: FAIL / deadlock attack confirmed

That failure is the motivation for the next protocol mechanism: a **conflict-local round-change / canonical-winner rule** that lets honest nodes safely converge without globally ordering unrelated payments.

## Claim limits

This is still one physical host. It does not prove WAN behavior, arbitrary asynchronous-network liveness, kernel-level packet-loss behavior, power-loss or disk-controller durability, malicious storage snapshot rollback resistance, committee rotation, Sybil resistance, or production finality.

No blockchain, block chain, DAG, or universal transaction ordering is used by this experiment.
