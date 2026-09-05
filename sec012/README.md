# CALIBRE SECURITY SEC-012

## Bounded exhaustive conflict-local QC / round-change state model

SEC-012 complements the real-TCP randomized SEC-009/010/011 experiments with a bounded exhaustive state-space model of the same `N=7, Q=5, f<=2` conflict-local safety rules.

The model explores all seven leader offsets across three adversarial conflict-local rounds. It branches over:

- no-QC outcomes caused by delay or withholding;
- Byzantine-leader attempts for either conflicting successor;
- honest-leader proposals following the highest known conflict-local PREVOTE QC, otherwise the canonical candidate;
- every subset of honest nodes that receives a valid PREVOTE QC and therefore durably PRECOMMITS/locks that digest;
- Byzantine completion or withholding of PREVOTE/PRECOMMIT quorum certificates;
- partial QC-lock delivery, full honest QC-lock delivery, and finality branches;
- later higher-round safe unlocking only when a conflicting digest carries a strictly higher valid PREVOTE QC.

After the adversarial bound, every reachable non-final state is checked under a healed-network/GST assumption where Byzantine leaders may stay silent but conflict-local leaders rotate through all seven committee members. The model asks whether an honest leader can safely drive five honest PREVOTEs and five honest PRECOMMITS to one successor within seven rounds.

## Abstraction boundary

SEC-012 is **not** a network benchmark and **not** a formal unbounded Byzantine consensus theorem. Cryptographic signatures are abstracted as unforgeable, and durable same-round non-equivocation/QC-lock persistence are imported as assumptions already attacked operationally in SEC-011.

The purpose is to search the bounded protocol state space more exhaustively than randomized scheduling can.

A PASS may be labelled:

`BOUNDED EXHAUSTIVE CONFLICT-LOCAL QC/ROUND-CHANGE SAFETY + POST-HEAL RECOVERY PASS WITHIN MODELED N=7,Q=5,f<=2 BOUND`

It must not be labelled a complete formal proof.

No blockchain, blocks, DAG, or universal transaction ordering are used by the model.
