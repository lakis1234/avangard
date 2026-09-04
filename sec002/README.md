# CALIBRE SECURITY SEC-002

## 5-of-7 Threshold Authorization + Conflict-Lock Quorum Boundary

SEC-001 proved owner-bound user authorization but also demonstrated that one trusted certifier could forge an authorization handoff. SEC-002 replaces that single-certifier trust point with seven independent certifiers and requires five unique valid Ed25519 shares.

Each honest certifier independently verifies the user's Ed25519 signature, checks that the signing key owns every referenced active cell, checks generation and value conservation, and then records a one-digest-per-input-generation lock for the current certificate epoch before signing.

The experiment tests two different Byzantine properties:

1. **Unauthorized theft:** two Byzantine certifiers cannot fabricate a 5-of-7 threshold certificate for a user who does not own the cells.
2. **Conflicting successors:** with `N=7`, `Q=5`, quorum intersection is `2Q-N = 3`. Under the honest one-digest lock rule, two conflicting 5-share certificates cannot exist when `f <= 2`; when `f = 3`, the three Byzantine certifiers can sign both candidates while the four honest certifiers split 2+2, producing two valid 5-share certificates on partitioned replicas.

This is a security-semantics experiment, not a throughput benchmark. It does not use blocks, a DAG, or universal transaction ordering. Persistent crash-safe certifier locks and physical multi-machine/WAN partitions are not yet tested.
