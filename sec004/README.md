# CALIBRE SECURITY SEC-004

## Distributed 5-of-7 lock anchor + 6-of-7 rollback recovery

SEC-004 extends the SEC-003 durable local conflict lock with independent witness anchors.

Before an honest certifier returns an authorization share, it signs lock evidence for each input-generation and obtains 5 unique Ed25519 witness acknowledgements. After local state rollback, the certifier requires 6 witness responses before signing again. A prior 5-witness anchor and a 6-witness recovery set intersect in at least 4 nodes; with at most 2 Byzantine witnesses, at least 2 honest witnesses are in the intersection and can return the certifier-signed prior lock evidence.

The experiment deliberately also rolls back the three honest witness WALs that retained the prior anchor. That coordinated software-storage rollback is expected to erase the distributed evidence and recreate two valid 5-of-7 successors. This is the boundary being measured; TPM/hardware monotonic anti-rollback is not yet included.

No global blockchain or universal transaction order is used.
