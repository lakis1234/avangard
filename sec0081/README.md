# CALIBRE SECURITY SEC-008.1

## Durable conflict-lock restart forensics

SEC-008.1 isolates the unexpected local SEC-008 abort:

`restart lost honest durable lock at trial 1000 node 4`

The goal is to determine whether a correctly synced conflict lock is actually missing after process restart, or whether the earlier campaign/harness was too weak to diagnose the event.

This experiment uses five separate honest certifier OS processes communicating over real TCP loopback sockets. Each process maintains its own append-only conflict-lock WAL using a stronger 96-byte record format:

- 8-byte magic
- 8-byte epoch
- 8-byte input id
- 8-byte input generation
- 32-byte transaction digest
- 32-byte BLAKE3 checksum

Before an honest certifier returns an Ed25519 share it:

1. seeks to the end of its WAL,
2. appends the complete lock record,
3. calls `sync_all()`,
4. inserts the lock into memory,
5. only then returns the signature share.

The controller directly rereads and verifies the WAL before and after every scheduled crash/restart. After restart it requires:

- the same digest to remain present in the WAL,
- the same transaction to still be signable,
- the conflicting transaction to remain rejected.

The default campaign writes 2500 unique monetary conflict locks and performs a process crash/restart every 50 trials. Trial 1000 explicitly targets certifier node 4 to reproduce the location of the earlier abort.

## Claim discipline

A PASS means the hardened checksummed WAL/replay path survived the tested process kill/restart campaign on the tested host. It does **not** prove sudden power-loss durability, disk-controller cache guarantees, storage rollback resistance, TPM anti-rollback, physical multi-machine behavior, or Byzantine network liveness.
