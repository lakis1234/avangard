# CALIBRE SECURITY SEC-019 v0.19.0

SEC-019 replaces SEC-018's abstract attested-generation object with actual TPM2 command traffic against an isolated `swtpm` process in GitHub Actions.

## The simple question

Can a verifier demand a fresh, signed receipt saying all three of these are true at once?

1. This exact client nonce was answered.
2. This exact pinned NV counter was read.
3. The certified counter equals the state generation the client is being asked to accept.

The verifier also checks the TPM attestation magic/type and independently verifies the RSA signature over the raw `TPMS_ATTEST` bytes.

## Positive path

- Create a TPM-generated restricted RSA attestation key under an endorsement key.
- Require `fixedtpm`, `fixedparent`, `sensitivedataorigin`, `restricted`, and `sign` attributes.
- Define an eight-byte TPM NV counter.
- Increment it to generation 1 and certify it with nonce 1.
- Restart the software TPM, increment to generation 2, and certify it with nonce 2.
- Reject the generation-1 certificate when presented for nonce 2 / generation 2.
- Undefine and identically redefine the same counter Name; require the first new value to remain greater than generation 2.

## Deliberate boundary attack

The experiment copies the complete `swtpm` state directory at generation 1. After advancing, it restores that directory and asks for a new certification. The simulator freshly certifies the rolled-back generation 1 under the same pinned key and NV Name.

That is an expected attack witness: a file-backed virtual TPM does not defeat an attacker who can roll back all of its host state. It prevents SEC-019 from being misreported as physical-hardware or cloud-vTPM rollback proof.

## What a PASS proves

- The actual `TPM2_NV_Increment` / `TPM2_NV_Certify` tool and command path works in the isolated simulator.
- The verifier correctly decodes `TPMS_ATTEST` and binds the signature to the exact nonce, NV Name, counter value, and offset.
- The counter persists across an ordinary simulator restart.
- An identical same-Name NV undefine/redefine does not reset the counter in the tested simulator lifetime.
- Old certificates are rejected for a new client request.

## What it does not prove

- Physical TPM behavior, physical anti-rollback, power-loss durability, or SSD/controller flush semantics.
- Resistance to TPM clear, hierarchy-owner compromise, firmware compromise, or full virtual-TPM state rollback.
- Vendor attestation-key certificates or remote proof that a key belongs to genuine hardware.
- The SEC-018 5-of-7 result on seven physical machines or over a WAN.

## Safety

The workflow creates only an ephemeral file-backed software TPM on a disposable Linux CI runner. It never opens the runner's or the user's physical TPM device and never modifies PCRs, BitLocker, Secure Boot, or an existing key.

## Run on a disposable Linux host

Install `swtpm`, `tpm2-tools`, OpenSSL, and Python 3, then run:

```bash
python3 -m unittest discover -s sec019/tests -v
bash sec019/run_experiment_019.sh
```

Do not redirect this experiment to `/dev/tpm0`, `/dev/tpmrm0`, or a Windows platform TPM.
