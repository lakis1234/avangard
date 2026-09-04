use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::{HashMap, HashSet};

const NETWORK_ID: u32 = 1;
const MAX_INPUTS: usize = 8;
const CELL_VALUE: u64 = 100;
const CERT_EPOCH: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cell {
    id: u64,
    value: u64,
    generation: u64,
    owner: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InputRef {
    id: u64,
    generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SpendTx {
    network_id: u32,
    tx_id: u64,
    inputs: Vec<InputRef>,
    output_id: u64,
    recipient: [u8; 32],
    output_value: u64,
    expiry: u64,
}

#[derive(Clone, Copy, Debug)]
struct UserAuthorization {
    signer: [u8; 32],
    signature: [u8; 64],
}

#[derive(Clone, Copy, Debug)]
struct VerifiedSpend {
    tx_digest: [u8; 32],
    user_signer: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct AuthorizationCertificate {
    certifier: [u8; 32],
    user_signer: [u8; 32],
    tx_digest: [u8; 32],
    epoch: u64,
    signature: [u8; 64],
}

#[derive(Clone)]
struct CoreState {
    active: HashMap<u64, Cell>,
    trusted_certifier: [u8; 32],
}

fn deterministic_key(label: u64) -> SigningKey {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC001_DETERMINISTIC_KEY_V1");
    h.update(&label.to_le_bytes());
    let seed = *h.finalize().as_bytes();
    SigningKey::from_bytes(&seed)
}

fn canonical_user_message(tx: &SpendTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + tx.inputs.len() * 16);
    out.extend_from_slice(b"CALIBRE_SEC001_USER_SPEND_V1");
    out.extend_from_slice(&tx.network_id.to_le_bytes());
    out.extend_from_slice(&tx.tx_id.to_le_bytes());
    out.extend_from_slice(&(tx.inputs.len() as u64).to_le_bytes());
    for input in &tx.inputs {
        out.extend_from_slice(&input.id.to_le_bytes());
        out.extend_from_slice(&input.generation.to_le_bytes());
    }
    out.extend_from_slice(&tx.output_id.to_le_bytes());
    out.extend_from_slice(&tx.recipient);
    out.extend_from_slice(&tx.output_value.to_le_bytes());
    out.extend_from_slice(&tx.expiry.to_le_bytes());
    out
}

fn tx_commitment(tx: &SpendTx, signer: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC001_AUTHORIZED_TX_COMMITMENT_V1");
    h.update(&canonical_user_message(tx));
    h.update(signer);
    *h.finalize().as_bytes()
}

fn certificate_message(
    tx_digest: &[u8; 32],
    user_signer: &[u8; 32],
    epoch: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(b"CALIBRE_SEC001_AUTH_CERTIFICATE_V1");
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(tx_digest);
    out.extend_from_slice(user_signer);
    out
}

fn sign_user_spend(tx: &SpendTx, sk: &SigningKey) -> UserAuthorization {
    let signature = sk.sign(&canonical_user_message(tx)).to_bytes();
    UserAuthorization {
        signer: sk.verifying_key().to_bytes(),
        signature,
    }
}

fn verify_user_authorization(
    tx: &SpendTx,
    auth: &UserAuthorization,
    cells: &HashMap<u64, Cell>,
) -> Result<VerifiedSpend, String> {
    if tx.network_id != NETWORK_ID {
        return Err("wrong network/domain".into());
    }
    if tx.inputs.is_empty() || tx.inputs.len() > MAX_INPUTS {
        return Err("invalid input count".into());
    }

    let vk = VerifyingKey::from_bytes(&auth.signer).map_err(|_| "invalid user public key")?;
    let sig = Signature::from_bytes(&auth.signature);
    vk.verify_strict(&canonical_user_message(tx), &sig)
        .map_err(|_| "user signature rejected")?;

    let mut seen = HashSet::with_capacity(tx.inputs.len());
    let mut total = 0u64;
    for input in &tx.inputs {
        if !seen.insert(input.id) {
            return Err("duplicate input".into());
        }
        let cell = cells
            .get(&input.id)
            .ok_or_else(|| format!("input {} not active", input.id))?;
        if cell.generation != input.generation {
            return Err(format!("input {} generation mismatch", input.id));
        }
        if cell.owner != auth.signer {
            return Err(format!("input {} owner mismatch", input.id));
        }
        total = total
            .checked_add(cell.value)
            .ok_or_else(|| "input value overflow".to_string())?;
    }

    if total != tx.output_value {
        return Err(format!(
            "value conservation mismatch: inputs={} output={}",
            total, tx.output_value
        ));
    }

    Ok(VerifiedSpend {
        tx_digest: tx_commitment(tx, &auth.signer),
        user_signer: auth.signer,
    })
}

fn issue_certificate(
    verified: VerifiedSpend,
    certifier_sk: &SigningKey,
) -> AuthorizationCertificate {
    let signature = certifier_sk
        .sign(&certificate_message(
            &verified.tx_digest,
            &verified.user_signer,
            CERT_EPOCH,
        ))
        .to_bytes();
    AuthorizationCertificate {
        certifier: certifier_sk.verifying_key().to_bytes(),
        user_signer: verified.user_signer,
        tx_digest: verified.tx_digest,
        epoch: CERT_EPOCH,
        signature,
    }
}

// Diagnostic helper used only to demonstrate the trust limitation of a single trusted certifier.
// It deliberately bypasses verify_user_authorization().
fn issue_raw_certificate_without_user_check(
    tx: &SpendTx,
    claimed_user: [u8; 32],
    certifier_sk: &SigningKey,
) -> AuthorizationCertificate {
    issue_certificate(
        VerifiedSpend {
            tx_digest: tx_commitment(tx, &claimed_user),
            user_signer: claimed_user,
        },
        certifier_sk,
    )
}

impl CoreState {
    fn new(cells: HashMap<u64, Cell>, trusted_certifier: [u8; 32]) -> Self {
        Self {
            active: cells,
            trusted_certifier,
        }
    }

    fn apply_certified_spend(
        &mut self,
        tx: &SpendTx,
        cert: &AuthorizationCertificate,
    ) -> Result<Cell, String> {
        if tx.network_id != NETWORK_ID {
            return Err("core wrong network/domain".into());
        }
        if cert.epoch != CERT_EPOCH {
            return Err("certificate epoch mismatch".into());
        }
        if cert.certifier != self.trusted_certifier {
            return Err("certificate signer is not trusted".into());
        }

        let expected_digest = tx_commitment(tx, &cert.user_signer);
        if expected_digest != cert.tx_digest {
            return Err("certificate does not bind this exact transaction".into());
        }

        let vk = VerifyingKey::from_bytes(&cert.certifier)
            .map_err(|_| "invalid certificate public key")?;
        let sig = Signature::from_bytes(&cert.signature);
        vk.verify_strict(
            &certificate_message(&cert.tx_digest, &cert.user_signer, cert.epoch),
            &sig,
        )
        .map_err(|_| "certificate signature rejected")?;

        if tx.inputs.is_empty() || tx.inputs.len() > MAX_INPUTS {
            return Err("core invalid input count".into());
        }
        if self.active.contains_key(&tx.output_id) {
            return Err("output id already active".into());
        }

        // The core checks current-state existence/generation/value atomically, but intentionally
        // delegates USER ownership/signature verification to the authorization tier in SEC-001.
        let mut seen = HashSet::with_capacity(tx.inputs.len());
        let mut total = 0u64;
        for input in &tx.inputs {
            if !seen.insert(input.id) {
                return Err("core duplicate input".into());
            }
            let cell = self
                .active
                .get(&input.id)
                .ok_or_else(|| format!("core input {} already spent/not active", input.id))?;
            if cell.generation != input.generation {
                return Err(format!("core input {} generation mismatch", input.id));
            }
            total = total
                .checked_add(cell.value)
                .ok_or_else(|| "core input value overflow".to_string())?;
        }
        if total != tx.output_value {
            return Err("core value conservation mismatch".into());
        }

        for input in &tx.inputs {
            self.active.remove(&input.id);
        }
        let output = Cell {
            id: tx.output_id,
            value: tx.output_value,
            generation: 0,
            owner: tx.recipient,
        };
        if self.active.insert(output.id, output.clone()).is_some() {
            return Err("core output collision after validation".into());
        }
        Ok(output)
    }
}

fn alice_cells(alice: [u8; 32]) -> HashMap<u64, Cell> {
    (0..MAX_INPUTS)
        .map(|i| {
            let id = 1_000 + i as u64;
            (
                id,
                Cell {
                    id,
                    value: CELL_VALUE,
                    generation: 7,
                    owner: alice,
                },
            )
        })
        .collect()
}

fn base_tx(recipient: [u8; 32]) -> SpendTx {
    SpendTx {
        network_id: NETWORK_ID,
        tx_id: 42,
        inputs: (0..MAX_INPUTS)
            .map(|i| InputRef {
                id: 1_000 + i as u64,
                generation: 7,
            })
            .collect(),
        output_id: 9_000,
        recipient,
        output_value: CELL_VALUE * MAX_INPUTS as u64,
        expiry: 2_000_000_000,
    }
}

fn main() {
    let alice_sk = deterministic_key(1);
    let bob_sk = deterministic_key(2);
    let mallory_sk = deterministic_key(3);
    let certifier_sk = deterministic_key(100);
    let rogue_certifier_sk = deterministic_key(101);

    let alice = alice_sk.verifying_key().to_bytes();
    let bob = bob_sk.verifying_key().to_bytes();
    let mallory = mallory_sk.verifying_key().to_bytes();
    let trusted_certifier = certifier_sk.verifying_key().to_bytes();

    println!("CALIBRE SECURITY SEC-001 v0.1.0");
    println!("OWNER-BOUND USER AUTHORIZATION -> TRUSTED CERTIFICATE HANDOFF -> STATE-ONLY CORE");
    println!("Purpose: bind spend authority to the owner stored in each monetary cell, then test the certificate handoff used by the fast path");
    println!("Performance target: NONE - performance phase is frozen; this is a security-semantics experiment");
    println!();

    let tx = base_tx(bob);
    let cells = alice_cells(alice);
    let auth = sign_user_spend(&tx, &alice_sk);
    let verified = verify_user_authorization(&tx, &auth, &cells)
        .expect("SEC-001 valid Alice authorization should verify");
    let cert = issue_certificate(verified, &certifier_sk);
    let mut core = CoreState::new(cells.clone(), trusted_certifier);
    let output = core
        .apply_certified_spend(&tx, &cert)
        .expect("SEC-001 valid certified spend should commit");
    assert_eq!(output.owner, bob);
    assert_eq!(output.value, 800);
    println!("VALID OWNER SPEND ALICE -> BOB: PASS");

    let mallory_auth = sign_user_spend(&tx, &mallory_sk);
    assert!(verify_user_authorization(&tx, &mallory_auth, &cells).is_err());
    println!("WRONG KEY ATTEMPTS TO SPEND ALICE CELLS: REJECTED");

    let mut tampered_recipient = tx.clone();
    tampered_recipient.recipient = mallory;
    assert!(verify_user_authorization(&tampered_recipient, &auth, &cells).is_err());
    println!("RECIPIENT CHANGED AFTER ALICE SIGNS: REJECTED");

    let mut tampered_amount = tx.clone();
    tampered_amount.output_value -= 1;
    assert!(verify_user_authorization(&tampered_amount, &auth, &cells).is_err());
    println!("AMOUNT CHANGED AFTER ALICE SIGNS: REJECTED");

    let mut replay_core = CoreState::new(cells.clone(), trusted_certifier);
    assert!(replay_core
        .apply_certified_spend(&tampered_recipient, &cert)
        .is_err());
    println!("CERTIFICATE REPLAYED ON MODIFIED TRANSACTION: REJECTED");

    let rogue_verified = verify_user_authorization(&tx, &auth, &cells).unwrap();
    let rogue_cert = issue_certificate(rogue_verified, &rogue_certifier_sk);
    let mut rogue_core = CoreState::new(cells.clone(), trusted_certifier);
    assert!(rogue_core.apply_certified_spend(&tx, &rogue_cert).is_err());
    println!("UNTRUSTED CERTIFIER: REJECTED");

    // Local double-spend safety: after the first certified handoff consumes Alice's inputs,
    // replaying the same certificate cannot resurrect or spend those cells again.
    assert!(core.apply_certified_spend(&tx, &cert).is_err());
    println!("LOCAL REPLAY / SECOND SPEND OF CONSUMED CELLS: REJECTED");

    // Expected limitation: because the fast core delegates individual user-signature checking to
    // the authorization tier, a malicious TRUSTED single certifier can lie about that check.
    let forged_tx = base_tx(mallory);
    let forged_cert = issue_raw_certificate_without_user_check(&forged_tx, mallory, &certifier_sk);
    let mut vulnerable_core = CoreState::new(cells, trusted_certifier);
    let forged_output = vulnerable_core
        .apply_certified_spend(&forged_tx, &forged_cert)
        .expect("SEC-001 expected limitation: trusted certifier forgery should reach core");
    assert_eq!(forged_output.owner, mallory);
    println!("MALICIOUS TRUSTED SINGLE CERTIFIER FORGERY: ATTACK CONFIRMED (EXPECTED LIMITATION)");
    println!();

    println!("=== SEC-001 DECISION ===");
    println!("USER KEY BOUND TO INPUT-CELL OWNER IN AUTHORIZATION TIER: PASS");
    println!("USER SIGNATURE BINDS INPUTS + RECIPIENT + AMOUNT + OUTPUT ID + NETWORK + EXPIRY: PASS");
    println!("CERTIFICATE BINDS EXACT AUTHORIZED TRANSACTION + CLAIMED USER: PASS");
    println!("UNTRUSTED CERTIFIER REJECTION: PASS");
    println!("LOCAL CONSUMED-CELL REPLAY REJECTION: PASS");
    println!("SINGLE TRUSTED CERTIFIER BYZANTINE SAFETY: FAIL - ATTACK CONFIRMED BY DESIGN");
    println!("DISTRIBUTED THRESHOLD AUTHORIZATION / BYZANTINE QUORUM: NOT YET");
    println!("PERSISTENCE / CRASH RECOVERY: NOT YET");
    println!("PHYSICAL/WAN NETWORK: NOT YET");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        SigningKey,
        SigningKey,
        SigningKey,
        SigningKey,
        SigningKey,
        HashMap<u64, Cell>,
        SpendTx,
    ) {
        let alice_sk = deterministic_key(1);
        let bob_sk = deterministic_key(2);
        let mallory_sk = deterministic_key(3);
        let certifier_sk = deterministic_key(100);
        let rogue_certifier_sk = deterministic_key(101);
        let alice = alice_sk.verifying_key().to_bytes();
        let bob = bob_sk.verifying_key().to_bytes();
        let cells = alice_cells(alice);
        let tx = base_tx(bob);
        (
            alice_sk,
            bob_sk,
            mallory_sk,
            certifier_sk,
            rogue_certifier_sk,
            cells,
            tx,
        )
    }

    #[test]
    fn valid_owner_authorization_and_certificate_commit() {
        let (alice_sk, bob_sk, _, certifier_sk, _, cells, tx) = fixture();
        let auth = sign_user_spend(&tx, &alice_sk);
        let verified = verify_user_authorization(&tx, &auth, &cells).unwrap();
        let cert = issue_certificate(verified, &certifier_sk);
        let mut core = CoreState::new(cells, certifier_sk.verifying_key().to_bytes());
        let output = core.apply_certified_spend(&tx, &cert).unwrap();
        assert_eq!(output.owner, bob_sk.verifying_key().to_bytes());
        assert_eq!(output.value, 800);
    }

    #[test]
    fn wrong_owner_key_is_rejected() {
        let (_, _, mallory_sk, _, _, cells, tx) = fixture();
        let auth = sign_user_spend(&tx, &mallory_sk);
        assert!(verify_user_authorization(&tx, &auth, &cells).is_err());
    }

    #[test]
    fn signed_recipient_and_amount_tamper_are_rejected() {
        let (alice_sk, _, mallory_sk, _, _, cells, tx) = fixture();
        let auth = sign_user_spend(&tx, &alice_sk);

        let mut recipient_tamper = tx.clone();
        recipient_tamper.recipient = mallory_sk.verifying_key().to_bytes();
        assert!(verify_user_authorization(&recipient_tamper, &auth, &cells).is_err());

        let mut amount_tamper = tx.clone();
        amount_tamper.output_value -= 1;
        assert!(verify_user_authorization(&amount_tamper, &auth, &cells).is_err());
    }

    #[test]
    fn certificate_replay_on_modified_transaction_is_rejected() {
        let (alice_sk, _, mallory_sk, certifier_sk, _, cells, tx) = fixture();
        let auth = sign_user_spend(&tx, &alice_sk);
        let cert = issue_certificate(
            verify_user_authorization(&tx, &auth, &cells).unwrap(),
            &certifier_sk,
        );
        let mut modified = tx.clone();
        modified.recipient = mallory_sk.verifying_key().to_bytes();
        let mut core = CoreState::new(cells, certifier_sk.verifying_key().to_bytes());
        assert!(core.apply_certified_spend(&modified, &cert).is_err());
    }

    #[test]
    fn untrusted_certifier_is_rejected() {
        let (alice_sk, _, _, certifier_sk, rogue_certifier_sk, cells, tx) = fixture();
        let auth = sign_user_spend(&tx, &alice_sk);
        let verified = verify_user_authorization(&tx, &auth, &cells).unwrap();
        let rogue_cert = issue_certificate(verified, &rogue_certifier_sk);
        let mut core = CoreState::new(cells, certifier_sk.verifying_key().to_bytes());
        assert!(core.apply_certified_spend(&tx, &rogue_cert).is_err());
    }

    #[test]
    fn local_double_spend_replay_is_rejected_after_commit() {
        let (alice_sk, _, _, certifier_sk, _, cells, tx) = fixture();
        let auth = sign_user_spend(&tx, &alice_sk);
        let cert = issue_certificate(
            verify_user_authorization(&tx, &auth, &cells).unwrap(),
            &certifier_sk,
        );
        let mut core = CoreState::new(cells, certifier_sk.verifying_key().to_bytes());
        assert!(core.apply_certified_spend(&tx, &cert).is_ok());
        assert!(core.apply_certified_spend(&tx, &cert).is_err());
    }

    #[test]
    fn trusted_single_certifier_can_forge_expected_limitation() {
        let (_, _, mallory_sk, certifier_sk, _, cells, _) = fixture();
        let mallory = mallory_sk.verifying_key().to_bytes();
        let forged_tx = base_tx(mallory);
        let forged_cert = issue_raw_certificate_without_user_check(
            &forged_tx,
            mallory,
            &certifier_sk,
        );
        let mut core = CoreState::new(cells, certifier_sk.verifying_key().to_bytes());
        let output = core
            .apply_certified_spend(&forged_tx, &forged_cert)
            .expect("trusted single certifier is intentionally a security boundary in SEC-001");
        assert_eq!(output.owner, mallory);
    }
}
